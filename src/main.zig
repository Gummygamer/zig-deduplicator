const std = @import("std");

const Dir = std.fs.Dir;
const Allocator = std.mem.Allocator;

const Config = struct {
    dir_path: []const u8,
    action: enum { Delete, Move },
    move_path: ?[]const u8,
};

fn parseArgs(allocator: std.mem.Allocator) !Config {
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    _ = args.skip(); // skip the first argument, which is typically the program name itself.
    var config = Config{
        .dir_path = "",
        .action = .Delete,
        .move_path = null,
    };

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--dir")) {
            config.dir_path = args.next() orelse "";
            // We also need to check that the directory exists and is readable here, but this depends on your specific requirements.
        } else if (std.mem.eql(u8, arg, "--move")) {
            config.action = .Move;
            config.move_path = args.next() orelse "";
            // We also need to check that the destination directory exists and is writable here, but this depends on your specific requirements.
        } else if (std.mem.eql(u8, arg, "--help")) {
            std.log.info("Usage: ./program --dir <directory> [--move <destination_directory>]", .{});
            std.process.exit(0);
        } else {
            std.debug.print("Unknown argument: {s}\n", .{arg});
            return error.InvalidArgument;
        }
    }

    if (std.mem.eql(u8, config.dir_path, "")) {
        std.debug.print("Directory path is missing.\n", .{});
        return error.MissingDirPath;
    }

    return config;
}

fn scanDirectory(dir: std.fs.Dir, config: Config, hashes: *std.HashMap([]const u8, []const u8, std.hash_map.StringContext, std.hash_map.default_max_load_percentage), duplicates: *std.ArrayList([]const u8)) !void {
    var iterator = dir.iterate();
    const openOptions = std.fs.Dir.OpenDirOptions{ .access_sub_paths = true, .iterate = true, .no_follow = false };
    const openFlags = std.fs.File.OpenFlags{ .mode = .read_write };

    while (true) {
        const entry = try iterator.next() orelse break;
        if (entry.kind == std.fs.File.Kind.directory) {
            var subdir = try std.fs.Dir.openDir(dir, entry.name, openOptions);
            defer subdir.close();
            try scanDirectory(subdir, config, hashes, duplicates);
        } else {
            const file = try std.fs.openFileAbsolute(entry.name, openFlags);
            const file_hash = try calculateFileHash(file);
            if (hashes.contains(file_hash)) {
                try duplicates.append(entry.name);
            } else {
                try hashes.put(file_hash, entry.name);
            }
        }
    }
}

const crypto = std.crypto;

fn calculateFileHash(file: std.fs.File) ![]u8 {
    var hasher = crypto.hash.sha3.Sha3_256.init(crypto.hash.sha3.Sha3_256.Options{});

    var offset: u64 = 0;

    while (true) {
        var chunk: [1024]u8 = undefined;
        const bytes_read = try file.pread(chunk[0..], offset);
        if (bytes_read == 0) break;
        hasher.update(&chunk);
        offset += bytes_read;
    }

    var hash: [32]u8 = undefined;
    hasher.final(&hash);
    return &hash;
}

fn handleDuplicates(duplicates: std.ArrayList([]const u8), config: Config) !void {
    for (duplicates.items) |duplicate_path| {
        std.debug.print("Handling duplicate: {s}\n", .{duplicate_path});

        switch (config.action) {
            .Delete => {
                std.debug.print("Deleting file: {s}\n", .{duplicate_path});
                std.fs.deleteFileAbsolute(duplicate_path) catch |err| {
                    std.debug.print("Error deleting file: {}\n", .{err});
                    return err;
                };
            },
            .Move => {
                if (config.move_path) |move_path| {
                    const file_name = std.fs.path.basename(duplicate_path);
                    const destination = try std.fs.path.join(std.heap.page_allocator, &[_][]const u8{ move_path, file_name });
                    defer std.heap.page_allocator.free(destination);

                    std.debug.print("Moving file from {s} to {s}\n", .{ duplicate_path, destination });
                    std.fs.renameAbsolute(duplicate_path, destination) catch |err| {
                        std.debug.print("Error moving file: {}\n", .{err});
                        return err;
                    };
                } else {
                    return error.MissingMovePath;
                }
            },
        }
    }
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const config = try parseArgs(allocator);

    var hashes = std.HashMap([]const u8, []const u8, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator);
    defer hashes.deinit();

    var duplicates = std.ArrayList([]const u8).init(allocator);
    defer duplicates.deinit();

    var dir = try std.fs.cwd().openDir(config.dir_path, .{ .iterate = true });
    defer dir.close();

    if (config.action == .Delete) {
        try scanDirectory(dir, config, &hashes, &duplicates);
    } else if (config.action == .Move) {
        try scanDirectory(dir, config, &hashes, &duplicates);
    }

    try handleDuplicates(duplicates, config);
}
