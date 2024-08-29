const std = @import("std");
const yazap = @import("yazap");
const shamir = @import("sss.zig");

const log = std.log;
const App = yazap.App;
const Arg = yazap.Arg;

pub fn main() !void {
    // stdout is for the actual output of your application, for example if you
    // are implementing gzip, then only the compressed bytes should be sent to
    // stdout, not any debugging messages.
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const allocator = arena.allocator();
    var app = App.init(allocator, "sss", "Shamir Secret Sharing CLI tool");
    defer app.deinit();

    var cli = app.rootCommand();

    var generate_cmd = app.createCommand("generate", "Generate shares given a secret key");
    try generate_cmd.addArg(Arg.singleValueOption("threshold", 't', "Minimum number of shares required to reconstruct the secret key"));
    try generate_cmd.addArg(Arg.singleValueOption("total", 'n', "Total number of shares to generate"));
    try generate_cmd.addArg(Arg.singleValueOption("secret", 's', "Secret key to generate shares for"));

    var reconstruct_cmd = app.createCommand("reconstruct", "Reconstruct a secret key given a number of shares (must meet the min. number of shares required to work)");
    try reconstruct_cmd.addArg(Arg.multiValuesOption("shares", 's', "Share values to reconstruct secret key", 255));

    try cli.addSubcommand(generate_cmd);
    try cli.addSubcommand(reconstruct_cmd);

    const matches = try app.parseProcess();

    // `Generate` subcommand setup
    if (matches.subcommandMatches("generate")) |gen_cmd_matches| {
        if (gen_cmd_matches.getSingleValue("threshold") == null) {
            try stdout.print("Please provide minimum number of shares to reconstruct secret", .{});
            try bw.flush();
            return;
        }
        if (gen_cmd_matches.getSingleValue("total") == null) {
            try stdout.print("Please provide total number of shares to generate", .{});
            try bw.flush();
            return;
        }
        if (gen_cmd_matches.getSingleValue("secret") == null) {
            try stdout.print("Please provide your secret", .{});
            try bw.flush();
            return;
        }

        const threshold = try std.fmt.parseInt(u8, gen_cmd_matches.getSingleValue("threshold").?, 10);
        const total = try std.fmt.parseInt(u8, gen_cmd_matches.getSingleValue("total").?, 10);
        const secret = gen_cmd_matches.getSingleValue("secret").?;

        // Secret can have max size of 255
        var buffer: [255]u8 = undefined;
        const secret_slice = buffer[0..secret.len];
        std.mem.copyForwards(u8, secret_slice, secret);
        const secret_list = std.ArrayList(u8).fromOwnedSlice(allocator, secret_slice);

        const shares = try shamir.generate(secret_list, total, threshold, allocator);
        for (shares.items, 0..) |share, i| {
            if (i > 0) {
                try stdout.print("\n", .{});
            }
            for (share.items) |s| {
                try stdout.print("{X:0>2}", .{s});
            }
        }

        try bw.flush();
    }

    // `Reconstruct` subcommand setup
    if (matches.subcommandMatches("reconstruct")) |gen_cmd_matches| {
        if (gen_cmd_matches.getMultiValues("shares") == null) {
            try stdout.print("Please provide your share values", .{});
            try bw.flush();
            return;
        }

        const shares = gen_cmd_matches.getMultiValues("shares").?;
        var share_lists = std.ArrayList(std.ArrayList(u8)).init(allocator);
        defer share_lists.deinit();

        for (shares) |raw_share| {
            // Input is expected to be in 2-digit hex format
            var buffer: [256]u8 = undefined;
            var i: usize = 0;
            while (i < raw_share.len) : (i += 2) {
                const raw_hex = raw_share[i .. i + 2];
                const hex = try std.fmt.parseInt(u8, raw_hex, 16);
                buffer[i / 2] = hex;
            }
            const s_slice = buffer[0 .. raw_share.len / 2];
            const share_list = std.ArrayList(u8).fromOwnedSlice(allocator, s_slice);

            // Clone is required to prevent being overwritten
            // in subsequent iteration of loop
            const share_list_clone = try share_list.clone();
            try share_lists.append(share_list_clone);
        }

        const share_lists_slice = try share_lists.toOwnedSlice();
        const secret = try shamir.reconstruct(share_lists_slice, allocator);

        try stdout.print("Regenerated secret: ", .{});
        for (secret.items) |s| {
            try stdout.print("{c}", .{s});
        }

        try bw.flush();
    }
}
