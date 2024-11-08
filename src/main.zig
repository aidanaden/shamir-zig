const std = @import("std");
const Allocator = std.mem.Allocator;

const Keccak256 = std.crypto.hash.sha3.Keccak256;
const Ristretto255 = std.crypto.ecc.Ristretto255;

const ShamirRistretto = @import("shamir.zig").ShamirRistretto(1);
const ShamirGF256 = @import("shamir.zig").ShamirGF256;

const FeldmanRistretto = @import("feldman.zig").Feldman;
const FeldmanShare = @import("feldman.zig").Share;

const PedersenRistretto = @import("pedersen.zig").Pedersen;
const PedersenShare = @import("pedersen.zig").Share;

const yazap = @import("yazap");
const log = std.log;
const App = yazap.App;
const Arg = yazap.Arg;

const ModeError = error{InvalidMode};
const Mode = enum {
    ShamirGF256,
    ShamirRistretto,
    FeldmanRistretto,
    PedersenRistretto,

    pub fn fromStr(raw_str: []const u8) ModeError!Mode {
        if (std.mem.eql(u8, raw_str, "s256")) {
            return Mode.ShamirGF256;
        } else if (std.mem.eql(u8, raw_str, "s25519")) {
            return Mode.ShamirRistretto;
        } else if (std.mem.eql(u8, raw_str, "f25519")) {
            return Mode.FeldmanRistretto;
        } else if (std.mem.eql(u8, raw_str, "p25519")) {
            return Mode.PedersenRistretto;
        } else {
            return ModeError.InvalidMode;
        }
    }
};

const Algo = union(enum) {
    shamir_gf256: ShamirGF256,
    shamir_ristretto: ShamirRistretto,
    feldman_ristretto: FeldmanRistretto,
    pedersen_ristretto: PedersenRistretto,

    const Self = @This();
    pub fn init(mode: Mode, allocator: Allocator) Self {
        return switch (mode) {
            Mode.ShamirGF256 => Self{ .shamir_gf256 = ShamirGF256.init(allocator) },
            Mode.ShamirRistretto => Self{ .shamir_ristretto = ShamirRistretto.init(allocator) },
            Mode.FeldmanRistretto => Self{ .feldman_ristretto = FeldmanRistretto.init(allocator) },
            Mode.PedersenRistretto => Self{ .pedersen_ristretto = PedersenRistretto.init(allocator) },
        };
    }
};

pub fn main() !void {
    // stdout is for the actual output of your application, for example if you
    // are implementing gzip, then only the compressed bytes should be sent to
    // stdout, not any debugging messages.
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();
    const stdout_any = stdout.any();

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const allocator = arena.allocator();
    var app = App.init(allocator, "shamir", "Shamir Secret Sharing CLI tool");
    defer app.deinit();

    var cli = app.rootCommand();

    var generate_cmd = app.createCommand("generate", "Generate shares given a secret key");
    try generate_cmd.addArg(Arg.singleValueOption("mode", 'm', "Mode to use for share generator. Available modes are:\n\t- 's256': Shamir via GF256\n\t- 's25519': Shamir via Ed25519 (Ristretto255)\n\t- 'f25519': Feldman via Ed25519 (Ristretto255)\n\t- 'p25519': Pedersen via Ed25519 (Ristretto255)"));

    try generate_cmd.addArg(Arg.singleValueOption("threshold", 't', "Minimum number of shares required to reconstruct the secret key (default: 2)"));
    try generate_cmd.addArg(Arg.singleValueOption("total", 'n', "Total number of shares to generate (default: 3)"));
    try generate_cmd.addArg(Arg.singleValueOption("secret", 's', "Secret key to generate shares for"));

    var reconstruct_cmd = app.createCommand("reconstruct", "Reconstruct a secret key given a number of shares (must meet the min. number of shares required to work)");
    try reconstruct_cmd.addArg(Arg.singleValueOption("mode", 'm', "Mode to use for share generator. Available modes are:\n\t- 's256': Shamir via GF256\n\t- 's25519': Shamir via Ed25519 (Ristretto255)\n\t- 'f25519': Feldman via Ed25519 (Ristretto255)\n\t- 'p25519': Pedersen via Ed25519 (Ristretto255)"));
    try reconstruct_cmd.addArg(Arg.multiValuesOption("shares", 's', "Share values to reconstruct secret key", 255));

    var verify_cmd = app.createCommand("verify", "Verify a given share using commitments that were generated along with the shares (only supported in mode 'f25519')");
    try verify_cmd.addArg(Arg.singleValueOption("mode", 'm', "Mode to use for share generator. Available modes are:\n\t- 's256': Shamir via GF256\n\t- 's25519': Shamir via Ed25519 (Ristretto255)\n\t- 'f25519': Feldman via Ed25519 (Ristretto255)\n\t- 'p25519': Pedersen via Ed25519 (Ristretto255)"));
    try verify_cmd.addArg(Arg.singleValueOption("share", 's', "Share to verify"));
    try verify_cmd.addArg(Arg.multiValuesOption("commitments", 'c', "Commitment values used to verify the given share", 255));

    try cli.addSubcommand(generate_cmd);
    try cli.addSubcommand(reconstruct_cmd);
    try cli.addSubcommand(verify_cmd);

    const matches = try app.parseProcess();

    // `Generate` subcommand setup
    if (matches.subcommandMatches("generate")) |gen_cmd_matches| {
        if (gen_cmd_matches.getSingleValue("secret") == null) {
            try stdout.print("Please enter the secret you'd like to generate shares for!", .{});
            try bw.flush();
            return;
        }

        const threshold = try std.fmt.parseInt(u8, gen_cmd_matches.getSingleValue("threshold") orelse "2", 10);
        const total = try std.fmt.parseInt(u8, gen_cmd_matches.getSingleValue("total") orelse "3", 10);
        const raw_secret = gen_cmd_matches.getSingleValue("secret").?;

        const raw_mode = gen_cmd_matches.getSingleValue("mode") orelse "s256";
        const mode = Mode.fromStr(raw_mode) catch |err| {
            const err_text = switch (err) {
                ModeError.InvalidMode => "Invalid mode. Please select 's256', 's25519', 'f25519' or 'p25519'.",
            };
            try stdout.print(err_text, .{});
            try bw.flush();
            return;
        };

        const algo = Algo.init(mode, allocator);
        switch (algo) {
            .shamir_gf256 => |shamir| {
                try stdout.print("secret (hex): ", .{});
                try print_hex(raw_secret, stdout_any, true);

                const generated = try shamir.generate(raw_secret, total, threshold);
                defer generated.deinit();

                try stdout.print("\nshares ({d}/{d} required):\n", .{ threshold, total });
                const shares = generated.shares;
                for (shares.items, 0..) |share, i| {
                    if (i > 0) {
                        try stdout.print("\n", .{});
                    }
                    const bytes = try share.toBytes(allocator);
                    defer bytes.deinit();
                    try print_hex(bytes.items, stdout_any, null);
                }
            },

            .shamir_ristretto => |shamir| {
                var secret: [32]u8 = undefined;
                Keccak256.hash(raw_secret, &secret, .{});
                try stdout.print("secret (hashed): ", .{});
                try print_hex(&secret, stdout_any, true);

                secret = Ristretto255.scalar.reduce(secret);
                try stdout.print("secret (hashed + reduced): ", .{});
                try print_hex(&secret, stdout_any, true);

                const generated = try shamir.generate(&secret, total, threshold);
                defer generated.deinit();

                try stdout.print("\nshares ({d}/{d} required):\n", .{ threshold, total });
                const shares = generated.shares;
                for (shares.items, 0..) |share, i| {
                    if (i > 0) {
                        try stdout.print("\n", .{});
                    }
                    const bytes = share.toBytes();
                    try print_hex(&bytes, stdout_any, null);
                }
            },

            .feldman_ristretto => |feldman| {
                var secret: [32]u8 = undefined;
                Keccak256.hash(raw_secret, &secret, .{});
                try stdout.print("secret (hashed): ", .{});
                try print_hex(&secret, stdout_any, true);

                secret = Ristretto255.scalar.reduce(secret);
                try stdout.print("secret (hashed + reduced): ", .{});
                try print_hex(&secret, stdout_any, true);

                const generated = try feldman.generate(&secret, total, threshold);
                defer generated.deinit();

                const shares = generated.shares;
                try stdout.print("\nshares ({d}/{d} required):\n", .{ threshold, total });
                for (shares.items, 0..) |share, i| {
                    if (i > 0) {
                        try stdout.print("\n", .{});
                    }
                    const bytes = share.toBytes();
                    try print_hex(&bytes, stdout_any, null);
                }

                try stdout.print("\n\ncommitments:\n", .{});
                for (generated.commitments.items, 0..) |coeff, i| {
                    if (i > 0) {
                        try stdout.print("\n", .{});
                    }
                    try print_hex(&coeff, stdout_any, null);
                }
            },

            .pedersen_ristretto => |pedersen| {
                var secret: [32]u8 = undefined;
                Keccak256.hash(raw_secret, &secret, .{});
                try stdout.print("secret (hashed): ", .{});
                try print_hex(&secret, stdout_any, true);

                secret = Ristretto255.scalar.reduce(secret);
                try stdout.print("secret (hashed + reduced): ", .{});
                try print_hex(&secret, stdout_any, true);

                const generated = try pedersen.generate(&secret, total, threshold);
                defer generated.deinit();

                const shares = generated.shares;
                try stdout.print("\nshares ({d}/{d} required):\n", .{ threshold, total });
                for (shares.items, 0..) |share, i| {
                    if (i > 0) {
                        try stdout.print("\n", .{});
                    }
                    const bytes = share.toBytes();
                    try print_hex(&bytes, stdout_any, null);
                }

                try stdout.print("\n\ncommitments:\n", .{});
                for (generated.commitments.items, 0..) |coeff, i| {
                    if (i > 0) {
                        try stdout.print("\n", .{});
                    }
                    try print_hex(&coeff, stdout_any, null);
                }
            },
        }

        try stdout.print("\n", .{});
        try bw.flush();
    }

    // `Reconstruct` subcommand setup
    if (matches.subcommandMatches("reconstruct")) |gen_cmd_matches| {
        if (gen_cmd_matches.getMultiValues("shares") == null) {
            try stdout.print("Please provide your share values", .{});
            try bw.flush();
            return;
        }
        const raw_shares = gen_cmd_matches.getMultiValues("shares").?;

        const raw_mode = gen_cmd_matches.getSingleValue("mode") orelse "s256";
        const mode = Mode.fromStr(raw_mode) catch |err| {
            const err_text = switch (err) {
                ModeError.InvalidMode => "Invalid mode. Please select 's256', 's25519', 'f25519' or 'p25519'.",
            };
            try stdout.print(err_text, .{});
            try bw.flush();
            return;
        };

        const algo = Algo.init(mode, allocator);
        switch (algo) {
            .shamir_gf256 => |shamir| {
                var shares = std.ArrayList(ShamirGF256.Share).init(allocator);
                defer shares.deinit();

                for (raw_shares) |raw_share| {
                    // Input is expected to be in 2-digit hex format
                    var buffer = std.ArrayList(u8).init(allocator);
                    defer buffer.deinit();
                    var i: usize = 0;
                    while (i < raw_share.len) : (i += 2) {
                        const raw_hex = raw_share[i .. i + 2];
                        const hex = try std.fmt.parseInt(u8, raw_hex, 16);
                        try buffer.append(hex);
                    }
                    const share = try ShamirGF256.Share.fromBytes(buffer.items, allocator);
                    try shares.append(share);
                }

                const secret = try shamir.reconstruct(shares.items);

                try stdout.print("secret (hex): ", .{});
                try print_hex(secret.items, stdout_any, true);
                try stdout.print("secret (text): {s}", .{secret.items});
            },

            // ```
            // .shamir_ristretto, .feldman_ristretto => |shamir| {
            // ```
            //
            // The above is NOT allowed since payloads are of different types.
            // @see https://ziglang.org/documentation/0.13.0/#switch
            .shamir_ristretto => |shamir| {
                var shares = std.ArrayList(ShamirRistretto.Share).init(allocator);
                defer shares.deinit();

                for (raw_shares) |raw_share| {
                    // Input is expected to be in 2-digit hex format
                    var buffer: [64]u8 = undefined;
                    var i: usize = 0;
                    while (i < raw_share.len) : (i += 2) {
                        const raw_hex = raw_share[i .. i + 2];
                        const hex = try std.fmt.parseInt(u8, raw_hex, 16);
                        buffer[i / 2] = hex;
                    }
                    const share = ShamirRistretto.Share.fromBytes(&buffer);
                    try shares.append(share);
                }

                const secret = try shamir.reconstruct(shares.items);

                try stdout.print("secret: ", .{});
                try print_hex(&secret, stdout_any, null);
            },

            .feldman_ristretto => |feldman| {
                var shares = std.ArrayList(FeldmanShare).init(allocator);
                defer shares.deinit();

                for (raw_shares) |raw_share| {
                    // Input is expected to be in 2-digit hex format
                    var buffer: [64]u8 = undefined;
                    var i: usize = 0;
                    while (i < raw_share.len) : (i += 2) {
                        const raw_hex = raw_share[i .. i + 2];
                        const hex = try std.fmt.parseInt(u8, raw_hex, 16);
                        buffer[i / 2] = hex;
                    }
                    const share = FeldmanShare.fromBytes(&buffer);
                    try shares.append(share);
                }

                const secret = try feldman.reconstruct(shares.items);

                try stdout.print("secret: ", .{});
                try print_hex(&secret, stdout_any, null);
            },

            .pedersen_ristretto => |pedersen| {
                var shares = std.ArrayList(PedersenShare).init(allocator);
                defer shares.deinit();

                for (raw_shares) |raw_share| {
                    // Input is expected to be in 2-digit hex format
                    var buffer: [96]u8 = undefined;
                    var i: usize = 0;
                    while (i < raw_share.len) : (i += 2) {
                        const raw_hex = raw_share[i .. i + 2];
                        const hex = try std.fmt.parseInt(u8, raw_hex, 16);
                        buffer[i / 2] = hex;
                    }
                    const share = PedersenShare.fromBytes(&buffer);
                    try shares.append(share);
                }

                const secret = try pedersen.reconstruct(shares.items);

                try stdout.print("secret: ", .{});
                try print_hex(&secret, stdout_any, null);
            },
        }

        try stdout.print("\n", .{});
        try bw.flush();
    }

    // `Verify` subcommand setup
    if (matches.subcommandMatches("verify")) |verify_cmd_matches| {
        if (verify_cmd_matches.getSingleValue("share") == null) {
            try stdout.print("Please include your share", .{});
            try bw.flush();
            return;
        }
        if (verify_cmd_matches.getMultiValues("commitments") == null) {
            try stdout.print("Please provide generated commitment values", .{});
            try bw.flush();
            return;
        }
        const raw_share = verify_cmd_matches.getSingleValue("share").?;

        const raw_mode = verify_cmd_matches.getSingleValue("mode") orelse "s256";
        const mode = Mode.fromStr(raw_mode) catch |err| {
            const err_text = switch (err) {
                ModeError.InvalidMode => "Invalid mode. Please select 's256', 's25519', 'f25519' or 'p25519'.",
            };
            try stdout.print(err_text, .{});
            try bw.flush();
            return;
        };

        const algo = Algo.init(mode, allocator);

        const raw_commitments = verify_cmd_matches.getMultiValues("commitments").?;
        var commitments = try std.ArrayList([32]u8).initCapacity(allocator, 2);
        defer commitments.deinit();

        for (raw_commitments) |raw_commitment| {
            // Input is expected to be in 2-digit hex format
            var commitment: [32]u8 = undefined;
            var j: usize = 0;
            while (j < raw_commitment.len) : (j += 2) {
                const raw_hex = raw_commitment[j .. j + 2];
                const hex = try std.fmt.parseInt(u8, raw_hex, 16);
                commitment[j / 2] = hex;
            }
            try commitments.append(commitment);
        }

        // Input is expected to be in 2-digit hex format
        // var buffer: [64]u8 = undefined;
        var buffer = try std.ArrayList(u8).initCapacity(allocator, 96);
        var i: usize = 0;
        while (i < raw_share.len) : (i += 2) {
            const raw_hex = raw_share[i .. i + 2];
            const hex = try std.fmt.parseInt(u8, raw_hex, 16);
            try buffer.append(hex);
        }

        switch (algo) {
            .shamir_ristretto, .shamir_gf256 => {},
            .feldman_ristretto => {
                const share = FeldmanShare.fromBytes(buffer.items);
                const verified = try FeldmanRistretto.verify(commitments.items, &share);
                try stdout.print("\nshare validity: {any}", .{verified});
            },
            .pedersen_ristretto => {
                const share = PedersenShare.fromBytes(buffer.items);
                const verified = try PedersenRistretto.verify(commitments.items, &share);
                try stdout.print("\nshare validity: {any}", .{verified});
            },
        }

        try bw.flush();
    }
}

fn print_hex(input: []const u8, writer: std.io.AnyWriter, append_newln: ?bool) !void {
    for (0..input.len) |i| {
        try writer.print("{X:0>2}", .{input[i]});
    }
    const newln = append_newln orelse false;
    if (newln) {
        try writer.print("\n", .{});
    }
}
