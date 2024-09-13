const std = @import("std");
const Keccak256 = std.crypto.hash.sha3.Keccak256;
const Ristretto255 = std.crypto.ecc.Ristretto255;

const Shamir = @import("shamir.zig");
const ShamirRistretto = Shamir.ShamirRistretto;
const ShamirGF256 = Shamir.ShamirGF256;
const FeldmanRistretto = @import("feldman.zig").Feldman;

const yazap = @import("yazap");
const log = std.log;
const App = yazap.App;
const Arg = yazap.Arg;

fn print_hex(input: []const u8, writer: std.io.AnyWriter) !void {
    for (0..input.len) |i| {
        try writer.print("{X:0>2}", .{input[i]});
    }
}

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
    try generate_cmd.addArg(Arg.singleValueOption("mode", 'm', "Mode to use for share generator. Available modes are: '25519' and '256', standing for ED25519 and GF256 respectively."));
    try generate_cmd.addArg(Arg.singleValueOption("threshold", 't', "Minimum number of shares required to reconstruct the secret key"));
    try generate_cmd.addArg(Arg.singleValueOption("total", 'n', "Total number of shares to generate"));
    try generate_cmd.addArg(Arg.singleValueOption("secret", 's', "Secret key to generate shares for"));
    try generate_cmd.addArg(Arg.singleValueOption("verifiable", 'v', "Whether to generate verifiable shares (commitments will be broadcasted for share verification)"));

    var reconstruct_cmd = app.createCommand("reconstruct", "Reconstruct a secret key given a number of shares (must meet the min. number of shares required to work)");
    try reconstruct_cmd.addArg(Arg.singleValueOption("mode", 'm', "Mode to use for share generator. Available modes are: '25519' and '256', standing for ED25519 and GF256 respectively."));
    try reconstruct_cmd.addArg(Arg.multiValuesOption("shares", 's', "Share values to reconstruct secret key", 255));

    var verify_cmd = app.createCommand("verify", "Verify a given share using commitments that were generated along with the shares");
    try verify_cmd.addArg(Arg.singleValueOption("share", 's', "Share to verify"));
    try verify_cmd.addArg(Arg.multiValuesOption("commitments", 'c', "Commitment values used to verify the given share", 255));

    try cli.addSubcommand(generate_cmd);
    try cli.addSubcommand(reconstruct_cmd);
    try cli.addSubcommand(verify_cmd);

    const matches = try app.parseProcess();

    // `Generate` subcommand setup
    if (matches.subcommandMatches("generate")) |gen_cmd_matches| {
        if (gen_cmd_matches.getSingleValue("mode") == null) {
            try stdout.print("Please select a mode", .{});
            try bw.flush();
            return;
        }
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

        const mode = try std.fmt.parseInt(u32, gen_cmd_matches.getSingleValue("mode").?, 10);
        const threshold = try std.fmt.parseInt(u8, gen_cmd_matches.getSingleValue("threshold").?, 10);
        const total = try std.fmt.parseInt(u8, gen_cmd_matches.getSingleValue("total").?, 10);
        const raw_secret = gen_cmd_matches.getSingleValue("secret").?;
        const raw_verifiable = gen_cmd_matches.getSingleValue("verifiable");
        const verifiable: bool = if (raw_verifiable == null) false else true;

        if (mode != 25519 and mode != 256) {
            try stdout.print("Invalid mode. Please select either '25519' or '256'.", .{});
            try bw.flush();
            return;
        }

        if (mode == 25519) {
            var secret: [32]u8 = undefined;
            Keccak256.hash(raw_secret, &secret, .{});
            try stdout.print("hashed secret: ", .{});

            try print_hex(&secret, stdout_any);
            try stdout.print("\n", .{});
            secret = Ristretto255.scalar.reduce(secret);

            try stdout.print("hashed reduced secret: ", .{});
            try print_hex(&secret, stdout_any);

            if (verifiable) {
                const feldman = FeldmanRistretto.init(allocator);
                const generated = try feldman.generate(&secret, total, threshold);
                defer generated.deinit();
                const shares = generated.shares;

                try stdout.print("\nshares:\n", .{});
                for (shares.items, 0..) |share, i| {
                    if (i > 0) {
                        try stdout.print("\n", .{});
                    }
                    const bytes = share.toBytes();
                    try print_hex(&bytes, stdout_any);
                }

                try stdout.print("\ncommitments:\n", .{});
                for (generated.commitments.items, 0..) |coeff, i| {
                    if (i > 0) {
                        try stdout.print("\n", .{});
                    }
                    try print_hex(&coeff, stdout_any);
                }
            } else {
                const shamir = ShamirRistretto.init(allocator);
                const generated = try shamir.generate(&secret, total, threshold);
                defer generated.deinit();
                const shares = generated.shares;

                try stdout.print("\nshares:\n", .{});
                for (shares.items, 0..) |share, i| {
                    if (i > 0) {
                        try stdout.print("\n", .{});
                    }
                    const bytes = share.toBytes();
                    try print_hex(&bytes, stdout_any);
                }
            }
        }

        if (mode == 256) {
            const shamir = ShamirGF256.init(allocator);

            try stdout.print("raw secret: ", .{});
            try print_hex(raw_secret, stdout_any);
            try stdout.print("\n", .{});

            const generated = try shamir.generate(raw_secret, total, threshold);
            defer generated.deinit();
            const shares = generated.shares;
            for (shares.items, 0..) |share, i| {
                if (i > 0) {
                    try stdout.print("\n", .{});
                }
                const bytes = try share.toBytes(allocator);
                try print_hex(bytes.items, stdout_any);
                bytes.deinit();
            }
        }

        try bw.flush();
    }

    // `Reconstruct` subcommand setup
    if (matches.subcommandMatches("reconstruct")) |gen_cmd_matches| {
        if (gen_cmd_matches.getSingleValue("mode") == null) {
            try stdout.print("Please select a mode", .{});
            try bw.flush();
            return;
        }
        if (gen_cmd_matches.getMultiValues("shares") == null) {
            try stdout.print("Please provide your share values", .{});
            try bw.flush();
            return;
        }

        const mode = try std.fmt.parseInt(u32, gen_cmd_matches.getSingleValue("mode").?, 10);
        if (mode != 25519 and mode != 256) {
            try stdout.print("Invalid mode. Please select either '25519' or '256'.", .{});
            try bw.flush();
            return;
        }

        const raw_shares = gen_cmd_matches.getMultiValues("shares").?;

        if (mode == 25519) {
            const shamir = ShamirRistretto.init(allocator);
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
                const share = ShamirRistretto.Share.fromBytes(buffer);
                try shares.append(share);
            }

            const secret = try shamir.reconstruct(shares.items);

            try stdout.print("Regenerated secret: ", .{});
            try print_hex(&secret, stdout_any);
        }

        if (mode == 256) {
            const shamir = ShamirGF256.init(allocator);
            var shares = std.ArrayList(ShamirGF256.Share).init(allocator);
            defer shares.deinit();

            for (raw_shares) |raw_share| {
                // Input is expected to be in 2-digit hex format
                var buffer = std.ArrayList(u8).init(allocator);
                var i: usize = 0;
                while (i < raw_share.len) : (i += 2) {
                    const raw_hex = raw_share[i .. i + 2];
                    const hex = try std.fmt.parseInt(u8, raw_hex, 16);
                    try buffer.append(hex);
                }
                const share = try ShamirGF256.Share.fromBytes(buffer.items, allocator);
                try shares.append(share);
                buffer.deinit();
            }

            const secret = try shamir.reconstruct(shares.items);

            try stdout.print("Regenerated secret (hex): ", .{});
            try print_hex(secret.items, stdout_any);

            try stdout.print("\nRegenerated secret (text): ", .{});
            for (0..secret.items.len) |i| {
                try stdout.print("{c}", .{secret.items[i]});
            }
        }

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

        // Input is expected to be in 2-digit hex format
        var buffer: [64]u8 = undefined;
        var i: usize = 0;
        while (i < raw_share.len) : (i += 2) {
            const raw_hex = raw_share[i .. i + 2];
            const hex = try std.fmt.parseInt(u8, raw_hex, 16);
            buffer[i / 2] = hex;
        }
        const share = ShamirRistretto.Share.fromBytes(buffer);

        const raw_commitments = verify_cmd_matches.getMultiValues("commitments").?;
        var commitments = std.ArrayList([32]u8).init(allocator);
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

        const verified = try FeldmanRistretto.verify(commitments.items, &share);
        try stdout.print("\nShare validity check: {any}", .{verified});
        try bw.flush();
    }
}
