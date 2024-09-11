const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const Ristretto255 = std.crypto.ecc.Ristretto255;
const Keccak256 = std.crypto.hash.sha3.Keccak256;
const CompressedScalar = std.crypto.ecc.Ristretto255.scalar.CompressedScalar;

pub const gf256 = @import("gf256.zig");
pub const ristretto255 = @import("ristretto255.zig");

pub fn Shamir(comptime T: type) type {
    return struct {
        const Self = @This();

        allocator: Allocator,
        pub fn init(allocator: Allocator) Self {
            return Self{ .allocator = allocator };
        }

        pub const Secret = switch (T) {
            u8 => std.ArrayList(u8),
            CompressedScalar => CompressedScalar,
            else => unreachable,
        };

        pub const Share = switch (T) {
            u8 => gf256.Share,
            CompressedScalar => ristretto255.Share,
            else => unreachable,
        };

        pub const GeneratedShares = switch (T) {
            u8 => gf256.GeneratedShares,
            CompressedScalar => ristretto255.GeneratedShares,
            else => unreachable,
        };

        pub fn generate(self: *const Self, secret: []u8, num_shares: u8, threshold: u8) !GeneratedShares {
            const generated = switch (T) {
                u8 => try gf256.generate(secret, num_shares, threshold, self.allocator),
                CompressedScalar => try ristretto255.generate(secret, num_shares, threshold, self.allocator),
                else => unreachable,
            };
            return generated;
        }

        pub fn reconstruct(self: *const Self, shares: []Share) !Secret {
            const secret = switch (T) {
                u8 => try gf256.reconstruct(shares, self.allocator),
                CompressedScalar => try ristretto255.reconstruct(shares, self.allocator),
                else => unreachable,
            };
            return secret;
        }
    };
}

pub const ShamirRistretto = Shamir(CompressedScalar);
pub const ShamirRF256 = Shamir(u8);

const shamir_RF256 = ShamirRF256.init(std.testing.allocator);
const shamir_Ristretto255 = ShamirRistretto.init(std.testing.allocator);

const expect = std.testing.expect;

test "rf256: can split secret into multiple shares" {
    var secret = std.ArrayList(u8).init(std.testing.allocator);
    defer secret.deinit();
    try secret.appendSlice(&[_]u8{ 0x73, 0x65, 0x63, 0x72, 0x65, 0x74 });
    assert(secret.items.len == 6);

    const generated = try shamir_RF256.generate(secret.items, 3, 2);
    defer generated.deinit();
    const shares = generated.shares;
    assert(shares.items.len == 3);

    const first_share = shares.items[0];
    assert(first_share.y.items.len == secret.items.len);
    const second_share = shares.items[1];

    var thresholds = [2]ShamirRF256.Share{ first_share, second_share };
    const reconstructed = try shamir_RF256.reconstruct(&thresholds);
    defer reconstructed.deinit();

    assert(std.mem.eql(u8, secret.items, reconstructed.items));

    std.debug.print("\nreconstructed (integers): ", .{});
    try std.json.stringify(&reconstructed.items, .{ .emit_strings_as_arrays = true }, std.io.getStdErr().writer());
    std.debug.print("\nreconstructed (string): ", .{});
    try std.json.stringify(&reconstructed.items, .{ .emit_strings_as_arrays = false }, std.io.getStdErr().writer());
}

test "rf256: can split a 1 byte secret" {
    var secret = std.ArrayList(u8).init(std.testing.allocator);
    defer secret.deinit();
    try secret.appendSlice(&[_]u8{0x33});
    assert(secret.items.len == 1);

    const generated = try shamir_RF256.generate(secret.items, 3, 2);
    defer generated.deinit();
    const shares = generated.shares;
    assert(shares.items.len == 3);

    const first_share = shares.items[0];
    assert(first_share.y.items.len == secret.items.len);
    const third_share = shares.items[2];

    var thresholds = [2]ShamirRF256.Share{ first_share, third_share };
    const reconstructed = try shamir_RF256.reconstruct(&thresholds);
    defer reconstructed.deinit();

    assert(std.mem.eql(u8, secret.items, reconstructed.items));
}

test "rf256: can require all shares to reconstruct" {
    var secret = std.ArrayList(u8).init(std.testing.allocator);
    defer secret.deinit();
    try secret.appendSlice(&[_]u8{ 0x73, 0x65, 0x63, 0x72, 0x65, 0x74 });
    assert(secret.items.len == 6);

    const generated = try shamir_RF256.generate(secret.items, 3, 3);
    defer generated.deinit();
    const shares = generated.shares;
    assert(shares.items.len == 3);

    const first_share = shares.items[0];
    assert(first_share.y.items.len == secret.items.len);

    const second_share = shares.items[1];
    assert(second_share.y.items.len == secret.items.len);

    const third_share = shares.items[2];
    assert(third_share.y.items.len == secret.items.len);

    var thresholds = [3]ShamirRF256.Share{ first_share, second_share, third_share };
    const reconstructed = try shamir_RF256.reconstruct(&thresholds);
    defer reconstructed.deinit();

    assert(std.mem.eql(u8, secret.items, reconstructed.items));
}

test "rf256: can combine using any combination of shares that meets the given threshold" {
    var secret = std.ArrayList(u8).init(std.testing.allocator);
    defer secret.deinit();
    try secret.appendSlice(&[_]u8{ 0x73, 0x65, 0x63, 0x72, 0x65, 0x74 });
    assert(secret.items.len == 6);

    const generated = try shamir_RF256.generate(secret.items, 5, 3);
    defer generated.deinit();
    const shares = generated.shares;
    assert(shares.items.len == 5);

    for (shares.items, 0..) |s, i| {
        assert(s.y.items.len == secret.items.len);

        for (0..5) |j| {
            if (j == i) {
                continue;
            }

            for (0..5) |k| {
                if (k == i or k == j) {
                    continue;
                }

                var thresholds = [3]ShamirRF256.Share{ shares.items[i], shares.items[j], shares.items[k] };
                const reconstructed = try shamir_RF256.reconstruct(&thresholds);

                assert(std.mem.eql(u8, secret.items, reconstructed.items));
                reconstructed.deinit();
            }
        }
    }
}

test "rf256: can split secret into 255 shares" {
    var secret = std.ArrayList(u8).init(std.testing.allocator);
    defer secret.deinit();
    try secret.appendSlice(&[_]u8{ 0x73, 0x65, 0x63, 0x72, 0x65, 0x74 });
    assert(secret.items.len == 6);

    const generated = try shamir_RF256.generate(secret.items, 255, 255);
    defer generated.deinit();
    var shares = generated.shares;
    assert(shares.items.len == 255);
    const shares_arr = try shares.toOwnedSlice();

    const reconstructed = try shamir_RF256.reconstruct(shares_arr);
    defer reconstructed.deinit();

    assert(std.mem.eql(u8, secret.items, reconstructed.items));
}

test "ristretto255: can split secret into multiple shares" {
    const word_secret = "secret";
    var secret: [32]u8 = undefined;
    Keccak256.hash(word_secret, &secret, .{});
    secret = Ristretto255.scalar.reduce(secret);

    const generated = try shamir_Ristretto255.generate(&secret, 3, 2);
    defer generated.deinit();
    const shares = generated.shares;
    try expect(shares.items.len == 3);

    const first_share = shares.items[0];
    const second_share = shares.items[1];

    var thresholds = [2]ShamirRistretto.Share{ first_share, second_share };
    const reconstructed = try shamir_Ristretto255.reconstruct(&thresholds);

    const isEqual = Ristretto255.scalar.Scalar.fromBytes(Ristretto255.scalar.sub(secret, reconstructed)).isZero();
    try expect(isEqual);
}

test "ristretto255: can require all shares to reconstruct" {
    const word_secret = "secret";
    var secret: [32]u8 = undefined;
    Keccak256.hash(word_secret, &secret, .{});
    secret = Ristretto255.scalar.reduce(secret);

    const generated = try shamir_Ristretto255.generate(&secret, 3, 2);
    defer generated.deinit();
    const shares = generated.shares;
    try expect(shares.items.len == 3);

    const first_share = shares.items[0];
    const second_share = shares.items[1];
    const third_share = shares.items[2];

    var thresholds = [_]ShamirRistretto.Share{ first_share, second_share, third_share };
    const reconstructed = try shamir_Ristretto255.reconstruct(&thresholds);

    const isEqual = Ristretto255.scalar.Scalar.fromBytes(Ristretto255.scalar.sub(secret, reconstructed)).isZero();
    try expect(isEqual);
}

test "ristretto255: can combine using any combination of shares that meets the given threshold" {
    const word_secret = "secret";
    var secret: [32]u8 = undefined;
    Keccak256.hash(word_secret, &secret, .{});
    secret = Ristretto255.scalar.reduce(secret);

    const generated = try shamir_Ristretto255.generate(&secret, 5, 3);
    defer generated.deinit();
    const shares = generated.shares;
    try expect(shares.items.len == 5);

    for (shares.items, 0..) |_, i| {
        for (0..5) |j| {
            if (j == i) {
                continue;
            }
            for (0..5) |k| {
                if (k == i or k == j) {
                    continue;
                }
                var thresholds = [3]ShamirRistretto.Share{ shares.items[i], shares.items[j], shares.items[k] };
                const reconstructed = try shamir_Ristretto255.reconstruct(&thresholds);
                const isEqual = Ristretto255.scalar.Scalar.fromBytes(Ristretto255.scalar.sub(secret, reconstructed)).isZero();
                try expect(isEqual);
            }
        }
    }
}

test "ristretto255: can split secret into 255 shares" {
    const word_secret = "secret";
    var secret: [32]u8 = undefined;
    Keccak256.hash(word_secret, &secret, .{});
    secret = Ristretto255.scalar.reduce(secret);

    const generated = try shamir_Ristretto255.generate(&secret, 255, 255);
    defer generated.deinit();
    const shares = generated.shares;
    try expect(shares.items.len == 255);

    const reconstructed = try shamir_Ristretto255.reconstruct(shares.items);

    const isEqual = Ristretto255.scalar.Scalar.fromBytes(Ristretto255.scalar.sub(secret, reconstructed)).isZero();
    try expect(isEqual);
}
