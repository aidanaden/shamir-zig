const std = @import("std");
const Allocator = std.mem.Allocator;

const Ristretto255 = std.crypto.ecc.Ristretto255;
const CompressedScalar = Ristretto255.scalar.CompressedScalar;
const Keccak256 = std.crypto.hash.sha3.Keccak256;

const Shamir = @import("shamir.zig");
const ShamirRistretto = Shamir.ShamirRistretto;

pub const GeneratedShares = struct {
    shares: std.ArrayList(ShamirRistretto.Share),
    commitments: std.ArrayList(CompressedScalar),

    const Self = @This();
    pub fn deinit(self: *const Self) void {
        self.shares.deinit();
        self.commitments.deinit();
    }
};

pub const Feldman = struct {
    shamir: ShamirRistretto,
    allocator: Allocator,

    const Self = @This();
    pub fn init(allocator: Allocator) Self {
        return Self{ .shamir = ShamirRistretto.init(allocator), .allocator = allocator };
    }

    pub fn generate(self: *const Self, secret: []const u8, num_shares: u8, threshold: u8) !GeneratedShares {
        const generated = try self.shamir.generate(secret, num_shares, threshold);
        defer generated.polynomial.deinit();
        var commitments = std.ArrayList([32]u8).init(self.allocator);
        for (generated.polynomial.coefficients.items) |coeff| {
            const commitment = try Ristretto255.basePoint.mul(coeff);
            try commitments.append(commitment.toBytes());
        }
        return GeneratedShares{ .shares = generated.shares, .commitments = commitments };
    }

    pub fn verify(commitments: []CompressedScalar, share: *const ShamirRistretto.Share) !bool {
        var i: ?CompressedScalar = null;
        var rhs = try Ristretto255.fromBytes(commitments[0]);
        for (commitments, 0..) |commitment_bytes, j| {
            if (j == 0) {
                continue;
            }
            if (i == null) {
                i = share.x;
            } else {
                i = Ristretto255.scalar.mul(i.?, share.x);
            }
            const commitment = try Ristretto255.fromBytes(commitment_bytes);
            const c_i = try Ristretto255.mul(commitment, i.?);
            rhs = Ristretto255.add(rhs, c_i);
        }
        const lhs = try Ristretto255.basePoint.mul(share.y);
        return Ristretto255.equivalent(lhs, rhs);
    }

    pub fn reconstruct(self: *const Self, shares: []ShamirRistretto.Share) !ShamirRistretto.Secret {
        return self.shamir.reconstruct(shares);
    }
};

const expect = std.testing.expect;

test "can split secret into multiple shares" {
    const word_secret = "secret";
    var secret: [32]u8 = undefined;
    Keccak256.hash(word_secret, &secret, .{});
    secret = Ristretto255.scalar.reduce(secret);

    const feldman = Feldman.init(std.testing.allocator);
    const generated = try feldman.generate(&secret, 3, 2);
    defer generated.deinit();
    const shares = generated.shares;
    try expect(shares.items.len == 3);

    for (shares.items) |share| {
        const verified = try Feldman.verify(generated.commitments.items, &share);
        try expect(verified);
    }

    const first_share = shares.items[0];
    const second_share = shares.items[1];

    var thresholds = [2]ShamirRistretto.Share{ first_share, second_share };
    const reconstructed = try feldman.reconstruct(&thresholds);

    const isEqual = Ristretto255.scalar.Scalar.fromBytes(Ristretto255.scalar.sub(secret, reconstructed)).isZero();
    try expect(isEqual);
}
