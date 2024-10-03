const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

const Ristretto255 = std.crypto.ecc.Ristretto255;
const CompressedScalar = Ristretto255.scalar.CompressedScalar;
const Keccak256 = std.crypto.hash.sha3.Keccak256;

const shamir = @import("shamir.zig");
const ShamirRistretto = shamir.ShamirRistretto;
const PedersenRistretto = ShamirRistretto(2);

pub const ristretto255 = @import("ristretto255.zig");

pub const GeneratedShares = struct {
    shares: std.ArrayList(PedersenRistretto.Share),
    commitments: std.ArrayList(CompressedScalar),

    const Self = @This();
    pub fn deinit(self: *const Self) void {
        self.shares.deinit();
        self.commitments.deinit();
    }
};

pub const Share = PedersenRistretto.Share;

pub const Pedersen = struct {
    shamir: PedersenRistretto,
    allocator: Allocator,

    const Self = @This();
    pub fn init(allocator: Allocator) Self {
        return Self{ .shamir = PedersenRistretto.init(allocator), .allocator = allocator };
    }

    pub fn generate(self: *const Self, secret: []const u8, num_shares: u8, threshold: u8) !GeneratedShares {
        const secret_shares = try self.shamir.generate(secret, num_shares, threshold);
        defer secret_shares.deinit();

        var commitments = std.ArrayList([32]u8).init(self.allocator);
        assert(secret_shares.polynomials[0].coefficients.items.len == secret_shares.polynomials[1].coefficients.items.len);

        const num_coeffs = secret_shares.polynomials[0].coefficients.items.len;
        for (0..num_coeffs) |i| {
            var commitment: ?Ristretto255 = null;

            for (secret_shares.polynomials) |poly| {
                const coeff = poly.coefficients.items[i];

                const coeff_commitment = try Ristretto255.basePoint.mul(coeff);
                if (commitment == null) {
                    commitment = coeff_commitment;
                } else {
                    commitment = Ristretto255.add(commitment.?, coeff_commitment);
                }
            }

            try commitments.append(commitment.?.toBytes());
        }

        var shares = try std.ArrayList(PedersenRistretto.Share).initCapacity(self.allocator, num_shares);
        for (secret_shares.shares.items) |share| {
            // const share = Share{ .shares = secret_share, .blinder_y = blinder_share.y };
            try shares.append(share);
        }

        return GeneratedShares{ .shares = shares, .commitments = commitments };
    }

    pub fn verify(commitments: []CompressedScalar, share: *const PedersenRistretto.Share) !bool {
        assert(commitments.len > 0);

        var i: ?CompressedScalar = null;
        var rhs = try Ristretto255.fromBytes(commitments[0]);
        for (commitments, 0..) |commitment_bytes, j| {
            if (j == 0) {
                continue;
            }
            i = if (i == null) share.x else Ristretto255.scalar.mul(i.?, share.x);
            const commitment = try Ristretto255.fromBytes(commitment_bytes);
            const c_i = try Ristretto255.mul(commitment, i.?);
            rhs = Ristretto255.add(rhs, c_i);
        }

        var lhs: ?Ristretto255 = null;
        for (0..2) |j| {
            const start_idx: usize = j * 32;
            const poly_y = share.ys[start_idx..][0..32];
            const lhs_i = try Ristretto255.basePoint.mul(poly_y.*);
            lhs = if (lhs == null) lhs_i else Ristretto255.add(lhs.?, lhs_i);
        }
        return Ristretto255.equivalent(lhs.?, rhs);
    }

    pub fn reconstruct(self: *const Self, shares: []PedersenRistretto.Share) !PedersenRistretto.Secret {
        return self.shamir.reconstruct(shares);
    }
};

const expect = std.testing.expect;

test "pedersen: can split secret into multiple shares" {
    const word_secret = "secret";
    var secret: [32]u8 = undefined;
    Keccak256.hash(word_secret, &secret, .{});
    secret = Ristretto255.scalar.reduce(secret);

    const pedersen = Pedersen.init(std.testing.allocator);
    const generated = try pedersen.generate(&secret, 3, 2);
    defer generated.deinit();
    const shares = generated.shares;
    try expect(shares.items.len == 3);

    for (shares.items) |share| {
        const verified = try Pedersen.verify(generated.commitments.items, &share);
        try expect(verified);
    }

    const first_share = shares.items[0];
    const second_share = shares.items[1];

    var thresholds = [2]PedersenRistretto.Share{ first_share, second_share };
    const reconstructed = try pedersen.reconstruct(&thresholds);

    const isEqual = Ristretto255.scalar.Scalar.fromBytes(Ristretto255.scalar.sub(secret, reconstructed)).isZero();
    std.debug.print("\npedersen verification is equal: {}", .{isEqual});
    try expect(isEqual);
}
