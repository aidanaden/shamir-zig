const std = @import("std");
const Allocator = std.mem.Allocator;
const Ristretto255 = std.crypto.ecc.Ristretto255;
const assert = std.debug.assert;

const CompressedScalar = std.crypto.ecc.Ristretto255.scalar.CompressedScalar;

/// Creates a pseudo-random set of coefficients for a polynomial.
///
/// Returned coefficients are always `degree + 1` in length since
/// the given secret (intercept) is stored as the first value
fn new_coefficients(intercept: CompressedScalar, degree: u8, allocator: Allocator) !std.ArrayList(CompressedScalar) {
    var coefficients = std.ArrayList(CompressedScalar).init(allocator);
    // The first byte is always the intercept
    try coefficients.append(intercept);
    for (0..degree) |_| {
        // degree is equal to t-1, where t is the threshold of required shares.
        // The coefficient at t-1 cannot equal 0.
        // const coeff_idx = i + 1;
        const rand_scalar = Ristretto255.scalar.random();
        try coefficients.append(rand_scalar);
    }
    return coefficients;
}

/// Creates a set of values from [1, 256).
/// Returns a psuedo-random shuffling of the set.
fn new_coordinates() ![255]CompressedScalar {
    var coordinates: [255]CompressedScalar = undefined;
    for (0..255) |i| {
        coordinates[i] = Ristretto255.scalar.random();
    }
    return coordinates;
}

const InterpolationError = error{SampleLengthMismatch};

/// Takes N sample points and returns the value at a given x using a lagrange interpolation.
///
/// @see `Definition` section of https://en.wikipedia.org/wiki/Lagrange_polynomial to best
/// understand the following code
fn interpolate_polynomial(x_samples: []CompressedScalar, y_samples: []CompressedScalar) InterpolationError!CompressedScalar {
    if (x_samples.len != y_samples.len) {
        return InterpolationError.SampleLengthMismatch;
    }

    const limit = x_samples.len;

    var result: CompressedScalar = Ristretto255.scalar.zero;

    // Calculate basis polynomials for jth share
    for (0..limit) |j| {
        var num = Ristretto255.scalar.zero;
        num[31] = 1;
        var denom: CompressedScalar = Ristretto255.scalar.zero;
        denom[31] = 1;

        for (0..limit) |k| {
            // Basis polynomial is calculated
            // with x-values of all other k-1 shares,
            // hence we ignore our own x-value
            if (j == k) {
                continue;
            }
            // Corresponds to `x - x(k)` but addition
            // and subtraction are equivalent in GF
            num = Ristretto255.scalar.mul(num, x_samples[k]);
            denom = Ristretto255.scalar.mul(denom, Ristretto255.scalar.sub(x_samples[k], x_samples[j]));
            // const num = gadd(x, x_samples[k]);
            // Corresponds to `x(j) - x(k)` but addition
            // and subtraction are equivalent in GF
            // const denom = Ristretto255.scalar.sub(x_samples[j], x_samples[k]);
            // const denom = gadd(x_samples[j], x_samples[k]);

            // const denom_expanded = Ristretto255.scalar.Scalar.fromBytes(denom);
            // const denom_inverted = Ristretto255.scalar.Scalar.invert(denom_expanded).toBytes();
            // const term = Ristretto255.scalar.mul(num, denom_inverted);
            // // const term = try gdiv(num, denom);
            // basis = Ristretto255.scalar.mul(basis, term);
            // // basis = gmult(basis, term);
        }

        std.debug.assert(!Ristretto255.scalar.Scalar.fromBytes(denom).isZero());

        const denom_expanded = Ristretto255.scalar.Scalar.fromBytes(denom);
        const denom_inverted = Ristretto255.scalar.Scalar.invert(denom_expanded).toBytes();
        result = Ristretto255.scalar.add(result, Ristretto255.scalar.mul(y_samples[j], Ristretto255.scalar.mul(num, denom_inverted)));

        // const group = Ristretto255.scalar.mul(y_samples[j], basis);
        // const group = gmult(y_samples[j], basis);
        // result = Ristretto255.scalar.add(result, group);
        // result = gadd(result, group);
    }

    return result;
}

const EvaluationError = error{InvalidZeroXValue};

/// Evaluates a polynomial with the given x using Horner's method.
/// @see https://en.wikipedia.org/wiki/Horner%27s_method
///
/// This is used to evaluate the y-value for each share's randomly
/// assigned unique x-value given
fn evaluate(coefficients: std.ArrayList(CompressedScalar), x: CompressedScalar, degree: u8) EvaluationError!CompressedScalar {
    if (Ristretto255.scalar.Scalar.fromBytes(x).isZero()) {
        return EvaluationError.InvalidZeroXValue;
    }
    // Initialise result with final coefficient
    // and calculate backwards recursively
    var result = coefficients.items[degree];
    var i = degree - 1;
    while (i >= 0) : (i -= 1) {
        const coeff = coefficients.items[i];
        result = Ristretto255.scalar.add(Ristretto255.scalar.mul(result, x), coeff);
        // result = gadd(gmult(result, x), coeff);
        if (i == 0) {
            break;
        }
    }
    return result;
}

pub const Share = struct {
    x: CompressedScalar,
    y: CompressedScalar,
};

const Polynomial = struct {
    coefficients: std.ArrayList(CompressedScalar),

    const Self = @This();

    fn init(allocator: Allocator) Self {
        return Polynomial{ .coefficients = std.ArrayList(u8).init(allocator) };
    }
    fn deinit(self: *Self) void {
        self.coefficients.deinit();
    }
};

const GeneratedShares = struct {
    shares: std.ArrayList(Share),
    polynomials: std.ArrayList(Polynomial),

    const Self = @This();

    fn deinit(self: *const Self) void {
        for (0..self.polynomials.items.len) |i| {
            self.polynomials.items[i].deinit();
        }
        self.polynomials.deinit();
        self.shares.deinit();
    }
};

/// Generate `shares` number of shares from given `secret` value, requiring `threshold` of them to reconstruct `secret`.
///
/// @param `secret` The secret value to split into shares.
/// @param `shares` The total number of shares to split `secret` into. Must be at least 2 and at most 255.
/// @param `threshold` The minimum number of shares required to reconstruct `secret`. Must be at least 2 and at most 255.
/// @param `allocator` Allocator to allocate arraylists on the heap
///
/// @returns A list of `shares` shares.
pub fn generate(
    secret: CompressedScalar,
    num_shares: u8,
    threshold: u8,
    allocator: Allocator,
) !GeneratedShares {
    // secret must be a non-empty
    assert(!Ristretto255.scalar.Scalar.fromBytes(secret).isZero());
    // num_shares must be a number in the range [2, 256)
    assert((num_shares >= 2) and (num_shares <= 255));
    // threshold must be a number in the range [2, 256)
    assert((threshold >= 2) and (threshold <= 255));
    // total number of shares must be greater than or equal to the required threshold
    assert(num_shares >= threshold);

    var shares = try std.ArrayList(Share).initCapacity(allocator, num_shares);
    const x_coordinates = try new_coordinates();

    // Generate unique x-value for each share
    for (0..num_shares) |k| {
        // var share = std.ArrayList(u8).init(allocator);
        const x_k = x_coordinates[k];
        const share = Share{ .x = x_k, .y = Ristretto255.scalar.zero };
        try shares.append(share);
    }

    // Generate y-values with the following
    //
    // 1. Generate curve via coefficients of length `degree` for secret byte i
    // 2. Calculate y-value of each share's x-value within generated curve
    // 3. Store y-value for secret byte i in share[i]
    //
    // This results in share's containing [y1, y2, y3, ... yN, x]
    // where N is total number of bytes in secret
    const degree = threshold - 1;
    var polynomials = std.ArrayList(Polynomial).init(allocator);
    const coeffs = try new_coefficients(secret, degree, allocator);
    const polynomial = Polynomial{ .coefficients = coeffs };

    for (0..num_shares) |k| {
        const x = x_coordinates[k];
        const y = try evaluate(coeffs, x, degree);
        shares.items[k].y = y;
    }
    try polynomials.append(polynomial);

    return GeneratedShares{ .shares = shares, .polynomials = polynomials };
}

const CombineError = error{InvalidDuplicateShareFound};

/// Reconstruct the secret from the given shares.
///
/// @param `shares` A list of shares to reconstruct the secret from. Must be at least 2 and at most 255.
/// @param `allocator` Allocator to allocate arraylists on the heap
///
/// @returns The reconstructed secret.
pub fn reconstruct(shares: []Share, allocator: Allocator) !CompressedScalar {
    // Shares must be an array with length in the range [2, 256)
    assert((shares.len >= 2) and (shares.len <= 255));
    // Shares must be a Uint8Array with at least 2 bytes and all shares must have the same byte length.

    const num_shares = shares.len;

    var x_samples = std.ArrayList(CompressedScalar).init(allocator);
    defer x_samples.deinit();
    var y_samples = std.ArrayList(CompressedScalar).init(allocator); // const xSamples = new Uint8Array(sharesLength);
    defer y_samples.deinit();
    for (num_shares) |_| {
        try y_samples.append(Ristretto255.scalar.zero);
    }

    var share_ids = std.ArrayList(CompressedScalar).init(allocator);
    defer share_ids.deinit();
    for (0..num_shares) |i| {
        const share = shares[i];
        const share_id = share.x;

        const is_duplicate = for (share_ids.items) |eid| {
            if (Ristretto255.scalar.Scalar.isZero(Ristretto255.scalar.Scalar.fromBytes(Ristretto255.scalar.sub(eid, share_id)))) {
                break true;
            }
        } else false;
        if (is_duplicate) {
            return CombineError.InvalidDuplicateShareFound;
        }

        try share_ids.append(share_id);
        try x_samples.append(share_id);
    }

    // Set y-value for each share
    for (0..num_shares) |j| {
        const y = shares[j].y;
        y_samples.items[j] = y;
    }

    // Interpolate the polynomial and compute the value
    // at y-intersect aka when x = 0 (secret)
    const secret = try interpolate_polynomial(x_samples.items, y_samples.items);

    return secret;
}

test "can split secret into multiple shares" {
    const raw_secret: CompressedScalar = Ristretto255.scalar.random();
    const secret = raw_secret;

    const generated = try generate(secret, 3, 2, std.testing.allocator);
    defer generated.deinit();
    const shares = generated.shares;
    assert(shares.items.len == 3);

    const first_share = shares.items[0];
    const second_share = shares.items[1];

    var thresholds = [2]Share{ first_share, second_share };
    const reconstructed = try reconstruct(&thresholds, std.testing.allocator);

    const isEqual = Ristretto255.scalar.Scalar.fromBytes(Ristretto255.scalar.sub(secret, reconstructed)).isZero();
    std.debug.print("\nsecret: {any}, reconstructed: {any}, isEqual: {any}", .{ secret, reconstructed, isEqual });
    assert(isEqual);

    std.debug.print("\nreconstructed (integers): ", .{});
    try std.json.stringify(&reconstructed, .{ .emit_strings_as_arrays = true }, std.io.getStdErr().writer());
    std.debug.print("\nreconstructed (string): ", .{});
    try std.json.stringify(&reconstructed, .{ .emit_strings_as_arrays = false }, std.io.getStdErr().writer());
}

test "can require all shares to reconstruct" {
    const raw_secret: CompressedScalar = Ristretto255.scalar.random();
    const secret = raw_secret;

    const generated = try generate(secret, 3, 2, std.testing.allocator);
    defer generated.deinit();
    const shares = generated.shares;
    assert(shares.items.len == 3);

    const first_share = shares.items[0];
    const second_share = shares.items[1];
    const third_share = shares.items[2];

    var thresholds = [_]Share{ first_share, second_share, third_share };
    const reconstructed = try reconstruct(&thresholds, std.testing.allocator);

    const isEqual = Ristretto255.scalar.Scalar.fromBytes(Ristretto255.scalar.sub(secret, reconstructed)).isZero();
    std.debug.print("\nsecret: {any}, reconstructed: {any}, isEqual: {any}", .{ secret, reconstructed, isEqual });
    assert(isEqual);

    std.debug.print("\nreconstructed (integers): ", .{});
    try std.json.stringify(&reconstructed, .{ .emit_strings_as_arrays = true }, std.io.getStdErr().writer());
    std.debug.print("\nreconstructed (string): ", .{});
    try std.json.stringify(&reconstructed, .{ .emit_strings_as_arrays = false }, std.io.getStdErr().writer());
}

test "can combine using any combination of shares that meets the given threshold" {
    const raw_secret: CompressedScalar = Ristretto255.scalar.random();
    const secret = raw_secret;

    const generated = try generate(secret, 5, 3, std.testing.allocator);
    defer generated.deinit();
    const shares = generated.shares;
    assert(shares.items.len == 5);

    for (shares.items, 0..) |_, i| {
        for (0..5) |j| {
            if (j == i) {
                continue;
            }
            for (0..5) |k| {
                if (k == i or k == j) {
                    continue;
                }
                var thresholds = [3]Share{ shares.items[i], shares.items[j], shares.items[k] };
                const reconstructed = try reconstruct(&thresholds, std.testing.allocator);
                const isEqual = Ristretto255.scalar.Scalar.fromBytes(Ristretto255.scalar.sub(secret, reconstructed)).isZero();
                assert(isEqual);
            }
        }
    }
}

test "can split secret into 255 shares" {
    const raw_secret: CompressedScalar = Ristretto255.scalar.random();
    const secret = raw_secret;

    const generated = try generate(secret, 255, 255, std.testing.allocator);
    defer generated.deinit();
    const shares = generated.shares;
    assert(shares.items.len == 255);

    const reconstructed = try reconstruct(shares.items, std.testing.allocator);

    const isEqual = Ristretto255.scalar.Scalar.fromBytes(Ristretto255.scalar.sub(secret, reconstructed)).isZero();
    std.debug.print("\nsecret: {any}, reconstructed: {any}, isEqual: {any}", .{ secret, reconstructed, isEqual });
    assert(isEqual);

    std.debug.print("\nreconstructed (integers): ", .{});
    try std.json.stringify(&reconstructed, .{ .emit_strings_as_arrays = true }, std.io.getStdErr().writer());
    std.debug.print("\nreconstructed (string): ", .{});
    try std.json.stringify(&reconstructed, .{ .emit_strings_as_arrays = false }, std.io.getStdErr().writer());
}
