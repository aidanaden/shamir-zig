const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Ristretto255 = std.crypto.ecc.Ristretto255;
const CompressedScalar = Ristretto255.scalar.CompressedScalar;

pub const one: CompressedScalar = [_]u8{0} ** 31 ++ [_]u8{1};

fn new_coordinates() [255]CompressedScalar {
    var coordinates: [255]CompressedScalar = undefined;
    for (0..255) |i| {
        coordinates[i] = Ristretto255.scalar.random();
    }
    return coordinates;
}

fn new_coefficients(intercept: CompressedScalar, degree: u8, allocator: Allocator) !std.ArrayList(CompressedScalar) {
    var coefficients = std.ArrayList(CompressedScalar).init(allocator);
    // The first byte is always the intercept
    try coefficients.append(intercept);
    // degree is equal to t-1, where t is the
    // threshold of required shares.
    for (0..degree) |_| {
        const rand_scalar = Ristretto255.scalar.random();
        try coefficients.append(rand_scalar);
    }
    return coefficients;
}

pub const Share = struct {
    x: CompressedScalar,
    y: CompressedScalar,

    const Self = @This();
    pub fn toBytes(self: *const Self) [64]u8 {
        return self.x ++ self.y;
    }
    pub fn fromBytes(bytes: [64]u8) Self {
        const x = bytes[0..32].*;
        const y = bytes[32..].*;
        return Self{ .x = x, .y = y };
    }
};

pub const GeneratedShares = struct {
    shares: std.ArrayList(Share),
    coeffs: std.ArrayList(CompressedScalar),

    const Self = @This();
    pub fn deinit(self: *const Self) void {
        self.coeffs.deinit();
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
pub fn generate(secret_slice: []u8, num_shares: u8, threshold: u8, allocator: Allocator) !GeneratedShares {
    const secret: CompressedScalar = secret_slice[0..32].*;

    // secret must be a non-empty
    assert(!Ristretto255.scalar.Scalar.fromBytes(secret).isZero());
    // num_shares must be a number in the range [2, 256)
    assert((num_shares >= 2) and (num_shares <= 255));
    // threshold must be a number in the range [2, 256)
    assert((threshold >= 2) and (threshold <= 255));
    // total number of shares must be greater than or equal to the required threshold
    assert(num_shares >= threshold);

    var shares = try std.ArrayList(Share).initCapacity(allocator, num_shares);
    const x_coordinates = new_coordinates();

    // Generate y-values with the following
    //
    // 1. Generate curve via coefficients of length `degree`
    // 2. Calculate y-value of each share's x-value within generated curve
    // 3. Store y-value
    const degree = threshold - 1;
    const coeffs = try new_coefficients(secret, degree, allocator);

    for (0..num_shares) |k| {
        const x = x_coordinates[k];
        const y = try evaluate(coeffs, x, degree);
        const share = Share{ .x = x, .y = y };
        try shares.append(share);
    }

    return GeneratedShares{ .shares = shares, .coeffs = coeffs };
}

const CombineError = error{InvalidDuplicateShareFound};

/// Reconstruct the secret from the given shares.
///
/// @param `shares` A list of shares to reconstruct the secret from. Must be at least 2 and at most 255.
/// @param `allocator` Allocator to allocate arraylists on the heap
///
/// @returns The reconstructed secret.
pub fn reconstruct(shares: []Share, allocator: Allocator) !CompressedScalar {
    // Shares must be an array with length in the range [2, 255)
    assert((shares.len >= 2) and (shares.len <= 255));

    const num_shares = shares.len;

    var x_samples = try std.ArrayList(CompressedScalar).initCapacity(allocator, num_shares);
    defer x_samples.deinit();
    var y_samples = try std.ArrayList(CompressedScalar).initCapacity(allocator, num_shares); // const xSamples = new Uint8Array(sharesLength);
    defer y_samples.deinit();
    for (num_shares) |_| {
        try y_samples.append(Ristretto255.scalar.zero);
    }

    for (0..num_shares) |i| {
        const share = shares[i];
        const share_id = share.x;

        // Filter for duplicate x-values, all
        // x-values are expected to be unique
        const is_duplicate = for (x_samples.items) |eid| {
            if (Ristretto255.scalar.Scalar.isZero(Ristretto255.scalar.Scalar.fromBytes(Ristretto255.scalar.sub(eid, share_id)))) {
                break true;
            }
        } else false;
        if (is_duplicate) {
            return CombineError.InvalidDuplicateShareFound;
        }

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
        if (i == 0) {
            break;
        }
    }
    return result;
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
        var num = one;
        var denom = one;
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
            // Corresponds to `x(j) - x(k)` but addition
            // and subtraction are equivalent in GF
        }

        std.debug.assert(!Ristretto255.scalar.Scalar.fromBytes(denom).isZero());

        const denom_expanded = Ristretto255.scalar.Scalar.fromBytes(denom);
        const denom_inverted = Ristretto255.scalar.Scalar.invert(denom_expanded).toBytes();
        result = Ristretto255.scalar.add(result, Ristretto255.scalar.mul(y_samples[j], Ristretto255.scalar.mul(num, denom_inverted)));
    }

    return result;
}
