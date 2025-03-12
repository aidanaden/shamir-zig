const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Ristretto255 = std.crypto.ecc.Ristretto255;
const scalar = Ristretto255.scalar;
const CompressedScalar = scalar.CompressedScalar;
const Scalar = scalar.Scalar;

pub const one: CompressedScalar = [_]u8{0} ** 31 ++ [_]u8{1};

fn new_coordinates(num_coords: u8) [255]CompressedScalar {
    var coordinates: [255]CompressedScalar = undefined;
    for (0..num_coords) |i| {
        coordinates[i] = scalar.random();
    }
    return coordinates;
}

pub const Polynomial = struct {
    coefficients: std.ArrayList(CompressedScalar),
    degree: u8,

    const Self = @This();
    pub fn init(intercept: CompressedScalar, degree: u8, allocator: Allocator) !Self {
        var coefficients = std.ArrayList(CompressedScalar).init(allocator);
        // The first byte is always the intercept
        try coefficients.append(intercept);
        // degree is equal to t-1, where t is the
        // threshold of required shares.
        for (0..degree) |_| {
            const rand_scalar = scalar.random();
            try coefficients.append(rand_scalar);
        }
        return Self{ .coefficients = coefficients, .degree = degree };
    }

    const EvaluationError = error{InvalidZeroXValue};

    /// Evaluates a polynomial with the given x using Horner's method.
    /// @see https://en.wikipedia.org/wiki/Horner%27s_method
    ///
    /// This is used to evaluate the y-value for each share's randomly
    /// assigned unique x-value given
    pub fn evaluate(self: *const Self, x: CompressedScalar) EvaluationError!CompressedScalar {
        if (Scalar.fromBytes(x).isZero()) {
            return EvaluationError.InvalidZeroXValue;
        }
        // Initialise result with final coefficient
        // and calculate backwards recursively
        var result = self.coefficients.items[self.degree];
        var i = self.degree - 1;
        while (i >= 0) : (i -= 1) {
            const coeff = self.coefficients.items[i];
            result = scalar.add(scalar.mul(result, x), coeff);
            if (i == 0) {
                break;
            }
        }
        return result;
    }

    pub fn deinit(self: *const Self) void {
        self.coefficients.deinit();
    }
};

pub fn Share(comptime num_y: u8) type {
    comptime assert(num_y > 0);
    const yBytes = num_y * 32;
    return struct {
        x: CompressedScalar,
        ys: [yBytes]u8,

        const Self = @This();
        const OutputBytes = 32 + yBytes;
        pub fn toBytes(self: *const Self) [OutputBytes]u8 {
            return @bitCast(self.x ++ self.ys);
        }
        pub fn fromBytes(bytes: []u8) Self {
            assert(bytes.len == OutputBytes);
            const x = bytes[0..32].*;
            const ys: [yBytes]u8 = bytes[32..][0..yBytes].*;
            return Self{ .x = x, .ys = ys };
        }
    };
}

pub fn GeneratedShares(comptime num_y: u8) type {
    comptime assert(num_y > 0);
    return struct {
        shares: std.ArrayList(Share(num_y)),
        polynomials: [num_y]Polynomial,

        const Self = @This();
        pub fn deinit(self: *const Self) void {
            self.shares.deinit();
            for (self.polynomials) |poly| {
                poly.deinit();
            }
        }
    };
}

/// Generate `shares` number of shares from given `secret` value, requiring `threshold` of them to reconstruct `secret`.
///
/// @param `secret` The secret value to split into shares.
/// @param `shares` The total number of shares to split `secret` into. Must be at least 2 and at most 255.
/// @param `threshold` The minimum number of shares required to reconstruct `secret`. Must be at least 2 and at most 255.
/// @param `num_ys` The minimum number of shares required to reconstruct `secret`. Must be at least 2 and at most 255.
/// @param `allocator` Allocator to allocate arraylists on the heap
///
/// @returns A list of `shares` shares.
pub fn generate(secret_slice: []const u8, num_shares: u8, threshold: u8, comptime num_ys: u8, allocator: Allocator) !GeneratedShares(num_ys) {
    comptime assert(num_ys > 0);

    assert(secret_slice.len == 32);
    var secret: CompressedScalar = secret_slice[0..32].*;
    secret = scalar.reduce(secret);

    // secret must be a non-empty
    assert(!Scalar.fromBytes(secret).isZero());
    // num_shares must be a number in the range [2, 256)
    assert((num_shares >= 2) and (num_shares <= 255));
    // threshold must be a number in the range [2, 256)
    assert((threshold >= 2) and (threshold <= 255));
    // total number of shares must be greater than or equal to the required threshold
    assert(num_shares >= threshold);

    const GeneratedShare = Share(num_ys);

    var shares = try std.ArrayList(GeneratedShare).initCapacity(allocator, num_shares);
    const x_coordinates = new_coordinates(num_shares);

    // Generate y-values with the following
    //
    // 1. Generate curve via coefficients of length `degree`
    // 2. Calculate y-value of each share's x-value within generated curve
    // 3. Store y-value
    const degree = threshold - 1;

    var polynomials: [num_ys]Polynomial = undefined;
    for (0..num_ys) |i| {
        const polynomial = try Polynomial.init(secret, degree, allocator);
        polynomials[i] = polynomial;
    }

    for (0..num_shares) |k| {
        const x = x_coordinates[k];

        const yBytes = comptime num_ys * 32;
        var ys: [yBytes]u8 = undefined;

        // `inline` is required to fix comptime type check.
        //
        // Without `inline`, compiler cannot determine how
        // large `ys` is (it will assume `yBytes` = 32)
        inline for (0..num_ys) |i| {
            const poly_y = try polynomials[i].evaluate(x);
            if (i == 0) {
                std.mem.copyForwards(u8, &ys, &poly_y);
            } else {
                const ys_slice = ys[i * 32 ..];
                std.mem.copyForwards(u8, ys_slice, &poly_y);
            }
        }
        const share = GeneratedShare{ .x = x, .ys = ys };
        try shares.append(share);
    }

    return GeneratedShares(num_ys){ .shares = shares, .polynomials = polynomials };
}

const CombineError = error{InvalidDuplicateShareFound};

/// Reconstruct the secret from the given shares.
///
/// @param `shares` A list of shares to reconstruct the secret from. Must be at least 2 and at most 255.
/// @param `allocator` Allocator to allocate arraylists on the heap
///
/// @returns The reconstructed secret.
pub fn reconstruct(comptime num_ys: u8, shares: []Share(num_ys), allocator: Allocator) !CompressedScalar {
    // Shares must be an array with length in the range [2, 255)
    assert((shares.len >= 2) and (shares.len <= 255));

    const num_shares = shares.len;

    var x_samples = try std.ArrayList(CompressedScalar).initCapacity(allocator, num_shares);
    defer x_samples.deinit();
    var y_samples = try std.ArrayList(CompressedScalar).initCapacity(allocator, num_shares); // const xSamples = new Uint8Array(sharesLength);
    defer y_samples.deinit();
    for (0..num_shares) |_| {
        try y_samples.append(scalar.zero);
    }

    for (0..num_shares) |i| {
        const share = shares[i];
        const share_id = share.x;

        // Filter for duplicate x-values, all x-values are
        // expected to be unique
        const is_duplicate = for (x_samples.items) |eid| {
            if (Scalar.isZero(Scalar.fromBytes(scalar.sub(eid, share_id)))) {
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
        // secret y-value is assumed to be the first value
        const y: CompressedScalar = shares[j].ys[0..32].*;
        y_samples.items[j] = y;
    }

    // Interpolate the polynomial and compute the value
    // at y-intersect aka when x = 0 (secret)
    const secret = try interpolate_polynomial(x_samples.items, y_samples.items);
    return secret;
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
    var result: CompressedScalar = scalar.zero;
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
            num = scalar.mul(num, x_samples[k]);
            denom = scalar.mul(denom, scalar.sub(x_samples[k], x_samples[j]));
            // Corresponds to `x(j) - x(k)` but addition
            // and subtraction are equivalent in GF
        }

        std.debug.assert(!Scalar.fromBytes(denom).isZero());

        const denom_expanded = Scalar.fromBytes(denom);
        const denom_inverted = Scalar.invert(denom_expanded).toBytes();
        result = scalar.add(result, scalar.mul(y_samples[j], scalar.mul(num, denom_inverted)));
    }

    return result;
}
