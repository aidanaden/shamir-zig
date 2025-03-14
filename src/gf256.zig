const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

/// The Polynomial used is: x⁸ + x⁴ + x³ + x + 1 (used to calculate divisions: A . B mod <Polynomial>)
///
/// Lookup tables pulled from:
///
///     * https://github.com/hashicorp/vault/blob/9d46671659cbfe7bbd3e78d1073dfb22936a4437/shamir/tables.go
///     * http://www.samiam.org/galois.html
///
/// 0xe5 (229) is used as the generator.
/// Provides log(X)/log(g) at each index X.
const LOG_TABLE = [256]u8{
    0x00, 0xff, 0xc8, 0x08, 0x91, 0x10, 0xd0, 0x36, 0x5a, 0x3e, 0xd8, 0x43, 0x99, 0x77, 0xfe, 0x18,
    0x23, 0x20, 0x07, 0x70, 0xa1, 0x6c, 0x0c, 0x7f, 0x62, 0x8b, 0x40, 0x46, 0xc7, 0x4b, 0xe0, 0x0e,
    0xeb, 0x16, 0xe8, 0xad, 0xcf, 0xcd, 0x39, 0x53, 0x6a, 0x27, 0x35, 0x93, 0xd4, 0x4e, 0x48, 0xc3,
    0x2b, 0x79, 0x54, 0x28, 0x09, 0x78, 0x0f, 0x21, 0x90, 0x87, 0x14, 0x2a, 0xa9, 0x9c, 0xd6, 0x74,
    0xb4, 0x7c, 0xde, 0xed, 0xb1, 0x86, 0x76, 0xa4, 0x98, 0xe2, 0x96, 0x8f, 0x02, 0x32, 0x1c, 0xc1,
    0x33, 0xee, 0xef, 0x81, 0xfd, 0x30, 0x5c, 0x13, 0x9d, 0x29, 0x17, 0xc4, 0x11, 0x44, 0x8c, 0x80,
    0xf3, 0x73, 0x42, 0x1e, 0x1d, 0xb5, 0xf0, 0x12, 0xd1, 0x5b, 0x41, 0xa2, 0xd7, 0x2c, 0xe9, 0xd5,
    0x59, 0xcb, 0x50, 0xa8, 0xdc, 0xfc, 0xf2, 0x56, 0x72, 0xa6, 0x65, 0x2f, 0x9f, 0x9b, 0x3d, 0xba,
    0x7d, 0xc2, 0x45, 0x82, 0xa7, 0x57, 0xb6, 0xa3, 0x7a, 0x75, 0x4f, 0xae, 0x3f, 0x37, 0x6d, 0x47,
    0x61, 0xbe, 0xab, 0xd3, 0x5f, 0xb0, 0x58, 0xaf, 0xca, 0x5e, 0xfa, 0x85, 0xe4, 0x4d, 0x8a, 0x05,
    0xfb, 0x60, 0xb7, 0x7b, 0xb8, 0x26, 0x4a, 0x67, 0xc6, 0x1a, 0xf8, 0x69, 0x25, 0xb3, 0xdb, 0xbd,
    0x66, 0xdd, 0xf1, 0xd2, 0xdf, 0x03, 0x8d, 0x34, 0xd9, 0x92, 0x0d, 0x63, 0x55, 0xaa, 0x49, 0xec,
    0xbc, 0x95, 0x3c, 0x84, 0x0b, 0xf5, 0xe6, 0xe7, 0xe5, 0xac, 0x7e, 0x6e, 0xb9, 0xf9, 0xda, 0x8e,
    0x9a, 0xc9, 0x24, 0xe1, 0x0a, 0x15, 0x6b, 0x3a, 0xa0, 0x51, 0xf4, 0xea, 0xb2, 0x97, 0x9e, 0x5d,
    0x22, 0x88, 0x94, 0xce, 0x19, 0x01, 0x71, 0x4c, 0xa5, 0xe3, 0xc5, 0x31, 0xbb, 0xcc, 0x1f, 0x2d,
    0x3b, 0x52, 0x6f, 0xf6, 0x2e, 0x89, 0xf7, 0xc0, 0x68, 0x1b, 0x64, 0x04, 0x06, 0xbf, 0x83, 0x38,
};

/// Provides the exponentiation value at each index X.
const EXP_TABLE = [256]u8{
    0x01, 0xe5, 0x4c, 0xb5, 0xfb, 0x9f, 0xfc, 0x12, 0x03, 0x34, 0xd4, 0xc4, 0x16, 0xba, 0x1f, 0x36,
    0x05, 0x5c, 0x67, 0x57, 0x3a, 0xd5, 0x21, 0x5a, 0x0f, 0xe4, 0xa9, 0xf9, 0x4e, 0x64, 0x63, 0xee,
    0x11, 0x37, 0xe0, 0x10, 0xd2, 0xac, 0xa5, 0x29, 0x33, 0x59, 0x3b, 0x30, 0x6d, 0xef, 0xf4, 0x7b,
    0x55, 0xeb, 0x4d, 0x50, 0xb7, 0x2a, 0x07, 0x8d, 0xff, 0x26, 0xd7, 0xf0, 0xc2, 0x7e, 0x09, 0x8c,
    0x1a, 0x6a, 0x62, 0x0b, 0x5d, 0x82, 0x1b, 0x8f, 0x2e, 0xbe, 0xa6, 0x1d, 0xe7, 0x9d, 0x2d, 0x8a,
    0x72, 0xd9, 0xf1, 0x27, 0x32, 0xbc, 0x77, 0x85, 0x96, 0x70, 0x08, 0x69, 0x56, 0xdf, 0x99, 0x94,
    0xa1, 0x90, 0x18, 0xbb, 0xfa, 0x7a, 0xb0, 0xa7, 0xf8, 0xab, 0x28, 0xd6, 0x15, 0x8e, 0xcb, 0xf2,
    0x13, 0xe6, 0x78, 0x61, 0x3f, 0x89, 0x46, 0x0d, 0x35, 0x31, 0x88, 0xa3, 0x41, 0x80, 0xca, 0x17,
    0x5f, 0x53, 0x83, 0xfe, 0xc3, 0x9b, 0x45, 0x39, 0xe1, 0xf5, 0x9e, 0x19, 0x5e, 0xb6, 0xcf, 0x4b,
    0x38, 0x04, 0xb9, 0x2b, 0xe2, 0xc1, 0x4a, 0xdd, 0x48, 0x0c, 0xd0, 0x7d, 0x3d, 0x58, 0xde, 0x7c,
    0xd8, 0x14, 0x6b, 0x87, 0x47, 0xe8, 0x79, 0x84, 0x73, 0x3c, 0xbd, 0x92, 0xc9, 0x23, 0x8b, 0x97,
    0x95, 0x44, 0xdc, 0xad, 0x40, 0x65, 0x86, 0xa2, 0xa4, 0xcc, 0x7f, 0xec, 0xc0, 0xaf, 0x91, 0xfd,
    0xf7, 0x4f, 0x81, 0x2f, 0x5b, 0xea, 0xa8, 0x1c, 0x02, 0xd1, 0x98, 0x71, 0xed, 0x25, 0xe3, 0x24,
    0x06, 0x68, 0xb3, 0x93, 0x2c, 0x6f, 0x3e, 0x6c, 0x0a, 0xb8, 0xce, 0xae, 0x74, 0xb1, 0x42, 0xb4,
    0x1e, 0xd3, 0x49, 0xe9, 0x9c, 0xc8, 0xc6, 0xc7, 0x22, 0x6e, 0xdb, 0x20, 0xbf, 0x43, 0x51, 0x52,
    0x66, 0xb2, 0x76, 0x60, 0xda, 0xc5, 0xf3, 0xf6, 0xaa, 0xcd, 0x9a, 0xa0, 0x75, 0x54, 0x0e, 0x01,
};

pub fn get_rand_byte() u8 {
    var bytes: [1]u8 = undefined;
    std.crypto.random.bytes(&bytes);
    return bytes[0];
}

pub fn get_nonzero_rand_byte() u8 {
    while (true) {
        const byte = get_rand_byte();
        if (byte > 0) {
            return byte;
        }
    }
}

/// Creates a set of values from [1, 256).
/// Returns a psuedo-random shuffling of the set.
pub fn new_coordinates() [255]u8 {
    var coordinates = std.mem.zeroes([255]u8);
    for (0..255) |i| {
        coordinates[i] = @as(u8, @intCast(i)) + 1;
    }

    // Pseudo-randomize the array of coordinates.
    //
    // This impl maps almost perfectly because both of the lists (coordinates and randomIndices)
    // have a length of 255 and byte values are between 0 and 255 inclusive. The only value that
    // does not map neatly here is if the random byte is 255, since that value used as an index
    // would be out of bounds. Thus, for bytes whose value is 255, wrap around to 0.
    for (0..255) |i| {
        const random_index = get_rand_byte();
        const j: u8 = random_index % 255; // Make sure to handle the case where the byte is 255.
        const temp = coordinates[i];
        coordinates[i] = coordinates[j];
        coordinates[j] = temp;
    }
    return coordinates;
}

/// Combines two numbers in GF(2^8).
/// This can be used for both addition and subtraction.
fn gadd(a: u8, b: u8) u8 {
    return a ^ b;
}

const DivisionError = error{InvalidZeroDenominator};

/// Divides two numbers in GF(2^8).
fn gdiv(a: u8, b: u8) DivisionError!u8 {
    // This should never happen
    if (b == 0) {
        return DivisionError.InvalidZeroDenominator;
    }
    const logA: u32 = LOG_TABLE[a];
    const logB: u32 = LOG_TABLE[b];
    const diff: u32 = (logA + 255 - logB);
    const mod: u32 = diff % 255;
    const result = EXP_TABLE[mod];
    return if (a == 0) 0 else result;
}

/// Multiplies two numbers in GF(2^8).
fn gmult(a: u8, b: u8) u8 {
    const logA: u32 = LOG_TABLE[a];
    const logB: u32 = LOG_TABLE[b];
    const mod: u32 = (logA + logB) % 255;
    const result = EXP_TABLE[mod];
    return if (a == 0 or b == 0) 0 else result;
}

pub const Polynomial = struct {
    coefficients: std.ArrayList(u8),
    degree: u8,

    const Self = @This();

    /// Creates a pseudo-random set of coefficients for a polynomial.
    ///
    /// Returned coefficients are always `degree + 1` in length since
    /// the given secret (intercept) is stored as the first value
    pub fn init(intercept: u8, degree: u8, allocator: Allocator) !Self {
        var coefficients = std.ArrayList(u8).init(allocator);
        // The first byte is always the intercept
        try coefficients.append(intercept);
        for (0..degree) |i| {
            // degree is equal to t-1, where t is the threshold of required shares.
            // The coefficient at t-1 cannot equal 0.
            const coeff_idx = i + 1;
            const byte = if (coeff_idx == degree) get_nonzero_rand_byte() else get_rand_byte();
            try coefficients.append(byte);
        }
        return Self{ .coefficients = coefficients, .degree = degree };
    }

    const EvaluationError = error{InvalidZeroXValue};

    /// Evaluates a polynomial with the given x using Horner's method.
    /// @see https://en.wikipedia.org/wiki/Horner%27s_method
    ///
    /// This is used to evaluate the y-value for each share's randomly
    /// assigned unique x-value given
    fn evaluate(self: *const Self, x: u8) EvaluationError!u8 {
        if (x == 0) {
            return EvaluationError.InvalidZeroXValue;
        }
        // Initialise result with final coefficient
        // and calculate backwards recursively
        var result = self.coefficients.items[self.degree];
        var i = self.degree - 1;
        while (i >= 0) : (i -= 1) {
            const coeff = self.coefficients.items[i];
            result = gadd(gmult(result, x), coeff);
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

pub const Share = struct {
    x: u8,
    y: std.ArrayList(u8),

    const Self = @This();
    fn init(x: u8, allocator: Allocator) Share {
        return Share{ .x = x, .y = std.ArrayList(u8).init(allocator) };
    }
    fn deinit(self: *const Self) void {
        self.y.deinit();
    }
    pub fn toBytes(self: *const Self, allocator: Allocator) !std.ArrayList(u8) {
        var bytes = std.ArrayList(u8).init(allocator);
        try bytes.append(self.x);
        try bytes.appendSlice(self.y.items);
        return bytes;
    }
    pub fn fromBytes(bytes: []const u8, allocator: Allocator) !Self {
        const x = bytes[0];
        var y = std.ArrayList(u8).init(allocator);
        try y.appendSlice(bytes[1..]);
        return Self{ .x = x, .y = y };
    }
};

pub const GeneratedShares = struct {
    shares: std.ArrayList(Share),

    const Self = @This();
    pub fn deinit(self: *const Self) void {
        for (0..self.shares.items.len) |i| {
            self.shares.items[i].deinit();
        }
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
    secret: []const u8,
    num_shares: u8,
    threshold: u8,
    allocator: Allocator,
) !GeneratedShares {
    // secret must be a non-empty
    assert(secret.len > 0);
    // num_shares must be a number in the range [2, 256)
    assert((num_shares >= 2) and (num_shares <= 255));
    // threshold must be a number in the range [2, 256)
    assert((threshold >= 2) and (threshold <= 255));
    // total number of shares must be greater than or equal to the required threshold
    assert(num_shares >= threshold);

    var shares = try std.ArrayList(Share).initCapacity(allocator, num_shares);
    const secret_len = secret.len;
    const x_coordinates = new_coordinates();

    // Generate unique x-value for each share
    for (0..num_shares) |k| {
        // var share = std.ArrayList(u8).init(allocator);
        const x_k = x_coordinates[k];
        const share = Share.init(x_k, allocator);
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
    for (0..secret_len) |i| {
        const secret_byte = secret[i];
        const polynomial = try Polynomial.init(secret_byte, degree, allocator);
        for (0..num_shares) |k| {
            const x = x_coordinates[k];
            const y = try polynomial.evaluate(x);
            try shares.items[k].y.append(y);
        }
        polynomial.deinit();
    }

    return GeneratedShares{ .shares = shares };
}

const CombineError = error{InvalidDuplicateShareFound};

/// Reconstruct the secret from the given shares.
///
/// @param `shares` A list of shares to reconstruct the secret from. Must be at least 2 and at most 255.
/// @param `allocator` Allocator to allocate arraylists on the heap
///
/// @returns The reconstructed secret.
pub fn reconstruct(shares: []Share, allocator: Allocator) !std.ArrayList(u8) {
    // Shares must be an array with length in the range [2, 256)
    assert((shares.len >= 2) and (shares.len <= 255));
    // Shares must be a Uint8Array with at least 2 bytes and all shares must have the same byte length.
    const first_share = shares[0];
    for (shares) |share| {
        assert((share.y.items.len >= 1) and (share.y.items.len == first_share.y.items.len));
    }

    const num_shares = shares.len;
    const secret_len = shares[0].y.items.len;
    var secret = std.ArrayList(u8).init(allocator);
    for (0..secret_len) |_| {
        try secret.append(0);
    }

    var x_samples = std.ArrayList(u8).init(allocator);
    defer x_samples.deinit();
    var y_samples = std.ArrayList(u8).init(allocator); // const xSamples = new Uint8Array(sharesLength);
    defer y_samples.deinit();
    for (0..num_shares) |_| {
        try y_samples.append(0);
    }

    var share_ids = std.ArrayList(u8).init(allocator);
    defer share_ids.deinit();
    for (0..num_shares) |i| {
        const share = shares[i];
        const share_id = share.x;

        const is_duplicate = for (share_ids.items) |eid| {
            if (eid == share_id) {
                break true;
            }
        } else false;
        if (is_duplicate) {
            return CombineError.InvalidDuplicateShareFound;
        }

        try share_ids.append(share_id);
        try x_samples.append(share_id);
    }

    // Reconstruct each byte
    for (0..secret_len) |i| {
        // Set y-value for each share
        for (0..num_shares) |j| {
            const y = shares[j].y.items[i];
            y_samples.items[j] = y;
        }

        // Interpolate the polynomial and compute the value
        // at y-intersect aka when x = 0 (secret)
        const secret_i = try interpolate_polynomial(x_samples.items, y_samples.items, 0);
        secret.items[i] = secret_i;
    }

    return secret;
}

const InterpolationError = error{SampleLengthMismatch} || DivisionError;

/// Takes N sample points and returns the value at a given x using a lagrange interpolation.
///
/// @see `Definition` section of https://en.wikipedia.org/wiki/Lagrange_polynomial to best
/// understand the following code
pub fn interpolate_polynomial(x_samples: []u8, y_samples: []u8, x: u8) InterpolationError!u8 {
    if (x_samples.len != y_samples.len) {
        return InterpolationError.SampleLengthMismatch;
    }

    const limit = x_samples.len;

    var basis: u8 = 0;
    var result: u8 = 0;

    // Calculate basis polynomials for jth share
    for (0..limit) |j| {
        basis = 1;

        for (0..limit) |k| {
            // Basis polynomial is calculated
            // with x-values of all other k-1 shares,
            // hence we ignore our own x-value
            if (j == k) {
                continue;
            }
            // Corresponds to `x - x(k)` but addition
            // and subtraction are equivalent in GF
            const num = gadd(x, x_samples[k]);
            // Corresponds to `x(j) - x(k)` but addition
            // and subtraction are equivalent in GF
            const denom = gadd(x_samples[j], x_samples[k]);

            const term = try gdiv(num, denom);
            basis = gmult(basis, term);
        }

        const group = gmult(y_samples[j], basis);
        result = gadd(result, group);
    }

    return result;
}
