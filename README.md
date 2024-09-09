# shamir-secret-sharing

![Github CI](https://github.com/privy-io/shamir-secret-sharing/workflows/Github%20CI/badge.svg)

Simple zig implementation of [Shamir's Secret Sharing algorithm](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing).

Uses GF(2^8). Implementation inspired by [privy-io/shamir-secret-sharing](https://github.com/privy-io/shamir-secret-sharing) and [hashicorp/vault](https://github.com/hashicorp/vault/tree/main/shamir).

Includes a CLI app for independent/one-time using of shamir secret sharing.

## Security considerations

1. Although the reference implementations have been audited, this implementation was NOT audited and was written for FUN. DO NOT USE THIS IN PRODUCTION.
2. This library is not responsible for verifying the result of share reconstruction. Incorrect or corrupted shares will produce an incorrect value. Thus, it is the responsibility of users of this library to verify the integrity of the reconstructed secret.
3. Secrets should ideally be uniformly distributed at random. If this is not the case, it is recommended to first encrypt the value and split the encryption key.

## Installing

1. Run the following command:

```
zig fetch --save git+https://github.com/aidanaden/shamir-zig
```

2. Add the following to `build.zig`:

```zig
const shamir = b.dependency("shamir-zig", .{});
exe.root_module.addImport("shamir", shamir.module("shamir"));
```

## Build

```sh
zig build
```

## Usage

We can `generate` shares from a given secret and later `reconstruct` the secret from the minimum number of shares (as configured when running `generate`).

### CLI

```sh
./zig-out/bin/sss generate --threshold 4 --total 10 --secret mynamejeff
# --- output ---
# 582119FAF8CD1A1B8B478B
# E2C639374D22AF2F7F9A92
# EC199A1E26F30DA8545C35
# 18D1CD0C31AB9CF5543BBA
# 21E445153208A7B8FDD341
# 445DC7E47841916D1D3B5A
# C724D4678DF493727F99D0
# B611E915CAB0609FABEC18
# 8B67CE0445E7CF07E780C3
# CF8770A2BFCCFD4712EDB2
```

```sh
./zig-out/bin/sss reconstruct -s=18D1CD0C31AB9CF5543BBA,C724D4678DF493727F99D0,B611E915CAB0609FABEC18,CF8770A2BFCCFD4712EDB2
# --- output ---
# Regenerated secret: mynamejeff
```

### Code example

```zig
test "can split secret into multiple shares" {
    var secret = std.ArrayList(u8).init(std.testing.allocator);
    defer secret.deinit();
    // Hex value of "secret"
    try secret.appendSlice(&[_]u8{ 0x73, 0x65, 0x63, 0x72, 0x65, 0x74 });
    assert(secret.items.len == 6);

    const shares = try generate(secret, 3, 2, std.testing.allocator);
    defer {
        for (shares.items) |s| {
            s.deinit();
        }
        shares.deinit();
    }
    assert(shares.items.len == 3);

    const first_share = shares.items[0];
    assert(first_share.items.len == secret.items.len + 1);
    const second_share = shares.items[1];

    var thresholds = [2]std.ArrayList(u8){ first_share, second_share };
    const reconstructed = try reconstruct(&thresholds, std.testing.allocator);
    defer reconstructed.deinit();

    assert(std.mem.eql(u8, secret.items, reconstructed.items));

    std.debug.print("\nreconstructed (integers): ", .{});
    try std.json.stringify(&reconstructed.items, .{ .emit_strings_as_arrays = true }, std.io.getStdErr().writer());
    std.debug.print("\nreconstructed (string): ", .{});
    try std.json.stringify(&reconstructed.items, .{ .emit_strings_as_arrays = false }, std.io.getStdErr().writer());
}
```

## API

This package exposes two functions: `generate` and `reconstruct`.

#### Generate

```zig
/// Generate `shares` number of shares from given `secret` value, requiring `threshold` of them to reconstruct `secret`.
///
/// @param `secret` The secret value to split into shares.
/// @param `shares` The total number of shares to split `secret` into. Must be at least 2 and at most 255.
/// @param `threshold` The minimum number of shares required to reconstruct `secret`. Must be at least 2 and at most 255.
/// @param `allocator` Allocator to allocate arraylists on the heap
///
/// @returns A list of `shares` shares.
pub fn generate(
    secret: std.ArrayList(u8),
    shares: u8,
    threshold: u8,
    allocator: Allocator,
) !std.ArrayList(std.ArrayList(u8))
```

#### Reconstruct

```zig
/// Reconstruct the secret from the given shares.
///
/// @param `shares` A list of shares to reconstruct the secret from. Must be at least 2 and at most 255.
/// @param `allocator` Allocator to allocate arraylists on the heap
///
/// @returns The reconstructed secret.
pub fn reconstruct(shares: []std.ArrayList(u8), allocator: Allocator) !std.ArrayList(u8)
```

## License

Apache-2.0. See the [license file](LICENSE).
