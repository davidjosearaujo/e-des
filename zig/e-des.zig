const std = @import("std");
const sha2 = std.crypto.hash.sha2;
const chacha_poly = std.crypto.aead.chacha_poly;

pub fn main() void {
    var password = "hello";

    // Key generation
    var key: [sha2.Sha256.digest_length]u8 = undefined;
    sha2.Sha256.hash(password, &key, .{});

    // Generate pre-shuffle clean box
    var cleanbox: [4096]u8 = undefined;
    for (0..256) |i| {
        for (0..16) |j| {
            cleanbox[i * 16 + j] = @as(u8, @intCast(i));
        }
    }

    // Generate list of exchange indexes
    var ciphertext: [256]u8 = undefined;
    var nonce: [chacha_poly.ChaCha12Poly1305.nonce_length]u8 = undefined;
    const m: [256]u8 = undefined;
    const ad = "";
    chacha_poly.ChaCha20Poly1305.encrypt(ciphertext[0..m.len], ciphertext[240..], &m, ad, nonce, key);

    std.debug.print("Password: {s}\nHash: {s}\n", .{ password, std.fmt.fmtSliceHexLower(&key) });

    std.debug.print("Cleanbox: {s}\n", .{std.fmt.fmtSliceHexLower(&cleanbox)});

    std.debug.print("Shuffle Key: {s}\n", .{std.fmt.fmtSliceHexLower(&ciphertext)});
}
