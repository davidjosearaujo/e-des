const std = @import("std");
const math = std.math;
const sha2 = std.crypto.hash.sha2;
const chacha_poly = std.crypto.aead.chacha_poly;

pub fn RubikShuffle(matrix: []const u8, ciphertext: []const u8) !void {
    var sideSize = math.sqrt(matrix.len);

    if (sideSize * sideSize != matrix.len) {
        std.debug.print("it is now a square matrix\n", .{});
        std.os.exit(1);
    }

    if (sideSize * 2 != ciphertext.len) {
        std.debug.print("shuffling key is not the correct size\n", .{});
        std.os.exit(1);
    }

    std.debug.print("{d}\n", .{sideSize});
}

pub fn SboxGen() !void {
    // TESTING
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
    const aead = chacha_poly.XChaCha20Poly1305;
    var nonce = [_]u8{0} ** aead.nonce_length;
    var ciphertext: [256]u8 = undefined;
    var m = [_]u8{0} ** 256;
    var ad = "";
    var tag: [aead.tag_length]u8 = undefined;
    aead.encrypt(&ciphertext, &tag, &m, ad, nonce, key);

    try RubikShuffle(&cleanbox, &ciphertext);
}

pub fn main() !void {
    try SboxGen();
}
