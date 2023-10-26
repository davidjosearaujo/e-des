const std = @import("std");
const sha2 = std.crypto.hash.sha2;
const chacha_poly = std.crypto.aead.chacha_poly;

pub fn RubikShuffle() !void{
    
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
    var c: [256]u8 = undefined;
    var m = [_]u8{0} ** 256;
    var ad = "";
    var tag: [aead.tag_length]u8 = undefined;
    aead.encrypt(&c, &tag, &m, ad, nonce, key);

    std.debug.print("{s}\n", .{std.fmt.fmtSliceHexLower(&c)});
}

pub fn main() !void {
    try SboxGen();
}
