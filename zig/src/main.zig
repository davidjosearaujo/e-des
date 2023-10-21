const std = @import("std");
const print = std.debug.print;
const sha = std.crypto.hash.sha2.Sha256;
const testing = std.testing;

export fn add(a: i32, b: i32) i32 {
    return a + b;
}

fn _keyGen() [256]u8 {}

test "basic add functionality" {
    try testing.expect(add(3, 7) == 10);
}

test "basic key generation with SHA256" {
    var block = [_]u8{'#'} ** sha.block_length;
    var h0 = sha.init(.{});
    var out1: [sha.digest_length]u8 = undefined;
    var out2: [sha.digest_length]u8 = undefined;
    var h = h0;
    h.update(block[0..]);
    h.final(&out1);
    h = h0;
    h.update(block[0..1]);
    h.update(block[1..]);
    h.final(&out2);
    print("sha2: {any}\n", .{out1});
    print("sha2: {any}\n", .{out2});
    try std.testing.expectEqual(out1, out2);
}
