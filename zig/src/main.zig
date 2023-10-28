const std = @import("std");
const math = std.math;
const sha2 = std.crypto.hash.sha2;
const chacha_poly = std.crypto.aead.chacha_poly;

pub fn RubikShuffle(matrix: []u8, ciphertext: []const u8) !void {
    var sideSize = math.sqrt(matrix.len);

    // Size of matrix
    if (sideSize * sideSize != matrix.len) {
        std.debug.print("it is now a square matrix\n", .{});
        std.os.exit(1);
    }

    // Size of ciphertext
    if (sideSize * 2 != ciphertext.len) {
        std.debug.print("shuffling key is not the correct size\n", .{});
        std.os.exit(1);
    }

    // Convert to shuffle key list with modulus of 64
    var shuffleKey = [_]u8{0} ** 128;
    for (0..ciphertext.len) |i| {
        shuffleKey[i] = ciphertext[i] % 64;
    }

    // Rotate columns
    for (0..sideSize) |i| {
        var temp = [_]u8{0} ** 64;
        for (0..sideSize) |j| {
            temp[j] = matrix[i + (j * sideSize)];
        }
        var lastk = temp[(sideSize - shuffleKey[i])..sideSize];
        var firstK = temp[0..(sideSize - shuffleKey[i])];

        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const allocator = arena.allocator();
        var newcol = try std.mem.concat(allocator, u8, &[_][]const u8{ lastk, firstK });

        for (0..sideSize) |j| {
            matrix[i + (j * sideSize)] = newcol[j];
        }
    }

    var shuffleKeyH = shuffleKey[sideSize..];

    // Rotate rows
    for (0..sideSize) |i| {
        var temp = matrix[i * sideSize .. (i * sideSize) + sideSize];
        var lastk = temp[(sideSize - shuffleKeyH[i])..sideSize];
        var firstK = temp[0..(sideSize - shuffleKeyH[i])];
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const allocator = arena.allocator();
        var newrow = try std.mem.concat(allocator, u8, &[_][]const u8{ lastk, firstK });

        for ((i * sideSize)..(i * sideSize) + sideSize, 0..sideSize) |j, k| {
            matrix[j] = newrow[k];
        }
    }
}

pub fn SboxGen(cleanbox: []u8) !void {
    // TESTING
    var password = "hello";

    // Key generation
    var key: [sha2.Sha256.digest_length]u8 = undefined;
    sha2.Sha256.hash(password, &key, .{});

    // Generate pre-shuffle clean box
    //var cleanbox = [_]u8{0} ** 4096;
    for (0..256) |i| {
        for (0..16) |j| {
            cleanbox[i * 16 + j] = @as(u8, @intCast(i));
        }
    }

    // Generate list of exchange indexes
    const aead = chacha_poly.XChaCha20Poly1305;
    var nonce = [_]u8{0} ** aead.nonce_length;
    var ciphertext: [128]u8 = undefined;
    var m = [_]u8{0} ** 128;
    var ad = "";
    var tag: [aead.tag_length]u8 = undefined;
    aead.encrypt(&ciphertext, &tag, &m, ad, nonce, key);

    try RubikShuffle(cleanbox, &ciphertext);
}

pub fn main() !void {
    var sboxes = [_]u8{0} ** 4096;
    try SboxGen(&sboxes);
    std.debug.print("{d}\n\n", .{sboxes});
}
