// Copyright 2023 davidjosearaujo
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

const std = @import("std");
const pkcs = @import("./pkcs7.zig");
const fent = @import("./feistelnetwork.zig");

const ArrayList = std.ArrayList;
const math = std.math;
const sha2 = std.crypto.hash.sha2;
const chacha_poly = std.crypto.aead.chacha_poly;

const help_message =
    \\Usage:
    \\    e-des [MODE] <PASSWORD> <MESSAGE>
    \\
    \\Examples:
    \\    e-des encrypt password1234 "This is my secret, there are many like it, but this one is mine"
    \\    e-des decrypt password1234 a35f8s12069c63
    \\
    \\MODE:
    \\    encrypt     encrypt the message with given password, returns a ciphertext in hex format
    \\    decrypt     encrypt the message with given password, returns plaintext message in ASCII format
    \\
    \\
;

// DONE
pub fn RubikShuffle(matrix: []u8, ciphertext: []const u8) !void {
    var sideSize = math.sqrt(matrix.len);

    // Size of matrix
    if (sideSize * sideSize != matrix.len) {
        std.debug.print("rubikShuffle: it is now a square matrix\n", .{});
        std.os.exit(1);
    }

    // Size of ciphertext
    if (sideSize * 2 != ciphertext.len) {
        std.debug.print("rubikShuffle:shuffling key is not the correct size\n", .{});
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

// DONE
pub fn SboxGen(cleanbox: []u8, password: []u8) !void {
    // Key generation
    var key: [sha2.Sha256.digest_length]u8 = undefined;
    sha2.Sha256.hash(password, &key, .{});

    // Generate pre-shuffle clean box
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

pub fn encrypt(message: []u8, sboxes: []u8) ![]u8 {
    // Add PKCS#7 padding to the message
    var paddedData = try pkcs.PKCS7pad(message, 8);

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var out = ArrayList(u8).init(allocator);
    defer out.deinit();

    for (0..paddedData.len / 8) |i| {
        var block = paddedData[i * 8 .. i * 8 + 8];
        for (0..16) |j| {
            var sbox = sboxes[j * 256 .. j * 256 + 256];
            block = try fent.EncFeistelNetwork(block, sbox);
        }
        try out.appendSlice(block[0..]);
        std.heap.page_allocator.free(block);
    }
    std.heap.page_allocator.free(paddedData);

    return try std.heap.page_allocator.dupe(u8, out.items[0..]);
}

pub fn decrypt(message: []u8, sboxes: []u8) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var out = ArrayList(u8).init(allocator);
    defer out.deinit();

    for (0..message.len / 8) |i| {
        var block = message[i * 8 .. i * 8 + 8];

        var j: u16 = 16;
        while (j > 0) {
            var sbox = sboxes[j * 256 - 256 .. j * 256];
            block = try fent.DecFeistelNetwork(block, sbox);
            j -= 1;
        }
        try out.appendSlice(block[0..]);
        std.heap.page_allocator.free(block);
    }

    return try pkcs.PKCS7strip(out.items[0..], 8);
}

pub fn main() !void {
    // Argument calling order
    //      1º: encrypt or decrypt option
    //      2º: password
    //      3º: message (in quotes)
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const aa = gpa.allocator();
    const args = try std.process.argsAlloc(aa);
    defer std.process.argsFree(aa, args);

    // Number of arguments
    if (4 != args.len) {
        std.debug.print(help_message, .{});
        std.os.exit(1);
    }

    // Calling arguments
    var option = args[1];
    var password = args[2];
    var message = args[3];

    // SBox generation
    var sboxes = [_]u8{0} ** 4096;
    try SboxGen(&sboxes, password);

    if (std.mem.eql(u8, option, "encrypt")) {
        var out = try encrypt(message, &sboxes);
        std.debug.print("{s}\n", .{std.fmt.fmtSliceHexLower(out)});
    } else if (std.mem.eql(u8, option, "decrypt")) {
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        // Half the size of the string because is each byte is represented
        // by two characters
        var blocks = try allocator.alloc(u8, message.len / 2);
        _ = try std.fmt.hexToBytes(blocks, message);

        var out = try decrypt(blocks, &sboxes);
        std.debug.print("{s}\n", .{out});
    } else {
        std.debug.print("Option not available! Please choose either 'encrypt' or 'decrypt' mode\n", .{});
    }
}

test "encryt speed test" {
    var password = [_]u8{ 'h', 'e', 'l', 'l', 'o' };

    var sboxes = [_]u8{0} ** 4096;
    try SboxGen(&sboxes, &password);

    var enc_max: i128 = 0;
    var enc_min: i128 = 0;
    var enc_sum: i128 = 0;

    var dec_max: i128 = 0;
    var dec_min: i128 = 0;
    var dec_sum: i128 = 0;

    var rnd = std.rand.DefaultPrng.init(0);
    var nTest: u64 = 4;
    for (0..nTest) |j| {
        _ = j;
        // Generate new random message
        var message = [_]u8{0} ** 4096;
        for (0..message.len) |i| {
            var some_random_num = rnd.random().int(u8);
            message[i] = some_random_num;
        }

        // Encrypt
        var start_enc = std.time.nanoTimestamp();
        var enc_out = try encrypt(&message, &sboxes);
        var delta_enc = std.time.nanoTimestamp() - start_enc;

        if (delta_enc > enc_max) {
            enc_max = delta_enc;
        }
        if (delta_enc < enc_min or enc_min == 0) {
            enc_min = delta_enc;
        }
        enc_sum += delta_enc;

        // Decrypt
        var start_dec = std.time.nanoTimestamp();
        var dec_out = try decrypt(enc_out, &sboxes);
        var delta_dec = std.time.nanoTimestamp() - start_dec;

        if (delta_dec > dec_max) {
            dec_max = delta_dec;
        }
        if (delta_dec < dec_min or dec_min == 0) {
            dec_min = delta_dec;
        }
        dec_sum += delta_dec;

        std.debug.assert(std.mem.eql(u8, &message, dec_out));

        std.heap.page_allocator.free(enc_out);
        std.heap.page_allocator.free(dec_out);
    }

    std.debug.print("\nEncryption times\nMax: {d}\tMin: {d}\tAverage: {d}\n", .{ enc_max, enc_min, @divFloor(enc_sum, nTest) });
    std.debug.print("Decryption times\nMax: {d}\tMin: {d}\tAverage: {d}\n", .{ dec_max, dec_min, @divFloor(dec_sum, nTest) });
}
