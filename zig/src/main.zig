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
                block = try fent.EncFeistelNetwork(block, sboxes[j * 256 .. j * 256 + 256]);
            }
            try out.appendSlice(block[0..]);
        }

        std.debug.print("{d}\n", .{out.items});
    } else if (std.mem.eql(u8, option, "decrypt")) {
        // TODO: Call decryption feistel network

        // DONE (uncomment later)
        //var unpaddedData = try pkcs.PKCS7strip(paddedData, 8);
        //std.debug.print("{d}\n", .{unpaddedData});
    } else {
        std.debug.print("Option not available! Please choose either 'encrypt' or 'decrypt' mode\n", .{});
    }
}
