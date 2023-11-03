const std = @import("std");
const ArrayList = std.ArrayList;

pub fn PKCS7pad(data: []u8, blockSize: u8) ![]u8 {
    if (blockSize <= 1 or blockSize >= 256) {
        std.debug.print("pkcs7: Invalid block size {d}\n", .{blockSize});
        std.os.exit(1);
    } else {
        var t = data.len % blockSize;

        var padLen: u8 = blockSize - @as(u8, @intCast(t));

        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var padding = ArrayList(u8).init(allocator);
        defer padding.deinit();

        for (0..data.len) |i| {
            try padding.append(data[i]);
        }
        for (0..padLen) |i| {
            _ = i;
            try padding.append(padLen);
        }

        var paddedData = padding.items[0..];
        return try std.heap.page_allocator.dupe(u8, paddedData);
    }
}

pub fn PKCS7strip(data: []u8, blockSize: u8) ![]u8 {
    var length = data.len;
    if (length == 0) {
        std.debug.print("pkcs7: Data is empty\n", .{});
        std.os.exit(1);
    } else if (length % blockSize != 0) {
        std.debug.print("pkcs7: Data is not block-aligned\n", .{});
        std.os.exit(1);
    }

    var padLen: u8 = data[length - 1];

    if (padLen > blockSize or padLen == 0) {
        std.debug.print("pkcs7: Invalid padding\n", .{});
        std.os.exit(1);
    }

    var unpaddedData = data[0..(length - padLen)];
    return try std.heap.page_allocator.dupe(u8, unpaddedData);
}

test "pad & unpad" {
    var data = [_]u8{ 't', 'e', 's', 't' };
    var padded = try PKCS7pad(data[0..], 8);
    var unpadded = try PKCS7strip(padded, 8);
    std.debug.assert(std.mem.eql(u8, &data, unpadded));
}
