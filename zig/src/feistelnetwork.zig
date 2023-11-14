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
const ArrayList = std.ArrayList;

pub fn EncFeistelNetwork(block: []u8, sbox: []u8) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var limit = @as(u8, @intCast(block.len / 2));

    var out = try allocator.alloc(u8, block.len);
    var temp = try allocator.alloc(u8, limit);

    var start_i: u8 = @as(u8, @intCast(block.len - 1));
    var start_j: u8 = 0;

    var index: u32 = block[start_i];

    while (start_i >= limit) {
        out[start_i - limit] = block[start_i];
        temp[start_j] = sbox[index];

        index = (index + block[start_i - 1]) % @as(u32, @intCast(sbox.len));

        start_i -= 1;
        start_j += 1;
    }

    for (0..limit) |i| {
        out[i + limit] = temp[i] ^ block[i];
    }

    allocator.free(temp);

    return try std.heap.page_allocator.dupe(u8, out);
}

pub fn DecFeistelNetwork(block: []u8, sbox: []u8) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var limit = @as(u8, @intCast(block.len / 2));

    var out = try allocator.alloc(u8, block.len);
    var temp = try allocator.alloc(u8, limit);

    var index: u32 = block[limit - 1];

    for (0..limit) |i| {
        out[limit + i] = block[i];
        temp[i] = sbox[index];
        if (i <= 2) {
            index = (index + block[limit - 2 - i]) % @as(u32, @intCast(sbox.len));
        }
    }

    for (0..limit) |i| {
        out[i] = temp[i] ^ block[i + limit];
    }

    allocator.free(temp);

    return try std.heap.page_allocator.dupe(u8, out);
}
