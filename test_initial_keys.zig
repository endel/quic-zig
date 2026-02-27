const std = @import("std");
const crypto_mod = @import("src/quic/crypto.zig");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    _ = allocator;

    // Test with different DCIDs to see which one quic-go might be using

    // Client's chosen DCID from the first client Initial packet
    const client_dcid = [_]u8{126, 50, 163, 192, 178, 204, 44, 32};

    // Client's SCID (which becomes server's DCID in response)
    const client_scid = [_]u8{62, 161, 111, 45, 6, 0, 134, 211};

    // Empty DCID (quic-go might use this for initial packets)
    const empty_dcid = [_]u8{};

    // Server's SCID from its response (unlikely, but let's try)
    const server_scid = [_]u8{197, 23, 2, 245};

    std.debug.print("Testing different DCIDs for Initial key derivation:\n\n", .{});

    std.debug.print("1. With client's DCID ({d} bytes): {any}\n", .{client_dcid.len, client_dcid});
    const keys1 = try crypto_mod.deriveInitialKeyMaterial(&client_dcid, 0x00000001, false);
    std.debug.print("   Server key (open): {any}\n", .{keys1[0].key});
    std.debug.print("   HP key (open): {any}\n", .{keys1[0].hp_key});
    std.debug.print("   IV (open): {any}\n\n", .{keys1[0].nonce});

    std.debug.print("2. With empty DCID:\n", .{});
    const keys2 = try crypto_mod.deriveInitialKeyMaterial(&empty_dcid, 0x00000001, false);
    std.debug.print("   Server key (open): {any}\n", .{keys2[0].key});
    std.debug.print("   HP key (open): {any}\n", .{keys2[0].hp_key});
    std.debug.print("   IV (open): {any}\n\n", .{keys2[0].nonce});

    std.debug.print("3. With client's SCID ({d} bytes): {any}\n", .{client_scid.len, client_scid});
    const keys3 = try crypto_mod.deriveInitialKeyMaterial(&client_scid, 0x00000001, false);
    std.debug.print("   Server key (open): {any}\n", .{keys3[0].key});
    std.debug.print("   HP key (open): {any}\n", .{keys3[0].hp_key});
    std.debug.print("   IV (open): {any}\n\n", .{keys3[0].nonce});

    std.debug.print("4. With server's SCID ({d} bytes): {any}\n", .{server_scid.len, server_scid});
    const keys4 = try crypto_mod.deriveInitialKeyMaterial(&server_scid, 0x00000001, false);
    std.debug.print("   Server key (open): {any}\n", .{keys4[0].key});
    std.debug.print("   HP key (open): {any}\n", .{keys4[0].hp_key});
    std.debug.print("   IV (open): {any}\n\n", .{keys4[0].nonce});

    std.debug.print("Expected server key from failed decryption: {any}\n", .{[_]u8{203, 180, 97, 65, 22, 80, 118, 14, 242, 105, 37, 102, 173, 172, 155, 203}});
}
