const std = @import("std");
const crypto_mod = @import("src/quic/crypto.zig");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    _ = alloc;

    // RFC 9001 Appendix A.2 test vector
    const plaintext = "Sample Plaintext";
    const additional_data = "Sample AD";
    const key = [_]u8{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    const nonce = [_]u8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    var ciphertext: [32]u8 = undefined;
    var tag: [16]u8 = undefined;

    std.debug.print("Testing AEAD encryption with simple test vector:\n", .{});
    std.debug.print("Plaintext: {s}\n", .{plaintext});
    std.debug.print("Key: {any}\n", .{key});
    std.debug.print("Nonce: {any}\n\n", .{nonce});

    // Encrypt
    const Aead = std.crypto.aead.aes_gcm.Aes128Gcm;
    const ct = ciphertext[0..plaintext.len];
    Aead.encrypt(ct, &tag, plaintext, additional_data, nonce, key);

    std.debug.print("Ciphertext: {any}\n", .{ct});
    std.debug.print("Tag: {any}\n\n", .{tag});

    // Decrypt
    var pt: [32]u8 = undefined;
    Aead.decrypt(pt[0..plaintext.len], ct, tag, additional_data, nonce, key) catch |err| {
        std.debug.print("Decryption failed: {}\n", .{err});
        return;
    };

    std.debug.print("Decrypted plaintext: {s}\n", .{pt[0..plaintext.len]});
    std.debug.print("Match: {}\n", .{std.mem.eql(u8, pt[0..plaintext.len], plaintext)});
}
