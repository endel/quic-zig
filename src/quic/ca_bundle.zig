//! Loading X.509 trust anchors.
//!
//! Zig 0.16 moved certificate loading behind the `Io` interface. The rest of
//! this library deliberately does not thread `Io` through its signatures (see
//! the note at the top of `src/sys.zig`), so the seam lives here: an `Io` is
//! built for the load and torn down as soon as it returns.
//!
//! A bundle is only the trust anchors. Everything else the chain has to
//! satisfy — hostname, each link's signature, CA:TRUE, keyCertSign, validity
//! dates — is in `tls13.zig` and runs whether or not one is configured. What
//! a bundle adds is the last step: that the chain ends somewhere trusted.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Certificate = std.crypto.Certificate;

pub const Error = error{ LoadFailed, OutOfMemory };

/// The platform's CA certificates — the system keychain on macOS, the usual
/// `/etc/ssl` locations on Linux and the BSDs.
///
/// The caller owns the bundle: `deinit(gpa)` it, and keep it alive for as long
/// as any handshake configured with it. It is read-only once built, so one
/// bundle can serve every connection in a process.
pub fn loadSystem(gpa: Allocator) Error!Certificate.Bundle {
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var bundle: Certificate.Bundle = .empty;
    errdefer bundle.deinit(gpa);
    bundle.rescan(gpa, io, Io.Clock.real.now(io)) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.LoadFailed,
    };
    return bundle;
}

/// One PEM file of CA certificates, in place of the platform's. Use it to
/// trust a private CA — an interop peer's, a test rig's — without trusting
/// everything the machine does.
pub fn loadFile(gpa: Allocator, path: []const u8) Error!Certificate.Bundle {
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var bundle: Certificate.Bundle = .empty;
    errdefer bundle.deinit(gpa);

    const now = Io.Clock.real.now(io);
    if (std.fs.path.isAbsolute(path)) {
        bundle.addCertsFromFilePathAbsolute(gpa, io, now, path) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.LoadFailed,
        };
    } else {
        const dir = Io.Dir.cwd();
        bundle.addCertsFromFilePath(gpa, io, now, dir, path) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.LoadFailed,
        };
    }
    return bundle;
}

test "the system bundle has trust anchors in it" {
    // Skipped rather than failed on a machine with no trust store: a CI
    // container may genuinely have none, and that is not a code defect.
    var bundle = loadSystem(std.testing.allocator) catch return error.SkipZigTest;
    defer bundle.deinit(std.testing.allocator);
    if (bundle.map.count() == 0) return error.SkipZigTest;

    try std.testing.expect(bundle.bytes.items.len > 0);
}
