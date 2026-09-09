const std = @import("std");

// Zig 0.16 migration: in-progress Phase 2 — libxev now supports 0.16
// (upstream commit a82a04eabb46). event_loop.zig is back on the library
// surface; non-manual apps are being restored one canary at a time.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Link libc on platforms that need it (Linux requires explicit libc for std.c.recvmsg).
    const need_libc: ?bool = if (target.result.os.tag == .windows) null else true;

    // libxev dependency (used by event-loop-based servers)
    const xev_dep = b.dependency("libxev", .{ .target = target, .optimize = optimize });

    // Library module — shared by all apps and exposed to downstream dependencies.
    const lib_mod = b.addModule("quic", .{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = need_libc,
        .imports = &.{.{ .name = "xev", .module = xev_dep.module("xev") }},
    });

    // Helper to build an app executable
    const App = struct {
        fn add(
            b2: *std.Build,
            name: []const u8,
            path: []const u8,
            t: std.Build.ResolvedTarget,
            opt: std.builtin.OptimizeMode,
            libc: ?bool,
            lib: *std.Build.Module,
        ) *std.Build.Step.Compile {
            return b2.addExecutable(.{
                .name = name,
                .root_module = b2.createModule(.{
                    .root_source_file = b2.path(path),
                    .target = t,
                    .optimize = opt,
                    .link_libc = libc,
                    .imports = &.{.{ .name = "quic", .module = lib }},
                }),
            });
        }
    };

    // Phase 1 apps: self-contained apps that manage their own socket
    // + event loop (no libxev).
    const exe_interop_client_manual = App.add(
        b,
        "interop-client-manual",
        "apps/interop_client_manual.zig",
        target,
        optimize,
        need_libc,
        lib_mod,
    );
    b.installArtifact(exe_interop_client_manual);
    const run_interop_client_manual = b.addRunArtifact(exe_interop_client_manual);
    run_interop_client_manual.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_interop_client_manual.addArgs(args);
    b.step("run-interop-client-manual", "Run interop runner client (manual event loop)")
        .dependOn(&run_interop_client_manual.step);

    const exe_interop_server_manual = App.add(
        b,
        "interop-server-manual",
        "apps/interop_server_manual.zig",
        target,
        optimize,
        need_libc,
        lib_mod,
    );
    b.installArtifact(exe_interop_server_manual);
    const run_interop_server_manual = b.addRunArtifact(exe_interop_server_manual);
    run_interop_server_manual.step.dependOn(b.getInstallStep());
    b.step("run-interop-server-manual", "Run interop runner server (manual event loop)")
        .dependOn(&run_interop_server_manual.step);

    const exe_wt_browser_server_manual = App.add(
        b,
        "wt-browser-server-manual",
        "apps/wt_browser_server_manual.zig",
        target,
        optimize,
        need_libc,
        lib_mod,
    );
    b.installArtifact(exe_wt_browser_server_manual);
    const run_wt_browser_server_manual = b.addRunArtifact(exe_wt_browser_server_manual);
    run_wt_browser_server_manual.step.dependOn(b.getInstallStep());
    b.step("run-wt-browser-server-manual", "Run WebTransport browser server (manual event loop)")
        .dependOn(&run_wt_browser_server_manual.step);

    // C API shared library
    const lib_shared = b.addLibrary(.{
        .linkage = .dynamic,
        .name = "quic-zig",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/c_api.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = need_libc,
            .imports = &.{.{ .name = "quic", .module = lib_mod }},
        }),
    });
    const lib_install = b.addInstallArtifact(lib_shared, .{});
    b.step("lib", "Build C API shared library").dependOn(&lib_install.step);

    // ── Event-loop-based apps ─────────────────────────────────────────────
    const exe_server = App.add(b, "server", "apps/server.zig", target, optimize, need_libc, lib_mod);
    b.installArtifact(exe_server);
    const run_server = b.addRunArtifact(exe_server);
    run_server.step.dependOn(b.getInstallStep());
    b.step("run-server", "Run QUIC server").dependOn(&run_server.step);

    const exe_client = App.add(b, "client", "apps/client.zig", target, optimize, need_libc, lib_mod);
    b.installArtifact(exe_client);
    const run_client = b.addRunArtifact(exe_client);
    run_client.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_client.addArgs(args);
    b.step("run-client", "Run QUIC client").dependOn(&run_client.step);

    const exe_h3_client = App.add(b, "h3-client", "apps/h3_client.zig", target, optimize, need_libc, lib_mod);
    b.installArtifact(exe_h3_client);
    const run_h3_client = b.addRunArtifact(exe_h3_client);
    run_h3_client.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_h3_client.addArgs(args);
    b.step("run-h3-client", "Run H3 client").dependOn(&run_h3_client.step);

    const exe_quic_server = App.add(b, "quic-server", "apps/quic_server.zig", target, optimize, need_libc, lib_mod);
    b.installArtifact(exe_quic_server);
    const run_quic_server = b.addRunArtifact(exe_quic_server);
    run_quic_server.step.dependOn(b.getInstallStep());
    b.step("run-quic-server", "Run raw QUIC echo server").dependOn(&run_quic_server.step);

    const exe_quic_client = App.add(b, "quic-client", "apps/quic_client.zig", target, optimize, need_libc, lib_mod);
    b.installArtifact(exe_quic_client);
    const run_quic_client = b.addRunArtifact(exe_quic_client);
    run_quic_client.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_quic_client.addArgs(args);
    b.step("run-quic-client", "Run raw QUIC echo client").dependOn(&run_quic_client.step);

    const exe_wt_server = App.add(b, "wt-server", "apps/wt_server.zig", target, optimize, need_libc, lib_mod);
    b.installArtifact(exe_wt_server);
    const run_wt_server = b.addRunArtifact(exe_wt_server);
    run_wt_server.step.dependOn(b.getInstallStep());
    b.step("run-wt-server", "Run WebTransport server").dependOn(&run_wt_server.step);

    const exe_wt_client = App.add(b, "wt-client", "apps/wt_client.zig", target, optimize, need_libc, lib_mod);
    b.installArtifact(exe_wt_client);
    const run_wt_client = b.addRunArtifact(exe_wt_client);
    run_wt_client.step.dependOn(b.getInstallStep());
    b.step("run-wt-client", "Run WebTransport client").dependOn(&run_wt_client.step);

    const exe_wt_browser = App.add(b, "wt-browser-server", "apps/wt_browser_server.zig", target, optimize, need_libc, lib_mod);
    b.installArtifact(exe_wt_browser);
    const run_wt_browser = b.addRunArtifact(exe_wt_browser);
    run_wt_browser.step.dependOn(b.getInstallStep());
    b.step("run-wt-browser-server", "Run WebTransport browser server").dependOn(&run_wt_browser.step);

    const exe_moq_relay = App.add(b, "moq-relay", "apps/moq_relay.zig", target, optimize, need_libc, lib_mod);
    b.installArtifact(exe_moq_relay);
    const run_moq_relay = b.addRunArtifact(exe_moq_relay);
    run_moq_relay.step.dependOn(b.getInstallStep());
    if (b.args) |moq_args| run_moq_relay.addArgs(moq_args);
    b.step("run-moq-relay", "Run MoQ Transport relay").dependOn(&run_moq_relay.step);

    const exe_moq_server = App.add(b, "moq-server", "apps/moq_server.zig", target, optimize, need_libc, lib_mod);
    b.installArtifact(exe_moq_server);
    const run_moq_server = b.addRunArtifact(exe_moq_server);
    run_moq_server.step.dependOn(b.getInstallStep());
    if (b.args) |moq_args| run_moq_server.addArgs(moq_args);
    b.step("run-moq-server", "Run MoQ Transport server (raw QUIC)").dependOn(&run_moq_server.step);

    const exe_moq_client = App.add(b, "moq-client", "apps/moq_client.zig", target, optimize, need_libc, lib_mod);
    b.installArtifact(exe_moq_client);
    const run_moq_client = b.addRunArtifact(exe_moq_client);
    run_moq_client.step.dependOn(b.getInstallStep());
    if (b.args) |moq_args| run_moq_client.addArgs(moq_args);
    b.step("run-moq-client", "Run MoQ Transport client (raw QUIC)").dependOn(&run_moq_client.step);

    const exe_moq_browser = App.add(b, "moq-browser-server", "apps/moq_browser_server.zig", target, optimize, need_libc, lib_mod);
    b.installArtifact(exe_moq_browser);
    const run_moq_browser = b.addRunArtifact(exe_moq_browser);
    run_moq_browser.step.dependOn(b.getInstallStep());
    if (b.args) |moq_args| run_moq_browser.addArgs(moq_args);
    b.step("run-moq-browser-server", "Run MoQ Transport browser demo server").dependOn(&run_moq_browser.step);

    const exe_wt_echo = App.add(b, "wt-echo-server", "apps/wt_echo_server.zig", target, optimize, need_libc, lib_mod);
    b.installArtifact(exe_wt_echo);
    const run_wt_echo = b.addRunArtifact(exe_wt_echo);
    run_wt_echo.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_wt_echo.addArgs(args);
    b.step("run-wt-echo-server", "Run WebTransport echo server").dependOn(&run_wt_echo.step);

    const exe_wpt = App.add(b, "wpt-server", "apps/wpt_server.zig", target, optimize, need_libc, lib_mod);
    b.installArtifact(exe_wpt);
    const run_wpt = b.addRunArtifact(exe_wpt);
    run_wpt.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_wpt.addArgs(args);
    b.step("run-wpt-server", "Run WPT WebTransport test server").dependOn(&run_wpt.step);

    const exe_interop_server = App.add(b, "interop-server", "apps/interop_server.zig", target, optimize, need_libc, lib_mod);
    b.installArtifact(exe_interop_server);
    const run_interop_server = b.addRunArtifact(exe_interop_server);
    run_interop_server.step.dependOn(b.getInstallStep());
    b.step("run-interop-server", "Run interop runner server").dependOn(&run_interop_server.step);

    const exe_interop_client = App.add(b, "interop-client", "apps/interop_client.zig", target, optimize, need_libc, lib_mod);
    b.installArtifact(exe_interop_client);
    const run_interop_client = b.addRunArtifact(exe_interop_client);
    run_interop_client.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_interop_client.addArgs(args);
    b.step("run-interop-client", "Run interop runner client").dependOn(&run_interop_client.step);

    const exe_interop_wt_server = App.add(b, "interop-wt-server", "apps/interop_wt_server.zig", target, optimize, need_libc, lib_mod);
    b.installArtifact(exe_interop_wt_server);
    const run_interop_wt_server = b.addRunArtifact(exe_interop_wt_server);
    run_interop_wt_server.step.dependOn(b.getInstallStep());
    b.step("run-interop-wt-server", "Run interop runner WebTransport server").dependOn(&run_interop_wt_server.step);

    const exe_interop_wt_client = App.add(b, "interop-wt-client", "apps/interop_wt_client.zig", target, optimize, need_libc, lib_mod);
    b.installArtifact(exe_interop_wt_client);
    const run_interop_wt_client = b.addRunArtifact(exe_interop_wt_client);
    run_interop_wt_client.step.dependOn(b.getInstallStep());
    b.step("run-interop-wt-client", "Run interop runner WebTransport client").dependOn(&run_interop_wt_client.step);

    // The interop docker image needs these four and nothing else. Building the
    // default step there compiles all 24 apps, which is most of the image's
    // ~18 minute ReleaseSafe build.
    {
        const step = b.step("interop", "Build only the binaries the interop image ships");
        for ([_]*std.Build.Step.Compile{
            exe_interop_server,
            exe_interop_client,
            exe_interop_wt_server,
            exe_interop_wt_client,
        }) |exe| step.dependOn(&b.addInstallArtifact(exe, .{}).step);
    }

    const exe_lb = App.add(b, "quic-lb", "apps/quic_lb.zig", target, optimize, need_libc, lib_mod);
    b.installArtifact(exe_lb);
    const run_lb = b.addRunArtifact(exe_lb);
    run_lb.step.dependOn(b.getInstallStep());
    if (b.args) |args_lb| run_lb.addArgs(args_lb);
    b.step("run-quic-lb", "Run QUIC load balancer").dependOn(&run_lb.step);

    const exe_bench = App.add(b, "bench", "apps/bench.zig", target, optimize, need_libc, lib_mod);
    b.installArtifact(exe_bench);
    const run_bench = b.addRunArtifact(exe_bench);
    run_bench.step.dependOn(b.getInstallStep());
    if (b.args) |args_b| run_bench.addArgs(args_b);
    b.step("run-bench", "Run benchmark client").dependOn(&run_bench.step);

    // Codec microbench — pure CPU (parse/serialize loops), no sockets.
    // Used to track perf of the fixedBufferStream shim vs. std.Io native.
    const exe_bench_codec = App.add(b, "bench-codec", "apps/bench_codec.zig", target, optimize, need_libc, lib_mod);
    b.installArtifact(exe_bench_codec);
    const run_bench_codec = b.addRunArtifact(exe_bench_codec);
    run_bench_codec.step.dependOn(b.getInstallStep());
    b.step("run-bench-codec", "Run codec microbench").dependOn(&run_bench_codec.step);

    // kqueue latency benchmark (raw kqueue vs libxev) — macOS/BSD only
    if (target.result.os.tag == .macos or target.result.os.tag == .freebsd) {
        const exe_bench_kq = b.addExecutable(.{
            .name = "bench-kqueue",
            .root_module = b.createModule(.{
                .root_source_file = b.path("apps/bench_kqueue.zig"),
                .target = target,
                .optimize = optimize,
                .link_libc = need_libc,
                .imports = &.{
                    .{ .name = "quic", .module = lib_mod },
                    .{ .name = "xev", .module = xev_dep.module("xev") },
                },
            }),
        });
        b.installArtifact(exe_bench_kq);
        const run_bench_kq = b.addRunArtifact(exe_bench_kq);
        run_bench_kq.step.dependOn(b.getInstallStep());
        b.step("run-bench-kqueue", "Run kqueue latency benchmark").dependOn(&run_bench_kq.step);
    }

    // Tests
    const exe_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/test_all.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = need_libc,
            .imports = &.{.{ .name = "xev", .module = xev_dep.module("xev") }},
        }),
    });
    const run_tests = b.addRunArtifact(exe_tests);
    b.step("test", "Run unit tests").dependOn(&run_tests.step);

    // Fuzz tests (smoke test: zig build fuzz)
    const exe_fuzz = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/fuzz.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = need_libc,
        }),
    });
    const run_fuzz = b.addRunArtifact(exe_fuzz);
    b.step("fuzz", "Run fuzz tests").dependOn(&run_fuzz.step);
}
