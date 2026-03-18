const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Link libc on platforms that need it (Linux requires explicit libc for std.c.recvmsg).
    const need_libc: ?bool = if (target.result.os.tag == .windows) null else true;

    // libxev dependency (used by event-loop-based servers)
    const xev_dep = b.dependency("libxev", .{ .target = target, .optimize = optimize });

    // Library module — shared by all apps and exposed to downstream dependencies
    const lib_mod = b.addModule("quic", .{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = need_libc,
        .imports = &.{.{ .name = "xev", .module = xev_dep.module("xev") }},
    });

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

    // Server
    const exe_server = App.add(b, "server", "apps/server.zig", target, optimize, need_libc, lib_mod);
    b.installArtifact(exe_server);
    const run_server = b.addRunArtifact(exe_server);
    run_server.step.dependOn(b.getInstallStep());
    b.step("run-server", "Run QUIC server").dependOn(&run_server.step);

    // Client
    const exe_client = App.add(b, "client", "apps/client.zig", target, optimize, need_libc, lib_mod);
    b.installArtifact(exe_client);
    const run_client = b.addRunArtifact(exe_client);
    run_client.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_client.addArgs(args);
    b.step("run-client", "Run QUIC client").dependOn(&run_client.step);

    // WebTransport server
    const exe_wt_server = App.add(b, "wt-server", "apps/wt_server.zig", target, optimize, need_libc, lib_mod);
    b.installArtifact(exe_wt_server);
    const run_wt_server = b.addRunArtifact(exe_wt_server);
    run_wt_server.step.dependOn(b.getInstallStep());
    b.step("run-wt-server", "Run WebTransport server").dependOn(&run_wt_server.step);

    // WebTransport client
    const exe_wt_client = App.add(b, "wt-client", "apps/wt_client.zig", target, optimize, need_libc, lib_mod);
    b.installArtifact(exe_wt_client);
    const run_wt_client = b.addRunArtifact(exe_wt_client);
    run_wt_client.step.dependOn(b.getInstallStep());
    b.step("run-wt-client", "Run WebTransport client").dependOn(&run_wt_client.step);

    // WebTransport browser server
    const exe_wt_browser = App.add(b, "wt-browser-server", "apps/wt_browser_server.zig", target, optimize, need_libc, lib_mod);
    b.installArtifact(exe_wt_browser);
    const run_wt_browser = b.addRunArtifact(exe_wt_browser);
    run_wt_browser.step.dependOn(b.getInstallStep());
    b.step("run-wt-browser-server", "Run WebTransport browser server").dependOn(&run_wt_browser.step);

    // WebTransport echo server (production deployment)
    const exe_wt_echo = App.add(b, "wt-echo-server", "apps/wt_echo_server.zig", target, optimize, need_libc, lib_mod);
    b.installArtifact(exe_wt_echo);
    const run_wt_echo = b.addRunArtifact(exe_wt_echo);
    run_wt_echo.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_wt_echo.addArgs(args);
    b.step("run-wt-echo-server", "Run WebTransport echo server").dependOn(&run_wt_echo.step);

    // WPT (Web Platform Tests) WebTransport server
    const exe_wpt = App.add(b, "wpt-server", "apps/wpt_server.zig", target, optimize, need_libc, lib_mod);
    b.installArtifact(exe_wpt);
    const run_wpt = b.addRunArtifact(exe_wpt);
    run_wpt.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_wpt.addArgs(args);
    b.step("run-wpt-server", "Run WPT WebTransport test server").dependOn(&run_wpt.step);

    // Interop runner server
    const exe_interop_server = App.add(b, "interop-server", "apps/interop_server.zig", target, optimize, need_libc, lib_mod);
    b.installArtifact(exe_interop_server);
    const run_interop_server = b.addRunArtifact(exe_interop_server);
    run_interop_server.step.dependOn(b.getInstallStep());
    b.step("run-interop-server", "Run interop runner server").dependOn(&run_interop_server.step);

    // Interop runner client
    const exe_interop_client = App.add(b, "interop-client", "apps/interop_client.zig", target, optimize, need_libc, lib_mod);
    b.installArtifact(exe_interop_client);
    const run_interop_client = b.addRunArtifact(exe_interop_client);
    run_interop_client.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_interop_client.addArgs(args);
    b.step("run-interop-client", "Run interop runner client").dependOn(&run_interop_client.step);

    // Interop runner WebTransport server
    const exe_interop_wt_server = App.add(b, "interop-wt-server", "apps/interop_wt_server.zig", target, optimize, need_libc, lib_mod);
    b.installArtifact(exe_interop_wt_server);
    const run_interop_wt_server = b.addRunArtifact(exe_interop_wt_server);
    run_interop_wt_server.step.dependOn(b.getInstallStep());
    b.step("run-interop-wt-server", "Run interop runner WebTransport server").dependOn(&run_interop_wt_server.step);

    // Interop runner WebTransport client
    const exe_interop_wt_client = App.add(b, "interop-wt-client", "apps/interop_wt_client.zig", target, optimize, need_libc, lib_mod);
    b.installArtifact(exe_interop_wt_client);
    const run_interop_wt_client = b.addRunArtifact(exe_interop_wt_client);
    run_interop_wt_client.step.dependOn(b.getInstallStep());
    b.step("run-interop-wt-client", "Run interop runner WebTransport client").dependOn(&run_interop_wt_client.step);

    // QUIC Load Balancer
    const exe_lb = App.add(b, "quic-lb", "apps/quic_lb.zig", target, optimize, need_libc, lib_mod);
    b.installArtifact(exe_lb);
    const run_lb = b.addRunArtifact(exe_lb);
    run_lb.step.dependOn(b.getInstallStep());
    if (b.args) |args_lb| run_lb.addArgs(args_lb);
    b.step("run-quic-lb", "Run QUIC load balancer").dependOn(&run_lb.step);

    // Benchmark
    const exe_bench = App.add(b, "bench", "apps/bench.zig", target, optimize, need_libc, lib_mod);
    b.installArtifact(exe_bench);
    const run_bench = b.addRunArtifact(exe_bench);
    run_bench.step.dependOn(b.getInstallStep());
    if (b.args) |args_b| run_bench.addArgs(args_b);
    b.step("run-bench", "Run benchmark client").dependOn(&run_bench.step);

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
            .imports = &.{.{ .name = "xev", .module = xev_dep.module("xev") }},
        }),
    });
    const run_fuzz = b.addRunArtifact(exe_fuzz);
    b.step("fuzz", "Run fuzz tests").dependOn(&run_fuzz.step);
}
