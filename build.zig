const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe_server = b.addExecutable(.{
        .name = "server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/server.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(exe_server);

    const exe_client = b.addExecutable(.{
        .name = "client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/client.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(exe_client);

    const run_server = b.addRunArtifact(exe_server);
    run_server.step.dependOn(b.getInstallStep());
    const run_server_step = b.step("run-server", "Run QUIC server");
    run_server_step.dependOn(&run_server.step);

    const run_client = b.addRunArtifact(exe_client);
    run_client.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_client.addArgs(args);
    }
    const run_client_step = b.step("run-client", "Run QUIC client");
    run_client_step.dependOn(&run_client.step);

    const exe_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/server.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const run_tests = b.addRunArtifact(exe_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
}
