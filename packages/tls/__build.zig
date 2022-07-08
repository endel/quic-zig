const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const lib = b.addStaticLibrary("feilich", "src/feilich.zig");
    lib.setBuildMode(mode);
    lib.install();

    var main_tests = b.addTest("src/feilich.zig");
    main_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);

    const example = b.addExecutable("server", "examples/server.zig");
    example.setBuildMode(mode);
    example.addPackagePath("feilich", "src/feilich.zig");

    const example_run_step = example.run();
    example_run_step.step.dependOn(&example.step);

    const example_cmd_step = b.step("example-server", "Sets up an example tls 1.3 http server");
    example_cmd_step.dependOn(&example_run_step.step);
}
