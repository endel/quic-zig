const std = @import("std");

const Builder = std.build.Builder;
const print = std.debug.print;

pub fn build(b: *Builder) void {
  const mode = b.standardReleaseOptions();

//   const exe = b.addExecutable("main", "src/threading.zig");
  const exe = b.addExecutable("main", "src/udp.zig");
  exe.setBuildMode(mode);

  exe.valgrind_support = true;
  exe.strip = false;
  const run_cmd = exe.run();

  const run_step = b.step("run", "Run the app");
  run_step.dependOn(&run_cmd.step);

  b.default_step.dependOn(&exe.step);
  b.installArtifact(exe);
}
