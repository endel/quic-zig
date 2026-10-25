// How an expect_fail note is matched to the browser running: per engine, and
// per version range. Plain ES module with no Node imports, so the hand-run page
// (interop/browser/wpt-tests.html) uses it as the automated runner does.

/// Dotted version parts, compared part by part with missing ones as 0: so
/// '27' == '27.0' and '26.4' < '26.10'.
function compareVersions(a, b) {
  const pa = String(a).split('.').map(Number);
  const pb = String(b).split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

/// Whether `version` is in `range`: '*', 'N', '<N', '<=N', '>N', '>=N' or
/// 'N-M', inclusive. A bare major ('148') matches every 148.x; so does each
/// end of 'N-M'.
export function versionInRange(version, range) {
  if (range === '*') return true;
  const v = String(version);
  const op = range.match(/^(<=|>=|<|>)(.+)$/);
  if (op) {
    const d = compareVersions(v, op[2]);
    return { '<': d < 0, '<=': d <= 0 || sameRelease(v, op[2]), '>': d > 0 && !sameRelease(v, op[2]), '>=': d >= 0 }[op[1]];
  }
  const span = range.match(/^([\d.]+)-([\d.]+)$/);
  if (span) return (compareVersions(v, span[1]) >= 0) && (compareVersions(v, span[2]) <= 0 || sameRelease(v, span[2]));
  return sameRelease(v, range);
}

/// `v` is release `r` or a later build of it: 148.0.2 is 148, 26.4.1 is 26.4.
function sameRelease(v, r) {
  const pv = v.split('.');
  const pr = r.split('.');
  return pr.every((part, i) => Number(pv[i] ?? 0) === Number(part));
}

/// The known failure, if any, of `scenario` on `engine` at `version`. With no
/// version known, only a '*' note applies.
export function expectFailFor(scenario, engine, version) {
  const notes = scenario.expect_fail?.[engine] ?? [];
  const hit = notes.find((n) => (version ? versionInRange(version, n.versions) : n.versions === '*'));
  return hit ? `${engine} ${hit.versions}: ${hit.why}` : null;
}
