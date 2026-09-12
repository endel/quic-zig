// Node-side view of the shared conformance suite: the manifest read off disk,
// plus the scenario bodies from bodies.mjs.
//
// The scenario list lives in scenarios.json and is the authority. Both runners —
// this one and apps/wpt_client.zig — refuse to start unless they implement
// exactly that list, so a scenario cannot quietly exist on only one side.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

export { BODIES } from './bodies.mjs';
import { BODIES } from './bodies.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

export const MANIFEST = JSON.parse(
  readFileSync(join(HERE, 'scenarios.json'), 'utf8'),
).scenarios;

/// Fail loudly when the manifest and the bodies disagree, rather than silently
/// running a subset.
export function assertComplete() {
  const wanted = MANIFEST.filter((s) => s.runners.some((r) => r !== 'zig')).map((s) => s.id);
  const have = new Set(Object.keys(BODIES));
  const missing = wanted.filter((id) => !have.has(id));
  const extra = [...have].filter((id) => !wanted.includes(id));
  if (missing.length || extra.length) {
    throw new Error(
      'scenarios.mjs is out of step with scenarios.json' +
        (missing.length ? `\n  missing bodies: ${missing.join(', ')}` : '') +
        (extra.length ? `\n  bodies with no manifest entry: ${extra.join(', ')}` : ''),
    );
  }
}

/// Technology Preview is the same engine as Safari, so it runs the same
/// scenarios — but it gets its own `expect_fail` key (looked up by the runner),
/// deliberately empty, so a gap the preview has closed shows up as XPASS
/// instead of being masked by the release browser's notes.
const ENGINE_BASE = { 'safari-preview': 'safari' };

export function scenariosFor(runner) {
  const base = ENGINE_BASE[runner] ?? runner;
  return MANIFEST.filter((s) => s.runners.includes(base));
}
