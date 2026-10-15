'use strict';

// Single entry point for entitlement checks.
//
// v1 distribution is a private GitHub repo: anyone who can run
// `npx github:getsecuritykit/kit` already has access, so this is a no-op.
// When license keys arrive, verify the key here (and only here). Every command
// calls this before doing any work. Keep it free of telemetry: send only the key,
// never project paths or source code.
async function checkEntitlement(/* command, { projectDir } */) {
  return { ok: true };
}

module.exports = { checkEntitlement };
