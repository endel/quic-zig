#!/bin/sh
# moq-interop-runner client contract: env in, flags out.
# https://github.com/englishm/moq-interop-runner/blob/main/docs/TEST-CLIENT-INTERFACE.md
#
# Any args given to the container are appended, so `docker run <image> --list`
# still works; the flags win over the env because they come last.
set -eu

FLAGS=""
[ -n "${RELAY_URL:-}" ] && FLAGS="$FLAGS --relay $RELAY_URL"
[ -n "${TESTCASE:-}" ] && FLAGS="$FLAGS --test $TESTCASE"
case "${TLS_DISABLE_VERIFY:-}" in 1|true) FLAGS="$FLAGS --tls-disable-verify" ;; esac
case "${VERBOSE:-}" in 1|true) FLAGS="$FLAGS --verbose" ;; esac

# shellcheck disable=SC2086 # FLAGS is built from values without whitespace
exec /app/moq-test-client $FLAGS "$@"
