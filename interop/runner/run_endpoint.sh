#!/bin/bash
set -e

# Setup routing for the simulated network
source /setup.sh

# Determine if this is a WebTransport test case
is_wt_test() {
    case "$TESTCASE" in
        handshake|transfer|transfer-unidirectional-*|transfer-bidirectional-*|transfer-datagram-*)
            # These are WT test names; check if WT binaries exist (i.e., we're in WT mode)
            # The interop runner sets TESTCASE differently for QUIC vs WT tests.
            # For WT, the runner uses the wt docker-compose which passes WT-specific env vars.
            # We detect WT mode by checking if PROTOCOLS env var is set (only WT tests set it).
            if [ -n "$PROTOCOLS" ]; then
                return 0
            fi
            return 1
            ;;
        *)
            return 1
            ;;
    esac
}

if [ "$ROLE" == "client" ]; then
    # Wait for the simulated network to be ready
    /wait-for-it.sh sim:57832 -s -t 30
    if is_wt_test; then
        echo "Starting quic-zig WT client (testcase=$TESTCASE)"
        exec interop-wt-client $REQUESTS
    else
        echo "Starting quic-zig client (testcase=$TESTCASE)"
        exec interop-client $REQUESTS
    fi
elif [ "$ROLE" == "server" ]; then
    if is_wt_test; then
        echo "Starting quic-zig WT server (testcase=$TESTCASE)"
        exec interop-wt-server
    else
        echo "Starting quic-zig server (testcase=$TESTCASE)"
        exec interop-server
    fi
else
    echo "Unknown role: $ROLE"
    exit 127
fi
