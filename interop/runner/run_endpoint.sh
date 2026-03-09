#!/bin/bash
set -e

# Setup routing for the simulated network
source /setup.sh

if [ "$ROLE" == "client" ]; then
    # Wait for the simulated network to be ready
    /wait-for-it.sh sim:57832 -s -t 30
    echo "Starting quic-zig client (testcase=$TESTCASE)"
    # REQUESTS is a space-separated list of URLs; pass each as a CLI arg
    exec interop-client $REQUESTS
elif [ "$ROLE" == "server" ]; then
    echo "Starting quic-zig server (testcase=$TESTCASE)"
    exec interop-server
else
    echo "Unknown role: $ROLE"
    exit 127
fi
