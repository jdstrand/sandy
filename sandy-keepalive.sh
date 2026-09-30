#!/bin/bash
# Keep the container's PID 2 alive until poweroff (SIGTERM or SIGHUP).
trap 'kill "$!" 2>/dev/null; exit 0' TERM HUP
while :; do
    sleep infinity &
    wait "$!"
    rc=$?
    # Restart sleep only if a signal killed it; fail closed otherwise.
    [ "$rc" -gt 128 ] || exit "$rc"
done
