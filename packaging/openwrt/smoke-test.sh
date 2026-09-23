#!/bin/sh
# Run only inside the disposable CI OpenWrt container.
set -eu
mkdir -p /var/lock /var/run
opkg update
opkg install /packages/fakeflow_*.ipk
test "$(uci -q get fakeflow.main.enabled)" = 0
fakeflow validate --config /etc/fakeflow.toml
sed -i 's/name = "eth1"/name = "eth0"/' /etc/fakeflow.toml
fakeflow check --config /etc/fakeflow.toml
fakeflow run --config /etc/fakeflow.toml >/tmp/fakeflow.log 2>&1 &
daemon=$!
trap 'kill "$daemon" 2>/dev/null || true; cat /tmp/fakeflow.log' EXIT
ready=0
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if fakeflow status; then ready=1; break; fi
    kill -0 "$daemon"
    sleep 1
done
test "$ready" = 1
fakeflow stats --json
fakeflow stop
wait "$daemon"
test -z "$(tc filter show dev eth0 ingress)"
test -z "$(tc filter show dev eth0 egress)"
echo 'OpenWrt IPK install, configuration, BPF load, TC attach and cleanup passed.'
