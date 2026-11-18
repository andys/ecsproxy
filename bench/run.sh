#!/bin/bash
# Benchmarks the proxy in front of a hello-world backend with 1000 concurrent `hey` connections.
#
#   bench/run.sh [label] [seconds]     # defaults: the current commit, 20
#   BUILD=0 bench/run.sh <label>       # rerun the binaries an earlier run saved under that label
#
# The proxy runs on one pinned core so it is the bottleneck: requests/s then tracks the proxy's
# cost per request. The backend gets core 1 and hey cores 2-3. A fake ECS endpoint serves one
# task labelled proxy-hostname=bench.local, so the binary runs unmodified.
# Throughput comes from the normal release build; allocations per request come from a second
# build with `--features count-allocs`. Binaries and results land in bench/out/<label>/.
# Needs: cargo, hey, python3, curl, taskset and at least 4 CPUs.
set -euo pipefail
cd "$(dirname "$0")/.."

LABEL=${1:-$(git rev-parse --short HEAD)}
SECS=${2:-20}
OUT=bench/out/$LABEL
URL=http://127.0.0.1:8080/
mkdir -p $OUT
ulimit -n 65536

cargo build --release --example bench-hello
if [ "${BUILD:-1}" = 1 ]; then
    cargo build --release --features count-allocs
    cp target/release/ecsproxy $OUT/ecsproxy-count
    cargo build --release
    cp target/release/ecsproxy $OUT/ecsproxy
fi

if curl -s -o /dev/null $URL; then
    echo "something is already listening on $URL" >&2
    exit 1
fi
# SIGKILL, because SIGTERM would leave the proxy serving through Pingora's graceful shutdown period.
trap 'kill -KILL $(jobs -p) 2>/dev/null || true' EXIT
taskset -c 1 target/release/examples/bench-hello &
python3 bench/fake_ecs.py 9000 &

# Starts a proxy binary on core 0 and waits until it routes to the backend.
start_proxy() {
    AWS_ENDPOINT_URL=http://127.0.0.1:4566 AWS_REGION=us-east-1 AWS_ACCESS_KEY_ID=x \
    AWS_SECRET_ACCESS_KEY=x AWS_EC2_METADATA_DISABLED=true RUST_LOG=info \
    taskset -c 0 "$1" --cluster bench --s3-bucket bench --threads 1 \
        --acme-directory http://127.0.0.1:4566/directory \
        --http-listen 127.0.0.1:8080 --https-listen 127.0.0.1:8443 >"$2" 2>&1 &
    PROXY=$!
    for _ in $(seq 100); do
        [ "$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: bench.local' $URL)" = 200 ] && return
        sleep 0.2
    done
    echo "proxy did not start; see $2" >&2
    exit 1
}

load() {
    taskset -c 2,3 hey -c 1000 -z "$1s" -host bench.local $URL
}

cpu_ticks() {
    awk '{print $14 + $15}' /proc/$PROXY/stat
}

exec > >(tee "$OUT/result.txt")
echo "$LABEL: hey -c 1000 -z ${SECS}s, proxy on 1 thread"
start_proxy $OUT/ecsproxy $OUT/proxy.log
load 5 >/dev/null
for run in 1 2 3; do
    before=$(cpu_ticks)
    load "$SECS" >$OUT/hey.txt
    cpu=$(( ($(cpu_ticks) - before) * 100 / $(getconf CLK_TCK) / SECS ))
    echo "run $run: $(grep Requests/sec $OUT/hey.txt | xargs)," \
        "$(grep -E '^ +(50|99)%' $OUT/hey.txt | xargs)," \
        "$(grep -E '^ +\[[0-9]+\]' $OUT/hey.txt | xargs), proxy cpu $cpu%"
done
echo "peak RSS: $(awk '/VmHWM/ {print $2, $3}' /proc/$PROXY/status)"
kill -KILL $PROXY
wait $PROXY 2>/dev/null || true

start_proxy $OUT/ecsproxy-count $OUT/proxy-count.log
load 12 >/dev/null
sleep 5
echo "allocations: $(grep -ao '[0-9]* requests, .*allocations/request' $OUT/proxy-count.log | sort -n | tail -1)"
