#!/bin/bash
set -u
X="$PWD/target/debug/xtrace"
ls "$X" || cargo build -p xtrace-cli
W=$(mktemp -d "$TMPDIR/expd.XXXX"); mkdir -p $W/repo; export XTRACE_DATA_HOME=$W/data
"$X" init --project-dir $W/repo
cd adapters/node/examples/express4-app
ts(){ python3 -c 'import time;print(round(time.time()%1000,2))'; }
echo "t0 $(ts)"
APP_PORT=18431 "$X" run --project-dir $W/repo --node-adapter $PWD/../../packages/adapter-core/dist --node-mode cjs -- node --no-warnings app.js > $W/out.log 2> $W/err.log &
P=$!
for i in $(seq 1 100); do grep -q EXPRESS_READY $W/out.log && break; sleep 0.2; done
echo "ready $(ts)"
for t in / /done; do curl -s -o /dev/null -w "%{http_code} " http://127.0.0.1:18431$t; done; echo
echo "sent done $(ts)"
for i in $(seq 1 40); do
  kill -0 $P 2>/dev/null || { echo "xtrace exited at $(ts)"; break; }
  if [ $i = 3 ] || [ $i = 6 ]; then echo "== t=$i $(ts)"; sample $P 1 -file $W/sample$i.txt >/dev/null 2>&1; sed -n '/Sort by top of stack/,$p' $W/sample$i.txt | cut -c1-200 | head -25; grep -n -E "spawn|posix_spawn|fork" $W/sample$i.txt | head -5; grep -E "^ +\+ +[! :|]*[0-9]+ .*xtrace_(store|private_storage)" $W/sample$i.txt | sed -E 's/\(in xtrace\).*//' | cut -c1-260 | sort -t' ' -k1 | head -0; fi
  sleep 1
done
cat $W/out.log; tail -20 $W/err.log
