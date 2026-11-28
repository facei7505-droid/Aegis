#!/bin/bash
# 1C-Bitrix lab: PHP's built-in server with Bitrix on :8093, Aegis Gateway on :8092 in front, then run a command.
# usage: lab.sh <block|monitor> <log-dir> '<shield options JSON>' <command...>
# env: AEGIS_LAB_SECRET=<hex> signs requests to Bitrix; AEGIS_LAB_CONNECTOR=1 trusts editors only by the
#      connector's signed pass. BX_SITE: the Bitrix folder (default /tmp/bxlab/site).
set -u
REPO=$(cd "$(dirname "$0")/../.." && pwd)
MODE=$1; LOGS=$2; OPTS=$3; shift 3
bash "$REPO/benchmarks/bitrix/php.sh" "${BX_SITE:-/tmp/bxlab/site}" > /dev/null
pkill -f "aegis_bx_gateway" ; sleep 1
mkdir -p "$LOGS"
(nohup python3 - "$MODE" "$LOGS" "$OPTS" aegis_bx_gateway > /tmp/bxlab/gw.log 2>&1 <<PY &
import json, os, sys, time
sys.path.insert(0, "$REPO")
from aegis.gateway import AppSpec, Gateway, serve
mode, logdir, options = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
secret = os.environ.get("AEGIS_LAB_SECRET") or None
if secret and os.environ.get("AEGIS_LAB_CONNECTOR"):
    options["editor_secret"] = secret
spec = AppSpec("bx", "http://127.0.0.1:8093", ["bx.localhost"], shield=mode, heal="off", preserve_host=True,
               options=options, origin_secret=secret)
serve(Gateway([spec], log_dir=logdir), 8092)
while True:
    time.sleep(3600)
PY
)
sleep 3
"$@"
