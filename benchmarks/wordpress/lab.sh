#!/bin/bash
# Start WordPress (PHP :8091) and Aegis Gateway (:8090) in front of it, then run a command.
# usage: lab.sh <db-file> <block|monitor> <log-dir> '<shield options JSON>' <command...>
# env: AEGIS_LAB_SECRET=<hex> signs requests to WordPress; AEGIS_LAB_CONNECTOR=1 also trusts editors only by
#      the connector's signed pass (render it with aegis.edge.connector.render("wordpress", secret) into
#      wp-content/mu-plugins/)
# example: lab.sh wp.sqlite block /tmp/wplab/logs '{"preset":"wordpress","login_limit":10,"rate_limit":300}' \
#            python3 benchmarks/wordpress/session.py http://wp.localhost:8090 install
set -u
LAB=${WPLAB:-/tmp/wplab}
REPO=$(cd "$(dirname "$0")/../.." && pwd)
DB=$1; MODE=$2; LOGS=$3; OPTS=$4; shift 4
sed -i "s/define( 'DB_FILE', '[^']*' );/define( 'DB_FILE', '$DB' );/" "$LAB/site/wp-config.php"
pkill -f "php -S 127.0.0.1:8091" ; pkill -f "aegis_wp_gateway" ; sleep 1
(cd "$LAB" && PHP_CLI_SERVER_WORKERS=8 nohup php -S 127.0.0.1:8091 -t site > php.log 2>&1 &)
mkdir -p "$LOGS"
(nohup python3 - "$MODE" "$LOGS" "$OPTS" aegis_wp_gateway > "$LAB/gw.log" 2>&1 <<PY &
import json, os, sys, time
sys.path.insert(0, "$REPO")
from aegis.gateway import AppSpec, Gateway, serve
mode, logdir, options = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
secret = os.environ.get("AEGIS_LAB_SECRET") or None  # with the connector in mu-plugins: origin lock + editor pass
if secret and os.environ.get("AEGIS_LAB_CONNECTOR"):
    options["editor_secret"] = secret
spec = AppSpec("wp", "http://127.0.0.1:8091", ["wp.localhost"], shield=mode, heal="off", preserve_host=True,
               options=options, origin_secret=secret)
serve(Gateway([spec], log_dir=logdir), 8090)
while True:
    time.sleep(3600)
PY
)
sleep 3
"$@"
