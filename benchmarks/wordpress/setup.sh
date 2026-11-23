#!/bin/bash
# Real WordPress (SQLite, PHP's built-in server) for the Aegis lab. Needs php (pdo_sqlite), git.
# Usage: benchmarks/wordpress/setup.sh [LAB_DIR]   (default /tmp/wplab)
set -euo pipefail
LAB=${1:-/tmp/wplab}
mkdir -p "$LAB" && cd "$LAB"
[ -d wp-src ] || git clone -q --depth 1 https://github.com/WordPress/WordPress.git wp-src
[ -d wp-sqlite ] || git clone -q --depth 1 https://github.com/WordPress/sqlite-database-integration.git wp-sqlite
[ -d site ] || cp -r wp-src site
P=site/wp-content/plugins/sqlite-database-integration
if [ ! -d "$P" ]; then
  cp -r wp-sqlite/packages/plugin-sqlite-database-integration "$P"
  rm -f "$P/wp-includes/database" && cp -r wp-sqlite/packages/mysql-on-sqlite/src "$P/wp-includes/database"
  cp "$P/db.copy" site/wp-content/db.php
  sed -i "s#'{SQLITE_IMPLEMENTATION_FOLDER_PATH}'#__DIR__.'/plugins/sqlite-database-integration'#g; s#{SQLITE_PLUGIN}#sqlite-database-integration/load.php#g" site/wp-content/db.php
fi
mkdir -p data
if [ ! -f site/wp-config.php ]; then
  cp site/wp-config-sample.php site/wp-config.php
  python3 - "$LAB" <<'PY'
import secrets, sys
from pathlib import Path
lab = sys.argv[1]
p = Path(lab) / "site/wp-config.php"; s = p.read_text()
s = s.replace("define( 'DB_NAME', 'database_name_here' );",
              f"define( 'DB_NAME', 'wp' );\ndefine( 'DB_DIR', '{lab}/data/' );\ndefine( 'DB_FILE', 'wp.sqlite' );\n"
              "define( 'AUTOMATIC_UPDATER_DISABLED', true );\ndefine( 'WP_HTTP_BLOCK_EXTERNAL', true );")
s = s.replace("'put your unique phrase here'", "'%s'")
s = s % tuple(f"{secrets.token_hex(24)}" for _ in range(s.count("%s")))
p.write_text(s)
PY
fi
grep -q "wp.localhost" /etc/hosts 2>/dev/null || echo "add '127.0.0.1 wp.localhost' to /etc/hosts for the attack script"
echo "ready: $LAB"
