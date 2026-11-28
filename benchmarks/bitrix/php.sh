#!/bin/bash
# Start 1C-Bitrix on PHP's built-in server (:8093) for the lab. usage: php.sh <site dir>
SITE=${1:-/tmp/bxlab/site}
HERE=$(cd "$(dirname "$0")" && pwd)
pkill -f "php .*-S 127.0.0.1:8093" ; sleep 1
mkdir -p /tmp/bxlab/sessions
cd "$SITE" && PHP_CLI_SERVER_WORKERS=8 nohup php \
  -d memory_limit=512M -d max_input_vars=10000 -d max_execution_time=300 -d post_max_size=64M \
  -d upload_max_filesize=64M -d date.timezone=Asia/Almaty -d default_charset=UTF-8 \
  -d opcache.enable=1 -d opcache.revalidate_freq=0 -d opcache.validate_timestamps=1 -d opcache.max_accelerated_files=100000 \
  -d session.save_path=/tmp/bxlab/sessions -d realpath_cache_size=4096K -d short_open_tag=On \
  -S 127.0.0.1:8093 -t "$SITE" "$HERE/router.php" > /tmp/bxlab/php.log 2>&1 &
sleep 2
curl -s -o /dev/null -w "bitrix php: %{http_code}\n" -H "Host: bx.localhost:8092" http://127.0.0.1:8093/
