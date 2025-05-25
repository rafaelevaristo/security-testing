#!/bin/bash
set -euo pipefail

if [[ "${1:-}" == "--cron" ]]; then
    shift
    echo "0 2 * * * /app/security_test.sh $* >> /app/logs/cron.log 2>&1" > /tmp/crontab
    crontab /tmp/crontab
    crond -f
else
    exec /app/security_test.sh "$@"
fi