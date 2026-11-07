#!/data/data/com.termux/files/usr/bin/bash
set -eu
cd /data/data/com.termux/files/home/poco-agent
mkdir -p logs
exec 9>agent.lock
if ! flock -w 30 9; then exit 0; fi
termux-wake-lock
trap 'termux-wake-unlock' EXIT
qa_restarts=0
while true; do
  if python core.py >>logs/agent.log 2>&1; then break; else qa_exit=$?; fi
  qa_restarts=$((qa_restarts + 1))
  if [ "$qa_restarts" -ge 3 ]; then exit "$qa_exit"; fi
  sleep "$((qa_restarts * 2))"
done
