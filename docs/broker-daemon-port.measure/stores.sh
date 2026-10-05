#!/bin/sh
# Read-only census of ~/.agent-broker/state/*/broker.sqlite (SQLite read-only URI).
cd "$HOME/.agent-broker/state" || exit 1
echo "project|missions|open_work_items|jobs|non_terminal_jobs|open_questions|db_KB"
for d in */; do d=${d%/}; f=$d/broker.sqlite; [ -f "$f" ] || { echo "$d|no store"; continue; }
  echo "$d|$(sqlite3 "file:$f?mode=ro" "select (select count(*) from missions),(select count(*) from work_items where closed_at is null),(select count(*) from jobs),(select count(*) from jobs where state not in ('completed','rejected','failed','timed_out','cancelled','orphaned')),(select count(*) from work_questions where answered_at is null and withdrawn_at is null);")|$(du -k "$f" | cut -f1)"
done
echo "--- jobs by provider/adapter, all stores"
for d in */; do f=${d%/}/broker.sqlite; [ -f "$f" ] && sqlite3 "file:$f?mode=ro" "select coalesce(worker_provider,'-')||'/'||adapter, count(*) from jobs group by 1"; done | awk -F'|' '{c[$1]+=$2} END{for(k in c) print k, c[k]}' | sort
