#!/bin/sh
set -eu

ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
SERVICE="$ROOT/module/service.sh"
TMP=${TMPDIR:-/tmp}/tsoss-supervisor-test.$$
lock_owner=
trap 'if [ -n "$lock_owner" ]; then kill "$lock_owner" 2>/dev/null || true; fi; rm -rf "$TMP"' EXIT HUP INT TERM
mkdir -p "$TMP"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

run_case() {
  name=$1
  shift
  dir="$TMP/$name"
  mkdir -p "$dir"
  cp "$SERVICE" "$dir/service.sh"
  cat > "$dir/daemon" <<'MOCK'
#!/bin/sh
printf '%s\n' "$*" >> "$MOCK_LOG"
MOCK_COUNT=$(wc -l < "$MOCK_LOG")
case "$MOCK_MODE:$MOCK_COUNT" in
  nonzero:*) exit 7 ;;
  zero:*) exit 0 ;;
  reset:1|reset:2) exit 7 ;;
  reset:3) sleep 2; exit 7 ;;
  reset:*) exit 7 ;;
esac
MOCK
  chmod +x "$dir/daemon"
  export MOCK_LOG="$dir/invocations" MOCK_MODE="$1"
  shift
  : > "$MOCK_LOG"
  set +e
  (cd "$dir" && env TSOSS_SUPERVISOR_MAX_FAILURES="${MAX_FAILURES:-3}" \
    TSOSS_SUPERVISOR_STABILITY_SECONDS="${STABILITY_SECONDS:-2}" \
    TSOSS_SUPERVISOR_BACKOFF_MAX=1 "$@" sh ./service.sh) > "$dir/log" 2>&1
  result=$?
  set -e
  count=$(wc -l < "$MOCK_LOG" | tr -d ' ')
  printf '%s %s %s\n' "$result" "$count" "$dir"
}

run_foreground() {
  name=$1 mode=$2 failures=$3 stable=$4
  dir="$TMP/$name"
  mkdir -p "$dir"
  cp "$SERVICE" "$dir/service.sh"
  cat > "$dir/daemon" <<'MOCK'
#!/bin/sh
printf '%s\n' "$*" >> "$MOCK_LOG"
MOCK_COUNT=$(wc -l < "$MOCK_LOG")
case "$MOCK_MODE:$MOCK_COUNT" in
  nonzero:*) exit 7 ;;
  zero:*) exit 0 ;;
  reset:1|reset:2) exit 7 ;;
  reset:3) sleep 2; exit 7 ;;
  reset:*) exit 7 ;;
esac
MOCK
  chmod +x "$dir/daemon"
  export MOCK_LOG="$dir/invocations" MOCK_MODE="$mode"
  : > "$MOCK_LOG"
  set +e
  (cd "$dir" && TSOSS_SUPERVISOR_MAX_FAILURES="$failures" \
    TSOSS_SUPERVISOR_STABILITY_SECONDS="$stable" TSOSS_SUPERVISOR_BACKOFF_MAX=1 \
    TSOSS_SUPERVISOR_FOREGROUND=true sh ./service.sh --worker) > "$dir/log" 2>&1
  result=$?
  set -e
  count=$(wc -l < "$MOCK_LOG" | tr -d ' ')
  printf '%s %s %s\n' "$result" "$count" "$dir"
}

read_result() {
  result=$1
  printf '%s' "$result" | cut -d ' ' -f1
}
read_count() {
  result=$1
  printf '%s' "$result" | cut -d ' ' -f2
}
read_dir() {
  result=$1
  printf '%s' "$result" | cut -d ' ' -f3
}

nonzero=$(run_foreground nonzero nonzero 3 2)
[ "$(read_result "$nonzero")" -ne 0 ] || fail "nonzero exits should exhaust the budget"
[ "$(read_count "$nonzero")" -eq 3 ] || fail "expected exactly 3 nonzero daemon invocations"
grep -q 'failure budget exhausted' "$(read_dir "$nonzero")/log" || fail "missing exhaustion log"

zero=$(run_foreground zero zero 3 2)
[ "$(read_result "$zero")" -ne 0 ] || fail "exit 0 should not restart forever"
[ "$(read_count "$zero")" -eq 3 ] || fail "exit 0 should consume the finite failure budget"

reset=$(run_foreground reset reset 3 2)
[ "$(read_result "$reset")" -ne 0 ] || fail "post-stability failures should eventually exhaust"
[ "$(read_count "$reset")" -eq 6 ] || fail "stable run should reset the failure budget (expected 6 invocations)"
grep -q 'stability reset' "$(read_dir "$reset")/log" || fail "missing stability reset log"

# A live supervisor owner prevents an additional daemon from starting.
mkdir -p "$TMP/locked"
cp "$SERVICE" "$TMP/locked/service.sh"
cat > "$TMP/locked/daemon" <<'MOCK'
#!/bin/sh
printf '%s\n' "$$" > "$LOCKED_DAEMON_PID"
exec sleep 60
MOCK
chmod +x "$TMP/locked/daemon"
export LOCKED_DAEMON_PID="$TMP/locked/daemon.pid"
(cd "$TMP/locked" && TSOSS_SUPERVISOR_FOREGROUND=true sh ./service.sh --worker) > "$TMP/locked/log" 2>&1 &
lock_owner=$!
waited=0
while [ ! -e "$TMP/locked/.service.lock/starttime" ] && [ "$waited" -lt 5 ]; do
  sleep 1
  waited=$((waited + 1))
done
[ -e "$TMP/locked/.service.lock/starttime" ] || fail "live supervisor did not write identity"
[ -s "$LOCKED_DAEMON_PID" ] || fail "live supervisor did not start daemon"
(cd "$TMP/locked" && sh ./service.sh) >/dev/null 2>&1
[ -e "$TMP/locked/.service.lock" ] || fail "contending supervisor removed live lock"
rm -f "$TMP/locked/.service.lock/boot_id" "$TMP/locked/.service.lock/starttime"
(cd "$TMP/locked" && sh ./service.sh) >/dev/null 2>&1
[ -e "$TMP/locked/.service.lock" ] || fail "legacy live supervisor lock was not preserved"
kill -TERM "$lock_owner" 2>/dev/null || true
kill -TERM "$(cat "$LOCKED_DAEMON_PID")" 2>/dev/null || true
wait "$lock_owner" 2>/dev/null || true
lock_owner=

# A live unrelated PID must not block a new supervisor when its legacy lock is stale.
mkdir -p "$TMP/reused"
cp "$SERVICE" "$TMP/reused/service.sh"
cat > "$TMP/reused/daemon" <<'MOCK'
#!/bin/sh
exit 99
MOCK
chmod +x "$TMP/reused/daemon"
sleep 60 &
unrelated_pid=$!
mkdir -p "$TMP/reused/.service.lock"
printf '%s\n' "$unrelated_pid" > "$TMP/reused/.service.lock/pid"
set +e
(cd "$TMP/reused" && TSOSS_SUPERVISOR_MAX_FAILURES=1 TSOSS_SUPERVISOR_FOREGROUND=true sh ./service.sh --worker) > "$TMP/reused/log" 2>&1
reused_status=$?
set -e
kill "$unrelated_pid" 2>/dev/null || true
[ "$reused_status" -ne 0 ] || fail "live unrelated legacy PID should be reclaimed and daemon should exhaust"
[ ! -e "$TMP/reused/.service.lock" ] || fail "reclaimed legacy lock was not released"

# Matching PID and boot ID with a different start time is a reused PID, not an owner.
mkdir -p "$TMP/mismatch/.service.lock"
cp "$SERVICE" "$TMP/mismatch/service.sh"
cat > "$TMP/mismatch/daemon" <<'MOCK'
#!/bin/sh
exit 99
MOCK
chmod +x "$TMP/mismatch/daemon"
current_boot_id=$(cat /proc/sys/kernel/random/boot_id)
current_starttime=$(awk '{ sub(/^.*\\) /, ""); print $20 }' /proc/$$/stat)
printf '%s\n' "$$" > "$TMP/mismatch/.service.lock/pid"
printf '%s\n' "$current_boot_id" > "$TMP/mismatch/.service.lock/boot_id"
printf '%s\n' "${current_starttime}0" > "$TMP/mismatch/.service.lock/starttime"
set +e
(cd "$TMP/mismatch" && TSOSS_SUPERVISOR_MAX_FAILURES=1 TSOSS_SUPERVISOR_FOREGROUND=true sh ./service.sh --worker) > "$TMP/mismatch/log" 2>&1
mismatch_status=$?
set -e
[ "$mismatch_status" -ne 0 ] || fail "mismatched start time should be reclaimed"
[ ! -e "$TMP/mismatch/.service.lock" ] || fail "mismatched identity lock was not released"

# A lock without a PID may still be in the creator's mkdir/write window.
mkdir -p "$TMP/initializing/.service.lock"
cp "$SERVICE" "$TMP/initializing/service.sh"
cat > "$TMP/initializing/daemon" <<'MOCK'
#!/bin/sh
exit 99
MOCK
chmod +x "$TMP/initializing/daemon"
(cd "$TMP/initializing" && sh ./service.sh --worker) >/dev/null 2>&1
[ -d "$TMP/initializing/.service.lock" ] || fail "supervisor removed a lock while its owner PID was being written"
[ ! -e "$TMP/initializing/invocations" ] || fail "supervisor started a daemon while lock ownership was unknown"

# A stale lock is reclaimed. Stub kill reports a dead owner, while the shell's
# builtin kill is used after the service starts to verify its own process lock.
mkdir -p "$TMP/stale/.service.lock"
echo 99999999 > "$TMP/stale/.service.lock/pid"
cp "$SERVICE" "$TMP/stale/service.sh"
cat > "$TMP/stale/daemon" <<'MOCK'
#!/bin/sh
printf '%s\n' "$*" >> "$MOCK_LOG"
exit 7
MOCK
chmod +x "$TMP/stale/daemon"
: > "$TMP/stale/invocations"
export MOCK_LOG="$TMP/stale/invocations"
set +e
(cd "$TMP/stale" && TSOSS_SUPERVISOR_MAX_FAILURES=1 TSOSS_SUPERVISOR_FOREGROUND=true sh ./service.sh --worker) > "$TMP/stale/log" 2>&1
stale_status=$?
set -e
[ "$stale_status" -ne 0 ] || fail "stale lock case should run daemon and exhaust"
[ ! -e "$TMP/stale/.service.lock" ] || fail "lock should be removed after supervisor exit"
[ "$(wc -l < "$TMP/stale/invocations" | tr -d ' ')" -eq 1 ] || fail "stale lock was not reclaimed"

# The service entry point returns after launching its worker; the worker runs
# the finite retry budget and releases its lock.
mkdir -p "$TMP/background"
cp "$SERVICE" "$TMP/background/service.sh"
cat > "$TMP/background/daemon" <<'MOCK'
#!/bin/sh
printf '%s\n' "$*" >> "$MOCK_LOG"
exit 7
MOCK
chmod +x "$TMP/background/daemon"
export MOCK_LOG="$TMP/background/invocations"
: > "$MOCK_LOG"
if ! (cd "$TMP/background" && TSOSS_SUPERVISOR_MAX_FAILURES=1 \
  TSOSS_SUPERVISOR_BACKOFF_MAX=1 sh ./service.sh) > "$TMP/background/log" 2>&1; then
  fail "service entry point should return after launching the worker"
fi
waited=0
while [ ! -e "$TMP/background/.service.lock/pid" ] && [ "$waited" -lt 5 ]; do
  sleep 1
  waited=$((waited + 1))
done
[ "$(wc -l < "$MOCK_LOG" | tr -d ' ')" -eq 1 ] || fail "background worker did not run the daemon"
waited=0
while [ -e "$TMP/background/.service.lock" ] && [ "$waited" -lt 5 ]; do
  sleep 1
  waited=$((waited + 1))
done
[ ! -e "$TMP/background/.service.lock" ] || fail "background worker did not release its lock"

# Terminating a worker removes only its own live lock.
mkdir -p "$TMP/signaled"
cp "$SERVICE" "$TMP/signaled/service.sh"
cat > "$TMP/signaled/daemon" <<'MOCK'
#!/bin/sh
printf '%s\n' "$$" > "$DAEMON_PID_FILE"
exec sleep 60
MOCK
chmod +x "$TMP/signaled/daemon"
export DAEMON_PID_FILE="$TMP/signaled/daemon.pid"
(cd "$TMP/signaled" && TSOSS_SUPERVISOR_FOREGROUND=true sh ./service.sh --worker) > "$TMP/signaled/log" 2>&1 &
lock_owner=$!
waited=0
while [ ! -s "$DAEMON_PID_FILE" ] && [ "$waited" -lt 5 ]; do
  sleep 1
  waited=$((waited + 1))
done
[ -s "$DAEMON_PID_FILE" ] || fail "daemon did not start for signal-cleanup test"
daemon_pid=$(cat "$DAEMON_PID_FILE")
kill -TERM "$lock_owner" 2>/dev/null || true
kill -TERM "$daemon_pid" 2>/dev/null || true
wait "$lock_owner" 2>/dev/null || true
lock_owner=
[ ! -e "$TMP/signaled/.service.lock" ] || fail "terminated worker left its lock behind"

if grep -Eiq 'keystore2?|stop-service|ctl\.stop' "$SERVICE"; then
  fail "supervisor must not restart/stop a keystore service"
fi

echo 'PASS: bounded exits, stability reset, singleton/stale locks, background worker, signal cleanup, no keystore restart'
