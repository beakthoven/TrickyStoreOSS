# shellcheck shell=sh
# shellcheck disable=SC2034,SC2086
DEBUG=false
MODDIR=${0%/*}
[ "$MODDIR" = "$0" ] && MODDIR=.
MODDIR=$(unset CDPATH; cd -- "$MODDIR" 2>/dev/null && pwd) || exit 1

MAX_FAILURES=${TSOSS_SUPERVISOR_MAX_FAILURES:-5}
STABILITY_SECONDS=${TSOSS_SUPERVISOR_STABILITY_SECONDS:-30}
BACKOFF_MAX=${TSOSS_SUPERVISOR_BACKOFF_MAX:-16}
LOCKDIR="$MODDIR/.service.lock"

case "$MAX_FAILURES" in
  ''|*[!0-9]*|0) MAX_FAILURES=5 ;;
esac
case "$STABILITY_SECONDS" in
  ''|*[!0-9]*|0) STABILITY_SECONDS=30 ;;
esac
case "$BACKOFF_MAX" in
  ''|*[!0-9]*|0) BACKOFF_MAX=16 ;;
esac
[ "$MAX_FAILURES" -gt 100 ] && MAX_FAILURES=100
[ "$STABILITY_SECONDS" -gt 86400 ] && STABILITY_SECONDS=86400
[ "$BACKOFF_MAX" -gt 300 ] && BACKOFF_MAX=300

if [ "${1:-}" != --worker ] && [ "${TSOSS_SUPERVISOR_FOREGROUND:-false}" != true ]; then
  if command -v log >/dev/null 2>&1; then
    sh "$0" --worker </dev/null 2>&1 | log -t TrickyStoreOSS &
  else
    sh "$0" --worker </dev/null >"$MODDIR/service.log" 2>&1 &
  fi
  exit 0
fi

process_starttime() {
  stat_line=$(cat "/proc/$1/stat" 2>/dev/null) || return 1
  stat_line=${stat_line##*") "}
  set -- $stat_line
  [ "$#" -ge 20 ] || return 1
  printf '%s\n' "${20}"
}

is_service_process() {
  service_pid=$1
  kill -0 "$service_pid" 2>/dev/null || return 1
  service_cwd=$(readlink "/proc/$service_pid/cwd" 2>/dev/null) || return 1
  [ "$service_cwd" = "$MODDIR" ] || return 1
  service_cmdline=$(tr '\000' ' ' < "/proc/$service_pid/cmdline" 2>/dev/null) || return 1
  case "$service_cmdline" in
    *service.sh*) return 0 ;;
  esac
  return 1
}

lock_owner_state() {
  owner_pid=$(cat "$LOCKDIR/pid" 2>/dev/null)
  [ -n "$owner_pid" ] || return 2
  lock_boot_id=$(cat "$LOCKDIR/boot_id" 2>/dev/null)
  lock_starttime=$(cat "$LOCKDIR/starttime" 2>/dev/null)
  if [ -n "$lock_boot_id" ] || [ -n "$lock_starttime" ]; then
    [ -n "$lock_boot_id" ] && [ -n "$lock_starttime" ] || return 2
    current_boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null) || return 2
    current_starttime=$(process_starttime "$owner_pid") || return 1
    [ "$lock_boot_id" = "$current_boot_id" ] && [ "$lock_starttime" = "$current_starttime" ] && return 0
    return 1
  fi
  if ! kill -0 "$owner_pid" 2>/dev/null; then
    return 1
  fi
  is_service_process "$owner_pid" && return 0
  service_cmdline=$(tr '\000' ' ' < "/proc/$owner_pid/cmdline" 2>/dev/null) || return 2
  [ -n "$service_cmdline" ] || return 2
  return 1
}

run_supervisor() {
  if ! cd "$MODDIR"; then
    echo "TrickyStoreOSS: cannot enter module directory: $MODDIR"
    return 1
  fi

  if ! mkdir "$LOCKDIR" 2>/dev/null; then
    lock_owner_state
    owner_state=$?
    [ "$owner_state" -eq 0 ] && return 0
    [ "$owner_state" -eq 2 ] && return 0
    if ! mkdir "$LOCKDIR/reap" 2>/dev/null; then
      return 0
    fi
    lock_owner_state
    owner_state=$?
    if [ "$owner_state" -ne 1 ]; then
      rmdir "$LOCKDIR/reap" 2>/dev/null || true
      return 0
    fi
    rm -rf "$LOCKDIR"
    if ! mkdir "$LOCKDIR" 2>/dev/null; then
      return 0
    fi
  fi

  own_boot_id=$(cat /proc/sys/kernel/random/boot_id) || {
    rm -rf "$LOCKDIR"
    return 1
  }
  own_starttime=$(process_starttime "$$") || {
    rm -rf "$LOCKDIR"
    return 1
  }
  printf '%s\n' "$$" > "$LOCKDIR/pid" || {
    rm -rf "$LOCKDIR"
    return 1
  }
  printf '%s\n' "$own_boot_id" > "$LOCKDIR/boot_id" || {
    rm -rf "$LOCKDIR"
    return 1
  }
  printf '%s\n' "$own_starttime" > "$LOCKDIR/starttime" || {
    rm -rf "$LOCKDIR"
    return 1
  }

  cleanup() {
    owner_pid=$(cat "$LOCKDIR/pid" 2>/dev/null)
    owner_boot_id=$(cat "$LOCKDIR/boot_id" 2>/dev/null)
    owner_starttime=$(cat "$LOCKDIR/starttime" 2>/dev/null)
    if [ "$owner_pid" = "$$" ] && [ "$owner_boot_id" = "$own_boot_id" ] &&
      [ "$owner_starttime" = "$own_starttime" ]; then
      rm -rf "$LOCKDIR"
    fi
  }
  trap cleanup EXIT
  trap 'exit 1' HUP INT TERM

  failures=0
  backoff=1

  while [ "$failures" -lt "$MAX_FAILURES" ]; do
    attempt=$((failures + 1))
    started=$(date +%s)
    ./daemon "$MODDIR"
    status=$?
    finished=$(date +%s)
    runtime=$((finished - started))

    if [ "$runtime" -ge "$STABILITY_SECONDS" ]; then
      failures=0
      backoff=1
      echo "TrickyStoreOSS: daemon attempt $attempt exited $status after ${runtime}s; stability reset"
      continue
    fi

    failures=$((failures + 1))
    echo "TrickyStoreOSS: daemon attempt $attempt exited $status after ${runtime}s; failure $failures/$MAX_FAILURES"
    if [ "$failures" -ge "$MAX_FAILURES" ]; then
      echo "TrickyStoreOSS: daemon failure budget exhausted"
      return 1
    fi

    sleep "$backoff"
    if [ "$backoff" -lt "$BACKOFF_MAX" ]; then
      backoff=$((backoff * 2))
      if [ "$backoff" -gt "$BACKOFF_MAX" ]; then
        backoff=$BACKOFF_MAX
      fi
    fi
  done
}

run_supervisor
