#!/bin/sh
# Regression test for the injector's fd hand-off.
#
# The injector hands the library to the target over an AF_UNIX datagram socket. Starting recvmsg() in
# the target before sending the datagram used to park the target's main thread in that recvmsg() for
# good whenever the send failed, e.g. on an SELinux denial (the "Failed to send fd to remote process
# ... Permission denied" followed by "Failed to set register set ... No such process" in #120). The
# datagram is now queued before recvmsg() runs, so the remote call cannot block and a failed send
# leaves the target exactly where it was.
#
# Requirements: a rooted Android device, the unpacked module (the zip from out/) in $TSOSS_MODULE, and
# either the NDK toolchain directory in $NDK_TOOLCHAIN (the helpers are built on the spot) or prebuilt
# helpers in $SLEEPER and $FAIL_SENDMSG. Run as root: su -c "sh tests/injector-fd-handoff.sh"
set -eu

ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
MODULE=${TSOSS_MODULE:?set TSOSS_MODULE to the unpacked module directory}
ABI=$(getprop ro.product.cpu.abi)

case $(uname -m) in
  aarch64) RECVMSG=212 ;; # __NR_recvmsg
  x86_64) RECVMSG=45 ;;
  *) echo "FAIL: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

TMP=${TMPDIR:-/data/local/tmp}/tsoss-fd-handoff.$$
trap 'kill $(cat "$TMP/target" 2>/dev/null) 2>/dev/null || true; rm -rf "$TMP"' EXIT HUP INT TERM
mkdir -p "$TMP"
cd "$TMP"

# The zip keeps the binaries under lib/<abi>/, an installed module moves the injector to its root.
if [ -f "$MODULE/inject" ]; then
  INJECTOR_SRC=$MODULE/inject
  LIBRARY_SRC=$MODULE/libTrickyStoreOSS.so
else
  INJECTOR_SRC=$MODULE/lib/$ABI/libinject.so
  LIBRARY_SRC=$MODULE/lib/$ABI/libTrickyStoreOSS.so
fi
[ -f "$INJECTOR_SRC" ] && [ -f "$LIBRARY_SRC" ] || { echo "FAIL: no injector and library for $ABI in $MODULE" >&2; exit 1; }
INJECTOR=$TMP/inject
LIBRARY=$TMP/libTrickyStoreOSS.so
cp "$INJECTOR_SRC" "$INJECTOR"
cp "$LIBRARY_SRC" "$LIBRARY"
chmod 755 "$INJECTOR"

SLEEPER=${SLEEPER:-$TMP/sleeper}
FAIL_SENDMSG=${FAIL_SENDMSG:-$TMP/fail_sendmsg.so}
if [ ! -e "$SLEEPER" ] || [ ! -e "$FAIL_SENDMSG" ]; then
  case "$ABI" in
    arm64-v8a) TRIPLE=aarch64-linux-android ;;
    armeabi-v7a) TRIPLE=armv7a-linux-androideabi ;;
    x86_64) TRIPLE=x86_64-linux-android ;;
    x86) TRIPLE=i686-linux-android ;;
  esac
  # 29 is the module's minimum SDK, so the wrapper exists in every supported NDK.
  CC="${NDK_TOOLCHAIN:?set NDK_TOOLCHAIN or provide SLEEPER and FAIL_SENDMSG}/$TRIPLE29-clang"
  cat > sleeper.c <<'SRC'
#include <unistd.h>
/* Idles in a restartable syscall, like the main thread of a system service. */
int main(void) {
    for (;;) pause();
}
SRC
  cat > fail_sendmsg.c <<'SRC'
#include <errno.h>
#include <sys/socket.h>
/* Makes sendmsg(2) fail the way an SELinux denial does. */
ssize_t sendmsg(int fd, const struct msghdr *msg, int flags) {
    (void)fd;
    (void)msg;
    (void)flags;
    errno = EACCES;
    return -1;
}
SRC
  "$CC" -O2 -o "$SLEEPER" sleeper.c
  "$CC" -shared -fPIC -O2 -o "$FAIL_SENDMSG" fail_sendmsg.c
fi

start_target() {
  "$SLEEPER" &
  echo $! > "$TMP/target"
  sleep 0.3
}

# main_thread_syscall <pid>: the syscall number the target's main thread is blocked in
main_thread_syscall() {
  cut -d' ' -f1 "/proc/$1/task/$1/syscall"
}

echo "case: failed send leaves the target idle"
start_target
LD_PRELOAD="$FAIL_SENDMSG" "$INJECTOR" "$(cat "$TMP/target")" "$LIBRARY" entry >/dev/null 2>&1 && status=0 || status=$?
[ "$status" -ne 0 ] || { echo "FAIL: injector succeeded although the send failed" >&2; exit 1; }
sleep 1
syscall=$(main_thread_syscall "$(cat "$TMP/target")")
[ "$syscall" != "$RECVMSG" ] || { echo "FAIL: target main thread is parked in recvmsg(2)" >&2; exit 1; }
kill "$(cat "$TMP/target")" 2>/dev/null || true
wait 2>/dev/null || true

# The toy target's socket is not covered by the module's SELinux rules, so the successful hand-off can
# only be exercised with the policy permissive.
if [ "$(getenforce)" = Permissive ]; then
  echo "case: successful send loads the library"
  start_target
  "$INJECTOR" "$(cat "$TMP/target")" "$LIBRARY" entry >/dev/null 2>&1 || { echo "FAIL: injector failed on the happy path" >&2; exit 1; }
  grep -q libTrickyStoreOSS "/proc/$(cat "$TMP/target")/maps" || { echo "FAIL: library is not mapped" >&2; exit 1; }
  kill "$(cat "$TMP/target")" 2>/dev/null || true
else
  echo "case: successful send loads the library (skipped: SELinux is enforcing)"
fi

echo "PASS"
