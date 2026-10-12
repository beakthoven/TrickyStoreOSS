# Disposable Android Keystore harness

This standalone `app_process` smoke harness drives Android Keystore through the framework's `AndroidKeyStore` provider and keystore Binder service. Since app_process may start without that provider registered, the harness reflectively invokes the platform's `android.security.keystore2.AndroidKeyStoreProvider.install()` before looking up the keystore. It adds no app, Gradle, or runtime dependency. It creates up to five uniquely prefixed aliases per run, never exports/logs private key material, and deletes only aliases it created. With TrickyStoreOSS active, these calls may be intercepted; the harness does not claim to distinguish hardware-backed results from module-generated results.

The checks generate attested EC P-256 and RSA-2048 signing keys, sign and verify a fixed message, and validate the returned leaf public key, attestation challenge, and exact requested certificate dates. An auth-bound EC key is signed without invoking any authentication UI; success is a failure, and an authorization-required rejection is expected.

## Build

From the repository root, with JDK `javac`/`jar` and Android SDK platform 37 installed:

```sh
SDK=/opt/android-sdk
OUT=/tmp/tsoss-binder-harness
rm -rf "$OUT"
mkdir -p "$OUT/classes" "$OUT/dex"
javac -source 8 -target 8 -bootclasspath "$SDK/platforms/android-37.0/android.jar" \
  -d "$OUT/classes" tools/verification/binder-crypto/Harness.java
jar cf "$OUT/harness.jar" -C "$OUT/classes" .
"$SDK/build-tools/37.0.0/d8" --lib "$SDK/platforms/android-37.0/android.jar" \
  --output "$OUT/dex" "$OUT/harness.jar"
```

Use another installed platform's `android.jar` and matching `d8` if needed. The source deliberately uses SDK-public Android APIs, not the compile-only project stubs. `d8` must write `classes.dex`; the resulting directory is the class path supplied to `app_process`. Do not use the host `jar` output as the runtime class path.

## Run on a disposable/test device

The shell needs root because a system-level `app_process` Keystore client is intended for testing a system module. Do not run during real payment/authentication flows. Install no app and change no module configuration.

```sh
adb push /tmp/tsoss-binder-harness/dex/classes.dex /data/local/tmp/tsoss-binder-harness/classes.dex
adb shell su -c 'CLASSPATH=/data/local/tmp/tsoss-binder-harness/classes.dex app_process /system/bin io.github.beakthoven.trickystoreoss.harness.Harness'
```

`RESULT PASS` means the implemented checks passed on that run. The root `app_process` shell has a different UID/context from an installed target app, so this validates only the harness caller path, not module interception from a target-app UID. A missing/altered attestation extension, unsupported operation, wrong challenge/dates, failed signature verification, successful unauthenticated signing, successful use of an ordinary SIGN-only designated signer, or cleanup error is a failure. Ordinary-signer rejection is accepted only for incompatible-purpose error `-3` or an `InvalidAlgorithmParameterException` whose message specifically identifies attestation purpose. Exception output is limited to type/numeric error code. The harness removes only its generated aliases in a `finally` block and verifies each alias is absent afterward; it never clears the keystore, wipes data, or writes private-key material or private logs. If the process is forcibly killed, inspect and manually delete only the exact `tsoss-harness-<printed-run-id>-*` aliases using Android Keystore tooling. Never clear the keystore or module data.

The default platform app-process path can differ by ROM. If `app_process` or `su` is located elsewhere, adapt only that executable path. API 29+ is required. API 30+ uses per-operation biometric/device-credential auth parameters; API 29 uses the legacy auth-required policy. Android 12/13 app_process attested JCA generation may hit the daemon missing-application-context RKP failure described in the fix plan; treat that as a blocked gate, not successful key validation. Hardware attestation/RKP availability is device-specific and must be reported as a failed or unavailable gate, not inferred from software certificate success.

Where the runtime exposes the public `KeyGenParameterSpec.Builder.setAttestKeyAlias` method, the harness creates a disposable EC key with ordinary SIGN-only purpose and verifies that it is rejected as the designated attestation signer. Older runtimes report this gate as `UNAVAILABLE`. The standalone SDK has no public keystore2 GRANT-domain Binder binding, so grant/access-vector checks are reported `UNAVAILABLE`; the harness does not grant access to another UID.

## Paired getKeyEntry timing

The source also supports `timing` mode and mirrors Duck's exact private Keystore2 sequence. It creates three disposable descriptors, generates a `PURPOSE_ATTEST_KEY` reference key outside the timed region, resolves the returned descriptor (including `KEY_ID` metadata), then generates one EC P-256 signing key with that explicit signer and one otherwise-matched EC key with a null signer. The timed region contains only private `IKeystoreService.getKeyEntry(KeyDescriptor)` calls on the resolved descriptors. Generation, descriptor resolution, five warmup pairs, response validation, deletion, and reflection setup are outside the samples. Attested and plain calls alternate for the requested sample count (default 500), and output reports successful counts, failed pairs, medians in nanoseconds, and `attested - plain`. This is distinct from the old APP-alias/simple timing mode and must not be reported as an exact Duck reproduction if the `PURPOSE_ATTEST_KEY` setup is unavailable.

For the installed validation APK, pass `mode=timing`, an optional `iterations` extra (`100` or `500`), and a unique `run-id` through `ValidationActivity`. The package is `io.github.beakthoven.tsoss.verification`; install only this dedicated APK for the target-app UID path, launch its exported activity with an explicit intent, capture logcat, then uninstall it. The root `app_process` path above remains a separate caller path and is not equivalent. If exact setup fails because direct `PURPOSE_ATTEST_KEY` hardware generation or the explicit signer is unsupported, report the framework error and run the supported coarse mode separately without claiming an exact pass.

Correlate timing with safe daemon/native active-state and counter/log lines only; do not log key material, change keybox/config, tune detector thresholds, or use key-swipe operations. Verify that only the exact `tsoss-harness-<run-id>-timing-*` aliases were created and deleted, and restore/remove the dedicated package after the run.