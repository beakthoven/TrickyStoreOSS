/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.trickystoreoss.harness;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TimeZone;
import java.util.UUID;
import java.security.KeyStore;
import javax.security.auth.x500.X500Principal;

public final class Harness {
    private static final byte[] MESSAGE = "TrickyStoreOSS disposable Binder crypto check".getBytes(StandardCharsets.UTF_8);
    private static final byte[] CHALLENGE = "tsoss-harness-challenge-v1".getBytes(StandardCharsets.UTF_8);
    private static final String ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";
    private static final Date NOT_BEFORE = date("2020-01-02T03:04:05Z");
    private static final Date NOT_AFTER = date("2035-06-07T08:09:10Z");

    private final KeyStore keyStore;
    private final String prefix;
    private final Set<String> aliases = new HashSet<String>();
    private final Set<String> retainedAliases = new HashSet<String>();
    private int failures;

    private Harness(String mode, String runId) throws Exception {
        Class.forName("android.security.keystore2.AndroidKeyStoreProvider")
                .getMethod("install")
                .invoke(null);
        keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        if (!"before".equals(mode) && !"after".equals(mode) && !"full".equals(mode) && !"timing".equals(mode))
            throw new IllegalArgumentException("invalid mode");
        if (("before".equals(mode) || "full".equals(mode) || "timing".equals(mode)) && runId == null)
            runId = UUID.randomUUID().toString();
        if (runId == null || !runId.matches("[0-9a-f-]{36}")) throw new IllegalArgumentException("missing run id");
        prefix = "tsoss-harness-" + runId + "-";
        this.mode = mode;
        this.runId = runId;
    }

    private final String mode;
    private final String runId;

    public static void main(String[] args) {
        int result = runInApp();
        if (result != 0) System.exit(1);
    }

    public static int runInApp() {
        return runInApp("full", null);
    }

    public static int runInApp(String mode, String runId) {
        return runInApp(mode, runId, 500);
    }

    public static int runInApp(String mode, String runId, int iterations) {
        try {
            Harness harness = new Harness(mode, runId);
            int result = harness.run(iterations);
            System.out.println(result == 0 ? "RESULT PASS" : "RESULT FAIL failures=" + result);
            return result;
        } catch (Throwable t) {
            System.out.println("FAIL harness-start " + safeError(t));
            System.out.println("RESULT FAIL failures=1");
            return 1;
        }
    }

    private int run(int iterations) {
        System.out.println("Android SDK=" + Build.VERSION.SDK_INT + " alias-prefix=" + prefix + " mode=" + mode);
        if ("timing".equals(mode) && (iterations < 1 || iterations > 500)) {
            System.out.println("FAIL timing-iterations range=1..500");
            return 1;
        }
        if ("before".equals(mode)) System.out.println("RUN_ID " + runId);
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            System.out.println("UNAVAILABLE Android 10+ required");
            return 1;
        }

        try {
            if ("timing".equals(mode)) {
                check("paired EC getKeyEntry timing", new Check() {
                    @Override public void run() throws Exception { timeGetKeyEntry(iterations); }
                });
            } else if ("after".equals(mode)) {
                check("persisted EC public hash/sign after daemon restart", new Check() {
                    @Override public void run() throws Exception { verifyPersistedKey("ec", KeyProperties.KEY_ALGORITHM_EC); }
                });
                check("persisted RSA public hash/sign after daemon restart", new Check() {
                    @Override public void run() throws Exception { verifyPersistedKey("rsa", KeyProperties.KEY_ALGORITHM_RSA); }
                });
            } else {
                check("EC attested sign/verify, challenge and dates", new Check() {
                    @Override public void run() throws Exception { testAttestedKey("ec", KeyProperties.KEY_ALGORITHM_EC); }
                });
                check("RSA attested sign/verify, challenge and dates", new Check() {
                    @Override public void run() throws Exception { testAttestedKey("rsa", KeyProperties.KEY_ALGORITHM_RSA); }
                });
                check("auth-bound sign rejected without prompt", new Check() {
                    @Override public void run() throws Exception { testAuthBoundKey(); }
                });
                if (hasAttestKeyAliasApi()) {
                    check("ordinary SIGN key rejected as attestation signer", new Check() {
                        @Override public void run() throws Exception { testOrdinarySignerRejected(); }
                    });
                } else {
                    System.out.println("UNAVAILABLE explicit designated-attestation-key rejection: setAttestKeyAlias API absent");
                }
                System.out.println("UNAVAILABLE grant access-vector checks: this standalone SDK-compiled harness has no public keystore2 GRANT-domain Binder binding");
            }
        } finally {
            for (String alias : aliases) {
                try {
                    keyStore.deleteEntry(alias);
                    if (keyStore.containsAlias(alias)) throw new IllegalStateException("test alias still exists");
                    System.out.println("CLEANED " + alias);
                } catch (Throwable t) {
                    failures++;
                    System.out.println("FAIL cleanup " + alias + " " + safeError(t));
                }
            }
        }
        return failures;
    }

    private void timeGetKeyEntry(int iterations) throws Exception {
        String attestKeyAlias = prefix + "timing-attest-key";
        String attestedAlias = prefix + "timing-attested";
        String plainAlias = prefix + "timing-plain";
        trackAlias(attestKeyAlias);
        trackAlias(attestedAlias);
        trackAlias(plainAlias);

        DuckTimingClient client = new DuckTimingClient();
        Object session = client.openTrustedEnvironment();
        Object attestKeyRequested = client.createAliasDescriptor(attestKeyAlias);
        Object attestedRequested = client.createAliasDescriptor(attestedAlias);
        Object plainRequested = client.createAliasDescriptor(plainAlias);
        Object attestKey = null;
        Object attested = null;
        Object plain = null;
        try {
            Object attestKeyMetadata = client.generateAttestationKey(session, attestKeyRequested);
            attestKey = client.followUpDescriptor(attestKeyRequested, attestKeyMetadata);
            Object attestedMetadata = client.generateSigningKey(session, attestedRequested, attestKey, true);
            attested = client.followUpDescriptor(attestedRequested, attestedMetadata);
            Object plainMetadata = client.generateSigningKey(session, plainRequested, null, false);
            plain = client.followUpDescriptor(plainRequested, plainMetadata);
            System.out.println("TIMING exact-duck-flow attestation-signer=explicit-key-id plain-signer=null"
                    + " attestation-descriptor=" + client.describeDescriptor(attestKey)
                    + " attested-descriptor=" + client.describeDescriptor(attested)
                    + " plain-descriptor=" + client.describeDescriptor(plain));

            List<Long> attestedNanos = new ArrayList<Long>(iterations);
            List<Long> plainNanos = new ArrayList<Long>(iterations);
            List<String> errors = new ArrayList<String>();
            for (int i = 0; i < 5; i++) {
                client.invokeTimedEntry(session, attested, null, null);
                client.invokeTimedEntry(session, plain, null, null);
            }
            int failedPairs = 0;
            for (int i = 0; i < iterations; i++) {
                TimedEntry attestedEntry = client.invokeTimedEntry(session, attested, attestedNanos, errors);
                TimedEntry plainEntry = client.invokeTimedEntry(session, plain, plainNanos, errors);
                if (!attestedEntry.success || !plainEntry.success) failedPairs++;
            }
            if (attestedNanos.isEmpty() || plainNanos.isEmpty())
                throw new AssertionError("exact timing produced no successful samples");
            long attestedMedian = median(attestedNanos);
            long plainMedian = median(plainNanos);
            System.out.println("TIMING operation=private-keystore2.getKeyEntry caller-uid=" + android.os.Process.myUid()
                    + " warmup-pairs=5 iterations=" + iterations + " attempted-pairs=" + iterations
                    + " successful-attested=" + attestedNanos.size() + " successful-plain=" + plainNanos.size()
                    + " failed-pairs=" + failedPairs);
            System.out.println("TIMING median-ns attested=" + attestedMedian + " plain=" + plainMedian
                    + " delta-attested-minus-plain=" + (attestedMedian - plainMedian));
            for (int i = 0; i < Math.min(errors.size(), 5); i++)
                System.out.println("TIMING error " + errors.get(i));
        } finally {
            client.deleteKey(session, attested);
            client.deleteKey(session, attestedRequested);
            client.deleteKey(session, plain);
            client.deleteKey(session, plainRequested);
            client.deleteKey(session, attestKey);
            client.deleteKey(session, attestKeyRequested);
            client.close(session);
        }
    }

    private static long median(List<Long> samples) {
        List<Long> sorted = new ArrayList<Long>(samples);
        Collections.sort(sorted);
        return sorted.get(sorted.size() / 2).longValue();
    }

    private static final class TimedEntry {
        final boolean success;
        TimedEntry(boolean success) { this.success = success; }
    }

    private static final class DuckTimingClient {
        private static final int DOMAIN_APP = 0;
        private static final int DOMAIN_KEY_ID = 4;
        private static final int SECURITY_LEVEL_TEE = 1;
        private static final String SERVICE = "android.system.keystore2.IKeystoreService/default";
        private static final String SERVICE_INTERFACE = "android.system.keystore2.IKeystoreService";
        private static final String SECURITY_INTERFACE = "android.system.keystore2.IKeystoreSecurityLevel";
        private final Class<?> descriptorClass;
        private final Class<?> parameterClass;
        private final Class<?> parameterValueClass;
        private final Class<?> serviceInterface;
        private final Class<?> securityInterface;

        DuckTimingClient() throws Exception {
            exemptHiddenApi();
            descriptorClass = Class.forName("android.system.keystore2.KeyDescriptor");
            parameterClass = Class.forName("android.hardware.security.keymint.KeyParameter");
            parameterValueClass = Class.forName("android.hardware.security.keymint.KeyParameterValue");
            serviceInterface = Class.forName(SERVICE_INTERFACE);
            securityInterface = Class.forName(SECURITY_INTERFACE);
        }

        Object openTrustedEnvironment() throws Exception {
            Class<?> manager = Class.forName("android.os.ServiceManager");
            Object binder = manager.getMethod("getService", String.class).invoke(null, SERVICE);
            if (binder == null) throw new IllegalStateException("keystore2 service binder unavailable");
            Class<?> stub = Class.forName(SERVICE_INTERFACE + "$Stub$Proxy");
            java.lang.reflect.Constructor<?> constructor = stub.getDeclaredConstructor(android.os.IBinder.class);
            constructor.setAccessible(true);
            Object service = constructor.newInstance(binder);
            java.lang.reflect.Method getLevel = findMethod(service, "getSecurityLevel", 1);
            getLevel.setAccessible(true);
            Object level = getLevel.invoke(service, Integer.valueOf(SECURITY_LEVEL_TEE));
            if (level == null) throw new IllegalStateException("TEE security level unavailable");
            return new Object[] {service, level};
        }

        Object createAliasDescriptor(String alias) throws Exception {
            Object descriptor = descriptorClass.getDeclaredConstructor().newInstance();
            setField(descriptor, "domain", Integer.valueOf(DOMAIN_APP));
            setField(descriptor, "nspace", Long.valueOf(-1L));
            setField(descriptor, "alias", alias);
            setField(descriptor, "blob", null);
            return descriptor;
        }

        Object generateAttestationKey(Object session, Object descriptor) throws Exception {
            return generate(session, descriptor, null, new Object[] {
                    parameter(0x10000002, Integer.valueOf(3)),
                    parameter(0x30000003, Integer.valueOf(256)),
                    parameter(0x1000000A, Integer.valueOf(1)),
                    parameter(0x20000001, Integer.valueOf(7)),
                    parameter(0x20000005, Integer.valueOf(4)),
                    parameter(0x700001F7, Boolean.TRUE),
            });
        }

        Object generateSigningKey(Object session, Object descriptor, Object signer, boolean attest) throws Exception {
            List<Object> parameters = new ArrayList<Object>();
            parameters.add(parameter(0x10000002, Integer.valueOf(3)));
            parameters.add(parameter(0x30000003, Integer.valueOf(256)));
            parameters.add(parameter(0x1000000A, Integer.valueOf(1)));
            parameters.add(parameter(0x20000001, Integer.valueOf(2)));
            parameters.add(parameter(0x20000005, Integer.valueOf(4)));
            parameters.add(parameter(0x700001F7, Boolean.TRUE));
            if (attest) {
                byte[] challenge = new byte[32];
                new java.security.SecureRandom().nextBytes(challenge);
                parameters.add(parameter(0x900002C4, challenge));
            }
            return generate(session, descriptor, signer, parameters.toArray());
        }

        private Object generate(Object session, Object descriptor, Object signer, Object[] parameters) throws Exception {
            Object[] pair = (Object[]) session;
            Object level = pair[1];
            Object array = java.lang.reflect.Array.newInstance(parameterClass, parameters.length);
            for (int i = 0; i < parameters.length; i++)
                java.lang.reflect.Array.set(array, i, parameters[i]);
            java.lang.reflect.Method method = findGenerateMethod(level, descriptorClass, parameterClass);
            return method.invoke(level, descriptor, signer, array, Integer.valueOf(0), new byte[0]);
        }

        Object followUpDescriptor(Object requested, Object generated) throws Exception {
            Object returned = generated == null ? null : fieldOrMetadataKey(generated);
            if (returned == null) return requested;
            int domain = ((Integer) field(returned, "domain")).intValue();
            long nspace = ((Long) field(returned, "nspace")).longValue();
            if (domain == DOMAIN_KEY_ID) return returned;
            if (nspace >= 0) {
                Object keyId = descriptorClass.getDeclaredConstructor().newInstance();
                setField(keyId, "domain", Integer.valueOf(DOMAIN_KEY_ID));
                setField(keyId, "nspace", Long.valueOf(nspace));
                setField(keyId, "alias", field(requested, "alias"));
                setField(keyId, "blob", null);
                return keyId;
            }
            return returned;
        }

        private static Object fieldOrMetadataKey(Object generated) throws Exception {
            Object metadata = fieldOrNull(generated, "metadata");
            Object returned = metadata == null ? null : fieldOrNull(metadata, "key");
            return returned != null ? returned : fieldOrNull(generated, "key");
        }

        TimedEntry invokeTimedEntry(Object session, Object descriptor, List<Long> samples, List<String> errors) {
            long start = System.nanoTime();
            try {
                Object response = findMethod(((Object[]) session)[0], "getKeyEntry", 1).invoke(((Object[]) session)[0], descriptor);
                Object metadata = response == null ? null : field(response, "metadata");
                if (metadata == null) throw new IllegalStateException("getKeyEntry returned no metadata");
                if (samples != null) samples.add(Long.valueOf(System.nanoTime() - start));
                return new TimedEntry(true);
            } catch (Throwable t) {
                if (errors != null) errors.add(safeError(t));
                return new TimedEntry(false);
            }
        }

        void deleteKey(Object session, Object descriptor) {
            if (descriptor == null) return;
            try { findMethod(((Object[]) session)[0], "deleteKey", 1).invoke(((Object[]) session)[0], descriptor); }
            catch (Throwable t) {
                if (!hasKeyStoreError(t, 7) && !hasServiceSpecificError(t, 7))
                    System.out.println("FAIL timing cleanup " + safeError(t));
            }
        }

        void close(Object session) { }

        String describeDescriptor(Object descriptor) {
            if (descriptor == null) return "null";
            try { return "domain=" + field(descriptor, "domain") + "/nspace=" + field(descriptor, "nspace"); }
            catch (Throwable t) { return "unavailable"; }
        }

        private Object parameter(int tag, Object value) throws Exception {
            Object parameter = parameterClass.getDeclaredConstructor().newInstance();
            setField(parameter, "tag", Integer.valueOf(tag));
            Object union = parameterValueClass.getDeclaredConstructor().newInstance();
            String setter;
            int tagId = tag & 0x0fffffff;
            if (value instanceof Boolean) setter = "setBoolValue";
            else if (value instanceof byte[]) setter = "setBlob";
            else if (tagId == 1) setter = "setKeyPurpose";
            else if (tagId == 2) setter = "setAlgorithm";
            else if (tagId == 5 || tagId == 203) setter = "setDigest";
            else if (tagId == 10) setter = "setEcCurve";
            else if ((tag & 0xf0000000) == 0x30000000) setter = "setInteger";
            else setter = "setInteger";
            java.lang.reflect.Method method = null;
            for (java.lang.reflect.Method candidate : parameterValueClass.getDeclaredMethods()) {
                if (setter.equals(candidate.getName()) && candidate.getParameterTypes().length == 1
                        && boxed(candidate.getParameterTypes()[0]).isAssignableFrom(value.getClass())) {
                    method = candidate;
                    method.setAccessible(true);
                    break;
                }
            }
            if (method == null) throw new NoSuchMethodException(setter + "(" + value.getClass().getName() + ")");
            method.invoke(union, value);
            setField(parameter, "value", union);
            return parameter;
        }

        private static java.lang.reflect.Method findGenerateMethod(Object target, Class<?> descriptor, Class<?> parameter) throws Exception {
            for (java.lang.reflect.Method method : target.getClass().getMethods()) {
                Class<?>[] types = method.getParameterTypes();
                if ("generateKey".equals(method.getName()) && types.length == 5
                        && types[0].isAssignableFrom(descriptor) && types[1].isAssignableFrom(descriptor)
                        && types[2].isArray() && types[2].getComponentType().isAssignableFrom(parameter)
                        && types[3] == Integer.TYPE && types[4] == byte[].class) {
                    method.setAccessible(true);
                    return method;
                }
            }
            throw new NoSuchMethodException("generateKey(KeyDescriptor,KeyDescriptor,KeyParameter[],int,byte[])");
        }

        private static java.lang.reflect.Method findMethod(Object target, String name, int arity) throws Exception {
            for (java.lang.reflect.Method method : target.getClass().getMethods()) {
                if (name.equals(method.getName()) && method.getParameterTypes().length == arity) {
                    method.setAccessible(true);
                    return method;
                }
            }
            throw new NoSuchMethodException(name + "/" + arity);
        }

        private static Class<?> boxed(Class<?> type) {
            if (!type.isPrimitive()) return type;
            if (type == Boolean.TYPE) return Boolean.class;
            if (type == Integer.TYPE) return Integer.class;
            if (type == Long.TYPE) return Long.class;
            if (type == Byte.TYPE) return Byte.class;
            if (type == Short.TYPE) return Short.class;
            if (type == Character.TYPE) return Character.class;
            if (type == Float.TYPE) return Float.class;
            if (type == Double.TYPE) return Double.class;
            return type;
        }

        private static Object field(Object target, String name) throws Exception {
            try { return target.getClass().getField(name).get(target); }
            catch (NoSuchFieldException e) { java.lang.reflect.Field f = target.getClass().getDeclaredField(name); f.setAccessible(true); return f.get(target); }
        }

        private static Object fieldOrNull(Object target, String name) {
            if (target == null) return null;
            try { return field(target, name); }
            catch (Throwable ignored) { return null; }
        }

        private static void setField(Object target, String name, Object value) throws Exception {
            try { target.getClass().getField(name).set(target, value); }
            catch (NoSuchFieldException e) { java.lang.reflect.Field f = target.getClass().getDeclaredField(name); f.setAccessible(true); f.set(target, value); }
        }

        private static void exemptHiddenApi() throws Exception {
            Class<?> runtime = Class.forName("dalvik.system.VMRuntime");
            Object instance = runtime.getDeclaredMethod("getRuntime").invoke(null);
            runtime.getDeclaredMethod("setHiddenApiExemptions", String[].class).invoke(instance, new Object[] {new String[] {"L"}});
        }
    }

    private void testAttestedKey(String kind, String algorithm) throws Exception {
        String alias = prefix + kind;
        trackAlias(alias);
        int purposes = KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY;
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm, "AndroidKeyStore");
        KeyGenParameterSpec.Builder spec = new KeyGenParameterSpec.Builder(alias, purposes)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(CHALLENGE)
                .setCertificateSubject(new X500Principal("CN=TSOSS disposable " + kind))
                .setCertificateSerialNumber(java.math.BigInteger.valueOf(11001L))
                .setCertificateNotBefore(NOT_BEFORE)
                .setCertificateNotAfter(NOT_AFTER);
        if (KeyProperties.KEY_ALGORITHM_EC.equals(algorithm)) spec.setAlgorithmParameterSpec(new java.security.spec.ECGenParameterSpec("secp256r1"));
        else spec.setKeySize(2048).setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1);
        generator.initialize(spec.build());
        KeyPair pair = generator.generateKeyPair();

        Certificate certificate = keyStore.getCertificate(alias);
        if (!(certificate instanceof X509Certificate)) throw new AssertionError("missing X509 leaf certificate");
        X509Certificate leaf = (X509Certificate) certificate;
        if (!Arrays.equals(pair.getPublic().getEncoded(), leaf.getPublicKey().getEncoded())) throw new AssertionError("leaf public key mismatch");
        if (!NOT_BEFORE.equals(leaf.getNotBefore()) || !NOT_AFTER.equals(leaf.getNotAfter())) throw new AssertionError("certificate validity mismatch");
        byte[] attestationExtension = leaf.getExtensionValue(ATTESTATION_OID);
        byte[] returnedChallenge = attestationChallenge(attestationExtension);
        if (!Arrays.equals(CHALLENGE, returnedChallenge)) throw new AssertionError("attestation challenge mismatch");
        int attestationVersion = attestationVersion(attestationExtension);
        if (attestationVersion < 100) throw new AssertionError("attestation version below 100: " + attestationVersion);

        String signatureAlgorithm = KeyProperties.KEY_ALGORITHM_EC.equals(algorithm) ? "SHA256withECDSA" : "SHA256withRSA";
        Signature signer = Signature.getInstance(signatureAlgorithm);
        signer.initSign(pair.getPrivate());
        signer.update(MESSAGE);
        byte[] signature = signer.sign();
        Signature verifier = Signature.getInstance(signatureAlgorithm);
        verifier.initVerify(pair.getPublic());
        verifier.update(MESSAGE);
        if (!verifier.verify(signature)) throw new AssertionError("signature verification failed");

        if (!"before".equals(mode)) {
            byte[] originalPublicKey = pair.getPublic().getEncoded();
            keyStore.deleteEntry(alias);
            if (keyStore.containsAlias(alias)) throw new AssertionError("alias survived delete");
            if (keyStore.getCertificate(alias) != null) throw new AssertionError("certificate survived delete");
            KeyPairGenerator regenerated = KeyPairGenerator.getInstance(algorithm, "AndroidKeyStore");
            regenerated.initialize(spec.build());
            KeyPair regeneratedPair = regenerated.generateKeyPair();
            if (Arrays.equals(originalPublicKey, regeneratedPair.getPublic().getEncoded())) throw new AssertionError("regenerated public key unchanged");
            Signature regeneratedSigner = Signature.getInstance(signatureAlgorithm);
            regeneratedSigner.initSign(regeneratedPair.getPrivate());
            regeneratedSigner.update(MESSAGE);
            byte[] regeneratedSignature = regeneratedSigner.sign();
            Signature regeneratedVerifier = Signature.getInstance(signatureAlgorithm);
            regeneratedVerifier.initVerify(regeneratedPair.getPublic());
            regeneratedVerifier.update(MESSAGE);
            if (!regeneratedVerifier.verify(regeneratedSignature)) throw new AssertionError("regenerated signature verification failed");
            System.out.println("PASS lifecycle " + kind + " alias=" + alias + " delete-and-regenerate");
        } else {
            retainedAliases.add(alias);
            aliases.remove(alias);
        }
        System.out.println("PASS " + kind + " alias=" + alias + " public-sha256=" + hex(MessageDigest.getInstance("SHA-256").digest(leaf.getPublicKey().getEncoded())));
        printKeyMetadata(alias);
    }

    private void verifyPersistedKey(String kind, String algorithm) throws Exception {
        String alias = prefix + kind;
        trackAlias(alias);
        if (!keyStore.containsAlias(alias)) throw new AssertionError("persisted alias missing");
        Certificate certificate = keyStore.getCertificate(alias);
        if (!(certificate instanceof X509Certificate)) throw new AssertionError("persisted certificate missing");
        java.security.Key privateKey = keyStore.getKey(alias, null);
        if (privateKey == null) throw new AssertionError("persisted private key unavailable");
        String signatureAlgorithm = KeyProperties.KEY_ALGORITHM_EC.equals(algorithm) ? "SHA256withECDSA" : "SHA256withRSA";
        Signature signer = Signature.getInstance(signatureAlgorithm);
        signer.initSign((java.security.PrivateKey) privateKey);
        signer.update(MESSAGE);
        byte[] signature = signer.sign();
        Signature verifier = Signature.getInstance(signatureAlgorithm);
        verifier.initVerify(certificate.getPublicKey());
        verifier.update(MESSAGE);
        if (!verifier.verify(signature)) throw new AssertionError("persisted signature verification failed");
        System.out.println("PASS persisted " + kind + " alias=" + alias + " public-sha256=" + hex(MessageDigest.getInstance("SHA-256").digest(certificate.getPublicKey().getEncoded())));
        printKeyMetadata(alias);
    }

    private void printKeyMetadata(String alias) {
        try {
            Class<?> descriptorClass = Class.forName("android.system.keystore2.KeyDescriptor");
            Object descriptor = descriptorClass.getDeclaredConstructor().newInstance();
            descriptorClass.getField("alias").set(descriptor, alias);
            descriptorClass.getField("domain").setInt(descriptor, 0);
            descriptorClass.getField("nspace").setLong(descriptor, android.os.Process.myUid());
            Class<?> keyStoreClass = Class.forName("android.security.KeyStore2");
            Object keyStore2 = keyStoreClass.getMethod("getInstance").invoke(null);
            Object response = keyStoreClass.getMethod("getKeyEntry", descriptorClass).invoke(keyStore2, descriptor);
            Object metadata = response.getClass().getField("metadata").get(response);
            if (metadata == null) throw new IllegalStateException("metadata missing");
            Object key = metadata.getClass().getField("key").get(metadata);
            int securityLevel = metadata.getClass().getField("keySecurityLevel").getInt(metadata);
            long modified = metadata.getClass().getField("modificationTimeMs").getLong(metadata);
            Object auths = metadata.getClass().getField("authorizations").get(metadata);
            int authCount = auths == null ? 0 : java.lang.reflect.Array.getLength(auths);
            System.out.println("META alias=" + alias + " key-class=" + (key == null ? "null" : key.getClass().getSimpleName())
                    + " security-level=" + securityLevel + " modified-ms=" + modified + " auth-count=" + authCount);
        } catch (Throwable t) {
            System.out.println("UNAVAILABLE raw keystore2 metadata " + safeError(t));
        }
    }

    private void testAuthBoundKey() throws Exception {
        String alias = prefix + "auth";
        trackAlias(alias);
        KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        KeyGenParameterSpec.Builder spec = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(true);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            int authTypes = KeyProperties.class.getField("AUTH_BIOMETRIC_STRONG").getInt(null)
                    | KeyProperties.class.getField("AUTH_DEVICE_CREDENTIAL").getInt(null);
            spec.getClass()
                    .getMethod("setUserAuthenticationParameters", int.class, int.class)
                    .invoke(spec, 0, authTypes);
        } else {
            spec.setUserAuthenticationValidityDurationSeconds(-1);
        }
        generator.initialize(spec.build());
        KeyPair pair = generator.generateKeyPair();
        try {
            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(pair.getPrivate());
            signer.update(MESSAGE);
            signer.sign();
            throw new AssertionError("sign succeeded without authentication");
        } catch (Throwable t) {
            if (!hasCauseNamed(t, "UserNotAuthenticatedException") && !hasKeyStoreError(t, -26)) throw t;
        }
    }

    private void testOrdinarySignerRejected() throws Exception {
        String signerAlias = prefix + "ordinary-signer";
        String targetAlias = prefix + "designated-target";
        trackAlias(signerAlias);
        trackAlias(targetAlias);
        KeyPairGenerator signerGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        signerGenerator.initialize(
                new KeyGenParameterSpec.Builder(signerAlias, KeyProperties.PURPOSE_SIGN)
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .build());
        signerGenerator.generateKeyPair();

        try {
            KeyGenParameterSpec.Builder targetSpec = new KeyGenParameterSpec.Builder(
                    targetAlias, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(CHALLENGE)
                    .setCertificateSubject(new X500Principal("CN=TSOSS designated signer rejection"))
                    .setCertificateNotBefore(NOT_BEFORE)
                    .setCertificateNotAfter(NOT_AFTER);
            targetSpec.getClass().getMethod("setAttestKeyAlias", String.class).invoke(targetSpec, signerAlias);
            KeyPairGenerator targetGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            targetGenerator.initialize(targetSpec.build());
            targetGenerator.generateKeyPair();
            throw new AssertionError("ordinary SIGN-only key accepted as designated attestation signer");
        } catch (AssertionError e) {
            throw e;
        } catch (Throwable t) {
            if (!hasKeyStoreError(t, -3)
                    && !hasServiceSpecificError(t, -3)
                    && !isInvalidAttestPurpose(t)) throw t;
        }
    }

    private static boolean isInvalidAttestPurpose(Throwable t) {
        for (Throwable current = t; current != null; current = current.getCause()) {
            if (!"java.security.InvalidAlgorithmParameterException".equals(current.getClass().getName())) continue;
            String message = current.getMessage();
            if (message == null) continue;
            String normalized = message.toLowerCase(Locale.ROOT);
            if (normalized.contains("attest") && normalized.contains("purpose")) return true;
        }
        return false;
    }

    private static boolean hasAttestKeyAliasApi() {
        try {
            KeyGenParameterSpec.Builder.class.getMethod("setAttestKeyAlias", String.class);
            return true;
        } catch (NoSuchMethodException e) {
            return false;
        }
    }

    private void trackAlias(String alias) throws Exception {
        if (keyStore.containsAlias(alias)) {
            if (!"after".equals(mode)) throw new IllegalStateException("random test alias already exists");
        }
        aliases.add(alias);
    }

    private void check(String name, Check check) {
        try {
            check.run();
            System.out.println("PASS " + name);
        } catch (Throwable t) {
            failures++;
            System.out.println("FAIL " + name + " " + safeError(t));
        }
    }

    private interface Check { void run() throws Exception; }

    private static boolean hasCauseNamed(Throwable t, String simpleName) {
        for (Throwable current = t; current != null; current = current.getCause()) {
            if (simpleName.equals(current.getClass().getSimpleName())) return true;
        }
        return false;
    }

    private static boolean hasKeyStoreError(Throwable t, int code) {
        for (Throwable current = t; current != null; current = current.getCause()) {
            if (!"android.security.KeyStoreException".equals(current.getClass().getName())) continue;
            try {
                if (((Integer) current.getClass().getMethod("getErrorCode").invoke(current)).intValue() == code) return true;
            } catch (Throwable ignored) { }
        }
        return false;
    }

    private static boolean hasServiceSpecificError(Throwable t, int code) {
        for (Throwable current = t; current != null; current = current.getCause()) {
            if (!"android.os.ServiceSpecificException".equals(current.getClass().getName())) continue;
            try {
                if (current.getClass().getField("errorCode").getInt(current) == code) return true;
            } catch (Throwable ignored) { }
        }
        return false;
    }

    private static String safeError(Throwable t) {
        StringBuilder types = new StringBuilder();
        for (Throwable current = t; current != null; current = current.getCause()) {
            if (types.length() != 0) types.append("->");
            String name = current.getClass().getSimpleName();
            types.append(name);
            if ("ServiceSpecificException".equals(name)) {
                try { types.append(" errorCode=").append(current.getClass().getField("errorCode").getInt(current)); }
                catch (Throwable ignored) { }
            } else if ("KeyStoreException".equals(name)) {
                try { types.append(" errorCode=").append(current.getClass().getMethod("getErrorCode").invoke(current)); }
                catch (Throwable ignored) { }
            } else if ("NoSuchMethodException".equals(name) && current.getMessage() != null) {
                types.append(" method=").append(current.getMessage().replace(' ', '_'));
            } else if ("AssertionError".equals(name) && current.getMessage() != null) {
                types.append(" reason=").append(current.getMessage().replace(' ', '_'));
            }
        }
        return types.toString();
    }

    private static Date date(String value) {
        try {
            SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.ROOT);
            format.setTimeZone(TimeZone.getTimeZone("UTC"));
            format.setLenient(false);
            return format.parse(value);
        } catch (Exception e) { throw new AssertionError(e); }
    }

    private static byte[] attestationChallenge(byte[] extension) throws Exception {
        DerReader fields = attestationFields(extension);
        for (int i = 0; i < 4; i++) fields.readAny();
        byte[] challenge = fields.read(0x04);
        fields.read(0x04);
        fields.read(0x30);
        fields.read(0x30);
        fields.requireEnd();
        return challenge;
    }

    private static int attestationVersion(byte[] extension) throws Exception {
        return new java.math.BigInteger(attestationFields(extension).read(0x02)).intValue();
    }

    private static DerReader attestationFields(byte[] extension) {
        if (extension == null) throw new AssertionError("missing Android attestation extension");
        DerReader outer = new DerReader(extension);
        byte[] sequenceBytes = outer.read(0x04);
        outer.requireEnd();
        DerReader sequence = new DerReader(sequenceBytes);
        DerReader fields = new DerReader(sequence.read(0x30));
        sequence.requireEnd();
        return fields;
    }

    private static final class DerReader {
        private final byte[] bytes;
        private int position;
        DerReader(byte[] bytes) { this.bytes = bytes; }
        byte[] read(int expectedTag) {
            int tag = readByte();
            if (tag != expectedTag) throw new IllegalArgumentException("unexpected DER tag");
            int length = readLength();
            if (length < 0 || position + length > bytes.length) throw new IllegalArgumentException("invalid DER length");
            byte[] value = Arrays.copyOfRange(bytes, position, position + length);
            position += length;
            return value;
        }
        byte[] readAny() {
            int tag = readByte();
            int length = readLength();
            if (length < 0 || position + length > bytes.length) throw new IllegalArgumentException("invalid DER length");
            byte[] value = Arrays.copyOfRange(bytes, position, position + length);
            position += length;
            return value;
        }
        void requireEnd() { if (position != bytes.length) throw new IllegalArgumentException("trailing DER bytes"); }
        private int readByte() { if (position >= bytes.length) throw new IllegalArgumentException("truncated DER"); return bytes[position++] & 0xff; }
        private int readLength() {
            int first = readByte();
            if ((first & 0x80) == 0) return first;
            int count = first & 0x7f;
            if (count == 0 || count > 4 || position + count > bytes.length) throw new IllegalArgumentException("invalid DER length");
            int length = 0;
            for (int i = 0; i < count; i++) length = (length << 8) | readByte();
            return length;
        }
    }

    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) out.append(String.format(Locale.ROOT, "%02x", b & 0xff));
        return out.toString();
    }
}
