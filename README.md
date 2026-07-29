# Tricky Store OSS – A Trick of Keystore They Forgot to Hide

A **FOSS** alternative to the proprietary [TrickyStore](https://github.com/5ec1cff/TrickyStore) Magisk module.  

## ❓ Why?

We all know about the [multiple violations and questionable practices by the author of TrickyStore](docs/5ec1cff-violations.md).  
Because of this, I decided to create a **complete rewrite from scratch**, based on:  

- Various projects mentioned in [Acknowledgement](https://github.com/beakthoven/TrickyStoreOSS?tab=readme-ov-file#%EF%B8%8F-acknowledgement) section
- Official changelogs and expected behavior of newer releases  
- My own feature additions and fixes that were part of an earlier fork of the older codebase  

Tricky Store OSS is **rightfully licensed under GPLv3**, ensuring it stays free and compliant with open-source laws.

## ✨ Features

- 100% **FOSS**
- Developed to match the proprietary implementation’s behavior and feature set as closely as possible

## 📱 Requirements
- Android 10 or above

## 📦 Installtion

1. Flash this module and reboot
2. (Optional) Place an unrevoked hardware keybox.xml at `/data/adb/tricky_store/keybox.xml` for extended integrity
3. (Optional) Customize target packages in `/data/adb/tricky_store/target.txt`
4. (Optional) Customize security patch in `/data/adb/tricky_store/security_patch.txt`
5. Enjoy!


**All configuration files will take effect immediately.**

### keybox.xml

format:

```xml
<?xml version="1.0"?>
<AndroidAttestation>
    <NumberOfKeyboxes>1</NumberOfKeyboxes>
    <Keybox DeviceID="...">
        <Key algorithm="ecdsa|rsa">
            <PrivateKey format="pem">
-----BEGIN EC PRIVATE KEY-----
...
-----END EC PRIVATE KEY-----
            </PrivateKey>
            <CertificateChain>
                <NumberOfCertificates>...</NumberOfCertificates>
                    <Certificate format="pem">
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
                    </Certificate>
                ... more certificates
            </CertificateChain>
        </Key>...
    </Keybox>
</AndroidAttestation>
```

### Mode configuration

Tricky Store OSS supports two modes: leaf certificate hacking and certificate generation.
On TEE-broken devices, leaf hacking won’t work since the leaf certificate can’t be retrieved from TEE. The module automatically selects the appropriate mode for your device.

You can override this behavior per package:
- Add ! → Force certificate generation mode
- Add ? → Force leaf hacking mode
- No symbol → Automatic mode

For example:

```
# target.txt
# use automatic mode for gsf
com.google.android.gsf
# use leaf certificate hacking mode for key attestation App
io.github.vvb2060.keyattestation?
# use certificate generating mode for gms
com.google.android.gms!
```

### Customize security patch level 

Create the file `/data/adb/tricky_store/security_patch.txt`.

Simple:

```
# Hack os/vendor/boot security patch level
20241101
```

Advanced:

```
# os security patch level is 202411
system=202411
# do not hack boot patch level
boot=no
# vendor patch level is 20241101 (another format)
vendor=2024-11-01
# default value
# all=20241101
# keep consistent with system prop
# system=prop
```

Note: This only affects KeyAttestation results.
It does not change system properties; use resetprop separately if needed.

## 🤝 Contributions
PRs are welcome. Thank you for supporting true open-source development.

## ❤️ Acknowledgement

- [BootloaderSpoofer](https://github.com/chiteroman/BootloaderSpoofer) (dead, relied on forks and mirrors)
- [FrameworkPatch](https://github.com/chiteroman/FrameworkPatch) (dead, relied on forks and mirrors)
- [KeyAttestation](https://github.com/vvb2060/KeyAttestation)
- [KeystoreInjection](https://github.com/aviraxp/Zygisk-KeystoreInjection)
- [PLTI](https://github.com/PerformanC/PLTI)
- [LSPosed](https://github.com/LSPosed/LSPosed)
- [PlayIntegrityFork](https://github.com/osm0sis/PlayIntegrityFork)
