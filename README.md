# Tricky Store OSS

*A trick of Keystore they forgot to hide.*

A fully open-source, FOSS alternative to the proprietary [TrickyStore](https://github.com/5ec1cff/TrickyStore) Magisk module.

---

## Why this exists

TrickyStore's author has a track record of [violations and questionable practices](docs/5ec1cff-violations.md)

So this is a complete rewrite from scratch, built on:

- The projects credited in [Acknowledgements](#acknowledgements)
- Official changelogs and the expected behavior of newer releases
- Original fixes and features carried over from an earlier fork of the old codebase

Licensed under **GPLv3** and it stays that way.

---

## Features

- 100% FOSS, no closed-source components
- Matches the proprietary implementation's behavior and feature set as closely as possible

## Requirements

- Android 10+

---

## Installation

1. Flash the module and reboot
2. *(Optional)* Place an unrevoked hardware keybox at `/data/adb/tricky_store/keybox.xml` for extended integrity
3. *(Optional)* Customize target packages in `/data/adb/tricky_store/target.txt`
4. *(Optional)* Customize the security patch level in `/data/adb/tricky_store/security_patch.txt`

All config files take effect immediately — no reboot needed after step 1.

---

## Configuration

### `keybox.xml`

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
                <!-- more certificates -->
            </CertificateChain>
        </Key>
    </Keybox>
</AndroidAttestation>
```

### `target.txt` — mode selection

Tricky Store OSS supports two modes: **leaf certificate hacking** and **certificate generation**. On TEE-broken devices, leaf hacking won't work since the leaf certificate can't be retrieved from TEE. The module picks the right mode automatically per device.

Override per package with a suffix:

| Suffix | Behavior |
|--------|----------|
| *(none)* | Automatic mode |
| `?` | Force leaf hacking |
| `!` | Force certificate generation |

```
# target.txt
com.google.android.gsf              # automatic
io.github.vvb2060.keyattestation?   # leaf hacking
com.google.android.gms!             # certificate generation
```

### `security_patch.txt` — patch level override

**Simple form** — hacks os/vendor/boot patch level to one value:

```
20241101
```

**Advanced form** — per-partition control:

```
# system patch level
system=202411
# don't touch boot patch level
boot=no
# vendor patch level, alternate date format
vendor=2024-11-01
# default fallback for unset partitions
# all=20241101
# keep consistent with system prop
# system=prop
```

> This only affects KeyAttestation results so it does **not** change system properties. Use `resetprop` separately if you need that.

---

## Contributing

PRs welcome. Thanks for backing real open-source work.

## Acknowledgements

- [BootloaderSpoofer](https://github.com/chiteroman/BootloaderSpoofer) *(dead, relies on forks/mirrors)*
- [FrameworkPatch](https://github.com/chiteroman/FrameworkPatch) *(dead, relies on forks/mirrors)*
- [KeyAttestation](https://github.com/vvb2060/KeyAttestation)
- [KeystoreInjection](https://github.com/aviraxp/Zygisk-KeystoreInjection)
- [PLTI](https://github.com/PerformanC/PLTI)
- [LSPosed](https://github.com/LSPosed/LSPosed)
- [PlayIntegrityFork](https://github.com/osm0sis/PlayIntegrityFork)