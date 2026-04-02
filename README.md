# axios npm Supply Chain Compromise — IoC Scanner

Cross-platform Python scanner for indicators of compromise from the **axios npm supply chain attack** (2026-03-31), attributed to DPRK-linked threat actor UNC1069.

The malicious `axios@1.14.1` and `axios@0.30.4` packages injected a phantom dependency (`plain-crypto-js`) that deployed a cross-platform RAT via postinstall hook. During an approximately three-hour exposure window, any system that ran `npm install` and resolved to the backdoored versions executed the payload automatically.

**Source:** [Huntress — Supply Chain Compromise of axios npm Package](https://www.huntress.com/blog/supply-chain-compromise-axios-npm-package)

## What it checks

| # | Check | Description |
|---|-------|-------------|
| 1 | **Filesystem artifacts** | Platform-specific RAT binaries and dropper remnants (`com.apple.act.mond`, `wt.exe`, `system.bat`, `/tmp/ld.py`, temp VBS/PS1 files) |
| 2 | **Registry persistence** | Windows `MicrosoftUpdate` Run key → `system.bat` |
| 3 | **node_modules crawl** | Finds `plain-crypto-js` directories anywhere on disk, flags the anti-forensics `package.json` swap |
| 4 | **Lockfile scan** | Format-aware parsing of `package-lock.json` (v1/v2/v3), `yarn.lock`, and `pnpm-lock.yaml` — matches exact package names to avoid false positives from similarly-named packages (e.g. `gaxios` vs `axios`) or unrelated packages at the same version |
| 5 | **Network connections** | Active connections to C2 IP `142.11.206.73`, DNS cache hits for `sfrclak.com`, `calltan.com`, `callnrwise.com` |
| 6 | **Running processes** | RAT processes with context-aware filtering (e.g. `wt.exe` only flagged from `ProgramData`, not legit Windows Terminal) |
| 7 | **npm cache** | SHA-256 hash matching against known payload hashes in the content-addressed cache store |

## Usage

```bash
# No dependencies — stdlib only, Python 3.7+
python3 axios_ioc_scanner.py

# Run as root/admin for full filesystem and network visibility
sudo python3 axios_ioc_scanner.py
```

Exits `0` if clean, `1` if any critical finding. Writes a JSON report to `~/axios_ioc_report.json`.

## IoCs covered

### Malicious packages

| Package | Version | SHA-1 |
|---------|---------|-------|
| axios | 1.14.1 | `2553649f2322049666871cea80a5d0d6adc700ca` |
| axios | 0.30.4 | `d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71` |
| plain-crypto-js | 4.2.1 | `07d889e2dadce6f3910dcbc253317d28ca61c766` |

### Payload hashes (SHA-256)

| Platform | SHA-256 |
|----------|---------|
| Windows Stage 1 | `f7d335205b8d7b20208fb3ef93ee6dc817905dc3ae0c10a0b164f4e7d07121cd` |
| Windows Stage 2 | `617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101` |
| macOS | `92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a` |
| Linux | `fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf` |

### Network indicators

| Indicator | Type |
|-----------|------|
| `sfrclak.com` | C2 domain |
| `calltan.com` | Related C2 domain |
| `callnrwise.com` | Related C2 domain |
| `142.11.206.73` | C2 IP |
| Port `8000`, path `/6202033` | C2 endpoint |
| `mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)` | RAT User-Agent (all platforms) |

### Filesystem indicators

| Platform | Path |
|----------|------|
| macOS | `/Library/Caches/com.apple.act.mond` |
| Windows | `%PROGRAMDATA%\wt.exe` |
| Windows | `%PROGRAMDATA%\system.bat` |
| Windows | `%TEMP%\6202033.vbs` |
| Windows | `%TEMP%\6202033.ps1` |
| Linux | `/tmp/ld.py` |
| All | `node_modules/plain-crypto-js/` |

### Registry (Windows)

| Key | Value | Data |
|-----|-------|------|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | `MicrosoftUpdate` | `%PROGRAMDATA%\system.bat` |

## Remediation (if compromised)

1. **Isolate** the system from the network immediately
2. **Do not clean in place** — rebuild from a known-good image
3. **Rotate all credentials** accessible from the system: npm tokens, SSH keys, AWS/cloud keys, `.env` secrets, API keys, OAuth tokens, CI/CD secrets
4. **Block C2** at the network perimeter: `sfrclak.com`, `calltan.com`, `callnrwise.com`, `142.11.206.73:8000`
5. **Pin axios** to safe versions: `1.14.0` (1.x) or `0.30.3` (0.x)
6. **Clean up**: `rm -rf node_modules/plain-crypto-js && npm ci`
7. **Purge npm cache**: `npm cache clean --force`

## Attribution

Multiple researchers and Huntress have linked this campaign to **UNC1069**, a suspected North Korean (DPRK) state-sponsored threat actor. The macOS binary has overlaps with BlueNoroff's RustBucket malware and uses the internal project name `macWebT`.

## License

MIT
