# Contributing to Android Sandbox Guard

Thank you for contributing! Because this repository builds multi-OEM rooted system modules, please follow every hygiene, testing, and compile-time isolation check below.

## Mandatory Hygiene Rules

1. **Zero Personal Data or Device Identifiers**: Never commit serial numbers, device model codes tied to personal hardware, IP addresses, local filesystem paths, or keystores (`.p12`, `.jks`, `.keystore`).
2. **Strict UNIX LF Line Endings**: All `.sh`, `.sh.tmpl`, and `.rule` files must use LF (`\n`), never CRLF (`\r\n`).
3. **Compile-Time Specialization Discipline**:
   - Put OEM-specific constants, clone user exclusions, bloat lists, and property slots strictly behind OEM build tags (`oem_hyperos`, `oem_aosp`, `oem_oplus`, `oem_oneui`, `oem_generic` / `-DOEM_*`).
   - Do not reintroduce hardcoded carrier/region defaults inside runtime code; keep defaults neutral and place regional values in `presets/*.json`.
4. **No Compiled Artifacts in Git**: Built ZIPs, `.so`, `.apk`, and intermediate headers live under gitignored `dist/` or `build/`.

## Pre-PR Verification Checklist

Run all checks locally before opening a pull request:

```bash
# 1. Privacy & LF gatekeeper
python tools/verify_privacy_leak.py

# 2. Go 6-profile verification (host + linux/arm64 + race detector)
cd guard
for tags in oem_hyperos oem_aosp oem_oplus oem_oneui oem_generic oem_generic,kernel_compat,transport_vpn; do
  go vet -tags "$tags" ./...
  GOOS=linux GOARCH=arm64 go vet -tags "$tags" ./...
  go test -race -count=1 -tags "$tags" ./...
done
cd ..

# 3. C++ 5-OEM unit tests
for oem in OEM_HYPEROS OEM_OPLUS OEM_ONEUI OEM_AOSP OEM_GENERIC; do
  g++ -std=c++17 -O2 -Wall -Wextra -Werror "-D$oem" stealth/tests/stealth_logic_test.cpp -o /tmp/stealth_test && /tmp/stealth_test
done

# 4. Python selector & privacy unit tests
python -m unittest discover -s tools -p "test_*.py" -v
```
