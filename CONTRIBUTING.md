# Contributing to KernBox

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

# 3. C++ 5-OEM & C11 Broker unit tests
for oem in OEM_HYPEROS OEM_OPLUS OEM_ONEUI OEM_AOSP OEM_GENERIC; do
  g++ -std=c++17 -O2 -Wall -Wextra -Werror "-D$oem" stealth/tests/stealth_logic_test.cpp -o /tmp/stealth_test && /tmp/stealth_test
done
gcc -std=c11 -O2 -Wall -Wextra -Werror broker/broker_core.c broker/tests/broker_test.c -o /tmp/broker_test && /tmp/broker_test

# 4. Java Host Unit Tests & APK Compilation
javac --release 11 -encoding UTF-8 -Xlint:all,-options -Werror -cp "$ANDROID_HOME/platforms/android-35/android.jar" -d /tmp/stealth_classes stealth/java/com/sandbox/stealth/*.java stealth/tests/StealthHookHostTest.java
java -cp "/tmp/stealth_classes:$ANDROID_HOME/platforms/android-35/android.jar" com.sandbox.stealth.StealthHookHostTest
javac --release 11 -encoding UTF-8 -Xlint:all,-options -Werror -d /tmp/ctrl_classes controller/java/com/sandbox/controller/BrokerProtocol.java controller/java/com/sandbox/controller/Strings.java controller/tests/BrokerProtocolHostTest.java
java -cp /tmp/ctrl_classes com.sandbox.controller.BrokerProtocolHostTest
python controller/build-controller.py --out /tmp/KernBox.apk
python verify/build-probe.py --out /tmp/KernBoxVerify.apk

# 5. Python selector, packaging & privacy unit tests
python -m unittest discover -s tools -p "test_*.py" -v
```
