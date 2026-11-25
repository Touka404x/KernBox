## Summary

- What problem does this PR solve?
- Affected components (`guard/` / `stealth/` / `controller/` / `verify/` / `packaging/` / `tools/` / docs):

## Hygiene & Compile-Time Specialization Checklist

- [ ] **Zero sensitive data**: Ran `python tools/verify_privacy_leak.py` -> `findings=0` (no serials, IMEIs, MACs, private IPs, local paths, or keystores)
- [ ] **Strict UNIX LF line endings**: All `.sh`, `.sh.tmpl`, `.rule`, `.prop.tmpl` files use LF (`\n`)
- [ ] **Compile-time discipline**: OEM/kernel logic stays gated behind `oem_*` / `kernel_compat` / `-DOEM_*` flags; no hardcoded regional/carrier defaults outside `presets/`
- [ ] **Tests passing**:
  - [ ] Python unit tests (`python -m unittest discover -s tools -p "test_*.py" -v`)
  - [ ] Go 6-profile `go vet` (host + `linux/arm64`) & `go test -race -count=1 ./...`
  - [ ] C++ 5-OEM `stealth_logic_test.cpp`
  - [ ] Java `StealthHookHostTest` & `BrokerProtocolHostTest`
- [ ] **No compiled artifacts committed**: No `.apk`, `.zip`, `.so`, or keystore files tracked in git
