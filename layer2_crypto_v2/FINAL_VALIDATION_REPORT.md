# UAV-C2-PQ-L2 v2 — Final Validation & Reproducibility Report

**Validation Timestamp:** `2026-10-28`
**Overall Validation Status:** **PASS** (`157 / 157` tests passed; `17 / 17` audit findings remediated and verified; `v1` baseline 100% preserved)
**v1 Workspace (Read-Only Baseline):** `C:\Users\smanv\UAV_Security_Project\layer2_crypto`
**v2 Workspace (Hardened Implementation):** `C:\Users\smanv\UAV_Security_Project\layer2_crypto_v2`

---

## 1. Executive Validation Checklist

| Requirement | Status | Evidence |
| :--- | :--- | :--- |
| Preserve `layer2_crypto` (`v1`) 100% untouched | **PASS** | All 30 `v1` SHA-256 hashes match pre-work baseline identically (Section 4.1) |
| Remediate P0-A (`F-01`, `F-02`, `F-03`, `F-04`) | **PASS** | `SessionState.AWAITING_CONFIRM`, isolated `_pending_session`, echoed KEM key, length-framed transcript |
| Remediate P0-B (`F-15`) | **PASS** | End-to-end `ROLE_GROUND_STATION` / `ROLE_UAV` enforcement in `TrustStore`, `Sender`, and `Receiver` |
| Remediate P0-C (`F-06`, `F-12`, `F-13`) | **PASS** | Two-stage `HKDF-SHA-256`, `ML-DSA-65`-signed `RekeyPayload` & `TerminatePayload`, chained `root_secret`, atomic rollback |
| Remediate P1/P2 (`F-05`, `F-07..F-11`, `F-14`, `F-16`, `F-17`) | **PASS** | Pre-FFI FIPS length checks, `O(200)` nonce window, `VALID_COMMANDS`, finite/fresh timestamps, sequence-before-sig, `time.monotonic()` |
| Bump protocol version (`PROTOCOL_VERSION = 2`) | **PASS** | `protocol/constants.py:10`, `protocol/__init__.py:15`; rejects `v1` downgrade attempts with `VersionError` |
| Pass all baseline + new `v2` regression tests | **PASS** | `157 passed in 1.92s` (`120` baseline + `37` new `v2` security regression tests) |
| Store benchmark run in timestamped directory with raw samples | **PASS** | `results/2026-10-28T153951Z/` (`raw_benchmark_samples.csv`, `benchmark_environment.json`, CSVs, PNG) |
| Measure serialization/framing directly | **PASS** | `command_serialize_and_frame` (`0.0200 ms`), `command_parse_and_unframe` (`0.0219 ms`), `handshake_serialize_and_parse` (`0.0898 ms`) |

---

## 2. Test Suite Execution Summary

### 2.1 `v1` Baseline Verification (Read-Only)
- **Command:** `python -B -m pytest "C:\Users\smanv\UAV_Security_Project\layer2_crypto\test_protocol.py" -v -p no:cacheprovider`
- **Result:** `120 passed in 1.82s`

### 2.2 `v2` Full Regression & Adversarial Suite
- **Command:** `python -m pytest test_protocol.py -v` (in `C:\Users\smanv\UAV_Security_Project\layer2_crypto_v2`)
- **Result:** `157 passed in 1.92s` (recorded in [`TEST_RESULTS.txt`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/TEST_RESULTS.txt))
- **New `v2` Test Classes Added (`37` tests):**
  1. `TestV2HandshakeStateAndSessionPreservation` (`10` tests covering `F-01`, `F-02`, `F-03`, `F-04`, `F-05`, `v1` downgrade rejection)
  2. `TestV2RoleEnforcement` (`6` tests covering `F-15` across initiator, responder, and mid-session role checks)
  3. `TestV2RekeyAndKeyScheduleSecurity` (`6` tests covering `F-06`, `F-12`, `F-13` atomic rollback, confirm tag tampering, and signed termination)
  4. `TestV2CommandValidationAndTimestamps` (`9` parametrized tests covering `F-09` `VALID_COMMANDS` and `F-10` `NaN`/`Infinity`/negative/stale timestamps)
  5. `TestV2BoundsReplayAndLifecycle` (`6` tests covering `F-05`, `F-07`, `F-08` `O(200)` nonce window, `F-11` sequence-before-signature, `F-14` `time.monotonic()`, `F-16`, `F-17`)

---

## 3. Benchmark Artifact Locations

All `v2` benchmark outputs were generated from a single deterministic run (`2026-10-28T153951Z`, `WARMUPS = 10`, `RUNS = 100`, `BOOTSTRAP_RESAMPLES = 2000`, `BOOTSTRAP_SEED = 42`):
- **Timestamped Run Directory:** [`results/2026-10-28T153951Z/`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/results/2026-10-28T153951Z)
  - [`raw_benchmark_samples.csv`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/results/2026-10-28T153951Z/raw_benchmark_samples.csv) (`1,900` individual timing rows)
  - [`benchmark_environment.json`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/results/2026-10-28T153951Z/benchmark_environment.json)
  - [`layer2_protocol_benchmark_results.csv`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/results/2026-10-28T153951Z/layer2_protocol_benchmark_results.csv)
  - [`layer2_message_overhead_results.csv`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/results/2026-10-28T153951Z/layer2_message_overhead_results.csv)
  - [`layer2_protocol_e2e_benchmark.png`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/results/2026-10-28T153951Z/layer2_protocol_e2e_benchmark.png)
- **Synchronized Top-Level Copies (Identical SHA-256):**
  - [`layer2_protocol_benchmark_results.csv`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/layer2_protocol_benchmark_results.csv)
  - [`layer2_message_overhead_results.csv`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/layer2_message_overhead_results.csv)
  - [`layer2_protocol_e2e_benchmark.png`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/layer2_protocol_e2e_benchmark.png)

---

## 4. SHA-256 Integrity Manifests

### 4.1 Preserved `v1` Workspace (`C:\Users\smanv\UAV_Security_Project\layer2_crypto`) — Unchanged

| Relative Path (`layer2_crypto\...`) | SHA-256 Hash | Status |
| :--- | :--- | :--- |
| `protocol/__init__.py` | `DBE72C7044BDC15E3BEB6048CB1EF307A43D97E9FFBEF7A09E2BF29B8C0D37DA` | Unchanged |
| `protocol/constants.py` | `6428C72AAFF0FF940B53E3167A9FCD3AA32690D1A87483CD93968F02B1F12455` | Unchanged |
| `protocol/crypto_core.py` | `D369F80D0BC690143F928ECD40AB7A89F0909EA05F9C29776708A21BA83F8D2A` | Unchanged |
| `protocol/errors.py` | `AB74AC6FF50655DFDCDBCA7C80793E0C3E3C8E8F807B89751163C1C216D93591` | Unchanged |
| `protocol/identity.py` | `756706D6BDFEAB9ABD371B568FDE60525443FC7B48F1978DA0E9F40097BA2317` | Unchanged |
| `protocol/messages.py` | `CF9ABBC25AA92DDAC18D56AD9609B20C32DED2AFAFF0DE7BC58ABCEDD575161C` | Unchanged |
| `protocol/receiver.py` | `0CD12425F125C2CE4AB09C58F41864F8DC667AAF9BFC13A8227B16B33D9CD691` | Unchanged |
| `protocol/sender.py` | `A0A00A65DF554480BF47C1137427B85584E6E50247EE08A420CEAF545A83A784` | Unchanged |
| `protocol/session.py` | `7EDD655D8094349336D43C667E20DC24EF1F6BF8742CC941D5C9B4810A30CBA5` | Unchanged |
| `protocol/transport.py` | `9B6C635CB636DED24334047C6571E500EAE26B88C628FF670EBE244673EAA33C` | Unchanged |
| `test_protocol.py` | `56E29107CDC51A2C57DA5E244F306B2C43B977CE14EF9BB22D7A48EE9FB4DEC5` | Unchanged |
| `layer2_protocol_benchmark.py` | `0A6419E8B6F5B1163CE84A90D29FDFE019B592CB5E89A1BC17139A1AACFD6120` | Unchanged |
| `layer2_protocol_benchmark_results.csv` | `506A3853328C9776543EAAFF4E1E15C460E1B6CD8099A9E931EDA40FE57A53E1` | Unchanged |
| `layer2_message_overhead_results.csv` | `AF511F93D8F78BCEFE99B60FEB2E9DB446C9CB542C4C165CC54FAE539E81DC6D` | Unchanged |
| `layer2_protocol_e2e_benchmark.png` | `22BBCC53720E69EBA73D4243577AEB8FB03F62CE9A5379CC663354BE8D81AF6B` | Unchanged |

### 4.2 New `v2` Workspace (`C:\Users\smanv\UAV_Security_Project\layer2_crypto_v2`)

| Relative Path (`layer2_crypto_v2\...`) | SHA-256 Hash |
| :--- | :--- |
| `protocol/__init__.py` | `7FEB1DA96D146CB6C3EAB0B8BCC56F4E746B4B84EE24BE58A9DDEFDF1121B7ED` |
| `protocol/constants.py` | `5427822073A6AE776CCAF3EA06FAF2EAE44D406A24F4D437979AFBEF3359CDD3` |
| `protocol/crypto_core.py` | `E1A35CE0FBE42EF8D52FDC8AAB3DCB227BCD04DBF683CEFD5BF874A238B50712` |
| `protocol/errors.py` | `210800DEDD68ECBFCC8F5174A16664054E98A2A37DAEF3BB8B73DA2E45D81404` |
| `protocol/identity.py` | `1C91CF78716303BCD0E6619BFEC34C13FAA5CD1A935C2D0A1748313EF59AEA65` |
| `protocol/messages.py` | `147CB15910FC01AEF0F10750EF30B03C1F651F6A92A87DCE300F621593C7EFB8` |
| `protocol/receiver.py` | `823A57B579F2AA9A4027C0DF50AF45C389D2F77F68CF9C156AEF4DA772D45BFA` |
| `protocol/sender.py` | `5F3972B9DBA7C47589644C42F3B7E6F81FB7E471564494FED607A69EFE48D7DB` |
| `protocol/session.py` | `214C8C3ECA61293BE16D00206D4E4521BC0BD3437A6B52A80CA1BEE531F4068D` |
| `protocol/transport.py` | `9B6C635CB636DED24334047C6571E500EAE26B88C628FF670EBE244673EAA33C` |
| `test_protocol.py` | `3022DEFEB5AF94FA51C1BD331995D8F601A087895ABE226655E67984273DDD4A` |
| `layer2_protocol_benchmark.py` | `FAE4651EE6A284B3BF59A17A724D2710719461451225A680C5DA093A85C27F36` |
| `layer2_protocol_benchmark_results.csv` | `0C827B70AE97B10429BEB46CBD6D9DE48F6FD3C16AB51DA16498DFC6AB4D74DC` |
| `layer2_message_overhead_results.csv` | `26E21C6821254C76B8D2A6B5E89571E13B952FF53F8BE7AB46873D6B9A4BE64D` |
| `layer2_protocol_e2e_benchmark.png` | `63E5BD77C45F9E4D26E41052E60DAD59AD2ACC1E48AADC03E2E139044E991239` |
| `results/2026-10-28T153951Z/raw_benchmark_samples.csv` | `1F1D4C0E3E57DDD7EC5C79DE9928D366ABEFF430142D7DF0655925FEE8364FEE` |
| `results/2026-10-28T153951Z/benchmark_environment.json` | `E10F699C712792586B3EC9724EF2E281B8E24422DAEFC3A2A072DDBAC8F2FECC` |
| `SECURITY_REMEDIATION_REPORT.md` | `67D2DFF3E3C0672525C816713DB8F9BC0837220BB6BAB2CAD6C9360535835B32` |
| `SECURITY_TRACEABILITY.csv` | `AC39908E91DBE054EB05FEF0A3C5BBB820D8EB0DE5C6F7EC318EB1B84C9C4594` |
| `PROTOCOL_V2_SPEC.md` | `E7E7018141D40325448F632F056C209F621023F00DAFC881B7F1FF45314D2BC5` |
| `BENCHMARK_METHODOLOGY.md` | `91D8D4EE608BB70D809E79338859ADA8B948FC836F9229724433E20A2751354B` |
| `CHANGELOG_V2.md` | `9630E36756EA902EEF0A01D8974DCF409A3C7B66AF3F184BB34CE6EFA2362E40` |
| `NOT_REVIEWED_AND_LIMITATIONS.md` | `3A7734D00A18C5B3572395528DDE07EFBCB3D880D39D60661A81CCEDC77004DF` |
| `README.md` | `72AB94E9C56117AEC4191E93831AA99077F4F3B83A692AD72C61959468EE8873` |
| `TEST_RESULTS.txt` | `11D4706174850405022F75E3CA225F6A9DA242CADCB1FD4567DFE0C17653D209` |

---

## 5. Summary of Residual Risks & Future Work
1. **Hex-in-JSON Wire Overhead (`6,798 B` per command, `32,097 B` per 3-message handshake):** Switching from hex-encoded JSON to compact binary struct/CBOR framing in a future revision would reduce wire size by ~50% (`~3.4 KB` per command, `~15.6 KB` per handshake) for low-bandwidth serial/radio links.
2. **CPython Memory Zeroization (`F-16`):** Mutable `bytearray` key buffers are overwritten in place upon session termination/rekey, but CPython's immutable `bytes` objects cannot be deterministically zeroed prior to garbage collection without a C extension or hardware security module.
3. **Formal Verification:** Modeling the `v2` handshake and chained rekey state machine in Tamarin Prover or ProVerif is recommended prior to hardware-in-the-loop deployment.
