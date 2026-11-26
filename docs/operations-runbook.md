# Operations Runbook — Earned Autonomy Graduation Engine

**Audience:** Security Operations (SOC), Application Owners, and Platform/IAM Engineers operating an AI agent governed by Earned Autonomy.

---

## 1. Onboarding a New Agent or Action Class

1. **Author the Domain Contract (`contracts/<domain>.json`):**
   - Declare `contract_id`, `domain`, `threshold` (minimum consecutive verified runs required for `Tier 2`), `action_classes` (separate read vs. write classes), and `protected_invariants` (non-target records/groups that must never change).
2. **Provision Separate Identities:**
   - **Agent runtime identity:** Holds zero database/core write credentials. Calls only the Governed API.
   - **Out-of-band Observer identity:** Read-only access to the system of record + exclusive access to the verifier signing key (`observer.key.pem` in prototype; hardware-backed HSM/KMS in production).
3. **Pin the Verifier Public Key & Compute Build Fingerprint:**
   ```bash
   python -B cli.py init-key --out-dir ./verifier-keys
   python -B cli.py fingerprint --manifest ./agent-manifest.json
   ```
   - Distribute **only** `verifier.pub.pem` to the Governed API and CI/CD release gate.
   - Register the exact `build_fingerprint` in the release-admission allowlist (`D01`). Any unadmitted fingerprint is rejected with HTTP `403 release_not_admitted`.

---

## 2. Responding to Alerts & Tier Demotions

| Signal / Exit Code | Meaning | Immediate Operator Action |
|---|---|---|
| **Exit `0` · `currency: STALE`** (`build_fingerprint_drift`) | Prompt, model, tool schema, or policy changed after prior `Verified` receipts were signed. Action class auto-demoted `Tier 2 -> Tier 1`. | Confirm the change was intentional and admitted (`D01`). Re-earn `Tier 2` with `N` fresh verified runs under the new fingerprint. |
| **Exit `0` · `demotion_reason: unverified_missing_readback`** | Observer could not bind an independent readback to the commit/response. Streak reset to `0`; stays `Tier 1`. | **Do not retry the write automatically.** Reconcile the actual system-of-record state manually first, fix observer connectivity, and resume only after readback is restored. |
| **Exit `1` · `GLOBAL HOLD: ACTIVE`** (`Tier 0 / REVOKED`) | Bound contradiction detected (e.g., protected row `L42` mutated during an `L17` commit). Governed API blocks all calls with HTTP `403 autonomy_revoked_global_hold` and emits a `critical` `D04` SOC alert. | 1. Preserve the hash-chained ledger (`ledger.jsonl`) and correlated SOC alert JSON.<br>2. Investigate root cause in the writer/tool boundary.<br>3. Restore protected state out-of-band.<br>4. Ship a remediated build with a **new** `build_fingerprint`.<br>5. Record a signed `ReinstatementReceipt` bound to the new fingerprint (`cli.py reinstate`). Agent returns to **`Tier 1` (never directly to `Tier 2`)**. |
| **Exit `2` · `LedgerIntegrityError`** | Hash chain broken (single-byte edit, deletion, or reordering in `ledger.jsonl`) or invalid signature. | Treat as audit-tampering incident. Freeze the ledger copy, escalate to SOC, and fail closed. |

---

## 3. Verifier Key Rotation & Evidence Hygiene

- **Key rotation:** Generate a new Ed25519 keypair (or HSM key version), publish the new `verifier.pub.pem` to verifiers, and cut over the observer to the new `verifier_kid`. Retain old public keys read-only for historical ledger audits.
- **Evidence hygiene:** Receipts retain only opaque `action_id`s, counts, SHA-256 digests, and boolean invariant verdicts — **never** bearer tokens, passwords, session cookies, or raw customer record bodies.
- **Scope boundary:** The local prototype uses file-backed Ed25519 keys and local correlated alert JSON (`ea.soc-alert.v1`). Production deployments must bind the observer to an HSM/KMS signer and forward correlated alerts to the enterprise SIEM (e.g., Microsoft Sentinel).
