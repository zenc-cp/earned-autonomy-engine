# 20-Minute Executive Pitch & 10-Minute Live Demo Script

**Audience:** Security Architects, CISOs, and Engineering Leaders  
**Format:** 20-minute pitch + 10-minute live demo + 15-minute Q&A

---

## Positioning Statement (The One-Sentence Hook)

> **Earned Autonomy is not another pre-action agent guardrail.** Pre-action gateways (OPA, Cerbos, AGT, APIM) answer *"Was the agent allowed to try?"* Earned Autonomy answers the missing post-run question: *"Does independent, out-of-band evidence prove the intended change happened and protected state stayed untouched — and did this specific build earn or lose its autonomy tier?"*

---

## 20-Minute Pitch Arc (8 Beats)

| Time | Beat | Key Message & Evidence |
|---|---|---|
| `0:00–2:00` | **The Autonomy Dilemma** | Enterprises are stuck between permanent Human-in-the-Loop (zero ROI) and blind standing trust (one prompt edit or bad write causes silent cross-customer damage). |
| `2:00–4:30` | **Why Existing Tools Aren't Enough (Market REA)** | Code-level audit of both Microsoft (`agent-governance-toolkit`, `AI-Gateway`) and non-Microsoft peers (`Cerbos`, `OrgKernel`, `Clawvisor`, `aflock`, `Decionis/AgentSafe`): everyone stops at pre-action gating or runtime self-logging. Even `AgentSafe` allows finalization when effect observation is omitted. |
| `4:30–7:30` | **The Two-Plane Architecture** | Walk through `docs/architecture.png`: Plane 1 (Pre-Action Governance: OBO + Policy + HITL) vs. Plane 2 (Post-Run Independent Verification: Read-Only Observer + Build Fingerprint + Graduation Engine + Human Desk). One-way evidence boundary — zero write credentials in Plane 2. |
| `7:30–10:30` | **Four Core Primitives** | (1) `SHA-256(model + prompt + tools + policy)` build fingerprinting (`STALE` on 1-char drift); (2) Pinned Ed25519 observer/verifier key separation; (3) Append-only SHA-256 hash-chained ledger; (4) Per-action-class graduation (`read_loan` never graduates `extend_due_day`) + sticky `Tier 0 / global_hold`. |
| `10:30–13:30` | **Covering All 7 Security Boundaries (D01–D07)** | Show how the single engine covers release admission (`D01`), indirect injection quarantine (`D02`), cross-customer isolation (`D03`), correlated SOC alerts (`D04`), bounded servicing (`D05`), human-before-commit (`D06`), and independent audit reconstruction (`D07`). |
| `13:30–16:00` | **Cross-Industry Portability** | Same unchanged engine runs `contracts/banking-loan.json` (`L17`/`L42`) and `contracts/it-access.json` (`read_access_profile` / `set_temp_expiry` with privileged group protection). |
| `16:00–18:00` | **Operations & Trust Boundaries** | Walk through `docs/operations-runbook.md`: how SOC responds to `global_hold`, how a remediated build + signed `ReinstatementReceipt` restores `Tier 1` (never directly `Tier 2`). |
| `18:00–20:00` | **Honest Limits & Pilot Ask** | Clearly separate what is verified today (16/16 automated tests, live loopback E2E demo, portable CLI) from production requirements (HSM/KMS signer, live Entra delegated binding, Sentinel SIEM ingestion, and uncoached human practitioner trial). |

---

## 10-Minute Live Demo Script (`python -B live_desk.py --port 8790 --open`)

1. **`0:00–1:00` Baseline:** Show `GLOBAL HOLD: CLEAR`, `Build v1`, `L17` (Day 30 v12) and protected `L42` (Day 90 v5), both action classes at `Tier 1 (0/3)`.
2. **`1:00–2:30` Scoped Reads & Per-Action Graduation (`D03`):** Click **Read L17 (200)** -> **Read L42 (403 + SOC alert)** -> **Read L17 (200)**. Point out: `read_loan` promotes to **`Tier 2 (Bounded Pilot)` (3/3)** while `extend_due_day` stays isolated at **`Tier 1` (0/3)**.
3. **`2:30–3:30` Indirect Prompt Injection (`D02`):** Click **Simulate Indirect Injection (D02)**. Show retrieved untrusted note quarantined as data, zero authority granted, `L42` untouched, correlated `D02` SOC alert logged.
4. **`3:30–4:30` Build Drift (`STALE`):** Click **Edit Prompt (+1 Drift -> STALE)**. Show build SHA change -> `read_loan` immediately marked `STALE` and auto-demoted back to `Tier 1 (0/3)`.
5. **`4:30–5:30` Unadmitted Release (`D01`):** Click **Stage Unadmitted Build**, then **Read L17**. Show HTTP `403 release_not_admitted` + `D01` SOC alert.
6. **`5:30–7:30` Governed Write + Protected Tamper -> Sticky Revocation (`D06`/`D04`):** Click **Propose +7d Extension (202 Hold)** -> **Approve + Tamper L42 (Fault Injection)**. Show `L42` caught by read-only observer -> **`GLOBAL HOLD: ACTIVE`**, both classes revoked to **`Tier 0`**, and clicking **Read L17** now returns **HTTP `403 autonomy_revoked_global_hold`** (runtime enforcement!).
7. **`7:30–9:00` Remediate & Reinstate (`D07`):** Click **Reinstate on New Build (Tier 1)**. Show signed `ReinstatementReceipt` on new build lifting `global_hold` back to **`Tier 1`** (never directly `Tier 2`). Expand **Raw Ed25519-Signed Receipts** and **Correlated SOC Alerts**.
8. **`9:00–10:00` CLI Portability Proof:** Run `python -B -m unittest -v test_engine_core` in terminal to show hash-chain tamper detection (exit `2`) and the same engine evaluating `contracts/it-access.json` (exit `1` on hold -> exit `0` after reinstatement).
