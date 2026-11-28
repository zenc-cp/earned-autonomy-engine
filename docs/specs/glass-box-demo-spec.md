# Spec v2 (Revised After `/critic`): "The Glass Box" — Unified End-to-End Earned Autonomy Stage

**Status:** Revised v2 — ready for implementation approval  
**Target Files:** `live_desk.py`, `e2e_runner.py` (additive fields + `admit_current_build()` + `POST /api/reset`), `test_e2e.py`  
**Design System:** Sovereign Ledger (`DESIGN.md`, light + dark, zero external assets, strict `default-src 'none'` CSP)

---

## 1. Objective & Honest Evidence Boundary

Replace the raw button-grid UI in `live_desk.py` with a single-screen **"Glass Box" End-to-End Stage** that both non-technical executives and technical security architects understand in under 60 seconds — with **both PASS and BLOCK** scenarios shown clearly and honestly:

- **Honest labeling (never fake LLM theater):** The left pane is explicitly badged **`Simulated Borrower / Employee Client (Deterministic Local API)`** — every click calls the real loopback `/api/*` endpoints, real SQLite ledger, real isolated `observer_worker.py` subprocess, and real SHA-256 hash-chained `ledger.jsonl`.
- **Two disclosure depths:**
  - **Executive View (default):** Command Header + 4-Stage Flow Ribbon + Borrower Chat & Paired Controls (left) + Per-Action Tier Cards & Read-Only Observer Table (right) — designed to fit cleanly on a `1280x720` projector.
  - **Technical View (toggle):** Reveals the full Evidence Drawer (Activity Timeline, Correlated SOC Alerts `D04`, Signed Ed25519 Receipts, SHA-256 Chain Verification, and `verifier.pub.pem` fingerprint).
  - *(Note: `D04` alerts are explicitly labeled `local correlated JSON — not live SIEM/Sentinel ingestion`, and the local Ed25519 key is labeled `isolated subprocess PEM — production uses HSM/KMS`.)*

---

## 2. Layout Architecture (`1280x720` Projector-First)

```text
+-----------------------------------------------------------------------------------+
| HEADER: Earned Autonomy · Glass Box | [Banking|IT] | [Exec|Tech] | [Reset] | [OK] |
+-----------------------------------------------------------------------------------+
| 4-STAGE LIVE FLOW RIBBON (color + plain-English label):                           |
| [1. User/Agent] -> [2. Policy/ID Gate] -> [3. Ledger] -> [4. Observer & Standing] |
+----------------------------------------+------------------------------------------+
| LEFT (5 cols): BORROWER / AGENT CLIENT | RIGHT (7 cols): SECURITY & AUDITOR DESK  |
|  - Badge: Deterministic Local Client   |  - 2 Per-Action Tier Cards (3-seg meter) |
|  - Live transcript (latest 6 turns,    |  - Read-Only Observer Ledger Table       |
|    scrolls cleanly; PASS/BLOCK pills)  |    (L17 Target + L42 Protected Lock)     |
|  - Scenario Picker (5 Pass/Block pairs)|  - Chain & Key Strip + Verify Chain btn  |
|    + Inline 202 Human Approver Card    |                                          |
|    + Unadmitted Build Recovery button  |                                          |
+----------------------------------------+------------------------------------------+
| [TECHNICAL VIEW DRAWER]: Activity Timeline | SOC Alerts (D04) | Ed25519 Receipts  |
+-----------------------------------------------------------------------------------+
```

---

## 3. Five Paired PASS vs. BLOCK Scenarios (Both Domains)

| # | Control Pair | PASS Scenario | BLOCK / Adversary Scenario | 4-Stage Flow Ribbon & Recovery |
|---|---|---|---|---|
| 1 | **Scope (`D03`)** | *"Read my own loan L17"* -> HTTP `200`, `1/1` record | *"Read borrower B's loan L42"* -> HTTP `403`, `0/0` records | PASS: Stages 1–4 green (`read_loan` +1). BLOCK: Stage 2 red `BLOCKED 403 (D03)`, Stage 3 `Unchanged`, Stage 4 green `VERIFIED DENIAL` (`read_loan` +1 — explicitly explained in chat: *"Policy correctly blocked cross-customer access, so the observer credited a verified denial"*). |
| 2 | **Content (`D02`)** | *"Read clean L17 record"* -> HTTP `200` | *"Read L17 with hidden prompt injection"* -> quarantined | Stage 2 amber `D02 QUARANTINED`, Stage 3 `Unchanged`, Stage 4 green `VERIFIED` (zero authority granted; `L42` untouched). |
| 3 | **Release (`D01`)** | **Admit Current Build** (or baseline v1) -> serves normally | **Stage Unadmitted Build** + attempt read -> HTTP `403` | Stage 2 red `BLOCKED 403 (D01 release_not_admitted)`. Presenter can click **Admit Current Build** (`POST /api/admit-build`) to recover cleanly without resetting the demo! |
| 4 | **Write & Invariant (`D05`/`D06`)** | *"Extend L17 +7d"* -> `202 Hold` -> **Approve Clean** (`v12->13`) | *"Extend L17 +7d"* -> `202 Hold` -> **Approve + Tamper L42** | Clean: all 4 stages green (`extend_due_day` +1). Tamper: Stage 4 crimson `CONTRADICTION -> GLOBAL HOLD / TIER 0`; next call blocked at Stage 2 (`HTTP 403 autonomy_revoked_global_hold`). |
| 5 | **Drift, Blind Spot & Recovery (`D07`)** | **Reinstate on New Build** -> lifts `global_hold` to `Tier 1` | **Edit Prompt (+1 Drift -> `STALE`)** & **Omit Readback (`Unverified`)** | Drift: Stage 4 amber `STALE` (`Tier 2 -> Tier 1`). Omit Readback: Stage 4 amber `UNVERIFIED` (streak resets to `0`). Reinstate: Stage 4 green `REINSTATED AT TIER 1` (never directly Tier 2). |

*(Switching to **IT Identity** dynamically updates every prompt, table header, and button to `CONT-17` / `ADMIN-42`, `read_access_profile` / `set_temp_expiry`.)*

---

## 4. Technical Contract & Fixes From `/critic`

1. **No dead-end on D01 Unadmitted Build (Critic C-01 fix):** Add `admit_current_build()` in `e2e_runner.py` + `POST /api/admit-build` in `live_desk.py` (button enabled whenever `release_admitted == false`) so a presenter can demonstrate D01 blocking *and* cleanly admit the build to continue the demo without a full reset.
2. **Explicit explanation of D03 verified denial (Critic C-02 fix):** When `L42` returns HTTP `403`, Stage 2 shows **BLOCKED (403)** in crimson while Stage 4 shows **VERIFIED DENIAL (+1)** in green, and the chat bubble states in plain English: *"Blocked unauthorized access to L42. Independent observer verified zero data leaked — read_loan earned +1 verified run."*
3. **Full coverage of all 7 failure modes including `Omit Readback` (Critic C-03 fix):** Keep `btn-read-no-rb` visible inside Pair 5 (*Drift, Blind Spot & Recovery*) so the fail-closed missing-readback proof stays one click away.
4. **Clean Reset (`POST /api/reset`) with unique disposable run folder (Critic C-04 fix):** `POST /api/reset` creates a fresh `DemoSession` in a new timestamped/UUID subfolder under `runs/` for the active domain (never deleting or overwriting prior ledgers) and returns fresh state.
5. **Additive `last_flow` + `chat_message` from Python (`e2e_runner.py`):** Every action populates `last_flow` (`s1`..`s4` with `{status, title, detail}`) and `last_chat` (`{user, assistant, verdict}`) directly from Python so JS never invents status or diverges from the engine.
6. **Backward compatibility:** Preserve every existing `/api/*` route and test-checked DOM ID (`chain-line`, `btn-verify-chain`, `hold-pill`, `btn-read-l17`, `btn-read-l42`, `btn-read-no-rb`, `btn-propose`, `btn-drift`, `btn-unadmitted`, `btn-inject`, `btn-reinstate`, `btn-dom-banking`, `btn-dom-it`).

---

## 5. Verification & Acceptance Criteria

1. `python -B -m unittest -v test_engine test_e2e test_engine_core` passes all 20 existing tests + new tests for `last_flow`, `POST /api/admit-build`, `POST /api/reset`, and Glass Box DOM elements.
2. BrowserOS verification at **`1280x720`** (projector) and **`360x800`** (mobile):
   - Zero horizontal overflow (`scrollWidth <= innerWidth`) at both viewports.
   - Above-the-fold visibility of Header + 4-Stage Ribbon + Chat + Tier Cards + Observer Table in Executive View at `1280x720`.
   - Verified PASS (`Tier 2`), BLOCK (`403` D03, `D02`, `D01` + Admit recovery), Tamper -> `GLOBAL HOLD` -> blocked follow-up -> Reinstate, and IT Identity switch.
