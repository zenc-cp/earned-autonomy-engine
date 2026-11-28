# The Glass Box: 20-minute pitch and 10-minute operator script

**Opening line:** “Alex asks for seven more days. The assistant may propose a change to Alex's loan. Who will check that the bank changed only that loan?” Tell the audience that the client is simulated, the SQLite effects are real inside the demo, and the observer is a separate local process. Never call a recorded run a live customer session.

## Pitch clock (proposed, not a timed rehearsal)

| Minutes | Point | What the audience should be able to say |
|---|---|---|
| 0–2 | Ask to see your own record, then another person's. | “Both a useful answer and a correct refusal are successes for the control.” |
| 2–5 | Show a seven-day proposal before and after approval. | “A hold is not a commit. Only the specific record, starting version and change were expected.” |
| 5–7 | Point to the [architecture](architecture.png): permission is decided before dispatch; the observer checks the effect afterwards. | “Checking the second record matters just as much as checking the first.” |
| 7–10 | Follow a receipt to the pinned key, active build and class-specific count. | “Read evidence counts towards reads only; it does not issue write permission.” |
| 10–13 | Contrast an unverified result, a denied request and a detected bad write. | “Missing evidence earns no credit. An unexpected change stops subsequent work.” |
| 13–16 | Switch to the IT contract. Explain the proposed enterprise placements separately from the local adapter. | “The method travels; the protected invariant must be defined per system.” |
| 16–18 | Walk the investigation: correlate alert and receipt, inspect the rows, verify the chain, test the next denial. | “A valid signature or chain alone is not a business pass.” |
| 18–20 | Ask for a nonproduction, read-only pilot and an independent reviewer. | “Three verified current reads are a demo threshold, not an enterprise safety rate. Consequential writes stay human-approved.” |

## Run the 10-minute demonstration

From the Glass Box source directory: `python -B live_desk.py --port 8790 --open`. Start with a fresh disposable **Banking** run in **Executive** view. At 1280×720 the ribbon, transcript, standing and ledger table fit; scroll down for the two approval choices when the inbox opens. Allow 15 minutes after the demo for Q&A. Each button calls a local session action; the ribbon shows the modeled action result, even when the HTTP wrapper itself returns 200.

| Time | Action on screen | Check before moving on |
|---|---|---|
| 0:00–1:00 | Point to L17 (day 30 / v12) and protected L42 (day 90 / v5). Ask which row the customer may see. | The client is labeled **Deterministic Local API**. No change is pending; both classes are at Tier 1. |
| 1:00–2:30 | **PASS: Read L17** → **BLOCK: Read L42** → **PASS: Read L17**. | The second turn is a blocked request and a **verified denial**. Reads reach 3/3; writes stay 0/3. |
| 2:30–4:00 | **Propose +7d on L17**. Pause on the approver inbox. Choose **PASS: Approve Clean Commit**. | Before approval: unchanged. After: L17 30→37 / v12→13, L42 still 90 / v5. This is the successful write path. |
| 4:00–5:15 | **BLOCK: Prompt Injection**. Contrast with the ordinary read. Choose **Edit Prompt (STALE)**. | The fixed unsafe-note fixture grants no authority. After drift, earlier qualifying reads no longer support Tier 2. This does not test arbitrary prompts. |
| 5:15–6:15 | **BLOCK: Unadmitted Build** → **PASS: Read L17** → **PASS: Admit Build** → **PASS: Read L17**. | Staging alone is not the refusal: an actual attempted read must show `release_not_admitted`. Admission restores servicing, not a prior streak. |
| 6:15–7:45 | **Propose +7d** again. Choose **BLOCK/REVOKE: Tamper L42** in the inbox. Then try **PASS: Read L17**. | The faulty commit advanced L17 to 44 and changed L42 to 91. The observer detects it; the *next* read is blocked at the gate. Do not describe this as rollback. |
| 7:45–9:00 | Open **Technical**; inspect the critical local alert and matching signed observation. Check **Verify Chain Integrity**. Select **Reinstate → Tier 1**. | A structurally valid chain can contain a recorded failure. The demo restores the protected row and signs a new-build reinstatement; it does not erase the incident or grant Tier 2. |
| 9:00–10:00 | Select **IT Identity**. Use **PASS: Read CONT-17** and **BLOCK: Read ADMIN-42**. | Different targets, action classes and key; no banking streak transfers. Leave one sentence for the decision: pilot reads, not writes. |

If time is short, keep the matched reads, the clean commit, the contradiction and the blocked next call; omit the other fault fixtures. If the server is unavailable, open the [offline replay](../desk.html) and say “recorded scenarios”. Without Wi-Fi the local live desk still works once dependencies are installed. Do not reset a held run to imply recovery. No hosted LLM, cloud identity, external SIEM, or HSM is required by this script.
