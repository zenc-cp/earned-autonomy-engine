# Earned Autonomy Graduation Engine

**A correct read should earn confidence in reads, not permission to write.** The Glass Box is a deterministic local demo of an assistant that can look up a synthetic record or propose a change. An observer reads the system of record after the action. A release reviewer can see what was requested, what the gate allowed, what actually changed, and whether the evidence still applies to this build.

## Try one matched pair

With Python 3.11+ and the dependencies in [requirements.txt](requirements.txt) installed, start in this directory:

```sh
python -B live_desk.py --port 8790 --open
```

1. In **Banking / Executive**, choose **PASS: Read L17**, then **BLOCK: Read L42**, then **PASS: Read L17**. The second request is denied. That denial is correct behavior, so the observer credits the **read** class; it reaches 3/3. Writes remain at 0/3.
2. Choose **Propose +7d on L17**, then **PASS: Approve Clean Commit**. Compare the two ledger rows: L17 advances from day 30 to 37; L42 stays at 90. Proposing alone does not change either row.
3. Propose once more and select the clearly marked **Tamper L42** fault. This time the bad side effect **happens**. The observer detects it and the engine revokes both classes. Try the same L17 read: this **next** request is blocked. This is detection and containment, not retroactive prevention.

Use **Technical** to inspect alerts and signed receipts. The displayed `200`, `202`, or `403` is the **modeled action result** (`last_http_status`) in the local desk's API envelope, not necessarily that envelope's HTTP transport status. The client is not a hosted model, a tenant sign-in, or a bank connection. **IT Identity** opens a separate synthetic profile with its own ledger and pinned key. **Reset** starts a new disposable run; it is not incident remediation.

## How it works

![Two-plane reference architecture](docs/architecture.png)

- **Build binding:** [fingerprint.py](fingerprint.py) hashes the model, instructions, tools, and policy. An old build's receipts remain available for audit but do not qualify the new build.
- **Observed effects:** [e2e_runner.py](e2e_runner.py) owns the local writes. [observer_worker.py](observer_worker.py) checks the target and protected row using a read-only SQLite connection. Observations are Ed25519-signed via [signers.py](signers.py); verification uses the public key, not a key supplied by a receipt. The two processes share a workstation. The file-backed signer is not an HSM, and `KeyVaultSignerStub` deliberately does not sign.
- **Evidence history:** [store.py](store.py) checks sequence numbers and SHA-256 links. It detects inconsistent entries, not every possible deletion: a valid prefix still verifies without an independently retained head and count. A signature authenticates the signer's statement, not the truth of unobserved effects.
- **Standing:** [graduation.py](graduation.py) evaluates each action class separately. A missing readback gives no credit; a verified contradiction sets a session-wide hold. Removing that hold requires a different build and a matching signed reinstatement. The evaluator issues no credentials. The local gate reads the result before servicing the next action.
- **Two contracts:** [banking loans](contracts/banking-loan.json) and [IT temporary access](contracts/it-access.json). The policy is reusable; the adapters, seeded data and invariants are domain-specific.

## Verify or run offline

```sh
python -B -m unittest -v test_engine test_e2e test_engine_core
python -B cli.py --demo-scenarios
python -B cli.py --build-desk
```

The Glass Box test set contains 21 tests. [The offline desk](desk.html) is a **replay of bundled synthetic fixtures**, not a new request or a live signature audit. The six scenarios, standings and receipt JSON are embedded at build time. For the persistent CLI, `verify` exit `0` means **no global hold**, not “every receipt passed”; inspect the class reasons and trace. Exit `1` denotes global hold; invalid chain or input/key errors handled by `verify` give exit `2`.

## Presenter and operator material

[20-minute pitch and 10-minute walkthrough](docs/pitch-and-demo-script.md) · [Operations runbook](docs/operations-runbook.md) · [Glass Box spec](docs/specs/glass-box-demo-spec.md) · [Design tokens](DESIGN.md) · [Standalone architecture](docs/architecture.html) · [Vector diagram](docs/architecture.svg) · [MIT license](LICENSE)
