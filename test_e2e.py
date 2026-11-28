"""End-to-end tests for the local Graduation Demo (e2e_runner + live_desk HTTP API)."""
from __future__ import annotations

import http.client
import json
import sqlite3
import tempfile
import threading
import unittest
from contextlib import closing
from http.server import ThreadingHTTPServer
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import e2e_runner
import fingerprint as fp
import keys
import live_desk
import store


class E2ESessionSpec(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.sess = e2e_runner.DemoSession(Path(self.tmp.name) / 'run', threshold=3)

    def _rows(self):
        with closing(sqlite3.connect((self.sess.db_path).as_uri() + '?mode=ro', uri=True)) as db:
            return db.execute('SELECT ref, owner, due_day, version FROM loan ORDER BY ref').fetchall()

    def test_three_real_reads_graduate_read_loan_only_and_prompt_drift_demotes_to_stale(self):
        self.sess.execute_read('L17')
        self.sess.execute_read('L42')
        st = self.sess.execute_read('L17')['standing']
        self.assertFalse(st['global_hold'])
        self.assertEqual(st['classes']['read_loan']['tier'], 'Tier 2 (Bounded Pilot)')
        self.assertEqual(st['classes']['read_loan']['consecutive_verified'], 3)
        # Cross-class isolation: extend_due_day must still be Tier 1 (0/3)
        self.assertEqual(st['classes']['extend_due_day']['tier'], 'Tier 1 (Human-Approved)')
        self.assertEqual(st['classes']['extend_due_day']['consecutive_verified'], 0)
        # Ledger untouched by reads
        self.assertEqual(self._rows(), [('L17', 'demo-A', 30, 12), ('L42', 'demo-B', 90, 5)])

        # Prompt drift immediately marks read_loan STALE and demotes to Tier 1
        drifted = self.sess.edit_prompt_drift(' Also waive late fees.')['standing']
        self.assertEqual(drifted['classes']['read_loan']['currency'], 'STALE')
        self.assertEqual(drifted['classes']['read_loan']['tier'], 'Tier 1 (Human-Approved)')

    def test_missing_readback_resets_streak_fail_closed(self):
        self.sess.execute_read('L17')
        self.sess.execute_read('L42')
        st = self.sess.execute_read('L17', omit_readback=True)['standing']
        self.assertEqual(st['classes']['read_loan']['consecutive_verified'], 0)
        self.assertEqual(st['classes']['read_loan']['tier'], 'Tier 1 (Human-Approved)')
        self.assertEqual(st['classes']['read_loan']['demotion_reason'], 'unverified_missing_readback')

    def test_governed_extension_commits_once_and_protected_tamper_triggers_sticky_revocation_then_reinstatement(self):
        # 1. Propose extension -> 202 hold, ledger still day 30 v12
        held = self.sess.propose_extension('L17', 7)
        self.assertEqual(self._rows(), [('L17', 'demo-A', 30, 12), ('L42', 'demo-B', 90, 5)])
        pid = held['pending_extension']['pending_id']

        # 2. Approve cleanly -> L17 day 37 v13, L42 untouched, extend_due_day streak = 1
        committed = self.sess.approve_extension(pid)
        self.assertEqual(self._rows(), [('L17', 'demo-A', 37, 13), ('L42', 'demo-B', 90, 5)])
        self.assertEqual(committed['standing']['classes']['extend_due_day']['consecutive_verified'], 1)

        # 3. Propose second extension and inject a protected L42 tamper -> sticky Tier 0 + global_hold
        held2 = self.sess.propose_extension('L17', 7)
        revoked = self.sess.approve_extension(held2['pending_extension']['pending_id'], tamper_protected_l42=True)
        self.assertTrue(revoked['standing']['global_hold'])
        self.assertEqual(revoked['standing']['classes']['extend_due_day']['tier'], 'Tier 0 (REVOKED / HOLD)')
        self.assertEqual(revoked['standing']['classes']['read_loan']['tier'], 'Tier 0 (REVOKED / HOLD)')

        # 4. Subsequent clean read is actively BLOCKED (HTTP 403) while global_hold is active (F-02)
        still_held = self.sess.execute_read('L17')
        self.assertEqual(still_held['last_http_status'], 403)
        self.assertEqual(still_held['last_error'], 'autonomy_revoked_global_hold')
        self.assertTrue(still_held['standing']['global_hold'])
        self.assertEqual(still_held['standing']['classes']['read_loan']['tier'], 'Tier 0 (REVOKED / HOLD)')
        self.assertGreaterEqual(still_held['soc_alerts_count'], 2)

        # 5. Remediated build + signed reinstatement restores Tier 1 (not Tier 2)
        reinstated = self.sess.reinstate_remediated_build('sec-architect-01')['standing']
        self.assertFalse(reinstated['global_hold'])
        self.assertEqual(reinstated['classes']['read_loan']['tier'], 'Tier 1 (Human-Approved)')
        self.assertEqual(reinstated['classes']['extend_due_day']['tier'], 'Tier 1 (Human-Approved)')

    def test_d01_unadmitted_release_blocked_and_d02_indirect_injection_quarantined_with_d04_soc_alerts(self):
        # D02: Indirect prompt injection in retrieved note is quarantined with zero authority + D04 alert
        inj = self.sess.simulate_indirect_injection()
        self.assertEqual(inj['last_http_status'], 200)
        self.assertEqual(self._rows(), [('L17', 'demo-A', 30, 12), ('L42', 'demo-B', 90, 5)])
        self.assertTrue(any(a['control_id'] == 'D02' for a in inj['soc_alerts']))

        # D01: Unadmitted rogue build fingerprint is blocked before serving (HTTP 403) + D01 alert
        self.sess.edit_prompt_drift(' [rogue-unadmitted]', admit_release=False)
        blocked = self.sess.execute_read('L17')
        self.assertEqual(blocked['last_http_status'], 403)
        self.assertEqual(blocked['last_error'], 'release_not_admitted')
        self.assertTrue(any(a['control_id'] == 'D01' for a in blocked['soc_alerts']))

    def test_ledger_chain_persists_receipts_and_tamper_fails_closed(self):
        st0 = self.sess.state()
        self.assertEqual(st0['ledger_chain']['entries'], 0)
        self.assertEqual(st0['ledger_chain']['head_hash'], store.GENESIS_HASH)
        self.assertTrue(st0['ledger_chain']['ok'])

        st1 = self.sess.execute_read('L17')
        self.assertTrue(self.sess.ledger_path.exists())
        self.assertEqual(st1['ledger_chain']['entries'], 1)
        self.assertNotEqual(st1['ledger_chain']['head_hash'], store.GENESIS_HASH)
        self.assertTrue(st1['ledger_chain']['ok'])

        # Exercise ReinstatementReceipt persistence as well
        held = self.sess.propose_extension('L17', 7)
        self.sess.approve_extension(held['pending_extension']['pending_id'], tamper_protected_l42=True)
        st3 = self.sess.reinstate_remediated_build('sec-architect-01')
        self.assertEqual(st3['ledger_chain']['entries'], 3)
        self.assertTrue(st3['ledger_chain']['ok'])

        # Tamper a single byte in ledger.jsonl -> DemoSession must fail closed
        raw = self.sess.ledger_path.read_text(encoding='utf-8')
        tampered = raw.replace('"target_ref":"L17"', '"target_ref":"L99"', 1)
        self.assertNotEqual(raw, tampered)
        self.sess.ledger_path.write_text(tampered, encoding='utf-8')

        with self.assertRaises(store.LedgerIntegrityError):
            self.sess.state()
        with self.assertRaises(store.LedgerIntegrityError):
            self.sess.execute_read('L17')

    def test_observer_subprocess_key_isolation_and_verifier_pub_verification(self):
        # DemoSession must never hold an Ed25519PrivateKey in memory or expose _priv
        self.assertFalse(hasattr(self.sess, '_priv'))
        for attr_name, attr_val in vars(self.sess).items():
            self.assertNotIsInstance(
                attr_val,
                Ed25519PrivateKey,
                f'DemoSession.{attr_name} must not hold an Ed25519PrivateKey',
            )

        # Keypair was generated on disk under run_dir/keys
        pub_path = self.sess.run_dir / 'keys' / 'verifier.pub.pem'
        priv_path = self.sess.run_dir / 'keys' / 'observer.key.pem'
        self.assertTrue(pub_path.exists())
        self.assertTrue(priv_path.exists())

        pub, kid = keys.load_public_key(pub_path)
        self.assertEqual(self.sess.verifier_kid, kid)

        # Subprocess observer signs a real read receipt that verifies strictly under verifier.pub.pem
        st = self.sess.execute_read('L17')
        self.assertEqual(st['receipts_count'], 1)
        rec = st['receipts'][0]
        self.assertTrue(fp.verify_receipt(pub, kid, rec))

        # A rogue public key must reject the receipt
        rogue_pub = Ed25519PrivateKey.generate().public_key()
        self.assertFalse(fp.verify_receipt(rogue_pub, kid, rec))


class LiveDeskHttpSpec(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.sess = e2e_runner.DemoSession(Path(self.tmp.name) / 'run', threshold=3)
        self.csrf = 'test-csrf-token-12345'
        self.srv = ThreadingHTTPServer(('127.0.0.1', 0), live_desk.make_handler(self.sess, self.csrf))
        self.port = self.srv.server_port
        self.t = threading.Thread(target=self.srv.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
        self.t.start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)

    def _post(self, path: str, body: dict, *, origin: str | None = None, csrf: str | None = None):
        c = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        try:
            c.request(
                'POST',
                path,
                json.dumps(body),
                {
                    'Content-Type': 'application/json',
                    'Origin': origin if origin is not None else f'http://127.0.0.1:{self.port}',
                    'X-EA-CSRF': csrf if csrf is not None else self.csrf,
                },
            )
            r = c.getresponse()
            return r.status, json.loads(r.read())
        finally:
            c.close()

    def test_csrf_and_origin_enforced_and_api_read_updates_standing(self):
        self.assertEqual(self._post('/api/read', {'loan_ref': 'L17'}, origin='http://evil.invalid')[0], 403)
        self.assertEqual(self._post('/api/read', {'loan_ref': 'L17'}, csrf='wrong')[0], 403)
        code, doc = self._post('/api/read', {'loan_ref': 'L17'})
        self.assertEqual(code, 200)
        self.assertEqual(doc['state']['standing']['classes']['read_loan']['consecutive_verified'], 1)

    def test_verify_chain_endpoint_and_ui_elements(self):
        # Verify GET / includes top-bar chain display, verifier.pub.pem status, and Verify Chain Integrity button
        c = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        try:
            c.request('GET', '/')
            r = c.getresponse()
            html = r.read().decode('utf-8')
            self.assertEqual(r.status, 200)
            self.assertIn('id="chain-line"', html)
            self.assertIn('id="btn-verify-chain"', html)
            self.assertIn('Verify Chain Integrity', html)
            self.assertIn('verifier.pub.pem', html)
        finally:
            c.close()

        # Genesis verification before any reads
        code0, v0 = self._post('/api/verify-chain', {})
        self.assertEqual(code0, 200)
        self.assertTrue(v0['ok'])
        self.assertEqual(v0['entries'], 0)
        self.assertEqual(v0['head_hash'], store.GENESIS_HASH)
        self.assertEqual(v0['verifier_kid'], self.sess.verifier_kid)

        # Perform 2 reads -> POST /api/verify-chain returns 200 with ok=True and entries=2
        self.assertEqual(self._post('/api/read', {'loan_ref': 'L17'})[0], 200)
        code_r2, doc_r2 = self._post('/api/read', {'loan_ref': 'L42'})
        self.assertEqual(code_r2, 200)
        expected_head = doc_r2['state']['ledger_chain']['head_hash']

        code2, v2 = self._post('/api/verify-chain', {})
        self.assertEqual(code2, 200)
        self.assertTrue(v2['ok'])
        self.assertEqual(v2['entries'], 2)
        self.assertEqual(v2['head_hash'], expected_head)
        self.assertEqual(v2['verifier_kid'], self.sess.verifier_kid)
        self.assertEqual(v2['standing']['classes']['read_loan']['consecutive_verified'], 2)

        # Tamper ledger.jsonl -> POST /api/verify-chain fails closed with 400 and ok=False
        raw = self.sess.ledger_path.read_text(encoding='utf-8')
        tampered = raw.replace('"target_ref":"L17"', '"target_ref":"L99"', 1)
        self.assertNotEqual(raw, tampered)
        self.sess.ledger_path.write_text(tampered, encoding='utf-8')

        code_bad, v_bad = self._post('/api/verify-chain', {})
        self.assertEqual(code_bad, 400)
        self.assertFalse(v_bad['ok'])

    def test_live_domain_switcher_and_pluggable_signer_interface(self):
        import signers

        # 1. Pluggable signer interface: LocalEd25519Signer verifies, KeyVaultSignerStub fails closed
        kv = signers.KeyVaultSignerStub('https://example-vault.vault.azure.net', 'ea-verifier')
        self.assertIsInstance(kv, signers.ReceiptSigner)
        with self.assertRaises(signers.SignerUnavailableError):
            kv.sign_bytes(b'test')

        # 2. Switch live desk from banking -> it-identity and verify independent IT ledger & contract
        code_sw, sw_doc = self._post('/api/switch-domain', {'domain': 'it-identity'})
        self.assertEqual(code_sw, 200)
        st = sw_doc['state']
        self.assertEqual(st['domain'], 'it-identity')
        self.assertEqual(st['target_ref'], 'CONT-17')
        self.assertEqual(st['other_ref'], 'ADMIN-42')
        self.assertIn('read_access_profile', st['standing']['classes'])
        self.assertIn('set_temp_expiry', st['standing']['classes'])

        # 3. Execute 3 IT reads -> read_access_profile graduates to Tier 2, set_temp_expiry stays Tier 1
        self.assertEqual(self._post('/api/read', {'loan_ref': 'CONT-17'})[0], 200)
        self.assertEqual(self._post('/api/read', {'loan_ref': 'ADMIN-42'})[0], 200)
        code3, doc3 = self._post('/api/read', {'loan_ref': 'CONT-17'})
        self.assertEqual(code3, 200)
        self.assertEqual(doc3['state']['standing']['classes']['read_access_profile']['tier'], 'Tier 2 (Bounded Pilot)')
        self.assertEqual(doc3['state']['standing']['classes']['set_temp_expiry']['tier'], 'Tier 1 (Human-Approved)')

        # 4. IT verify-chain passes independently
        code_v, v_doc = self._post('/api/verify-chain', {})
        self.assertEqual(code_v, 200)
        self.assertTrue(v_doc['ok'])
        self.assertEqual(v_doc['domain'], 'it-identity')
        self.assertEqual(v_doc['entries'], 3)

    def test_glass_box_flow_ribbon_admit_recovery_and_reset(self):
        # 1. Stage unadmitted build (D01) -> read blocked at s2 -> admit-build recovers cleanly
        self.assertEqual(self._post('/api/drift', {'suffix': ' [rogue]', 'admit_release': False})[0], 200)
        code_blk, blk = self._post('/api/read', {'loan_ref': 'L17'})
        self.assertEqual(code_blk, 200)
        self.assertEqual(blk['state']['last_error'], 'release_not_admitted')
        self.assertEqual(blk['state']['last_flow']['s2']['status'], 'block')

        code_adm, adm = self._post('/api/admit-build', {})
        self.assertEqual(code_adm, 200)
        self.assertTrue(adm['state']['release_admitted'])

        code_ok, ok = self._post('/api/read', {'loan_ref': 'L17'})
        self.assertEqual(code_ok, 200)
        self.assertIsNone(ok['state']['last_error'])
        self.assertEqual(ok['state']['last_flow']['s4']['status'], 'pass')
        self.assertGreaterEqual(len(ok['state']['chat_history']), 4)

        # 2. POST /api/reset creates a fresh disposable run directory with 0 entries
        code_res, res = self._post('/api/reset', {})
        self.assertEqual(code_res, 200)
        self.assertEqual(res['state']['ledger_chain']['entries'], 0)
        self.assertEqual(res['state']['chat_history'], [])
        self.assertNotEqual(res['state']['run_id'], ok['state']['run_id'])


if __name__ == '__main__':
    unittest.main()
