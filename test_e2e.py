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

import e2e_runner
import live_desk


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


if __name__ == '__main__':
    unittest.main()
