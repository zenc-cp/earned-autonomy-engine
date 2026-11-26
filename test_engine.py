"""Unit tests for the Earned Autonomy Graduation Engine (Plan v2)."""
from __future__ import annotations

import tempfile
import unittest
import uuid
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import fingerprint as fp
import graduation as grad
import import_labs


class FingerprintSpec(unittest.TestCase):
    def setUp(self):
        self.priv = Ed25519PrivateKey.generate()
        self.pub = self.priv.public_key()
        self.rogue_priv = Ed25519PrivateKey.generate()
        self.kid = 'verifier-key-2026-11'
        self.tools = [{'name': 'read_loan', 'strict': True}]
        self.policy = {'release': 'b2-delegated-reader-v1', 'policy': 'customer-record-read-v1'}

    def test_build_fingerprint_changes_on_single_char_prompt_or_tool_addition(self):
        h1 = fp.compute_build_fingerprint('gpt-6.2-astra', 'Read synthetic loans.', self.tools, self.policy)
        h2 = fp.compute_build_fingerprint('gpt-6.2-astra', 'Read synthetic loans. ', self.tools, self.policy)
        h3 = fp.compute_build_fingerprint(
            'gpt-6.2-astra',
            'Read synthetic loans.',
            self.tools + [{'name': 'extend_due_day', 'strict': True}],
            self.policy,
        )
        self.assertEqual(len(h1), 64)
        self.assertNotEqual(h1, h2)
        self.assertNotEqual(h1, h3)

    def test_observation_receipt_requires_pinned_key_and_closed_schema(self):
        build_sha = fp.compute_build_fingerprint('gpt-6.2-astra', 'Read synthetic loans.', self.tools, self.policy)
        payload = {
            'action_id': '11111111-1111-4111-8111-111111111111',
            'action_class': 'read_loan',
            'recorded_utc': '2026-11-26T04:00:00+00:00',
            'verdict': 'verified',
            'protected_invariant_ok': True,
            'has_independent_readback': True,
            'build_fingerprint': build_sha,
        }
        good = fp.sign_observation(self.priv, self.kid, payload)
        self.assertTrue(fp.verify_receipt(self.pub, self.kid, good))

        # Forged with rogue key must fail even with matching kid
        forged = fp.sign_observation(self.rogue_priv, self.kid, payload)
        self.assertFalse(fp.verify_receipt(self.pub, self.kid, forged))

        # Wrong kid must fail
        self.assertFalse(fp.verify_receipt(self.pub, 'other-kid', good))

        # Tampering payload after signing must fail
        tampered = {**good, 'payload': {**payload, 'protected_invariant_ok': False}}
        self.assertFalse(fp.verify_receipt(self.pub, self.kid, tampered))

        # Missing required action_class or recorded_utc rejected at signing time
        for missing_key in ('action_class', 'recorded_utc'):
            bad = {k: v for k, v in payload.items() if k != missing_key}
            with self.assertRaises(fp.SchemaError):
                fp.sign_observation(self.priv, self.kid, bad)

    def test_reinstatement_receipt_binds_new_build_fingerprint(self):
        new_sha = fp.compute_build_fingerprint('gpt-6.2-astra', 'Fixed prompt.', self.tools, self.policy)
        rec = fp.sign_reinstatement(
            self.priv,
            self.kid,
            {
                'reinstatement_id': '22222222-2222-4222-8222-222222222222',
                'new_build_fingerprint': new_sha,
                'approver_alias': 'sec-architect-01',
                'recorded_utc': '2026-11-26T04:05:00+00:00',
            },
        )
        self.assertEqual(rec['kind'], 'reinstatement')
        self.assertTrue(fp.verify_receipt(self.pub, self.kid, rec))


class GraduationSpec(unittest.TestCase):
    def setUp(self):
        self.priv = Ed25519PrivateKey.generate()
        self.pub = self.priv.public_key()
        self.rogue_priv = Ed25519PrivateKey.generate()
        self.kid = 'verifier-key-2026-11'
        self.tools = [{'name': 'read_loan', 'strict': True}]
        self.policy = {'release': 'b2-delegated-reader-v1'}
        self.fp_v1 = fp.compute_build_fingerprint('gpt-6.2-astra', 'Read synthetic loans.', self.tools, self.policy)
        self.fp_v2 = fp.compute_build_fingerprint('gpt-6.2-astra', 'Read synthetic loans (remediated).', self.tools, self.policy)

    def _obs(
        self,
        action_class: str = 'read_loan',
        verdict: str = 'verified',
        protected_ok: bool = True,
        readback: bool = True,
        build_fp: str | None = None,
        action_id: str | None = None,
        signer=None,
    ) -> dict:
        return fp.sign_observation(
            signer or self.priv,
            self.kid,
            {
                'action_id': action_id or str(uuid.uuid4()),
                'action_class': action_class,
                'recorded_utc': '2026-11-26T04:10:00+00:00',
                'verdict': verdict,
                'protected_invariant_ok': protected_ok,
                'has_independent_readback': readback,
                'build_fingerprint': build_fp or self.fp_v1,
            },
        )

    def test_cross_class_isolation_reads_never_graduate_writes(self):
        receipts = [self._obs('read_loan') for _ in range(3)]
        st = grad.evaluate_standing(
            receipts,
            active_build_fingerprint=self.fp_v1,
            pinned_public_key=self.pub,
            pinned_kid=self.kid,
        )
        self.assertFalse(st['global_hold'])
        self.assertEqual(st['classes']['read_loan']['tier'], 'Tier 2 (Bounded Pilot)')
        self.assertEqual(st['classes']['read_loan']['consecutive_verified'], 3)
        self.assertEqual(st['classes']['extend_due_day']['tier'], 'Tier 1 (Human-Approved)')
        self.assertEqual(st['classes']['extend_due_day']['consecutive_verified'], 0)

    def test_forged_key_drift_replay_and_missing_readback_fail_closed(self):
        # 1. Forged key rejected
        forged = [self._obs('read_loan', signer=self.rogue_priv) for _ in range(3)]
        s1 = grad.evaluate_standing(forged, active_build_fingerprint=self.fp_v1, pinned_public_key=self.pub, pinned_kid=self.kid)
        self.assertEqual(s1['classes']['read_loan']['tier'], 'Tier 1 (Human-Approved)')
        self.assertEqual(s1['classes']['read_loan']['consecutive_verified'], 0)

        # 2. Prompt/build drift marks STALE and demotes Tier 2 -> Tier 1
        clean3 = [self._obs('read_loan') for _ in range(3)]
        s2 = grad.evaluate_standing(clean3, active_build_fingerprint=self.fp_v2, pinned_public_key=self.pub, pinned_kid=self.kid)
        self.assertEqual(s2['classes']['read_loan']['currency'], 'STALE')
        self.assertEqual(s2['classes']['read_loan']['tier'], 'Tier 1 (Human-Approved)')

        # 3. Duplicate action_id replay cannot inflate streak
        dup = self._obs('read_loan', action_id='33333333-3333-4333-8333-333333333333')
        s3 = grad.evaluate_standing([dup, dup, dup], active_build_fingerprint=self.fp_v1, pinned_public_key=self.pub, pinned_kid=self.kid)
        self.assertEqual(s3['classes']['read_loan']['consecutive_verified'], 1)
        self.assertEqual(s3['classes']['read_loan']['tier'], 'Tier 1 (Human-Approved)')

        # 4. Missing independent readback resets streak to 0
        no_rb = self._obs('read_loan', verdict='unverified', readback=False)
        s4 = grad.evaluate_standing(clean3[:2] + [no_rb], active_build_fingerprint=self.fp_v1, pinned_public_key=self.pub, pinned_kid=self.kid)
        self.assertEqual(s4['classes']['read_loan']['consecutive_verified'], 0)
        self.assertEqual(s4['classes']['read_loan']['tier'], 'Tier 1 (Human-Approved)')

    def test_protected_contradiction_triggers_sticky_global_hold_until_reinstated_on_new_build(self):
        clean_reads = [self._obs('read_loan') for _ in range(3)]
        tamper_write = self._obs('extend_due_day', verdict='failed', protected_ok=False)
        more_verified_same_build = [self._obs('read_loan') for _ in range(3)]

        # Sticky revocation: subsequent verified receipts on same build cannot auto-recover
        s_revoked = grad.evaluate_standing(
            clean_reads + [tamper_write] + more_verified_same_build,
            active_build_fingerprint=self.fp_v1,
            pinned_public_key=self.pub,
            pinned_kid=self.kid,
        )
        self.assertTrue(s_revoked['global_hold'])
        self.assertEqual(s_revoked['classes']['extend_due_day']['tier'], 'Tier 0 (REVOKED / HOLD)')
        self.assertEqual(s_revoked['classes']['read_loan']['tier'], 'Tier 0 (REVOKED / HOLD)')

        # Reinstatement bound to a NEW remediated build fingerprint lifts hold back to Tier 1 (not Tier 2)
        reinstate = fp.sign_reinstatement(
            self.priv,
            self.kid,
            {
                'reinstatement_id': str(uuid.uuid4()),
                'new_build_fingerprint': self.fp_v2,
                'approver_alias': 'sec-architect-01',
                'recorded_utc': '2026-11-26T04:20:00+00:00',
            },
        )
        s_reinstated = grad.evaluate_standing(
            clean_reads + [tamper_write, reinstate, self._obs('read_loan', build_fp=self.fp_v2)],
            active_build_fingerprint=self.fp_v2,
            pinned_public_key=self.pub,
            pinned_kid=self.kid,
        )
        self.assertFalse(s_reinstated['global_hold'])
        self.assertEqual(s_reinstated['classes']['read_loan']['tier'], 'Tier 1 (Human-Approved)')
        self.assertEqual(s_reinstated['classes']['read_loan']['consecutive_verified'], 1)
        self.assertEqual(s_reinstated['classes']['extend_due_day']['tier'], 'Tier 1 (Human-Approved)')
        self.assertEqual(s_reinstated['classes']['extend_due_day']['consecutive_verified'], 0)


class AdapterSpec(unittest.TestCase):
    def setUp(self):
        self.priv = Ed25519PrivateKey.generate()
        self.pub = self.priv.public_key()
        self.kid = 'verifier-key-adapter'
        self.build_fp = fp.compute_build_fingerprint('gpt-6.2-astra', 'Read loans', [{'name': 'read_loan'}], {'v': 1})

    def test_real_lab_receipts_normalize_into_separate_action_classes(self):
        receipts = import_labs.load_real_lab_receipts(self.priv, self.kid, self.build_fp)
        self.assertEqual(len(receipts), 3)
        st = grad.evaluate_standing(
            receipts,
            active_build_fingerprint=self.build_fp,
            pinned_public_key=self.pub,
            pinned_kid=self.kid,
            threshold=3,
        )
        # 2 read_loan + 1 extend_due_day must NEVER combine into 3/3 Tier 2!
        self.assertFalse(st['global_hold'])
        self.assertEqual(st['classes']['read_loan']['consecutive_verified'], 2)
        self.assertEqual(st['classes']['read_loan']['tier'], 'Tier 1 (Human-Approved)')
        self.assertEqual(st['classes']['extend_due_day']['consecutive_verified'], 1)
        self.assertEqual(st['classes']['extend_due_day']['tier'], 'Tier 1 (Human-Approved)')

    def test_missing_or_corrupt_lab_file_yields_unverified_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / 'corrupt.json'
            bad.write_text('{not json', encoding='utf-8')
            receipts = import_labs.load_real_lab_receipts(
                self.priv,
                self.kid,
                self.build_fp,
                tls_pair_path=Path(tmp) / 'missing.json',
                write_readback_path=bad,
            )
            self.assertEqual(len(receipts), 2)
            self.assertTrue(all(r['payload']['verdict'] == 'unverified' for r in receipts))
            st = grad.evaluate_standing(
                receipts,
                active_build_fingerprint=self.build_fp,
                pinned_public_key=self.pub,
                pinned_kid=self.kid,
            )
            self.assertEqual(st['classes']['read_loan']['consecutive_verified'], 0)
            self.assertEqual(st['classes']['extend_due_day']['consecutive_verified'], 0)


if __name__ == '__main__':
    unittest.main()
