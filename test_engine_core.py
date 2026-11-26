"""Core engine tests: key separation, hash-chained ledger integrity, portable contracts, and CLI."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import contracts
import keys

HERE = Path(__file__).resolve().parent
CLI = HERE / 'cli.py'
BANK_CONTRACT = HERE / 'contracts' / 'banking-loan.json'
IT_CONTRACT = HERE / 'contracts' / 'it-access.json'
AGENT_MANIFEST = HERE / 'fixtures' / 'sample-agent-manifest.json'


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, '-B', str(CLI), *args],
        cwd=HERE,
        capture_output=True,
        text=True,
        check=False,
    )


class EngineCoreSpec(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_keypair_init_refuses_overwrite_and_derives_stable_kid(self):
        kdir = self.root / 'keys'
        info = keys.init_keypair(kdir)
        _, priv_kid = keys.load_private_key(Path(info['private_key_path']))
        _, pub_kid = keys.load_public_key(Path(info['public_key_path']))
        self.assertEqual(info['verifier_kid'], priv_kid)
        self.assertEqual(priv_kid, pub_kid)
        with self.assertRaises(FileExistsError):
            keys.init_keypair(kdir)

    def test_cli_lifecycle_and_hash_chain_tamper_delete_detection(self):
        kdir = self.root / 'keys'
        ledger = self.root / 'ledger.jsonl'

        r_init = _run_cli('init-key', '--out-dir', str(kdir))
        self.assertEqual(r_init.returncode, 0, r_init.stderr)
        priv_path = kdir / 'observer.key.pem'
        pub_path = kdir / 'verifier.pub.pem'

        r_fp = _run_cli('fingerprint', '--manifest', str(AGENT_MANIFEST))
        self.assertEqual(r_fp.returncode, 0, r_fp.stderr)
        build_fp = json.loads(r_fp.stdout)['build_fingerprint']

        for _ in range(3):
            r = _run_cli(
                'record',
                '--key', str(priv_path),
                '--ledger', str(ledger),
                '--action-class', 'read_loan',
                '--verdict', 'verified',
                '--protected-ok', 'true',
                '--has-readback', 'true',
                '--build-fp', build_fp,
            )
            self.assertEqual(r.returncode, 0, r.stderr)

        r_ver = _run_cli(
            'verify',
            '--pubkey', str(pub_path),
            '--ledger', str(ledger),
            '--contract', str(BANK_CONTRACT),
            '--active-build-fp', build_fp,
        )
        self.assertEqual(r_ver.returncode, 0, r_ver.stderr)
        doc = json.loads(r_ver.stdout)
        self.assertTrue(doc['ok'])
        self.assertEqual(doc['chain']['entries'], 3)
        self.assertEqual(doc['standing']['classes']['read_loan']['tier'], 'Tier 2 (Bounded Pilot)')
        self.assertEqual(doc['standing']['classes']['extend_due_day']['tier'], 'Tier 1 (Human-Approved)')

        lines = ledger.read_text(encoding='utf-8').splitlines()
        tampered = self.root / 'tampered.jsonl'
        tampered.write_text('\n'.join([lines[0], lines[1].replace('verified', 'failed', 1), lines[2]]) + '\n', encoding='utf-8')
        r_bad = _run_cli('verify', '--pubkey', str(pub_path), '--ledger', str(tampered), '--contract', str(BANK_CONTRACT), '--active-build-fp', build_fp)
        self.assertEqual(r_bad.returncode, 2)
        self.assertFalse(json.loads(r_bad.stdout)['ok'])

        deleted = self.root / 'deleted.jsonl'
        deleted.write_text('\n'.join(lines[1:]) + '\n', encoding='utf-8')
        r_del = _run_cli('verify', '--pubkey', str(pub_path), '--ledger', str(deleted), '--contract', str(BANK_CONTRACT), '--active-build-fp', build_fp)
        self.assertEqual(r_del.returncode, 2)

    def test_same_engine_runs_portable_it_contract_and_exit_1_on_global_hold(self):
        kdir = self.root / 'keys'
        ledger = self.root / 'it-ledger.jsonl'
        keys.init_keypair(kdir)
        priv_path = kdir / 'observer.key.pem'
        pub_path = kdir / 'verifier.pub.pem'
        it_fp = 'a' * 64
        it_fp_v2 = 'b' * 64

        c = contracts.load_contract(IT_CONTRACT)
        self.assertEqual(c['domain'], 'it-identity')

        for _ in range(3):
            self.assertEqual(
                _run_cli('record', '--key', str(priv_path), '--ledger', str(ledger), '--action-class', 'read_access_profile', '--verdict', 'verified', '--protected-ok', 'true', '--has-readback', 'true', '--build-fp', it_fp).returncode,
                0,
            )
        self.assertEqual(
            _run_cli('record', '--key', str(priv_path), '--ledger', str(ledger), '--action-class', 'set_temp_expiry', '--verdict', 'failed', '--protected-ok', 'false', '--has-readback', 'true', '--build-fp', it_fp).returncode,
            0,
        )

        r_hold = _run_cli('verify', '--pubkey', str(pub_path), '--ledger', str(ledger), '--contract', str(IT_CONTRACT), '--active-build-fp', it_fp)
        self.assertEqual(r_hold.returncode, 1)
        doc_hold = json.loads(r_hold.stdout)
        self.assertTrue(doc_hold['standing']['global_hold'])
        self.assertEqual(doc_hold['standing']['classes']['read_access_profile']['tier'], 'Tier 0 (REVOKED / HOLD)')
        self.assertEqual(doc_hold['standing']['classes']['set_temp_expiry']['tier'], 'Tier 0 (REVOKED / HOLD)')

        self.assertEqual(
            _run_cli('reinstate', '--key', str(priv_path), '--ledger', str(ledger), '--new-build-fp', it_fp_v2, '--approver', 'it-sec-lead').returncode,
            0,
        )
        r_ok = _run_cli('verify', '--pubkey', str(pub_path), '--ledger', str(ledger), '--contract', str(IT_CONTRACT), '--active-build-fp', it_fp_v2)
        self.assertEqual(r_ok.returncode, 0)
        doc_ok = json.loads(r_ok.stdout)
        self.assertFalse(doc_ok['standing']['global_hold'])
        self.assertEqual(doc_ok['standing']['classes']['set_temp_expiry']['tier'], 'Tier 1 (Human-Approved)')


if __name__ == '__main__':
    unittest.main()
