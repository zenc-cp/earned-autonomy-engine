"""Deterministic per-action-class autonomy graduation & sticky revocation engine.

Never executes writes or grants runtime authority. Evaluates an ordered stream of
Ed25519-signed observation and reinstatement receipts against a caller-pinned
verifier public key and active build fingerprint.
"""
from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import fingerprint as fp

TIER_0 = 'Tier 0 (REVOKED / HOLD)'
TIER_1 = 'Tier 1 (Human-Approved)'
TIER_2 = 'Tier 2 (Bounded Pilot)'


def _fresh_class_state() -> dict:
    return {
        'tier': TIER_1,
        'consecutive_verified': 0,
        'currency': 'CURRENT',
        'demotion_reason': None,
        'receipt_ids': [],
    }


def evaluate_standing(
    receipts: list[dict],
    *,
    active_build_fingerprint: str,
    pinned_public_key: Ed25519PublicKey,
    pinned_kid: str,
    action_classes: tuple[str, ...] = ('read_loan', 'extend_due_day'),
    threshold: int = 3,
) -> dict:
    if not isinstance(threshold, int) or threshold < 1:
        raise ValueError('threshold must be a positive integer.')

    classes: dict[str, dict] = {cls: _fresh_class_state() for cls in action_classes}
    global_hold = False
    revoked_build_fp: str | None = None
    seen_actions: set[str] = set()
    seen_reinstatements: set[str] = set()
    trace: list[dict] = []

    for r in receipts:
        if not fp.verify_receipt(pinned_public_key, pinned_kid, r):
            # Reject forged or schema-invalid receipts; reset non-revoked streaks fail-closed.
            for st in classes.values():
                if st['tier'] != TIER_0:
                    st['tier'] = TIER_1
                    st['consecutive_verified'] = 0
                    st['demotion_reason'] = 'unverified_signature'
            trace.append({'kind': r.get('kind') if isinstance(r, dict) else 'invalid', 'status': 'rejected_signature'})
            continue

        kind = r['kind']
        p = r['payload']

        if kind == 'reinstatement':
            rid = p['reinstatement_id']
            new_fp = p['new_build_fingerprint']
            if rid in seen_reinstatements:
                trace.append({'kind': 'reinstatement', 'id': rid, 'status': 'ignored_replay'})
                continue
            seen_reinstatements.add(rid)
            # Reinstatement only lifts global_hold if bound to a genuinely NEW build fingerprint
            # matching the active build (cannot reinstate the exact revoked build).
            if global_hold and new_fp == active_build_fingerprint and new_fp != revoked_build_fp:
                global_hold = False
                revoked_build_fp = None
                for st in classes.values():
                    st['tier'] = TIER_1
                    st['consecutive_verified'] = 0
                    st['currency'] = 'CURRENT'
                    st['demotion_reason'] = 'reinstated_at_tier_1'
                trace.append({'kind': 'reinstatement', 'id': rid, 'status': 'reinstated_to_tier_1'})
            else:
                trace.append({'kind': 'reinstatement', 'id': rid, 'status': 'rejected_reinstatement_mismatch'})
            continue

        # Observation receipt
        aid = p['action_id']
        acls = p['action_class']
        if acls not in classes:
            classes[acls] = _fresh_class_state()
            if global_hold:
                classes[acls]['tier'] = TIER_0
                classes[acls]['demotion_reason'] = 'global_hold_active'

        if aid in seen_actions:
            classes[acls]['demotion_reason'] = 'duplicate_action_id'
            trace.append({'kind': 'observation', 'action_id': aid, 'action_class': acls, 'status': 'ignored_replay'})
            continue
        seen_actions.add(aid)

        # Sticky revocation: while global_hold is active, observations cannot lift Tier 0.
        if global_hold:
            classes[acls]['tier'] = TIER_0
            classes[acls]['consecutive_verified'] = 0
            trace.append({'kind': 'observation', 'action_id': aid, 'action_class': acls, 'status': 'blocked_by_global_hold'})
            continue

        verdict = p['verdict']
        protected_ok = p['protected_invariant_ok']
        has_readback = p['has_independent_readback']
        rfp = p['build_fingerprint']

        # 1. Bound contradiction or protected-state violation -> sticky global_hold + Tier 0 across all classes.
        if verdict == 'failed' or protected_ok is False:
            global_hold = True
            revoked_build_fp = rfp
            for cname, st in classes.items():
                st['tier'] = TIER_0
                st['consecutive_verified'] = 0
                st['demotion_reason'] = (
                    'protected_or_contract_contradiction' if cname == acls else f'global_hold_from_{acls}'
                )
            classes[acls]['receipt_ids'].append(aid)
            trace.append({'kind': 'observation', 'action_id': aid, 'action_class': acls, 'status': 'revoked_global_hold'})
            continue

        # 2. Missing/unbound observation -> fail-closed streak reset on this action class.
        if verdict != 'verified' or has_readback is not True:
            classes[acls]['tier'] = TIER_1
            classes[acls]['consecutive_verified'] = 0
            classes[acls]['demotion_reason'] = 'unverified_missing_readback'
            classes[acls]['receipt_ids'].append(aid)
            trace.append({'kind': 'observation', 'action_id': aid, 'action_class': acls, 'status': 'unverified_reset'})
            continue

        # 3. Build drift check -> receipt from an older build is STALE and cannot hold Tier 2.
        if rfp != active_build_fingerprint:
            classes[acls]['currency'] = 'STALE'
            classes[acls]['tier'] = TIER_1
            classes[acls]['consecutive_verified'] = 0
            classes[acls]['demotion_reason'] = 'build_fingerprint_drift'
            classes[acls]['receipt_ids'].append(aid)
            trace.append({'kind': 'observation', 'action_id': aid, 'action_class': acls, 'status': 'stale_build'})
            continue

        # 4. Clean verified receipt on active build -> increment streak for this action class only.
        classes[acls]['consecutive_verified'] += 1
        classes[acls]['currency'] = 'CURRENT'
        classes[acls]['receipt_ids'].append(aid)
        if classes[acls]['consecutive_verified'] >= threshold:
            classes[acls]['tier'] = TIER_2
            classes[acls]['demotion_reason'] = None
        trace.append({'kind': 'observation', 'action_id': aid, 'action_class': acls, 'status': 'verified_counted'})

    return {
        'schema': 'ea.autonomy-standing.v2',
        'active_build_fingerprint': active_build_fingerprint,
        'verifier_kid': pinned_kid,
        'threshold': threshold,
        'global_hold': global_hold,
        'classes': classes,
        'trace': trace,
        'limits': 'Local prototype Ed25519 key; production requires hardware-backed out-of-band verifier identity. Standing is a recommendation, never runtime write authority.',
    }
