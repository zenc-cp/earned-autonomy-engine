---
theme: sovereign-ledger
mode: operate
appearances: [light, dark]
contrast_floor: "WCAG AA >= 4.5:1 normal text; APCA >= 75 body"
tokens:
  light:
    bg_canvas: "#f7f6f2"
    bg_surface: "#ffffff"
    bg_surface_muted: "#f0efe9"
    ink_primary: "#141923"
    ink_secondary: "#475467"
    ink_tertiary: "#667085"
    border_subtle: "rgba(20, 25, 35, 0.12)"
    action_primary: "#1d4ed8"
    action_primary_ink: "#ffffff"
    status_tier2: "#15803d"
    status_tier2_bg: "#dcfce7"
    status_tier1: "#b45309"
    status_tier1_bg: "#fef3c7"
    status_tier0: "#b91c1c"
    status_tier0_bg: "#fee2e2"
  dark:
    bg_canvas: "#10141b"
    bg_surface: "#171d26"
    bg_surface_muted: "#202834"
    ink_primary: "#eef2f6"
    ink_secondary: "#a5b1c2"
    ink_tertiary: "#7e8b9d"
    border_subtle: "rgba(238, 242, 246, 0.13)"
    action_primary: "#60a5fa"
    action_primary_ink: "#09111c"
    status_tier2: "#4ade80"
    status_tier2_bg: "rgba(74, 222, 128, 0.14)"
    status_tier1: "#fbbf24"
    status_tier1_bg: "rgba(251, 191, 36, 0.14)"
    status_tier0: "#f87171"
    status_tier0_bg: "rgba(248, 113, 113, 0.16)"
spacing:
  intra_group_px: 8
  inter_group_px: 20
  card_padding_px: 18
  radius_card_px: 8
  radius_control_px: 6
---

# Earned Autonomy — Sovereign Ledger Design System

## Surface Mode: Operate
The Graduation Desk (`live_desk.py` and offline `desk.html`) is a high-trust **security & release governance console**. Scanability, honest status legibility, and clear separation between **Normal Agent Operations** and **Adversarial Fault Injection** outrank decorative flair.

## Core Rules
1. **One primary action fill per view:** Only the primary read/approve/reinstate action carries `--action-primary`; secondary controls stay neutral (`--bg-surface-muted`) with crisp borders.
2. **One color, one meaning:** Forest green (`--status-tier2`) is reserved exclusively for `Tier 2` / verified clear states; amber (`--status-tier1`) for `Tier 1` / `STALE` / `202 Hold`; crimson (`--status-tier0`) for `Tier 0` / `GLOBAL HOLD` / tampered invariants.
3. **Group with space, not lines:** 8px intra-group control spacing vs. 20px inter-group separation.
4. **Zero external dependencies:** System UI + monospace font stacks, strict `default-src 'none'` CSP, offline-first rendering.
