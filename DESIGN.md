# MacSentinel design system

## Product surface

MacSentinel is a native macOS evidence-inspection tool. The interface prioritizes scan coverage, evidence state, and safe next steps. It reports what checks returned; it does not claim that a Mac is clean or turn review counts into a safety score.

## Visual direction

The dashboard is an ink-black evidence workspace: a quiet near-black canvas holds raised graphite surfaces; ice-teal identifies collected evidence and primary actions; amber and coral distinguish review and attention states. System typography, SF Symbols, SwiftUI controls, and macOS interaction conventions keep the interface familiar and legible.

## Color roles

| Role | Color | Use |
|---|---|---|
| Canvas | `#090B0E` | Main scroll surface |
| Surface | `#13171C` | Panels and grouped content |
| Raised surface | `#1B2026` | Inputs, selected details, and supporting surfaces |
| Outline | `#2E373F` | Panel and control boundaries |
| Collected / action | `#4DDCCA` | Collected evidence, primary buttons, selection, and chart series |
| Review | `#FFBB57` | Evidence that needs contextual verification |
| Attention | `#FF6763` | Recognized settings or results requiring attention |
| Primary text | `#EDF2F6` | Main labels and values |
| Secondary text | `#B0BBC6` | Explanations and supporting copy |
| Muted text | `#8594A2` | Quiet metadata and tertiary labels |

Use the semantic role colors consistently in charts, labels, and actions. Never infer a malware verdict from a review or attention state.

## Components and interaction

- **Primary button:** filled teal with dark text; reserved for running a scan or saving an export.
- **Secondary button:** raised graphite fill and visible outline for updates, retries, and follow-up actions.
- **Quiet and destructive actions:** quiet controls stay low-emphasis; destructive actions use coral text and require confirmation where appropriate.
- **Action rows:** full-width, keyboard-accessible buttons with clear pressed feedback and an outline.
- **Panels:** graphite surfaces with a thin outline, 16-point corner radius, and consistent 18-point internal spacing.
- **Scan chart:** horizontal standard-stacked bars show only actual evidence counts per scan area, split into collected, review, and attention series. A legend names each state.
- **Theme:** dark appearance is intentional and applied throughout the window and its sheets. Native controls retain their standard keyboard and accessibility behavior.

## Layout

The header keeps scan profile and primary actions visible. The snapshot summary and result counts lead into the area chart and prioritized actions, followed by history, expandable evidence, and privacy/coverage notes. The window remains scrollable and supports the existing minimum width.
