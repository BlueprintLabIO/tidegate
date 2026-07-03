# SLUICE — Tidegate design system

Neo-brutalist. A sluice is the gate that controls the flow; the UI says the same thing the product does: hard edges, one loud warning color, nothing decorative that isn't structural.

Live styleguide: `/design`. Implementation: `src/styles/sluice.css` (tokens + `sl-` component classes).

## Rules

1. **Radius 0.** No rounded corners anywhere.
2. **Ink borders.** 3px solid `--ink` on components, 2px on small elements. Borders are the design.
3. **Hard shadows.** Offset, unblurred: `8px 8px 0 #111` (cards/terminal), `5px` (buttons/rows), `3px` (chips-scale). Hover presses the element *into* its shadow (translate + shrink), active removes it.
4. **One loud color.** `--gate` orange `#FF4D00` is the only accent. If two things are orange, one of them is wrong. Permission colors (`--allow/--ask/--deny`) are semantic, not decorative — they may only mark permission state.
5. **Flat fills.** No gradients, except the caution stripe (45° ink/orange), which means "barrier" and is used only as a divider or gate-marker.
6. **Paper texture.** Page background is cream `--paper` with a visible dot grid; surfaces are `--card` near-white.
7. **Motion is scarce.** One staggered rise on hero load (`.sl-rise` + animation-delay), press-into-shadow on hover, blinking terminal cursor. Nothing scroll-driven. Respect `prefers-reduced-motion`.

## Type

| Role | Font | Usage |
|---|---|---|
| Display | Archivo Black | headlines, uppercase, line-height 0.94 |
| Body | Archivo (variable) | prose |
| Mono | Martian Mono (variable) | commands, labels (`.sl-label`: 11px, 700, tracked 0.14em), receipts, buttons |

Fonts load from the Fontsource jsDelivr CDN as woff2 with `font-display: swap` (see top of `sluice.css`).

## Components (`sluice.css`)

- `.sl-btn` (+ `--gate`, `--ink`) — bordered button with hard shadow and press interaction.
- `.sl-card` — white card, 3px border, 8px shadow.
- `.sl-chip` (+ `--allow`, `--ask`, `--deny`) — permission chip; uppercase mono.
- `.sl-term` — terminal window: dark panel, square (not round) window buttons in deny/ask/allow colors, `$` prompts in gate-orange, `✔` output in allow-green, `.sl-cursor` blinking block.
- `.sl-cmd` — click-to-copy command row; `data-copy` attribute holds the payload; the `copy` tag flips to `copied` for 1.4s.
- `.sl-tabs` / `.sl-tab` — package-manager tabs; selected = ink fill, hover = gate fill; `aria-selected` drives state.
- `.sl-receipt` — audit log as printed receipt: dashed rule head/foot, sawtooth torn bottom edge (pseudo-element), hash line. Uses `filter: drop-shadow` so the shadow follows the teeth.
- `.sl-stamp` — rotated rubber stamp (border + offset outline), used for the "v0 · under construction" honesty mark.
- `.sl-stripe` — caution-stripe divider.

## Voice

Copy is short, declarative, lowercase-mono for labels, sentence case for prose. No marketing adjectives; state facts about the gate ("Keys stay home", "Ask before write", "Receipts for everything").
