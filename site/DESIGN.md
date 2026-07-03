# SLUICE — Tidegate design system

Neo-brutalist, tide-flavored. A sluice is the gate that controls the flow; the UI says the same thing the product does: hard edges, harbor colors, nothing decorative that isn't structural.

Live styleguide: `/design`. Implementation: `src/styles/sluice.css` (tokens + `sl-` component classes).

## Rules

1. **Radius 0.** No rounded corners anywhere.
2. **Ink borders.** 3px solid `--ink` (abyss navy, not black) on components, 2px on small elements. Borders are the design.
3. **Hard shadows.** Offset, unblurred: `8px 8px 0` (terminal/gate), `5px` (buttons/rows), `3px` (small). Hover presses the element *into* its shadow, active removes it.
4. **Coral shouts, tide aqua murmurs.** `--gate` coral `#FF5A47` is the loud accent — stamps, prompts, barrier statements, the redaction's cousin. `--tide` aqua `#189E94` is the quiet second tone — the waterline, hover states, dim annotations. If coral appears twice in one viewport without a reason, one of them is wrong. Permission colors (`--allow/--ask/--deny`) are semantic, never fashionable.
5. **Boxes only for objects.** Border+shadow treatment is reserved for things that are diegetically *objects*: the terminal (a window), the receipt (a paper artifact), the gate (a structure), and interactive controls (buttons, tabs, command rows). Prose, facts, lists, and diagram labels live directly on the paper as typography with hairline rules.
6. **Flat fills.** No gradients, except the tide gauge bands (navy over aqua = the waterline) used as dividers and the gate's header.
7. **Paper texture.** Page background is foam `--paper` with a visible dot grid; surfaces are `--card` near-white.
8. **Motion is scarce.** One staggered rise on hero load (`.sl-rise` + animation-delay), press-into-shadow on hover, blinking terminal cursor. Nothing scroll-driven. Respect `prefers-reduced-motion`.
9. **Asymmetry is deliberate.** Compositions stagger (terminal bottom-aligned and dipping into the gauge, channel sides offset above/below the waterline, receipt tilted ~1.5°). Never a grid of equal boxes.

## Palette

| Token | Hex | Role |
|---|---|---|
| `--paper` | `#F1EFE5` | page (foam) |
| `--card` | `#FCFBF4` | surfaces |
| `--ink` | `#0F2233` | borders, text (abyss navy) |
| `--gate` | `#FF5A47` | loud accent (coral) |
| `--tide` | `#189E94` | quiet accent (aqua) |
| `--allow/--ask/--deny` | `#0E9F6E / #FFB800 / #E02424` | permission semantics only |
| `--term` | `#0B1A26` | terminal (below the waterline) |

## Type

| Role | Font | Usage |
|---|---|---|
| Display | Archivo Black | headlines, uppercase, line-height 0.94 |
| Body | Archivo (variable) | prose |
| Mono | Martian Mono (variable) | commands, labels (`.sl-label`: 11px, 700, tracked 0.14em), receipts, buttons |

Fonts load from the Fontsource jsDelivr CDN as woff2 with `font-display: swap` (see top of `sluice.css`).

## Components (`sluice.css`)

- `.sl-redact` — the censor bar, in type: transparent letters behind a cap-height ink band (`SEC▮▮TS`). The product's job, performed by the headline.
- `.sl-gauge` — the waterline divider: navy over aqua horizontal bands with foam tick marks, like the depth gauge on a harbor wall.
- `.sl-btn` (+ `--gate`, `--ink`) — bordered button with hard shadow and press interaction.
- `.sl-chip` (+ `--allow`, `--ask`, `--deny`, `--gate`) — permission chip; uppercase mono. `--gate` marks barrier statements ("no tokens beyond this point").
- `.sl-term` — terminal window: navy panel, square (not round) window buttons in deny/ask/allow colors, `$` prompts in coral, `✔` output in allow-green, `.sl-cursor` blinking block. Lines are per-line `.tl` divs (`white-space: pre`) — never rely on literal newlines; the Astro compiler collapses whitespace-only text nodes.
- `.sl-cmd` — click-to-copy command row; `data-copy` attribute holds the payload; the `copy` tag flips to `copied` for 1.4s.
- `.sl-tabs` / `.sl-tab` — package-manager tabs; selected = ink fill, hover = tide fill; `aria-selected` drives state.
- `.sl-receipt` — audit log as printed receipt: dashed rule head/foot, sawtooth torn bottom edge (pseudo-element), hash line. Uses `filter: drop-shadow` so the shadow follows the teeth.
- `.sl-stamp` — rotated rubber stamp (coral border + offset outline), used for the "v0 · under construction" honesty mark.

## Voice

Copy is short, declarative, lowercase-mono for labels, sentence case for prose. No marketing adjectives; state facts about the gate ("Set up once", "They never see the key", "You hold the veto").
