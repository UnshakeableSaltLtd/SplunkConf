---
name: splunk-conf26-pptx-standard
description: "Standing brand/template standard for ALL PowerPoint slide or deck output produced in the Assets and Identity project (e.g. SEC1053 and other Splunk .conf26 breakout sessions). Use whenever the user in this project asks to create, add, or edit a PowerPoint slide, deck, or slide content. Enforces the Cisco/Splunk .conf26 Breakout Template (fonts, colors, layouts, footer/logo) instead of generic pptxgenjs design."
metadata:
  author: computer
  version: '1.0'
---

# Splunk .conf26 PowerPoint Brand Standard

## When to Use This Skill

Load this skill for ANY task in the Assets and Identity project that produces or edits a `.pptx` file — a single slide, a full deck, or edits to an existing deck. This includes opening/title slides, quote slides, agenda slides, section headers, content slides, or closing slides for SEC1053 or any other Splunk .conf26 breakout session.

Do NOT build slides from a blank pptxgenjs theme or generic Nexus design system for this project. The user has an explicit, strict brand template that MUST be used.

## The Master Template

The source of truth is `conf26_Breakout_Template.pptx`, a 46-slide Cisco/Splunk-branded template deck. It has been uploaded to this project's file repository — retrieve it with `search_files` (filename `conf26_Breakout_Template.pptx`) if it is not already in the local workspace. The user's own copy lives in github at  at:
`https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/docs/conf26_Breakout_Template.pptx`


Slide 5 of the template documents the typeface rules; slide 6 documents colors and elements. Slides 12-24 are the reusable content layouts (title, agenda, section header, statement, quote, half-slide, etc.) — see the layout index below.

## Design System (from template slides 5 & 6)

**Typeface — Inter family (embedded in the template file itself, so it renders correctly even if Inter isn't installed on the rendering machine):**
- Section title: Inter Regular 12pt
- H1: Inter SemiBold 32pt
- H2: Inter Light 24pt
- H3: Inter Bold ≤20pt
- Subtitle 1: Inter Regular 16pt
- H4: Inter Bold ≤16pt
- Body copy: Inter Regular 16pt (default)
- Hyperlinks: Inter Regular, underlined
- Labels 1: Inter Regular 10-16pt: Labels 2: Bold <10pt

**Colors:**
| Name | Hex | Usage |
|---|---|---|
| Splunk Magenta | `#FF007F` | Chart graphics only |
| Splunk Orange | `#FF9000` | Chart graphics only |
| Splunk Gradient | magenta→orange | Text/outlines only |
| Cisco Blue | `#02C8FF` | Text/graphics |
| Cisco Medium Blue | `#0A60FF` | Text/graphics |
| Cisco Gradient | light blue→medium blue | Text/outlines only |
| Light Grey | `#D6D6D6` | Text/graphics |
| Medium Grey | `#6B6B6B` | Large-text/graphics |
| 30% Midnight Blue | `#B4B9C0` | Text/graphics |
| 70% Midnight Blue | `#525E6C` | Decorative only |

Rules: prefer supporting/neutral colors for most content; grey lines for connectors/leaders; use gradients sparingly and never mix a gradient fill with a solid fill in the same shape; standard line weight 1.25pt; rounded corners on most containers/picture frames except titles and segues.

**Standing footer on every content slide** (inherited automatically from the slide layout/master — never build this manually): "© 2026 Cisco and/or its affiliates. All rights reserved." bottom-left, small grey text; Cisco logo + "Cisco Confidential" bottom-right.

## Layout Index (slide numbers in the 46-slide template)

- 1: Title slide (".conf26 Breakout Template")
- 12-14: Title layout options (with Session ID / Speaker / social handle placeholders)
- 15-17: Session title + speaker card variants (2-4 speakers)
- 18: Agenda (numbered 01-08)
- 19-20: Section header ("lorem ipsum dolor sit"), with gradient swoosh variant
- 21: Statement slide — large bold centered headline + pipe-separated subtitle
- 22: **Quote slide 1** — magenta-outlined curly-quote icon, large bold centered quote, "Source Name" + grey "Subtitle" lines below, subtle light gradient background. Use this for attributed-quote openers.
- 23: Quote slide 2 — same as above but dark quote icon + pink/orange gradient bleeding from bottom-left corner. Alternate quote treatment.
- 24: Half-slide title + body copy + gradient graphic

## Required Workflow: Never Rebuild From Scratch

Because this is a pixel-exact brand template (specific gradients, an embedded curly-quote vector icon, embedded Inter font files, exact placeholder positions), the correct and ONLY compliant way to produce a slide is to **clone the matching layout slide from the template and edit its text**, not to recreate the visual design with pptxgenjs or generic design tooling.

1. Load `office/pptx` skill, then read `office/pptx/EDITING.md` for the unpack → edit → repack workflow.
2. Unpack the template pptx: `python scripts/unpack.py conf26_Breakout_Template.pptx unpacked/`.
3. Identify the layout slide number that matches the requested content (see Layout Index above). Inspect its raw XML in `ppt/slides/slideN.xml` — for well-built template slides, all placeholders inherit font/color from the slide layout and master, so slide-level edits should only touch `<a:t>` text runs, never override font/color/position unless truly necessary.
4. In `ppt/presentation.xml`, trim `<p:sldIdLst>` to keep only the `<p:sldId>` entries for the slide(s) you are keeping (for a single-slide deliverable, keep exactly one). Also remove the `p14:sectionLst` extension block if present (it references section groupings for slides no longer present).
5. Run `python scripts/slides.py clean unpacked/` to drop orphaned slides, media, notes, and relationships.
6. Edit the kept slide's `<a:t>` runs with the new content. Never touch the slide layout or master files.
7. To add speaker notes: create `ppt/notesSlides/notesSlideN.xml` (copy the structure of an existing notes file such as `notesSlide1.xml`), add its `_rels/notesSlideN.xml.rels` (relationship to the slide + notesMaster + any hyperlink relationships for cited sources), register it in `[Content_Types].xml`, and add a `notesSlide` relationship in the slide's own `.xml.rels` file. Never leave a slide without proper notes registration if notes are requested.
8. Pack: `python scripts/pack.py unpacked/ output.pptx`.
9. **Verify embedded fonts survived**: `unzip -l output.pptx | grep -i font` should still list `ppt/fonts/font*.fntdata`, and `unzip -p output.pptx ppt/presentation.xml | grep embeddedFont` should still show the Inter family entries. If fonts are missing, the pack/clean step stripped them — investigate before delivering.
10. Run the full QA cycle from `office/pptx/SKILL.md` (markitdown content check, soffice+pdftoppm render, subagent visual QA, fix-and-verify) before delivering.

## Do NOT "Fix" Inherited Template Design Choices

Generic design-quality checks (e.g. WCAG contrast, 0.5" edge margins, element centering) may flag things like the grey subtitle text contrast, the footer/logo margins, or the quote icon's exact position as issues. If those elements are inherited unmodified from the template's own layout/master (i.e., you did not add or reposition them), do NOT change them — the strict template compliance requirement overrides generic design-polish heuristics for this project. Only flag such observations to the user as informational notes; never silently deviate from the template's own design.

## GitHub Repository — Source of Truth for Everything in This Project

Everything for this project lives in the GitHub repo `UnshakeableSaltLtd/SplunkConf` (private), and every talk is a `conf<year>/<SESSION_ID>/` folder there. This project's main location for content in 2026 is:

`https://github.com/UnshakeableSaltLtd/SplunkConf/conf26`

- `SEC1053/SEC1053.md` — the official session brief (title, abstract, and the 3 official takeaways). Always read this before drafting slide content — it is the source of truth for talk structure and takeaways, not the folder's `README.md` (which can drift out of date; cross-check the two and flag mismatches to the user rather than silently trusting either).
- `SEC1053/README.md` — session metadata (date, speaker, track, skill level) plus a content index.
- `SEC1053/slides/` — presentation slides (PPTX). **Every new slide is a separate, individually named PPTX file in this folder — never overwrite or edit a previously delivered slide file.** This preserves earlier work whether it was authored inside or outside this project.
- `SEC1053/demos/`, `conf26/SEC1053/images/` — demo scripts and diagrams/screenshots.
- `docs/conf26_Breakout_Template.pptx` — a repo-level copy of the master brand template (same file as the project's uploaded `conf26_Breakout_Template.pptx`).

**Sync behavior:** files uploaded to this Perplexity project's file repository (via `upload_file`) or shared with the user (via `share_file`) are automatically synced into this GitHub repo. There is no need to manually push slide deliverables — but always spot-check (`gh api repos/UnshakeableSaltLtd/SplunkConf/contents/<path>`) that the expected file landed correctly after delivering.

**Permissions:** you may add new files to this repo freely. Do NOT perform destructive actions (deleting or force-overwriting existing files/history, rewriting other people's committed content) without explicit human confirmation first.

## SEC1053 Talk Structure (from the brief)

"The other AI: Assets and Identity. Using Splunk to keep in check" — Theater Session, 20 minutes, Splunk .conf26, Security track.

- **Intro (3-4 slides):** opening hook (the Dave DeWalt quote slide already built), session framing, agenda.
- **Core content (~10 minutes, the bulk of the talk):** how to get Asset and Identity Management under control in Splunk Enterprise Security — continuous asset/identity discovery, mapping to risk, and automated governance workflows aligned to the UK Cyber Assessment Framework and NIST CSF.
- **Wrap-up (quicker close):** tie back explicitly to the three official takeaways from `SEC1053.md`:
  1. Continuous asset discovery and risk tracking across secure infrastructure.
  2. How Splunk's automated governance workflows simplify meeting regulatory mandates (CAF / NIST CSF).
  3. Turning compliance reports into proactive, automated security actions inside Splunk.

## Precedent: SEC1053 Opening Quote Slide

The first slide built under this standard was the SEC1053 opening quote slide, cloned from template slide 22 ("Quote slide 1"), with the quote "You can't protect what you don't know you have." attributed to Dave DeWalt (Former CEO, McAfee & FireEye · Founder, NightDragon), and speaker notes tying it to the UK NCSC Cyber Assessment Framework (Objective A, Principle A3 — Asset Management) and NIST CSF (Identify function, category ID.AM). Use this as a reference example of the workflow above.
