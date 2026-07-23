# Takeaway 3: Pitfalls We Hit — Part 2

**Pitfall 3 — LLM reply-format drift.**
Free-text answers to the original standing checks were unparseable. The fix: make the
required JSON shape part of the *prompt itself* (`perplexity_ask.reply_format`), and have
the bridge **log-and-skip, not crash**, on any reply that still doesn't parse — leaving the
raw reply visible for a human to check rather than losing it.

**Pitfall 4 — Modular input scheme overhead wasn't worth it for an internal poller.**
`slack_hec_bridge.py` is a plain classic scripted input, not a full
`splunklib.modularinput` scheme. Trade-off: no auto-generated Splunk Web settings page for
its custom keys — they're hand-edited in `local/inputs.conf` instead. Right call for a
single internal component; wrong call for anything meant to be configured by someone other
than the app's own maintainer.

## Speakers Notes

Source for both, verbatim from the architecture doc:
[ARCHITECTURE.md § Takeaway 3 pitfalls](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/SEC1215/ARCHITECTURE.md#how-this-maps-back-to-the-sessions-takeaways).

**Pitfall 3 detail:** this is the direct payback for Phase 2's design (slide 8) — tell the
story as "we tried it the naive way first" (just ask the AI to answer the checks, parse
whatever comes back) "and it didn't work reliably enough to trust." The fix that stuck:
`reply_format` pinned into `alert_actions.conf`'s `perplexity_ask.additional_fields` block,
instructing the AI to "Reply in this thread with ONLY a single JSON object, no prose before
or after it." Reinforce the resilience point from slide 9: a parse failure never crashes the
poller, it just leaves `awaiting_ai_response=1` so nothing silently vanishes.

**Pitfall 4 detail:** be honest that this was a deliberate, considered trade-off, not a
shortcut taken by accident — flag it as a decision point every team building something
similar will face. Classic scripted inputs are faster to ship for a single internal
component with one maintainer; full modular inputs pay off once you need Splunk Web's
config UI, validation, and multi-instance/clustering-aware input management for something
other people will configure.

Closing line for this pair of slides, before moving to the recap: "none of these four are
exotic — they're the kind of thing you only find by actually shipping something, which is
the entire point of Takeaway 3."
