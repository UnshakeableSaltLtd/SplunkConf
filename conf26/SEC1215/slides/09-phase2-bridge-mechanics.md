# Take 1 Mechanics: `bin/slack_hec_bridge.py` (Retired)

A classic Splunk scripted input, registered in `default/inputs.conf`, polling every 60s —
this is exactly how the v1.3.1–1.3.2 design closed the loop before v1.3.3 replaced it:

1. Poll the `notable_slack_enrichment` KV store for records flagged
   `awaiting_ai_response=1` (set by Phase 1 the moment a notable is sent).
2. Read the Slack thread via `conversations.replies` for the AI's answer.
3. Parse the reply against the strict `reply_format` JSON schema.
4. On success → build a CIM-shaped risk event, ready for Phase 3.
5. On parse failure → **log and skip, don't crash** — leave `awaiting_ai_response=1` so the
   raw reply stays visible for a human to check, nothing silently disappears.

It worked, end to end. It's also gone — archived at `lessons/`, not deleted, because building
it is what made the v1.3.3 design obviously correct in hindsight.

## Speakers Notes

This is the "how" behind Take 1's field-mapping table (slide 8) — keep it firmly in the past
tense, this component doesn't run anymore. Source:
[TA_ResponseActions README § Perplexity API: synchronous ask/response](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/TA_ResponseActions/README.md#perplexity-api-synchronous-askresponse)
(explains what replaced it) and
[ARCHITECTURE.md § Lesson: the Slack to HEC bridge, retired](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/SEC1215/ARCHITECTURE.md#lesson-the-slack-to-hec-bridge-retired)
for the full numbered list of what it cost to run.

Correlation keys worth calling out explicitly: the bridge finds its way back to the right
KV store record and the right notable using the **same `sid`/`rid`** that
`TA_ResponseActions` already established for its own KV-store enrichment back in v1.2.0 —
nothing new was invented for correlation, it reuses what Phase 1 already writes.

Design choice worth flagging here (comes back as its own pitfall on slide 13): this is
registered as a **plain classic scripted input** (`[script://...]` in `inputs.conf`), not a
full `splunklib.modularinput` scheme. That means Splunk Web doesn't auto-generate a settings
page for its custom keys (`risk_index`, `hec_url`, the credential realms) — they're
self-parsed out of `inputs.conf` via Python's `configparser` and must be hand-edited in
`local/inputs.conf`. Fine for a single internal component maintained by one team; call out
that it would be the wrong trade-off for anything meant to be configured by someone other
than the app's own maintainer — and it's a fair chunk of the reason it was retired rather
than kept and polished.

The "log and skip, don't crash" behaviour on parse failure is deliberate resilience design —
worth crediting even though the component is retired: never let an LLM's unpredictable
output take down your scripted input. Land the transition here explicitly: everything on
this slide is real engineering, it worked, and the team still pulled it once they'd run it
long enough to feel its operational weight. That's the "learned fast, reacted, trusted the
platform" arc in miniature — slides 12–13 turn each individual cost into a named, numbered
pitfall, and slide 14 shows how quickly the replacement shipped once the decision was made.
