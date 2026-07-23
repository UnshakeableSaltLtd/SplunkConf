# Phase 2 Mechanics: `bin/slack_hec_bridge.py`

A classic Splunk scripted input, registered in `default/inputs.conf`, polling every 60s:

1. Poll the `notable_slack_enrichment` KV store for records flagged
   `awaiting_ai_response=1` (set by Phase 1 the moment a notable is sent).
2. Read the Slack thread via `conversations.replies` for the AI's answer.
3. Parse the reply against the strict `reply_format` JSON schema.
4. On success → build a CIM-shaped risk event, ready for Phase 3.
5. On parse failure → **log and skip, don't crash** — leave `awaiting_ai_response=1` so the
   raw reply stays visible for a human to check, nothing silently disappears.

## Speakers Notes

This is the "how" behind Phase 2's field-mapping table (slide 8). Source:
[TA_ResponseActions README § Phase 2/3](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/TA_ResponseActions/README.md#phase-23-closing-the-agentic-loop-binslack_hec_bridgepy)
and
[ARCHITECTURE.md § Phase 2](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/SEC1215/ARCHITECTURE.md#phase-2--the-ais-answer-becomes-a-cim-compliant-event-shipped-v131).

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
than the app's own maintainer.

The "log and skip, don't crash" behaviour on parse failure is deliberate resilience design —
emphasise this as a best practice for anyone building their own AI-to-Splunk bridge: never
let an LLM's unpredictable output take down your scripted input.
