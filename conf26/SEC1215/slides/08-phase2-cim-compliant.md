# Phase 2: The AI's Answer Becomes a CIM-Compliant Event

An LLM's reply is prose. Enterprise Security's Risk Analysis framework needs fields.

| AI verdict concept | CIM Risk field it becomes |
|---|---|
| Which user/host/IP is this about | `risk_object` + `risk_object_type` |
| How risky is this, on our scale | `risk_score` |
| Why — the AI's reasoning, in one line | `risk_message` |
| Which notable this ties back to | `orig_sid` / `orig_rid` / `event_id` |

**The fix:** pin the required JSON shape into the prompt itself
(`perplexity_ask.reply_format` in `alert_actions.conf`), so the reply is deterministic, not
scraped from free text.

## Speakers Notes

This is Phase 2, and it's the technical heart of the talk — the moment "the AI said
something" becomes "Splunk can correlate, score, and dashboard what the AI said." Source:
[ARCHITECTURE.md § Phase 2](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/SEC1215/ARCHITECTURE.md#phase-2--the-ais-answer-becomes-a-cim-compliant-event-shipped-v131).

Repeat the field-minimum claim from slide 3, now with the "why" fully spelled out: a risk
modifier in the risk index is only usable by Risk Analysis and Incident Review once it
carries, at minimum, `risk_object`, `risk_object_type`, and `risk_score`, because the Risk
data model (`All_Risk`) accelerates exactly those fields, and an object's overall risk score
is the sum of every risk modifier's `risk_score` for it — reference:
[Risk Analysis framework](https://dev.splunk.com/enterprise/docs/devtools/enterprisesecurity/riskanalysisframework).
`risk_message` exists specifically so an automation can customise the human-readable reason
for the score — reference:
[CIM Risk data model reference](https://dev.splunk.com/view/enterprise-security/SP-CAAAFBM).

The concrete mechanism (shipped in v1.3.1): the `reply_format` key inside
`alert_actions.conf`'s `perplexity_ask.additional_fields` block instructs the AI to "Reply
in this thread with ONLY a single JSON object, no prose before or after it," in exactly the
shape in the table on this slide. This is the fix for a real pitfall hit during the build —
covered explicitly on slide 13 — free-text answers to the original checks were
unparseable until the required shape became part of the prompt itself.

Bridge slide into "how does it actually read that reply back" — that's slide 9.
