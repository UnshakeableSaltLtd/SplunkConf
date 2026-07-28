# Phase 2, Take 1: What We Thought We Needed (v1.3.1)

An LLM's reply is prose. Enterprise Security's Risk Analysis framework needs fields — so the
first design we shipped set out to map one straight onto the other:

| AI verdict concept | CIM Risk field it becomes |
|---|---|
| Which user/host/IP is this about | `risk_object` + `risk_object_type` |
| How risky is this, on our scale | `risk_score` |
| Why — the AI's reasoning, in one line | `risk_message` |
| Which notable this ties back to | `orig_sid` / `orig_rid` / `event_id` |

**The fix, at the time:** pin the required JSON shape into the prompt itself
(`perplexity_ask.reply_format` in `alert_actions.conf`), so the reply is deterministic, not
scraped from free text. It worked — and it's not what ships today. Here's why we built it,
and slide 9 shows exactly how it worked.

## Speakers Notes

This is the flashback slide: the *first* version of Phase 2, shipped as v1.3.1, and the
moment "the AI said something" was supposed to become "Splunk can correlate, score, and
dashboard what the AI said" by treating the verdict as a new CIM Risk modifier. It's a real,
worked design — not a straw man — which is exactly why it's worth walking through before
showing what replaced it. Source:
[ARCHITECTURE.md § What this doesn't do](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/SEC1215/ARCHITECTURE.md#what-this-doesnt-do-an-honest-scope-note)
and the full
[retired-design write-up in lessons/README.md](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/SEC1215/lessons/README.md).

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
`alert_actions.conf`'s `perplexity_ask.additional_fields` block instructed the AI to "Reply
in this thread with ONLY a single JSON object, no prose before or after it," in exactly the
shape in the table on this slide. This was the fix for a real pitfall hit during the build —
covered explicitly on slide 13 — free-text answers to the original checks were unparseable
until the required shape became part of the prompt itself. Land the caveat now, don't wait:
this pattern only works if something reads the reply back out of Slack, which is the whole
reason the bridge in slide 9 had to exist. Today's v1.3.3 doesn't populate these CIM Risk
fields at all — an honest, named trade-off, not an oversight — because the operational cost
of this design (next two slides) outweighed the benefit for what this build needs to prove.

Bridge slide into "how does it actually read that reply back" — that's slide 9.
