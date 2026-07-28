# Phase 3, Take 2: One Payload, Three Existing Write-Back Paths

No bespoke store, and — as of v1.3.3 — no second process either. The same envelope that
carried `perplexity_ask` now also carries `perplexity_response`, straight into the three
paths `TA_ResponseActions` already had:

- **Slack** (unchanged since v1.0.0) — still useful for visually auditing exactly what was
  asked and what came back, per notable, as it happens.
- **The Notable Event API → the originating notable.** A `POST /services/notable_update`
  comment summarising what was sent, now including the Perplexity answer — visible directly
  in that notable's own Activity timeline in Incident Review.
- **The `notable_slack_enrichment` KV store + custom drilldown.** The full ask-and-response
  JSON as a structured record, reached from the notable's Adaptive Responses panel.

No analyst forwards, tags, or re-keys anything. All three writes happen inside the same
alert-action invocation — no waiting on a reply, no second component to trigger them.

## Speakers Notes

This is Phase 3 — the payoff of Phases 1 and 2, and the clearest evidence that removing the
bridge cost nothing structurally. Source:
[ARCHITECTURE.md § Phase 3](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/SEC1215/ARCHITECTURE.md#phase-3-one-payload-three-existing-write-back-paths).

Emphasise "not a bespoke store, and no second process" — this is the point where the
"build vs. free" framing (slide 7) pays off most visibly: the same three write-back paths
v1.2.0 already had now just also carry `perplexity_response`. Nothing new was invented to
replace the bridge's writes — they were already there, waiting to be fed synchronously
instead of asynchronously. Contrast explicitly with slide 8's take: the bridge *did* also
feed the risk index via HEC, which this design deliberately doesn't do — that's the one
real capability gap, named honestly rather than glossed over (see slide 3's caveat and
[ARCHITECTURE.md § What this doesn't do](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/SEC1215/ARCHITECTURE.md#what-this-doesnt-do-an-honest-scope-note)).
Reference for the Notable Event API's actual capabilities/limits:
[Notable Event API reference](https://help.splunk.com/en/splunk-enterprise-security-7/api-reference/7.3/notable-event-endpoints/notable-event-api-reference).

Close this slide with the full "retaining the principles of being agentic" loop, repeated
from slide 5 but now every step has been shown concretely: **detect** (correlation search)
→ **decide** (agentic AI against the standing `perplexity_ask` checks, in-line) → **act**
(Slack + notable comment + KV store write-back, same call) → **record** (native Adaptive
Response panel, Incident Review) — one continuous loop, closed without a human in the
middle of it, closed synchronously.

Transition line into the demo: "so let's actually see this fire, end to end — and notice how
few steps that actually is now."
