# Live Demo: One Alert Action, One Shot, Done

1. **Trigger** — fire a correlation search in Splunk ES; a notable lands in Incident
   Review.
2. **Fire the action** — `TA_ResponseActions` builds the full CIM/risk JSON, including the
   `perplexity_ask` standing checks.
3. **The AI answers, in-line** — before anything is sent anywhere, a single synchronous
   call to the Perplexity API returns a structured `perplexity_response`, merged straight
   into the same payload.
4. **One payload, three deliveries** — Slack, the notable's comment trail, and the KV
   store record all get written in the same action invocation. No polling, no wait.
5. **Payoff** — show the same notable in Incident Review: Adaptive Responses panel,
   notable comment, and the KV-store drilldown dashboard, all populated — by the time you
   finish saying "and that's it."

## Speakers Notes

This is the live demo slide — talk through the five numbered steps as you drive the actual
Splunk instance, Slack workspace, and dashboards. Supporting demo scripts/config live in
[`demos/`](https://github.com/UnshakeableSaltLtd/SplunkConf/tree/main/conf26/SEC1215/demos)
in the session repo.

Suggested pacing for a 20-minute session: this demo now runs noticeably faster than the
version of this talk that would have run against v1.3.1–v1.3.2 — there's no 60-second poll
interval to wait out anymore, because there's no poll at all. Say that out loud: "the old
version of this demo had a built-in coffee-break while we waited for a bridge to notice a
Slack reply — watch how long this takes now." Have a fallback screenshot ready regardless,
in case the live Perplexity API call is slow or the network is uncooperative on the day, but
you should no longer need it purely to skip a polling delay.

Things to physically point at on screen for maximum impact:

- The Adaptive Responses panel entry (backed by `cim_actions.py`'s `ModularAction` — see
  slide 7) — proves the native panel integration works without any custom UI code.
- The KV-store drilldown dashboard
  (`default/data/ui/views/notable_slack_enrichment_drilldown.xml`) — shows the full
  `perplexity_ask`/`perplexity_response` pair, ask and answer side by side, next to the
  rest of the enrichment record.
- The notable comment itself in Incident Review's Activity timeline — this is the moment to
  say "this landed the moment the alert action ran, not sixty seconds and a Slack reply
  later." (Skip the `All_Risk`/risk-index datamodel search that would have been here in an
  earlier version of this demo — v1.3.3 deliberately doesn't write to the risk index; see
  slide 8's honest scope note if anyone asks why.)

Full technical detail behind everything you're showing is in
[TA_ResponseActions/README.md § Perplexity API: synchronous ask/response](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/TA_ResponseActions/README.md#perplexity-api-synchronous-askresponse)
and
[§ Closing the loop](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/TA_ResponseActions/README.md#closing-the-loop-getting-the-result-back-to-the-analyst).
