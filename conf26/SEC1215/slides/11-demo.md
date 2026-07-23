# Live Demo: Watching the Loop Fire End to End

1. **Trigger** — fire a correlation search in Splunk ES; a notable lands in Incident
   Review.
2. **Phase 1** — `TA_ResponseActions` posts the full CIM/risk JSON to Slack, with the
   `perplexity_ask` standing checks attached.
3. **The AI answers** — `@perplexity_ask` replies in-thread with the strict JSON verdict
   (`risk_score`, `risk_object`, `risk_object_type`, `risk_message`).
4. **Phase 2/3** — within 60 seconds, `bin/slack_hec_bridge.py` picks it up, POSTs a CIM
   Risk event to HEC, and writes back to the notable.
5. **Payoff** — show the same notable in Incident Review: Adaptive Responses panel,
   notable comment, and the KV-store drilldown dashboard, all populated automatically.

## Speakers Notes

This is the live demo slide — talk through the five numbered steps as you drive the actual
Splunk instance, Slack workspace, and dashboards. Supporting demo scripts/config live in
[`demos/`](https://github.com/UnshakeableSaltLtd/SplunkConf/tree/main/conf26/SEC1215/demos)
in the session repo.

Suggested pacing for a 20-minute session: this is the one slide you can afford to linger on
if the demo goes well, but have a fallback ready — if live Slack/HEC round-trips are too
slow to wait out live, cut from step 3 straight to a pre-captured screenshot of the AI's
reply and the resulting Incident Review view, and say so plainly ("here's one I ran
earlier, so we don't watch a poll interval for two minutes").

Things to physically point at on screen for maximum impact:

- The Adaptive Responses panel entry (backed by `cim_actions.py`'s `ModularAction` — see
  slide 7) — proves the native panel integration works without any custom UI code.
- The KV-store drilldown dashboard
  (`default/data/ui/views/notable_slack_enrichment_drilldown.xml`) — this is where the
  "Agentic AI verdict" panel (added in v1.3.1) shows `risk_score`/`risk_object`/
  `risk_message` next to the rest of the enrichment record.
- The risk index event itself (`index=risk`) via a quick `| datamodel Risk All_Risk search`
  — this is the moment to say "this is now indistinguishable, to Risk-Based Alerting, from
  a risk modifier written by a native correlation search."

Full technical detail behind everything you're showing is in
[TA_ResponseActions/README.md § Closing the loop](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/TA_ResponseActions/README.md#closing-the-loop-getting-the-result-back-to-the-analyst).
