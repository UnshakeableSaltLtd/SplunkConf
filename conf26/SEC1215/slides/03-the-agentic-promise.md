# "Agentic AI" Is Easy to Say, Hard to Ship

- Every vendor keynote: autonomous SOC, self-healing detections, AI analysts.
- The gap nobody shows you: what actually connects an LLM's opinion to a field Splunk can
  score, correlate, and dashboard.
- An LLM's reply is prose, or loose JSON at best — Enterprise Security's Risk Analysis
  framework and Incident Review don't care what the AI *said*. They care about **fields**.
- Start with Smart LLM's and tune down to specific API addressing.
- This talk is the plumbing between "the AI had a thought" and "the SOC analyst sees a risk
  score, with zero copy/paste."

## Speakers Notes

This is the hook / problem statement before we show any architecture. The core tension to
land here: agentic AI demos always show the LLM reasoning about a security event, but they
skip the unglamorous part — getting that reasoning back into the platform in a form the
platform's own automation (Risk-Based Alerting, Incident Review) can actually use.

Land the specific technical claim early, because it's the thesis of Phase 2 later: a risk
modifier in the risk index is only usable by the Risk Analysis and Incident Review
dashboards once it carries, at minimum, `risk_object`, `risk_object_type`, and `risk_score`
— because the Risk data model (`All_Risk`) accelerates exactly those fields, and an object's
overall risk score is the sum of every risk modifier's `risk_score` for it. Reference:
[Risk Analysis framework](https://dev.splunk.com/enterprise/docs/devtools/enterprisesecurity/riskanalysisframework).
`risk_message` exists specifically so an automation can customise the human-readable reason
for the score — reference:
[CIM Risk data model reference](https://dev.splunk.com/view/enterprise-security/SP-CAAAFBM).

Don't over-explain yet — this slide is intentionally a teaser for slide 8, where we walk
through the design we built *first* to chase exactly this bar (mapping the AI's verdict onto
`risk_object`/`risk_object_type`/`risk_score`). Small honest caveat to set up now so it isn't
a surprise later: what ships today (v1.3.3, slide 5) deliberately does not push the AI's
answer into the risk index — that trade-off, and why it was still the right call, is Takeaway
3's whole arc. The point right now is just: "posted to Slack" is not the same thing as
"usable by Splunk."
