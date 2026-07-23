# Takeaway 1: Choosing the Right LLM for SecOps

Four axes that actually matter — not "which model tops the leaderboard":

- **Cost** — priced per notable/investigation, not per demo. A SOC generates volume; the
  biggest frontier model on every single notable gets expensive fast.
- **Latency** — an analyst is waiting on this reply inside a Slack thread. Round-trip time
  is part of the user experience, not a footnote.
- **Privacy** — the payload is a full CIM/risk notable export. Where does that data go, and
  under what retention/training terms?
- **Capability** — does it need to reason over a full raw event, or just answer three
  standing yes/no/score questions well?

Design decision that follows from this: keep the **payload full and complete**, so a
smaller/cheaper model still gets the whole picture to reason over — don't compensate for a
weaker model by hand-crafting a bigger prompt.

## Speakers Notes

This slide is Takeaway 1 stated directly, then grounded in the one concrete design decision
it produced in the actual build. From
[ARCHITECTURE.md](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/SEC1215/ARCHITECTURE.md#how-this-maps-back-to-the-sessions-takeaways):
"Takeaway 1 (choosing the right LLM) is why Phase 1's payload is a full, denylist-scrubbed
JSON export rather than a squeezed summary — a smaller/cheaper model still gets the complete
picture to reason over."

Concretely, the agentic AI actor in this build is invoked in-thread via Slack as
`@perplexity_ask` — it's the model reading the JSON payload and answering the standing
`perplexity_ask` checks you'll see in Phase 1. Emphasise this is a *contract*, not a
lock-in: because the interface between Splunk and the AI is a plain JSON payload delivered
to a Slack thread, and the interface back is a pinned JSON reply shape (see Phase 2), the
LLM behind `@perplexity_ask` is swappable without touching `TA_ResponseActions` or the
bridge at all — the integration doesn't care which model answers, only that it answers in
the agreed shape.

Practical guidance to leave the audience with: start the cost/latency/privacy/capability
conversation with "what's the smallest model that reliably returns our JSON shape," not
"which model is smartest" — capability requirements here are narrow and specific (score a
notable against three standing checks, reply in strict JSON), not general reasoning.
