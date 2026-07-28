# Takeaway 1: Choosing the Right LLM for SecOps

Four axes that actually matter — not "which model tops the leaderboard":

- **Cost** — priced per notable/investigation, not per demo. A SOC generates volume; the
  biggest frontier model on every single notable gets expensive fast.
- **Latency** — the call happens synchronously, in-line, inside the alert action itself. The
  correlation search's adaptive response doesn't finish until the model replies, so round-trip
  time is part of the alert pipeline's own latency budget, not a footnote.
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

Concretely, the agentic AI actor in this build is called directly: `notable_to_perplexity_json.py`
makes a synchronous request to the Perplexity Chat Completions API, passing the JSON payload
plus the standing `perplexity_ask` checks you'll see in Phase 1, and the model is named by a
plain config value, `param.perplexity_model`. Emphasise this is a *contract*, not a lock-in:
because the interface between Splunk and the AI is a plain JSON payload in, and a JSON Schema
`response_format` out (see Phase 2), the model behind that call is swappable by editing one
config field — the integration doesn't care which model answers, only that it can honour a
structured schema. Worth naming explicitly: this is simpler than the first version of this
build, which invoked the AI in-thread via a Slack mention and had to parse whatever came back
as a reply — swapping models there meant hoping the new model kept following the same
free-text convention. That's gone now; the schema does the enforcing, not the model's good
behaviour.

Practical guidance to leave the audience with: start the cost/latency/privacy/capability
conversation with "what's the smallest model that reliably returns our JSON shape," not
"which model is smartest" — capability requirements here are narrow and specific (score a
notable against three standing checks, reply in strict JSON), not general reasoning.
