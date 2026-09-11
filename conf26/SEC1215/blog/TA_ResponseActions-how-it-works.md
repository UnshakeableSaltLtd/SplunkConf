# Inside TA_ResponseActions: How the SEC1215 Agentic Response Pipeline Actually Works

**Companion post to:** [SEC1215 — From Zero to Agentic: Building Your First AI-Driven Threat Investigation in Splunk Enterprise Security](../README.md)
**App source:** [`TA_ResponseActions`](../../TA_ResponseActions/README.md)
**Author:** David Pollard, Unshakeable Salt Ltd

## Quick introduction

This post is a companion to the SEC1215 talk at Splunk .conf26, *From Zero to Agentic: Building Your First AI-Driven Threat Investigation in Splunk Enterprise Security*. The talk walks through the reasoning, the trade-offs, and the pitfalls of building a bespoke agentic use case inside Splunk Enterprise Security. This post picks up where the talk's live demo leaves off and goes deeper into the thing that actually makes it work: **`TA_ResponseActions`**, the custom Splunk app that sits at the centre of the whole pipeline.

Everything below is drawn directly from the app's own [`README.md`](../../TA_ResponseActions/README.md) and [`process.md`](../../TA_ResponseActions/process.md) in this repository, so if you want to go straight to source rather than prose, those two files are the definitive reference.

## Why TA_ResponseActions exists

Splunk Enterprise Security already knows how to raise a notable when a correlation search fires. What it doesn't do out of the box is *ask an AI model anything about that notable*, get a structured answer back, and act on that answer — synchronously, inside the same alert cycle, without a bridge, a queue, or a second process polling for results later.

`TA_ResponseActions` was built to close exactly that gap, and to do it as two clean, independently configurable Adaptive Response Actions rather than one monolithic script:

- **`notable_to_perplexity_json`** — *"Send Notable to Perplexity API (Agentic Response)"*. This is the agentic action. It answers a standing set of questions about the notable synchronously via the Perplexity API, runs two deterministic verification checks first, and writes the outcome straight back onto the notable — comment, urgency, and a structured record. It has no Slack objects at all.
- **`notable_to_slack_json`** — *"Send Notable to Slack (ES Findings)"*. This is the human-notification action. It posts the same finding to a Slack channel as a complete JSON payload, using the identical envelope shape built for the Perplexity call — but it never calls Perplexity and never answers anything. It exists purely so analysts have a visual audit trail of exactly what was asked, independent of how (or whether) it was answered.

Both actions can be enabled, disabled, or have their credentials rotated completely independently of one another, and both share a common module, `bin/ta_common.py`, for payload construction, credential vault lookups, deterministic checks, and notable write-back — so the two stay in lockstep on payload shape without being coupled to each other's delivery path.

The design goal, in short: give a correlation search a genuinely agentic response option that behaves like every other native Adaptive Response Action — same Incident Review panel, same audit trail, same credential vault — rather than a bolt-on integration that only a few people on the team understand.

## How it works

### The two verified checks, before the model ever sees anything

Before `notable_to_perplexity_json` calls Perplexity at all, it runs two **deterministic, verified** checks against the raw event fields:

- A live **GitHub repository-existence** check (`GET /repos/{owner}/{repo}`) against the field named in `param.github_repo_field`.
- A live **AbuseIPDB reputation** check against the field named in `param.source_ip_field`.

These are genuine facts, not model inference. Their results are injected into the Perplexity prompt as ground truth the model is explicitly instructed not to soften or contradict — and, critically, they can force a hard escalation of the notable's urgency entirely independently of whatever the model's own narrative concludes.

### The one synchronous call to Perplexity

Once the deterministic checks have run, the action builds an envelope containing the notable's context fields and a `perplexity_ask` block — a set of natural-language questions with `$result.<field>$` tokens already substituted with real values from the row (by default: is the repository one commonly seen for this kind of finding, is the user expected/authorised, is the source IP low threat).

It then makes exactly **one** synchronous call to Perplexity's [Agent API](https://docs.perplexity.ai/docs/agent-api/quickstart) (`POST https://api.perplexity.ai/v1/agent`), carrying:

- `instructions` — a standing system prompt telling the model it is a SOC triage assistant and that any deterministic check result supplied is verified ground truth.
- `input_text` — the notable's context fields, the deterministic check results, and the `perplexity_ask` questions themselves, as JSON.
- `response_format` — a JSON schema built dynamically from the `perplexity_ask` keys, plus two fixed fields: `overall` (a short free-text risk read-out) and `concern` (a boolean escalation signal set independently of the model's own prose).

The response is parsed and merged straight back into the same envelope as `perplexity_response`, sitting alongside the `perplexity_ask` it answers.

### Finding the right notable to write back to

This is the trickiest mechanical problem the app solves. `action.notable` (Splunk's own built-in response action) and `notable_to_perplexity_json` both fire from the same correlation search job, as siblings — not as a hand-off. That means the modular action's own invocation payload never carries the `event_id` of the notable that `action.notable` just created.

To close that gap, the script looks its own notable back up with a oneshot search against `index=notable`, matching on `orig_sid`/`orig_rid` — the fields every ES-created notable carries back to the correlation search job that spawned it — reading the `source_event_id` field off the result, with retries built in because the two sibling actions aren't guaranteed to complete in the same instant.

### Writing the result back, three ways

Once the correct `event_id` is resolved, the result lands back on the notable through three separate mechanisms, so an analyst sees it without ever leaving Incident Review or Mission Control:

1. **Adaptive Responses panel** — both actions are built on `cim_actions.py`'s `ModularAction` class and report their own success/failure status natively.
2. **Notable comment and urgency** — a single `POST /services/notable_update` call writes a human-readable comment and, where applicable, a new urgency value. Urgency follows a fixed priority order: a confirmed deterministic finding always wins and force-escalates to `critical`; failing that, an overnight-hours window is considered; failing that, Perplexity's own `concern` flag; otherwise urgency is left unchanged.
3. **KV store enrichment record** — the entire envelope is written to the `notable_agentic_enrichment` KV store collection, keyed by the invocation's own `sid`/`rid`, giving analysts a genuinely structured, queryable record rather than just comment text. A shared drilldown dashboard renders this record directly from the notable's own Adaptive Responses panel.

### And the Slack side stays deliberately separate

`notable_to_slack_json` builds the identical `perplexity_ask` envelope and delivers it to a Slack channel — either as a bot-token file upload (recommended, no size limit) or an incoming webhook (simpler, but subject to Slack's block size limits) — but it never calls Perplexity itself. That keeps the human-notification path entirely free of any dependency on the Perplexity credential, and gives analysts a way to audit exactly what was asked, separately from how or whether it was answered.

The full step-by-step version of everything above — including the exact search used to resolve `source_event_id` and the complete pipeline diagram — is documented in [`process.md`](../../TA_ResponseActions/process.md).

## Thank you

Thank you to everyone who attended the SEC1215 session at Splunk .conf26 — the questions and conversations afterward are exactly what pushed several of the design decisions described here and in [`ARCHITECTURE.md`](../ARCHITECTURE.md), including the decision to retire the original Slack → HEC bridge design documented in [`lessons/`](../lessons/README.md).

The session recording will be linked here once .conf26 publishes it:

**Session recording:** _(placeholder — link to be added once .conf26 publishes the SEC1215 recording)_
