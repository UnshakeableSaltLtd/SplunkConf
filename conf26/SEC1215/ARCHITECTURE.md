# SEC1215 Talk Narrative: Closing the Agentic Loop

This is the architecture arc for the session — how a Splunk Enterprise Security
notable becomes an agentic AI decision, and how that decision gets back into
Splunk in a form the platform actually understands, with no analyst copy/paste
in the loop. It builds directly on [`TA_ResponseActions`](../TA_ResponseActions/README.md)
and is the "what to build yourself vs. what Splunk gives you for free" spine
referenced in Takeaway 2.

The talk originally scoped this as a three-phase loop with an asynchronous
Slack → HEC bridge as phases 2/3. That bridge was built, shipped (v1.3.1–1.3.2),
and then deliberately retired in favor of a much simpler synchronous design
(v1.3.3) — the loop below reflects what's actually shipping today, with the
retired bridge folded into Takeaway 3 as a concrete, worked pitfall.

## The loop at a glance

**Shipped as of v1.3.3.**

```
ES Correlation Search
   └─ triggers Notable/Risk event
        └─ Adaptive Response Action: TA_ResponseActions (SHIPPED — v1.3.3)
             ├─ builds the full CIM/risk notable as JSON
             ├─ answers a "perplexity_ask" block of standing checks
             │    (repo check / user check / source IP check) via a
             │    SYNCHRONOUS call to the Perplexity API, in-line,
             │    before anything is sent anywhere
             ├─ merges the answer back in as "perplexity_response"
             └─ delivers the merged payload to:
                  ├─ Slack (file_upload or webhook) — for visual audit
                  ├─ the originating notable's comment trail
                  └─ the notable_slack_enrichment KV store record
                       (surfaced via a custom Incident Review drilldown)
```

One process, one request/response, no polling, no second index, no bridge.

## Phase 1: ES alert-action output feeds the agentic AI

**Shipped.**

`TA_ResponseActions` (Adaptive Response Action `notable_to_slack_json`) takes
the triggering notable/finding, keeps every CIM/risk/notable field, strips
noise fields, and delivers it to Slack as a complete JSON payload — no
size-limited summary, no lossy formatting. As of v1.3.0 it also ships a
`perplexity_ask` block in `param.additional_fields` by default: three standing
checks (is `$result.repo$` a repo we commonly see for this finding type, is
`$result.user$` expected/authorised, is `$result.src$` low-threat) that travel
with every notable so the agentic AI always has a consistent, structured
question to answer — not just a raw event dump.

This is the "what Splunk gives you for free vs. what you build" line in
practice: Splunk gives you the Adaptive Response framework, `cim_actions.py`'s
`ModularAction` for native panel reporting, and the CIM field set for free —
the delivery shaping and the standing-question payload are what you build.

## Phase 2: the AI answers, in-line, before delivery

**Shipped as of v1.3.3.**

The gap the talk calls out: getting an AI's answer is easy; getting it back
into Splunk in a *usable* shape, quickly, is the actual engineering problem.
The first attempt at solving this (see "Lesson: the Slack → HEC bridge"
below) answered it asynchronously — post to Slack, wait for a reply, poll for
it, parse it. v1.3.3 answers it synchronously instead: right after building
the notable's JSON payload and before anything is sent anywhere,
`notable_to_slack_json.py` calls the
[Perplexity Chat Completions API](https://docs.perplexity.ai/) directly,
passing the notable's context plus the `perplexity_ask` questions, with a
JSON Schema `response_format` built dynamically from the ask keys (plus an
`overall` risk read-out field). The parsed answer is merged straight into the
same `additional_fields` object as `perplexity_response` — sitting right next
to the question it answers, before the payload is serialized once for every
downstream consumer.

This is a strictly simpler shape than "AI verdict → separate CIM Risk event":
no risk index write, no polling interval, no thread-ts correlation. The
trade-off, made explicitly for this talk: it does **not** attempt to also
fold the AI's answer into Splunk's Risk-Based Alerting / `All_Risk` data
model as a first-class risk modifier — see "What this doesn't do" below and
the retired bridge's write-up for what that would have taken.

## Phase 3: one payload, three existing write-back paths

**Shipped.**

Once `perplexity_response` is merged in, the *same* envelope flows into every
write-back path `TA_ResponseActions` already had — no new API surface at all:

1. **Slack** (`param.delivery_method` — unchanged from v1.0.0) — still useful
   for visually auditing exactly what was asked and what came back, per
   notable, as it happens.
2. **The Notable Event API → the originating notable**
   (`param.write_back_comment`, default on) — a `POST /services/notable_update`
   comment summarizing what was sent, now including the Perplexity answer, so
   it's visible directly in that notable's own Activity timeline in Incident
   Review ([API reference](https://help.splunk.com/en/splunk-enterprise-security-7/api-reference/7.3/notable-event-endpoints/notable-event-api-reference)).
3. **The `notable_slack_enrichment` KV store + custom drilldown**
   (`param.write_back_kvstore`, default on) — the full `additional_fields`
   JSON (ask + response) as a structured record, reached from the notable's
   Adaptive Responses panel via `param._cam`'s `drilldown_uri` — see
   [`TA_ResponseActions`'s README](../TA_ResponseActions/README.md#closing-the-loop-getting-the-result-back-to-the-analyst).

Nothing here required a new index, a new credential realm beyond the
Perplexity API key, or a background process — it's the same three consumers
v1.2.0 already fed, just now also fed `perplexity_response`.

### What this doesn't do: an honest scope note

The original three-phase narrative described mapping the AI's verdict onto
CIM Risk data model fields (`risk_object`, `risk_object_type`, `risk_score`,
`risk_message`) and pushing it into the risk index via HEC, so it would feed
Risk-Based Alerting and the `All_Risk` data model
([Risk Analysis framework](https://dev.splunk.com/enterprise/docs/devtools/enterprisesecurity/riskanalysisframework)).
v1.3.3 deliberately does not do this — `perplexity_response` lands as an
enrichment on the *existing* notable, not as a new risk modifier contributing
to some other object's aggregate score. That's a real capability gap versus
the original pitch, kept in the narrative on purpose: it's the honest answer
to "then why not keep the bridge?" — because for what this talk demos (one
notable, one analyst, one answer), the added correctness of a same-object
risk modifier didn't justify the operational cost of a second component. A
team that genuinely needs the AI's verdict to move the needle on Risk-Based
Alerting would still want something like the bridge's HEC write — just built
with a request/response pattern from the start, not a poll loop bolted on
after.

## Lesson: the Slack to HEC bridge, retired

**Shipped as v1.3.1–v1.3.2. Retired in v1.3.3.**

`bin/slack_hec_bridge.py` was a classic Splunk scripted input
(`default/inputs.conf`) that closed the loop asynchronously: it polled the
`notable_slack_enrichment` KV store every 60 seconds for records
`TA_ResponseActions` had flagged `awaiting_ai_response=1`, read the Slack
thread with `conversations.replies`, and parsed the reply against a strict
JSON reply shape (`alert_actions.conf`'s `perplexity_ask.reply_format`) into
`risk_object`/`risk_object_type`/`risk_score`/`risk_message`, then wrote that
to the risk index via HEC and back onto the notable.

It worked end to end. It was retired anyway, because it surfaced pitfalls
worth calling out explicitly for anyone tempted to build the same shape —
this is Takeaway 3 in concrete, worked form:

1. **The Notable Event API can't carry new structured fields.**
   `/services/notable_update` only accepts `comment`/`status`/`urgency`/
   `newOwner`/`disposition`
   ([API reference](https://help.splunk.com/en/splunk-enterprise-security-7/api-reference/7.3/notable-event-endpoints/notable-event-api-reference)) —
   there is no REST call that attaches a new indexed field to an existing
   notable after the fact. This constraint is unchanged by retiring the
   bridge — v1.3.3 still relies on the KV-store + custom-drilldown pattern
   for structured fields, same as v1.2.0.
2. **Webhook delivery silently couldn't be bridged.** Slack's Incoming
   Webhooks carry no bot token and no `conversations.read` scope, so there
   was no API call that read a reply back out of a webhook-posted message.
   Nothing errored to tell you that — it only surfaced if you noticed
   `awaiting_ai_response` never got set to `1`. A synchronous, in-process
   call doesn't have this failure mode at all: there's no delivery-method
   dependence, because nothing is read back out of Slack in the first place.
3. **LLM reply-format drift.** Free-text answers to the original
   `perplexity_ask` checks were unparseable in Slack-reply form — the fix at
   the time was to pin a required JSON shape into the *prompt itself*
   (`perplexity_ask.reply_format`) and have the bridge log-and-skip on
   anything that still didn't parse. v1.3.3 solves the same problem more
   directly, at the source: the Perplexity API's own `response_format`
   (JSON Schema) constrains the model's output structurally, so there's no
   prose to parse and no reply-format instruction competing for space with
   the actual ask/response keys.
4. **A second moving part with its own operational surface.** The bridge
   needed its own credential realm (`hec_risk_bridge`), its own log file, its
   own polling cadence, and — because it was a classic scripted input rather
   than a full `splunklib.modularinput` scheme — no auto-generated Splunk Web
   settings page for its custom keys (`risk_index`, `hec_url`, the credential
   realms); they had to be self-parsed out of `inputs.conf` via `configparser`
   and edited by hand in `local/inputs.conf`. None of that exists anymore in
   v1.3.3: one credential realm (the Perplexity API key), one log file, one
   request per notable, made by the same process that was already running.
5. **Latency and a race window.** The loop only closed once Slack, a human
   (or nothing) triggered a reply, and the next poll interval ticked over —
   the "zero human intervention" framing only held if nobody read the thread
   first. A synchronous call closes before the Slack message is even sent.

The full retired script, its `inputs.conf` registration, and this same
write-up are archived at [`lessons/`](./lessons/README.md) as a "before"
artifact for the talk — not because the idea was wrong, but because building
it first is what made the simpler v1.3.3 design obviously correct in
hindsight. That arc — try the more powerful/complex thing, learn exactly what
it costs, then replace it with the smallest thing that solves the actual
demo's problem — is itself Takeaway 3's central point.

What made the turnaround fast wasn't caution, it was the opposite: trusting
the platforms enough to remove the defensive plumbing built around them.
Item 3 above (reply-format drift) was worked around by asking the model
nicely and hoping; the fix wasn't a better prompt, it was noticing Perplexity
already has a `response_format`/JSON Schema feature that constrains output
structurally — trust the API to do that instead of parsing free text
yourself. Items 2 and 5 were worked around with a second scripted process
polling a chat app for a reply and racing the clock to read it back; the fix
was noticing Adaptive Response actions already run synchronously with full
context, so Splunk didn't need a hand-off at all — trust the platform's own
execution model instead of building around it. Once both of those were trusted rather
than defended against, the bridge's entire reason for existing disappeared,
and replacing it took hours, not another sprint.

## How this maps back to the session's takeaways

- **Takeaway 1** (choosing the right LLM) is why Phase 1's payload is a full,
  denylist-scrubbed JSON export rather than a squeezed summary — a smaller/
  cheaper model still gets the complete picture to reason over, and a
  structured `response_format` call (Phase 2) means the model choice doesn't
  need to include "reliably free-texts valid JSON in a Slack reply" as a
  selection criterion at all.
- **Takeaway 2** (repeatable pattern, build-vs-free) is this whole document:
  Adaptive Response + CIM + the Notable Event API + KV store are Splunk's own
  primitives; the JSON shaping, the standing checks, and the synchronous
  Perplexity call are the glue you write once and reuse per correlation
  search.
- **Takeaway 3** (avoiding pitfalls) is the "Lesson" section above in full —
  a real design that shipped, worked, and was still worth replacing once its
  operational cost became clear. It's also the fast-reaction story: once the
  pitfalls were understood, trusting the platforms' own features over
  hand-built workarounds turned a multi-component rebuild into a same-day
  patch release.

## Status

| Phase | Component | Status |
|---|---|---|
| 1 | `TA_ResponseActions` — notable → Slack JSON + `perplexity_ask` | Shipped (v1.3.0+) |
| 2 | Synchronous Perplexity call → `perplexity_response` | Shipped (v1.3.3) |
| 3 | Slack + notable comment + KV store write-back (same payload) | Shipped (v1.3.3 carries `perplexity_response` through paths built in v1.1.0/v1.2.0) |
| — | Slack → HEC bridge (async verdict → CIM Risk fields via HEC) | Retired (shipped v1.3.1–v1.3.2, removed in v1.3.3) — archived at [`lessons/`](./lessons/README.md) |
