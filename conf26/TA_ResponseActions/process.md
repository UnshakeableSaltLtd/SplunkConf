# How the agentic response pipeline works

This document walks through what actually happens, end to end, when a correlation search fires and
the **Send Notable to Perplexity API (Agentic Response)** action (`notable_to_perplexity_json`) is
attached to it — from detection through to the notable being updated in Mission Control. See
[`README.md`](README.md) for installation and credential setup; this document is about the
mechanics of the flow itself.

## Stage 1 — Detection

A correlation search runs on its own schedule (in the worked example used throughout this
document, every minute) and evaluates events against its SPL. When a row matches, that row becomes
a **result** of the search job — identified by the job's own `sid` (search ID) and the row's `rid`
(result ID within that job).

Nothing agentic has happened yet at this point: this is a normal Splunk Enterprise Security
correlation search doing normal correlation. The fields it selects (via `table`, `eval`, etc.) are
exactly and only the fields carried forward to the next stage — Splunk does not silently attach
extra metadata to the row.

## Stage 2 — Notable creation and the alert action firing together

A single correlation search job can have **multiple response actions** attached to it, and they
all fire from the same job, for the same matching result:

- **`action.notable`** — Splunk Enterprise Security's own built-in response action — creates the
  actual notable event in `index=notable`. This is what makes the finding show up in Incident
  Review / Mission Control at all.
- **`notable_to_perplexity_json`** — this app's custom modular alert action — is invoked
  independently, in the same job, with the job's `sid` and the matching row's fields passed to it
  on stdin as JSON.

These two actions are not sequential steps in a hand-off — they're siblings, both triggered by the
same search firing. That matters for Stage 5 below: the modular action's own invocation payload
does **not** contain the `event_id` of the notable `action.notable` just created, because
`action.notable` doesn't hand its result back to the other response actions in the same cycle.
Whatever comment/urgency write-back happens later has to find that notable again on its own.

## Stage 3 — What gets sent to Perplexity

Once invoked, `notable_to_perplexity_json.py` reads the JSON payload Splunk wrote to its stdin
(`sid`, `search_name`, the matching result row's fields, and the action's own configuration
parameters). It then:

1. Builds an **envelope** (`ta_common.build_payload()`) containing the notable's context fields
   (with any denylisted fields stripped) and the `perplexity_ask` block from
   `param.additional_fields` — a set of natural-language questions with `$result.<field>$` tokens
   already substituted with real values from the row (e.g. `repo`, `user`, `src`).
2. Runs the two **deterministic checks** (`ta_common.run_deterministic_checks()`) against the raw
   row, before calling Perplexity at all:
   - A live **GitHub repository-existence** check (`GET /repos/{owner}/{repo}` using the
     `perplexity_notable_action_github` credential) against the field named in
     `param.github_repo_field`.
   - A live **AbuseIPDB reputation** check against the field named in `param.source_ip_field`,
     using the `perplexity_notable_action_abuseipdb` credential.
   Both are genuinely verified facts, not model inference — a nonexistent repository or an IP with
   a high abuse confidence score is treated as ground truth for the rest of the pipeline.
3. Sends **one synchronous call** to Perplexity's Agent API:

   ```
   POST https://api.perplexity.ai/v1/agent
   ```

   The request carries:
   - `instructions` — a standing system prompt telling the model it's a SOC triage assistant, to
     answer each `perplexity_ask` question concisely, and — critically — that any deterministic
     check result supplied is verified ground truth that must not be softened or contradicted.
   - `input_text` — the notable's context fields, the deterministic check results (if any), and
     the `perplexity_ask` questions themselves, all as JSON.
   - `response_format` — a JSON schema built dynamically from the `perplexity_ask` keys, plus two
     fixed fields: `overall` (a short free-text risk read-out) and `concern` (a boolean escalation
     signal the model sets independently of its own prose, so escalation logic downstream doesn't
     have to parse free text).

## Stage 4 — How the response comes back, and where it's stored in flight

Perplexity's Agent API response is parsed by `ta_common.extract_agent_output_text()`, which reads
the model's structured JSON out of the API's `output` array (stripping any `<think>...</think>`
block a reasoning-style model might prepend, even with `response_format` set). The resulting object
— one answer per `perplexity_ask` key, plus `overall` and `concern` — is merged straight into the
same in-memory envelope as `additional_fields["perplexity_response"]`, sitting alongside the
original `perplexity_ask` it answers.

At this point the enriched envelope exists only in the running script's memory. Two things happen
with it next, independently of each other:

- If `param.write_back_comment` or an urgency change is due, a **human-readable comment** is built
  (`ta_common.format_perplexity_comment()`) — pairing each question with its answer as plain text,
  not a raw JSON blob, since Incident Review/Mission Control renders notable comments as plain
  text.
- If `param.write_back_kvstore` is on, the **entire envelope** (as JSON) is written to a KV store
  record — this is the durable, structured copy of the exchange, independent of whatever else
  happens to the notable itself.

Both writes are described in Stages 5 and 6.

## Stage 5 — Pinning the response back to the right notable

This is the step that makes the write-back land on the *correct* notable, not just *some* notable,
and it exists because of the sibling-firing behaviour described in Stage 2.

The modular action's own row never carries an `event_id` on an automatic (correlation-search-
triggered) firing — that field only appears when a human manually invokes a response action from
Incident Review's own UI. What the script does have, unconditionally, is its own job's `sid` (and,
usually, the row's `rid`).

Every notable that `action.notable` creates carries `orig_sid` and `orig_rid` fields pointing back
to the `sid`/`rid` of the correlation search job that spawned it. So the script looks its own
notable back up by running a oneshot search (`ta_common.resolve_notable_event_id()`, via
`POST /services/search/jobs/export`) against:

```
index=notable orig_sid="<this script's own sid>" orig_rid="<this row's rid>"
| head 1 | fields source_event_id
```

with a fallback to an `orig_sid`-only match if no `orig_rid` match is found — but only when that
fallback returns a single, unambiguous result, since a `sid`-only match could otherwise return the
wrong notable if the same job produced more than one.

Two details matter here:

- The field actually read off the raw notable event is **`source_event_id`**, not `event_id` —
  `event_id` is a name that only exists when Incident Review's own UI hands a row to a manually
  invoked response action; the raw indexed field on the notable itself is `source_event_id`.
- The lookup **retries** a few times with a short delay, because `action.notable`'s own write to
  `index=notable` is not guaranteed to be searchable in the exact same instant this script runs —
  the two actions fire concurrently within the same cycle, not in a guaranteed order, so a
  first-attempt miss is expected and handled, not an error.

Once resolved, this `source_event_id` is exactly the `event_id` needed for Stage 6's write-back
call — it's what makes the comment and urgency update land on the same notable the correlation
search just created, rather than being silently dropped or attached to nothing.

## Stage 6 — Updating urgency, status, and the comment

With a resolved `event_id` in hand, `ta_common.update_notable()` makes a single
`POST /services/notable_update` call:

```
ruleUIDs=<event_id>
comment=<human-readable ask/response narrative, if write_back_comment is on>
urgency=<new urgency, if a change is due>
```

The urgency value, when set, follows a fixed priority order (`ta_common.compute_notable_urgency()`
plus the hard-escalation override applied by the calling script):

1. **Hard escalation** — if either deterministic check came back with a confirmed problem (e.g. a
   nonexistent repository, an AbuseIPDB score over the configured threshold), the notable is force-
   escalated to `param.hard_escalation_urgency` (default `critical`), overriding everything below.
   This is deliberately independent of the model's own narrative — a verified fact can't be
   talked out of firing by anything Perplexity says.
2. **Overnight window** — if the event's own `_time` falls inside the configured overnight window
   (`param.overnight_start`/`param.overnight_end`), urgency is raised, on the reasoning that the
   same finding warrants closer attention outside normal working hours.
3. **Perplexity's own `concern` flag** — if the model set `concern: true` in its structured
   response, urgency is raised to `param.concern_urgency` (default `high`).
4. **No change** — if none of the above apply, urgency is left as `action.notable` originally set
   it.

This same call is also where the KV store record and the notable's own comment/urgency
diverge in what they're for: the KV store record (Stage 4/5) is the durable, structured audit
trail — everything sent and received, queryable by `sid`/`rid` via the drilldown dashboard. The
notable comment and urgency (this stage) are what an analyst sees immediately, without leaving
Incident Review or Mission Control, alongside the rest of the finding.

## Summary of the full path

```
Correlation search fires (Stage 1)
        |
        v
action.notable creates the notable   \
notable_to_perplexity_json invoked    >  same job, same cycle (Stage 2)
        |
        v
Envelope built + deterministic GitHub/AbuseIPDB checks run (Stage 3)
        |
        v
POST https://api.perplexity.ai/v1/agent  (Stage 3)
        |
        v
perplexity_response parsed and merged into the envelope (Stage 4)
        |
        +--> KV store record written (notable_agentic_enrichment)  [durable structured copy]
        |
        v
event_id resolved via orig_sid/orig_rid lookup against index=notable (Stage 5)
        |
        v
POST /services/notable_update: comment + urgency, same notable (Stage 6)
        |
        v
Analyst sees the result in Incident Review / Mission Control,
with the structured record one click away via the drilldown dashboard
```
