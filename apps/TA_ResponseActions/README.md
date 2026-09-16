# TA_ResponseActions

**App Name:** Notable to Perplexity / Slack
**Author:** David Pollard, Unshakeable Salt Ltd
**Associated Session:** [SEC1215 — From Zero to Agentic](../../conf26/SEC1215/README.md)

## Overview

Two independent, custom Splunk Enterprise Security **Adaptive Response Actions** that can be
enabled, disabled, or have their credentials rotated completely independently of one another:

- **`notable_to_perplexity_json`** — *"Send Notable to Perplexity API (Agentic Response)"*. The
  agentic response action: answers the notable's `perplexity_ask` block synchronously via the
  Perplexity API, runs deterministic GitHub/AbuseIPDB checks, and writes the result back onto the
  same notable (comment, urgency, and a structured KV store record). **No Slack objects at all.**
- **`notable_to_slack_json`** — *"Send Notable to Slack (ES Findings)"*. The human-notification
  action: posts the triggering notable/finding to a Slack channel as a complete JSON payload — the
  same envelope shape built for the Perplexity call, but never answered (this action never calls
  Perplexity).

Both share `bin/ta_common.py` for payload construction, credential vault lookups, deterministic
checks, and write-back-to-notable helpers, so the two stay in lockstep on payload shape while
remaining independently configurable.

`notable_to_slack_json`'s two delivery modes:

- **file_upload** (recommended) — uses a Slack bot token via `files.getUploadURLExternal` /
  `files.completeUploadExternal` to deliver the entire JSON with no size limit.
- **webhook** — quick to set up via an Incoming Webhook, but truncates large payloads to fit
  Slack's block limits.

## Requirements

- Splunk Enterprise Security 7.x+ on Splunk Enterprise 9.x/10.x
- Python 3.x (bundled with Splunk)
- `Splunk_SA_CIM` (Common Information Model Add-on) — ships by default with every ES install.
  Required for the native Adaptive Response panel status reporting (both actions degrade
  gracefully and still run their normal flow if it's missing)
- A Slack app with a bot token (only needed for `notable_to_slack_json`)
- A Perplexity API key (only needed for `notable_to_perplexity_json`'s synchronous
  `perplexity_ask`/`perplexity_response` call)
- A GitHub personal access token and an AbuseIPDB API key (only needed if you keep the two
  optional deterministic checks enabled — see below)

## How the agentic flow works

`param.additional_fields` on `notable_to_perplexity_json` ships a standing `perplexity_ask` block
of natural-language questions to ask about the notable (by default: is the repository one commonly
seen for this kind of finding, is the user expected/authorized, is the source IP low threat).
Before calling Perplexity, the action also runs two **deterministic, verified** checks against the
raw event fields — a live GitHub repository-existence lookup and a live AbuseIPDB reputation
lookup — and injects their results into the prompt as ground truth the model must not contradict.
Perplexity's [Agent API](https://docs.perplexity.ai/docs/agent-api/quickstart)
(`POST https://api.perplexity.ai/v1/agent`) is then called once, synchronously, with a JSON-schema
`response_format` built from the ask keys plus `overall` (short risk read-out) and `concern`
(boolean escalation signal). The result is merged back into `additional_fields` as
`perplexity_response`, then:

1. Written back to the notable's own **comment** (`param.write_back_comment`).
2. Used, together with the deterministic checks, to optionally set the notable's **urgency**
   (`param.urgency_override_enabled`) — a confirmed deterministic finding (e.g. a nonexistent repo,
   a high AbuseIPDB score) always overrides everything else; otherwise an overnight-hours window
   and Perplexity's own `concern` flag are considered, in that priority order.
3. Written to a structured **KV store enrichment record** (`param.write_back_kvstore`), so a
   drilldown dashboard shows the ask and the answer side by side.

`notable_to_slack_json` builds the **same** `perplexity_ask` envelope and posts it to Slack, but
**never answers it** — no Perplexity call is made from that action at all. This keeps the
human-notification channel free of any dependency on the Perplexity credential, and gives analysts
a way to visually audit exactly what was asked, separately from whether/how it was answered.

See [`process.md`](../../conf26/SEC1215/process.md) for the full step-by-step pipeline, from correlation search firing
through to the notable being updated in Mission Control.

## Closing the loop: getting the result back to the analyst

After processing, **both** actions write back to the **same** notable so the analyst sees the
result alongside the rest of the event, without leaving Incident Review:

1. **Adaptive Responses panel** — each action is built on `cim_actions.py`'s `ModularAction` class
   and calls `self.message(..., status='success'/'failure')`. This populates the notable's native
   "Adaptive Responses" section / "View Adaptive Response Invocations" audit trail.
2. **Notable comment and urgency** — each action calls `POST /services/notable_update` with
   `ruleUIDs=<event_id>` and, depending on configuration, a `comment` and/or an `urgency` value.
   This is a permanent entry in that notable's own Activity timeline. Automatic
   (correlation-search-triggered) notables don't carry an `event_id` on their result row — the
   action resolves it itself by looking its own notable back up via `orig_sid`/`orig_rid` (see
   `process.md` for the full mechanism).
3. **KV store enrichment + custom drilldown** (`param.write_back_kvstore`) — gives analysts
   genuinely structured fields, not just comment text: delivery status, `perplexity_api` or Slack
   channel, the exact `additional_fields` sent, and error detail on failure. Both actions write to
   the same `notable_agentic_enrichment` collection, so a single dashboard shows both actions'
   records for a given `sid`/`rid`.

### KV store enrichment / custom drilldown

`/services/notable_update` only supports `comment`/`status`/`urgency`/`newOwner`/`disposition` —
no arbitrary new fields. To surface real structured data next to the notable, each action also:

1. Writes a record to the **`notable_agentic_enrichment`** KV store collection
   (`default/collections.conf`), keyed by **this invocation's `sid`/`rid`** — not `event_id`.
   That's because Incident Review's custom `drilldown_uri` (in `param._cam`) only supports the
   tokens `$sid$`, `$rid$`, `$time$`, `$earliest$`, `$latest$`, `$action_name$` — `event_id` isn't
   one of them. `event_id`/`orig_sid`/`orig_rid` are still stored on the record for ad hoc
   lookups. `notable_to_perplexity_json`'s records set `delivery_method="perplexity_api"` and
   leave `slack_channel`/`slack_permalink` blank; `notable_to_slack_json`'s records set
   `delivery_method` to `file_upload`/`webhook` and populate those fields.
2. Declares `param._cam = {"supports_adhoc": true, "drilldown_uri":
   "notable_agentic_enrichment_drilldown?form.sid=$sid$&form.rid=$rid$", ...}` in
   `alert_actions.conf`. `supports_adhoc` is also what makes each action appear under Incident
   Review's **Run Adaptive Response Actions** ad hoc menu at all.
3. Both share a Simple XML view, `default/data/ui/views/notable_agentic_enrichment_drilldown.xml`,
   that takes `sid`/`rid` from the drilldown URL and runs
   `| inputlookup notable_agentic_enrichment_lookup where sid="$sid$" AND rid="$rid$"` (lookup
   defined in `default/transforms.conf`) to render the record(s) as a table — so if both actions
   fired for the same notable, both rows show up together.

From a notable's Adaptive Responses panel, click through either action's entry and you land on
that dashboard with the structured record already loaded — no re-typing tokens.

Adjust `metadata/default.meta`'s `[collections/notable_agentic_enrichment]` write ACL if the role
that invokes either action (correlation search owner, or an analyst running it ad hoc) isn't
`admin`.

## Installation

1. Copy this folder to `$SPLUNK_HOME/etc/apps/TA_ResponseActions/`.
2. Set ownership and permissions to match Splunk's own service account (typically `splunk:splunk`
   on a standard Linux install — adjust to whatever user/group Splunk actually runs as on your
   instance):

   ```shell
   chown -R splunk:splunk $SPLUNK_HOME/etc/apps/TA_ResponseActions
   find $SPLUNK_HOME/etc/apps/TA_ResponseActions -type d -exec chmod 755 {} \;
   find $SPLUNK_HOME/etc/apps/TA_ResponseActions -type f -exec chmod 644 {} \;
   chmod 755 $SPLUNK_HOME/etc/apps/TA_ResponseActions/bin/*.py
   ```

3. Restart Splunk.
4. In Splunk Enterprise Security, ensure this app is covered by **Configure > General > App
   Import** so ES recognizes it as an Adaptive Response provider.
5. Create the credentials described below.
6. On a correlation search, **Add New Response Action** and add either or both:
   - **Send Notable to Perplexity API (Agentic Response)** — configure `perplexity_enabled`,
     `perplexity_model`/`perplexity_preset`, `additional_fields` (the `perplexity_ask` block), and
     the deterministic-check toggles, then save.
   - **Send Notable to Slack (ES Findings)** — configure `delivery_method`, `slack_channel`,
     `additional_fields`, and save.
7. Test via Incident Review → Run Adaptive Response Actions on a notable, or trigger the
   correlation search directly. Use `param.test_connectivity=1` on either action first (see
   "Testing connectivity / credentials" below) to confirm credentials are valid before relying on
   a live notable.

## Credential setup: tokens required and their scopes

Every credential is stored in Splunk's own encrypted credential vault (`storage/passwords`), never
in a `.conf` file. Four realms are used, one per external service. Create the token/key at the
provider first, then load it into Splunk using the command-line steps in the next section.

| Realm | Used by | What to create | Fine-grained scope required |
| --- | --- | --- | --- |
| `slack_notable_action` | `notable_to_slack_json` | A Slack app + bot token (`xoxb-...`) | Bot token scopes `files:write` and `chat:write` only. No admin or workspace-wide scopes are needed. |
| `perplexity_notable_action` | `notable_to_perplexity_json` | A Perplexity API key | Standard API key from your Perplexity account — no special scope selection exists for this key type. |
| `perplexity_notable_action_github` | `notable_to_perplexity_json` (deterministic GitHub check) | A GitHub **fine-grained** personal access token | Repository access limited to the repositories you expect this check to query. Permission: **Metadata → Read-only** — that single permission is sufficient, since the check only calls `GET /repos/{owner}/{repo}` to confirm a repository exists. Do not grant any write permission. |
| `perplexity_notable_action_abuseipdb` | `notable_to_perplexity_json` (deterministic IP reputation check) | An AbuseIPDB API key | Standard API key from your AbuseIPDB account (free tier is sufficient for the reputation-check endpoint used here). |

Only the Slack and Perplexity realms have a setup page in Splunk Web (**Manage Apps >
TA_ResponseActions > Set up**); the GitHub and AbuseIPDB realms are command-line only by design,
since they're optional checks rather than core delivery credentials.

### Loading credentials via the command line

Use the `storage/passwords` REST endpoint. Run these against your own Splunk management port
(default `8089`) with an account that has admin (or credential-management) rights:

```shell
# Slack bot token
curl -k https://localhost:8089/servicesNS/nobody/TA_ResponseActions/storage/passwords \
  -u admin:<pass> -d name=slack_notable_action -d realm=slack_notable_action -d password=xoxb-...

# Perplexity API key
curl -k https://localhost:8089/servicesNS/nobody/TA_ResponseActions/storage/passwords \
  -u admin:<pass> -d name=perplexity_notable_action -d realm=perplexity_notable_action \
  -d password=<perplexity_api_key>

# GitHub fine-grained PAT (Metadata: Read-only)
curl -k https://localhost:8089/servicesNS/nobody/TA_ResponseActions/storage/passwords \
  -u admin:<pass> -d name=perplexity_notable_action_github -d realm=perplexity_notable_action_github \
  -d password=<github_fine_grained_token>

# AbuseIPDB API key
curl -k https://localhost:8089/servicesNS/nobody/TA_ResponseActions/storage/passwords \
  -u admin:<pass> -d name=perplexity_notable_action_abuseipdb -d realm=perplexity_notable_action_abuseipdb \
  -d password=<abuseipdb_api_key>
```

**These credentials must survive every redeploy.** Splunk physically persists `storage/passwords`
entries under each app's own `local/passwords.conf` and `metadata/local.meta` — both are
instance-owned, not package-owned. Any deployment process that rebuilds this app from a fresh
package **must never touch `local/` or `metadata/local.meta`** — only the package-owned top-level
content (`bin/`, `default/`, `README/`, `README.md`, `app.manifest`, etc.) and
`metadata/default.meta` should be replaced on redeploy. If your deployment tooling wipes the
entire app directory before unpacking a new copy, your credentials will be silently destroyed on
the next update and every alert action will start failing until they're re-entered. Confirm your
own deployment automation preserves `local/` and `metadata/local.meta` before relying on this in
production.

## Testing connectivity / credentials

Each action's credential can silently go bad between deployments (rotated, revoked, expired, realm
renamed) without anyone noticing until the next real notable fires and delivery/answering fails.
`param.test_connectivity` gives you a side-effect-free way to check each one independently, right
now, without needing a real notable or firing any correlation search. Each action tests **only its
own** credential:

- **`notable_to_perplexity_json`** — tests the **Perplexity** credential only.
- **`notable_to_slack_json`** — tests the **Slack** credential only.

When `param.test_connectivity = 1` on either action, it skips all normal processing — no result
rows are read, nothing is posted to Slack, nothing is written back to any notable comment or KV
store record — and instead just resolves and probes its own credential.

Invoke either ad hoc via Splunk's built-in `sendalert` search command — this works from Splunk
Web's Search app, no correlation search required:

``` code
| makeresults | sendalert notable_to_perplexity_json param.test_connectivity=1
| makeresults | sendalert notable_to_slack_json param.test_connectivity=1
```

Then check `$SPLUNK_HOME/var/log/splunk/notable_to_perplexity_json.log` and
`$SPLUNK_HOME/var/log/splunk/notable_to_slack_json.log` respectively and grep for one of these
unambiguous outcome lines:

| Log line prefix | Meaning |
| --- | --- |
| `SLACK AUTH OK` / `PERPLEXITY AUTH OK` | Credential is valid and the API accepted it |
| `SLACK AUTH FAILURE` / `PERPLEXITY AUTH FAILURE` | Credential is invalid/expired/revoked — this is NOT a transient/network error, the API explicitly rejected it |
| `PERPLEXITY API FAILURE (non-auth)` | Perplexity API reachable and credential fine, but the request failed for another reason (rate limit, bad model name, etc.) |
| `SLACK AUTH SKIPPED` / `PERPLEXITY AUTH SKIPPED` | Nothing configured for that credential (or `perplexity_enabled=0`) — not a failure, just not tested |

Every invocation of either script — with or without `test_connectivity` set, successful or not —
also always logs an unconditional `Invoked: sid=... search_name=... test_connectivity=...`
heartbeat line first, so "did the alert action even run" is never a question you have to guess at
from a missing log entry.

## Local testing without a Splunk instance (`test_harness.py`)

`bin/test_harness.py` is a standalone dev/test tool (not registered in `alert_actions.conf`, never
invoked by Splunk itself) that sends a Splunk-alert-action-style JSON payload to either script on
stdin — exactly the way Splunk does — so you can test `alert_actions.conf`'s actual configured
values (template, model, delivery method, credentials) from a laptop with no Splunk instance, no
correlation search, and no real notable required:

```bash
# Pure config/template check - no network calls, no credentials needed:
python3 bin/test_harness.py perplexity --dry-run
python3 bin/test_harness.py slack --dry-run

# Same side-effect-free connectivity probe as `sendalert ... param.test_connectivity=1` above,
# runnable standalone (plaintext credential override shown; a realm + --server-uri/--session-key
# pointed at a real Splunk vault works too):
python3 bin/test_harness.py perplexity --test-connectivity --override perplexity_api_key=pplx-...
python3 bin/test_harness.py slack --test-connectivity --override slack_bot_token=xoxb-...

# Full run against a real credential, overriding sample event fields, tailing the resulting log:
python3 bin/test_harness.py perplexity \
    --override perplexity_api_key=pplx-... \
    --field repo=some-org/some-repo --field user=jdoe --field src=1.2.3.4 --show-log

# Run both actions back to back against the same event fields, to compare their output:
python3 bin/test_harness.py both --field repo=octocat/Hello-World --dry-run
```

`--dry-run` reads the real stanza from `default/alert_actions.conf` and, using `ta_common`
directly, builds and prints both the raw payload and the fully substituted/JSON-parsed envelope —
so a broken `additional_fields` template (bad JSON, wrong token name) shows up immediately as a
parse error, with zero network calls or credentials involved. A real (non-dry-run) invocation
pipes the same payload to the actual script via `subprocess`, prints its exit code and
stdout/stderr, and (`--show-log`) tails its log file. Run `python3 bin/test_harness.py --help` for
the full flag reference.

## GUI: README + Setup pages

The app is visible in Splunk Web's app nav (`is_visible = 1`) with two pages:

- **README** (default landing page) — renders this file's content in-app via
  `appserver/static/readme.html`, so anyone can read the app's own documentation without leaving
  Splunk Web or finding this repo.
- **Setup** — a standard Splunk `setup.xml` page (shown automatically the first time the app is
  opened, and reachable afterwards via **Manage Apps > TA_ResponseActions > Set up**) with blocks
  for submitting the Slack bot token and the Perplexity API key directly into Splunk's
  `storage/passwords` credential vault, under the realms both scripts already expect — no `curl`
  required for initial setup of those two, though the `curl` commands above still work for
  scripted/headless deployment or later rotation of any of the four credentials.

## Worked example: GitHub push audit detection

This is the detection currently used to validate this app end to end, kept here as a concrete,
copy-adaptable example. It looks for pushes into the org's GitHub repositories via a cloud audit
log source and hands each one to the agentic response action:

**Correlation search:** `GitHub Push: Auto AI Response Action`, scheduled every minute
(`cron_schedule = * * * * *`):

```spl
index=github sourcetype="github:cloud:audit" command="git.push" earliest=-2m@m latest=-1m@m
object_attrs="git.push"
| eval action_notification = repo . " by " . user
| table _time, repo, user, src, action_notification
```

With `notable_to_perplexity_json` attached as a response action, every matching push:

1. Fires a notable and, in the same job, sends `repo`, `user`, and `src` to the agentic action.
2. The action runs the deterministic GitHub repository-existence check against `repo` and the
   AbuseIPDB reputation check against `src`, then asks Perplexity the standing `perplexity_ask`
   questions with those verified facts included as ground truth.
3. If the repository doesn't exist (a strong signal of a typo'd or spoofed push target) or the
   source IP has a high abuse confidence score, the action force-escalates the notable's urgency
   regardless of what the model itself concludes, and writes a plain-text summary comment back
   onto the notable.

Confirmed working end to end: a push claiming a nonexistent repository and an IP with a
maximum AbuseIPDB confidence score produced a hard escalation to `critical` urgency, with the
Perplexity narrative and both verified checks written back to the notable's comment timeline and
KV store record.

**Adapting this to your own use case:** the fields above are configurable, not hardcoded —

- `param.github_repo_field` and `param.source_ip_field` on the alert action tell the deterministic
  checks which result field to read (default `repo` / `src`); point them at whatever fields your
  own search produces.
- `param.additional_fields`'s `perplexity_ask` block is free-text JSON — rewrite the questions to
  match what actually matters for your detection (e.g. an unusual login source, an unexpected
  process name, an unfamiliar cloud region) and reference your own result fields with `$result.
  <field>$` tokens.
- The GitHub and AbuseIPDB checks can each be disabled independently
  (`param.github_check_enabled` / `param.abuseipdb_check_enabled`) if they don't apply to your
  detection — Perplexity is still called with whatever context remains.

See [`process.md`](../../conf26/SEC1215/process.md) for the detailed mechanics of every stage in this pipeline.

## Files

| Path | Description |
| --- | --- |
| `default/alert_actions.conf` | Registers both actions — `[notable_to_perplexity_json]` (agentic, no Slack params) and `[notable_to_slack_json]` (Slack notification, no Perplexity params) — with their delivery/payload parameters and `param._cam` (adhoc + drilldown) |
| `README/alert_actions.conf.spec` | Splunk config spec for both stanzas — drives the auto-generated config UI |
| `bin/ta_common.py` | Shared code used by both actions — payload building, credential vault lookups, the Perplexity API call, deterministic GitHub/AbuseIPDB checks, Slack delivery helpers, notable comment/urgency write-back, KV store write, and both `check_slack_connectivity()`/`check_perplexity_connectivity()` probes |
| `bin/notable_to_perplexity_json.py` | Agentic response action — answers `perplexity_ask` synchronously via Perplexity, runs deterministic checks, Adaptive Response panel status, notable comment/urgency write-back, KV store enrichment write. No Slack objects. |
| `bin/notable_to_slack_json.py` | Slack notification action — builds the same JSON envelope (unanswered) and delivers to Slack, Adaptive Response panel status, notable comment write-back, KV store enrichment write. No Perplexity objects. |
| `bin/test_harness.py` | Standalone dev/test tool (not registered in `alert_actions.conf`, never invoked by Splunk) — sends a Splunk-alert-action-style payload to either script on stdin to test `alert_actions.conf`'s real config without a live Splunk instance |
| `default/collections.conf` | `notable_agentic_enrichment` KV store collection schema (shared by both actions) |
| `default/transforms.conf` | `notable_agentic_enrichment_lookup` — lookup wrapper for reading the collection via SPL |
| `default/data/ui/views/notable_agentic_enrichment_drilldown.xml` | Dashboard rendering the enrichment record(s) (from either/both actions) for a given `sid`/`rid` |
| `default/data/ui/nav/default.xml` | App nav — README page as the default landing view, plus the drilldown dashboard and stock Search |
| `default/data/ui/views/readme.xml` | Simple XML view embedding `appserver/static/readme.html` |
| `appserver/static/readme.html` | Static in-app rendering of this README |
| `default/setup.xml` | Splunk Setup page — submits the Slack bot token and Perplexity API key straight into `storage/passwords` under the realms both scripts expect |
| `metadata/default.meta` | Object ACLs |
| `static/appIcon.png`, `appIconAlt.png`, `appIcon_2x.png`, `appIconAlt_2x.png`, `appLogo.png`, `appLogo_2x.png` | App-level icon/logo set (App Manager convention) |
| `appserver/static/appIcon.png` | Icon referenced by `alert_actions.conf`'s `icon_path = appIcon.png` for each action's UI icon in Incident Review |
| `process.md` | Step-by-step description of the full detection-to-write-back pipeline |

Logs: `$SPLUNK_HOME/var/log/splunk/notable_to_perplexity_json.log` and
`$SPLUNK_HOME/var/log/splunk/notable_to_slack_json.log` (separate files, one per action).
