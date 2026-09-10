# TA_ResponseActions

**App Name:** Notable to Perplexity / Slack
**Version:** 1.4.9
**Author:** David Pollard, Unshakeable Salt Ltd
**Associated Session:** [SEC1215 — From Zero to Agentic](../SEC1215/README.md)

## Overview

Two independent, custom Splunk Enterprise Security **Adaptive Response Actions**, split apart in
1.4.0 so the agentic flow and the human-notification flow can be enabled, disabled, or have their
credentials rotated completely independently:

- **`notable_to_perplexity_json`** — *"Send Notable to Perplexity API (Agentic Response)"*. Part of
  the agentic response process: answers the notable's `perplexity_ask` block synchronously via the
  Perplexity API and writes the result back to the same notable. **No Slack objects at all.**
- **`notable_to_slack_json`** — *"Send Notable to Slack (ES Findings)"*. **Not** part of the agentic
  response process: posts the triggering Notable/Finding to the `#es-findings` Slack channel as a
  complete JSON payload — the exact same envelope shape built for the Perplexity call, but never
  answered (this action never calls Perplexity).

Both share `bin/ta_common.py` for payload construction, credential vault lookups, and
write-back-to-notable helpers, so the two stay in lockstep on payload shape while remaining
independently configurable.

`notable_to_slack_json`'s two delivery modes (unchanged from pre-split):

- **file_upload** (recommended) — uses a Slack bot token via `files.getUploadURLExternal` /
  `files.completeUploadExternal` to deliver the entire JSON with no size limit ([Slack retired
  `files.upload` on 2025-11-12](https://slack.com/help/articles/4426294050451-Slack-feature-and-plan-retirements)).
- **webhook** — quick to set up via an Incoming Webhook, but truncates large payloads to fit
  Slack's block limits.

## Requirements

- Splunk Enterprise Security 7.x+ on Splunk Enterprise 9.x/10.x
- Python 3.x (bundled with Splunk)
- A Slack app with a bot token scoped `files:write`, `chat:write` (only needed for
  `notable_to_slack_json`)
- A [Perplexity API key](https://www.perplexity.ai/settings/api) (only needed for
  `notable_to_perplexity_json`'s synchronous `perplexity_ask`/`perplexity_response` call — see
  below)
- `Splunk_SA_CIM` (Common Information Model Add-on) — ships by default with every ES install.
  Required for the native Adaptive Response panel status reporting below (both actions degrade
  gracefully and still run their normal flow if it's missing)

## Perplexity API: synchronous ask/response (agentic flow)

`param.additional_fields` (on both actions, from the same default template) ships a standing
`perplexity_ask` block with three checks run against every notable: is `$result.repo$` a repo
commonly seen for this kind of finding, is `$result.user$` an expected/authorized user, and is
`$result.src$` a low-threat source IP.

`notable_to_perplexity_json` — when `param.perplexity_enabled` is on (default) — answers that
block **in-line, synchronously** — a single call to the
[Perplexity Agent API](https://docs.perplexity.ai/docs/agent-api/quickstart) (`POST
https://api.perplexity.ai/v1/agent`, since 1.4.5 — see Release Notes) with a JSON schema
`response_format` built from the ask keys plus an `overall` risk read-out. The result is merged
back into the same `additional_fields` object as `perplexity_response`, then travels through:

1. **The notable comment write-back** (`param.write_back_comment`).
2. **The KV store enrichment record** (`param.write_back_kvstore`), so the drilldown dashboard
   shows the ask and the answer side by side.

`notable_to_slack_json` builds the **same** `perplexity_ask` envelope and posts it to Slack, but
**never answers it** — no Perplexity call is made from that action at all. This is deliberate: it
keeps the human-notification channel free of any dependency on the Perplexity credential, and
gives analysts a way to visually audit exactly what was asked, separately from whether/how it was
answered.

No separate index, credential realm, polling interval, or scripted input is required — the alert
action already has full notable context at send time, so there's nothing to hand off. An earlier
design (`bin/slack_hec_bridge.py`, shipped in 1.3.1–1.3.2) polled Slack asynchronously for a
reply and mapped it onto CIM Risk fields via HEC; it worked, but added a second moving part
(polling interval, thread-ts plumbing, a fixed reply-format contract) to answer questions this
action already had the answer to. It's kept only as a documented "before" lesson — see
[`../SEC1215/lessons/README.md`](../SEC1215/lessons/README.md) for the full write-up of why it
was retired.

## Closing the loop: getting the result back to the analyst

After processing, **both** actions write back to the **same** notable so the analyst sees the
result alongside the rest of the event, without leaving Incident Review:

1. **Adaptive Responses panel** — each action is built on `cim_actions.py`'s `ModularAction`
   class and calls `self.message(..., status='success'/'failure')`. This populates the notable's
   native "Adaptive Responses" section / "View Adaptive Response Invocations" audit trail
   (backed by the `Splunk_Audit.Modular_Actions` data model), typically visible within ~5 minutes.
2. **Notable comment (`param.write_back_comment`, default on)** — each action calls
   `POST /services/notable_update` with `ruleUIDs=<event_id>` and a `comment` summarizing what
   happened (for `notable_to_perplexity_json`: the ask/response pair; for `notable_to_slack_json`:
   delivery method, timestamp, `additional_fields`). This is a permanent entry in that notable's
   own Activity timeline, so any analyst who later opens the notable sees it directly — this only
   works when the action runs in a notable context (i.e. `event_id` is present on the triggering
   row) and only supports comment text, not new structured/columnar fields.
3. **KV store enrichment + custom drilldown (`param.write_back_kvstore`, default on)** — see
   below. Gives analysts genuinely structured fields, not just comment text. Both actions write to
   the **same** collection, so a single dashboard shows both actions' records for a given
   `sid`/`rid`.

### KV store enrichment / custom drilldown

`/services/notable_update` only supports `comment`/`status`/`urgency`/`newOwner`/`disposition` —
no arbitrary new fields. To surface real structured data (delivery status, Slack channel or
`perplexity_api`, the exact `additional_fields` sent, error detail on failure) next to the
notable, each action also:

1. Writes a record to the **`notable_agentic_enrichment`** KV store collection
   (`default/collections.conf`) via `POST /servicesNS/nobody/<app>/storage/collections/data/...`,
   keyed by **this invocation's `sid`/`rid`** — not `event_id`. That's because Incident Review's
   custom `drilldown_uri` (in `param._cam`) only supports the tokens `$sid$`, `$rid$`, `$time$`,
   `$earliest$`, `$latest$`, `$action_name$` — `event_id` isn't one of them
   ([reference](https://community.splunk.com/t5/Splunk-Search/How-to-change-Custom-Adaptive-response-action-succ-td-p/310960)).
   `event_id`/`orig_sid`/`orig_rid` are still stored on the record for ad hoc `event_id` lookups.
   `notable_to_perplexity_json`'s records set `delivery_method="perplexity_api"` and leave
   `slack_channel`/`slack_permalink` blank; `notable_to_slack_json`'s records set
   `delivery_method` to `file_upload`/`webhook` and populate those fields.
2. Declares `param._cam = {"supports_adhoc": true, "drilldown_uri": "notable_agentic_enrichment_drilldown?form.sid=$sid$&form.rid=$rid$", ...}`
   in `alert_actions.conf`. `supports_adhoc` is also what makes each action appear under
   Incident Review's **Run Adaptive Response Actions** ad hoc menu at all
   ([reference](https://community.splunk.com/t5/Splunk-Enterprise-Security/The-quot-Run-Adaptive-Response-Actions-quot-is-not-listing-all/m-p/472638)).
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

## Testing connectivity / credentials

Each action's credential can silently go bad between deployments (rotated, revoked, expired,
realm renamed) without anyone noticing until the next real notable fires and delivery/answering
fails. `param.test_connectivity` gives you a side-effect-free way to check each one independently,
right now, without needing a real notable or firing any correlation search. Since the two actions
were split, each now tests **only its own** credential:

- **`notable_to_perplexity_json`** — tests the **Perplexity** credential only (no Slack
  credential exists on this action anymore).
- **`notable_to_slack_json`** — tests the **Slack** credential only (no Perplexity credential
  exists on this action anymore).

When `param.test_connectivity = 1` on either action, it skips **all** normal processing — no
result rows are read, nothing is posted to Slack, nothing is written back to any notable comment
or KV store record — and instead just resolves and probes its own credential:

- **Slack** (`notable_to_slack_json` only) — calls `auth.test` (no message posted, no file
  uploaded). Skipped entirely if no `param.slack_bot_token`/`param.slack_bot_token_realm` is
  configured.
- **Perplexity** (`notable_to_perplexity_json` only) — sends a minimal (16-token, the API's
  current minimum) completion request. Skipped if `param.perplexity_enabled` is off, or if no
  `param.perplexity_api_key`/`param.perplexity_api_key_realm` is configured.

Invoke either ad hoc via Splunk's built-in `sendalert` search command — this works from Splunk
Web's Search app, no correlation search required:

```
| makeresults | sendalert notable_to_perplexity_json param.test_connectivity=1
| makeresults | sendalert notable_to_slack_json param.test_connectivity=1
```

Then check `$SPLUNK_HOME/var/log/splunk/notable_to_perplexity_json.log` and
`$SPLUNK_HOME/var/log/splunk/notable_to_slack_json.log` respectively (each action now logs to its
own file — see Release Notes 1.4.0) and grep for one of these unambiguous outcome lines:

| Log line prefix | Meaning |
|---|---|
| `SLACK AUTH OK` / `PERPLEXITY AUTH OK` | Credential is valid and the API accepted it |
| `SLACK AUTH FAILURE` / `PERPLEXITY AUTH FAILURE` | Credential is invalid/expired/revoked — this is NOT a transient/network error, the API explicitly rejected it (e.g. `auth.test` returned `ok=false error=invalid_auth`, or Perplexity returned HTTP 401/403) |
| `PERPLEXITY API FAILURE (non-auth)` | Perplexity API reachable and credential fine, but the request failed for another reason (rate limit, bad model name, etc.) |
| `SLACK AUTH SKIPPED` / `PERPLEXITY AUTH SKIPPED` | Nothing configured for that credential (or `perplexity_enabled=0`) — not a failure, just not tested |

Every invocation of either script — with or without `test_connectivity` set, successful or not —
also always logs an unconditional `Invoked: sid=... search_name=... test_connectivity=...` (plus
an action-specific flag: `perplexity_enabled=...` for the Perplexity action,
`delivery_method=...` for the Slack action) heartbeat line first, so "did the alert action even
run" is never a question you have to guess at from a missing log entry.

The same `SLACK AUTH FAILURE` / `PERPLEXITY AUTH FAILURE` labelling is also used during **real**
delivery/answering (not just the test mode) — if a live Slack send fails because Slack rejects the
bot token, or a `perplexity_ask` call gets a 401/403, the log line makes that unmistakable rather
than burying it in a generic Python traceback.

## Local testing without a Splunk instance (`test_harness.py`)

`bin/test_harness.py` is a standalone dev/test tool (not registered in `alert_actions.conf`, never
invoked by Splunk itself) that sends a Splunk-alert-action-style JSON payload to either script on
stdin - exactly the way Splunk does - so you can test `alert_actions.conf`'s actual configured
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
directly, builds and prints both the raw payload and the fully substituted/JSON-parsed envelope -
so a broken `additional_fields` template (bad JSON, wrong token name) shows up immediately as a
parse error, with zero network calls or credentials involved. A real (non-dry-run) invocation pipes
the same payload to the actual script via `subprocess`, prints its exit code and stdout/stderr, and
(`--show-log`) tails its log file - logs land under `.test_harness_home/` next to this README by
default (already excluded from git via this repo's `.gitignore`). Run
`python3 bin/test_harness.py --help` for the full flag reference (`--override` for
`configuration`/`param.*` values, `--field`/`--result-file` for the sample event row, `--sid`,
`--search-name`, `--server-uri`/`--session-key` to exercise real vault-realm credential resolution
instead of a plaintext override, etc.).

## GUI: README + Setup pages

Since 1.4.0 the app is visible in Splunk Web's app nav (`is_visible = 1`) with two pages:

- **README** (default landing page) — renders this file's content in-app via
  `appserver/static/readme.html`, so anyone can read the app's own documentation without leaving
  Splunk Web or finding this repo.
- **Setup** — a standard Splunk `setup.xml` page (shown automatically the first time the app is
  opened, and reachable afterwards via **Manage Apps > TA_ResponseActions > Set up**) with two
  blocks for submitting/updating the Slack bot token and the Perplexity API key directly into
  Splunk's `storage/passwords` credential vault, under the realms both scripts already expect
  (`slack_notable_action` / `perplexity_notable_action`) — no `curl` required for initial setup,
  though the `curl` commands below still work for scripted/headless deployment or later rotation.

## Installation

> **Upgrading from 1.4.0 or earlier?** The KV store collection was renamed from
> `notable_slack_enrichment` to `notable_agentic_enrichment` in 1.4.1 (see Release Notes). Splunk
> does not rename existing KV store collections on upgrade — any enrichment records already
> written under the old name stay in `notable_slack_enrichment` and won't show up in the renamed
> drilldown dashboard. If you need that history, export it first (`| inputlookup
> notable_slack_enrichment_lookup`) and re-import into the new collection, or simply let old
> records age out and let new invocations populate `notable_agentic_enrichment` going forward.

1. Copy this folder to `$SPLUNK_HOME/etc/apps/TA_ResponseActions/`, restart Splunk.
2. Open the app in Splunk Web — the **Setup** page appears automatically (or via **Manage Apps >
   TA_ResponseActions > Set up**) — and submit the Slack bot token and Perplexity API key there.
   Alternatively, store them directly via `curl`:

   ``` shell
   curl -k https://localhost:8089/servicesNS/nobody/TA_ResponseActions/storage/passwords \
     -u admin:<pass> -d name=slack_notable_action -d realm=slack_notable_action -d password=xoxb-...

   curl -k https://localhost:8089/servicesNS/nobody/TA_ResponseActions/storage/passwords \
     -u admin:<pass> -d name=perplexity_notable_action -d realm=perplexity_notable_action \
     -d password=<perplexity_api_key>
   ```

   Get a Perplexity key at [perplexity.ai/settings/api](https://www.perplexity.ai/settings/api).

   The two v1.4.9 deterministic-check credentials (GitHub token, AbuseIPDB key) have **no**
   `setup.xml` GUI block by design — set them via `curl` only, same pattern, different realms:

   ``` shell
   curl -k https://localhost:8089/servicesNS/nobody/TA_ResponseActions/storage/passwords \
     -u admin:<pass> -d name=perplexity_notable_action_github -d realm=perplexity_notable_action_github \
     -d password=<github_fine_grained_token>

   curl -k https://localhost:8089/servicesNS/nobody/TA_ResponseActions/storage/passwords \
     -u admin:<pass> -d name=perplexity_notable_action_abuseipdb -d realm=perplexity_notable_action_abuseipdb \
     -d password=<abuseipdb_api_key>
   ```

   Scope the GitHub token to read-only repository access (a fine-grained PAT's default
   Metadata: Read-only permission is all `GET /repos/{owner}/{repo}` requires — no write scopes).
   Get an AbuseIPDB key at [abuseipdb.com/account/api](https://www.abuseipdb.com/account/api).
3. In ES, ensure this app is covered by **Configure > General > App Import** so ES recognizes it
   as an Adaptive Response provider.
4. On a correlation search, **Add New Response Action** and add either or both:
   - **Send Notable to Perplexity API (Agentic Response)** — configure `perplexity_enabled`,
     `perplexity_model`/`perplexity_preset`, `additional_fields` (the `perplexity_ask` block), and
     save.
   - **Send Notable to Slack (ES Findings)** — configure `delivery_method`, `slack_channel`
     (defaults to `C0BKA6D4AFL` / `#es-findings`), `additional_fields`, and save.
5. Test via Incident Review → Run Adaptive Response Actions on a notable, or trigger the
   correlation search directly. Use `param.test_connectivity=1` on either action first (see
   "Testing connectivity / credentials" above) to confirm credentials are valid before relying on
   a live notable.

## Files

| Path | Description |
|---|---|
| `default/alert_actions.conf` | Registers both actions — `[notable_to_perplexity_json]` (agentic, no Slack params) and `[notable_to_slack_json]` (Slack notification, no Perplexity params) — with their delivery/payload parameters and `param._cam` (adhoc + drilldown) |
| `README/alert_actions.conf.spec` | Splunk config spec for both stanzas — drives the auto-generated config UI |
| `bin/ta_common.py` | Shared code used by both actions — payload building, credential vault lookups (Slack + Perplexity), the Perplexity API call, Slack delivery helpers, notable comment write-back, KV store write, and both `check_slack_connectivity()`/`check_perplexity_connectivity()` probes. Each caller passes in its own `log`/`app_name` so log lines land in that script's own log file. |
| `bin/notable_to_perplexity_json.py` | Agentic response action — answers `perplexity_ask` synchronously via Perplexity, Adaptive Response panel status, notable comment write-back, KV store enrichment write. No Slack objects. |
| `bin/notable_to_slack_json.py` | Slack notification action — builds the same JSON envelope (unanswered) and delivers to Slack, Adaptive Response panel status, notable comment write-back, KV store enrichment write. No Perplexity objects. |
| `bin/test_harness.py` | Standalone dev/test tool (not registered in `alert_actions.conf`, never invoked by Splunk) — sends a Splunk-alert-action-style payload to either script on stdin to test `alert_actions.conf`'s real config without a live Splunk instance. See "Local testing without a Splunk instance" above. |
| `default/collections.conf` | `notable_agentic_enrichment` KV store collection schema (shared by both actions) |
| `default/transforms.conf` | `notable_agentic_enrichment_lookup` — lookup wrapper for reading the collection via SPL |
| `default/data/ui/views/notable_agentic_enrichment_drilldown.xml` | Dashboard rendering the enrichment record(s) (from either/both actions) for a given `sid`/`rid` |
| `default/data/ui/nav/default.xml` | App nav — README page as the default landing view, plus the drilldown dashboard and stock Search |
| `default/data/ui/views/readme.xml` | Simple XML view embedding `appserver/static/readme.html` |
| `appserver/static/readme.html` | Static in-app rendering of this README |
| `default/setup.xml` | Splunk Setup page — submits the Slack bot token and Perplexity API key straight into `storage/passwords` under the realms both scripts expect |
| `metadata/default.meta` | Object ACLs |
| `static/appIcon.png`, `appIconAlt.png`, `appIcon_2x.png`, `appIconAlt_2x.png`, `appLogo.png`, `appLogo_2x.png` | App-level icon/logo set (App Manager convention), copied from [`splunk_build`'s `org_template`](https://github.com/UnshakeableSaltLtd/splunk_build/tree/main/library/unshakeablesalt/org_template/static) |
| `appserver/static/appIcon.png` | Icon referenced by `alert_actions.conf`'s `icon_path = appIcon.png` for each action's UI icon in Incident Review |

Logs: `$SPLUNK_HOME/var/log/splunk/notable_to_perplexity_json.log` and
`$SPLUNK_HOME/var/log/splunk/notable_to_slack_json.log` (separate files since 1.4.0).

## Release Notes

### 1.4.9

- **Added: deterministic GitHub-existence and AbuseIPDB-reputation verification checks**, run
  BEFORE the Perplexity call. An LLM's own web search can't reliably prove a negative ("this repo
  doesn't exist") and easily hedges an absence of results into "no reliable public result" instead
  of a hard "confirmed does not exist" - these two checks call the real GitHub and AbuseIPDB REST
  APIs directly so existence/reputation are verified facts, not model inference.
  - `ta_common.check_github_repo_exists()` — `GET /repos/{owner}/{repo}`; HTTP 404 is treated as a
    confirmed non-existent repo, 401/403 is reported distinctly as a credential failure (never
    conflated with "confirmed not to exist").
  - `ta_common.check_ip_reputation()` — `GET /api/v2/check` against AbuseIPDB for the notable's
    source IP, returning a real 0–100 abuse confidence score.
  - `ta_common.run_deterministic_checks()` orchestrates both against the raw notable row and
    produces a `hard_escalation` flag + `hard_escalation_reasons` list from the verified facts
    alone — no LLM judgement involved, so it can't be talked out of firing by a well-worded prompt
    injection.
  - Verified facts are injected into the Perplexity Agent API call as ground truth the model is
    instructed not to contradict or hedge against, and are weighted into the `overall`/`concern`
    fields.
  - `hard_escalation` **overrides** the 1.4.8 overnight-window/concern urgency logic
    (`param.hard_escalation_urgency`, default `critical`) — a confirmed signal on this specific
    notable wins over the blanket time-based policy. Still gated by
    `param.urgency_override_enabled`.
  - The write-back comment is prefixed with a `*** HARD ESCALATION ***` banner + reasons when
    triggered (`ta_common.format_perplexity_comment()`).
  - New KV store fields `hard_escalation` (bool) / `hard_escalation_reasons` (string) added to
    `default/collections.conf`, `default/transforms.conf`'s `fields_list`, and the
    `notable_agentic_enrichment_drilldown` dashboard's table columns. Always `false`/blank on
    `notable_to_slack_json`'s own records, which never run these checks.
  - New params: `param.github_check_enabled`, `param.github_repo_field`,
    `param.github_token_realm`/`param.github_token`, `param.abuseipdb_check_enabled`,
    `param.source_ip_field`, `param.abuseipdb_api_key_realm`/`param.abuseipdb_api_key`,
    `param.abuseipdb_escalation_threshold`, `param.hard_escalation_urgency`. Credentials go in
    `storage/passwords` under realms `perplexity_notable_action_github` /
    `perplexity_notable_action_abuseipdb` — set via `curl` (see "Installation" below); deliberately
    no `setup.xml` GUI block for these two.
  - Known gap: `bin/test_harness.py` does not yet support `--override github_token=...` /
    `--override abuseipdb_api_key=...`, so these two checks can't be dry-run standalone the way
    the Slack/Perplexity credentials can - only live via a real notable or
    `sendalert ... param.test_connectivity=1`.
- Version bumped **1.4.8 → 1.4.9** (increment only, per this project's versioning convention).

### 1.4.8

- **Added: automatic notable urgency write-back.** `notable_to_perplexity_json` now sets the
  notable's `urgency` field via the same `/services/notable_update` call used for the comment
  write-back (bundled into a single POST when both are due - see `ta_common.update_notable()`,
  generalised from the old `post_comment_to_notable()`). Priority order (highest wins):
  1. The notable's own event time (`_time`, UTC) falls inside the configurable overnight window
     (`param.overnight_start`/`param.overnight_end`, default **00:30–06:00 UTC**) → **`high`**,
     regardless of what Perplexity concluded - out-of-hours activity (e.g. a GitHub push at 2am)
     is treated as inherently suspicious even when nothing else looks wrong.
  2. Otherwise, if Perplexity's response indicates a genuine concern → **`medium`**.
  3. Otherwise (no concern, and not overnight) → **`low`**.
  A missing/failed Perplexity response (e.g. `perplexity_enabled=0`, no `perplexity_ask`
  configured, or an API failure) and not-overnight is never silently treated as `low` - there must
  be positive evidence (a real `concern` verdict, or the overnight override) before urgency is
  touched at all. New toggle: `param.urgency_override_enabled` (default `1`) to disable entirely.
  Note: `urgency` (used here) is the ES notable field this endpoint can actually write - there is
  no separate writable per-notable "severity" field; severity is a static correlation-search-level
  property. [How urgency is assigned to notable events](https://help.splunk.com/en/splunk-enterprise-security-7/user-guide/7.3/incident-review/how-urgency-is-assigned-to-notable-events-in-splunk-enterprise-security),
  [Notable Event API reference](https://help.splunk.com/en/splunk-enterprise-security-7/api-reference/7.2/notable-event-endpoints/notable-event-api-reference).
- **Added: structured `concern` boolean field** to the Perplexity response schema (alongside the
  existing free-text `overall` field), so the urgency decision above is driven by an explicit
  true/false model signal rather than keyword-parsing the `overall` narrative. Surfaced in the
  notable's write-back comment as a new `Concern flagged: Yes/No` line.
- **Added: `urgency_set` field** to the shared `notable_agentic_enrichment` KV store collection
  (`default/collections.conf`, `default/transforms.conf`'s `fields_list`, and the
  `notable_agentic_enrichment_drilldown` dashboard's table columns), recording whatever urgency
  value (if any) was written back for that row. Always blank on `notable_to_slack_json`'s own
  records, since that action never touches urgency.
- Version bumped **1.4.7 → 1.4.8** (increment only, per this project's versioning convention -
  new feature, no `major.minor` change).

### 1.4.7

- **Fixed: `notable_to_perplexity_json`'s write-back comment on the notable's own
  Activity/Finding-update timeline displayed as raw, single-line JSON** in Incident
  Review/Mission Control, e.g. `Additional fields: {"perplexity_ask": {...}, ...}`. Root
  cause: the comment body was built with `json.dumps(envelope['additional_fields'])` and
  posted as-is - readable to a script, not to an analyst reading the Finding Update panel.
  Fixed by adding `ta_common.format_perplexity_comment()`, which renders the same data as a
  short plain-text narrative (an `Overall:` summary line, followed by each `perplexity_ask`
  question paired with its matching `perplexity_response` answer under a human-readable
  label, e.g. "Source IP check" rather than the raw `source_ip_check` key), while still
  falling back to an indented JSON dump for any additional_fields shape outside the expected
  ask/response pair so nothing is silently dropped. The KV store enrichment record (used by
  the `notable_agentic_enrichment_drilldown` dashboard's dedicated "Raw additional_fields
  JSON" panel) is unchanged and still stores the raw JSON, since that panel is explicitly for
  programmatic/raw inspection.
- Version bumped **1.4.6 → 1.4.7** (patch bump, comment-formatting/display fix only - no
  request/response shape, KV store schema, or config schema changes).

### 1.4.6

- **Fixed: Splunk invoked both alert action scripts with no `--execute` argument at all**,
  tripping the FATAL invocation-contract check added in 1.4.4. Root cause: `alert_actions.conf`
  explicitly overrides `alert.execute.cmd` (to `notable_to_perplexity_json.py` /
  `notable_to_slack_json.py`), which disables Splunk's default auto-injection of `--execute` as
  `argv[1]` - that auto-behaviour only applies when `alert.execute.cmd` is left unset. Once
  customised, every argument (including `--execute`) must be supplied explicitly via
  `alert.execute.cmd.arg.N`. Fixed by adding `alert.execute.cmd.arg.1 = --execute` to both
  stanzas. Confirmed via `sendmodalert`/`AlertNotifierWorker` internal logs and the scripts' own
  logs against a real triggered alert (`Detect GitHub Push`) on Splunk Enterprise 10.4.3.
- **Fixed: KV store enrichment write-back returned HTTP 404** on every invocation. Root cause:
  `kvstore_app` was derived from `payload.get("app", "TA_ResponseActions")`, but Splunk's alert
  payload always populates `"app"` with the *triggering saved search's* own app context (e.g.
  `TA_AllIndexCreation`, `SplunkEnterpriseSecuritySuite`), never `TA_ResponseActions` - so the
  fallback never applied and the REST write targeted a namespace where the
  `notable_agentic_enrichment` collection doesn't exist. Fixed by hardcoding `kvstore_app =
  "TA_ResponseActions"` in both scripts, since that's the only app that ever owns this collection
  (`default/collections.conf`), regardless of which app's search fires the alert.
- Version bumped **1.4.5 → 1.4.6** (patch bump, live-environment bug fixes only - no request/
  response shape or config schema changes beyond the two `alert.execute.cmd.arg.1` additions).

### 1.4.5

- **Migrated from the legacy Sonar `/chat/completions` endpoint to Perplexity's Agent API**
  (`POST https://api.perplexity.ai/v1/agent`). Perplexity is sunsetting `/chat/completions` on
  27 September 2026 ("Sonar Chat Completions is now Agent API" — see the
  [Sonar quickstart](https://docs.perplexity.ai/docs/sonar/quickstart) and
  [migration guide](https://docs.perplexity.ai/docs/agent-api/migrate-from-sonar/overview)), and
  this app's Perplexity organisation/project API keys turned out to be Agent-API-only already —
  `/chat/completions` returned HTTP 403 `Perplexity organization API keys are not supported on
  this endpoint.` even against a freshly issued key from
  [console.perplexity.ai/project/keys](https://console.perplexity.ai/project/keys).
- **Request shape changed**: the old `messages` array (`system`/`user` roles) is replaced by the
  Agent API's `instructions` (system prompt, applied every turn) and `input` (the specific
  question/task) fields — see the
  [prompt guide](https://docs.perplexity.ai/docs/agent-api/building-agents/prompt-the-agent).
  `response_format` (JSON-schema structured output) keeps the same shape as before —
  `{"type": "json_schema", "json_schema": {"name": ..., "schema": ...}}` — so the
  `perplexity_ask`/`perplexity_response` schema-building logic in `get_perplexity_response()` was
  untouched. `max_tokens` is renamed `max_output_tokens`.
- **Response parsing changed**: the old single `choices[0].message.content` string is replaced by
  an `output` array that can contain multiple item types (e.g. a `search_results` item alongside a
  `message` item); a new `extract_agent_output_text()` helper in `ta_common.py` walks that array
  for the `message` item's text content. See the
  [output control docs](https://docs.perplexity.ai/docs/agent-api/output-control).
- **Model configuration changed**: the old free-text `param.perplexity_model` (default `sonar`,
  which no longer exists on this endpoint) is now optional — set it to pin an exact
  `provider/model` id (e.g. `openai/gpt-5.6-sol`), or leave it blank to use the new
  `param.perplexity_preset` (default `fast-search`, a quick web-search-capable preset chosen as
  the closest match to the old Sonar default's speed/cost profile for these short triage checks).
  An explicit `perplexity_model` always wins over `perplexity_preset`. See
  [presets](https://docs.perplexity.ai/docs/agent-api/presets).
- `check_perplexity_connectivity()`'s probe call and `get_perplexity_response()`'s main
  ask/response call both moved onto the new helpers (`resolve_perplexity_model_or_preset()`,
  `extract_agent_output_text()`) so both paths stay in lockstep on request/response shape.
- `test_harness.py` needed no functional changes — it shells out to the real script exactly as
  Splunk would, so it exercises whatever `alert_actions.conf` (or `--override`) configures; its
  `--override` help text example was updated to show the new `perplexity_preset`/`perplexity_model`
  options instead of the retired `sonar-pro`.
- Version bumped **1.4.4 → 1.4.5** (patch bump — credential/endpoint migration forced by
  Perplexity's own API changes; no change to this app's own external interface/behavioural
  contract beyond the `perplexity_model`/`perplexity_preset` config split described above).

### 1.4.4

- **Diagnosable "error code 1"**: both scripts exit 1 in exactly one place — right at the top,
  before stdin is even read, if `sys.argv[1] != "--execute"`. Every other failure path (bad JSON,
  credential lookup, API auth) exits 2 or 3, so exit 1 always means Splunk did not invoke the
  script with the standard custom alert action contract (`script --execute`, payload JSON on
  stdin) — e.g. a stale/shadowing app copy, a config that never made it onto the server, or the
  action firing outside the expected `sendalert`/correlation-search path. This used to only write
  `FATAL usage: ...` to stderr, which meant root-causing it required pulling the exact stderr text
  out of the Job Inspector's `search.log`. Both scripts now also unconditionally log the full
  invocation context — `argv`, Python version/executable, cwd, and resolved script path — to their
  own log file (falling back to stderr via `logging.basicConfig` if the log file itself can't be
  opened, which will usually still surface in the Job Inspector). Grep for `FATAL invocation
  contract violation` to diagnose this class of failure from the log alone.
- **Fixed inconsistent executable bit**: `notable_to_perplexity_json.py` was the only one of the
  three `bin/` scripts marked executable; `notable_to_slack_json.py` and `test_harness.py` are now
  `chmod +x` too, matching their shebang lines. Splunk invokes both actions via the configured
  Python interpreter either way (`python.version = python3` in `alert_actions.conf`), so this was
  not itself the cause of any invocation failure, but it's fixed for consistency and so
  `test_harness.py` and `notable_to_slack_json.py` can be run directly (`./notable_to_slack_json.py
  --execute`) the same way `notable_to_perplexity_json.py` already could.
- Version bumped **1.4.3 → 1.4.4** (patch bump — diagnostics and permissions only, no interface or
  behavioral changes to the normal success path).

### 1.4.3

- **Fixed `check_perplexity_connectivity()`'s test call**: it hardcoded `max_tokens=5`, but
  `api.perplexity.ai` now rejects any request with `max_tokens < 16` (HTTP 400
  `max_tokens must be at least 16`). This meant `param.test_connectivity=1` on
  `notable_to_perplexity_json` — and `test_harness.py perplexity --test-connectivity` — always
  reported failure even with a fully valid API key, misreporting a real credential as broken.
  Found by testing `test_harness.py` end-to-end against a live Perplexity API key. Bumped the probe
  to `max_tokens=16` (the API's current minimum). The main enrichment path
  (`get_perplexity_response()`) was never affected — it doesn't pass `max_tokens` at all, so it was
  never subject to this minimum.
- Version bumped **1.4.2 → 1.4.3** (patch bump — bug fix only, no interface changes).

### 1.4.2

- **Added `bin/test_harness.py`** — a standalone dev/test tool that sends a Splunk-alert-action-style
  JSON payload to either `notable_to_perplexity_json.py` or `notable_to_slack_json.py` on stdin,
  exactly as Splunk itself would invoke them. Reads the real stanza out of `default/alert_actions.conf`
  so it tests the *actual configured* `additional_fields` template, model, delivery method, etc.
  (with `--override`/`--field` to tweak values ad hoc), and requires no live Splunk instance,
  correlation search, or real notable. Supports a `--dry-run` mode (builds and prints the payload plus
  the `ta_common.build_payload()` envelope with tokens substituted — zero network calls, no
  credentials needed) and a real-invocation mode that pipes to the actual script via `subprocess` and
  can tail the resulting log file. Not registered in `alert_actions.conf` and not part of the app's
  Splunk-invoked surface — dev/test tooling only. See "Local testing without a Splunk instance" above
  for usage examples.
- Version bumped **1.4.1 → 1.4.2** (patch bump — new dev/test tooling only, no behavioral change to
  either shipped alert action).

### 1.4.1

- **Renamed the shared KV store collection, lookup, and drilldown dashboard away from their
  Slack-specific names**, since 1.4.0 made it a genuinely shared object written by both actions —
  including `notable_to_perplexity_json` records that never touch Slack at all:
  - Collection: `notable_slack_enrichment` → **`notable_agentic_enrichment`**
    (`default/collections.conf`).
  - Lookup: `notable_slack_enrichment_lookup` → **`notable_agentic_enrichment_lookup`**
    (`default/transforms.conf`).
  - Dashboard: `default/data/ui/views/notable_slack_enrichment_drilldown.xml` →
    **`default/data/ui/views/notable_agentic_enrichment_drilldown.xml`**, relabeled "Notable
    Agentic Enrichment" with an updated description noting both actions write to it.
  - Updated every reference: both `param._cam.drilldown_uri` values in `alert_actions.conf`, the
    `[collections/...]`/`[views/...]` ACL stanzas in `metadata/default.meta`, the nav entry in
    `default/data/ui/nav/default.xml`, and all mentions in `bin/ta_common.py`,
    `README/alert_actions.conf.spec`, and this README.
  - No field-level renames — `field.slack_channel`/`field.slack_permalink` stay as-is (still
    accurate for `notable_to_slack_json` records; simply blank for `notable_to_perplexity_json`
    records) and no data migration is needed for existing KV store rows under the old collection
    name, though they won't be visible under the new name — see the note in "Installation" below.
- Version bumped **1.4.0 → 1.4.1** (patch bump — naming/documentation fix only, no behavioral
  change to either action's logic).

### 1.4.0

- **Split the single combined action into two independent Adaptive Response actions**, so the
  agentic flow and the human-notification flow can be enabled, disabled, or have their credentials
  rotated completely independently:
  - **`notable_to_perplexity_json`** — kept the agentic response flow only. Answers
    `perplexity_ask` synchronously via the Perplexity API and writes the result back to the
    notable (comment + KV store, `delivery_method="perplexity_api"`). **All Slack objects,
    params, and delivery code removed** — this action makes zero Slack calls and has no
    `slack_*` params. Its `test_connectivity` mode now tests Perplexity only.
  - **`notable_to_slack_json`** (new file, replacing the pre-split
    `notable_to_perplexity_json.py`'s Slack half) — posts the same envelope to Slack, unanswered.
    This action makes zero Perplexity calls and has no `perplexity_*` params. Its
    `test_connectivity` mode now tests Slack only. Default `param.slack_channel` set to
    `C0BKA6D4AFL` (`#es-findings`).
- Extracted all shared logic into a new `bin/ta_common.py` module — payload building, credential
  vault lookups, the Perplexity API call, Slack delivery helpers, notable comment/KV store
  write-back, and both connectivity checks — imported by both scripts so payload shape and
  behavior stay in lockstep. Every function that logs now takes the caller's `log` object
  explicitly, so each action writes to its own log file
  (`notable_to_perplexity_json.log` / `notable_to_slack_json.log`) instead of sharing one.
- `default/alert_actions.conf` and `README/alert_actions.conf.spec` split into two stanzas —
  `[notable_to_perplexity_json]` (no `slack_*` params) and `[notable_to_slack_json]` (no
  `perplexity_*` params) — each documenting only the params relevant to that action.
- **App is now visible in Splunk Web** (`is_visible = 0` → `1`) with a new GUI:
  - `default/data/ui/nav/default.xml` — a README page as the default landing view, the existing
    drilldown dashboard, and stock Search.
  - `default/data/ui/views/readme.xml` + `appserver/static/readme.html` — renders this README
    in-app.
  - `default/setup.xml` — a Setup page for submitting/updating the Slack bot token and Perplexity
    API key directly into `storage/passwords`, shown automatically on first open and reachable
    afterward via **Manage Apps > Set up**.
- Version bumped **1.3.4 → 1.4.0** (minor bump, explicitly requested — this is a breaking change
  to the alert action's shape, not a patch).

### 1.3.4

- Added `param.test_connectivity` — a side-effect-free credential check mode (see "Testing
  connectivity / credentials" above). Skips all real processing and just probes Slack
  (`auth.test`) and Perplexity (a minimal 1-token completion), logging unambiguous
  `SLACK/PERPLEXITY AUTH OK` / `AUTH FAILURE` / `AUTH SKIPPED` lines. Invoke via
  `| makeresults | sendalert notable_to_perplexity_json param.test_connectivity=1`.
- Added `SlackApiError` and `PerplexityApiError` exception classes (each with an `is_auth_error`
  flag) so a bad/expired/revoked credential is now always distinguishable in the log from a
  generic network/timeout/parse error, both in the new test mode and during normal delivery.
- Added `resolve_slack_bot_token()` / `resolve_perplexity_api_key()` helpers that centralize the
  vault-vs-plaintext credential lookup (previously duplicated inline in `main()`) and report a
  clear "source" string (`vault realm=...` / `plaintext` / `not configured`) in every related log
  line.
- `get_perplexity_response()` now logs a distinct `PERPLEXITY AUTH FAILURE` line for HTTP
  401/403 versus `PERPLEXITY API FAILURE` for other errors (rate limits, network issues, response
  parsing failures), instead of one generic `log.exception(...)` for every case.
- Every invocation now logs an unconditional `Invoked: sid=... search_name=...
  test_connectivity=... perplexity_enabled=... delivery_method=...` heartbeat line immediately
  after parsing configuration, regardless of outcome.
- The real Slack delivery failure path now detects `SlackApiError` and logs a distinct
  `SLACK AUTH FAILURE` line (with the failing method + Slack error code) when the token itself is
  the problem, in addition to the existing generic failure logging for non-auth errors.

### 1.3.3

- **Replaced the Slack → HEC bridge (`bin/slack_hec_bridge.py`, 1.3.1–1.3.2) with a synchronous
  Perplexity API call made in-line inside `bin/notable_to_perplexity_json.py`.** The bridge script,
  its `inputs.conf`/`inputs.conf.spec` registration, and the KV store/collections/transforms/
  drilldown fields it added (`slack_thread_ts`, `awaiting_ai_response`, `risk_object`,
  `risk_object_type`, `risk_score`, `risk_message`, `hec_sent`, `notable_enriched_at`) have all
  been removed from this app and archived as a documented lesson at
  [`../SEC1215/lessons/`](../SEC1215/lessons/README.md).
- Added `param.perplexity_enabled`, `param.perplexity_api_key_realm`, `param.perplexity_api_key`,
  and `param.perplexity_model` to `alert_actions.conf`. When enabled,
  `bin/notable_to_perplexity_json.py` answers the standing `perplexity_ask` block via the Perplexity
  API before delivery and merges the result into `additional_fields.perplexity_response` — see
  "Perplexity API: synchronous ask/response" above.
- Removed the `reply_format` key from the default `perplexity_ask` block in
  `param.additional_fields` (no longer needed — the synchronous call uses a proper JSON Schema
  `response_format` instead of instructing the model to reply with raw JSON text in Slack).
- Slack delivery itself is unchanged — still useful for visually auditing what was asked and
  answered.

### 1.3.2

- Fixed `README/alert_actions.conf.spec` for `[notable_to_perplexity_json]`: added the missing
  `param._cam` documentation line. Splunk's own dev docs say `param._cam` is inherited from
  `Splunk_SA_CIM`'s spec and doesn't need redeclaring, but any tooling that only resolves specs
  on a per-app basis (rather than merging in other installed apps' specs) will otherwise flag it.
- Added app icon/logo assets (`static/appIcon.png`, `appIconAlt.png`, `appIcon_2x.png`,
  `appIconAlt_2x.png`, `appLogo.png`, `appLogo_2x.png`) plus `appserver/static/appIcon.png`,
  reused from [`splunk_build`'s `org_template`](https://github.com/UnshakeableSaltLtd/splunk_build/tree/main/library/unshakeablesalt/org_template/static).
  This satisfies `alert_actions.conf`'s `icon_path = appIcon.png` setting, which per Splunk's own
  spec "refers to the `appserver/static` directory in the app that the alert action is defined in."
- **Note on the VS Code Splunk extension linter:** the official
  [Visual Studio Code Extension for Splunk](https://github.com/splunk/vscode-extension-splunk) only
  validates `.conf` files against its own bundled global spec files (or a single folder set via the
  `splunk.spec.FilePath` setting) — it never reads an app's own `README/*.conf.spec` file
  (confirmed in `extension.js`'s `getSpecFilePath()`, and tracked as a known gap for `inputs.conf` in
  [issue #59](https://github.com/splunk/vscode-extension-splunk/issues/59), which applies to every
  conf type). That means every custom `param.*` key on a custom alert action — including
  `param._cam` — will always show as "Invalid key in stanza" in that extension, regardless of what's
  declared in this app's spec file. This is a known limitation of the extension, not a defect in this
  app; these specific warnings are safe to ignore. (Community reports of the same `param._cam`
  warning, e.g. [Splunk Add-on Builder thread](https://community.splunk.com/t5/All-Apps-and-Add-ons/Splunk-Add-on-Builder-How-to-resolve-quot-Invalid-key-in-stanza/m-p/215990)
  and [VictorOps app thread](https://community.splunk.com/t5/Splunk-On-Call/Invalid-key-in-stanza/m-p/477090),
  confirm the same root cause.)

### 1.3.1

- Added `bin/slack_hec_bridge.py`, a classic scripted input (`default/inputs.conf`,
  `README/inputs.conf.spec`) that closes the Phase 2/3 agentic loop: polls the KV store for
  `awaiting_ai_response=1` records, reads the AI's reply from the Slack thread, parses it against
  the strict JSON schema, POSTs a CIM Risk event to HEC (`index=risk` by default), and writes the
  verdict back to the originating notable's comment trail. See
  [../SEC1215/ARCHITECTURE.md](../SEC1215/ARCHITECTURE.md) for the full narrative.
- `alert_actions.conf`'s default `perplexity_ask.additional_fields` block now also ships a
  `reply_format` key that pins the AI to a fixed JSON reply shape
  (`risk_score`/`risk_object`/`risk_object_type`/`risk_message`), so `slack_hec_bridge.py` can
  parse it deterministically instead of scraping free-text prose.
- `bin/notable_to_perplexity_json.py` now resolves the Slack channel + message `ts` of the uploaded
  file via `files.info` (file_upload delivery only) and stores it as `slack_thread_ts` on the
  KV store record, with `awaiting_ai_response=1`, so the bridge knows which thread to poll.
- `default/collections.conf`/`transforms.conf` extended with `slack_thread_ts`,
  `awaiting_ai_response`, `risk_object`, `risk_object_type`, `risk_score`, `risk_message`,
  `hec_sent`, `notable_enriched_at`; the drilldown dashboard gained a new "Agentic AI verdict"
  panel showing them.
- **Known limitation:** the bridge only works for `delivery_method=file_upload` — webhook
  delivery has no bot token/`conversations.read` scope to read a reply back with.

### 1.3.0

- `param.additional_fields` now ships a default `perplexity_ask` block with three standing checks
  run against every notable by the Slack->HEC bridge automation: is `$result.repo$` a repo we
  commonly see for this kind of finding, is `$result.user$` an expected/authorized user, and is
  `$result.src$` a low-threat source IP. Override or extend per correlation search as needed.
- Slack `initial_comment`/webhook summary text (both delivery methods) now reads
  `Notable - <search_name>` / `Event time: <event time>` ahead of the JSON payload, instead of the
  old `:rotating_light:`/SID-only line. Event time is read from the notable's own `_time` field
  where available, falling back to the send timestamp.

### 1.2.0

- Added `param.write_back_kvstore` — persists a structured enrichment record (event_id, delivery
  method, Slack channel, `additional_fields` JSON, status/error) to a new `notable_agentic_enrichment`
  KV store collection, keyed by the AR invocation's `sid`/`rid`.
- Added `param._cam` to `alert_actions.conf`: `supports_adhoc: true` (makes the action available
  under Incident Review's "Run Adaptive Response Actions" ad hoc menu) and a `drilldown_uri`
  pointing at a new custom dashboard.
- Added `default/collections.conf`, `default/transforms.conf`, and
  `default/data/ui/views/notable_agentic_enrichment_drilldown.xml` for the KV store lookup + view.
- Fixed a repo-level `.gitignore` bug (a leftover PyInstaller `*.spec` rule) that was silently
  excluding Splunk's `.conf.spec` convention files from commits.

### 1.1.0

- Added native Incident Review "Adaptive Responses" panel reporting via `cim_actions.ModularAction.message()`.
- Added `param.write_back_comment` — posts a comment back to the triggering notable via
  `/services/notable_update` so the collected Slack data appears in that notable's own Activity
  timeline for analysts.

### 1.0.0

- Initial release: full-JSON notable delivery to Slack via bot token (file_upload) or webhook,
  configurable additional fields, credential vault support, field denylist.
