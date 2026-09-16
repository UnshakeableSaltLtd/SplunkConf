[notable_to_perplexity_json]
param._cam = <string> JSON object describing this action's Common Action Model (CAM) classification -
  category, task, subject, technology, supports_adhoc, and drilldown_uri. drilldown_uri points the
  action's row in the notable's Adaptive Responses panel at the SAME custom KV-store-backed
  dashboard [notable_to_slack_json] also drills into
  (default/data/ui/views/notable_agentic_enrichment_drilldown.xml) instead of the default "search for
  result events" link. Splunk_SA_CIM's own README/alert_actions.conf.spec documents param._cam as a
  standard adaptive-response key, so Splunk Enterprise itself does not require it to be redeclared
  here - it is included for local documentation completeness and for tooling (e.g. some conf linters)
  that only resolves specs on a per-app basis and does not merge in specs from other installed apps.

param.additional_fields = <string> JSON object of extra fields to merge into the outgoing payload
  under "additional_fields". Supports $result.<field>$ and $job.<field>$ tokens, which are
  substituted per-event before the JSON is parsed. Default ships a "perplexity_ask" block - the SAME
  template [notable_to_slack_json] uses to build its (unanswered) Slack copy of the payload. Example:
  {"environment": "prod-uk1", "runbook": "https://wiki.internal/notable/$result.rule_id$"}

param.field_denylist = <string> Comma-separated list of field names to remove from the notable
  before it is processed.

param.include_raw_event = <bool> Whether to include the _raw event text in the payload. Default: 0

param.pretty_print = <bool> Whether to indent the JSON for readability. Default: 1

param.max_events = <number> Maximum number of result rows to process per invocation. Default: 5

param.write_back_comment = <bool> Whether to POST a comment back to the triggering notable
  (via /services/notable_update, matched by event_id) after processing, so the perplexity_ask/
  perplexity_response pair appears in that notable's own Activity timeline in Incident Review.
  Requires the action to be invoked in a notable context (event_id present in the result row).
  Default: 1

param.write_back_kvstore = <bool> Whether to persist a structured record (event_id,
  delivery_method="perplexity_api", additional_fields JSON, status/error) to the
  notable_agentic_enrichment KV store collection - the SAME collection [notable_to_slack_json]
  writes to - keyed by this invocation's sid/rid. Surfaced to analysts via the drilldown_uri
  configured in param._cam - use this when you need real structured fields next to the notable,
  not just comment text. Default: 1

param.perplexity_enabled = <bool> Whether to answer the "perplexity_ask" block in
  param.additional_fields synchronously via the Perplexity API, merging the result into
  additional_fields.perplexity_response. Default: 1

param.perplexity_api_key_realm = <string> Name of the credential realm in Splunk's
  storage/passwords vault that holds the Perplexity API key. Recommended over plaintext. Can also
  be submitted via the app's Setup page in Splunk Web.

param.perplexity_api_key = <string> Plaintext fallback for the Perplexity API key. Leave blank
  if using perplexity_api_key_realm.

param.perplexity_model = <string> Exact Perplexity Agent API "provider/model" id to pin for the
  ask/response call (e.g. openai/gpt-5.6-sol). Takes precedence over perplexity_preset if set.
  Default: (blank - falls back to perplexity_preset)

param.perplexity_preset = <string> Perplexity Agent API managed preset to use instead of a pinned
  model (e.g. fast-search, pro-search) - Perplexity tunes the underlying model/tooling over time,
  so this needs no config change to pick up improvements. Ignored if perplexity_model is set.
  Default: fast-search

param.test_connectivity = <bool> Side-effect-free credential check mode. When enabled (1),
  the action skips ALL normal processing (no result rows are read, nothing is written back to
  any notable comment or KV store record) and instead resolves + probes the Perplexity credential
  via a minimal 1-token completion (only if perplexity_enabled=1). Outcome is logged unambiguously
  as PERPLEXITY AUTH OK, AUTH FAILURE, or AUTH SKIPPED in notable_to_perplexity_json.log. Intended
  for ad-hoc manual invocation via Splunk's sendalert search command, not for use on a real
  correlation search. Default: 0


[notable_to_slack_json]
param._cam = <string> JSON object describing this action's Common Action Model (CAM) classification -
  see [notable_to_perplexity_json] above; both actions drill into the SAME dashboard.

param.delivery_method = <string> "file_upload" or "webhook". file_upload sends the complete JSON with
  no size cap via a Slack bot token; webhook is quicker to set up but truncates large payloads.
  Default: file_upload

param.slack_webhook_url = <string> Slack Incoming Webhook URL. Only used when delivery_method=webhook.

param.slack_bot_token_realm = <string> Name of the credential realm in Splunk's storage/passwords
  vault that holds the Slack bot token (xoxb-...). Recommended over storing the token in plaintext.
  Can also be submitted via the app's Setup page in Splunk Web.

param.slack_bot_token = <string> Plaintext fallback for the Slack bot token. Leave blank if using
  slack_bot_token_realm. Only used when delivery_method=file_upload.

param.slack_channel = <string> Slack channel ID (e.g. C0123ABCD) to post/upload the notable JSON to.
  Only used when delivery_method=file_upload. Default: C0BKA6D4AFL (#es-findings).

param.additional_fields = <string> JSON object of extra fields to merge into the outgoing payload
  under "additional_fields" - the SAME template [notable_to_perplexity_json] uses. Any
  "perplexity_ask" block here is posted to Slack unanswered (this action never calls Perplexity).
  Supports $result.<field>$ and $job.<field>$ tokens, which are substituted per-event before the
  JSON is parsed.

param.field_denylist = <string> Comma-separated list of field names to remove from the notable
  before it is sent to Slack.

param.include_raw_event = <bool> Whether to include the _raw event text in the payload. Default: 0

param.pretty_print = <bool> Whether to indent the JSON for readability. Default: 1

param.max_events = <number> Maximum number of result rows to send per invocation. Default: 5

param.write_back_comment = <bool> Whether to POST a comment back to the triggering notable
  (via /services/notable_update, matched by event_id) after a successful Slack send, so the
  collected data appears in that notable's own Activity timeline in Incident Review. Requires
  the action to be invoked in a notable context (event_id present in the result row). Default: 1

param.write_back_kvstore = <bool> Whether to persist a structured record (event_id, delivery
  details, additional_fields JSON, status/error) to the notable_agentic_enrichment KV store
  collection - the SAME collection [notable_to_perplexity_json] writes to - keyed by this
  invocation's sid/rid. Surfaced to analysts via the drilldown_uri configured in param._cam - use
  this when you need real structured fields next to the notable, not just comment text. Default: 1

param.test_connectivity = <bool> Side-effect-free credential check mode. When enabled (1),
  the action skips ALL normal processing (no result rows are read, nothing is sent to Slack,
  nothing is written back to any notable comment or KV store record) and instead resolves +
  probes the Slack credential via auth.test (no message posted). Outcome is logged unambiguously
  as SLACK AUTH OK, AUTH FAILURE, or AUTH SKIPPED in notable_to_slack_json.log. Intended for
  ad-hoc manual invocation via Splunk's sendalert search command, not for use on a real
  correlation search. Default: 0
