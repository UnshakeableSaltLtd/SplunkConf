#!/usr/bin/env python3
"""
ta_common.py
--------------------------------------------------------------------
Shared helpers for TA_ResponseActions' two Adaptive Response actions:

  - notable_to_perplexity_json.py - the AGENTIC flow. Answers the
    notable's "perplexity_ask" block synchronously via the Perplexity
    API and writes the result back to the SAME notable (comment +
    KV store). Contains NO Slack objects/params - this is deliberate,
    per the 1.4.0 split (see README.md release notes): Slack delivery
    is not part of the agentic response process.
  - notable_to_slack_json.py - the NOTIFICATION flow. Posts the exact
    same JSON envelope (built by build_payload() below - same shape
    that would be sent to Perplexity) to the #es-findings Slack
    channel for human visibility. Does NOT call Perplexity and is NOT
    part of the agentic response process.

Both scripts import this module rather than duplicating: payload
construction, credential vault lookups, Perplexity/Slack API calls,
write-back-to-notable helpers, and connectivity test helpers. Each
script still owns its OWN main()/APP_NAME/log file, so
notable_to_perplexity_json.log and notable_to_slack_json.log stay
independent and it's still unambiguous "did action X even run" per
script.

Every function that logs takes the caller's `log` (a
logging.Logger) as an explicit argument, rather than a module-global
logger, so log lines always land in the CALLING script's own log
file/APP_NAME - not a shared/ambiguous "ta_common" logger.
--------------------------------------------------------------------
"""
import csv
import gzip
import json
import logging
import logging.handlers
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

TOKEN_RE = re.compile(r"\$(result|job)\.([A-Za-z0-9_.]+)\$")
THINK_TAG_RE = re.compile(r"<think>.*?</think>", re.DOTALL)
PERPLEXITY_API_URL = "https://api.perplexity.ai/chat/completions"

# Known Slack Web API error codes that mean "this credential is bad", as opposed to a
# transient network problem or a channel/permission issue unrelated to the token itself.
# https://api.slack.com/methods/auth.test
_SLACK_AUTH_ERRORS = {
    "invalid_auth", "not_authed", "account_inactive", "token_revoked",
    "token_expired", "no_permission", "missing_scope", "ekm_access_denied",
}


class SlackApiError(RuntimeError):
    """Raised for any Slack Web API call that returns ok=false. is_auth_error flags
    the subset of error codes that specifically mean "this bot token is bad", so
    callers can log an unambiguous, greppable AUTH FAILURE line instead of a generic
    one - the whole point being that a bad credential should never look the same in
    the log as a bad channel ID or a network blip."""

    def __init__(self, method, result):
        self.method = method
        self.result = result
        self.error = result.get("error", "unknown_error")
        self.is_auth_error = self.error in _SLACK_AUTH_ERRORS
        super().__init__(f"{method} failed: {result}")


class PerplexityApiError(RuntimeError):
    """Raised for any non-2xx response from api.perplexity.ai. is_auth_error flags
    401/403 specifically (bad/expired API key) so callers can distinguish "the key is
    wrong" from "the API had a bad day" (rate limit, 5xx, timeout, etc.) in the log."""

    def __init__(self, status_code, body):
        self.status_code = status_code
        self.body = body
        self.is_auth_error = status_code in (401, 403)
        super().__init__(f"HTTP {status_code}: {body}")


# ----------------------------------------------------------------------
# Optional: Splunk_SA_CIM's ModularAction gives us the native Incident
# Review "Adaptive Responses" panel + "View Adaptive Response Invocations"
# audit trail for free, via self.message(). Splunk_SA_CIM (the Common
# Information Model Add-on) ships by default with every Splunk ES
# install, but both actions degrade gracefully if it's missing.
# https://dev.splunk.com/enterprise/docs/devtools/enterprisesecurity/adaptiveresponseframework/
# ----------------------------------------------------------------------
_SPLUNK_HOME = os.environ.get("SPLUNK_HOME", "/opt/splunk")
sys.path.append(os.path.join(_SPLUNK_HOME, "etc", "apps", "Splunk_SA_CIM", "bin"))
try:
    from cim_actions import ModularAction
except ImportError:
    ModularAction = None


# ----------------------------------------------------------------------
# Logging - each caller passes its own APP_NAME so the RotatingFileHandler
# writes to $SPLUNK_HOME/var/log/splunk/<app_name>.log, keeping the two
# actions' logs independent.
# ----------------------------------------------------------------------
def setup_logging(app_name):
    log_dir = os.path.join(os.environ.get("SPLUNK_HOME", "/opt/splunk"), "var", "log", "splunk")
    logger = logging.getLogger(app_name)
    logger.setLevel(logging.INFO)
    try:
        handler = logging.handlers.RotatingFileHandler(
            os.path.join(log_dir, f"{app_name}.log"), maxBytes=5_000_000, backupCount=3
        )
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(handler)
    except Exception:
        logging.basicConfig(level=logging.INFO)
    return logger


# ----------------------------------------------------------------------
# Token substitution for the additional_fields template
# ----------------------------------------------------------------------
def substitute_tokens(template, row, job):
    def repl(m):
        scope, field = m.group(1), m.group(2)
        source = row if scope == "result" else job
        return str(source.get(field, ""))

    return TOKEN_RE.sub(repl, template)


# ----------------------------------------------------------------------
# Pull the triggering event row(s) out of the Splunk-provided payload
# ----------------------------------------------------------------------
def load_rows(payload):
    if payload.get("result"):
        return [payload["result"]]

    rows = []
    results_file = payload.get("results_file")
    if results_file and os.path.exists(results_file):
        opener = gzip.open if results_file.endswith(".gz") else open
        with opener(results_file, "rt", encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                rows.append(row)
    return rows


# ----------------------------------------------------------------------
# Build the outgoing JSON envelope. This is THE shared payload shape:
# notable_to_perplexity_json.py sends it to the Perplexity API (as
# context for perplexity_ask) and writes it back to the notable;
# notable_to_slack_json.py posts the SAME shape to Slack, unmodified -
# no perplexity_response is ever merged in by that script since it
# never calls Perplexity.
# ----------------------------------------------------------------------
def build_payload(row, job, cfg, log, app_name):
    denylist = {f.strip() for f in cfg.get("field_denylist", "").split(",") if f.strip()}
    include_raw = cfg.get("include_raw_event", "0") in ("1", "true", "True")
    if not include_raw:
        denylist.add("_raw")

    notable_fields = {k: v for k, v in row.items() if k not in denylist}

    additional = {}
    raw_additional = (cfg.get("additional_fields") or "").strip()
    if raw_additional:
        substituted = substitute_tokens(raw_additional, row, job)
        try:
            additional = json.loads(substituted)
        except json.JSONDecodeError as e:
            log.warning("additional_fields is not valid JSON after token substitution: %s", e)
            additional = {"_additional_fields_raw": substituted, "_parse_error": str(e)}

    return {
        "source": "splunk_es_adaptive_response",
        "action": app_name,
        "sent_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "search_name": job.get("search_name"),
        "sid": job.get("sid"),
        "app": job.get("app"),
        "owner": job.get("owner"),
        "results_link": job.get("results_link"),
        "server_host": job.get("server_host"),
        "notable": notable_fields,
        "additional_fields": additional,
    }


# ----------------------------------------------------------------------
# Credential vault lookup (recommended over plaintext token params) -
# shared by the Slack bot token and the Perplexity API key below.
# ----------------------------------------------------------------------
def get_secret_from_vault(server_uri, session_key, realm, app):
    """Fetch a clear-text password from Splunk's storage/passwords vault by realm.
    Uses an unverified TLS context because this call targets splunkd's own
    management port (typically self-signed / internally issued cert)."""
    url = (
        f"{server_uri}/servicesNS/nobody/{app}/storage/passwords"
        f"?output_mode=json&count=0&search=realm%3D{urllib.parse.quote(realm)}"
    )
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"Authorization": f"Splunk {session_key}"})
    with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    for entry in data.get("entry", []):
        content = entry.get("content", {})
        if content.get("realm") == realm:
            return content.get("clear_password")
    return None


# ----------------------------------------------------------------------
# Credential resolution helpers - shared by the real send path AND the
# test_connectivity check path in each script, so both report the SAME
# "where did this credential come from" source string in the log (vault
# realm=X vs plaintext vs not configured at all).
# ----------------------------------------------------------------------
def resolve_slack_bot_token(cfg, server_uri, session_key, app, log):
    token = (cfg.get("slack_bot_token") or "").strip()
    if token:
        return token, "plaintext (param.slack_bot_token)"
    realm = (cfg.get("slack_bot_token_realm") or "").strip()
    if not realm:
        return "", "not configured (no slack_bot_token or slack_bot_token_realm)"
    try:
        token = get_secret_from_vault(server_uri, session_key, realm, app) or ""
    except Exception:
        log.exception(
            "SLACK CREDENTIAL LOOKUP FAILURE: could not read realm=%s from storage/passwords "
            "(vault unreachable, bad realm name, or insufficient permissions on the running "
            "user context) - this is NOT the same as an invalid token, check connectivity to "
            "server_uri first",
            realm,
        )
        return "", f"vault lookup failed for realm={realm}"
    if not token:
        log.warning(
            "SLACK CREDENTIAL LOOKUP FAILURE: realm=%s has no stored password (empty result, "
            "not a lookup error) - nothing was ever saved under this realm",
            realm,
        )
        return "", f"vault realm={realm} (empty)"
    return token, f"vault realm={realm}"


def resolve_perplexity_api_key(cfg, server_uri, session_key, app, log):
    api_key = (cfg.get("perplexity_api_key") or "").strip()
    if api_key:
        return api_key, "plaintext (param.perplexity_api_key)"
    realm = (cfg.get("perplexity_api_key_realm") or "").strip()
    if not realm:
        return "", "not configured (no perplexity_api_key or perplexity_api_key_realm)"
    try:
        api_key = get_secret_from_vault(server_uri, session_key, realm, app) or ""
    except Exception:
        log.exception(
            "PERPLEXITY CREDENTIAL LOOKUP FAILURE: could not read realm=%s from storage/passwords "
            "(vault unreachable, bad realm name, or insufficient permissions on the running user "
            "context) - this is NOT the same as an invalid key, check connectivity to server_uri "
            "first",
            realm,
        )
        return "", f"vault lookup failed for realm={realm}"
    if not api_key:
        log.warning(
            "PERPLEXITY CREDENTIAL LOOKUP FAILURE: realm=%s has no stored password (empty "
            "result, not a lookup error) - nothing was ever saved under this realm",
            realm,
        )
        return "", f"vault realm={realm} (empty)"
    return api_key, f"vault realm={realm}"


# ----------------------------------------------------------------------
# Perplexity API: answer a notable's "perplexity_ask" questions
# synchronously, so the answer travels with the SAME write-back-to-
# notable paths (comment + KV store) - no separate polling agent or
# bridge required. Used only by notable_to_perplexity_json.py.
# https://docs.perplexity.ai/docs/agent-api/output-control (structured outputs)
# ----------------------------------------------------------------------
def call_perplexity_api(api_key, model, messages, response_format=None, max_tokens=None, timeout=30):
    """Low-level POST to /chat/completions, shared by the real ask/response path and
    the test_connectivity check below. Raises PerplexityApiError on any non-2xx
    response, carrying the HTTP status and raw response body so the caller can log
    the EXACT reason (e.g. the API's own "Invalid API key provided." text on a 401)
    instead of a bare stack trace."""
    req_body = {"model": model, "messages": messages}
    if response_format is not None:
        req_body["response_format"] = response_format
    if max_tokens is not None:
        req_body["max_tokens"] = max_tokens
    req = urllib.request.Request(
        PERPLEXITY_API_URL,
        data=json.dumps(req_body).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", errors="replace")
        raise PerplexityApiError(e.code, body_text) from e


def get_perplexity_response(perplexity_ask, context_fields, cfg, server_uri, session_key, app, log):
    if not isinstance(perplexity_ask, dict) or not perplexity_ask:
        return None

    api_key, source = resolve_perplexity_api_key(cfg, server_uri, session_key, app, log)
    if not api_key:
        log.info(
            "No Perplexity API key configured (%s); skipping perplexity_response", source
        )
        return None

    model = (cfg.get("perplexity_model") or "sonar").strip()
    ask_keys = list(perplexity_ask.keys())

    schema = {
        "type": "object",
        "properties": {k: {"type": "string"} for k in ask_keys},
        "required": list(ask_keys),
        "additionalProperties": False,
    }
    schema["properties"]["overall"] = {"type": "string"}
    schema["required"].append("overall")

    system_prompt = (
        "You are a SOC triage assistant reviewing a single Splunk Enterprise Security notable. "
        "For each question below, give a concise 1-3 sentence answer grounded in the provided "
        "context and, where useful, current public information (e.g. known malicious IP ranges, "
        "well-known Tor exit nodes, common repository/service reputations). Then add one 'overall' "
        "field with a short risk read-out synthesizing all the answers - call out anything atypical "
        "or worth a human follow-up. Answer strictly as JSON matching the given schema."
    )
    user_prompt = (
        f"Notable context (already extracted from the finding):\n{json.dumps(context_fields, default=str)}\n\n"
        f"Questions to answer:\n{json.dumps(perplexity_ask, default=str)}"
    )
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]
    response_format = {
        "type": "json_schema",
        "json_schema": {"name": "perplexity_response", "schema": schema},
    }

    try:
        result = call_perplexity_api(api_key, model, messages, response_format=response_format)
    except PerplexityApiError as e:
        if e.is_auth_error:
            log.error(
                "PERPLEXITY AUTH FAILURE: HTTP %s from api.perplexity.ai (key source=%s, "
                "ask_keys=%s, model=%s): %s - perplexity_response skipped",
                e.status_code, source, ask_keys, model, e.body,
            )
        else:
            log.error(
                "PERPLEXITY API FAILURE (non-auth): HTTP %s from api.perplexity.ai (key "
                "source=%s, ask_keys=%s, model=%s): %s",
                e.status_code, source, ask_keys, model, e.body,
            )
        return None
    except Exception:
        log.exception(
            "PERPLEXITY API FAILURE: network/timeout error calling api.perplexity.ai (key "
            "source=%s, ask_keys=%s, model=%s)",
            source, ask_keys, model,
        )
        return None

    try:
        content = result["choices"][0]["message"]["content"]
        # sonar-reasoning* models prepend a <think>...</think> block even
        # with response_format set; strip it before parsing, just in case
        # this TA is ever pointed at one of those models.
        content = THINK_TAG_RE.sub("", content).strip()
        answer = json.loads(content)
    except Exception:
        log.exception(
            "PERPLEXITY API FAILURE: could not parse response content (key source=%s, "
            "ask_keys=%s, model=%s): %s",
            source, ask_keys, model, result,
        )
        return None

    log.info(
        "PERPLEXITY AUTH OK: got perplexity_response for keys=%s via model=%s (key source=%s)",
        ask_keys, model, source,
    )
    return answer


# ----------------------------------------------------------------------
# Write the collected data back onto the SAME notable so it shows up in
# the analyst's queue as part of that notable's own Activity trail (not
# just a status flag). Only comment/status/urgency/newOwner/disposition
# are writable via this endpoint - no arbitrary new fields.
# https://help.splunk.com/en/splunk-enterprise-security-7/api-reference/7.2/notable-event-endpoints/notable-event-api-reference
# ----------------------------------------------------------------------
def post_comment_to_notable(server_uri, session_key, event_id, comment, log):
    if not server_uri or not session_key:
        raise RuntimeError("server_uri/session_key unavailable; cannot call notable_update")
    url = f"{server_uri}/services/notable_update"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    body = urllib.parse.urlencode({"ruleUIDs": event_id, "comment": comment}).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST", headers={"Authorization": f"Splunk {session_key}"}
    )
    with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
        result = json.loads(resp.read().decode("utf-8"))
    log.info("Wrote comment back to notable event_id=%s: %s", event_id, result)
    return result


# ----------------------------------------------------------------------
# Write a STRUCTURED enrichment record to the shared notable_agentic_enrichment
# KV store collection, keyed by this AR invocation's sid/rid (the only tokens
# Incident Review's custom drilldown_uri supports - event_id is NOT one of
# them). Both actions write to this SAME collection (see default/collections.conf)
# so both surface through the same drilldown dashboard
# (default/data/ui/views/notable_agentic_enrichment_drilldown.xml); the
# perplexity action simply leaves delivery_method/slack_channel/slack_permalink
# blank or set to "perplexity_api" since it never talks to Slack.
# https://dev.splunk.com/view/SP-CAAAEZG (KV store REST write)
# ----------------------------------------------------------------------
def write_kvstore_record(server_uri, session_key, app, record, log):
    if not server_uri or not session_key:
        raise RuntimeError("server_uri/session_key unavailable; cannot write to KV store")
    url = f"{server_uri}/servicesNS/nobody/{app}/storage/collections/data/notable_agentic_enrichment"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    body = json.dumps(record).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Authorization": f"Splunk {session_key}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
        result = json.loads(resp.read().decode("utf-8"))
    log.info("Wrote KV store enrichment record _key=%s", result.get("_key"))
    return result


# ----------------------------------------------------------------------
# Human-readable timestamp for when the underlying event/notable actually
# occurred, as opposed to envelope['sent_at'] (when this action ran).
# Splunk notable rows carry the event time in _time (epoch seconds); fall
# back to the row's own 'time' field, then to sent_at if neither is present.
# ----------------------------------------------------------------------
def format_event_time(row, envelope):
    raw_time = row.get("_time") or row.get("time")
    if raw_time:
        try:
            return time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime(float(raw_time)))
        except (TypeError, ValueError):
            return str(raw_time)
    return envelope.get("sent_at", "")


# ----------------------------------------------------------------------
# Slack delivery: file_upload (recommended - no size limit)
# ----------------------------------------------------------------------
def slack_api_post(url, token, data=None, json_body=None):
    headers = {"Authorization": f"Bearer {token}"}
    if json_body is not None:
        body = json.dumps(json_body).encode("utf-8")
        headers["Content-Type"] = "application/json; charset=utf-8"
    else:
        body = urllib.parse.urlencode(data).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def raise_for_slack_error(method, result):
    """Slack's Web API returns HTTP 200 even for a bad/expired/revoked token - the
    ONLY signal is result['ok'] == False plus an error code (see _SLACK_AUTH_ERRORS
    above). Centralising the check here means every call site raises the SAME
    SlackApiError, so a bad credential is always logged the same unambiguous way,
    however deep in the file_upload flow it happens to fail."""
    if not result.get("ok"):
        raise SlackApiError(method, result)


def upload_json_to_slack(token, channel, filename, json_bytes, comment):
    # Step 1: request an upload URL (files.upload is retired as of 2025-11-12)
    step1 = slack_api_post(
        "https://slack.com/api/files.getUploadURLExternal",
        token,
        data={"filename": filename, "length": str(len(json_bytes))},
    )
    raise_for_slack_error("files.getUploadURLExternal", step1)
    upload_url, file_id = step1["upload_url"], step1["file_id"]

    # Step 2: POST the raw JSON bytes to that URL
    req = urllib.request.Request(
        upload_url, data=json_bytes, method="POST",
        headers={"Content-Type": "application/octet-stream"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        resp.read()

    # Step 3: finalize + share into the channel
    step3 = slack_api_post(
        "https://slack.com/api/files.completeUploadExternal",
        token,
        json_body={
            "files": [{"id": file_id, "title": filename}],
            "channel_id": channel,
            "initial_comment": comment,
        },
    )
    raise_for_slack_error("files.completeUploadExternal", step3)
    return step3


# ----------------------------------------------------------------------
# Slack delivery: webhook (quick start, truncates large payloads)
# ----------------------------------------------------------------------
def post_webhook_summary(webhook_url, envelope, row, max_chars=3500):
    text_json = json.dumps(envelope, indent=2, default=str)
    truncated = len(text_json) > max_chars
    snippet = text_json[:max_chars]
    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*Notable - {envelope.get('search_name', '')}*\n"
                    f"Event time: {format_event_time(row, envelope)}"
                ),
            },
        },
        {"type": "section", "text": {"type": "mrkdwn", "text": f"```{snippet}```"}},
    ]
    if truncated:
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": ":warning: JSON truncated to fit Slack limits. "
                        "Switch delivery_method to file_upload for the full payload.",
                    }
                ],
            }
        )
    body = json.dumps({"blocks": blocks}).encode("utf-8")
    req = urllib.request.Request(
        webhook_url, data=body, method="POST", headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read()


# ----------------------------------------------------------------------
# Connectivity / credential test helpers (param.test_connectivity=1).
# Each check is side-effect-free: Slack gets only an auth.test call (no
# message posted, no file uploaded); Perplexity gets a minimal 1-token
# completion. Nothing is written back to any notable, comment, or KV
# store record in this mode.
# ----------------------------------------------------------------------
def check_slack_connectivity(cfg, server_uri, session_key, app, log):
    """Returns (ok, detail): ok is True/False/None (None = not configured)."""
    token, source = resolve_slack_bot_token(cfg, server_uri, session_key, app, log)
    if not token:
        log.warning("SLACK AUTH SKIPPED: %s", source)
        return None, source
    try:
        result = slack_api_post("https://slack.com/api/auth.test", token, data={})
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", errors="replace")
        log.error(
            "SLACK AUTH FAILURE: HTTP %s calling auth.test (token source=%s): %s",
            e.code, source, body_text,
        )
        return False, f"HTTP {e.code}: {body_text}"
    except Exception as e:
        log.exception(
            "SLACK AUTH FAILURE: network/timeout error calling auth.test (token source=%s)",
            source,
        )
        return False, str(e)
    if result.get("ok"):
        log.info(
            "SLACK AUTH OK: team=%s user=%s bot_id=%s (token source=%s)",
            result.get("team"), result.get("user"), result.get("bot_id"), source,
        )
        return True, result
    error = result.get("error", "unknown_error")
    log.error(
        "SLACK AUTH FAILURE: auth.test returned ok=false error=%s (token source=%s) - "
        "this token will NOT be able to deliver notables",
        error, source,
    )
    return False, error


def check_perplexity_connectivity(cfg, server_uri, session_key, app, log):
    """Returns (ok, detail): ok is True/False/None (None = not configured)."""
    api_key, source = resolve_perplexity_api_key(cfg, server_uri, session_key, app, log)
    if not api_key:
        log.warning("PERPLEXITY AUTH SKIPPED: %s", source)
        return None, source
    model = (cfg.get("perplexity_model") or "sonar").strip()
    try:
        call_perplexity_api(
            api_key, model,
            [{"role": "user", "content": "Reply with exactly: OK"}],
            max_tokens=16,  # api.perplexity.ai now rejects max_tokens<16 with HTTP 400
            timeout=15,
        )
    except PerplexityApiError as e:
        if e.is_auth_error:
            log.error(
                "PERPLEXITY AUTH FAILURE: HTTP %s from api.perplexity.ai (key source=%s, "
                "model=%s): %s - this key will NOT be able to answer perplexity_ask checks",
                e.status_code, source, model, e.body,
            )
        else:
            log.error(
                "PERPLEXITY API FAILURE (non-auth): HTTP %s from api.perplexity.ai (key "
                "source=%s, model=%s): %s",
                e.status_code, source, model, e.body,
            )
        return False, f"HTTP {e.status_code}: {e.body}"
    except Exception as e:
        log.exception(
            "PERPLEXITY API FAILURE: network/timeout error calling api.perplexity.ai (key "
            "source=%s, model=%s)",
            source, model,
        )
        return False, str(e)
    log.info("PERPLEXITY AUTH OK: model=%s responded to test call (key source=%s)", model, source)
    return True, "ok"
