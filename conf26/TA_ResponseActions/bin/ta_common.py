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
import datetime
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
# v1.4.5: migrated from the legacy Sonar /chat/completions endpoint to the Agent
# API. Perplexity is sunsetting /chat/completions on 27 Sep 2026 ("Sonar Chat
# Completions is now Agent API" - https://docs.perplexity.ai/docs/sonar/quickstart),
# and this app's organisation/project API keys are Agent-API-only in any case -
# /chat/completions now returns HTTP 403 "Perplexity organization API keys are not
# supported on this endpoint." for those keys, confirmed against a freshly issued
# console.perplexity.ai/project/keys key. See README.md release notes for 1.4.5.
PERPLEXITY_API_URL = "https://api.perplexity.ai/v1/agent"

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
    """Raised for any non-2xx response from api.perplexity.ai (the Agent API,
    /v1/agent). is_auth_error flags 401/403 specifically (bad/expired/unsupported API
    key) so callers can distinguish "the key is wrong" from "the API had a bad day"
    (rate limit, 5xx, timeout, etc.) in the log."""

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
def resolve_perplexity_model_or_preset(cfg):
    """Returns (model, preset) - exactly one of the two will be truthy. The Agent API
    replaces the legacy single free-text "model" string (e.g. the old default
    "sonar", which no longer exists on this endpoint) with a choice between a
    specific "provider/model" id (param.perplexity_model, e.g. "openai/gpt-5.6-sol")
    or a Perplexity-managed preset (param.perplexity_preset, e.g. "fast-search") that
    picks up future model/tooling improvements with no config change. An explicit
    param.perplexity_model always wins if set; otherwise we fall back to
    param.perplexity_preset, defaulting to "fast-search" (a quick, web-search-capable
    preset - the closest equivalent to the old "sonar" default's speed/cost profile
    for these short triage checks). See https://docs.perplexity.ai/docs/agent-api/presets
    """
    model = (cfg.get("perplexity_model") or "").strip()
    if model:
        return model, None
    preset = (cfg.get("perplexity_preset") or "fast-search").strip()
    return None, preset


def extract_agent_output_text(result):
    """Extract the model's reply text from an Agent API (/v1/agent) response body.
    Unlike the legacy /chat/completions endpoint (a single result["choices"][0]
    ["message"]["content"] string), the Agent API returns an "output" array that can
    contain several item types (e.g. a "search_results" item alongside a "message"
    item) - we want the text content of the "message" item.
    https://docs.perplexity.ai/docs/agent-api/output-control
    https://docs.perplexity.ai/docs/resources/faq
    """
    for item in result.get("output") or []:
        if item.get("type") != "message":
            continue
        for part in item.get("content") or []:
            if part.get("type") in ("output_text", "text") and part.get("text"):
                return part["text"]
    raise KeyError('no "message" item with text content found in Agent API "output" array')


def call_perplexity_api(api_key, input_text, instructions=None, model=None, preset=None,
                         response_format=None, max_output_tokens=None, timeout=30):
    """Low-level POST to /v1/agent (Perplexity's Agent API), shared by the real
    ask/response path and the test_connectivity check below. Raises
    PerplexityApiError on any non-2xx response, carrying the HTTP status and raw
    response body so the caller can log the EXACT reason (e.g. the API's own auth
    error text on a 401/403) instead of a bare stack trace.

    Exactly one of `model` (a specific "provider/model" id, e.g.
    "openai/gpt-5.6-sol") or `preset` (a managed configuration, e.g. "fast-search")
    must be supplied - see resolve_perplexity_model_or_preset(). `model` takes
    precedence if both are somehow set. `instructions` carries the system prompt
    (applied every turn); `input_text` is the actual question/task for this call -
    see https://docs.perplexity.ai/docs/agent-api/building-agents/prompt-the-agent
    """
    if not model and not preset:
        raise ValueError("call_perplexity_api requires either model= or preset=")
    req_body = {"input": input_text}
    if instructions is not None:
        req_body["instructions"] = instructions
    if model:
        req_body["model"] = model
    else:
        req_body["preset"] = preset
    if response_format is not None:
        req_body["response_format"] = response_format
    if max_output_tokens is not None:
        req_body["max_output_tokens"] = max_output_tokens
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


# ----------------------------------------------------------------------
# GitHub repo existence check (deterministic ground truth, NOT LLM-judged) -
# added in 1.4.9 after a prompt-injection test showed a fabricated repo name
# only got a hedged "no reliable public result" answer instead of a hard
# "this does not exist". The Agent API's own web search has no privileged
# view of the org's real repo inventory and, more fundamentally, can't
# reliably prove a NEGATIVE ("this repo doesn't exist") from open web search
# absence alone. This calls the GitHub REST API directly so existence is a
# verified fact, not a guess, before it's ever handed to the LLM as context.
# https://docs.github.com/en/rest/repos/repos#get-a-repository
# ----------------------------------------------------------------------
GITHUB_API_URL = "https://api.github.com"


def resolve_github_token(cfg, server_uri, session_key, app, log):
    token = (cfg.get("github_token") or "").strip()
    if token:
        return token, "plaintext (param.github_token)"
    realm = (cfg.get("github_token_realm") or "").strip()
    if not realm:
        return "", "not configured (no github_token or github_token_realm)"
    try:
        token = get_secret_from_vault(server_uri, session_key, realm, app) or ""
    except Exception:
        log.exception(
            "GITHUB CREDENTIAL LOOKUP FAILURE: could not read realm=%s from storage/passwords "
            "(vault unreachable, bad realm name, or insufficient permissions on the running "
            "user context) - this is NOT the same as an invalid token, check connectivity to "
            "server_uri first",
            realm,
        )
        return "", f"vault lookup failed for realm={realm}"
    if not token:
        log.warning(
            "GITHUB CREDENTIAL LOOKUP FAILURE: realm=%s has no stored password (empty result, "
            "not a lookup error) - nothing was ever saved under this realm",
            realm,
        )
        return "", f"vault realm={realm} (empty)"
    return token, f"vault realm={realm}"


def check_github_repo_exists(token, repo_full_name, log, timeout=10):
    """repo_full_name must be 'owner/repo'. Returns a dict that is always JSON-
    serialisable ground truth and never raises - any transport/auth failure is
    captured in the dict itself (checked=False) rather than silently skipping
    the check or crashing the caller. exists is True/False/None (None = could
    not be determined, e.g. credential failure - NOT the same as 'exists=False')."""
    result = {"repo": repo_full_name, "checked": False, "exists": None, "detail": ""}
    if not repo_full_name or "/" not in repo_full_name:
        result["detail"] = f"not a valid owner/repo string: {repo_full_name!r}"
        return result
    url = f"{GITHUB_API_URL}/repos/{repo_full_name}"
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        result.update(
            checked=True,
            exists=True,
            detail=(
                f"found (private={data.get('private')}, "
                f"default_branch={data.get('default_branch')}, created_at={data.get('created_at')})"
            ),
        )
        log.info("GITHUB CHECK OK: repo=%s exists=True", repo_full_name)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            result.update(
                checked=True,
                exists=False,
                detail="HTTP 404 - repository not found (does not exist under this owner, "
                "or is private and not visible to the configured token)",
            )
            log.warning("GITHUB CHECK: repo=%s does NOT exist (HTTP 404)", repo_full_name)
        elif e.code in (401, 403):
            body_text = e.read().decode("utf-8", errors="replace")
            result["detail"] = f"HTTP {e.code} (credential problem, NOT a repo-existence answer): {body_text}"
            log.error(
                "GITHUB CHECK CREDENTIAL FAILURE: HTTP %s checking repo=%s: %s",
                e.code, repo_full_name, body_text,
            )
        else:
            body_text = e.read().decode("utf-8", errors="replace")
            result["detail"] = f"HTTP {e.code}: {body_text}"
            log.error("GITHUB CHECK FAILURE: HTTP %s checking repo=%s: %s", e.code, repo_full_name, body_text)
    except Exception as e:
        result["detail"] = f"network/timeout error: {e}"
        log.exception("GITHUB CHECK FAILURE: network/timeout error checking repo=%s", repo_full_name)
    return result


def check_github_connectivity(cfg, server_uri, session_key, app, log):
    """Returns (ok, detail): ok is True/False/None (None = not configured)."""
    token, source = resolve_github_token(cfg, server_uri, session_key, app, log)
    if not token:
        log.warning("GITHUB AUTH SKIPPED: %s", source)
        return None, source
    req = urllib.request.Request(
        f"{GITHUB_API_URL}/rate_limit",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", errors="replace")
        log.error(
            "GITHUB AUTH FAILURE: HTTP %s calling /rate_limit (token source=%s): %s",
            e.code, source, body_text,
        )
        return False, f"HTTP {e.code}: {body_text}"
    except Exception as e:
        log.exception("GITHUB AUTH FAILURE: network/timeout error calling /rate_limit (token source=%s)", source)
        return False, str(e)
    log.info(
        "GITHUB AUTH OK: rate_limit remaining=%s (token source=%s)",
        data.get("rate", {}).get("remaining"), source,
    )
    return True, data


# ----------------------------------------------------------------------
# AbuseIPDB reputation check (deterministic ground truth) - same rationale
# as the GitHub check above: an LLM's web search may or may not surface a
# public AbuseIPDB report page for a given IP, and even if it does, can't
# return a real confidence score from that - this calls the actual API.
# https://docs.abuseipdb.com/#check-endpoint
# ----------------------------------------------------------------------
ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"


def resolve_abuseipdb_api_key(cfg, server_uri, session_key, app, log):
    api_key = (cfg.get("abuseipdb_api_key") or "").strip()
    if api_key:
        return api_key, "plaintext (param.abuseipdb_api_key)"
    realm = (cfg.get("abuseipdb_api_key_realm") or "").strip()
    if not realm:
        return "", "not configured (no abuseipdb_api_key or abuseipdb_api_key_realm)"
    try:
        api_key = get_secret_from_vault(server_uri, session_key, realm, app) or ""
    except Exception:
        log.exception(
            "ABUSEIPDB CREDENTIAL LOOKUP FAILURE: could not read realm=%s from storage/passwords "
            "(vault unreachable, bad realm name, or insufficient permissions on the running user "
            "context) - this is NOT the same as an invalid key, check connectivity to server_uri "
            "first",
            realm,
        )
        return "", f"vault lookup failed for realm={realm}"
    if not api_key:
        log.warning(
            "ABUSEIPDB CREDENTIAL LOOKUP FAILURE: realm=%s has no stored password (empty "
            "result, not a lookup error) - nothing was ever saved under this realm",
            realm,
        )
        return "", f"vault realm={realm} (empty)"
    return api_key, f"vault realm={realm}"


def check_ip_reputation(api_key, ip_address, log, max_age_days=90, timeout=10):
    """Returns a dict that is always JSON-serialisable ground truth and never
    raises - any transport/auth failure is captured in the dict itself
    (checked=False) rather than silently skipping the check."""
    result = {"ip": ip_address, "checked": False, "abuse_confidence_score": None, "detail": ""}
    if not ip_address:
        result["detail"] = "no IP address provided"
        return result
    url = f"{ABUSEIPDB_API_URL}?{urllib.parse.urlencode({'ipAddress': ip_address, 'maxAgeInDays': max_age_days})}"
    req = urllib.request.Request(url, headers={"Key": api_key, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        data = body.get("data", {})
        result.update(
            checked=True,
            abuse_confidence_score=data.get("abuseConfidenceScore"),
            total_reports=data.get("totalReports"),
            country_code=data.get("countryCode"),
            isp=data.get("isp"),
            is_tor=data.get("isTor"),
            detail=f"abuseConfidenceScore={data.get('abuseConfidenceScore')} totalReports={data.get('totalReports')}",
        )
        log.info(
            "ABUSEIPDB CHECK OK: ip=%s abuse_confidence_score=%s",
            ip_address, data.get("abuseConfidenceScore"),
        )
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", errors="replace")
        if e.code in (401, 403):
            result["detail"] = f"HTTP {e.code} (credential problem, NOT a reputation answer): {body_text}"
            log.error(
                "ABUSEIPDB CHECK CREDENTIAL FAILURE: HTTP %s checking ip=%s: %s",
                e.code, ip_address, body_text,
            )
        else:
            result["detail"] = f"HTTP {e.code}: {body_text}"
            log.error("ABUSEIPDB CHECK FAILURE: HTTP %s checking ip=%s: %s", e.code, ip_address, body_text)
    except Exception as e:
        result["detail"] = f"network/timeout error: {e}"
        log.exception("ABUSEIPDB CHECK FAILURE: network/timeout error checking ip=%s", ip_address)
    return result


def check_abuseipdb_connectivity(cfg, server_uri, session_key, app, log):
    """Returns (ok, detail): ok is True/False/None (None = not configured)."""
    api_key, source = resolve_abuseipdb_api_key(cfg, server_uri, session_key, app, log)
    if not api_key:
        log.warning("ABUSEIPDB AUTH SKIPPED: %s", source)
        return None, source
    # 8.8.8.8 is a stable, always-safe public IP used purely to prove the key
    # works - not a signal about this deployment's actual traffic.
    check = check_ip_reputation(api_key, "8.8.8.8", log)
    if not check["checked"]:
        log.error("ABUSEIPDB AUTH FAILURE: %s (key source=%s)", check["detail"], source)
        return False, check["detail"]
    log.info("ABUSEIPDB AUTH OK: test call against 8.8.8.8 succeeded (key source=%s)", source)
    return True, check


# ----------------------------------------------------------------------
# Orchestrates BOTH deterministic checks above for a single notable row -
# these run BEFORE the Perplexity call and their results are injected into
# get_perplexity_response() as verified ground truth: the LLM is told these
# facts are already confirmed and must synthesize around them, not re-derive
# or contradict them. Also computes a hard_escalation flag straight from the
# verified facts, with no LLM judgement involved - e.g. a nonexistent repo or
# a high AbuseIPDB score escalates regardless of what any narrative text
# says, so this can't be talked out of firing by a well-worded injection the
# way a pure prompt answer could be. See notable_to_perplexity_json.py for
# how hard_escalation is reconciled with the 1.4.8 overnight/concern urgency
# logic (compute_notable_urgency) - hard_escalation takes priority over both.
# ----------------------------------------------------------------------
def run_deterministic_checks(row, cfg, server_uri, session_key, app, log):
    checks = {}
    reasons = []

    github_enabled = (cfg.get("github_check_enabled", "1")) in ("1", "true", "True")
    repo_field = (cfg.get("github_repo_field") or "repo").strip()
    repo_value = (row.get(repo_field) or "").strip()
    if github_enabled and repo_value:
        token, token_source = resolve_github_token(cfg, server_uri, session_key, app, log)
        if token:
            gh = check_github_repo_exists(token, repo_value, log)
            checks["github_repo_check"] = gh
            if gh["checked"] and gh["exists"] is False:
                reasons.append(
                    f"repository '{repo_value}' does not exist (verified via GitHub API, HTTP 404)"
                )
        else:
            log.warning("GITHUB CHECK SKIPPED for repo=%s: %s", repo_value, token_source)
            checks["github_repo_check"] = {
                "repo": repo_value, "checked": False, "exists": None, "detail": token_source,
            }

    abuseipdb_enabled = (cfg.get("abuseipdb_check_enabled", "1")) in ("1", "true", "True")
    ip_field = (cfg.get("source_ip_field") or "src").strip()
    ip_value = (row.get(ip_field) or "").strip()
    if abuseipdb_enabled and ip_value:
        api_key, key_source = resolve_abuseipdb_api_key(cfg, server_uri, session_key, app, log)
        if api_key:
            try:
                threshold = int(cfg.get("abuseipdb_escalation_threshold") or 50)
            except ValueError:
                threshold = 50
            ipcheck = check_ip_reputation(api_key, ip_value, log)
            checks["ip_reputation_check"] = ipcheck
            score = ipcheck.get("abuse_confidence_score")
            if ipcheck["checked"] and isinstance(score, (int, float)) and score >= threshold:
                reasons.append(
                    f"source IP '{ip_value}' has an AbuseIPDB confidence score of {score} "
                    f"(>= configured threshold {threshold})"
                )
        else:
            log.warning("ABUSEIPDB CHECK SKIPPED for ip=%s: %s", ip_value, key_source)
            checks["ip_reputation_check"] = {
                "ip": ip_value, "checked": False, "abuse_confidence_score": None, "detail": key_source,
            }

    checks["hard_escalation"] = bool(reasons)
    checks["hard_escalation_reasons"] = reasons
    return checks


def get_perplexity_response(
    perplexity_ask, context_fields, cfg, server_uri, session_key, app, log, deterministic_checks=None
):
    if not isinstance(perplexity_ask, dict) or not perplexity_ask:
        return None

    api_key, source = resolve_perplexity_api_key(cfg, server_uri, session_key, app, log)
    if not api_key:
        log.info(
            "No Perplexity API key configured (%s); skipping perplexity_response", source
        )
        return None

    model, preset = resolve_perplexity_model_or_preset(cfg)
    model_desc = model or f"preset:{preset}"
    ask_keys = list(perplexity_ask.keys())

    schema = {
        "type": "object",
        "properties": {k: {"type": "string"} for k in ask_keys},
        "required": list(ask_keys),
        "additionalProperties": False,
    }
    schema["properties"]["overall"] = {"type": "string"}
    schema["required"].append("overall")
    # v1.4.8: structured boolean signal for automated urgency-setting (see
    # compute_notable_urgency() below), so that decision doesn't depend on
    # fragile keyword-parsing of the free-text 'overall' narrative above.
    schema["properties"]["concern"] = {"type": "boolean"}
    schema["required"].append("concern")

    # instructions = the standing system prompt (applied every turn); input_text =
    # the specific question/task for this call. See
    # https://docs.perplexity.ai/docs/agent-api/building-agents/prompt-the-agent
    instructions = (
        "You are a SOC triage assistant reviewing a single Splunk Enterprise Security notable. "
        "For each question below, give a concise 1-3 sentence answer grounded in the provided "
        "context and, where useful, current public information (e.g. known malicious IP ranges, "
        "well-known Tor exit nodes, common repository/service reputations). "
        + (
            "Some facts below have already been VERIFIED PROGRAMMATICALLY (e.g. a live GitHub API "
            "repo-existence check, a live AbuseIPDB reputation lookup) - these are ground truth, not "
            "your own inference. Treat them as authoritative: do not contradict, soften, or hedge "
            "against a verified fact just because your own web search doesn't independently "
            "corroborate it - a verified 'does not exist' or a high abuse confidence score is "
            "definitive on its own. Weight these heavily in your answers and in 'overall'. "
            if deterministic_checks
            else ""
        )
        + "Then add one 'overall' field with a short risk read-out synthesizing all the answers - call "
        "out anything atypical or worth a human follow-up. Also add a 'concern' boolean field: true "
        "if ANY answer surfaces something a human analyst should actually review (e.g. an unexpected "
        "repository, an unconfirmed/unauthorized user, a suspicious or unverified source IP) - this "
        "MUST be true if a verified fact below already indicates a problem; false if every check came "
        "back clean/expected with nothing worth escalating. Answer strictly as JSON matching the "
        "given schema."
    )
    input_text = (
        f"Notable context (already extracted from the finding):\n{json.dumps(context_fields, default=str)}\n\n"
        + (
            f"Verified facts (already confirmed programmatically, NOT to be re-derived or "
            f"contradicted):\n{json.dumps(deterministic_checks, default=str)}\n\n"
            if deterministic_checks
            else ""
        )
        + f"Questions to answer:\n{json.dumps(perplexity_ask, default=str)}"
    )
    response_format = {
        "type": "json_schema",
        "json_schema": {"name": "perplexity_response", "schema": schema},
    }

    try:
        result = call_perplexity_api(
            api_key, input_text, instructions=instructions,
            model=model, preset=preset, response_format=response_format,
        )
    except PerplexityApiError as e:
        if e.is_auth_error:
            log.error(
                "PERPLEXITY AUTH FAILURE: HTTP %s from api.perplexity.ai (key source=%s, "
                "ask_keys=%s, model=%s): %s - perplexity_response skipped",
                e.status_code, source, ask_keys, model_desc, e.body,
            )
        else:
            log.error(
                "PERPLEXITY API FAILURE (non-auth): HTTP %s from api.perplexity.ai (key "
                "source=%s, ask_keys=%s, model=%s): %s",
                e.status_code, source, ask_keys, model_desc, e.body,
            )
        return None
    except Exception:
        log.exception(
            "PERPLEXITY API FAILURE: network/timeout error calling api.perplexity.ai (key "
            "source=%s, ask_keys=%s, model=%s)",
            source, ask_keys, model_desc,
        )
        return None

    try:
        content = extract_agent_output_text(result)
        # sonar-reasoning*-style reasoning models can prepend a <think>...</think>
        # block even with response_format set; strip it before parsing, just in
        # case this TA is ever pointed at one of those models.
        content = THINK_TAG_RE.sub("", content).strip()
        answer = json.loads(content)
    except Exception:
        log.exception(
            "PERPLEXITY API FAILURE: could not parse response content (key source=%s, "
            "ask_keys=%s, model=%s): %s",
            source, ask_keys, model_desc, result,
        )
        return None

    log.info(
        "PERPLEXITY AUTH OK: got perplexity_response for keys=%s via model=%s (key source=%s)",
        ask_keys, model_desc, source,
    )
    return answer


# ----------------------------------------------------------------------
# Render the perplexity_ask/perplexity_response pair as short, readable
# prose for the notable's own Activity/Finding-update comment timeline.
# Incident Review/Mission Control renders this comment as plain text, so a
# single-line json.dumps() blob (the previous behaviour) displays to the
# analyst as raw, unformatted JSON. This builds a plain-text narrative
# instead - pairing each perplexity_ask question with its matching
# perplexity_response answer under a human-readable label - while still
# falling back to an indented (still human-readable) JSON dump for any
# other/unexpected additional_fields shape, so nothing is silently dropped.
# ----------------------------------------------------------------------
# Common acronyms/initialisms that would otherwise get title-cased into an
# awkward form (e.g. "Source ip check" instead of "Source IP check") when
# turning a snake_case check key into a human-readable label.
_LABEL_ACRONYMS = {"ip", "url", "id", "kv", "api", "tls", "ssl", "dns", "cidr", "asn"}


def _humanize_check_label(key):
    words = key.replace("_", " ").strip().split(" ")
    out = []
    for i, word in enumerate(words):
        if word.lower() in _LABEL_ACRONYMS:
            out.append(word.upper())
        elif i == 0:
            out.append(word.capitalize())
        else:
            out.append(word.lower())
    return " ".join(out)


def format_perplexity_comment(sent_at, additional_fields, deterministic_checks=None):
    additional_fields = additional_fields or {}
    ask = additional_fields.get("perplexity_ask") or {}
    response = additional_fields.get("perplexity_response") or {}
    lines = [f"Perplexity ask/response processed at {sent_at}."]

    # v1.4.9: a HARD ESCALATION banner, sourced purely from run_deterministic_checks()'
    # verified facts (GitHub/AbuseIPDB), always goes first and is never dependent on
    # what the LLM narrative below says - see hard_escalation_reasons.
    if deterministic_checks and deterministic_checks.get("hard_escalation"):
        lines.append("*** HARD ESCALATION (verified programmatically, not an LLM judgement) ***")
        for reason in deterministic_checks.get("hard_escalation_reasons") or []:
            lines.append(f"  - {reason}")

    if not isinstance(ask, dict) or not isinstance(response, dict) or (not ask and not response):
        # Nothing in the expected ask/response shape - fall back to an
        # indented (not single-line) JSON dump so it's at least readable.
        if additional_fields:
            lines.append("")
            lines.append("Additional fields:")
            lines.append(json.dumps(additional_fields, indent=2, default=str))
        return "\n".join(lines)

    overall = response.get("overall")
    if overall:
        lines.append("")
        lines.append(f"Overall: {overall}")

    if "concern" in response:
        lines.append(f"Concern flagged: {'Yes' if response.get('concern') else 'No'}")

    check_keys = list(ask.keys()) or [k for k in response.keys() if k not in ("overall", "concern")]
    if check_keys:
        lines.append("")
        lines.append("Checks:")
        for key in check_keys:
            label = _humanize_check_label(key)
            question = ask.get(key)
            answer = response.get(key)
            lines.append(f"- {label}")
            if question:
                lines.append(f"    Asked: {question}")
            if answer:
                lines.append(f"    Result: {answer}")

    # Anything beyond the two known keys is still surfaced, just indented
    # rather than crammed onto the same line as everything else.
    extra = {
        k: v for k, v in additional_fields.items()
        if k not in ("perplexity_ask", "perplexity_response")
    }
    if extra:
        lines.append("")
        lines.append("Other fields:")
        lines.append(json.dumps(extra, indent=2, default=str))

    return "\n".join(lines)


# ----------------------------------------------------------------------
# Write the collected data back onto the SAME notable so it shows up in
# the analyst's queue as part of that notable's own Activity trail (not
# just a status flag). Only comment/status/urgency/newOwner/disposition
# are writable via this endpoint - no arbitrary new fields.
# https://help.splunk.com/en/splunk-enterprise-security-7/api-reference/7.2/notable-event-endpoints/notable-event-api-reference
#
# v1.4.8: generalised from the original post_comment_to_notable(), which only
# ever wrote "comment", to also (optionally, in the SAME POST) write
# "urgency" - see compute_notable_urgency() below for how that value is
# decided. Both comment= and urgency= are optional but at least one must be
# given; either can be set independently so callers can update urgency
# without touching the comment (or vice versa) without a second round trip.
# ----------------------------------------------------------------------
def update_notable(server_uri, session_key, event_id, log, comment=None, urgency=None):
    if not server_uri or not session_key:
        raise RuntimeError("server_uri/session_key unavailable; cannot call notable_update")
    if comment is None and urgency is None:
        raise ValueError("update_notable requires at least one of comment= or urgency=")
    fields = {"ruleUIDs": event_id}
    if comment is not None:
        fields["comment"] = comment
    if urgency is not None:
        fields["urgency"] = urgency
    url = f"{server_uri}/services/notable_update"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    body = urllib.parse.urlencode(fields).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST", headers={"Authorization": f"Splunk {session_key}"}
    )
    with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
        result = json.loads(resp.read().decode("utf-8"))
    log.info(
        "Wrote notable_update event_id=%s (comment=%s, urgency=%s): %s",
        event_id, comment is not None, urgency, result,
    )
    return result


# ----------------------------------------------------------------------
# Parse a "HH:MM" config value (24h, UTC) into a datetime.time, falling back
# to the given default - and logging a warning - on anything unparseable.
# Used for the configurable overnight-urgency-override window bounds
# (param.overnight_start / param.overnight_end) below.
# ----------------------------------------------------------------------
def parse_hhmm(value, default_hour, default_minute, log, label):
    value = (value or "").strip()
    if not value:
        return datetime.time(default_hour, default_minute)
    try:
        hh, mm = value.split(":", 1)
        return datetime.time(int(hh), int(mm))
    except Exception:
        log.warning(
            "Could not parse %s=%r as HH:MM; falling back to %02d:%02d",
            label, value, default_hour, default_minute,
        )
        return datetime.time(default_hour, default_minute)


# ----------------------------------------------------------------------
# True if event_time (epoch seconds - Splunk's native _time representation,
# UTC) falls within [overnight_start, overnight_end) UTC. Returns False (not
# an error) for anything unparseable/missing, since the caller treats "not
# overnight" as the safe default rather than crashing the action over a
# malformed/absent timestamp.
#
# NOTE: assumes overnight_start < overnight_end (does not support a window
# that wraps past midnight, e.g. 22:00-04:00). The default 00:30-06:00
# window doesn't need that; revisit this if a future window ever needs to
# cross midnight.
# ----------------------------------------------------------------------
def _push_time_is_overnight(event_time, overnight_start, overnight_end):
    if event_time in (None, ""):
        return False
    try:
        ts = float(event_time)
    except (TypeError, ValueError):
        return False
    event_clock = datetime.datetime.utcfromtimestamp(ts).time()
    return overnight_start <= event_clock < overnight_end


# ----------------------------------------------------------------------
# Decide what urgency (if any) should be written back to the notable,
# combining Perplexity's own structured "concern" verdict with a fixed
# overnight-push override. Priority order (highest wins):
#   1. event_time falls inside the overnight window (UTC) -> "high",
#      regardless of what Perplexity concluded - out-of-hours activity is
#      treated as inherently suspicious even when nothing else looks wrong,
#      so it always gets escalated for a human look.
#   2. perplexity_response["concern"] is True -> concern_urgency (v1.4.10:
#      configurable via param.concern_urgency, default "high" - an LLM-
#      flagged concern on this kind of detection warrants an analyst look
#      as soon as it surfaces, not a lower-tier queue position; previously
#      hardcoded to "medium" in 1.4.8/1.4.9).
#   3. Otherwise (perplexity_response present with concern=False, and not
#      overnight) -> "low".
# Returns None when there is no basis for a decision at all (no usable
# perplexity_response and not overnight) - e.g. perplexity_enabled=0, no
# perplexity_ask configured, or the API call failed - so a missing/failed
# response is never silently mistaken for "nothing to worry about".
#
# Valid urgency values per the notable_update endpoint: informational, low,
# medium, high, critical (lowercase).
# https://help.splunk.com/en/splunk-enterprise-security-7/user-guide/7.3/incident-review/how-urgency-is-assigned-to-notable-events-in-splunk-enterprise-security
# ----------------------------------------------------------------------
def compute_notable_urgency(
    perplexity_response, event_time, overnight_start, overnight_end, concern_urgency="high"
):
    if _push_time_is_overnight(event_time, overnight_start, overnight_end):
        return "high"
    if isinstance(perplexity_response, dict) and "concern" in perplexity_response:
        return concern_urgency if perplexity_response.get("concern") else "low"
    return None


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
    model, preset = resolve_perplexity_model_or_preset(cfg)
    model_desc = model or f"preset:{preset}"
    try:
        call_perplexity_api(
            api_key, "Reply with exactly: OK",
            model=model, preset=preset,
            # Agent API's documented max_output_tokens minimum is 1 (vs the legacy
            # /chat/completions endpoint's >=16 floor), but we keep 16 here for a
            # small safety margin - and note some providers (e.g. Anthropic models)
            # REQUIRE max_output_tokens to be set at all.
            # https://docs.perplexity.ai/api-reference/agent-post
            max_output_tokens=16,
            timeout=15,
        )
    except PerplexityApiError as e:
        if e.is_auth_error:
            log.error(
                "PERPLEXITY AUTH FAILURE: HTTP %s from api.perplexity.ai (key source=%s, "
                "model=%s): %s - this key will NOT be able to answer perplexity_ask checks",
                e.status_code, source, model_desc, e.body,
            )
        else:
            log.error(
                "PERPLEXITY API FAILURE (non-auth): HTTP %s from api.perplexity.ai (key "
                "source=%s, model=%s): %s",
                e.status_code, source, model_desc, e.body,
            )
        return False, f"HTTP {e.status_code}: {e.body}"
    except Exception as e:
        log.exception(
            "PERPLEXITY API FAILURE: network/timeout error calling api.perplexity.ai (key "
            "source=%s, model=%s)",
            source, model_desc,
        )
        return False, str(e)
    log.info("PERPLEXITY AUTH OK: model=%s responded to test call (key source=%s)", model_desc, source)
    return True, "ok"
