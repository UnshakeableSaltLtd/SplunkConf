#!/usr/bin/env python3
"""
test_harness.py
--------------------------------------------------------------------
Standalone test harness for TA_ResponseActions' two Adaptive Response
actions - notable_to_perplexity_json.py (agentic) and
notable_to_slack_json.py (Slack notification). Lets you exercise either
script exactly the way Splunk itself would invoke it (a JSON payload on
stdin, "--execute" on argv), WITHOUT needing a live Splunk instance, a
correlation search, or a real notable.

This is deliberately built to test the *configured* alert action, not a
hand-rolled stand-in for it: by default it reads the real
default/alert_actions.conf shipped in this app and uses that stanza's
own param.* values (additional_fields template, delivery_method,
model, realms, etc.) as the "configuration" object of the payload -
the same values Splunk would substitute in for param.<key> when it
invokes the script for real. --override lets you tweak individual
values on top of that (e.g. to point at a different model, or flip
test_connectivity on) without editing alert_actions.conf itself.

Two ways to use it:

  1. --dry-run: build the Splunk-style payload AND the envelope
     ta_common.build_payload() would construct from it (with
     $result.<field>$/$job.<field>$ tokens substituted and
     additional_fields JSON-parsed) - all pure/local, no network calls,
     no credentials required. Use this to sanity check that your
     alert_actions.conf additional_fields template is valid JSON and
     that your tokens substitute the way you expect, before ever
     touching a live credential.

  2. Real invocation: pipes the payload to the actual script via
     subprocess, exactly like Splunk does, and shows you the exit code,
     stdout/stderr, and (with --show-log) the tail of that script's own
     log file. This DOES make real Slack/Perplexity API calls if
     credentials resolve (plaintext override or a real
     --server-uri/--session-key pointed at a live Splunk vault) - same
     as a real notable firing.

Examples
--------
Dry run - just check the config/template, no network calls at all:
    python3 test_harness.py perplexity --dry-run

Real connectivity test (side-effect-free on the Perplexity/Slack side,
same as `| makeresults | sendalert ... param.test_connectivity=1`, but
runnable straight from a laptop with no Splunk instance needed):
    python3 test_harness.py perplexity --test-connectivity \\
        --override perplexity_api_key=pplx-...
    python3 test_harness.py slack --test-connectivity \\
        --override slack_bot_token=xoxb-...

Full run against a real credential, overriding one event field and
showing the resulting log file:
    python3 test_harness.py perplexity \\
        --override perplexity_api_key=pplx-... \\
        --field repo=some-org/some-repo --field user=jdoe --field src=1.2.3.4 \\
        --show-log

Run BOTH actions back to back with the same event fields, to compare
what each produces from the identical envelope:
    python3 test_harness.py both --field repo=octocat/Hello-World --dry-run

Point at a real Splunk instance's credential vault instead of a
plaintext override (mirrors production exactly, vault realm and all):
    python3 test_harness.py perplexity \\
        --server-uri https://splunk.example.com:8089 --session-key <key>
--------------------------------------------------------------------
"""
import argparse
import configparser
import json
import logging
import os
import subprocess
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
APP_ROOT = os.path.dirname(SCRIPT_DIR)
DEFAULT_CONF_PATH = os.path.join(APP_ROOT, "default", "alert_actions.conf")
DEFAULT_SPLUNK_HOME = os.path.join(APP_ROOT, ".test_harness_home")

# Maps the harness's short CLI names to the actual alert_actions.conf
# stanza name / bin/<stanza>.py filename (they're identical, kept as a
# dict anyway so the CLI can offer friendlier --help text and so "both"
# has a stable iteration order: agentic action first, then Slack).
ACTIONS = {
    "perplexity": "notable_to_perplexity_json",
    "slack": "notable_to_slack_json",
}

# A representative sample notable row. Deliberately matches the token
# names the shipped default param.additional_fields template references
# ($result.repo$/$result.user$/$result.src$) so a --dry-run or real run
# against the STOCK config substitutes something meaningful out of the
# box; override any of these with --field or replace the whole row with
# --result-file.
DEFAULT_ROW = {
    "event_id": "5B2F1B0A-0000-0000-0000-TESTHARNESS01",
    "_time": str(int(time.time())),
    "rule_name": "Test Harness Sample Finding",
    "search_name": "Test Harness Sample Finding",
    "repo": "UnshakeableSaltLtd/SplunkConf",
    "user": "dpollard",
    "src": "203.0.113.42",
    "dest": "10.0.0.5",
    "signature": "Sample Finding (test_harness.py)",
    "urgency": "medium",
}


def parse_kv_pairs(pairs, label):
    result = {}
    for pair in pairs:
        if "=" not in pair:
            raise SystemExit(f"Invalid {label} '{pair}' - expected KEY=VALUE")
        key, value = pair.split("=", 1)
        result[key.strip()] = value
    return result


def load_stanza_config(conf_path, stanza):
    """Read default/alert_actions.conf and return the param.* values for
    the given stanza as a flat dict with the 'param.' prefix stripped -
    exactly the shape Splunk hands each script as payload['configuration'].
    Non-param.* keys (is_custom, label, icon_path, alert.execute.cmd, ...)
    are intentionally dropped; Splunk itself never puts those in
    'configuration' either."""
    if not os.path.exists(conf_path):
        raise SystemExit(f"Conf file not found: {conf_path}")
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str  # preserve exact key case (Splunk conf keys are case-sensitive)
    with open(conf_path, "r", encoding="utf-8") as fh:
        parser.read_file(fh)
    if stanza not in parser:
        available = ", ".join(s for s in parser.sections() if s != "default")
        raise SystemExit(f"Stanza [{stanza}] not found in {conf_path}. Available: {available}")
    cfg = {}
    for key, value in parser[stanza].items():
        if key.startswith("param."):
            cfg[key[len("param."):]] = value
    return cfg


def build_job_dict(payload):
    """Mirrors the `job = {...}` dict each script itself builds from the
    raw payload before calling ta_common.build_payload() - kept in sync
    manually since it's only a few fields; if notable_to_perplexity_json.py
    or notable_to_slack_json.py ever add a new job.* field, add it here too
    so --dry-run's envelope preview stays accurate."""
    return {
        "search_name": payload.get("search_name"),
        "sid": payload.get("sid"),
        "app": payload.get("app"),
        "owner": payload.get("owner"),
        "results_link": payload.get("results_link"),
        "server_host": payload.get("server_host"),
    }


def make_null_logger():
    logger = logging.getLogger("test_harness.dry_run")
    if not logger.handlers:
        logger.addHandler(logging.NullHandler())
    logger.setLevel(logging.CRITICAL)
    return logger


def run_dry_run(stanza, payload, cfg):
    sys.path.insert(0, SCRIPT_DIR)
    import ta_common  # noqa: E402  (local import so --dry-run needs no Splunk env at all)

    print(f"\n=== [{stanza}] Payload that would be piped to bin/{stanza}.py --execute on stdin ===")
    print(json.dumps(payload, indent=2, default=str))

    print(f"\n=== [{stanza}] Envelope ta_common.build_payload() would construct ===")
    print("(this is what gets sent to Perplexity as context / posted to Slack / written to the notable+KV store)")
    job = build_job_dict(payload)
    log = make_null_logger()
    try:
        envelope = ta_common.build_payload(payload["result"], job, cfg, log, stanza)
        print(json.dumps(envelope, indent=2, default=str))
        additional = envelope.get("additional_fields", {})
        if "_parse_error" in additional:
            print(
                f"\n!! additional_fields failed to parse as JSON after token substitution: "
                f"{additional['_parse_error']}"
            )
            print("   Raw substituted text was:")
            print(f"   {additional.get('_additional_fields_raw', '')}")
        else:
            print(f"\nadditional_fields parsed OK - top-level keys: {list(additional.keys())}")
    except Exception as e:
        print(f"\n!! Failed to build envelope: {e!r}")
    print()


def run_real(stanza, payload, splunk_home, show_log, log_lines):
    script_path = os.path.join(SCRIPT_DIR, f"{stanza}.py")
    if not os.path.exists(script_path):
        raise SystemExit(f"Script not found: {script_path}")

    log_dir = os.path.join(splunk_home, "var", "log", "splunk")
    os.makedirs(log_dir, exist_ok=True)
    env = os.environ.copy()
    env["SPLUNK_HOME"] = splunk_home

    print(f"\n=== [{stanza}] Invoking bin/{stanza}.py --execute (SPLUNK_HOME={splunk_home}) ===")
    proc = subprocess.run(
        [sys.executable, script_path, "--execute"],
        input=json.dumps(payload).encode("utf-8"),
        capture_output=True,
        env=env,
    )
    print(f"exit code: {proc.returncode}")
    stdout = proc.stdout.decode("utf-8", errors="replace")
    stderr = proc.stderr.decode("utf-8", errors="replace")
    if stdout.strip():
        print("--- stdout ---")
        print(stdout)
    if stderr.strip():
        print("--- stderr ---")
        print(stderr)

    if show_log:
        log_path = os.path.join(log_dir, f"{stanza}.log")
        print(f"--- tail of {log_path} ---")
        if os.path.exists(log_path):
            with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
            for line in lines[-log_lines:]:
                print(line, end="")
        else:
            print("(no log file written - check exit code/stderr above for why)")
    print()
    return proc.returncode


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Send a Splunk-alert-action-style JSON payload to notable_to_perplexity_json.py "
            "and/or notable_to_slack_json.py, exactly as Splunk itself would invoke them, so "
            "the app's config (alert_actions.conf) can be tested without a live Splunk instance."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "action", choices=["perplexity", "slack", "both"],
        help="Which alert action to invoke: 'perplexity' (notable_to_perplexity_json, agentic), "
        "'slack' (notable_to_slack_json, ES-findings notification), or 'both' (runs perplexity "
        "then slack with the same event fields).",
    )
    parser.add_argument(
        "--conf", default=DEFAULT_CONF_PATH,
        help=f"Path to alert_actions.conf to read param.* defaults from (default: {DEFAULT_CONF_PATH})",
    )
    parser.add_argument(
        "--override", action="append", default=[], metavar="KEY=VALUE",
        help="Override/add a configuration value (param.* name WITHOUT the 'param.' prefix, e.g. "
        "--override perplexity_preset=pro-search, or --override perplexity_model=openai/gpt-5.6-sol "
        "to pin an exact model). Repeatable. Applied on top of the conf file.",
    )
    parser.add_argument(
        "--field", action="append", default=[], metavar="KEY=VALUE",
        help="Override/add a field on the sample triggering event row (e.g. --override "
        "would touch configuration; this touches the notable's OWN fields, e.g. --field "
        "repo=my-org/my-repo). Repeatable. Applied on top of the built-in sample row.",
    )
    parser.add_argument(
        "--result-file", default=None,
        help="Path to a JSON file containing the full 'result' row dict, replacing the built-in "
        "sample row wholesale (--field overrides still apply on top of it).",
    )
    parser.add_argument("--sid", default=None, help="Search job SID (default: auto-generated).")
    parser.add_argument("--search-name", default=None, help="Correlation search name (default: 'Test Harness Sample Finding').")
    parser.add_argument("--app", default="search", help="Splunk app context (default: search).")
    parser.add_argument("--owner", default="admin", help="Search owner (default: admin).")
    parser.add_argument("--results-link", default="", help="results_link field to include in the payload.")
    parser.add_argument("--server-host", default="localhost", help="server_host field to include in the payload.")
    parser.add_argument(
        "--server-uri", default="https://localhost:8089",
        help="server_uri for storage/passwords + notable_update/KV store REST calls. Point this "
        "at a real Splunk instance (with --session-key) to exercise vault-realm credential "
        "resolution and real write-back; otherwise those calls will fail (harmlessly - both "
        "scripts already catch and log these) unless you use plaintext credential overrides.",
    )
    parser.add_argument(
        "--session-key", default="",
        help="Splunk session key to pair with --server-uri for real REST calls (vault lookup, "
        "notable comment write-back, KV store write-back). Leave blank to skip all of that and "
        "only exercise the Perplexity/Slack API calls (works with plaintext --override credentials).",
    )
    parser.add_argument(
        "--test-connectivity", action="store_true",
        help="Shorthand for --override test_connectivity=1 - runs the action's side-effect-free "
        "credential check (no rows processed, nothing posted/written back) instead of a normal run.",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Build and print the payload plus the constructed envelope (additional_fields tokens "
        "substituted and JSON-parsed) without invoking the script at all - no network/API calls, "
        "no credentials needed, no SPLUNK_HOME required. Use this to validate alert_actions.conf's "
        "additional_fields template and token substitution before touching real credentials.",
    )
    parser.add_argument(
        "--show-log", action="store_true",
        help="After a real invocation, print the tail of that action's own log file "
        "($SPLUNK_HOME/var/log/splunk/<stanza>.log).",
    )
    parser.add_argument("--log-lines", type=int, default=40, help="Number of log lines to show with --show-log (default: 40).")
    parser.add_argument(
        "--splunk-home", default=DEFAULT_SPLUNK_HOME,
        help=f"SPLUNK_HOME to export for the subprocess (controls where logs land and where "
        f"cim_actions.py would be looked for, harmlessly absent here). Default: a throwaway "
        f"directory at {DEFAULT_SPLUNK_HOME} (already covered by this repo's .gitignore via its "
        f"'var/' rule), auto-created on first use.",
    )
    args = parser.parse_args()

    override_cfg = parse_kv_pairs(args.override, "--override")
    field_overrides = parse_kv_pairs(args.field, "--field")

    row = dict(DEFAULT_ROW)
    if args.result_file:
        with open(args.result_file, "r", encoding="utf-8") as fh:
            row.update(json.load(fh))
    row.update(field_overrides)

    actions_to_run = list(ACTIONS.keys()) if args.action == "both" else [args.action]

    overall_rc = 0
    for action_key in actions_to_run:
        stanza = ACTIONS[action_key]
        cfg = load_stanza_config(args.conf, stanza)
        cfg.update(override_cfg)
        if args.test_connectivity:
            cfg["test_connectivity"] = "1"

        sid = args.sid or f"test-harness-{stanza}-{int(time.time())}"
        search_name = args.search_name or "Test Harness Sample Finding"
        payload = {
            "sid": sid,
            "search_name": search_name,
            "app": args.app,
            "owner": args.owner,
            "results_link": args.results_link,
            "server_host": args.server_host,
            "server_uri": args.server_uri,
            "session_key": args.session_key,
            "result": row,
            "configuration": cfg,
        }

        if args.dry_run:
            run_dry_run(stanza, payload, cfg)
        else:
            rc = run_real(stanza, payload, args.splunk_home, args.show_log, args.log_lines)
            overall_rc = overall_rc or rc

    sys.exit(0 if args.dry_run else overall_rc)


if __name__ == "__main__":
    main()
