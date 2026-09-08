#!/usr/bin/env python3
"""
notable_to_perplexity_json.py
--------------------------------------------------------------------
Splunk Enterprise Security custom Adaptive Response Action.

AGENTIC RESPONSE FLOW ONLY - this action has NO Slack objects, params,
or delivery of any kind (see notable_to_slack_json.py for that; the
two were split into separate actions in v1.4.0 so the agentic loop and
the human-notification channel can be enabled/disabled/rotated
independently - see README.md's 1.4.0 release notes).

If a "perplexity_ask" object is present in additional_fields (see the
default param.additional_fields template), this action calls the
Perplexity API synchronously, right here: each ask question is
answered and the resulting "perplexity_response" object (same keys,
plus "overall") is merged into additional_fields alongside the ask.
An earlier iteration of this integration used a separate scripted
input (bin/slack_hec_bridge.py) that polled a KV store output, read
the AI's reply back out of a Slack thread, and posted a CIM Risk event
to HEC - see conf26/SEC1215/lessons/ for that retired design, kept only
as a historical/lessons-learned reference; it added real operational
overhead (polling interval, thread-ts plumbing, reply-format drift) to
answer questions this action already has all the context for at send
time.

After processing, the action writes back to the SAME notable so
analysts see the result alongside the rest of the event in Incident
Review:
  1. cim_actions.ModularAction.message() -> native "Adaptive Responses"
     panel / "View Adaptive Response Invocations" audit trail.
  2. /services/notable_update comment -> a permanent entry in that
     notable's own Activity/comment timeline (the perplexity_ask/
     perplexity_response pair).
  3. notable_agentic_enrichment KV store record -> structured fields
     surfaced via the SAME custom drilldown notable_to_slack_json.py
     also writes to (delivery_method is set to "perplexity_api" and
     the Slack-specific fields are left blank on this action's records).

Install at:
  $SPLUNK_HOME/etc/apps/TA_ResponseActions/bin/notable_to_perplexity_json.py

Contract: Splunk invokes this script as:
  notable_to_perplexity_json.py --execute
and writes the alert configuration payload (JSON) to stdin.
See: https://dev.splunk.com/enterprise/docs/devtools/customalertactions/writescriptcaa
--------------------------------------------------------------------
"""
import json
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ta_common  # noqa: E402

APP_NAME = "notable_to_perplexity_json"
log = ta_common.setup_logging(APP_NAME)


def main():
    if len(sys.argv) < 2 or sys.argv[1] != "--execute":
        # This is the ONLY place this script exits 1. Every other failure path
        # (bad JSON, credential lookup, API auth) exits 2 or 3 - so 1 always
        # means Splunk did not invoke this script with the standard custom
        # alert action contract (script --execute, payload JSON on stdin).
        # Log full invocation context unconditionally so this is diagnosable
        # from the log file alone, without needing Job Inspector access -
        # added in 1.4.4 after a fresh-build "error code 1" that could only
        # be root-caused from search.log at the time (see README 1.4.4 notes).
        try:
            log.error(
                "FATAL invocation contract violation: expected argv[1]=='--execute', "
                "got argv=%r | python=%s | executable=%s | cwd=%s | script=%s",
                sys.argv, sys.version.replace("\n", " "), sys.executable,
                os.getcwd(), os.path.abspath(__file__),
            )
        except Exception:
            pass
        sys.stderr.write("FATAL usage: notable_to_perplexity_json.py --execute\n")
        sys.exit(1)

    try:
        raw_stdin = sys.stdin.read()
        payload = json.loads(raw_stdin)
    except Exception:
        log.exception("Failed to parse payload JSON from stdin")
        sys.exit(2)

    # cim_actions.ModularAction wraps the SAME stdin payload and gives us
    # self.message() -> Incident Review's native "Adaptive Responses" panel.
    # It also deletes payload['result'] internally, so it must be built from
    # the raw JSON string, not the already-parsed `payload` dict.
    modaction = None
    if ta_common.ModularAction is not None:
        try:
            modaction = ta_common.ModularAction(raw_stdin, log, APP_NAME)
        except Exception:
            log.exception(
                "Failed to initialize cim_actions.ModularAction; continuing "
                "without native Adaptive Response panel reporting"
            )

    cfg = payload.get("configuration", {}) or {}
    write_back_comment = (cfg.get("write_back_comment", "1")) in ("1", "true", "True")
    write_back_kvstore = (cfg.get("write_back_kvstore", "1")) in ("1", "true", "True")
    perplexity_enabled = (cfg.get("perplexity_enabled", "1")) in ("1", "true", "True")
    test_connectivity = (cfg.get("test_connectivity", "0")) in ("1", "true", "True")
    # NOTE: deliberately NOT derived from payload.get("app") - that key holds
    # the app context of the TRIGGERING saved search (e.g. "TA_AllIndexCreation",
    # "SplunkEnterpriseSecuritySuite"), which varies per correlation search and
    # is never where the notable_agentic_enrichment collection lives. The
    # collection is defined exclusively in TA_ResponseActions/default/collections.conf,
    # so the KV store REST path must always target that app regardless of which
    # app's search fired the alert - using payload["app"] here caused a 404 on
    # every write-back (Not Found under the triggering app's own namespace).
    kvstore_app = "TA_ResponseActions"

    # Unconditional heartbeat: every single invocation of this script leaves
    # this log line no matter what happens next (bad payload, no rows, an
    # unhandled exception, a crash) - so "did the alert action even run" is
    # never a question that needs guessing at from an empty/missing log file.
    log.info(
        "Invoked: sid=%s search_name=%s test_connectivity=%s perplexity_enabled=%s",
        payload.get("sid"), payload.get("search_name"), test_connectivity, perplexity_enabled,
    )

    if test_connectivity:
        # Side-effect-free credential check: no rows are loaded, nothing is
        # written back to any notable or KV store. Perplexity-only, since
        # this action has no Slack credential to test (see
        # notable_to_slack_json.py for the Slack-side test).
        perplexity_ok = None
        perplexity_detail = "skipped (perplexity_enabled=0)"
        if perplexity_enabled:
            perplexity_ok, perplexity_detail = ta_common.check_perplexity_connectivity(
                cfg, payload.get("server_uri"), payload.get("session_key"),
                payload.get("app", "search"), log,
            )
        else:
            log.warning("PERPLEXITY AUTH SKIPPED: %s", perplexity_detail)

        overall_ok = perplexity_ok is not False
        log.info(
            "test_connectivity summary: perplexity_ok=%s (%s) -> %s",
            perplexity_ok, perplexity_detail, "PASS" if overall_ok else "FAIL",
        )
        if modaction is not None:
            try:
                modaction.message(
                    f"test_connectivity: perplexity_ok={perplexity_ok}",
                    status="success" if overall_ok else "failure",
                    level=logging.INFO if overall_ok else logging.ERROR,
                )
            except Exception:
                log.exception("modaction.message() failed for test_connectivity summary")
        sys.exit(0 if overall_ok else 3)

    job = {
        "search_name": payload.get("search_name"),
        "sid": payload.get("sid"),
        "app": payload.get("app"),
        "owner": payload.get("owner"),
        "results_link": payload.get("results_link"),
        "server_host": payload.get("server_host"),
    }

    rows = ta_common.load_rows(payload)
    if not rows:
        log.warning("No result rows found in payload for sid=%s", job.get("sid"))
        sys.exit(0)

    try:
        max_events = int(cfg.get("max_events") or 5)
    except ValueError:
        max_events = 5

    failures = 0
    for i, row in enumerate(rows[:max_events]):
        envelope = ta_common.build_payload(row, job, cfg, log, APP_NAME)

        # update() sets rid/orig_sid/orig_rid so message() correlates the
        # status back to THIS specific notable row in the AR audit trail.
        if modaction is not None:
            try:
                modaction.update(
                    {
                        "rid": row.get("rid", str(i)),
                        "orig_sid": row.get("orig_sid", ""),
                        "orig_rid": row.get("orig_rid", ""),
                    }
                )
            except Exception:
                log.exception("modaction.update() failed for row=%d", i)

        # If this notable carries a "perplexity_ask" object (see the default
        # param.additional_fields template), answer it synchronously via the
        # Perplexity API and merge the result in as "perplexity_response".
        ask = (envelope.get("additional_fields") or {}).get("perplexity_ask")
        response = None
        if perplexity_enabled and ask:
            try:
                response = ta_common.get_perplexity_response(
                    ask,
                    envelope.get("notable", {}),
                    cfg,
                    payload.get("server_uri"),
                    payload.get("session_key"),
                    payload.get("app", "search"),
                    log,
                )
                if response is not None:
                    envelope["additional_fields"]["perplexity_response"] = response
            except Exception:
                log.exception("Unexpected error answering perplexity_ask for row=%d", i)

        # Success = either there was nothing to ask, asking is disabled, or
        # we got a response back. A configured-but-unanswered ask (bad/missing
        # key, API failure - already logged distinctly inside
        # get_perplexity_response) counts as a failure for THIS row.
        success = not (perplexity_enabled and ask and response is None)
        error_detail = (
            ""
            if success
            else "perplexity_ask present but perplexity_response could not be obtained "
            "(see PERPLEXITY AUTH/API FAILURE log lines above)"
        )

        log.info(
            "Processed notable sid=%s row=%d: perplexity_enabled=%s ask_present=%s "
            "response_obtained=%s -> %s",
            job.get("sid"), i, perplexity_enabled, bool(ask), response is not None,
            "success" if success else "failure",
        )

        if modaction is not None:
            try:
                modaction.message(
                    "Perplexity ask/response processed"
                    if success
                    else "Failed to obtain perplexity_response for perplexity_ask",
                    status="success" if success else "failure",
                    level=logging.INFO if success else logging.ERROR,
                )
            except Exception:
                log.exception("modaction.message() failed for row=%d", i)

        if not success:
            failures += 1

        # 2) Persisted comment on the SAME notable's own Activity trail, so
        #    the perplexity_ask/perplexity_response pair is visible with the
        #    rest of the notable in the analyst's Incident Review queue.
        if write_back_comment:
            event_id = row.get("event_id")
            if event_id:
                try:
                    ta_common.post_comment_to_notable(
                        payload.get("server_uri"),
                        payload.get("session_key"),
                        event_id,
                        # Human-readable narrative, not a single-line JSON
                        # blob - Incident Review/Mission Control renders
                        # this comment as plain text, so json.dumps() here
                        # used to show up to the analyst as raw JSON.
                        ta_common.format_perplexity_comment(
                            envelope.get("sent_at"), envelope.get("additional_fields")
                        ),
                        log,
                    )
                except Exception:
                    log.exception(
                        "Failed to write comment back to notable event_id=%s", event_id
                    )
            else:
                log.debug(
                    "No event_id on row=%d (not a notable-context invocation); "
                    "skipping notable comment write-back",
                    i,
                )

        # 3) Structured enrichment record in the SAME KV store collection
        #    notable_to_slack_json.py writes to, keyed by sid/rid so it can be
        #    reached via the drilldown_uri custom view. delivery_method is set
        #    to "perplexity_api" and the Slack-specific fields are left blank -
        #    this action never talks to Slack.
        if write_back_kvstore:
            try:
                ta_common.write_kvstore_record(
                    payload.get("server_uri"),
                    payload.get("session_key"),
                    kvstore_app,
                    {
                        "sid": job.get("sid") or "",
                        "rid": row.get("rid", str(i)),
                        "orig_sid": row.get("orig_sid", ""),
                        "orig_rid": row.get("orig_rid", ""),
                        "event_id": row.get("event_id", ""),
                        "sent_at": envelope.get("sent_at", ""),
                        "delivery_method": "perplexity_api",
                        "slack_channel": "",
                        "slack_permalink": "",
                        "additional_fields": json.dumps(
                            envelope.get("additional_fields"), default=str
                        ),
                        "status": "success" if success else "failure",
                        "error": error_detail,
                    },
                    log,
                )
            except Exception:
                log.exception("Failed to write KV store enrichment record for row=%d", i)

    sys.exit(0 if failures == 0 else 3)


if __name__ == "__main__":
    main()
