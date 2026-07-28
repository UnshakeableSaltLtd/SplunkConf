# Takeaway 3: Pitfalls We Hit — Part 2

**Pitfall 3 — Solved once, then solved properly: LLM reply-format drift.**
Free-text answers to the original standing checks were unparseable. The first fix: pin the
required JSON shape into the *prompt itself* (`perplexity_ask.reply_format`) and have the
bridge **log-and-skip, not crash**, on anything that still didn't parse. It worked, but it
was still prose the model *chose* to format correctly. v1.3.3's fix goes one layer deeper:
the Perplexity API's own `response_format` (JSON Schema) constrains the output structurally
— there's no prose to parse, and no reply-format instruction competing for prompt space
with the actual questions.

**Pitfall 4 — Fully retired: the scripted-input overhead is gone because the scripted input
is gone.** `slack_hec_bridge.py` was a plain classic scripted input, not a full
`splunklib.modularinput` scheme — no auto-generated Splunk Web settings page for its custom
keys, hand-edited `local/inputs.conf` instead. That trade-off didn't get fixed with a better
input scheme; the team looked at the whole component and decided the poller itself wasn't
earning its keep. v1.3.3 has one credential realm, one log file, made by the process that
was already running — this is the single clearest "we reacted fast once we saw the
operational cost" moment in the whole build.

## Speakers Notes

Source for both, verbatim from the architecture doc:
[ARCHITECTURE.md § Lesson: the Slack to HEC bridge, retired](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/SEC1215/ARCHITECTURE.md#lesson-the-slack-to-hec-bridge-retired).

**Pitfall 3 detail:** this is the direct payback for slide 8's design — tell the story as
"we tried it the naive way first" (just ask the AI to answer the checks, parse whatever
comes back) "and it didn't work reliably enough to trust." The interim fix that shipped in
v1.3.1: `reply_format` pinned into `alert_actions.conf`'s `perplexity_ask.additional_fields`
block, instructing the AI to "Reply in this thread with ONLY a single JSON object, no prose
before or after it." Reinforce the resilience point from slide 9 as a real, credited
engineering decision at the time: a parse failure never crashed the poller, it just left
`awaiting_ai_response=1` so nothing silently vanished. Then land the actual pivot: once the
team was already deep in "how do we make an LLM reliably emit JSON," someone noticed
Perplexity's own API already solves exactly that problem as a first-class feature —
`response_format` — and trusting that feature made the prompt-pinning workaround
unnecessary entirely. That's the react-fast beat: don't keep polishing the workaround once
you've spotted the platform already had the answer.

**Pitfall 4 detail:** be honest that the original scripted-input choice was a deliberate,
considered trade-off, not a shortcut taken by accident — flag it as a decision point every
team building something similar will face. Classic scripted inputs are faster to ship for a
single internal component with one maintainer; full modular inputs pay off once you need
Splunk Web's config UI, validation, and multi-instance/clustering-aware input management for
something other people will configure. What actually happened here, though, is a step
further than "we'd pick modular input next time": once Phase 2/3 collapsed into a
synchronous in-process call, there was no poller left to configure at all — the entire
class of problem ("how do we expose this scripted input's settings nicely") disappeared
along with the component. Emphasise this as the clearest example in the whole talk of
reacting to a pitfall by removing its cause rather than mitigating it.

Closing line for this pair of slides, before moving to the recap: "none of these four came
from being careless — they came from actually shipping something and paying attention. Two
of them we fixed in place; two of them we fixed by trusting the platform enough to delete
the workaround. That's the whole talk in one sentence."
