# What You'll Walk Away With

- **Takeaway 1** — Choose the right LLM for SecOps: balancing cost, latency, privacy, and
  capability without defaulting to the biggest name.
- **Takeaway 2** — A repeatable pattern to integrate agentic workflows into Splunk ES: what to
  build yourself vs. what Splunk gives you for free.
- **Takeaway 3** — Avoid the top pitfalls: a prioritised starting framework for teams with
  limited time and budget to reach value fast.

Structure: one real architecture (three phases, all shipped) → a live look at each phase →
the pitfalls we hit building it, so you don't have to.

## Speakers Notes

These three takeaways come directly from the session abstract and are the spine of the
whole talk — every section maps back to one of them, and slide 14 closes by revisiting all
three explicitly. Source: [SEC1215.md](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/SEC1215/SEC1215.md).

Set expectations here: this isn't a roadmap or a vision talk. Everything shown from here on
is code that exists today in a public GitHub repo, currently at version 1.3.2 of the Splunk
app that implements it — [`TA_ResponseActions`](https://github.com/UnshakeableSaltLtd/SplunkConf/tree/main/conf26/TA_ResponseActions).
The architecture narrative behind it is written up in full in
[ARCHITECTURE.md](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/SEC1215/ARCHITECTURE.md),
which this deck follows section by section.
