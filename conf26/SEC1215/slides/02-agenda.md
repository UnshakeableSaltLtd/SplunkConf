# What You'll Walk Away With

- **Takeaway 1** — Choose the right LLM for SecOps: balancing cost, latency, privacy, and
  capability without defaulting to the biggest name.
- **Takeaway 2** — A repeatable pattern to integrate agentic workflows into Splunk ES: what to
  build yourself vs. what Splunk gives you for free.
- **Takeaway 3** — Avoid the top pitfalls: a prioritised starting framework for teams with
  limited time and budget to reach value fast.

Structure: one real architecture, built twice — what we shipped first, what it taught us, and
the simpler version running today → a live look at each phase → the pitfalls that drove the
rebuild, so you don't have to hit them yourself.

## Speakers Notes

These three takeaways come directly from the session abstract and are the spine of the
whole talk — every section maps back to one of them, and slide 14 closes by revisiting all
three explicitly. Source: [SEC1215.md](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/SEC1215/SEC1215.md).

Set expectations here: this isn't a roadmap or a vision talk. Everything shown from here on
is code that exists today in a public GitHub repo, currently at version 1.3.3 of the Splunk
app that implements it — [`TA_ResponseActions`](https://github.com/UnshakeableSaltLtd/SplunkConf/tree/main/conf26/TA_ResponseActions).
Worth flagging up front: 1.3.3 isn't the first design that shipped. An earlier version
(1.3.1–1.3.2) worked end to end and was still replaced once its operational cost became
clear — that's not a failure story, it's the Takeaway 3 story: build, learn fast, react,
and trust the platform enough to remove what turns out to be unnecessary. The architecture
narrative behind both versions is written up in full in
[ARCHITECTURE.md](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/SEC1215/ARCHITECTURE.md),
which this deck follows section by section.
