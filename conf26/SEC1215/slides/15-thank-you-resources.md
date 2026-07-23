# Thank You — Take the Code, Not Just the Slides

**Everything shown today is open source:**
[github.com/UnshakeableSaltLtd/SplunkConf](https://github.com/UnshakeableSaltLtd/SplunkConf/tree/main/conf26/SEC1215)

- Session narrative & architecture — [`SEC1215/ARCHITECTURE.md`](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/SEC1215/ARCHITECTURE.md)
- The shipped Splunk app — [`TA_ResponseActions/`](https://github.com/UnshakeableSaltLtd/SplunkConf/tree/main/conf26/TA_ResponseActions) (v1.3.2)
- Splunk platform docs — [docs.splunk.com](https://docs.splunk.com)

**David Pollard** — Unshakeable Salt Ltd

Questions?

## Speakers Notes

Closing slide — keep this short, the goal is to get to Q&A with time left in a 20-minute
slot. Restate in one sentence: "clone the repo, the app is versioned, documented, and the
architecture doc explains every decision — including the mistakes." That last clause
(pitfalls, slides 12–13) is deliberate: it's what makes this talk different from a vendor
demo, and worth repeating here as the final impression.

Full resource list to have ready if asked, all live in the repo:

- Session README: [SEC1215/README.md](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/SEC1215/README.md)
- Original submission text: [SEC1215/SEC1215.md](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/SEC1215/SEC1215.md)
- App install/config guide: [TA_ResponseActions/README.md § Installation](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/TA_ResponseActions/README.md#installation)
- Risk Analysis framework (Phase 2 background): [dev.splunk.com](https://dev.splunk.com/enterprise/docs/devtools/enterprisesecurity/riskanalysisframework)
- CIM Risk data model reference: [dev.splunk.com](https://dev.splunk.com/view/enterprise-security/SP-CAAAFBM)
- Notable Event API reference: [help.splunk.com](https://help.splunk.com/en/splunk-enterprise-security-7/api-reference/7.3/notable-event-endpoints/notable-event-api-reference)
- Splunk general documentation: [docs.splunk.com](https://docs.splunk.com)

If someone asks "can I see this live/on video" and a recording exists, point to the session
recording link in [SEC1215/README.md § Resources](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/SEC1215/README.md#resources)
(placeholder until .Conf26 publishes it).

Invite people to open issues/PRs against the repo directly if they try this pattern and hit
something not covered by the four documented pitfalls — that's the most useful outcome this
talk could produce.
