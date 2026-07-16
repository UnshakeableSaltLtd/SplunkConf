# Contributing

Thank you for your interest in contributing to this Splunk .Conf repository.

## How to Contribute

### Reporting Issues

If you find an error in a presentation, a bug in demo code, or have a suggestion, please [open an issue](../../issues) with:

- A clear title and description
- The session or file affected
- Steps to reproduce (for bugs in scripts or apps)

### Submitting Changes

1. Fork this repository
2. Create a feature branch: `git checkout -b fix/session-name-correction`
3. Commit your changes with a clear message
4. Open a pull request against `main`

---

## Adding a New Conference Session

Each session lives in its own folder under the relevant conference year directory (`conf25/`, `conf26/`, etc.).

### Folder Convention

```
confYY/<session-slug>/
├── README.md         # Required — session abstract, speaker bio, links
├── slides/           # Presentation slides (PDF preferred; PPTX also welcome)
├── demos/            # All demo scripts and code
│   ├── *.py          # Python demos
│   ├── *.sh          # Bash demos
│   └── *.ps1         # PowerShell demos
└── images/           # Diagrams and screenshots referenced in the README
```

### Session README Template

Each session `README.md` should include:

```markdown
# <Session Title>

**Event:** Splunk .Conf<YY>  
**Date:** <Month YYYY>  
**Speaker:** <Name>  
**Session ID:** <Splunk .Conf session ID if applicable>

## Abstract

<Session abstract>

## Contents

| File / Folder | Description |
|---|---|
| `slides/` | Presentation slides |
| `demos/` | Demo scripts and code |

## Prerequisites

List any prerequisites needed to run the demos.

## Running the Demos

Step-by-step instructions for running the demo code.

## Resources

- [Splunk Documentation](https://docs.splunk.com)
- [Session recording](link if available)
```

---

## Adding a Splunk App or Add-on

Splunk Apps and Add-ons live under the top-level `apps/` directory and follow the standard Splunk app directory layout:

```
apps/<app-name>/
├── README.md
├── default/
│   ├── app.conf
│   ├── transforms.conf
│   └── ...
├── metadata/
│   └── default.meta
├── bin/                  # Scripts used by the app
│   ├── *.py
│   ├── *.sh
│   └── *.ps1
└── lookups/
```

### Packaging

Do **not** commit packaged `.spl` archives to the repository — these are excluded by `.gitignore`. Release packages should be attached to GitHub Releases.

---

## Code Style

- **Python** — Follow PEP 8. Use a `requirements.txt` or `pyproject.toml` if the demo has dependencies.
- **Bash** — Use `#!/usr/bin/env bash` and `set -euo pipefail`.
- **PowerShell** — Use approved verbs for functions; target PowerShell 5.1+ compatibility where possible.

---

## License

By contributing to this repository, you agree that your contributions will be licensed under the [Creative Commons Attribution 4.0 International License](https://creativecommons.org/licenses/by/4.0/).
