# Splunk Apps and Add-ons

This directory contains Splunk Apps and Technology Add-ons (TAs) that accompany the .Conf presentation materials.

## Structure

Each app or add-on lives in its own subdirectory following the standard Splunk app layout:

```
apps/<app-name>/
├── README.md              # App overview, install instructions, release notes
├── default/
│   ├── app.conf           # App metadata (name, version, description)
│   ├── transforms.conf    # Field transforms, lookups
│   ├── props.conf         # Source type definitions
│   └── ...
├── metadata/
│   └── default.meta       # Object-level permissions
├── bin/                   # Scripts called by the app
│   ├── *.py               # Python scripts (Splunk SDK / REST API)
│   ├── *.sh               # Bash helper scripts
│   └── *.ps1              # PowerShell scripts
└── lookups/               # Static lookup files (CSV)
```

## Available Apps

| App / Add-on | Description | Associated Session |
|---|---|---|
| _(none yet)_ | — | — |

## Installation

1. Download or clone this repository
2. Copy the desired app folder into `$SPLUNK_HOME/etc/apps/`
3. Restart Splunk or use the Splunk UI to reload the app

## Packaging

Packaged `.spl` archives are distributed via [GitHub Releases](../../releases) and are excluded from source control by `.gitignore`.
