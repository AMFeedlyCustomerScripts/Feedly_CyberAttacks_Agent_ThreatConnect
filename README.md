# Feedly CyberAttacks Agent → ThreatConnect Integration

A standalone Python script that continuously pulls cyber attack intelligence
from a saved **Feedly Cyberattacks Agent** view and pushes it into
**ThreatConnect** as Incident Groups — with associated Adversary, Malware and
Vulnerability Groups — via the v3 REST API.

Companion integration: [Feedly Vulnerability Agent → ThreatConnect](https://github.com/AMFeedlyCustomerScripts/Feedly_Vulnerability_Agent_ThreatConnect)
(incidents associate to its Vulnerability Groups via shared CVE names).

The Cyberattacks Agent is a dashboard
product served by a POST endpoint
(`/v3/ml/relationships/cyber-attacks/dashboard/table`), not a stream, so the
app cannot reach it. This script ingests the Agent's structured intelligence
directly: victim organization/country/industry, attack types, attack date,
timeline, analyst so-what summaries, and threat actor / malware / CVE
relationships.

## Designed for evolving Agent configurations

Your saved Agent view is provided as a **JSON file that the script sends to
Feedly verbatim** (only the pagination `continuation` token is injected). This
means:

- You keep refining the Agent in the Feedly UI while the sync runs.
- When the configuration changes, re-export the JSON, overwrite the view file,
  and you're done — **no code changes, no restart**.
- In daemon mode the view file is **re-read at the start of every cycle**; the
  log prints a config hash so you can confirm an update was picked up.
- Response parsing is defensive (multiple candidate key names per field), so
  payload structure drift degrades gracefully instead of breaking the sync.

## Setup

```bash
pip install -r requirements.txt
cp config.yaml.template config.yaml
cp cyber_attacks_agent_view.json.template cyber_attacks_agent_view.json
```

Credentials via environment variables or a `.env` file next to the script:

```bash
# Feedly
FEEDLY_API_KEY=your_feedly_enterprise_token

# ThreatConnect (HMAC pair ...)
TC_API_URL=https://app.threatconnect.com
TC_ACCESS_ID=your_access_id
TC_SECRET_KEY=your_secret_key
TC_OWNER=Your Organization

# ... or an API token instead of the HMAC pair
TC_API_TOKEN=your_api_token
```

## Exporting your Agent view JSON

1. Open your saved Cyberattacks Agent view in Feedly.
2. Open the browser developer tools → **Network** tab and reload the view.
3. Find the POST request to `cyber-attacks/dashboard/table`.
4. Copy the **request payload** (right-click → Copy → Copy payload / request
   body) and save it as `cyber_attacks_agent_view.json`.
5. Repeat whenever you change the Agent configuration — the running sync picks
   the new file up on its next cycle.

The shipped template (ransomware attacks over the last 7 days) is a verified
working example:

```json
{
  "period": {"type": "Last7Days", "label": "Last7Days"},
  "layers": [{"filters": [{"field": "attackType", "value": "Ransomware"}]}]
}
```

## Usage

Always preview first:

```bash
python feedly_cyberattacks_agent_threatconnect.py --dry-run -v
```

Inspect the raw Agent records without touching ThreatConnect:

```bash
python feedly_cyberattacks_agent_threatconnect.py --dry-run --output records.json
```

One-shot sync:

```bash
python feedly_cyberattacks_agent_threatconnect.py --tc-owner "My Org"
```

Continuous sync (hourly):

```bash
python feedly_cyberattacks_agent_threatconnect.py --daemon --interval 60
```

Or schedule one-shot runs with cron instead of daemon mode:

```cron
30 * * * * cd /opt/feedly-tc && python3 feedly_cyberattacks_agent_threatconnect.py >> cron.log 2>&1
```

## ThreatConnect mapping

- **Name**: attack title; **Event Date**: attack date; **Status**: New
- **Description attribute**: full structured summary (overview, what /
  so-what / latest-activity analyst notes, attack types, victims, timeline,
  related CVEs, references) — always written, so nothing is lost if custom
  attribute types are missing
- **Custom attributes** (optional): `Attack Type`, `Victim Organization`,
  `Victim Country`, `Victim Industry`, `Attack Timeline`
- **Associations**: Adversary Groups (threat actors), Malware Groups, and
  Vulnerability Groups (related CVEs), created/matched by name in the same
  request (disable with `--no-associations`)
- **Tags**: `Feedly`, `Feedly Cyberattacks Agent`, one tag per attack type

### Custom attribute types

The structured attributes require matching **attribute types** to exist in
your ThreatConnect owner for the Incident group type (Organization Settings →
Attribute Types). If a type doesn't exist, ThreatConnect rejects that
attribute, the script logs it and moves on — the same data is always present
in the Description. To use different type names, remap them under
`threatconnect.attribute_mapping` in `config.yaml`, or disable the attempt
entirely with `--no-custom-attributes`.

## Deduplication and updates

The script keeps a state file (`feedly_tc_cyberattacks_state.json`) mapping
Feedly attack IDs to ThreatConnect group IDs. On every cycle, known records
are **updated** in place (or skipped with `--skip-existing`); unknown records
are also checked by exact name in ThreatConnect before creation, so re-running
never duplicates groups. Delete the state file to force a full re-evaluation.

## Files

- `feedly_cyberattacks_agent_threatconnect.py` — the integration script
- `cyber_attacks_agent_view.json.template` — example Cyberattacks Agent view payload
- `config.yaml.template` — optional YAML configuration
- `requirements.txt` — Python dependencies (`requests`, `PyYAML`)

## Testing checklist

1. `--dry-run` first, with `-v` for full payload previews.
2. `--dry-run --output records.json` to inspect exactly what the Agent returns
   for your view.
3. Sync into a test/sandbox ThreatConnect owner before production.
