#!/usr/bin/env python3
"""
feedly_cyberattacks_agent_threatconnect.py - Feedly Cyberattacks Agent to ThreatConnect Integration

Continuously pulls cyber attack intelligence from a saved Feedly Cyberattacks
Agent view and pushes it into ThreatConnect as Incident Groups (with associated
Adversary and Malware Groups) via the ThreatConnect v3 API.

The saved Agent view configuration is provided as a JSON file (the POST body of
the Cyberattacks Agent dashboard request, endpoint
/v3/ml/relationships/cyber-attacks/dashboard/table). The script sends that JSON
verbatim to the Feedly API, so the customer can refine their Agent
configuration in the Feedly UI, re-export the JSON, and the next sync cycle
picks it up automatically -- no code changes required. In daemon mode the view
file is re-read on every cycle.

Supports:
  - Pass-through saved view JSON via --agent-view (re-loaded every cycle)
  - Paginated retrieval via the continuation token
  - Mapping to ThreatConnect Incident Groups with victim, attack type and
    timeline data as attributes + tags
  - Associated Adversary Groups (threat actors) and Malware Groups
  - Deduplication via persisted state (Feedly attack ID -> ThreatConnect group ID)
  - Daemon mode for automated scheduled pulls
  - HMAC (Access ID + Secret Key) or API Token authentication for ThreatConnect

© 2025 Feedly, Inc. All rights reserved.

DISCLAIMERS. THE API SCRIPTS ARE PROVIDED "AS IS" FOR YOUR INTERNAL BUSINESS
USE ONLY. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE API SCRIPTS
IS WITH YOU. YOU AGREE THAT YOUR USE OF THE API SCRIPTS WILL BE AT YOUR SOLE
RISK. TO THE FULLEST EXTENT PERMITTED BY LAW, FEEDLY DISCLAIMS ALL WARRANTIES,
EXPRESS OR IMPLIED, IN CONNECTION WITH THE API SCRIPTS AND YOUR USE THEREOF,
INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. FEEDLY MAKES NO
WARRANTIES OR REPRESENTATIONS ABOUT THE ACCURACY OR COMPLETENESS OF THE API
SCRIPTS AND NO REPRESENTATIONS THAT THE API SCRIPTS ARE NOT OTHERWISE
ENCUMBERED BY ANY THIRD PARTY LICENSE, INCLUDING ANY OPEN-SOURCE LICENSE.
FEEDLY ASSUMES NO LIABILITY OR RESPONSIBILITY FOR ANY: (1) ERRORS, MISTAKES,
OR INACCURACIES; (2) PERSONAL INJURY OR PROPERTY DAMAGE, OF ANY NATURE
WHATSOEVER, RESULTING FROM YOUR USE OF THE API SCRIPTS; (3) ANY UNAUTHORIZED
ACCESS TO OR USE OF API SCRIPTS; (4) ANY INTERRUPTION OR CESSATION OF
TRANSMISSION TO OR FROM THE API SCRIPTS; (5) ANY BUGS, VIRUSES, TROJAN HORSES,
OR THE LIKE WHICH MAY BE TRANSMITTED TO OR THROUGH THE API SCRIPTS BY ANY
THIRD PARTY; OR (6) ANY ERRORS OR OMISSIONS IN THE API SCRIPTS OR FOR ANY LOSS
OR DAMAGE OF ANY KIND INCURRED AS A RESULT OF THE USE OF THE API SCRIPTS.

LIMITATION OF LIABILITY. IN NO EVENT SHALL FEEDLY BE LIABLE FOR ANY DAMAGES.
FURTHER, IN NO EVENT SHALL FEEDLY BE LIABLE FOR ANY CONSEQUENTIAL, INCIDENTAL
OR INDIRECT DAMAGES, INCLUDING, WITHOUT LIMITATION, ANY LOSS OF DATA, OR LOSS
OF PROFITS OR LOST SAVINGS, ARISING OUT OF USE OF OR INABILITY TO USE THE
LICENSED PRODUCT, EVEN IF FEEDLY HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH
DAMAGES, OR FOR ANY CLAIM BY ANY THIRD PARTY.

YOU ACKNOWLEDGE THAT YOU HAVE READ AND UNDERSTAND THESE TERMS AND AGREE TO BE
BOUND BY THEM. YOU FURTHER AGREE THAT THESE TERMS ARE THE COMPLETE AND
EXCLUSIVE STATEMENT OF THE AGREEMENT BETWEEN YOU AND FEEDLY FOR THE USE OF THE
API SCRIPTS, AND THESE TERMS SUPERSEDE ANY PRIOR AGREEMENT, ORAL OR WRITTEN,
AND ANY OTHER COMMUNICATIONS RELATING TO THE SUBJECT MATTER HEREOF.
"""

import argparse
import base64
import copy
import hashlib
import hmac
import json
import logging
import os
import sys
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

try:
    import requests
except ImportError:
    print("Error: 'requests' library is required. Install with: pip install requests")
    sys.exit(1)

try:
    import yaml
except ImportError:
    yaml = None
    print("WARNING: PyYAML not installed. Config file loading disabled.")


# =============================================================================
# CONFIGURATION
# =============================================================================

def _read_env_file_values(keys: List[str]) -> Dict[str, str]:
    """Read selected KEY=value pairs from a .env file in cwd or script dir."""
    values: Dict[str, str] = {}
    env_locations = [
        os.path.join(os.getcwd(), ".env"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"),
    ]
    for env_path in env_locations:
        if not os.path.exists(env_path):
            continue
        try:
            with open(env_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, val = line.split("=", 1)
                    key = key.strip()
                    if key in keys and key not in values:
                        val = val.strip()
                        if (val.startswith('"') and val.endswith('"')) or \
                           (val.startswith("'") and val.endswith("'")):
                            val = val[1:-1]
                        if val:
                            values[key] = val
        except Exception:
            pass
    return values


def load_api_key() -> str:
    """
    Load Feedly API key from environment variable or .env file.
    Priority: FEEDLY_API_KEY env var > .env file > fallback placeholder
    """
    api_key = os.environ.get("FEEDLY_API_KEY")
    if api_key:
        return api_key

    values = _read_env_file_values(["FEEDLY_API_KEY"])
    return values.get("FEEDLY_API_KEY", "APIKEYHERE")


def load_threatconnect_credentials() -> Dict[str, str]:
    """
    Load ThreatConnect credentials from environment variables or .env file.

    Supported keys:
      TC_API_URL     - e.g. https://app.threatconnect.com  (no trailing slash)
      TC_ACCESS_ID   - HMAC access ID            (HMAC auth)
      TC_SECRET_KEY  - HMAC secret key           (HMAC auth)
      TC_API_TOKEN   - API token                 (token auth, alternative to HMAC)
      TC_OWNER       - target owner / organization name
    """
    keys = ["TC_API_URL", "TC_ACCESS_ID", "TC_SECRET_KEY", "TC_API_TOKEN", "TC_OWNER"]
    creds = {k: os.environ.get(k, "") for k in keys}

    file_values = _read_env_file_values(keys)
    for k in keys:
        if not creds[k]:
            creds[k] = file_values.get(k, "")

    creds["TC_API_URL"] = (creds["TC_API_URL"] or "https://app.threatconnect.com").rstrip("/")
    return creds


def load_yaml_config(config_path: str) -> Dict[str, Any]:
    """Load configuration from YAML file, returning empty dict on failure."""
    if yaml is None:
        return {}
    if not os.path.exists(config_path):
        return {}
    try:
        with open(config_path, "r") as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        logging.warning(f"Could not load config file {config_path}: {e}")
        return {}


FEEDLY_API_KEY = load_api_key()
TC_CREDS = load_threatconnect_credentials()

# API Configuration
FEEDLY_BASE_URL = "https://api.feedly.com"
CYBER_ATTACKS_ENDPOINT = "/v3/ml/relationships/cyber-attacks/dashboard/table"
MAX_RETRIES = 3
RETRY_DELAY = 2       # seconds between retry attempts
RATE_LIMIT_DELAY = 1  # seconds between successful API calls

AGENT_VIEW_FILE = "cyber_attacks_agent_view.json"
STATE_FILE = "feedly_tc_cyberattacks_state.json"

# ThreatConnect attribute type names used for the structured Agent fields.
# These must exist as attribute types for the Incident group type in the
# customer's ThreatConnect owner. Names can be remapped in config.yaml; any
# attribute ThreatConnect rejects is logged and skipped -- the same data is
# always embedded in the Description attribute as a fallback.
DEFAULT_ATTRIBUTE_MAPPING = {
    "description":     "Description",
    "source":          "Source",
    "attack_type":     "Attack Type",
    "victim_org":      "Victim Organization",
    "victim_country":  "Victim Country",
    "victim_industry": "Victim Industry",
    "timeline":        "Attack Timeline",
}

# Human-readable labels for Feedly attack type identifiers
ATTACK_TYPE_LABELS: Dict[str, str] = {
    "Ransomware":                   "Ransomware",
    "DataBreachesAndExfiltration":  "Data Breach and Exfiltration",
    "DenialOfService":              "Denial of Service",
    "PhishingAndSocialEngineering": "Phishing and Social Engineering",
    "SupplyChainAttack":            "Supply Chain Attack",
    "ZeroDay":                      "Zero-Day Exploit",
    "APT":                          "Advanced Persistent Threat",
    "Cryptojacking":                "Cryptojacking",
    "Espionage":                    "Cyber Espionage",
    "Sabotage":                     "Cyber Sabotage",
    "Wiper":                        "Wiper Attack",
    "BEC":                          "Business Email Compromise",
}


# =============================================================================
# LOGGING
# =============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("feedly_tc_cyberattacks.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger(__name__)


# =============================================================================
# FEEDLY CLIENT
# =============================================================================

class FeedlyClient:
    """Client for the Feedly Enterprise API (Cyberattacks Agent)."""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

    def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict] = None,
        body: Optional[Dict] = None,
        retries: int = MAX_RETRIES,
    ) -> Optional[Dict]:
        """Make an API request with retry logic and rate limiting."""
        url = f"{FEEDLY_BASE_URL}{endpoint}"

        for attempt in range(retries):
            try:
                response = self.session.request(
                    method, url, params=params, json=body, timeout=60,
                )

                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", RETRY_DELAY * (attempt + 1)))
                    logger.warning(f"Rate limited. Waiting {retry_after}s...")
                    time.sleep(retry_after)
                    continue

                if response.status_code == 401:
                    logger.error("Feedly authentication failed. Check your Feedly API key.")
                    return None

                if response.status_code == 403:
                    logger.error("Access forbidden. Ensure your account has Cyberattacks Agent access.")
                    return None

                if response.status_code == 404:
                    logger.error(f"Endpoint not found: {url}")
                    return None

                if response.status_code >= 400:
                    if attempt < retries - 1:
                        logger.warning(
                            f"HTTP {response.status_code} on attempt {attempt + 1}/{retries}, retrying..."
                        )
                        time.sleep(RETRY_DELAY * (attempt + 1))
                        continue
                    logger.error(f"Feedly API error {response.status_code}: {response.text[:300]}")
                    return None

                time.sleep(RATE_LIMIT_DELAY)
                return response.json()

            except requests.exceptions.RequestException as e:
                if attempt < retries - 1:
                    logger.warning(f"Request error, retrying ({attempt + 1}/{retries}): {e}")
                    time.sleep(RETRY_DELAY * (attempt + 1))
                    continue
                logger.error(f"Feedly request failed after {retries} attempts: {e}")
                return None

        return None

    def fetch_agent_page(
        self,
        view_payload: Dict,
        continuation: Optional[str] = None,
    ) -> Optional[Dict]:
        """
        Fetch one page from the Cyberattacks Agent using the customer's saved
        view JSON as the POST body, verbatim. Only the continuation token is
        injected for pagination -- the view payload itself is never modified, so
        whatever the customer exports from their Agent configuration is exactly
        what Feedly receives.
        """
        body = copy.deepcopy(view_payload)
        if continuation:
            body["continuation"] = continuation
        return self._request("POST", CYBER_ATTACKS_ENDPOINT, body=body)

    def fetch_all(
        self,
        view_payload: Dict,
        max_results: int = 1000,
    ) -> List[Dict]:
        """Fetch all Agent records, following pagination via continuation tokens."""
        records: List[Dict] = []
        continuation = None
        page = 1

        logger.info("Fetching from Feedly Cyberattacks Agent...")
        while len(records) < max_results:
            logger.debug(f"  Page {page} (fetched so far: {len(records)})")
            response = self.fetch_agent_page(view_payload, continuation=continuation)
            if not response:
                break

            items = extract_items(response)
            if not items:
                logger.info("  No items in response - end of results.")
                break

            records.extend(items)
            logger.info(f"  Fetched {len(items)} records (total: {len(records)})")

            continuation = (
                response.get("continuation")
                or response.get("nextCursor")
                or response.get("next")
            )
            if not continuation:
                break

            page += 1

        return records[:max_results]


def extract_items(response: Dict) -> List[Dict]:
    """
    Extract the record list from an Agent response, tolerating top-level key
    changes across API versions.
    """
    for key in ("items", "attacks", "results", "rows", "cyberAttacks"):
        val = response.get(key)
        if isinstance(val, list):
            return val
    return []


# =============================================================================
# DATA PARSING
# =============================================================================

def _first(data: Dict, *keys: str, default: Any = None) -> Any:
    """Return the first non-None value among multiple candidate keys."""
    for key in keys:
        val = data.get(key)
        if val is not None:
            return val
    return default


def _extract_list(data: Dict, *keys: str) -> List:
    """Extract a list from a dict by trying multiple key names."""
    for key in keys:
        val = data.get(key)
        if isinstance(val, list):
            return val
    return []


def _label(entity: Any) -> str:
    """Extract a human-readable label from an entity object or bare string."""
    if isinstance(entity, str):
        return entity
    if isinstance(entity, dict):
        # Agent records wrap entities, e.g. {"entity": {"label": "Gunra", ...}}
        if isinstance(entity.get("entity"), dict):
            return _label(entity["entity"])
        return (
            entity.get("label")
            or entity.get("name")
            or entity.get("title")
            or entity.get("id", "")
        )
    return ""


def _to_iso(value: Any) -> str:
    """Convert a millisecond epoch or ISO string to an ISO-8601 string."""
    if value is None:
        return ""
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value) / 1000, tz=timezone.utc).isoformat()
        except (ValueError, OSError, OverflowError):
            return ""
    return str(value)


def parse_attack(attack: Dict) -> Dict:
    """
    Normalise a raw Cyberattacks Agent record into a standardised dict.

    Field names are based on the live cyber-attacks dashboard response, but
    the Agent payload structure may evolve while the customer iterates on
    their configuration, so every field is resolved through multiple candidate
    key names and missing fields degrade gracefully to empty values.
    """
    title = _first(attack, "shortOverview", "title", "name", default="Untitled Cyber Attack")

    description = _first(attack, "overview", "description", "summary", default=title)
    if isinstance(description, dict):
        description = description.get("content") or description.get("text") or title

    so_what = str(_first(attack, "soWhat", default="") or "")
    latest_activity = str(_first(attack, "latestActivity", default="") or "")
    what = str(_first(attack, "what", default="") or "")

    attack_date_iso = _to_iso(
        _first(attack, "attackDate", "date", "firstMentionedAt", "published", "timestamp")
    ) or datetime.now(timezone.utc).isoformat()

    # Attack types: [{"id": "Ransomware", "label": "Ransomware Attacks"}]
    raw_types = _extract_list(attack, "types", "attackTypes", "attack_types", "categories")
    attack_types: List[str] = []
    for at in raw_types:
        label = _label(at)
        if label and label not in attack_types:
            attack_types.append(ATTACK_TYPE_LABELS.get(label, label))
    if not attack_types and attack.get("attackType"):
        raw = _label(attack["attackType"])
        attack_types.append(ATTACK_TYPE_LABELS.get(raw, raw))

    # Threat actors / malware: [{"entity": {"label": ..., ...}}]
    raw_actors = _extract_list(attack, "threatActors", "actors", "threat_actors", "attackers")
    threat_actors: List[str] = []
    for actor in raw_actors:
        label = _label(actor)
        if label and label not in threat_actors:
            threat_actors.append(label)

    raw_malware = _extract_list(attack, "malwareFamilies", "malware", "malware_families", "tools")
    malware_families: List[str] = []
    for mw in raw_malware:
        label = _label(mw)
        if label and label not in malware_families:
            malware_families.append(label)

    # Related CVEs
    raw_cves = _extract_list(attack, "cves", "vulnerabilities")
    cves: List[str] = []
    for cve in raw_cves:
        label = _label(cve)
        if label and label not in cves:
            cves.append(label)

    # Victim: single object {"label", "countryIso2", "industries", "size", "websites"}
    victims: List[Dict] = []
    raw_victims = _extract_list(attack, "victims", "targets", "affected")
    single_victim = attack.get("victim")
    if isinstance(single_victim, dict):
        raw_victims = raw_victims + [single_victim]
    for v in raw_victims:
        if not isinstance(v, dict):
            if isinstance(v, str) and v:
                victims.append({"organization": v, "country": "", "industry": ""})
            continue
        country = str(
            _first(v, "countryIso2", default="")
            or _label(v.get("country") or "")
        )
        industries = [
            _label(ind) for ind in (v.get("industries") or []) if _label(ind)
        ]
        if not industries:
            industry_raw = v.get("industry") or v.get("sector") or {}
            ind = _label(industry_raw) if isinstance(industry_raw, (dict, str)) else ""
            if ind:
                industries = [ind]
        org = _first(v, "label", "name", "organization", "company", default="")
        if isinstance(org, dict):
            org = _label(org)
        victims.append({
            "organization": str(org),
            "country": country,
            "industry": ", ".join(industries),
        })

    # Top-level victim countries (ISO codes) when no victim object is present
    if not any(v["country"] for v in victims):
        for code in attack.get("countriesIso") or []:
            if victims:
                victims[0]["country"] = str(code)
                break
            victims.append({"organization": "", "country": str(code), "industry": ""})

    # Timeline events
    raw_timeline = _extract_list(attack, "timeline", "events", "timelineEvents")
    timeline: List[str] = []
    for ev in raw_timeline:
        if isinstance(ev, dict):
            when = _to_iso(_first(ev, "date", "timestamp", "time", "ts"))
            what_ev = _first(ev, "description", "title", "label", "event", default="")
            if isinstance(what_ev, dict):
                what_ev = _label(what_ev)
            entry = " - ".join(x for x in [when[:10] if when else "", str(what_ev)] if x)
            if entry:
                timeline.append(entry)
        elif isinstance(ev, str) and ev:
            timeline.append(ev)

    # References: explicit article objects, else Feedly entry IDs
    raw_articles = _extract_list(attack, "sourceArticles", "articles", "sources", "references")
    references: List[str] = []
    for art in raw_articles:
        if isinstance(art, dict):
            url = _first(art, "url", "href", "canonicalUrl", default="")
        elif isinstance(art, str):
            url = art
        else:
            url = ""
        if url and url.startswith("http") and url not in references:
            references.append(url)
    if not references:
        for entry_id in (attack.get("entryIds") or [])[:5]:
            references.append(
                "https://feedly.com/i/entry/" + urllib.parse.quote(str(entry_id), safe="")
            )

    return {
        "attack_id":        str(_first(attack, "id", "attackId", default="")),
        "title":            str(title),
        "description":      str(description)[:10000],
        "what":             what,
        "so_what":          so_what,
        "latest_activity":  latest_activity,
        "attack_date_iso":  attack_date_iso,
        "attack_types":     attack_types,
        "threat_actors":    threat_actors,
        "malware_families": malware_families,
        "cves":             cves,
        "victims":          victims,
        "timeline":         timeline,
        "references":       references[:10],
    }


def build_description(parsed: Dict) -> str:
    """
    Build the full Description attribute text. All Agent intelligence is
    embedded here so nothing is lost even if the custom attribute types do not
    exist in the customer's ThreatConnect owner.
    """
    lines: List[str] = []
    if parsed["description"]:
        lines.append(parsed["description"][:5000])
        lines.append("")
    if parsed["what"]:
        lines.append(f"What: {parsed['what']}")
    if parsed["so_what"]:
        lines.append(f"So What: {parsed['so_what']}")
    if parsed["latest_activity"]:
        lines.append(f"Latest Activity: {parsed['latest_activity']}")
    if parsed["what"] or parsed["so_what"] or parsed["latest_activity"]:
        lines.append("")

    lines.append("--- Feedly Cyberattacks Agent ---")
    if parsed["attack_types"]:
        lines.append(f"Attack Types: {', '.join(parsed['attack_types'])}")
    if parsed["attack_date_iso"]:
        lines.append(f"Attack Date: {parsed['attack_date_iso']}")
    if parsed["threat_actors"]:
        lines.append(f"Threat Actors: {', '.join(parsed['threat_actors'])}")
    if parsed["malware_families"]:
        lines.append(f"Malware: {', '.join(parsed['malware_families'])}")
    if parsed["cves"]:
        lines.append(f"Related CVEs: {', '.join(parsed['cves'][:15])}")
    for v in parsed["victims"][:10]:
        parts = [x for x in [v["organization"], v["industry"], v["country"]] if x]
        if parts:
            lines.append(f"Victim: {' | '.join(parts)}")
    if parsed["timeline"]:
        lines.append("Timeline:")
        lines.extend(f"  - {t}" for t in parsed["timeline"][:20])
    if parsed["references"]:
        lines.append("References:")
        lines.extend(f"  - {r}" for r in parsed["references"])

    return "\n".join(lines)[:10000]


# =============================================================================
# THREATCONNECT CLIENT
# =============================================================================

class ThreatConnectClient:
    """
    Minimal ThreatConnect v3 API client supporting HMAC (Access ID + Secret
    Key) and API Token authentication, with retry logic and rate limiting.
    """

    def __init__(
        self,
        api_url: str,
        access_id: str = "",
        secret_key: str = "",
        api_token: str = "",
        owner: str = "",
    ):
        self.api_url = api_url.rstrip("/")
        self.access_id = access_id
        self.secret_key = secret_key
        self.api_token = api_token
        self.owner = owner
        self.session = requests.Session()

        if not api_token and not (access_id and secret_key):
            raise ValueError(
                "ThreatConnect credentials missing: set TC_API_TOKEN, or "
                "TC_ACCESS_ID and TC_SECRET_KEY."
            )

    def _auth_headers(self, method: str, path_with_query: str) -> Dict[str, str]:
        """Build authentication headers for one request."""
        if self.api_token:
            return {"Authorization": f"TC-Token {self.api_token}"}

        timestamp = str(int(time.time()))
        message = f"{path_with_query}:{method.upper()}:{timestamp}"
        signature = base64.b64encode(
            hmac.new(
                self.secret_key.encode("utf-8"),
                message.encode("utf-8"),
                hashlib.sha256,
            ).digest()
        ).decode("utf-8")
        return {
            "Authorization": f"TC {self.access_id}:{signature}",
            "Timestamp": timestamp,
        }

    def _request(
        self,
        method: str,
        path: str,
        params: Optional[Dict] = None,
        body: Optional[Dict] = None,
        retries: int = MAX_RETRIES,
    ) -> Optional[Dict]:
        """Make a signed API request with retry logic and rate limiting."""
        query_params = dict(params or {})
        if self.owner and "owner" not in query_params:
            query_params["owner"] = self.owner

        # The HMAC signature covers the exact path + query string, so build
        # the URL manually rather than letting requests re-encode params.
        query = urllib.parse.urlencode(query_params, quote_via=urllib.parse.quote)
        path_with_query = f"{path}?{query}" if query else path
        url = f"{self.api_url}{path_with_query}"

        for attempt in range(retries):
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
            headers.update(self._auth_headers(method, path_with_query))

            try:
                response = self.session.request(
                    method, url, headers=headers, json=body, timeout=60,
                )

                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", RETRY_DELAY * (attempt + 1)))
                    logger.warning(f"ThreatConnect rate limited. Waiting {retry_after}s...")
                    time.sleep(retry_after)
                    continue

                if response.status_code == 401:
                    logger.error("ThreatConnect authentication failed. Check credentials.")
                    return None

                if response.status_code >= 400:
                    if attempt < retries - 1 and response.status_code >= 500:
                        logger.warning(
                            f"TC HTTP {response.status_code} on attempt {attempt + 1}/{retries}, retrying..."
                        )
                        time.sleep(RETRY_DELAY * (attempt + 1))
                        continue
                    logger.error(
                        f"ThreatConnect API error {response.status_code} "
                        f"({method} {path}): {response.text[:300]}"
                    )
                    return None

                time.sleep(RATE_LIMIT_DELAY)
                if not response.text:
                    return {}
                return response.json()

            except requests.exceptions.RequestException as e:
                if attempt < retries - 1:
                    logger.warning(f"TC request error, retrying ({attempt + 1}/{retries}): {e}")
                    time.sleep(RETRY_DELAY * (attempt + 1))
                    continue
                logger.error(f"ThreatConnect request failed after {retries} attempts: {e}")
                return None

        return None

    # ------------------------------------------------------------------
    # Groups
    # ------------------------------------------------------------------

    def find_group(self, group_type: str, name: str) -> Optional[int]:
        """Find an existing group by exact type + name (summary) via TQL."""
        safe_name = name.replace('"', '\\"')
        tql = f'typeName EQ "{group_type}" AND summary EQ "{safe_name}"'
        result = self._request(
            "GET", "/api/v3/groups",
            params={"tql": tql, "resultLimit": 1},
        )
        if result:
            data = result.get("data") or []
            if data:
                return data[0].get("id")
        return None

    def create_group(self, payload: Dict) -> Optional[int]:
        """Create a group; returns the new group ID."""
        result = self._request("POST", "/api/v3/groups", body=payload)
        if result:
            data = result.get("data") or {}
            return data.get("id")
        return None

    def update_group(self, group_id: int, payload: Dict) -> bool:
        """Update an existing group."""
        result = self._request("PUT", f"/api/v3/groups/{group_id}", body=payload)
        return result is not None


# =============================================================================
# GROUP PAYLOAD BUILDING
# =============================================================================

def build_incident_payload(
    parsed: Dict,
    attribute_mapping: Dict[str, str],
    use_custom_attributes: bool,
    extra_tags: List[str],
    associate_entities: bool,
) -> Dict:
    """Build the ThreatConnect v3 Incident group payload for one cyber attack."""
    name = parsed["title"][:100]

    attributes: List[Dict] = [
        {
            "type": attribute_mapping.get("description", "Description"),
            "value": build_description(parsed),
            "default": True,
        },
        {
            "type": attribute_mapping.get("source", "Source"),
            "value": "Feedly Cyberattacks Agent",
        },
    ]

    if use_custom_attributes:
        victim_orgs = ", ".join(
            v["organization"] for v in parsed["victims"] if v["organization"]
        )
        victim_countries = ", ".join(
            sorted({v["country"] for v in parsed["victims"] if v["country"]})
        )
        victim_industries = ", ".join(
            sorted({v["industry"] for v in parsed["victims"] if v["industry"]})
        )
        custom_fields = [
            ("attack_type", ", ".join(parsed["attack_types"])),
            ("victim_org", victim_orgs),
            ("victim_country", victim_countries),
            ("victim_industry", victim_industries),
            ("timeline", "\n".join(parsed["timeline"][:20])),
        ]
        for field_key, value in custom_fields:
            if not value:
                continue
            attr_type = attribute_mapping.get(field_key)
            if attr_type:
                attributes.append({"type": attr_type, "value": str(value)[:500]})

    tags = [{"name": "Feedly"}, {"name": "Feedly Cyberattacks Agent"}]
    for at in parsed["attack_types"][:5]:
        tags.append({"name": at})
    for t in extra_tags:
        tags.append({"name": t})

    payload: Dict[str, Any] = {
        "type": "Incident",
        "name": name,
        "eventDate": parsed["attack_date_iso"],
        "status": "New",
        "attributes": {"data": attributes},
        "tags": {"data": tags},
    }

    # Associated Adversary (threat actor), Malware and Vulnerability groups --
    # created or matched by name inside ThreatConnect as part of the same
    # request. CVE associations link incidents to the Vulnerability Groups
    # synced by the companion Vulnerability Agent script.
    if associate_entities:
        associated: List[Dict] = []
        for actor in parsed["threat_actors"][:10]:
            associated.append({"type": "Adversary", "name": actor[:100]})
        for mw in parsed["malware_families"][:10]:
            associated.append({"type": "Malware", "name": mw[:100]})
        for cve in parsed["cves"][:10]:
            associated.append({"type": "Vulnerability", "name": cve[:100]})
        if associated:
            payload["associatedGroups"] = {"data": associated}

    if parsed["references"]:
        payload["externalUrl"] = parsed["references"][0]

    return payload


# =============================================================================
# STATE MANAGEMENT
# =============================================================================

def load_state(state_file: str) -> Dict:
    """Load persisted sync state from a JSON file."""
    if os.path.exists(state_file):
        try:
            with open(state_file, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Could not load state file {state_file}: {e}")
    return {"synced": {}}


def save_state(state_file: str, state: Dict) -> None:
    """Persist sync state to a JSON file."""
    try:
        with open(state_file, "w") as f:
            json.dump(state, f, indent=2)
    except IOError as e:
        logger.warning(f"Could not save state file {state_file}: {e}")


# =============================================================================
# AGENT VIEW CONFIG
# =============================================================================

def load_agent_view(path: str) -> Optional[Dict]:
    """
    Load the customer's saved Agent view JSON (the POST body of their
    Cyberattacks Agent dashboard view). Re-called every sync cycle so edits
    take effect without restarting the script.
    """
    if not os.path.exists(path):
        logger.error(
            f"Agent view file not found: {path}\n"
            "  Export the JSON payload of your saved Cyberattacks Agent view "
            "from Feedly and save it to this file. See README for instructions."
        )
        return None
    try:
        with open(path, "r") as f:
            payload = json.load(f)
        if not isinstance(payload, dict):
            logger.error(f"Agent view file {path} must contain a JSON object.")
            return None
        # Pagination is managed by the script
        payload.pop("continuation", None)
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode("utf-8")
        ).hexdigest()[:12]
        logger.info(f"Loaded agent view '{path}' (config hash: {digest})")
        return payload
    except json.JSONDecodeError as e:
        logger.error(f"Agent view file {path} is not valid JSON: {e}")
        return None


# =============================================================================
# SYNC LOGIC
# =============================================================================

def run_sync(args: argparse.Namespace) -> None:
    """Execute one sync cycle: Feedly Cyberattacks Agent -> ThreatConnect."""
    view_payload = load_agent_view(args.agent_view)
    if view_payload is None:
        return

    feedly = FeedlyClient(api_key=args.feedly_api_key)

    tc: Optional[ThreatConnectClient] = None
    if not args.dry_run:
        tc = ThreatConnectClient(
            api_url=args.tc_url,
            access_id=args.tc_access_id,
            secret_key=args.tc_secret_key,
            api_token=args.tc_token,
            owner=args.tc_owner,
        )

    state = load_state(args.state_file)
    synced: Dict[str, Any] = state.setdefault("synced", {})

    records = feedly.fetch_all(view_payload, max_results=args.max_results)
    if not records:
        logger.info("No cyber attack records returned for the current agent view.")
        return

    if args.output:
        try:
            with open(args.output, "w") as f:
                json.dump(records, f, indent=2)
            logger.info(f"Raw agent records saved to {args.output}")
        except IOError as e:
            logger.warning(f"Could not write output file {args.output}: {e}")

    logger.info(f"Processing {len(records)} cyber attack records...")

    stats = {"processed": 0, "created": 0, "updated": 0, "skipped": 0, "failed": 0}

    for i, record in enumerate(records, 1):
        try:
            parsed = parse_attack(record)
            name = parsed["title"]
            stats["processed"] += 1

            payload = build_incident_payload(
                parsed,
                attribute_mapping=args.attribute_mapping,
                use_custom_attributes=args.custom_attributes,
                extra_tags=args.extra_tags,
                associate_entities=args.associate_entities,
            )

            if args.dry_run:
                actors = ", ".join(parsed["threat_actors"]) or "Unknown"
                types_str = ", ".join(parsed["attack_types"]) or "Unknown"
                logger.info(
                    f"[{i}/{len(records)}] [DRY RUN] Incident: {name[:60]} | "
                    f"{types_str} | Actors: {actors}"
                )
                if args.verbose:
                    logger.debug(json.dumps(payload, indent=2))
                continue

            dedupe_key = parsed["attack_id"] or name
            existing_id = synced.get(dedupe_key)
            if not existing_id:
                existing_id = tc.find_group("Incident", name[:100])

            if existing_id:
                if args.skip_existing:
                    logger.info(f"[{i}/{len(records)}] Skipping existing: {name[:60]} (TC #{existing_id})")
                    stats["skipped"] += 1
                    synced[dedupe_key] = existing_id
                    continue
                if tc.update_group(existing_id, payload):
                    logger.info(f"[{i}/{len(records)}] Updated: {name[:60]} (TC #{existing_id})")
                    stats["updated"] += 1
                    synced[dedupe_key] = existing_id
                else:
                    stats["failed"] += 1
            else:
                new_id = tc.create_group(payload)
                if new_id:
                    logger.info(f"[{i}/{len(records)}] Created: {name[:60]} (TC #{new_id})")
                    stats["created"] += 1
                    synced[dedupe_key] = new_id
                else:
                    stats["failed"] += 1

        except Exception as e:
            logger.error(f"Error processing record {i}: {e}", exc_info=args.verbose)
            stats["failed"] += 1

    if not args.dry_run:
        state["last_sync_iso"] = datetime.now(timezone.utc).isoformat()
        save_state(args.state_file, state)

    logger.info("")
    logger.info("=" * 60)
    logger.info("SYNC COMPLETE")
    logger.info("=" * 60)
    logger.info(f"  Records processed:   {stats['processed']}")
    logger.info(f"  Incidents created:   {stats['created']}")
    logger.info(f"  Incidents updated:   {stats['updated']}")
    logger.info(f"  Skipped (existing):  {stats['skipped']}")
    logger.info(f"  Failed:              {stats['failed']}")
    if args.dry_run:
        logger.info("  (Dry run - no changes written to ThreatConnect)")
    logger.info("=" * 60)


# =============================================================================
# CLI
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="feedly_cyberattacks_agent_threatconnect.py",
        description="Sync a saved Feedly Cyberattacks Agent view into ThreatConnect.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Preview what would be imported (always run this first)
  python feedly_cyberattacks_agent_threatconnect.py --dry-run

  # Save the raw Agent records to a file for inspection
  python feedly_cyberattacks_agent_threatconnect.py --dry-run --output records.json

  # One-shot sync into ThreatConnect
  python feedly_cyberattacks_agent_threatconnect.py --tc-owner "My Org"

  # Continuous sync every 60 minutes; edits to cyber_attacks_agent_view.json
  # are picked up automatically on the next cycle
  python feedly_cyberattacks_agent_threatconnect.py --daemon --interval 60

  # Use a different saved view file
  python feedly_cyberattacks_agent_threatconnect.py --agent-view my_view.json --dry-run
        """,
    )

    # ---- Feedly ----
    feedly = parser.add_argument_group("Feedly")
    feedly.add_argument(
        "--feedly-api-key",
        default=FEEDLY_API_KEY,
        metavar="KEY",
        help="Feedly API key (default: FEEDLY_API_KEY env var or .env)",
    )
    feedly.add_argument(
        "--agent-view",
        default=AGENT_VIEW_FILE,
        metavar="FILE",
        help=(
            "JSON file containing the saved Cyberattacks Agent view payload. "
            "Sent to Feedly verbatim; re-read every sync cycle so the customer "
            f"can update their Agent configuration anytime (default: {AGENT_VIEW_FILE})"
        ),
    )
    feedly.add_argument(
        "--max-results",
        type=int,
        default=500,
        metavar="N",
        help="Maximum records to fetch per sync cycle (default: 500)",
    )

    # ---- ThreatConnect ----
    tc = parser.add_argument_group("ThreatConnect")
    tc.add_argument(
        "--tc-url",
        default=TC_CREDS["TC_API_URL"],
        metavar="URL",
        help="ThreatConnect instance URL (default: TC_API_URL env var)",
    )
    tc.add_argument(
        "--tc-access-id",
        default=TC_CREDS["TC_ACCESS_ID"],
        metavar="ID",
        help="ThreatConnect HMAC Access ID (default: TC_ACCESS_ID env var)",
    )
    tc.add_argument(
        "--tc-secret-key",
        default=TC_CREDS["TC_SECRET_KEY"],
        metavar="KEY",
        help="ThreatConnect HMAC Secret Key (default: TC_SECRET_KEY env var)",
    )
    tc.add_argument(
        "--tc-token",
        default=TC_CREDS["TC_API_TOKEN"],
        metavar="TOKEN",
        help="ThreatConnect API Token, alternative to HMAC (default: TC_API_TOKEN env var)",
    )
    tc.add_argument(
        "--tc-owner",
        default=TC_CREDS["TC_OWNER"],
        metavar="OWNER",
        help="Target ThreatConnect owner/organization (default: TC_OWNER env var)",
    )
    tc.add_argument(
        "--no-custom-attributes",
        dest="custom_attributes",
        action="store_false",
        help=(
            "Do not attempt custom attributes (Attack Type, Victim Country, etc.). "
            "All data is still embedded in the Description attribute."
        ),
    )
    tc.add_argument(
        "--no-associations",
        dest="associate_entities",
        action="store_false",
        help="Do not create associated Adversary/Malware groups",
    )
    tc.add_argument(
        "--skip-existing",
        action="store_true",
        help="Skip incidents that already exist in ThreatConnect instead of updating them",
    )

    # ---- Automation ----
    auto = parser.add_argument_group("Automation")
    auto.add_argument(
        "--daemon",
        action="store_true",
        help="Run continuously, repeating the sync on a fixed interval",
    )
    auto.add_argument(
        "--interval",
        type=int,
        default=60,
        metavar="MINUTES",
        help="Interval between daemon sync cycles in minutes (default: 60)",
    )

    # ---- General ----
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview what would be imported without writing anything to ThreatConnect",
    )
    parser.add_argument(
        "--output",
        default=None,
        metavar="FILE",
        help="Save the raw Feedly Agent records to a JSON file",
    )
    parser.add_argument(
        "--state-file",
        default=STATE_FILE,
        metavar="FILE",
        help=f"Path to sync state JSON file (default: {STATE_FILE})",
    )
    parser.add_argument(
        "--config",
        default="config.yaml",
        metavar="FILE",
        help="Optional YAML config file (default: config.yaml)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose/debug output",
    )

    return parser


def apply_yaml_config(args: argparse.Namespace) -> None:
    """
    Overlay YAML config values onto parsed args, only for fields still at
    their defaults (i.e. not explicitly set on the command line).
    """
    cfg = load_yaml_config(args.config)

    feedly_cfg = cfg.get("feedly") or {}
    tc_cfg = cfg.get("threatconnect") or {}
    sync_cfg = cfg.get("sync") or {}

    if feedly_cfg.get("api_key") and args.feedly_api_key == "APIKEYHERE":
        args.feedly_api_key = feedly_cfg["api_key"]
    if feedly_cfg.get("agent_view") and args.agent_view == AGENT_VIEW_FILE:
        args.agent_view = feedly_cfg["agent_view"]
    if feedly_cfg.get("max_results") and args.max_results == 500:
        args.max_results = int(feedly_cfg["max_results"])

    if tc_cfg.get("url") and args.tc_url == "https://app.threatconnect.com":
        args.tc_url = tc_cfg["url"]
    if tc_cfg.get("access_id") and not args.tc_access_id:
        args.tc_access_id = tc_cfg["access_id"]
    if tc_cfg.get("secret_key") and not args.tc_secret_key:
        args.tc_secret_key = tc_cfg["secret_key"]
    if tc_cfg.get("api_token") and not args.tc_token:
        args.tc_token = tc_cfg["api_token"]
    if tc_cfg.get("owner") and not args.tc_owner:
        args.tc_owner = tc_cfg["owner"]
    if tc_cfg.get("custom_attributes") is False:
        args.custom_attributes = False
    if tc_cfg.get("associations") is False:
        args.associate_entities = False
    if tc_cfg.get("skip_existing") and not args.skip_existing:
        args.skip_existing = True

    # Attribute type name remapping + extra tags
    args.attribute_mapping = dict(DEFAULT_ATTRIBUTE_MAPPING)
    args.attribute_mapping.update(tc_cfg.get("attribute_mapping") or {})
    args.extra_tags = list(tc_cfg.get("extra_tags") or [])

    if sync_cfg.get("interval") and args.interval == 60:
        args.interval = int(sync_cfg["interval"])
    if sync_cfg.get("daemon") and not args.daemon:
        args.daemon = True


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    apply_yaml_config(args)

    if args.daemon:
        interval_secs = args.interval * 60
        logger.info(
            f"Daemon mode enabled - syncing every {args.interval} minute(s). "
            f"The agent view file '{args.agent_view}' is re-read each cycle, so "
            "you can update the saved view JSON without restarting. "
            "Press Ctrl+C to stop."
        )
        cycle = 0
        while True:
            cycle += 1
            logger.info(f"--- Daemon cycle #{cycle} ---")
            try:
                run_sync(args)
            except SystemExit:
                raise
            except Exception as e:
                logger.error(f"Sync cycle failed: {e}", exc_info=args.verbose)

            next_run = datetime.now(timezone.utc) + timedelta(seconds=interval_secs)
            logger.info(
                f"Next sync at {next_run.strftime('%Y-%m-%d %H:%M:%S UTC')} "
                f"(in {args.interval} minute(s))."
            )
            time.sleep(interval_secs)
    else:
        run_sync(args)


if __name__ == "__main__":
    main()
