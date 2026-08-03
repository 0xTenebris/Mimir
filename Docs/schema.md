# 0xGrimoire — Locked Schemas

These are the contracts between pipeline stages. Don't change field names/shapes without updating this file first — every module downstream assumes these exactly.

---

## 1. Joined CVE Store Record (output of Phase 1 ingestion/join.py)

```json
{
  "cve_id": "CVE-2021-41773",
  "description": "...",
  "cvss_score": 7.5,
  "cpe_matches": ["cpe:2.3:a:apache:http_server:2.4.49"],
  "epss_score": 0.94,
  "in_kev": true,
  "kev_date_added": "2021-11-03",
  "cwe_ids": ["CWE-22"],
  "attack_techniques": [
    {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}
  ],
  "owasp_category": "A01:2021 - Broken Access Control",
  "exploit_available": true,
  "exploit_source": "metasploit",
  "exploit_ref": "exploit/multi/http/apache_normalize_path_rce"
}
```

## 2. Retrieval Output (per asset, output of Phase 2)

```json
{
  "asset": "web-server-01:80",
  "raw_banner": "Apache/2.4.49 (Ubuntu)",
  "parsed_product": "apache:http_server",
  "parsed_version": "2.4.49",
  "match_tier": "deterministic",
  "confidence": "high",
  "candidates": [ /* array of Joined CVE Store Records, ranked */ ]
}
```

`match_tier` ∈ `{"deterministic", "semantic", "unrecognized"}`

## 3. Generation Output — `Finding` Pydantic model (Phase 3)

```python
class Verdict(str, Enum):
    confirmed_exploitable = "confirmed_exploitable"
    likely_exploitable = "likely_exploitable"
    theoretical = "theoretical"
    no_match_found = "no_match_found"

class Finding(BaseModel):
    cve_id: str
    verdict: Verdict
    synthesis: str          # one grounded sentence, plain language
    recommended_action: str
    citation: str            # MUST match a cve_id from retrieved candidates — validated post-generation
```

## 4. Test Fixture Format (tests/fixtures/banners.csv)

```csv
raw_banner,expected_product,expected_version,expected_cve_ids
"Apache/2.4.49 (Ubuntu)",apache:http_server,2.4.49,"CVE-2021-41773;CVE-2021-42013"
```

---

## Report ranking formula (Phase 2 rank.py)

```
priority = (in_kev ? KEV_BOOST : 0) + (epss_score * EPSS_WEIGHT) + (exploit_available ? EXPLOIT_BOOST : 0) + (cvss_score/10 * CVSS_WEIGHT)
```
Exact weight constants to be tuned once you have real data to test against — don't guess-tune before Phase 1 is done.
