# ⚡ ThreatHunter AI
### Real-Time SOC Triage Platform powered by Claude AI

![ThreatHunter Dashboard](images/dashboard.png)

> Upload raw security logs. Get AI-powered incident triage in seconds.

ThreatHunter AI is a browser-based Security Operations Center (SOC) triage platform that ingests raw log files, runs them through a 40-rule detection engine, correlates findings into structured incidents, and uses the **Anthropic Claude API** to generate expert-level triage reports — all without a backend server.

---

## 📋 Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Detection Rules](#detection-rules)
- [Incident Correlation](#incident-correlation)
- [AI Triage](#ai-triage)
- [Supported Log Formats](#supported-log-formats)
- [Architecture](#architecture)
- [Setup & Deployment](#setup--deployment)
- [Usage Walkthrough](#usage-walkthrough)
- [Tech Stack](#tech-stack)

---

## Overview

Traditional SIEM tools require complex infrastructure, expensive licenses, and dedicated engineers to operate. ThreatHunter AI takes a different approach — drop your log files in, and within seconds you get:

- Structured incidents with severity ratings
- Full attack chain narratives
- MITRE ATT&CK technique mapping
- AI-generated analyst recommendations
- False positive probability scoring

It runs entirely in the browser as a React application with no database, no server, and no persistent storage.

![Upload Screen](images/upload.png)

---

## How It Works

The platform follows a four-stage pipeline from raw logs to actionable intelligence:

```
Raw Log Files
      │
      ▼
 PARSER STAGE
 parseLogFile()
 ─────────────────────────────────────────────────────
 Detects format (NDJSON, array JSON, XML, syslog, CSV)
 Strips BOM, normalizes line endings
 Maps each entry to a standard internal schema:
 { host, user, timestamp, src_ip, dest_ip, event_id,
   command_line, process_image, alert_signature, ... }
      │
      ▼
 DETECTION STAGE
 detectEntry()  ←  40 rules run against every entry
 ─────────────────────────────────────────────────────
 Stateful counters track brute force, scan rates,
 DNS query volume, and DGA entropy across all entries.
 Each rule that fires produces a Detection object with:
 { rule_id, severity, confidence, description,
   mitre_tactics, mitre_techniques, extra_evidence }
      │
      ▼
 CORRELATION STAGE
 correlate()  ←  24 correlation patterns
 ─────────────────────────────────────────────────────
 Groups detections by host.
 Matches detection combinations against known
 attack patterns (ransomware, lateral movement,
 full kill chain, etc.)
 Builds Incident objects with attack chain narratives
 and composite severity scores.
      │
      ▼
 AI TRIAGE STAGE
 triageWithAI()  ←  Claude claude-sonnet-4-20250514
 ─────────────────────────────────────────────────────
 Top 10 detections by confidence sent to Claude API.
 Returns: severity, risk score (0-100), FP probability,
 attack narrative, recommended actions, analyst notes.
```

---

## Detection Rules

ThreatHunter AI ships with **40 detection rules** across three categories.

### 🖥️ Endpoint / Windows (20 rules)

| Rule ID | Name | Severity | MITRE |
|---|---|---|---|
| RULE-001 | Encoded / Obfuscated PowerShell | HIGH | T1059.001 |
| RULE-002 | Brute Force Login (Windows + SSH) | MEDIUM/HIGH | T1110 |
| RULE-003 | Successful Login After Brute Force | HIGH | T1078 |
| RULE-004 | Kerberoasting (RC4 TGS Requests) | HIGH | T1558.003 |
| RULE-008 | PsExec Lateral Movement | HIGH | T1021.002 |
| RULE-009 | Office Macro → Shell Spawn | HIGH | T1059.001 |
| RULE-013 | LOLBIN Abuse | HIGH | T1218 |
| RULE-014 | Registry Persistence Key Modified | HIGH | T1547.001 |
| RULE-015 | Suspicious Named Pipe (C2) | HIGH | T1071 |
| RULE-016 | Credential Dumping / LSASS Access | CRITICAL | T1003.001 |
| RULE-017 | Scheduled Task Persistence | MEDIUM | T1053.005 |
| RULE-018 | WMI Lateral Movement / Persistence | HIGH | T1047 |
| RULE-019 | Pass-the-Hash / Suspicious Logon Type | HIGH | T1550.002 |
| RULE-020 | Account Creation / Privilege Escalation | MEDIUM/HIGH | T1136.001 |
| RULE-021 | Security Tool / AV Tampering | HIGH | T1562.001 |
| RULE-022 | Shadow Copy / Backup Deletion | CRITICAL | T1490 |
| RULE-023 | Executable Dropped in Temp/Public | MEDIUM | T1105 |
| RULE-038 | Event Log Cleared | HIGH | T1070.001 |
| RULE-039 | Ransomware File Extension on Disk | CRITICAL | T1486 |
| RULE-040 | Port Forwarding / Tunnel Tool | HIGH | T1572 |

### 🌐 Network / Suricata (18 rules)

| Rule ID | Name | Severity | MITRE |
|---|---|---|---|
| RULE-005 | C2 Framework Communication | HIGH/CRITICAL | T1071.001 |
| RULE-006 | DNS Tunneling | HIGH | T1048.003 |
| RULE-007 | DGA-Based C2 Activity | MEDIUM | T1568.002 |
| RULE-010 | Network Reconnaissance / Port Scan | MEDIUM/HIGH | T1595.001 |
| RULE-011 | Threat Intel — Known Malicious IP | MEDIUM/HIGH | T1190 |
| RULE-012 | VoIP Reconnaissance (SIPVicious) | MEDIUM | T1595.001 |
| RULE-024 | Exploit / Shellcode Attempt | CRITICAL | T1190 |
| RULE-025 | Malware / RAT Detected | CRITICAL | T1219 |
| RULE-026 | Webshell / Web Attack Tool | HIGH | T1505.003 |
| RULE-027 | Suspicious TLS / Self-Signed Cert | MEDIUM | T1573.001 |
| RULE-028 | Scanner / Recon User-Agent | MEDIUM | T1595.002 |
| RULE-029 | Suspicious SSH Client Fingerprint | MEDIUM | T1021.004 |
| RULE-030 | Data Exfiltration Signature | HIGH | T1041 |
| RULE-031 | Tor / Anonymization Network | HIGH | T1090.003 |
| RULE-032 | Legacy Protocol Abuse (SNMP/Telnet) | LOW | T1046 |
| RULE-033 | Cryptocurrency Mining | MEDIUM | T1496 |
| RULE-034 | RDP Brute Force / Scanning | HIGH | T1110 |
| RULE-035 | Suspicious Rare TLD DNS Query | MEDIUM | T1568 |

### 🐧 Linux / Generic (2 rules)

| Rule ID | Name | Severity | MITRE |
|---|---|---|---|
| RULE-036 | Suspicious Linux Command Executed | MEDIUM | T1059.004 |
| RULE-037 | Sudo Escalation / Root Session | MEDIUM/HIGH | T1548.003 |

> Rules RULE-002, RULE-006, RULE-007, RULE-010, RULE-011, RULE-034 are **stateful** — they track cumulative event counts across the entire log session to detect patterns that only become visible over time.

---

## Incident Correlation

The correlator groups detections by host and matches them against **24 attack patterns**, building higher-level incidents with full attack chain narratives.

| # | Incident Pattern | Key Rules |
|---|---|---|
| 1 | Ransomware Attack Chain | 022, 039 + supporting |
| 2 | Full Kill Chain (Brute → Exec → C2) | 002, 003, exec group, C2 group |
| 3 | Exploit → Post-Exploitation | 024 + 025/005/exec |
| 4 | Webshell → Persistence/Lateral | 026 + 013/014/008 |
| 5 | Credential Dump → Lateral Movement | 016 + 008/018/019 |
| 6 | Credential Compromise → Post-Exploitation | 002 + 003 + supporting |
| 7 | Active Malware with C2 | 025 + 005/006/007 |
| 8 | Credential Dumping (standalone) | 016 + 004/019 |
| 9 | Kerberoasting / AD Credential Theft | 004 + 019/020 |
| 10 | Defense Evasion + Active Threat | 021/038 + exec/C2 |
| 11 | Lateral Movement | 008/018/019 |
| 12 | Multi-Vector Persistence | 014/017/020/015 (2+) |
| 13 | Tor-Anonymized C2 / Exfiltration | 031 + 030/005 |
| 14 | DNS-Based C2 / Exfiltration | 006/007 + 035 |
| 15 | Coordinated Recon from Threat-Intel IP | 010 + 011 + supporting |
| 16 | VoIP Scanning / Toll Fraud | 012 + 011 |
| 17 | Exploit (standalone) | 024 + scan/TI |
| 18 | Cryptocurrency Mining | 033 + exec/evasion |
| 19 | Living-off-the-Land + Evasion | 013 + 021/038 |
| 20 | Linux Privilege Escalation | 037 + 036 |
| 21 | Automated SSH Attack | 029 + 002 |
| 22 | Data Exfiltration in Progress | 030 + tunnel/DNS/C2 |
| 23 | Recon + Legacy Protocol Exploitation | scan group + 032 |
| 24 | Account Manipulation | 020 + exec/lat/pers |

Each incident receives a **composite severity** (highest among its detections) and a **confidence score** that increases with each corroborating signal (`+0.04` per additional supporting detection).

---

## AI Triage

Each correlated incident is automatically sent to the **Anthropic Claude API** (`claude-sonnet-4-20250514`) for expert analysis.

![AI Triage Result](images/triage_result.png)

### What Claude receives
To stay within the 200k token limit, the prompt is kept lean:
- Top **10 detections** ranked by confidence score (descriptions capped at 120 chars)
- Up to **6 attack chain steps**
- Up to **8 MITRE techniques**
- **2 evidence samples** from raw detection context

### What Claude returns

```json
{
  "severity": "HIGH",
  "risk_score": 78,
  "false_positive_probability": 0.12,
  "summary": "Coordinated port scan from a known threat-intel IP targeting multiple database and remote access services on the host.",
  "attack_narrative": "Attacker conducted systematic reconnaissance across MySQL, MSSQL, PostgreSQL, VNC, and SSH ports — consistent with automated pre-attack enumeration tools.",
  "recommended_actions": [
    "Block source IP at perimeter firewall immediately",
    "Review exposed service inventory and close unnecessary ports",
    "Enable alerting on repeated scan patterns from single sources",
    "Check for any successful connections from this IP in firewall logs"
  ],
  "mitre_tactics": ["Reconnaissance"],
  "analyst_notes": "Pattern consistent with Shodan/Masscan-style internet scanning. Low FP probability given TI match and scan breadth."
}
```

### Fallback
If the API is unavailable, a **heuristic triage** function computes a local score from severity weights, detection count, and confidence values — keeping the platform functional offline.

---

## Supported Log Formats

| Format | Extensions | Notes |
|---|---|---|
| Suricata EVE JSON | `.json` | Alerts, DNS, TLS, SSH, HTTP, fileinfo events |
| Sysmon JSON/XML | `.json`, `.xml` | Event IDs 1, 10, 11, 13, 17 |
| Winlogbeat JSON | `.json` | Windows Security Event Log via Elastic |
| Windows Auth Events | `.json`, `.log` | Event IDs 4624, 4625, 4720, 4728, 4732, 4769 |
| Linux auth.log | `.log`, `.txt` | SSH failures, sudo, PAM events |
| Generic JSON | `.json` | Best-effort field normalization |
| CSV | `.csv` | Raw line passthrough |

The parser handles:
- ✅ NDJSON (one object per line)
- ✅ Pretty-printed multi-line JSON
- ✅ JSON arrays and wrapped formats (`records`, `events`, Elasticsearch `hits.hits`)
- ✅ UTF-8 BOM stripping
- ✅ Windows (`\r\n`) and Unix (`\n`) line endings

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Browser (React)                    │
│                                                      │
│  ┌──────────┐   ┌───────────┐   ┌───────────────┐   │
│  │  Upload  │──▶│ Detection │──▶│  Correlator   │   │
│  │  Screen  │   │  Engine   │   │  (24 patterns)│   │
│  └──────────┘   │ (40 rules)│   └──────┬────────┘   │
│                 └───────────┘          │             │
│                                        ▼             │
│                               ┌────────────────┐    │
│                               │   Dashboard    │    │
│                               │  + Incident    │    │
│                               │    Viewer      │    │
│                               └───────┬────────┘    │
└───────────────────────────────────────┼─────────────┘
                                        │ fetch()
                                        ▼
                          ┌─────────────────────────┐
                          │   Anthropic Claude API   │
                          │  claude-sonnet-4-20250514│
                          └─────────────────────────┘
```

**No backend. No database. No persistent storage.**
All state lives in React memory for the duration of the session. Refreshing the page clears everything.

---

## Setup & Deployment

ThreatHunter AI is built to run as a **Claude.ai artifact** — no installation required.

### Running in Claude.ai
1. Open the artifact in any Claude.ai conversation
2. The Anthropic API is automatically available — no API key configuration needed
3. Upload log files and analyze immediately

### Running Outside Claude.ai (optional)
If you want to host this independently, the AI triage calls need an API key. Set up a lightweight proxy:

#### Cloudflare Worker Proxy
1. Create a free [Cloudflare account](https://dash.cloudflare.com/sign-up)
2. Go to **Workers & Pages** → **Create Worker**
3. Paste the following worker code:

```javascript
const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Max-Age": "86400",
};

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS")
      return new Response(null, { status: 204, headers: CORS_HEADERS });

    const body = await request.json();
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": env.ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify(body),
    });

    const data = await response.json();
    return new Response(JSON.stringify(data), {
      status: response.status,
      headers: { "Content-Type": "application/json", ...CORS_HEADERS },
    });
  },
};
```

4. Add your Anthropic API key as a secret: **Settings → Variables and Secrets → Add Secret**
   - Name: `ANTHROPIC_API_KEY`
   - Value: `sk-ant-...`
5. Update the fetch URL in `triageWithAI()` to point to your worker URL
6. Deploy

---

## Usage Walkthrough

### Step 1 — Upload Log Files

![Upload Interface](images/upload_screen.png)

Drag and drop one or more supported log files onto the upload zone, or click to browse. Multiple files can be queued and processed together. Supported formats are shown on the upload screen.

Click **⚡ Analyze Logs** to begin processing.

---

### Step 2 — Detection & Correlation

![Processing](images/processing.png)

The engine processes every log entry through all 40 rules simultaneously. Stateful counters track patterns across the full file. Progress is shown in real time:

```
Parsing eve.json…
Running 4,821 entries through 40 detection rules…
Correlating 312 detections into incidents…
Found 7 incident(s). Running AI triage…
```

---

### Step 3 — Review Incidents

![Incident List](images/incident_list.png)

Incidents appear in the left panel sorted by severity (CRITICAL → HIGH → MEDIUM → LOW). Each entry shows:
- Unique incident ID
- Incident title (correlated attack pattern name)
- Affected host and log source type
- AI risk score (0–100)
- Severity pill (color-coded)

Use the filter bar to view incidents by severity or triage status.

---

### Step 4 — AI Triage Analysis

![Triage Analysis](images/triage_analysis.png)

Click any incident to open the full triage view. The **Triage Analysis** tab shows:

- **Attack Chain** — step-by-step narrative of how the attack unfolded
- **MITRE ATT&CK** — technique and tactic tags mapped to the incident
- **AI Triage Result** — Claude's expert analysis including:
  - Severity rating and risk score ring
  - False positive probability
  - 2–3 sentence technical summary
  - Full attack narrative (kill chain + attacker intent)
  - Prioritised recommended response actions
  - Analyst notes and caveats

---

### Step 5 — Raw Detections

![Raw Detections](images/raw_detections.png)

Switch to the **Raw Detections** tab to inspect every individual rule that fired within the incident:
- Rule ID and name
- Confidence score
- Source log type
- Full description with evidence
- MITRE technique tags
- Raw evidence fields (IPs, commands, file paths, counts)

---

### Step 6 — Re-Triage

Any incident can be re-triaged at any time by clicking **re-triage** in the incident header. This sends the incident back to Claude for a fresh analysis — useful after reviewing raw detections and wanting a second opinion.

---

### Dashboard Stats (Right Rail)

![Dashboard Stats](images/stats.png)

The right rail shows live statistics as triage completes:
- **Severity breakdown** — bar chart of incidents per severity level
- **Sources** — count of incidents per log source type
- **Rule coverage** — how many rules fired per category (Endpoint / Network / Linux)
- **Triage progress** — ring showing % of incidents AI-triaged vs pending

---

## Tech Stack

| Component | Technology |
|---|---|
| UI Framework | React (hooks, no build step) |
| Styling | Inline styles + CSS variables |
| AI Model | Anthropic Claude (`claude-sonnet-4-20250514`) |
| State Management | React `useState` / `useCallback` |
| Storage | In-memory only (no localStorage, no DB) |
| Deployment | Claude.ai artifact sandbox |
| Optional Proxy | Cloudflare Workers (free tier) |

---

## Limitations

| Limitation | Detail |
|---|---|
| No persistence | All data clears on page refresh |
| Token limit | Very large files may hit Claude's 200k token limit — the engine automatically caps detections sent to the top 10 by confidence |
| Stateful counters reset | Brute force and scan counters start fresh each upload session |
| Rules are heuristic | Tuned for common patterns — noisy logs may produce false positives |
| Claude.ai dependency | AI triage requires a Claude.ai session or a configured proxy with a valid Anthropic API key |

---

## License

MIT — Free to use, modify, and distribute.

---

## Acknowledgements

Built with [Claude](https://claude.ai) by Anthropic · Detection rules based on MITRE ATT&CK framework · Suricata EVE format by the Suricata project
