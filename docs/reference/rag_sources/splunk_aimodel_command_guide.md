# Splunk AI Model Runner Command Guide

**Document Type**: Technical Reference & Examples  
**Topics**: aimodel command, SPL, RAG integration, AI-assisted search, threat analysis, SOAR playbooks  
**Keywords**: aimodel, ai model, rag, retrieval augmented generation, spl, ai search, prompt engineering, circuit ai, threat detection, ioc analysis, soar, playbook prompts  
**Last Updated**: February 2026

---

## Overview

The `aimodel` command is a Splunk streaming search command that integrates AI capabilities directly into SPL searches using Circuit AI (Azure OpenAI) with optional RAG (Retrieval Augmented Generation) support.

### Key Capabilities

- **AI-Powered Log Analysis**: Analyze log entries, events, and data using GPT-4
- **Field Substitution**: Dynamically inject Splunk field values into prompts
- **RAG Integration**: Query a knowledge base for context-aware responses
- **Streaming Command**: Process events as they flow through the search pipeline
- **Secure Credentials**: OAuth credentials stored in Splunk's encrypted password store

---

## Installation & Configuration

### Installation

1. Copy the `ai_model_runner` folder to `$SPLUNK_HOME/etc/apps/`
2. Restart Splunk
3. Navigate to **Apps > AI Model Runner > Setup** to configure credentials

### Required: LLM OAuth Credentials

| Field | Description |
|-------|-------------|
| **Client ID** | OAuth Client ID from Circuit AI |
| **Client Secret** | OAuth Client Secret from Circuit AI |

### Required: LLM Configuration

| Field | Description |
|-------|-------------|
| **LLM AppKey** | Your Circuit AI Application Key (e.g., `egai-prd-xxx-xxxxx`) |
| **LLM Model** | Model/deployment name (e.g., `gpt-4.1`, `gpt-4o`) |

### Optional: RAG Credentials

To enable knowledge base lookups:

| Field | Description |
|-------|-------------|
| **RAG API Key** | Circuit AI RAG Search API Key |
| **RAG Client ID** | OAuth Client ID for RAG service |
| **RAG Client Secret** | OAuth Client Secret for RAG service |

---

## Basic Syntax

```spl
| aimodel prompt="<your prompt>" [rag=true|false]
```

### Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `prompt` | Yes | - | The prompt to send to the AI model. Supports `${field}` substitution. |
| `rag` | No | `false` | Enable RAG knowledge base lookup for context-aware responses. |

### Output Fields

| Field | Description |
|-------|-------------|
| `ai_response` | The AI model's response |
| `rag_context` | (When `rag=true`) Relevant context from knowledge base (truncated to 500 chars) |

---

## Basic Usage Examples

### Simple Question (No Data)

```spl
| makeresults 
| eval question="What is the difference between a Splunk indexer and a search head?"
| aimodel prompt="${question}"
| table question ai_response
```

### With RAG Knowledge Base

```spl
| makeresults 
| eval question="What are the FedRAMP requirements for Splunk Cloud?"
| aimodel prompt="${question}" rag=true
| table question ai_response rag_context
```

### Field Substitution

Use `${field_name}` to inject field values:

```spl
index=main
| aimodel prompt="Analyze activity for user ${user} on host ${host} at ${_time}"
```

---

## Log Analysis Prompts

### Analyze a Single Log Entry

```spl
index=_internal sourcetype=splunkd ERROR
| head 1
| aimodel prompt="Analyze this Splunk log entry and explain what happened: ${_raw}"
| table _time _raw ai_response
```

### Batch Analyze Multiple Logs

```spl
index=_internal sourcetype=splunkd log_level=ERROR
| head 5
| aimodel prompt="Briefly explain this error: ${_raw}"
| table _time ai_response
```

### Windows Event Analysis

```spl
index=winevents EventCode=4625
| head 3
| aimodel prompt="Analyze this Windows failed login event. What does it indicate? User: ${Account_Name}, Source: ${src_ip}, Failure Reason: ${Failure_Reason}"
| table _time Account_Name src_ip ai_response
```

### Linux Auth Log Analysis

```spl
index=os sourcetype=linux_secure "Failed password"
| head 3
| aimodel prompt="Analyze this Linux authentication failure: ${_raw}"
| table _time ai_response
```

---

## Security Analysis Prompts

### Notable Event Triage

```spl
index=notable
| head 5
| aimodel prompt="Triage this security notable event. Rule: ${rule_name}, Severity: ${urgency}, Description: ${rule_description}. What actions should a SOC analyst take?" rag=true
| table rule_name urgency ai_response
```

### Threat Intelligence Lookup

```spl
| makeresults 
| eval ip="185.234.219.47"
| aimodel prompt="What do you know about IP address ${ip}? Is it associated with any known threats?" rag=true
| table ip ai_response
```

### MITRE ATT&CK Mapping

```spl
| makeresults
| eval technique="T1059.001"
| aimodel prompt="Explain MITRE ATT&CK technique ${technique}. What does it mean and how can it be detected in Splunk?" rag=true
| table technique ai_response
```

---

## Cybersecurity IOC Analysis Prompts

Use these prompts with `rag=true` to leverage the AlienVault OTX and Splunk Attack Data knowledge base.

### IOC Classification & Threat Intel

**Domain IOC Analysis:**
```spl
| makeresults 
| eval domain="malicious-domain.com"
| aimodel prompt="Analyze this domain IOC: ${domain}. What threat category does it belong to (C2, phishing, malware delivery)? What campaigns or malware families is it associated with?" rag=true
| table domain ai_response
```

**IP Address Investigation:**
```spl
| makeresults 
| eval ip="185.234.219.47"
| aimodel prompt="Investigate IP address ${ip}. Is it associated with SSH brute-force, botnets, web scanning, or C2 infrastructure? What threat actor or campaign does it belong to?" rag=true
| table ip ai_response
```

**Hash Lookup:**
```spl
| makeresults 
| eval hash="44d88612fea8a8f36de82e1278abb02f"
| aimodel prompt="Analyze this file hash: ${hash}. What malware family does it belong to? What are the associated MITRE ATT&CK techniques?" rag=true
| table hash ai_response
```

### MITRE ATT&CK Mapping

**Technique Explanation:**
```spl
| makeresults
| eval technique="T1003.001"
| aimodel prompt="Explain MITRE ATT&CK technique ${technique}. What does this technique involve? What are common tools and procedures? How can it be detected?" rag=true
| table technique ai_response
```

**Attack Chain Analysis:**
```spl
| makeresults
| eval techniques="T1566, T1059.001, T1003.001"
| aimodel prompt="Given these observed techniques: ${techniques}, what attack chain does this represent? What threat actor commonly uses this sequence? What should I look for next?" rag=true
| table techniques ai_response
```

### Threat Actor Intelligence

**APT Group Profile:**
```spl
| makeresults
| eval group="APT29"
| aimodel prompt="Provide intelligence on APT group ${group}. What are their TTPs, target industries, geographic focus, and associated malware families?" rag=true
| table group ai_response
```

**Ransomware Analysis:**
```spl
| makeresults
| eval ransomware="LockBit"
| aimodel prompt="Provide threat intelligence on ${ransomware}. What IOCs, file hashes, and MITRE ATT&CK techniques are associated with it? What is the initial access vector?" rag=true
| table ransomware ai_response
```

### Detection & Response

**Detection Strategy:**
```spl
| makeresults
| eval threat="credential dumping"
| aimodel prompt="How do I detect ${threat} in my environment? What log sources are needed? What specific indicators should I search for? Provide example detection logic." rag=true
| table threat ai_response
```

**Incident Response:**
```spl
| makeresults
| eval ioc="suspicious_process.exe"
| aimodel prompt="I've identified ${ioc} in my environment. What are the immediate containment steps? What additional artifacts should I collect?" rag=true
| table ioc ai_response
```

**Threat Hunting Query:**
```spl
| makeresults
| eval hunt_target="lateral movement"
| aimodel prompt="I want to hunt for ${hunt_target} activity. What behavioral indicators should I look for? What data sources are most relevant?" rag=true
| table hunt_target ai_response
```

---

## Splunk SOAR Playbook Prompts

These prompts are designed for use in Splunk SOAR playbooks to automate incident investigation and response decisions. They return JSON for easy parsing.

### Artifact Enrichment

**IP Reputation Check:**
```spl
| makeresults
| eval ip="192.168.1.100"
| aimodel prompt="Analyze IP address ${ip}. Is it malicious? What threat category? Return JSON with: {reputation, threat_type, confidence, recommended_action}" rag=true
| table ip ai_response
```

**Domain Reputation:**
```spl
| makeresults
| eval domain="suspicious-site.com"
| aimodel prompt="Analyze domain ${domain}. Is it associated with malware, phishing, or C2? Return JSON with: {reputation, category, associated_malware, recommended_action}" rag=true
| table domain ai_response
```

**File Hash Analysis:**
```spl
| makeresults
| eval hash="abc123def456"
| aimodel prompt="Analyze file hash ${hash}. Is it malicious? What malware family? Return JSON with: {verdict, malware_family, mitre_techniques, severity, recommended_action}" rag=true
| table hash ai_response
```

### Incident Triage

**Severity Assessment:**
```spl
| makeresults
| eval ips="10.1.1.5,185.234.219.47"
| eval domains="bad-domain.com"
| eval user="jsmith"
| aimodel prompt="Given these incident artifacts: IPs=${ips}, Domains=${domains}, User=${user}. Assess incident severity (critical/high/medium/low). What is the likely attack type? Return JSON with: {severity, attack_type, confidence, reasoning}" rag=true
| table ai_response
```

**False Positive Check:**
```spl
| makeresults
| eval alert_name="Brute Force Attempt"
| eval src_ip="10.1.1.100"
| eval dest_ip="10.1.1.5"
| eval user="admin"
| aimodel prompt="Evaluate if this alert is a false positive: Alert=${alert_name}, Source=${src_ip}, Destination=${dest_ip}, User=${user}. What is the likelihood of false positive? Return JSON with: {false_positive_likelihood, reasoning, verification_steps}" rag=true
| table ai_response
```

### Response Recommendations

**Containment Decision:**
```spl
| makeresults
| eval severity="high"
| eval assets="web-server-01,db-server-02"
| eval iocs="185.234.219.47,malware.exe"
| aimodel prompt="Given incident with severity=${severity}, affected_assets=${assets}, IOCs=${iocs}. What containment actions should be taken? Should we isolate hosts? Block IPs? Return JSON with: {containment_actions, priority_order, estimated_impact}" rag=true
| table ai_response
```

**Block Decision:**
```spl
| makeresults
| eval artifact_type="IP"
| eval artifact_value="185.234.219.47"
| eval fp_risk="low"
| eval impact="medium"
| aimodel prompt="Should we block ${artifact_type}: ${artifact_value}? Consider: false_positive_risk=${fp_risk}, business_impact=${impact}. Return JSON with: {block_recommended, reasoning, alternative_actions}" rag=true
| table ai_response
```

---

## Splunk Administration Prompts

### SPL Query Help

```spl
| makeresults
| eval question="How do I use the tstats command to count events per sourcetype over time?"
| aimodel prompt="${question}" rag=true
| table question ai_response
```

### Configuration Analysis

```spl
| rest /services/data/indexes
| head 5
| aimodel prompt="Analyze this Splunk index configuration. Name: ${title}, MaxSize: ${maxTotalDataSizeMB}MB, Retention: ${frozenTimePeriodInSecs}s. Is this configuration optimal?"
| table title ai_response
```

### Health Check Interpretation

```spl
| rest /services/server/health/splunkd/details
| aimodel prompt="Interpret this Splunk health status: Feature=${title}, Health=${health}, Reasons=${reasons}"
| table title health ai_response
```

---

## Data Quality Prompts

### Field Extraction Suggestions

```spl
index=main sourcetype=custom_app
| head 1
| aimodel prompt="Suggest regex field extractions for this log format: ${_raw}"
| table _raw ai_response
```

### Sourcetype Classification

```spl
index=main
| head 10
| stats values(_raw) as sample_logs by sourcetype
| aimodel prompt="Based on these sample logs, describe what data sourcetype '${sourcetype}' contains: ${sample_logs}"
| table sourcetype ai_response
```

---

## RAG-Specific Prompts

### Splunk Documentation Lookup

```spl
| makeresults
| eval query="How do I configure SAML authentication in Splunk Cloud?"
| aimodel prompt="${query}" rag=true
| table query ai_response rag_context
```

### Product Comparison

```spl
| makeresults
| eval query="What are the differences between Splunk Enterprise Security editions - Essentials vs Premier?"
| aimodel prompt="${query}" rag=true
| table query ai_response
```

### Troubleshooting Guidance

```spl
| makeresults
| eval issue="Splunk search head cluster captain is failing over frequently"
| aimodel prompt="Help me troubleshoot this issue: ${issue}. What are common causes and how do I investigate?" rag=true
| table issue ai_response
```

---

## Best Practices

### 1. Use Field Substitution

Include specific field values in your prompts using `${field_name}` syntax:

```spl
| aimodel prompt="Analyze user ${user} accessing ${dest} at ${_time}"
```

### 2. Enable RAG for Knowledge Questions

Use `rag=true` when asking about specific topics in your knowledge base:

```spl
| aimodel prompt="What is ITSI?" rag=true
```

> **Note**: Without RAG, the AI uses general knowledge. With RAG, responses are based on your configured knowledge base context.

### 3. Keep Prompts Focused

Be specific about what you want analyzed:

```spl
# Good - specific
| aimodel prompt="Is this login event suspicious? User: ${user}, Time: ${_time}, Location: ${src_geo}"

# Less Good - vague
| aimodel prompt="Analyze this: ${_raw}"
```

### 4. Limit Results for Batch Processing

Use `| head N` to control how many records are processed:

```spl
index=main ERROR
| head 10  # Process only 10 records
| aimodel prompt="Explain: ${_raw}"
```

### 5. Use Tables for Readable Output

```spl
| aimodel prompt="..."
| table _time source ai_response
```

### 6. Request JSON for Automation

When using with SOAR or automation, request JSON output:

```spl
| aimodel prompt="Analyze this IOC. Return JSON with: {verdict, confidence, recommended_action}" rag=true
```

---

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   SPL Search    │────▶│   aimodel.py     │────▶│   Circuit AI    │
│   Pipeline      │     │   (Streaming)    │     │   (Azure GPT-4) │
└─────────────────┘     └────────┬─────────┘     └─────────────────┘
                                 │
                                 │ rag=true
                                 ▼
                        ┌──────────────────┐
                        │ circuit_ai_rag.py│
                        │   (RAG Client)   │
                        └────────┬─────────┘
                                 │
                                 ▼
                        ┌──────────────────┐
                        │  Knowledge Base  │
                        │  (Circuit RAG)   │
                        └──────────────────┘
```

---

## File Structure

```
ai_model_runner/
├── bin/
│   ├── aimodel.py           # Main streaming search command
│   ├── circuit_ai_rag.py    # RAG client for knowledge base queries
│   ├── setup_handler.py     # REST handler for credential management
│   ├── splunklib/           # Splunk Python SDK
│   └── certifi/             # CA certificate bundle
├── appserver/
│   ├── static/
│   │   ├── setup_page.js    # Setup page JavaScript
│   │   └── css/             # Stylesheets
│   └── templates/
│       └── ai_model_credentials_setup.html
├── default/
│   ├── app.conf             # App configuration
│   ├── commands.conf        # Search command definition
│   ├── restmap.conf         # REST endpoint mapping
│   └── web.conf             # Web UI configuration
├── CONNECTION_NOTES.md      # Remote server SSH notes
├── PROMPTS.md               # Example prompts and queries
└── README.md                # Documentation
```

---

## Troubleshooting

### "No credentials found" or "LLM API Key not configured"

1. Go to **Apps > AI Model Runner > Setup**
2. Enter all required fields:
   - **LLM OAuth**: Client ID and Client Secret
   - **LLM Configuration**: AppKey and Model name
3. Click **Save Credentials**

### RAG not working

1. Ensure all 3 RAG fields are configured (API Key, Client ID, Client Secret)
2. Verify `rag=true` is set in your query
3. Check `python.log` for detailed errors:
   ```bash
   tail -100 $SPLUNK_HOME/var/log/splunk/python.log | grep aimodel
   ```

### Connection errors

1. Verify network connectivity to `chat-ai.cisco.com` and `id.cisco.com`
2. Check that the CA certificate bundle is present at `bin/certifi/cacert.pem`

### Debug mode

Check `$SPLUNK_HOME/var/log/splunk/python.log` for DEBUG messages.

---

## Security Considerations

- Credentials are stored in Splunk's encrypted password store (`passwords.conf`)
- OAuth tokens are obtained at runtime and cached for 1 hour
- All API calls use TLS with certificate verification
- Credentials are never logged or exposed in search results

---

## Requirements

- Splunk Enterprise 8.x, 9.x, or 10.x
- Python 3.9+ (bundled with Splunk)
- Network access to:
  - `https://chat-ai.cisco.com` (Circuit AI)
  - `https://id.cisco.com` (OAuth)

---

## System Prompt

The AI assistant uses a generic, RAG-focused system prompt:

> "You are a helpful assistant. If context is provided, use it to answer the user's question accurately. Base your responses on the provided context when available. If no context is provided, answer based on your general knowledge. Keep responses clear, concise, and actionable."

When `rag=true`, the knowledge base context is prepended to the user's question, allowing the AI to provide contextually relevant answers.

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | Oct 2025 | Initial release with Circuit AI integration |
| 1.1 | Dec 2025 | Added RAG support for knowledge base queries |
| 1.2 | Dec 2025 | Removed hardcoded credentials - LLM AppKey and Model now required via Setup page |
| 1.3 | Dec 2025 | Splunk 10 compatibility: chunked protocol, bundled typing_extensions |

---

## Related Documentation

- [Splunk ML Toolkit Circuit AI Configuration](splunk_mltk_circuit_ai_config.md)
- [Splunk AI Model SPL Examples](splunk_ai_model_spl_examples.md)
