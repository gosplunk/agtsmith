# Splunk ML Toolkit AI Commander Guide

**Document Type**: Technical Reference & Examples  
**Topics**: ML Toolkit, AI Commander, MLTK, ai command, Circuit AI, Connection Management  
**Keywords**: mltk, ai toolkit, ai commander, ai command, spl, circuit ai, cisco ai, openai, azure openai, gpt-4, smart assistant  
**Last Updated**: February 2026

---

## Overview

The Splunk ML Toolkit (MLTK) includes **AI Commander** - a feature that integrates LLM capabilities directly into Splunk through the `| ai` SPL command. This allows users to ask questions, analyze data, and get AI-powered insights within Splunk searches.

### Key Features

- **Multiple LLM Providers**: OpenAI, Azure OpenAI, Anthropic, Groq, Gemini, Ollama, Circuit AI (Other)
- **Smart Assistant UI**: Interactive chat interface within ML Toolkit
- **SPL Command Integration**: Use `| ai` in any search
- **Secure Credentials**: OAuth2/API keys stored in Splunk's encrypted storage
- **Streaming Support**: Real-time responses in search results

---

## Prerequisites

### 1. Python for Scientific Computing Add-on

The ML Toolkit requires the **Python for Scientific Computing** add-on:

```bash
# Check if installed
/opt/splunk/bin/splunk search "| rest /services/apps/local | search title=*python*"
```

**Installation**:
1. Download from Splunkbase: "Python for Scientific Computing"
2. Install via Splunk Web: **Manage Apps → Install from File**
3. Restart Splunk

### 2. mltk_admin Role

Users must have the **mltk_admin** role to configure Connection Management:

```bash
# Assign via CLI
/opt/splunk/bin/splunk edit user <username> -role mltk_admin -auth admin:password

# Or via REST API
curl -k -u admin:password \
  -X POST "https://localhost:8089/services/authentication/users/<username>" \
  -d "roles=mltk_admin"
```

### 3. Connection Management Configuration

Navigate to: **Apps → ML Toolkit → Connection Management**

---

## Provider Configuration

### Circuit AI (Other Provider)

| Field | Value | Description |
|-------|-------|-------------|
| **Select Service** | Other | Custom provider for Circuit API |
| **Endpoint** | `https://chat-ai.cisco.com` | Circuit AI API endpoint |
| **Token URL** | `https://id.cisco.com/oauth2/default/v1/token` | Cisco OAuth token endpoint |
| **Client ID** | `[Your Client ID]` | From Cisco API portal |
| **Client Secret** | `[Your Client Secret]` | From Cisco API portal |
| **App Key** | `[Your App Key]` | e.g., `egai-prd-ther-xxxxx` |
| **Request Timeout** | `200` | Seconds |
| **Select Model** | `gpt-4o-mini` | Or gpt-4o, gpt-4, claude-3-5-sonnet |

### OpenAI

| Field | Value |
|-------|-------|
| **Select Service** | OpenAI |
| **API Key** | `sk-...` |
| **Model** | gpt-4, gpt-4-turbo, gpt-3.5-turbo |

### Azure OpenAI

| Field | Value |
|-------|-------|
| **Select Service** | AzureOpenAI |
| **Endpoint** | Your Azure endpoint |
| **API Key** | Your Azure API key |
| **Deployment Name** | Your deployment name |

---

## Basic Syntax

```spl
| ai prompt="<your question or prompt>"
```

### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `prompt` | Yes | The question or prompt to send to the LLM |

### Output Fields

| Field | Description |
|-------|-------------|
| `response` | The AI-generated response |
| `model` | The model used |
| `provider` | The LLM provider |

---

## SPL Examples

### Simple Question

```spl
| makeresults 
| eval prompt="What is Splunk Enterprise Security?"
| ai prompt=prompt
| table prompt response
```

### Explain a Concept

```spl
| makeresults
| ai prompt="Explain the difference between a Splunk indexer and search head in simple terms"
| table response
```

### Security Analysis

```spl
| makeresults
| ai prompt="What are the MITRE ATT&CK techniques associated with ransomware attacks?"
| table response
```

### Log Analysis

```spl
index=_internal sourcetype=splunkd ERROR
| head 1
| eval prompt="Explain this Splunk error: " . _raw
| ai prompt=prompt
| table _time _raw response
```

### Windows Event Analysis

```spl
index=winevents EventCode=4625
| head 3
| eval prompt="Analyze this failed login event: User=" . Account_Name . ", Source IP=" . src_ip
| ai prompt=prompt
| table _time Account_Name src_ip response
```

### Field Value Analysis

```spl
index=main
| head 5
| eval prompt="Analyze this event: " . _raw
| ai prompt=prompt
| table _time response
```

---

## Security Operations Prompts

### Threat Intelligence

```spl
| makeresults
| eval ip="185.234.219.47"
| eval prompt="What threat intelligence do you have on IP address " . ip . "?"
| ai prompt=prompt
| table ip response
```

### MITRE ATT&CK Lookup

```spl
| makeresults
| eval technique="T1059.001"
| eval prompt="Explain MITRE ATT&CK technique " . technique . " and provide detection strategies"
| ai prompt=prompt
| table technique response
```

### Notable Event Triage

```spl
index=notable
| head 5
| eval prompt="Triage this security alert: Rule=" . rule_name . ", Severity=" . urgency . ", Description=" . rule_description
| ai prompt=prompt
| table rule_name urgency response
```

### Incident Response

```spl
| makeresults
| eval prompt="I found evidence of credential dumping (T1003) on a Windows server. What are the immediate containment and remediation steps?"
| ai prompt=prompt
| table response
```

---

## Splunk Administration Prompts

### SPL Help

```spl
| makeresults
| ai prompt="How do I use the tstats command to count events by sourcetype over time?"
| table response
```

### Configuration Questions

```spl
| makeresults
| ai prompt="What are the recommended index retention settings for a 1TB/day Splunk deployment?"
| table response
```

### Troubleshooting

```spl
| makeresults
| ai prompt="My Splunk search head cluster captain is failing over frequently. What are the common causes and how do I troubleshoot?"
| table response
```

### Architecture Questions

```spl
| makeresults
| ai prompt="What is the recommended architecture for a Splunk deployment handling 500GB/day with high availability requirements?"
| table response
```

---

## Data Analysis Prompts

### Field Extraction

```spl
index=main sourcetype=custom_app
| head 1
| eval prompt="Suggest regex field extractions for this log format: " . _raw
| ai prompt=prompt
| table _raw response
```

### Sourcetype Classification

```spl
index=main
| head 10
| stats values(_raw) as samples by sourcetype
| eval prompt="What type of data does this sourcetype contain based on these samples: " . samples
| ai prompt=prompt
| table sourcetype response
```

### Data Quality

```spl
| makeresults
| ai prompt="What are best practices for ensuring data quality in Splunk? How do I detect timestamp parsing issues?"
| table response
```

---

## Smart Assistant UI

The ML Toolkit includes a **Smart Assistant** chat interface:

1. Navigate to **Apps → ML Toolkit**
2. Click **AI Assistant** or **Smart Assistant** in the menu
3. Type questions in natural language
4. View responses in the chat interface

### Example Questions for Smart Assistant

- "How do I create a dashboard?"
- "What is the syntax for the stats command?"
- "How do I set up alerts in Splunk?"
- "Explain the difference between search-time and index-time field extractions"
- "What is ITSI and what are its key features?"

---

## Batch Processing

### Analyze Multiple Events

```spl
index=winevents EventCode IN (4624, 4625, 4648)
| head 10
| eval prompt="Classify this Windows event as normal or suspicious: EventCode=" . EventCode . ", User=" . Account_Name . ", LogonType=" . Logon_Type
| ai prompt=prompt
| table _time EventCode Account_Name response
```

### Multi-Event Summary

```spl
index=_internal ERROR
| head 20
| stats count by component
| eval prompt="Summarize these Splunk internal errors and prioritize which to investigate first: Component=" . component . ", Count=" . count
| ai prompt=prompt
| table component count response
```

---

## Best Practices

### 1. Be Specific with Prompts

```spl
# Good - specific context
| ai prompt="Analyze this Windows failed login (EventCode 4625) and determine if it indicates a brute force attack: User=admin, Source=192.168.1.100, FailureCount=50"

# Less Good - vague
| ai prompt="Is this suspicious?"
```

### 2. Include Relevant Context

```spl
| eval prompt="Given this Splunk error message, explain the cause and suggest a fix. Error: " . _raw
```

### 3. Limit Results for Batch Analysis

```spl
index=main
| head 10  # Process only 10 events
| ai prompt="Analyze: " . _raw
```

### 4. Use Tables for Readable Output

```spl
| ai prompt="..."
| table _time source response
```

### 5. Request Structured Output

```spl
| ai prompt="Analyze this IOC and return your assessment in JSON format with fields: verdict, confidence, threat_type, recommended_action"
```

---

## Troubleshooting

### "Connection Management is not yet configured"

1. Navigate to **Apps → ML Toolkit → Connection Management**
2. Select a provider and enter credentials
3. Click **Save** or **Test Connection**

### "mltk_admin role required"

1. Go to **Settings → Access Controls → Users**
2. Edit the user and add `mltk_admin` role
3. User must log out and log back in

### "Python for Scientific Computing not installed"

1. Download from Splunkbase
2. Install via **Manage Apps → Install from File**
3. Restart Splunk

### Connection Errors

```bash
# Check network connectivity
curl -v https://chat-ai.cisco.com

# Check OAuth token
curl -X POST "https://id.cisco.com/oauth2/default/v1/token" \
  -H "Authorization: Basic $(echo -n 'client_id:secret' | base64)" \
  -d "grant_type=client_credentials"
```

### Debug Logging

```bash
# Check python.log for errors
tail -100 $SPLUNK_HOME/var/log/splunk/python.log | grep -i "ai_commander\|mltk"
```

---

## Security Considerations

- Credentials stored in Splunk's encrypted `passwords.conf`
- OAuth tokens cached for ~50 minutes (refreshed automatically)
- All API calls use TLS
- Sensitive fields masked in UI (marked as `hidden: true`)
- Prompts and responses may be logged - review data handling policies

---

## Available Models by Provider

### Circuit AI (Other)

| Model | Description |
|-------|-------------|
| `gpt-4o-mini` | Fast, cost-effective (default) |
| `gpt-4o` | Latest GPT-4 Omni |
| `gpt-4` | GPT-4 base |
| `claude-3-5-sonnet` | Anthropic Claude 3.5 Sonnet |
| `claude-3-haiku` | Anthropic Claude 3 Haiku (fast) |
| `o1-mini` | OpenAI o1 Mini (reasoning) |
| `o1-preview` | OpenAI o1 Preview (reasoning) |

### OpenAI

- gpt-4-turbo
- gpt-4
- gpt-3.5-turbo

### Azure OpenAI

- Configured deployment names

### Anthropic

- claude-3-opus
- claude-3-sonnet
- claude-3-haiku

---

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   SPL Search    │────▶│   AI Commander   │────▶│   LLM Provider  │
│   | ai ...      │     │   (Python)       │     │   (Circuit/OAI) │
└─────────────────┘     └────────┬─────────┘     └─────────────────┘
                                 │
                                 │ OAuth2 Token
                                 ▼
                        ┌──────────────────┐
                        │  oauth_helper.py │
                        │  (Token Cache)   │
                        └────────┬─────────┘
                                 │
                                 ▼
                        ┌──────────────────┐
                        │  passwords.conf  │
                        │  (Encrypted)     │
                        └──────────────────┘
```

---

## File Locations

| File | Path | Purpose |
|------|------|---------|
| `constants.py` | `bin/ai_commander/` | Provider configurations |
| `llm_factory.py` | `bin/ai_commander/` | LLM request building |
| `llm_base.py` | `bin/ai_commander/` | HTTP request handling |
| `oauth_helper.py` | `bin/ai_commander/` | OAuth token caching |
| `ai_commander_util.py` | `bin/ai_commander/` | Credential storage |

---

## Comparison: AI Commander vs AI Model Runner

| Feature | ML Toolkit AI Commander | AI Model Runner App |
|---------|------------------------|---------------------|
| **Command** | `\| ai` | `\| aimodel` |
| **RAG Support** | No (built-in) | Yes (`rag=true`) |
| **Field Substitution** | Manual (`eval prompt=...`) | Built-in (`${field}`) |
| **UI** | Smart Assistant | Setup page only |
| **Providers** | Multiple built-in | Circuit AI only |
| **Installation** | Included in ML Toolkit | Separate app |

---

## Related Documentation

- [Splunk ML Toolkit Circuit AI Configuration](splunk_mltk_circuit_ai_config.md)
- [Splunk AI Model Runner Command Guide](splunk_aimodel_command_guide.md)
- [Splunk ML Toolkit Prerequisites](splunk_mltk_ai_prerequisites.md)
