# AI Co-Pilot Setup Guide

## Supported Models

### Claude (Anthropic)

- `claude-3-5-sonnet-20241022` — **Best for vulnerability analysis**, more reliable under load

## Environment Setup

Create or update your `.env` file in the NetMan directory:

```bash
ANTHROPIC_API_KEY=your_anthropic_api_key_here
OPENAI_API_KEY=your_openai_api_key_here
```

## How It Works

### Manual Model Selection

- Use the dropdown menu in the "AI Co-Pilot" tab to switch models
- Available at startup and anytime during analysis

### Automatic Fallback

- If **Claude returns 503 (overloaded) or 429 (rate limited):
  - System attempts 3 retries with exponential backoff
  - After 3 failures → automatically switches to GPT-4o
  - Logs the switch so you know what happened

### Vulnerability Analysis

- Right-click any request and select "Send to AI"
- Claude specializes in:
  - SQL Injection detection
  - Cross-Site Scripting (XSS)
  - Insecure Deserialization
  - IDOR (Insecure Direct Object References)
  - Authentication bypass flaws
  - Logic vulnerabilities

## API Keys

**Get Claude API Key:**

1. Go to https://console.anthropic.com
2. Create an API key
3. Paste into `.env`

**Get OpenAI API Key:**

1. Go to https://platform.openai.com/api-keys
2. Create an API key
3. Paste into `.env`

## Troubleshooting

| Issue                              | Solution                                                      |
| ---------------------------------- | ------------------------------------------------------------- |
| "No AI clients configured"         | Check `.env` for valid API keys                               |
| Claude not switching automatically | Ensure `ANTHROPIC_API_KEY` is set                             |
| Claude keeps failing               | Switch manually to GPT-4o, or wait for auto-activation        |
| "Service overloaded" for Claude    | Try again in 5 minutes or switch to GPT-4o                    |

## Performance Notes

- **Claude** is more consistent under server load and best for vulnerability reasoning
- **GPT-4o** is a strong fallback for lightweight and general analysis
- Each model maintains separate conversation context (history doesn't transfer between providers)
