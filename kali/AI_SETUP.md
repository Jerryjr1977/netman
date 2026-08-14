# AI Co-Pilot Setup Guide

## Supported Models

### Gemini (Google)

- `gemini-2.5-flash` (default) — Fast, good for quick analysis
- `gemini-2.5-pro` — More powerful, better reasoning

### Claude (Anthropic)

- `claude-3-5-sonnet-20241022` — **Best for vulnerability analysis**, more reliable under load

## Environment Setup

Create or update your `.env` file in the NetMan directory:

```bash
GEMINI_API_KEY=your_gemini_api_key_here
ANTHROPIC_API_KEY=your_anthropic_api_key_here
```

## How It Works

### Manual Model Selection

- Use the dropdown menu in the "AI Co-Pilot" tab to switch models
- Available at startup and anytime during analysis

### Automatic Fallback (NEW)

- If \*\*Gemini returns 503 (overloaded or 429 (rate limited):
  - System attempts 3 retries with exponential backoff
  - After 3 failures → automatically switches to Claude
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

**Get Gemini API Key:**

1. Go to https://aistudio.google.com/app/apikey
2. Create a new API key
3. Paste into `.env`

**Get Claude API Key:**

1. Go to https://console.anthropic.com
2. Create an API key
3. Paste into `.env`

## Troubleshooting

| Issue                              | Solution                                                      |
| ---------------------------------- | ------------------------------------------------------------- |
| "No AI clients configured"         | Check `.env` for valid API keys                               |
| Claude not switching automatically | Ensure `ANTHROPIC_API_KEY` is set                             |
| Gemini keeps failing               | Switch manually to Claude, or wait for Claude auto-activation |
| "Service overloaded" for Claude    | Try again in 5 minutes or use Gemini                          |

## Performance Notes

- **Claude** is more consistent under server load
- **Gemini Flash** is faster for lightweight analysis
- **Gemini Pro** provides more detailed vulnerability reasoning
- Each model maintains separate conversation context (history doesn't transfer between providers)
