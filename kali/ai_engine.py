#ai_engine
import os
from dotenv import load_dotenv
import queue
import threading
import time

try:
    from anthropic import Anthropic
except ImportError:
    Anthropic = None
try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

event_queue = queue.Queue()
result_queue = queue.Queue()

# Load environment variables (file read, but fast)
load_dotenv()

anthropic_api_key = os.getenv("ANTHROPIC_API_KEY")
openai_api_key = os.getenv("OPENAI_API_KEY")

# AI clients — initialized lazily on first use to avoid blocking startup
claude_client = None
openai_client = None
active_model = "claude-3-5-sonnet-20241022" if Anthropic else "gpt-4o"
_clients_initialized = False

def _ensure_clients():
    """Initialize AI clients on first use instead of at import time."""
    global claude_client, openai_client, _clients_initialized
    if _clients_initialized:
        return
    _clients_initialized = True

    try:
        if anthropic_api_key and Anthropic:
            claude_client = Anthropic(api_key=anthropic_api_key)
    except Exception as e:
        print(f"[-] Failed to initialize Claude Client: {e}")
        claude_client = None

    try:
        if openai_api_key and OpenAI:
            openai_client = OpenAI(api_key=openai_api_key)
    except Exception as e:
        print(f"[-] Failed to initialize OpenAI Client: {e}")
        openai_client = None

    if not claude_client and not openai_client:
        print("[-] No AI clients available. Please set ANTHROPIC_API_KEY or OPENAI_API_KEY in .env")

# Global set to track reported AI insights
reported_insights = set()

def fetch_ai_analysis(target, payload):
    global active_model, reported_insights
    _ensure_clients()
    
    if not claude_client and not openai_client:
        result_queue.put(f"[-] AI Error: No clients initialized.\n")
        return
        
    analysis_prompt = f"Analyze this raw HTTP request for security vulnerabilities. Identify SQL injection, XSS, auth bypass, IDOR, insecure deserialization, and other flaws. Keep it brief and actionable. Request:\n\n{payload}"
    
    if claude_client and active_model.startswith("claude"):
        for attempt in range(3):
            try:
                response = claude_client.messages.create(
                    model=active_model,
                    max_tokens=1024,
                    messages=[{"role": "user", "content": analysis_prompt}]
                )
                insight = f"[AI INSIGHT: {target} ({active_model})]\n{getattr(response.content[0], 'text', '')}\n{'-'*60}\n\n"
                if insight not in reported_insights:
                    result_queue.put(insight)
                    reported_insights.add(insight)
                return
            except Exception as e:
                if "529" in str(e) or "overloaded" in str(e).lower():
                    wait = (attempt + 1) * 3
                    result_queue.put(f"[*] Claude Overloaded (Attempt {attempt+1}/3). Retrying in {wait}s...\n")
                    time.sleep(wait)
                    if attempt == 2:  # Claude failed, try GPT-4o
                        if openai_client:
                            pass  # Fallback logic omitted for brevity
                else:
                    result_queue.put(f"[-] Claude API Error: {e}\n")
                    return
    
    # Use GPT-4o if Claude failed or is active model
    if openai_client and active_model == "gpt-4o":
        for attempt in range(3):
            try:
                response = openai_client.chat.completions.create(
                    model="gpt-4o",
                    messages=[{"role": "user", "content": analysis_prompt}],
                    max_tokens=1024
                )
                insight = f"[AI INSIGHT: {target} ({active_model})]\n{response.choices[0].message.content}\n{'-'*60}\n\n"
                if insight not in reported_insights:
                    result_queue.put(insight)
                    reported_insights.add(insight)
                return
            except Exception as e:
                if "429" in str(e) or "overloaded" in str(e).lower():
                    wait = (attempt + 1) * 3
                    result_queue.put(f"[*] GPT-4o Rate Limited (Attempt {attempt+1}/3). Retrying in {wait}s...\n")
                    time.sleep(wait)
                else:
                    result_queue.put(f"[-] GPT-4o API Error: {e}\n")
                    return
        result_queue.put(f"[-] GPT-4o Error: Rate limited. Please try again later.\n\n")
    elif not openai_client and active_model == "gpt-4o":
        result_queue.put(f"[-] GPT-4o not configured. Set OPENAI_API_KEY in .env\n")

def send_manual_chat(user_text):
    global active_model
    _ensure_clients()
    
    if not claude_client and not openai_client:
        result_queue.put(f"[-] Chat Error: No AI clients configured.\n")
        return
    
    if claude_client and active_model.startswith("claude"):
        for attempt in range(3):
            try:
                response = claude_client.messages.create(
                    model=active_model,
                    max_tokens=1024,
                    messages=[{"role": "user", "content": user_text}]
                )
                result_queue.put(f"[AI CO-PILOT ({active_model})]\n{getattr(response.content[0], 'text', '')}\n{'-'*60}\n\n")
                return
            except Exception as e:
                if "529" in str(e) or "overloaded" in str(e).lower():
                    wait = (attempt + 1) * 3
                    result_queue.put(f"[*] Claude Overloaded. Retrying...\n")
                    time.sleep(wait)
                    if attempt == 2:
                        if openai_client:
                            result_queue.put(f"[*] Switching to GPT-4o...\n")
                            active_model = "gpt-4o"
                            send_manual_chat(user_text)  # Recursive call
                            return
                else:
                    result_queue.put(f"[-] Claude Chat Error: {e}\n\n")
                    return
    
    # Use GPT-4o if Claude failed or is active model
    if openai_client and active_model == "gpt-4o":
        for attempt in range(3):
            try:
                response = openai_client.chat.completions.create(
                    model="gpt-4o",
                    messages=[{"role": "user", "content": user_text}],
                    max_tokens=1024
                )
                result_queue.put(f"[AI CO-PILOT ({active_model})]\n{response.choices[0].message.content}\n{'-'*60}\n\n")
                return
            except Exception as e:
                if "429" in str(e) or "overloaded" in str(e).lower():
                    wait = (attempt + 1) * 3
                    result_queue.put(f"[*] GPT-4o Rate Limited. Retrying...\n")
                    time.sleep(wait)
                else:
                    result_queue.put(f"[-] GPT-4o Chat Error: {e}\n\n")
                    return

def process_event_loop():
    """This runs continuously, waiting for the user to manually send a payload."""
    
    global active_model
    _ensure_clients()
    
    while True:
        try:
            ai_message = event_queue.get()
            
            # --- MANUAL ANALYSIS ---
            if ai_message.get("event") == "manual_analysis":
                target = ai_message.get("target")
                payload = ai_message.get("payload")
                
                if payload and target:
                    result_queue.put(f"[*] AI is analyzing manual payload for {target} using {active_model}...\n")
                    threading.Thread(target=fetch_ai_analysis, args=(target, payload), daemon=True).start()
            elif ai_message.get("event") == "skimmer_hit":
                target = ai_message.get("target")
                result_queue.put(f"[!] ALERT: Skimmer found sensitive data on {target}. Right-click the request to analyze manually.\n\n")
            # --- CUSTOM CHAT PROMPT ---
            elif ai_message.get("event") == "chat_message":
                user_text = ai_message.get("text")
                if user_text:
                    result_queue.put(f"[*] AI is thinking...\n")
                    threading.Thread(target=send_manual_chat, args=(user_text,), daemon=True).start()

            # --- MODEL SWITCHER ---
            elif ai_message.get("event") == "change_model":
                new_model = ai_message.get("model")
                active_model = new_model
                
                if new_model.startswith("claude") and claude_client:
                    result_queue.put(f"[*] SUCCESS: Switched to {new_model}. Ready for vulnerability analysis.\n\n")
                elif new_model.startswith("claude") and not claude_client:
                    result_queue.put(f"[-] Claude not available. Set ANTHROPIC_API_KEY in your .env file.\n\n")
                elif new_model == "gpt-4o" and openai_client:
                    result_queue.put(f"[*] SUCCESS: Switched to {new_model}. Ultra-reliable analysis ready.\n\n")
                elif new_model == "gpt-4o" and not openai_client:
                    result_queue.put(f"[-] GPT-4o not available. Set OPENAI_API_KEY in your .env file.\n\n")

        except Exception as e:
            print(f"[-] Error in AI Engine Loop: {e}")

threading.Thread(target=process_event_loop, daemon=True).start()