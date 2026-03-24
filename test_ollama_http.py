import httpx
import json
from scripts.runtime_config import get_ollama_host

OLLAMA_HOST = get_ollama_host()
MODEL_NAME = "hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M"

payload = {
    "model": MODEL_NAME,
    "prompt": "Reply with exactly: OLLAMA_HTTP_THINK_OFF_OK",
    "stream": False,
    "think": False
}

with httpx.Client(timeout=120.0) as client:
    response = client.post(f"{OLLAMA_HOST}/api/generate", json=payload)
    response.raise_for_status()
    data = response.json()

print("\n=== raw json ===")
print(json.dumps(data, indent=2))
