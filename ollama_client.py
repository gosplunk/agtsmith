import httpx
from scripts.runtime_config import get_ollama_host

OLLAMA_HOST = get_ollama_host()
DEFAULT_MODEL = "hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M"


def generate(prompt: str, model: str = DEFAULT_MODEL, timeout: float = 120.0) -> str:
    """Run a non-streaming Ollama generation request and return text.

    This wrapper keeps settings explicit for this lab:
    - stream=False for simple deterministic request/response handling
    - think=False based on validated behavior for current model
    """
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "think": False,
    }

    with httpx.Client(timeout=timeout) as client:
        response = client.post(f"{OLLAMA_HOST}/api/generate", json=payload)
        response.raise_for_status()
        data = response.json()

    text = data.get("response", "").strip()
    if not text:
        raise RuntimeError(
            "Ollama returned an empty response body. "
            f"done={data.get('done')} done_reason={data.get('done_reason')} "
            f"eval_count={data.get('eval_count')}"
        )

    return text


if __name__ == "__main__":
    reply = generate("Reply with exactly: CUSTOM_OLLAMA_WRAPPER_OK")
    print(reply)
