from langchain_ollama import ChatOllama
from scripts.runtime_config import get_ollama_host

OLLAMA_HOST = get_ollama_host()
MODEL_NAME = "hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M"

llm = ChatOllama(
    model=MODEL_NAME,
    base_url=OLLAMA_HOST,
    temperature=0,
    think=False,
)

response = llm.invoke("Reply with exactly: LANGCHAIN_THINK_OFF_OK")

print("\n=== response.content ===")
print(repr(response.content))

print("\n=== full object ===")
print(response)
