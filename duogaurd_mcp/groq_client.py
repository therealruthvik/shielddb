import os
from typing import Dict, Any

import httpx

# Groq exposes an OpenAI-compatible chat completions endpoint
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_CHAT_MODEL = "openai/gpt-oss-120b"


def chat_completion(payload: Dict[str, Any], timeout: float = 30.0) -> Dict[str, Any]:
    """Sends a chat completions request to Groq and returns the first choice's message."""
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError("GROQ_API_KEY is not set")
    response = httpx.post(
        GROQ_API_URL,
        json=payload,
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()["choices"][0]["message"]
