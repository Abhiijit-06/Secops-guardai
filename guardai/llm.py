import os

from langchain_google_genai import ChatGoogleGenerativeAI
from dotenv import load_dotenv


def get_llm():
    """Initialize Gemini using an environment variable, never a hardcoded key."""
    load_dotenv()
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        raise RuntimeError(
            "GOOGLE_API_KEY is missing. Set it in your environment or local .env file."
        )

    model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    return ChatGoogleGenerativeAI(
        model=model,
        google_api_key=api_key,
        temperature=0,
        max_tokens=2048,
    )
