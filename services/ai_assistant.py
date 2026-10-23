import os
from dotenv import load_dotenv
from google import genai

load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")
model_name = os.getenv("GEMINI_MODEL")

client = genai.Client(api_key=api_key) if api_key else None


def explain_finding(finding):
    if client is None:
        raise RuntimeError(
            "Gemini API key is missing. Check your .env file."
        )

    if not model_name:
        raise RuntimeError(
            "Gemini model is missing. Check your .env file."
        )

    response = client.models.generate_content(
        model=model_name,
        contents=f"""
        You are a defensive web security assistant.

        Explain this web security finding:
        {finding}

        Include:
        1. What it means
        2. Why it matters
        3. Recommended remediation steps
        4. How to verify the fix safely

        Keep the explanation clear and practical.
        """
    )

    return response.text or "No explanation was returned."