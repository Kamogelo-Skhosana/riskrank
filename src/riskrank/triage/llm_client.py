"""LLM client wrapper for the triage layer.

Ticket: R022
"""


class LLMClient:
    def __init__(self, api_key: str, model: str):
        self.api_key = api_key
        self.model = model

    def complete(self, prompt: str) -> str:
        """Send a prompt to the LLM and return the raw text response.

        TODO (R022): implement the actual API call, with retries and
        basic rate limiting. Tests should mock this method — see R025.
        """
        raise NotImplementedError
