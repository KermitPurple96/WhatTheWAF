"""
Automatic retry strategies when WAF blocks are detected.
"""

import random
import time
from typing import Any, Dict, List, Optional

import httpx

BROWSER_UAS: List[str] = [
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    # Chrome on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    # Firefox on Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    # Safari on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    # Chrome on Android
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    # Safari on iOS
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
]

BLOCK_STATUS_CODES = {403, 406, 429, 503}

BLOCK_KEYWORDS = [
    "access denied",
    "blocked",
    "captcha",
    "challenge",
    "attention required",
    "rate limit",
    "please wait",
    "checking your browser",
    "just a moment",
]


class ResponseAdvisor:
    """Detects WAF blocks and provides escalating retry strategies."""

    def __init__(
        self,
        max_retries: int = 3,
        strategies: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        self.max_retries = max_retries
        self._used_uas: List[str] = []
        if strategies is not None:
            self.strategies = strategies
        else:
            self.strategies = self._default_strategies()

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    @staticmethod
    def is_blocked(
        status_code: int,
        body: str = "",
        headers: Optional[Dict[str, str]] = None,
    ) -> bool:
        """Return True when the response looks like a WAF block."""
        if status_code in BLOCK_STATUS_CODES:
            return True
        body_lower = body.lower()
        for keyword in BLOCK_KEYWORDS:
            if keyword in body_lower:
                return True
        return False

    # ------------------------------------------------------------------
    # Strategy helpers
    # ------------------------------------------------------------------

    def _pick_ua(self) -> str:
        """Pick a random User-Agent that hasn't been used yet in this session."""
        available = [ua for ua in BROWSER_UAS if ua not in self._used_uas]
        if not available:
            # All exhausted – reset and pick again
            self._used_uas.clear()
            available = list(BROWSER_UAS)
        chosen = random.choice(available)
        self._used_uas.append(chosen)
        return chosen

    @staticmethod
    def _default_strategies() -> List[Dict[str, Any]]:
        """Built-in escalating retry strategies (indexed by attempt-1)."""
        return [
            # attempt 1: swap User-Agent
            {"change_ua": True, "delay": None, "cf_spoof": False},
            # attempt 2: swap UA + random delay
            {"change_ua": True, "delay": (1.0, 3.0), "cf_spoof": False},
            # attempt 3: swap UA + delay + CF header spoof
            {"change_ua": True, "delay": (1.0, 3.0), "cf_spoof": True},
        ]

    def get_retry_strategy(
        self,
        attempt_number: int,
        original_request: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return a strategy dict for the given 1-based attempt number."""
        idx = min(attempt_number - 1, len(self.strategies) - 1)
        strategy = dict(self.strategies[idx])

        # Resolve concrete values
        strategy["user_agent"] = self._pick_ua() if strategy.get("change_ua") else None

        if strategy.get("delay") is not None:
            low, high = strategy["delay"]
            strategy["delay_seconds"] = round(random.uniform(low, high), 2)
        else:
            strategy["delay_seconds"] = 0.0

        if strategy.get("cf_spoof"):
            strategy["extra_headers"] = {
                "CF-Connecting-IP": f"104.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}",
                "X-Forwarded-For": f"104.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}",
                "X-Real-IP": f"104.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}",
            }
        else:
            strategy["extra_headers"] = {}

        strategy["attempt"] = attempt_number
        return strategy

    @staticmethod
    def apply_strategy(
        strategy: Dict[str, Any],
        request_kwargs: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Modify *request_kwargs* in-place according to *strategy* and return it."""
        headers = dict(request_kwargs.get("headers", None) or {})

        if strategy.get("user_agent"):
            headers["User-Agent"] = strategy["user_agent"]

        if strategy.get("extra_headers"):
            headers.update(strategy["extra_headers"])

        request_kwargs["headers"] = headers

        delay = strategy.get("delay_seconds", 0.0)
        if delay > 0:
            time.sleep(delay)

        return request_kwargs


def retry_request(
    url: str,
    method: str = "GET",
    timeout: float = 10,
    max_retries: int = 3,
    proxy: Optional[str] = None,
) -> Dict[str, Any]:
    """Convenience wrapper: make a request with automatic WAF-block retries.

    Returns a dict with keys:
        status_code, headers, body, attempts, strategy_used
    """
    advisor = ResponseAdvisor(max_retries=max_retries)

    transport_kwargs: Dict[str, Any] = {}
    if proxy:
        transport_kwargs["proxy"] = proxy

    result: Dict[str, Any] = {
        "status_code": None,
        "headers": {},
        "body": "",
        "attempts": 0,
        "strategy_used": None,
    }

    request_kwargs: Dict[str, Any] = {
        "method": method,
        "url": url,
        "timeout": timeout,
        "headers": {"User-Agent": random.choice(BROWSER_UAS)},
        "follow_redirects": True,
    }

    with httpx.Client(**transport_kwargs) as client:
        for attempt in range(0, max_retries + 1):
            result["attempts"] = attempt + 1
            try:
                resp = client.request(**request_kwargs)
                status = resp.status_code
                body = resp.text
                resp_headers = dict(resp.headers)

                result["status_code"] = status
                result["headers"] = resp_headers
                result["body"] = body

                if not advisor.is_blocked(status, body, resp_headers):
                    # Success – no block detected
                    return result

                if attempt >= max_retries:
                    # Exhausted retries; return last response
                    return result

                # Blocked – escalate
                strategy = advisor.get_retry_strategy(
                    attempt_number=attempt + 1,
                    original_request=request_kwargs,
                )
                result["strategy_used"] = strategy
                request_kwargs = advisor.apply_strategy(strategy, request_kwargs)

            except httpx.HTTPError:
                if attempt >= max_retries:
                    return result
                # Network error – treat like a block and retry
                strategy = advisor.get_retry_strategy(
                    attempt_number=attempt + 1,
                    original_request=request_kwargs,
                )
                result["strategy_used"] = strategy
                request_kwargs = advisor.apply_strategy(strategy, request_kwargs)

    return result
