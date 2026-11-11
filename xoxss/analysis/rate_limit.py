"""
Smart rate limiting module for adaptive request management.
"""

import time
import asyncio
from typing import Dict, Optional
from dataclasses import dataclass
from collections import deque


@dataclass
class RateLimitStats:
    """Rate limiting statistics."""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_time: float = 0.0
    avg_response_time: float = 0.0
    current_rate: float = 0.0
    error_rate: float = 0.0


class SmartRateLimiter:
    """
    Adaptive smart rate limiter.
    Adjusts request rate based on response times and error rates.
    """

    def __init__(self, initial_rate: float = 10.0, min_rate: float = 1.0, max_rate: float = 50.0):
        self.initial_rate = initial_rate
        self.min_rate = min_rate
        self.max_rate = max_rate
        self.current_rate = initial_rate
        self._lock = None
        self._next_at = 0.0

        # Statistics
        self._stats = RateLimitStats()
        self._response_times = deque(maxlen=100)
        self._successes = deque(maxlen=50)
        self._failures = deque(maxlen=50)

        # Retry-After handling
        self._retry_after_delays: Dict[str, float] = {}

    async def acquire(self) -> None:
        """Wait for the next available request slot."""
        if not self._lock:
            self._lock = asyncio.Lock()

        interval = 1.0 / self.current_rate if self.current_rate > 0 else 0
        if interval <= 0:
            return

        async with self._lock:
            now = time.monotonic()
            wait = max(0.0, self._next_at - now)
            self._next_at = max(now, self._next_at) + interval
        if wait:
            await asyncio.sleep(wait)

    def record_request(
        self,
        success: bool,
        elapsed: float,
        is_retry: bool = False,
        retry_after: Optional[float] = None
    ) -> None:
        """
        Record a request result for adaptive rate adjustment.

        Args:
            success: Whether the request succeeded
            elapsed: Response time in seconds
            is_retry: Whether this was a retry
            retry_after: Retry-After header value if present
        """
        self._stats.total_requests += 1
        self._stats.total_time += elapsed
        self._response_times.append(elapsed)

        if success:
            self._stats.successful_requests += 1
            self._successes.append(1)
        else:
            self._stats.failed_requests += 1
            self._failures.append(1)

        # Handle Retry-After
        if retry_after:
            self.current_rate = self.min_rate
            self._retry_after_delays[str(time.monotonic())] = retry_after

        # Update statistics
        self._update_stats()

        # Adjust rate based on performance
        if self._stats.total_requests % 10 == 0:
            self._adjust_rate()

    def _update_stats(self) -> None:
        """Update rate limiting statistics."""
        if self._response_times:
            self._stats.avg_response_time = sum(self._response_times) / len(self._response_times)

        if self._stats.total_requests > 0:
            self._stats.error_rate = self._stats.failed_requests / self._stats.total_requests

        self._stats.current_rate = self.current_rate

    def _adjust_rate(self) -> None:
        """Adjust the rate based on recent performance."""
        if self._stats.total_requests == 0:
            return

        avg_time = self._stats.avg_response_time
        error_rate = self._stats.error_rate

        # Check for Retry-After delays
        current_time = time.monotonic()
        expired_delays = [k for k, v in self._retry_after_delays.items() if current_time - float(k) > v]
        for key in expired_delays:
            del self._retry_after_delays[key]

        if self._retry_after_delays:
            # Still under rate limit
            self.current_rate = self.min_rate
            return

        # Reduce rate if high error rate or slow responses
        if error_rate > 0.3 or avg_time > 2.0:
            new_rate = max(self.min_rate, self.current_rate * 0.8)
            self.current_rate = new_rate

        # Increase rate if low error rate and fast responses
        elif error_rate < 0.1 and avg_time < 0.5:
            new_rate = min(self.max_rate, self.current_rate * 1.1)
            self.current_rate = new_rate

    def get_stats(self) -> RateLimitStats:
        """Get current rate limiting statistics."""
        return self._stats

    def reset(self) -> None:
        """Reset the rate limiter to initial state."""
        self.current_rate = self.initial_rate
        self._stats = RateLimitStats()
        self._response_times.clear()
        self._successes.clear()
        self._failures.clear()
        self._retry_after_delays.clear()

    def set_rate(self, rate: float) -> None:
        """Manually set the current rate."""
        self.current_rate = max(self.min_rate, min(self.max_rate, rate))
