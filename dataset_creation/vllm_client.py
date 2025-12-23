#!/usr/bin/env python3
"""
Shared vLLM client module for parallel LLM inference.
Uses OpenAI-compatible API with asyncio for concurrent requests.
"""

import asyncio
import aiohttp
import json
import logging
import re
from typing import Optional, List, Dict, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class VLLMConfig:
    """Configuration for vLLM client."""
    base_url: str = "http://localhost:8000"
    model: str = "nemotron"
    max_tokens: int = 3072  # 2816 response + 256 reasoning budget
    temperature: float = 0.7
    timeout: int = 120
    max_concurrent: int = 8  # Maximum concurrent requests
    enable_thinking: bool = True  # Enable reasoning with budget limit
    reasoning_budget: int = 256  # Limit thinking tokens for quality reasoning
    max_retries: int = 3  # Maximum retries for transient errors
    retry_delay: float = 1.0  # Base delay between retries (exponential backoff)


class VLLMClient:
    """Async client for vLLM OpenAI-compatible API with parallel processing."""

    def __init__(self, config: VLLMConfig = None):
        self.config = config or VLLMConfig()
        self.semaphore = asyncio.Semaphore(self.config.max_concurrent)
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.config.timeout)
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._session:
            await self._session.close()

    def _clean_thinking_tags(self, text: str) -> str:
        """Remove <think>...</think> tags from response."""
        if text is None:
            return ""
        if "<think>" in text and "</think>" in text:
            text = text.split("</think>")[-1].strip()
        return text

    def _extract_json(self, text: str) -> Optional[Dict]:
        """Extract JSON from text response."""
        text = self._clean_thinking_tags(text)

        # Try to find JSON in code blocks
        if "```json" in text:
            try:
                json_content = text.split("```json", 1)[1].split("```", 1)[0].strip()
                return json.loads(json_content)
            except (json.JSONDecodeError, IndexError):
                pass

        if "```" in text:
            parts = text.split("```")
            for part in parts:
                part = part.strip()
                if part.startswith("{") or part.startswith("["):
                    try:
                        return json.loads(part)
                    except json.JSONDecodeError:
                        continue

        # Try to find JSON object/array directly
        for start_char, end_char in [('{', '}'), ('[', ']')]:
            start_idx = text.find(start_char)
            end_idx = text.rfind(end_char)
            if start_idx >= 0 and end_idx > start_idx:
                try:
                    return json.loads(text[start_idx:end_idx + 1])
                except json.JSONDecodeError:
                    continue

        return None

    def _is_retryable_error(self, error: Exception) -> bool:
        """Check if an error is transient and worth retrying."""
        error_str = str(error).lower()
        retryable_patterns = [
            'can not write request body',
            'connection reset',
            'connection refused',
            'server disconnected',
            'temporary failure',
            'too many requests',
            'service unavailable',
            'bad gateway',
            'gateway timeout',
        ]
        return any(pattern in error_str for pattern in retryable_patterns)

    async def chat_completion(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = None,
        temperature: float = None,
    ) -> Optional[str]:
        """Send a chat completion request to vLLM with automatic retry on transient errors."""
        async with self.semaphore:
            last_error = None

            for attempt in range(self.config.max_retries + 1):
                try:
                    # Build chat_template_kwargs for Nemotron reasoning control
                    chat_template_kwargs = {
                        "enable_thinking": self.config.enable_thinking,
                        "reasoning_budget": self.config.reasoning_budget,
                    }

                    payload = {
                        "model": self.config.model,
                        "messages": messages,
                        "max_tokens": max_tokens or self.config.max_tokens,
                        "temperature": temperature or self.config.temperature,
                        "chat_template_kwargs": chat_template_kwargs,
                    }

                    async with self._session.post(
                        f"{self.config.base_url}/v1/chat/completions",
                        json=payload,
                    ) as response:
                        if response.status == 200:
                            result = await response.json()
                            try:
                                message = result["choices"][0]["message"]
                                # Nemotron returns content in different fields depending on thinking mode
                                content = message.get("content")
                                if not content:
                                    # When enable_thinking=false, response may be in reasoning_content
                                    content = message.get("reasoning_content", "")
                                return self._clean_thinking_tags(content) if content else ""
                            except (KeyError, IndexError) as e:
                                logger.error(f"Unexpected vLLM response format: {e}")
                                return None
                        elif response.status in (502, 503, 504, 429):
                            # Retryable HTTP errors
                            error_text = await response.text()
                            last_error = f"HTTP {response.status}: {error_text[:100]}"
                            if attempt < self.config.max_retries:
                                delay = self.config.retry_delay * (2 ** attempt)
                                logger.warning(f"vLLM error {response.status}, retrying in {delay:.1f}s ({attempt + 1}/{self.config.max_retries})...")
                                await asyncio.sleep(delay)
                                continue
                        else:
                            error_text = await response.text()
                            logger.error(f"vLLM API error {response.status}: {error_text}")
                            return None

                except asyncio.TimeoutError:
                    last_error = f"Timeout after {self.config.timeout}s"
                    if attempt < self.config.max_retries:
                        delay = self.config.retry_delay * (2 ** attempt)
                        logger.warning(f"vLLM timeout, retrying in {delay:.1f}s ({attempt + 1}/{self.config.max_retries})...")
                        await asyncio.sleep(delay)
                        continue
                    logger.error(f"vLLM request timed out after {self.config.max_retries + 1} attempts")
                    return None

                except Exception as e:
                    last_error = str(e)
                    if self._is_retryable_error(e) and attempt < self.config.max_retries:
                        delay = self.config.retry_delay * (2 ** attempt)
                        logger.warning(f"vLLM connection error, retrying in {delay:.1f}s ({attempt + 1}/{self.config.max_retries})...")
                        await asyncio.sleep(delay)
                        continue
                    logger.error(f"vLLM request failed: {str(e)}")
                    return None

            # All retries exhausted
            logger.error(f"vLLM request failed after {self.config.max_retries + 1} attempts: {last_error}")
            return None

    async def chat_completion_json(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = None,
        temperature: float = None,
    ) -> Optional[Dict]:
        """Send a chat completion request and parse JSON response."""
        response = await self.chat_completion(messages, max_tokens, temperature)
        if response:
            return self._extract_json(response)
        return None

    async def simple_query(
        self,
        prompt: str,
        system_prompt: str = "You are a helpful assistant.",
        max_tokens: int = None,
        temperature: float = None,
    ) -> Optional[str]:
        """Simple query with system and user prompts."""
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ]
        return await self.chat_completion(messages, max_tokens, temperature)

    async def simple_query_json(
        self,
        prompt: str,
        system_prompt: str = "You are a helpful assistant. Always respond with valid JSON.",
        max_tokens: int = None,
        temperature: float = None,
    ) -> Optional[Dict]:
        """Simple query expecting JSON response."""
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ]
        return await self.chat_completion_json(messages, max_tokens, temperature)

    async def batch_process(
        self,
        items: List[Any],
        process_func,
        desc: str = "Processing",
    ) -> List[Any]:
        """Process a batch of items concurrently."""
        tasks = [process_func(item) for item in items]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Handle exceptions
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Error processing item {i}: {result}")
                processed_results.append(None)
            else:
                processed_results.append(result)

        return processed_results


async def check_vllm_health(base_url: str = "http://localhost:8000") -> bool:
    """Check if vLLM server is healthy."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{base_url}/health", timeout=aiohttp.ClientTimeout(total=5)) as response:
                return response.status == 200
    except Exception as e:
        logger.error(f"vLLM health check failed: {e}")
        return False


async def get_vllm_models(base_url: str = "http://localhost:8000") -> List[str]:
    """Get list of available models from vLLM."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{base_url}/v1/models", timeout=aiohttp.ClientTimeout(total=5)) as response:
                if response.status == 200:
                    result = await response.json()
                    return [model["id"] for model in result.get("data", [])]
                return []
    except Exception as e:
        logger.error(f"Failed to get vLLM models: {e}")
        return []
