"""
Token calculation utilities for dynamic max_tokens management.
Handles calculating appropriate max_tokens based on context length and input size,
and parsing token-related errors for automatic retry.
"""
import re
from typing import Optional, Tuple


# Approximate characters per token (conservative estimate)
CHARS_PER_TOKEN = 4


def estimate_tokens(text: str) -> int:
    """Estimate token count from text length.

    Uses a conservative 4 chars per token estimate.
    This is an approximation - actual tokenization varies by model.
    """
    return len(text) // CHARS_PER_TOKEN


def calculate_max_tokens(
    prompt: str,
    requested_max_tokens: int,
    max_context_length: int,
    min_output_tokens: int = 100
) -> int:
    """Calculate appropriate max_tokens based on prompt size and context limits.

    Args:
        prompt: The input prompt text
        requested_max_tokens: The desired max_tokens setting
        max_context_length: The model's maximum context window (0 = unknown)
        min_output_tokens: Minimum tokens to reserve for output

    Returns:
        Adjusted max_tokens value that fits within context limits
    """
    if max_context_length <= 0:
        # Unknown context length - use requested value as-is
        return requested_max_tokens

    estimated_input = estimate_tokens(prompt)
    available_for_output = max_context_length - estimated_input

    # Ensure we have at least minimum output space
    if available_for_output < min_output_tokens:
        # Not enough room even for minimum output
        return min_output_tokens

    # Use the smaller of requested and available
    return min(requested_max_tokens, available_for_output)


def parse_max_tokens_error(error_message: str) -> Optional[Tuple[int, int, int]]:
    """Parse a max_tokens error message to extract context limits.

    Handles error messages like:
    - "'max_tokens' or 'max_completion_tokens' is too large: 11000. This model's maximum context length is 16384 tokens and your request has 5655 input tokens"
    - "This model's maximum context length is 8192 tokens, however you requested 10000 tokens"

    Returns:
        Tuple of (max_context_length, input_tokens, requested_max_tokens) or None if not parseable
    """
    if not error_message:
        return None

    # Pattern 1: vLLM style - "max_tokens is too large: X. model's maximum context length is Y tokens and your request has Z input tokens"
    pattern1 = r"max.*tokens.*too large:\s*(\d+).*maximum context length is\s*(\d+).*has\s*(\d+)\s*input"
    match1 = re.search(pattern1, error_message, re.IGNORECASE)
    if match1:
        requested = int(match1.group(1))
        max_context = int(match1.group(2))
        input_tokens = int(match1.group(3))
        return (max_context, input_tokens, requested)

    # Pattern 2: OpenAI style - "maximum context length is X tokens, however you requested Y tokens (Z in your prompt)"
    pattern2 = r"maximum context length is\s*(\d+).*requested\s*(\d+).*\((\d+).*prompt"
    match2 = re.search(pattern2, error_message, re.IGNORECASE)
    if match2:
        max_context = int(match2.group(1))
        requested = int(match2.group(2))
        input_tokens = int(match2.group(3))
        return (max_context, input_tokens, requested)

    # Pattern 3: Simple context exceeded - "context length is X tokens"
    pattern3 = r"context length is\s*(\d+)"
    match3 = re.search(pattern3, error_message, re.IGNORECASE)
    if match3:
        max_context = int(match3.group(1))
        # Try to find input tokens
        input_match = re.search(r"(\d+)\s*input", error_message, re.IGNORECASE)
        input_tokens = int(input_match.group(1)) if input_match else 0
        # Try to find requested tokens
        requested_match = re.search(r"too large:\s*(\d+)", error_message)
        requested = int(requested_match.group(1)) if requested_match else 0
        return (max_context, input_tokens, requested)

    return None


def calculate_retry_max_tokens(error_message: str, fallback_reduction: float = 0.5) -> Optional[int]:
    """Calculate a valid max_tokens from an error message for retry.

    Args:
        error_message: The error message containing token limits
        fallback_reduction: If we can't parse exact values, reduce by this factor

    Returns:
        A valid max_tokens value for retry, or None if can't determine
    """
    parsed = parse_max_tokens_error(error_message)

    if parsed:
        max_context, input_tokens, requested = parsed
        # Calculate available tokens with a small safety margin (95%)
        available = int((max_context - input_tokens) * 0.95)
        if available > 0:
            return available

    # Fallback: try to extract just the requested value and reduce it
    requested_match = re.search(r"too large:\s*(\d+)", error_message)
    if requested_match:
        requested = int(requested_match.group(1))
        return int(requested * fallback_reduction)

    return None


def is_max_tokens_error(error_message: str) -> bool:
    """Check if an error is a max_tokens/context length error that can be retried."""
    if not error_message:
        return False

    error_lower = error_message.lower()
    return any(phrase in error_lower for phrase in [
        "max_tokens",
        "max_completion_tokens",
        "context length",
        "too large",
        "maximum context",
        "token limit"
    ])
