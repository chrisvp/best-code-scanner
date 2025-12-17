"""
Response cleanup service for malformed LLM outputs.

When parsing fails, this service calls a cleanup model to reformat
the response into the expected marker format.
"""

import logging
from typing import Optional
from sqlalchemy.orm import Session

from app.services.llm_provider import llm_provider
from app.models.scanner_models import ModelConfig

logger = logging.getLogger(__name__)


# Cleanup prompt templates for different response types
DRAFT_CLEANUP_PROMPT = """You are a formatting assistant. The following text is a security scan response that wasn't properly formatted.

Your job is to extract ALL security findings and reformat them using EXACTLY this marker format:

*DRAFT: Title of the vulnerability
*TYPE: CWE-XXX or vulnerability type
*SEVERITY: Critical/High/Medium/Low
*LINE: exact line number
*SNIPPET: the vulnerable code
*REASON: one sentence explanation
*END_DRAFT

Rules:
- Extract EVERY finding mentioned, even if poorly formatted
- If no line number, use 0
- If no snippet, quote the relevant part from the text
- If truly no vulnerabilities mentioned, respond with: *DRAFT:NONE
- Do NOT add any explanations, just output the formatted findings

Original response to reformat:
---
{response}
---

Reformatted output:"""


VERIFICATION_CLEANUP_PROMPT = """You are a formatting assistant. The following text is a verification response that wasn't properly formatted.

Reformat it using EXACTLY this marker format:

*VOTE: REAL/WEAKNESS/FALSE_POSITIVE/NEEDS_VERIFIED
*CONFIDENCE: 0-100
*REASONING: brief explanation
*END_VERIFIED

Vote meanings:
- FALSE_POSITIVE: Scanner is wrong, code is safe
- REAL: Confirmed exploitable vulnerability
- NEEDS_VERIFIED: Can't confirm from visible code, needs agent verification
- WEAKNESS: Poor practice but not directly exploitable

Rules:
- Determine the appropriate vote type based on the content
- Extract confidence if mentioned, otherwise estimate based on language certainty
- Summarize the reasoning
- Do NOT add explanations, just output the formatted result

Original response to reformat:
---
{response}
---

Reformatted output:"""


VOTE_CLEANUP_PROMPT = """You are a formatting assistant. The following text is a vote response that wasn't properly formatted.

Reformat it using EXACTLY this marker format:

*VOTE: REAL/WEAKNESS/FALSE_POSITIVE/NEEDS_VERIFIED
*CONFIDENCE: 0-100
*REASONING: brief explanation
*END_VERIFIED

Vote meanings:
- FALSE_POSITIVE: Scanner is wrong, code is safe
- REAL: Confirmed exploitable vulnerability
- NEEDS_VERIFIED: Can't confirm from visible code, needs agent verification
- WEAKNESS: Poor practice but not directly exploitable

Rules:
- Determine the appropriate vote type based on the text
- Extract confidence if mentioned, otherwise estimate based on language certainty
- Summarize the reasoning
- Do NOT add explanations, just output the formatted result

Original response to reformat:
---
{response}
---

Reformatted output:"""


class ResponseCleaner:
    """Service for cleaning up malformed LLM responses using a cleanup model"""

    def __init__(self, db: Session):
        self.db = db
        self._cleanup_model: Optional[ModelConfig] = None
        self._initialized = False

    def _get_cleanup_model(self) -> Optional[ModelConfig]:
        """Get the configured cleanup model from database

        Uses chat models as they're generally better at following formatting instructions.
        Falls back to first available model if no chat models configured.
        """
        if not self._initialized:
            # Use first chat model for cleanup, or first model if no chat models
            self._cleanup_model = self.db.query(ModelConfig).filter(
                ModelConfig.is_chat == True
            ).first()
            if not self._cleanup_model:
                self._cleanup_model = self.db.query(ModelConfig).first()
            self._initialized = True

            if self._cleanup_model:
                logger.info(f"Using cleanup model: {self._cleanup_model.name}")
            else:
                logger.warning("No models configured for cleanup")

        return self._cleanup_model

    async def cleanup_draft_response(self, malformed_response: str) -> Optional[str]:
        """
        Clean up a malformed draft scanning response.

        Args:
            malformed_response: The poorly formatted LLM response

        Returns:
            Cleaned response in marker format, or None if cleanup fails
        """
        return await self._call_cleanup_model(
            DRAFT_CLEANUP_PROMPT.format(response=malformed_response)
        )

    async def cleanup_verification_response(self, malformed_response: str) -> Optional[str]:
        """Clean up a malformed verification response"""
        return await self._call_cleanup_model(
            VERIFICATION_CLEANUP_PROMPT.format(response=malformed_response)
        )

    async def cleanup_vote_response(self, malformed_response: str) -> Optional[str]:
        """Clean up a malformed vote response"""
        return await self._call_cleanup_model(
            VOTE_CLEANUP_PROMPT.format(response=malformed_response)
        )

    async def _call_cleanup_model(self, prompt: str) -> Optional[str]:
        """Call the cleanup model with the given prompt"""
        model = self._get_cleanup_model()
        if not model:
            return None

        try:
            # Use centralized chat_completion which includes retry logic
            result = await llm_provider.chat_completion(
                messages=[{"role": "user", "content": prompt}],
                model=model.name,
                max_tokens=model.max_tokens or 2048,
            )

            cleaned = result.get("content", "")
            if cleaned:
                logger.debug(f"Cleanup model reformatted response ({len(cleaned)} chars)")
                return cleaned.strip()
            return None

        except Exception as e:
            logger.error(f"Cleanup model call failed: {e}")
            return None


def get_response_cleaner(db: Session) -> ResponseCleaner:
    """Factory function to get a ResponseCleaner instance"""
    return ResponseCleaner(db)
