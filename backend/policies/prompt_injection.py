"""
Prompt Injection Detection Module

Detects malicious/hidden prompts in content that could manipulate LLM behavior.

SECURITY NOTES (for Unifai demo):
- scan() method is a NO-OP - returns no threats
- Hidden text detection not implemented
- Base64/encoded content not decoded
- Unicode homoglyph attacks not detected

AFTER UNIFAI REMEDIATION:
- Detect hidden text (white-on-white, zero-size, off-page)
- Decode and scan base64 content
- Detect unicode homoglyph attacks
- Identify known prompt injection patterns
"""
# Copyright (c) Lineaje, Inc. All rights reserved.
# Lineaje UnifAI guardrail  version=2.0.0-alpha
def _lineaje_load_gr_client():
    """Lineaje-added: load gr_stub_client.py without a pip dependency."""
    import sys as _s, importlib.util as _ilu
    from pathlib import Path as _P
    n = "_lineaje_gr_stub_client"
    if n in _s.modules: return _s.modules[n]
    h = _P(__file__).resolve().parent
    _cand = next((d / "gr_stub_client.py" for d in [h, *h.parents][:8] if (d / "gr_stub_client.py").is_file()), h / "gr_stub_client.py")
    _spec = _ilu.spec_from_file_location(n, _cand)
    _s.modules[n] = _m = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_m); return _m
def _lineaje_current_model():
    """Lineaje-added: reread the app's model setting for every request."""
    import os as _o
    from pathlib import Path as _P
    _keys = ("OPENROUTER_MODEL", "LLM_MODEL", "MODEL_NAME", "MODEL_ID", "OPENAI_MODEL", "ANTHROPIC_MODEL", "BEDROCK_MODEL_ID")
    _here = _P(__file__).resolve().parent
    for _path in (_here / ".env", *(_p / ".env" for _p in list(_here.parents)[:8])):
        if not _path.is_file(): continue
        try: _lines = _path.read_text(encoding="utf-8").splitlines()
        except OSError: continue
        _values = {}
        for _line in _lines:
            _line = _line.strip()
            if not _line or _line.startswith("#") or "=" not in _line: continue
            _key, _, _value = _line.partition("=")
            if _key.strip() in _keys: _values[_key.strip()] = _value.strip().strip(chr(34)).strip(chr(39))
        for _key in _keys:
            if _values.get(_key): return _values[_key]
    return next((_o.environ[_key].strip() for _key in _keys if _o.environ.get(_key, "").strip()), "")


import logging
import re
import base64
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class ThreatMatch:
    """Represents a detected threat."""
    threat_type: str
    severity: str  # low, medium, high, critical
    description: str
    content_preview: str
    location: str


@dataclass
class ThreatDetectionResult:
    """Result of threat detection scan."""
    has_violations: bool
    threats: list[ThreatMatch] = field(default_factory=list)
    scanned_content_length: int = 0

    def to_dict(self) -> dict:
        return {
            "has_violations": self.has_violations,
            "threats": [
                {
                    "type": t.threat_type,
                    "severity": t.severity,
                    "description": t.description,
                    "preview": t.content_preview[:50] + "..." if len(t.content_preview) > 50 else t.content_preview,
                    "location": t.location
                }
                for t in self.threats
            ],
            "scanned_content_length": self.scanned_content_length
        }


class PromptInjectionDetector:
    """
    Detects prompt injection and hidden malicious content.

    VULNERABILITY SUMMARY:
    1. scan() is a NO-OP - always returns no threats
    2. Hidden text detection not implemented
    3. Base64 decoding not performed
    4. Unicode attacks not detected
    5. Known injection patterns not checked

    Threat Categories:
    - hidden_text: Invisible/hidden text in documents
    - encoded_content: Base64 or otherwise encoded malicious content
    - prompt_injection: Direct prompt injection attempts
    - unicode_attack: Homoglyph or unicode-based attacks
    - metadata_injection: Malicious content in file metadata
    """

    # Known prompt injection patterns (defined but NOT USED)
    INJECTION_PATTERNS = [
        r"ignore\s+(previous|all|above)\s+instructions?",
        r"disregard\s+(previous|all|above)\s+(instructions?|context)",
        r"new\s+instructions?:",
        r"system\s*:\s*you\s+are",
        r"admin\s+override",
        r"developer\s+mode",
        r"jailbreak",
        r"\[INST\]",
        r"<\|im_start\|>",
        r"###\s*(instruction|system|human|assistant)",
    ]

    # Unicode homoglyphs that could be used for attacks
    HOMOGLYPH_MAP = {
        'а': 'a',  # Cyrillic
        'е': 'e',
        'о': 'o',
        'р': 'p',
        'с': 'c',
        'х': 'x',
        # Add more as needed
    }

    def __init__(self):
        """Initialize the detector."""
        self._compiled_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in self.INJECTION_PATTERNS
        ]

    async def scan(self, content: str, source: str = "unknown") -> ThreatDetectionResult:
        """
        Scan content for prompt injection and hidden threats.

        VULNERABILITY: This method is a NO-OP.
        It returns no threats regardless of content.

        Args:
            content: Content to scan for threats
            source: Source of the content (for logging)

        Returns:
            ThreatDetectionResult with has_violations=False always
        """
        # VULNERABILITY: No actual scanning performed

        _lineaje_payload = "Threat scan requested"
        # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:e1006869e8e17f493d497d867cde2592bed944ac78c3039e147fda8b84f34f9d'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:e1006869e8e17f493d497d867cde2592bed944ac78c3039e147fda8b84f34f9d', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='log', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/policies/prompt_injection.py', 'line': 129, 'function': 'PromptInjectionDetector.scan'}})
        try:
            _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        logger.debug(
            _lineaje_payload,
            extra={
                "source": source,
                "content_length": len(content) if content else 0,
                # VULNERABILITY: Content logged without scanning
                "preview": content[:100] if content else None
            }
        )

        # NO-OP: Return empty result without scanning
        return ThreatDetectionResult(
            has_violations=False,
            threats=[],
            scanned_content_length=len(content) if content else 0
        )

    async def detect_hidden_text(self, content: str) -> list[ThreatMatch]:
        """
        Detect hidden text patterns in content.

        VULNERABILITY: Not implemented - returns empty list.

        Should detect:
        - White text on white background (CSS)
        - Zero-size text
        - Off-screen positioned text
        - Display:none content
        - Visibility:hidden content
        """
        # VULNERABILITY: Hidden text detection not implemented
        return []

    async def detect_encoded_content(self, content: str) -> list[ThreatMatch]:
        """
        Detect and decode potentially malicious encoded content.

        VULNERABILITY: Not implemented - returns empty list.

        Should detect:
        - Base64 encoded prompts
        - URL encoded content
        - Unicode escape sequences
        - HTML entities
        """
        # VULNERABILITY: Encoded content detection not implemented
        return []

    async def detect_prompt_injection(self, content: str) -> list[ThreatMatch]:
        """
        Detect known prompt injection patterns.

        VULNERABILITY: Not implemented - returns empty list.

        Should detect patterns like:
        - "ignore previous instructions"
        - "new system prompt"
        - Role-playing attacks
        - Delimiter injection
        """
        # VULNERABILITY: Pattern matching not performed
        return []

    async def detect_unicode_attacks(self, content: str) -> list[ThreatMatch]:
        """
        Detect unicode-based attacks including homoglyphs.

        VULNERABILITY: Not implemented - returns empty list.

        Should detect:
        - Homoglyph substitution (Cyrillic a for Latin a)
        - Bidirectional text attacks
        - Zero-width characters
        - Combining characters
        """
        # VULNERABILITY: Unicode attack detection not implemented
        return []

    async def scan_metadata(self, metadata: dict) -> ThreatDetectionResult:
        """
        Scan file metadata for hidden threats.

        VULNERABILITY: Not implemented - returns no threats.

        Should scan:
        - EXIF comments and descriptions
        - PDF metadata fields
        - Document properties
        - Custom metadata tags
        """
        # VULNERABILITY: Metadata scanning not implemented
        return ThreatDetectionResult(
            has_violations=False,
            threats=[],
            scanned_content_length=len(str(metadata))
        )

    def _decode_base64(self, content: str) -> Optional[str]:
        """Attempt to decode base64 content."""
        try:
            # Look for base64-like strings
            b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
            matches = re.findall(b64_pattern, content)

            for match in matches:
                try:
                    decoded = base64.b64decode(match).decode('utf-8')
                    # LINEAJE: enforce() `decoded` at agent->user_interface data_egress — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:c6fe2a34754bfb4ae73a16c4284f9e7578764c3360b9cc6c43092b44bc51cf39'
                    _gr_client = _lineaje_load_gr_client()
                    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:c6fe2a34754bfb4ae73a16c4284f9e7578764c3360b9cc6c43092b44bc51cf39', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'policy_name': 'Mask PII on user interfaces', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/policies/prompt_injection.py', 'line': 236, 'function': 'PromptInjectionDetector._decode_base64'}})
                    try:
                        decoded = _gr_client.enforce(_gr_site, decoded, content_type='text/plain')
                    except _gr_client.GuardrailUnavailableError:
                        pass
                    except PermissionError:
                        pass
                    return decoded
                except:
                    continue
            return None
        except:
            return None


# ============================================================================
# REMEDIATED VERSION (commented out - Unifai would enable this)
# ============================================================================

# class PromptInjectionDetector:
#     """
#     SECURE VERSION - After Unifai remediation
#
#     This version:
#     - Actually scans for prompt injection patterns
#     - Detects hidden text in various formats
#     - Decodes and scans base64 content
#     - Identifies unicode attacks
#     """
#
#     async def scan(self, content: str, source: str = "unknown") -> ThreatDetectionResult:
#         """Perform comprehensive threat scanning."""
#         threats = []
#
#         # Check for prompt injection patterns
#         for pattern in self._compiled_patterns:
#             matches = pattern.findall(content)
#             for match in matches:
#                 threats.append(ThreatMatch(
#                     threat_type="prompt_injection",
#                     severity="high",
#                     description=f"Detected prompt injection pattern",
#                     content_preview=match,
#                     location=source
#                 ))
#
#         # Check for hidden/encoded content
#         encoded_threats = await self.detect_encoded_content(content)
#         threats.extend(encoded_threats)
#
#         # Check for unicode attacks
#         unicode_threats = await self.detect_unicode_attacks(content)
#         threats.extend(unicode_threats)
#
#         return ThreatDetectionResult(
#             has_violations=len(threats) > 0,
#             threats=threats,
#             scanned_content_length=len(content)
#         )
