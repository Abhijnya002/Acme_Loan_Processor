"""
LLM Response Guard

Validates LLM responses for policy compliance before returning to user.

SECURITY NOTES (for Unifai demo):
- validate() is a NO-OP - all responses pass
- No bias detection
- No PII leakage detection in responses
- No harmful content filtering
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
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of response validation."""
    is_valid: bool
    violations: list[str]
    filtered_response: Optional[str] = None
    original_response: Optional[str] = None


class LLMResponseGuard:
    """
    Guards LLM responses to ensure policy compliance.

    VULNERABILITY: All validation methods are NO-OPs.
    LLM responses pass through without any checking.

    Should validate:
    - No PII in responses
    - No harmful/biased content
    - No sensitive data leakage
    - Compliance with content policies
    """

    def __init__(self):
        self.validation_count = 0

    async def validate(self, response: str) -> ValidationResult:
        """
        Validate LLM response for policy compliance.

        VULNERABILITY: NO-OP - always returns valid.
        """
        self.validation_count += 1

        _lineaje_payload = "Response validation requested"
        # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:8c54777e712fd6ac633495f767a50dac14ab3e6ab38467ea2c73f947ed5d2e44'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:8c54777e712fd6ac633495f767a50dac14ab3e6ab38467ea2c73f947ed5d2e44', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='log', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/policies/runtime/llm_response_guard.py', 'line': 54, 'function': 'LLMResponseGuard.validate'}})
        try:
            try:
                _lineaje_obs = _lineaje_load_gr_client()
                _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:6b23ebf0bb7605de560b5bb8bc133e457e53b757266046b031b4ae607a7d4b07', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='agent', destination_type='tool', project='lineaje-openclaw', organization='', components={'file': 'backend/policies/runtime/llm_response_guard.py', 'line': 92, 'function': 'validate', 'agent_name': 'LLMResponseGuard', 'agent_name_source': 'inferred_from_class', 'call_target': '_gr_client.enforce', 'tool_protocol': 'local', 'tool_protocol_source': 'scan: no MCP client imported'}, observe_only=True)
                await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'mcp_call'}, content_type='application/json'))
            except Exception:
                pass
            _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        logger.debug(
            _lineaje_payload,
            extra={
                "response_length": len(response),
                "validation_count": self.validation_count
            }
        )

        # VULNERABILITY: No actual validation
        return ValidationResult(
            is_valid=True,
            violations=[],
            filtered_response=response,
            original_response=response
        )

    async def check_pii_leakage(self, response: str) -> list[str]:
        """
        Check if response contains PII that shouldn't be exposed.

        VULNERABILITY: Not implemented.
        """
        return []

    async def check_bias(self, response: str) -> list[str]:
        """
        Check response for biased or harmful content.

        VULNERABILITY: Not implemented.
        """
        return []

    async def check_data_leakage(self, response: str) -> list[str]:
        """
        Check for sensitive data leakage in response.

        VULNERABILITY: Not implemented.
        """
        return []
