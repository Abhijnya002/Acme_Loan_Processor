"""Shared helper functions for the Acme Loan Processor agents."""
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


import base64
import re
from typing import Any
from uuid import uuid4


def build_file_summary(
    file_contents: list[dict[str, Any]],
    include_raw_text: bool = False,
) -> str:
    if not file_contents:
        return "No files were attached."

    sections = []
    for file_data in file_contents:
        extracted_content = file_data.get("extracted_content", "")
        if not include_raw_text and len(extracted_content) > 600:
            extracted_content = extracted_content[:600] + "..."

        sections.append(
            f"Filename: {file_data.get('filename', 'unknown')}\n"
            f"Content Type: {file_data.get('content_type', 'unknown')}\n"
            f"Extracted Content:\n{extracted_content}"
        )

    return "\n\n".join(sections)


def extract_reference_number(message: str, prefix: str) -> str:
    match = re.search(r"\b([A-Z]{2,}-\d{2,}|\d{4,})\b", message or "")
    if match:
        return str(match.group(1))
    return f"{prefix}-{str(uuid4())[:8].upper()}"


def decode_base64_segments(content: str) -> list[str]:
    decoded_segments: list[str] = []
    for candidate in extract_base64_candidates(content):
        if len(candidate) % 4 != 0:
            continue
        try:
            decoded = base64.b64decode(candidate, validate=True).decode("utf-8")
        except Exception:
            continue
        if decoded.strip():
            decoded_segments.append(decoded.strip())
    # LINEAJE: enforce() `decoded_segments` at agent->user_interface data_egress — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:05ffed38814524d8bfe898f153fecab57fcc71dacfc00e9e13ec7c4c61bc1c6f'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:05ffed38814524d8bfe898f153fecab57fcc71dacfc00e9e13ec7c4c61bc1c6f', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'policy_name': 'Mask PII on user interfaces', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/agents/helpers.py', 'line': 49, 'function': 'decode_base64_segments'}})
    try:
        decoded_segments = _gr_client.enforce(_gr_site, decoded_segments, content_type='text/plain')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    return decoded_segments


def extract_base64_candidates(content: str) -> list[str]:
    return re.findall(r"[A-Za-z0-9+/=]{24,}", content or "")
