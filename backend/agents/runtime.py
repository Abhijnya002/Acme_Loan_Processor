"""Thin runtime registry that ties the separated agent files together."""
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


from copy import deepcopy
from typing import Any

from .access_control_agent import access_control_agent
from .credit_eval_agent import credit_eval_agent
from .file_management_agent import file_management_agent
from .file_processor_agent import file_processor_agent
from .mcp_servers import MCP_SERVERS
from .orchestrator_agent import orchestrator_agent
from .rate_check_agent import rate_check_agent
from .loan_processing_agent import loan_processing_agent
from .scheduling_agent import scheduling_agent
from .installed_skill_agent import installed_skill_agent


AGENTS: dict[str, Any] = {
    loan_processing_agent.AGENT_NAME: loan_processing_agent,
    file_processor_agent.AGENT_NAME: file_processor_agent,
    file_management_agent.AGENT_NAME: file_management_agent,
    access_control_agent.AGENT_NAME: access_control_agent,
    credit_eval_agent.AGENT_NAME: credit_eval_agent,
    rate_check_agent.AGENT_NAME: rate_check_agent,
    orchestrator_agent.AGENT_NAME: orchestrator_agent,
    scheduling_agent.AGENT_NAME: scheduling_agent,
    installed_skill_agent.AGENT_NAME: installed_skill_agent,
}


def build_catalog() -> dict[str, Any]:
    return {
        "agents": deepcopy([agent.to_dict() for agent in AGENTS.values()]),
        "mcp_servers": deepcopy(list(MCP_SERVERS.values())),
    }


async def handle_chat_request(context: dict[str, Any]) -> dict[str, Any]:
    try:
        _lineaje_obs = _lineaje_load_gr_client()
        _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:a8f992226808466d81c219c43dd4b1aef0b7de8c92d918849c3bb082b2b4ba18', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='agent', destination_type='agent', project='lineaje-openclaw', organization='', components={'file': 'backend/agents/runtime.py', 'line': 39, 'function': 'handle_chat_request', 'agent_name': 'handle_chat_request', 'agent_name_source': 'inferred_from_function', 'call_target': 'orchestrator_agent.handle'}, observe_only=True)
        await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'agent_to_agent'}, content_type='application/json'))
    except Exception:
        pass
    return await orchestrator_agent.handle(context)


async def process_file_attachment(
    content: str | None,
    filename: str,
    content_type: str,
) -> dict[str, Any]:
    # LINEAJE: enforce() `content` at file_storage->agent file_upload — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:7fbf351abad2dec2f1c8a6f531e0151db0a93a6d39c11a3d633575a47bb51135'
    _lineaje_content_evidence = {'content': content, 'name': filename, 'content_type': content_type, 'project': 'lineaje-openclaw'}
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:7fbf351abad2dec2f1c8a6f531e0151db0a93a6d39c11a3d633575a47bb51135', phase='file_upload', boundary={'source': 'file_upload', 'sink': 'agent_context'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_023', 'policy_name': 'Redact PII from uploaded files.', 'guardrail_id': 'Redact PII from uploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_024', 'policy_name': 'Uploaded files must not contain PII (Singapore).', 'guardrail_id': 'Redact PII (Singapore) from contents ofuploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='file_storage', destination_type='agent', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/agents/runtime.py', 'line': 47, 'function': 'process_file_attachment'}})
    try:
        _lineaje_content_evidence = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_content_evidence, content_type='application/json'))
        content = _lineaje_content_evidence.get('content', content) if isinstance(_lineaje_content_evidence, dict) else content
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        raise
    return await file_processor_agent.process_attachment(content, filename, content_type)
