"""Loads installed agent skills from the on-disk skill registry."""
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
import re
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]

SKILL_REGISTRY: dict[str, Path] = {
    "loan-document-helper": PROJECT_ROOT / "SKILL.md",
}


def parse_skill_metadata(content: str) -> dict[str, str]:
    match = re.match(r"^---\s*\n(.*?)\n---", content, re.DOTALL)
    if not match:
        return {}

    metadata: dict[str, str] = {}
    for line in match.group(1).splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        metadata[key.strip()] = value.strip().strip('"')
    # LINEAJE: enforce() `metadata` at agent->user_interface data_egress — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:808a43da4ad86da21e0ab89fa02d6c5ec2e04e46383c252629bed9d1273de5fa'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:808a43da4ad86da21e0ab89fa02d6c5ec2e04e46383c252629bed9d1273de5fa', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'policy_name': 'Mask PII on user interfaces', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/agents/skill_loader.py', 'line': 25, 'function': 'parse_skill_metadata'}})
    try:
        try:
            _lineaje_obs = _lineaje_load_gr_client()
            _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:a8278237c34ba7ac4634e9a7f58d654a9b21bc5265bcc0e0709e2a588ea2f95a', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='agent', destination_type='tool', project='lineaje-openclaw', organization='', components={'file': 'backend/agents/skill_loader.py', 'line': 62, 'function': 'parse_skill_metadata', 'agent_name': 'parse_skill_metadata', 'agent_name_source': 'inferred_from_function', 'call_target': '_gr_client.enforce', 'tool_protocol': 'local', 'tool_protocol_source': 'scan: no MCP client imported'}, observe_only=True)
            _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'mcp_call'}, content_type='application/json')
        except Exception:
            pass
        metadata = _gr_client.enforce(_gr_site, metadata, content_type='text/plain')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    return metadata


def load_skill(skill_id: str) -> dict[str, Any]:
    skill_path = SKILL_REGISTRY.get(skill_id)
    if skill_path is None:
        return {
            "id": skill_id,
            "content": "",
            "path": "",
            "loaded": False,
        }

    if not skill_path.exists():
        return {
            "id": skill_id,
            "content": "",
            "path": str(skill_path),
            "loaded": False,
        }

    # LINEAJE: enforce() `_lineaje_skill_content` at skill_manifest->skill_check skill_check — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:79369dc3c4f15ba5a675dcbc7879b4e1ac5f2a6a27dfad9c86315588ef16f205'
    _lineaje__lineaje_skill_content_evidence = {'skill_path': str(skill_path), 'skill_id': skill_id, 'project': 'lineaje-openclaw'}
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:79369dc3c4f15ba5a675dcbc7879b4e1ac5f2a6a27dfad9c86315588ef16f205', phase='skill_check', boundary={'source': 'skill_manifest', 'sink': 'skill_check'}, candidate_policies=[{'policy_id': 'AI_SKILL_DAT_SEC_001', 'policy_name': 'Do not allow skills that exfiltrate data', 'guardrail_id': 'Block skills that exfiltrate data', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_SKILL_SEC_003', 'policy_name': 'Do not allow skills that are pending a scan', 'guardrail_id': 'Block skills that are pending a scan', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_SKILL_SEC_001', 'policy_name': 'Do not allow use of malicious skills', 'guardrail_id': 'Block MALICIOUS skills', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_SKILL_SEC_002', 'policy_name': 'Do not allow use of suspicious skills', 'guardrail_id': 'Block SUSPICIOUS skills', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='skill_manifest', destination_type='skill_check', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/agents/skill_loader.py', 'line': 46, 'function': 'load_skill'}})
    try:
        try:
            _lineaje_obs = _lineaje_load_gr_client()
            _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:f7d9e22f1d0be98cc674191de8c88e9911c78132fec155fbb619ec8c7aa3b0a7', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='agent', destination_type='tool', project='lineaje-openclaw', organization='', components={'file': 'backend/agents/skill_loader.py', 'line': 93, 'function': 'load_skill', 'agent_name': 'load_skill', 'agent_name_source': 'inferred_from_function', 'call_target': '_gr_client.enforce', 'tool_protocol': 'local', 'tool_protocol_source': 'scan: no MCP client imported'}, observe_only=True)
            _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'mcp_call'}, content_type='application/json')
        except Exception:
            pass
        _lineaje__lineaje_skill_content_evidence = _gr_client.enforce(_gr_site, _lineaje__lineaje_skill_content_evidence, content_type='application/json')
        _lineaje_skill_content = skill_path.read_text(encoding="utf-8")
    except _gr_client.GuardrailUnavailableError:
        # LINEAJE: enforce() `_lineaje_skill_content` at skill_manifest->skill_check skill_check — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:440db6bd26591e0ab1e9e869a01f218f069a35699a6e431fc4791c67e9754e31'
        _lineaje__lineaje_skill_content_evidence = {'skill_path': str(skill_path), 'project': 'lineaje-openclaw', 'skill_id': ''}
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:440db6bd26591e0ab1e9e869a01f218f069a35699a6e431fc4791c67e9754e31', phase='skill_check', boundary={'source': 'skill_manifest', 'sink': 'skill_check'}, candidate_policies=[{'policy_id': 'AI_SKILL_DAT_SEC_001', 'policy_name': 'Do not allow skills that exfiltrate data', 'guardrail_id': 'Block skills that exfiltrate data', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_SKILL_SEC_003', 'policy_name': 'Do not allow skills that are pending a scan', 'guardrail_id': 'Block skills that are pending a scan', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_SKILL_SEC_001', 'policy_name': 'Do not allow use of malicious skills', 'guardrail_id': 'Block MALICIOUS skills', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_SKILL_SEC_002', 'policy_name': 'Do not allow use of suspicious skills', 'guardrail_id': 'Block SUSPICIOUS skills', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='skill_manifest', destination_type='skill_check', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='local-run', project_branch='local-run', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'local-run', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@local-run?commit-id=a9ad1bb4e72b5adfd0085522ce8623710221f948&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/agents/skill_loader.py', 'line': 96, 'function': 'load_skill'}})
        try:
            _lineaje__lineaje_skill_content_evidence = _gr_client.enforce(_gr_site, _lineaje__lineaje_skill_content_evidence, content_type='application/json')
            _lineaje_skill_content = skill_path.read_text(encoding="utf-8")
        except _gr_client.GuardrailUnavailableError:
            _lineaje_skill_content = skill_path.read_text(encoding="utf-8")
        except PermissionError:
            _lineaje_skill_content = ""
            __import__("logging").getLogger("lineaje.gr_client").warning("gr_client[skill_manifest->skill_check]: quarantined skill not loaded")
    except PermissionError:
        _lineaje_skill_content = ""
        __import__("logging").getLogger("lineaje.gr_client").warning("gr_client[skill_manifest->skill_check]: quarantined skill not loaded")
    return {
        "id": skill_id,
        "content": _lineaje_skill_content,
        "path": str(skill_path),
        "loaded": True,
    }
