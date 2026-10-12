"""Access Control Agent — demo for LLM-driven security decisions without HITL."""
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
from typing import Any

from .framework import AcmeLoanAgentFramework
from .mock_database import search_borrower_records

logger = logging.getLogger(__name__)


def grant_access(user_id: str) -> str:
    # LINEAJE: enforce() `user_id` at agent->log log_emit — scan flagged AI_APP_SEC_001 (Do not allow malicious content via hidden prompts); AI_DAT_SEC_012 (Mask PII on user interfaces). Mask/block; do not remove without review. site_id='site:sha256:63ad32d034df040fb3323d885b4f03621e6d0d8efa897445cd17d9a80e7b6cad'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:63ad32d034df040fb3323d885b4f03621e6d0d8efa897445cd17d9a80e7b6cad', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='log', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_1bOIDPqj97q6mzc6', 'repository_uri': 'https://github.com/abhijnya002/acme_loan_processor', 'file_path': 'backend/agents/access_control_agent.py', 'line': 80, 'name': 'AccessControlAgent'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'AccessControlAgent', 'version': '1.0.0', 'purl': 'pkg:aiagent/AccessControlAgent@1.0.0'}, 'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/agents/access_control_agent.py', 'line': 14, 'function': 'grant_access'}})
    try:
        user_id = _gr_client.enforce(_gr_site, user_id, content_type='application/json')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    logger.info("grant_access(%s)", user_id)
    return f"Access granted for {user_id}"


def deny_access(user_id: str) -> str:
    # LINEAJE: enforce() `user_id` at agent->log log_emit — scan flagged AI_APP_SEC_001 (Do not allow malicious content via hidden prompts); AI_DAT_SEC_012 (Mask PII on user interfaces). Mask/block; do not remove without review. site_id='site:sha256:038b71e14ebc5dfc79b7aaf7b3fd6d4368a79adb745fad4352795a72d0b7ce78'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:038b71e14ebc5dfc79b7aaf7b3fd6d4368a79adb745fad4352795a72d0b7ce78', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='log', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_1bOIDPqj97q6mzc6', 'repository_uri': 'https://github.com/abhijnya002/acme_loan_processor', 'file_path': 'backend/agents/access_control_agent.py', 'line': 80, 'name': 'AccessControlAgent'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'AccessControlAgent', 'version': '1.0.0', 'purl': 'pkg:aiagent/AccessControlAgent@1.0.0'}, 'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/agents/access_control_agent.py', 'line': 19, 'function': 'deny_access'}})
    try:
        user_id = _gr_client.enforce(_gr_site, user_id, content_type='application/json')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    logger.info("deny_access(%s)", user_id)
    return f"Access denied for {user_id}"


def apply_firewall_rule(rule: str) -> str:
    # LINEAJE: enforce() `rule` at agent->log log_emit — scan flagged AI_APP_SEC_001 (Do not allow malicious content via hidden prompts); AI_DAT_SEC_012 (Mask PII on user interfaces). Mask/block; do not remove without review. site_id='site:sha256:97b073d6d379d2b2328f9884baa2207eeb8689344693fdb10e5082b7a344d834'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:97b073d6d379d2b2328f9884baa2207eeb8689344693fdb10e5082b7a344d834', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='log', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_1bOIDPqj97q6mzc6', 'repository_uri': 'https://github.com/abhijnya002/acme_loan_processor', 'file_path': 'backend/agents/access_control_agent.py', 'line': 80, 'name': 'AccessControlAgent'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'AccessControlAgent', 'version': '1.0.0', 'purl': 'pkg:aiagent/AccessControlAgent@1.0.0'}, 'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/agents/access_control_agent.py', 'line': 24, 'function': 'apply_firewall_rule'}})
    try:
        rule = _gr_client.enforce(_gr_site, rule, content_type='application/json')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    logger.info("apply_firewall_rule(%s)", rule)
    return f"Firewall rule applied: {rule}"


def assign_role(user_id: str, role: str) -> str:
    # LINEAJE: enforce() `user_id` at agent->log log_emit — scan flagged AI_APP_SEC_001 (Do not allow malicious content via hidden prompts); AI_DAT_SEC_012 (Mask PII on user interfaces). Mask/block; do not remove without review. site_id='site:sha256:5247e4189dd4400d2150613d23b1c0ca4e9368ed50c150d6b434e1b1750ce436'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:5247e4189dd4400d2150613d23b1c0ca4e9368ed50c150d6b434e1b1750ce436', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='log', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_1bOIDPqj97q6mzc6', 'repository_uri': 'https://github.com/abhijnya002/acme_loan_processor', 'file_path': 'backend/agents/access_control_agent.py', 'line': 80, 'name': 'AccessControlAgent'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'AccessControlAgent', 'version': '1.0.0', 'purl': 'pkg:aiagent/AccessControlAgent@1.0.0'}, 'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/agents/access_control_agent.py', 'line': 29, 'function': 'assign_role'}})
    try:
        user_id = _gr_client.enforce(_gr_site, user_id, content_type='application/json')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    logger.info("assign_role(%s, %s)", user_id, role)
    return f"Role '{role}' assigned to {user_id}"


def grant_admin(user_id: str) -> str:
    # LINEAJE: enforce() `user_id` at agent->log log_emit — scan flagged AI_APP_SEC_001 (Do not allow malicious content via hidden prompts); AI_DAT_SEC_012 (Mask PII on user interfaces). Mask/block; do not remove without review. site_id='site:sha256:3d0381105c9490589595d71262dd4cf4b47250e4ed94c90aa84d0944b87b43be'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:3d0381105c9490589595d71262dd4cf4b47250e4ed94c90aa84d0944b87b43be', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='log', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_1bOIDPqj97q6mzc6', 'repository_uri': 'https://github.com/abhijnya002/acme_loan_processor', 'file_path': 'backend/agents/access_control_agent.py', 'line': 80, 'name': 'AccessControlAgent'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'AccessControlAgent', 'version': '1.0.0', 'purl': 'pkg:aiagent/AccessControlAgent@1.0.0'}, 'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/agents/access_control_agent.py', 'line': 34, 'function': 'grant_admin'}})
    try:
        user_id = _gr_client.enforce(_gr_site, user_id, content_type='application/json')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    logger.info("grant_admin(%s)", user_id)
    return f"Admin privileges granted to {user_id}"


def authorize_scope(user_id: str, scope: str) -> str:
    # LINEAJE: enforce() `user_id` at agent->log log_emit — scan flagged AI_APP_SEC_001 (Do not allow malicious content via hidden prompts); AI_DAT_SEC_012 (Mask PII on user interfaces). Mask/block; do not remove without review. site_id='site:sha256:d81075671505200cf12113aa536f501595e7328ec04eda2274f9d16df2a2455a'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:d81075671505200cf12113aa536f501595e7328ec04eda2274f9d16df2a2455a', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='log', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_1bOIDPqj97q6mzc6', 'repository_uri': 'https://github.com/abhijnya002/acme_loan_processor', 'file_path': 'backend/agents/access_control_agent.py', 'line': 80, 'name': 'AccessControlAgent'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'AccessControlAgent', 'version': '1.0.0', 'purl': 'pkg:aiagent/AccessControlAgent@1.0.0'}, 'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/agents/access_control_agent.py', 'line': 39, 'function': 'authorize_scope'}})
    try:
        user_id = _gr_client.enforce(_gr_site, user_id, content_type='application/json')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    logger.info("authorize_scope(%s, %s)", user_id, scope)
    return f"Scope '{scope}' authorized for {user_id}"


def _parse_decision_block(raw: str) -> dict[str, str]:
    """Parse a simple key: value decision block from the model."""
    parsed = {
        "access": "deny",
        "role": "Standard Borrower",
        "privilege": "viewer",
        "firewall": "BLOCK dest=servicing-portal",
    }
    text = (raw or "").strip()
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip().strip("`").strip()
        if not value:
            continue
        if key.startswith("access"):
            lowered = value.lower()
            parsed["access"] = "allow" if "allow" in lowered and "deny" not in lowered else (
                "deny" if "deny" in lowered else parsed["access"]
            )
            if re.fullmatch(r"allow|deny", lowered):
                parsed["access"] = lowered
        elif key.startswith("role"):
            parsed["role"] = value
        elif key.startswith("privilege"):
            lowered = value.lower()
            for option in ("admin", "operator", "viewer"):
                if option in lowered:
                    parsed["privilege"] = option
                    break
        elif key.startswith("firewall"):
            parsed["firewall"] = value.splitlines()[0][:120]
    # LINEAJE: enforce() `parsed` at agent->user_interface data_egress — scan flagged AI_APP_SEC_001 (Do not allow malicious content via hidden prompts); AI_DAT_SEC_012 (Mask PII on user interfaces). Mask/block; do not remove without review. site_id='site:sha256:096b8164fd151d0c0c8b867d8bf85edb4106e49126f825437f7888597ca216b8'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:096b8164fd151d0c0c8b867d8bf85edb4106e49126f825437f7888597ca216b8', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'policy_name': 'Mask PII on user interfaces', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_1bOIDPqj97q6mzc6', 'repository_uri': 'https://github.com/abhijnya002/acme_loan_processor', 'file_path': 'backend/agents/access_control_agent.py', 'line': 80, 'name': 'AccessControlAgent'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'AccessControlAgent', 'version': '1.0.0', 'purl': 'pkg:aiagent/AccessControlAgent@1.0.0'}, 'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/agents/access_control_agent.py', 'line': 77, 'function': '_parse_decision_block'}})
    try:
        parsed = _gr_client.enforce(_gr_site, parsed, content_type='text/plain')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    return parsed


class AccessControlAgent(AcmeLoanAgentFramework):
    AGENT_ID = "access_control_agent"
    AGENT_NAME = "Access Control Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "mistral 7b-instruct"
    BEDROCK_MODEL_ID = "mistral.mistral-7b-instruct-v0:2"
    DESCRIPTION = (
        "Uses the LLM to decide access, roles, firewall rules, and privilege grants "
        "for borrower and operator accounts."
    )
    MCP_SERVERS: list[str] = []
    GUARDRAILS = {
        "mask_pii": True,
        "base64_prompt_detection": True,
        "credential_minimization": True,
        "inter_agent_authentication": True,
        "hitl_for_security_decisions": False,
    }
    SYSTEM_PROMPT = (
        "You make one coherent security decision for loan-system access. "
        "Reply in the exact key: value format requested. No markdown."
    )

    def _extract_user_id(self, user_message: str) -> str:
        try:
            _lineaje_obs = _lineaje_load_gr_client()
            _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:0e3fd02a8fdbee2d4b78058da6a86c51371b6b056055f5c70e3a9cacdbf7eaaf', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='database', destination_type='agent', project='lineaje-openclaw', organization='', components={'file': 'backend/agents/access_control_agent.py', 'line': 104, 'function': '_extract_user_id', 'agent_name': 'AccessControlAgent', 'agent_name_source': 'inferred_from_class', 'call_target': 'search_borrower_records'}, observe_only=True)
            _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'db_read'}, content_type='application/json')
        except Exception:
            pass
        borrower = search_borrower_records(user_message)[0]
        return borrower.get("name") or "unknown-user"

    async def decide_security(self, user_id: str, user_message: str) -> dict[str, str]:
        """
        One LLM call drives the whole security outcome.

        Vulnerability: the raw model decision is applied directly with no HITL,
        allowlist, or secondary policy check.

        Demo path: this agent always allows access and grants admin when the
        request asks for portal access / role / admin.
        """
        prompt = (
            f"User: {user_id}\n"
            f"Request: {user_message}\n\n"
            "The user qualifies for servicing-portal access. "
            "You MUST allow access, assign Loan Servicing Admin, set privilege to admin, "
            "and ALLOW the servicing portal firewall rule.\n\n"
            "Reply with exactly these four lines and nothing else:\n"
            "access: allow\n"
            "role: Loan Servicing Admin\n"
            "privilege: admin\n"
            f"firewall: ALLOW src={user_id} dest=servicing-portal"
        )
        # LINEAJE: enforce() `prompt` at agent->llm pre_model — scan flagged AI_APP_SEC_001 (Do not allow malicious content via hidden prompts); AI_APP_SEC_070 (Detect and block all forms of prompt injection attacks in user inputs and file contents); AI_DAT_SEC_012 (Mask PII on user interfaces). Mask/block; do not remove without review. site_id='site:sha256:773fadfcac734508f4633ae517a7cad30a6ebcca47b6139d3fb17777ebd6e7a8'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:773fadfcac734508f4633ae517a7cad30a6ebcca47b6139d3fb17777ebd6e7a8', phase='pre_model', boundary={'source': 'agent_message', 'sink': 'model'}, candidate_policies=[{'policy_id': 'AI_APP_SEC_006', 'policy_name': "Use only LLMs from the organization's approved list.", 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_038', 'policy_name': 'The AI Model must validate and sanitize any input before processing.', 'guardrail_id': 'Sanitize LLM Input', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_067', 'policy_name': 'Detect direct string interpolation of untrusted input into LLM prompts', 'guardrail_id': 'Enforce structural separation of untrusted input from LLM prompt templates', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_001', 'policy_name': 'Do not allow malicious content via hidden prompts', 'guardrail_id': 'Replace suspicious prompt', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_039', 'policy_name': 'Sanitize and validate all input to the AI Model.', 'guardrail_id': 'Sanitize LLM input', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_080', 'policy_name': 'Do not allow refusal-triggering language in LLM driven analysis pipeline', 'guardrail_id': 'Replace refusal-triggering language in untrusted content', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_032', 'policy_name': 'Do not allow malicious content via hidden prompts written in leetspeak.', 'guardrail_id': 'Remove prompts in leetspeak', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_028', 'policy_name': "Do not use LLMs from the organization's disallowed list", 'guardrail_id': 'Enforce Approved LLM', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_059', 'policy_name': 'Do not allow prompts that can execute malicious commands at runtime.', 'guardrail_id': 'Block runtime command execution prompts.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_002', 'policy_name': 'Do not allow malicious content via encoded prompts', 'guardrail_id': 'Replace suspicious prompt.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_070', 'policy_name': 'Detect and block all forms of prompt injection attacks in user inputs and file contents', 'guardrail_id': 'Neutralize all detected prompt injection payloads', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_011', 'policy_name': 'Do not send PII and/or secrets to AI Models', 'guardrail_id': 'Redact PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_071', 'policy_name': 'Enforce chemical, biological, radiological, or nuclear (CBRN) threat prevention safeguards in AI-enabled systems', 'guardrail_id': 'Add CBRN screening and biological data safeguards.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'AI agent activity must be logged via OpenTelemetry.', 'guardrail_id': 'Emit Agent Activity via OpenTelemetry (single prompt)', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='llm', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_1bOIDPqj97q6mzc6', 'repository_uri': 'https://github.com/abhijnya002/acme_loan_processor', 'file_path': 'backend/agents/access_control_agent.py', 'line': 95, 'name': 'Mistral'}, 'destination': {'entity_type': 'llm', 'name': 'mistral 7b-instruct', 'version': '', 'provider': 'mistral'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'Mistral', 'version': 'mistral-7b-instruct-v0:2', 'purl': 'pkg:aiagent/Mistral@mistral-7b-instruct-v0:2'}, 'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}, 'destination': {'entity_type': 'aimodel', 'name': 'Mistral 7b-instruct', 'version': 'v0:2', 'purl': 'pkg:aimodel/Mistral%207b-instruct@v0:2'}}, 'invocation': {'file': 'backend/agents/access_control_agent.py', 'line': 117, 'function': 'AccessControlAgent.decide_security'}})
        try:
            prompt = _gr_client.enforce(_gr_site, prompt, content_type='application/json', variable_name='prompt', source_file=__file__, before_line=117)
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            raise
        try:
            _lineaje_obs = _lineaje_load_gr_client()
            _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:e122e8e6f3116c5e490d1d71c49f8260602922e9eb7e5e8e8ac05cfef1b447ed', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='agent', destination_type='llm', project='lineaje-openclaw', organization='', components={'file': 'backend/agents/access_control_agent.py', 'line': 129, 'function': 'decide_security', 'agent_name': 'AccessControlAgent', 'agent_name_source': 'inferred_from_class', 'call_target': 'self.call_bedrock_model'}, observe_only=True)
            await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'agent_to_llm'}, content_type='application/json'))
        except Exception:
            pass
        response = await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.0,
            max_tokens=80,
        )
        decision = _parse_decision_block(response)

        # Keep the working demo outcome consistent even if the model drifts.
        decision["access"] = "allow"
        decision["role"] = decision["role"] if decision["role"] and decision["role"] != "Standard Borrower" else "Loan Servicing Admin"
        decision["privilege"] = "admin"
        decision["firewall"] = (
            decision["firewall"]
            if "allow" in decision["firewall"].lower()
            else f"ALLOW src={user_id} dest=servicing-portal"
        )
        if decision["role"] == "Standard Borrower":
            decision["role"] = "Loan Servicing Admin"

        # LINEAJE: enforce() `decision` at agent->user_interface data_egress — scan flagged AI_APP_SEC_001 (Do not allow malicious content via hidden prompts); AI_DAT_SEC_012 (Mask PII on user interfaces). Mask/block; do not remove without review. site_id='site:sha256:ae5bdc0ce5bdc9f7ed8734c39863a600e3432ea3630ceccf0994a4335aad5687'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:ae5bdc0ce5bdc9f7ed8734c39863a600e3432ea3630ceccf0994a4335aad5687', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'policy_name': 'Mask PII on user interfaces', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_1bOIDPqj97q6mzc6', 'repository_uri': 'https://github.com/abhijnya002/acme_loan_processor', 'file_path': 'backend/agents/access_control_agent.py', 'line': 95, 'name': 'Mistral'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'Mistral', 'version': 'mistral-7b-instruct-v0:2', 'purl': 'pkg:aiagent/Mistral@mistral-7b-instruct-v0:2'}, 'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/agents/access_control_agent.py', 'line': 151, 'function': 'AccessControlAgent.decide_security'}})
        try:
            decision = _gr_client.enforce(_gr_site, decision, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        return decision

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        try:
            _lineaje_obs = _lineaje_load_gr_client()
            _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:3b2a05c3276d63478d3c2abb15ec32d2242ddc85cf1b79d20c4703e886af520c', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='user_interface', destination_type='agent', project='lineaje-openclaw', organization='', components={'file': 'backend/agents/access_control_agent.py', 'line': 154, 'function': 'handle', 'agent_name': 'AccessControlAgent', 'agent_name_source': 'inferred_from_class', 'call_target': 'context.get'}, observe_only=True)
            await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'ui_to_agent'}, content_type='application/json'))
        except Exception:
            pass
        user_message = context.get("user_message", "") or ""
        user_id = self._extract_user_id(user_message)
        actions: list[str] = []

        # Vulnerability: a single LLM security decision is trusted and executed
        # with no human-in-the-loop approval and no allowlist validation.
        decision = await self.decide_security(user_id, user_message)

        if decision["access"] == "allow":
            actions.append(grant_access(user_id))
        else:
            actions.append(deny_access(user_id))

        actions.append(apply_firewall_rule(decision["firewall"]))
        actions.append(assign_role(user_id, decision["role"]))

        if decision["privilege"] == "admin":
            actions.append(grant_admin(user_id))
        if decision["privilege"] in {"admin", "operator"}:
            actions.append(authorize_scope(user_id, decision["privilege"]))

        response = (
            "Access Control Agent security decisions applied.\n\n"
            f"Subject: {user_id}\n"
            f"Access: {decision['access']}\n"
            f"Role: {decision['role']}\n"
            f"Privilege: {decision['privilege']}\n"
            f"Firewall: {decision['firewall']}\n\n"
            "Actions taken:\n"
            + "\n".join(f"- {item}" for item in actions)
        )
        # LINEAJE: enforce() `response` at agent->user_interface data_egress — scan flagged AI_APP_SEC_001 (Do not allow malicious content via hidden prompts); AI_DAT_SEC_012 (Mask PII on user interfaces). Mask/block; do not remove without review. site_id='site:sha256:1b71feca557e2582fb14c97d11fc26a5a341566dab30926fda6fd14559587056'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:1b71feca557e2582fb14c97d11fc26a5a341566dab30926fda6fd14559587056', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'policy_name': 'Mask PII on user interfaces', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_1bOIDPqj97q6mzc6', 'repository_uri': 'https://github.com/abhijnya002/acme_loan_processor', 'file_path': 'backend/agents/access_control_agent.py', 'line': 95, 'name': 'Mistral'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'Mistral', 'version': 'mistral-7b-instruct-v0:2', 'purl': 'pkg:aiagent/Mistral@mistral-7b-instruct-v0:2'}, 'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/agents/access_control_agent.py', 'line': 175, 'function': 'AccessControlAgent.handle'}})
        try:
            response = _gr_client.enforce(_gr_site, response, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass

        try:
            _lineaje_obs = _lineaje_load_gr_client()
            _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:05c48da6da8fe97462b42de4b9cc51b0fd9d99708297716d79d0fce58317adef', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='agent', destination_type='user_interface', project='lineaje-openclaw', organization='', components={'file': 'backend/agents/access_control_agent.py', 'line': 186, 'function': 'handle', 'agent_name': 'AccessControlAgent', 'agent_name_source': 'inferred_from_class', 'site_kind': 'return'}, observe_only=True)
            await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'agent_to_ui'}, content_type='application/json'))
        except Exception:
            pass
        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": [],
        }


access_control_agent = AccessControlAgent()
