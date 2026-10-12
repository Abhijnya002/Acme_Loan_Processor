"""Orchestrator Agent class with explicit model invocation."""
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
from typing import Any

from .access_control_agent import access_control_agent
from .credit_eval_agent import credit_eval_agent
from .environment_diagnostics_agent import environment_diagnostics_agent
from .file_management_agent import file_management_agent
from .file_processor_agent import file_processor_agent
from .framework import AcmeLoanAgentFramework
from .loan_processing_agent import loan_processing_agent
from .rate_check_agent import rate_check_agent
from .scheduling_agent import scheduling_agent
from .installed_skill_agent import installed_skill_agent

logger = logging.getLogger(__name__)


class OrchestratorAgent(AcmeLoanAgentFramework):
    AGENT_ID = "orchestrator_agent"
    AGENT_NAME = "Orchestrator Agent"
    VERSION = "1.0.0"
    OPENROUTER_MODEL = "meta-llama/llama-4-scout"
    MODEL_NAME = "meta-llama/llama-4-scout"
    BEDROCK_MODEL_ID = "us.anthropic.claude-3-5-sonnet-20241022-v2:0"
    DESCRIPTION = "Routes work between the specialized agents and shares the conversation context."
    MCP_SERVERS = ["Slack"]
    GUARDRAILS = {
        "mask_pii": None,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": False,
    }
    SYSTEM_PROMPT = "Route requests to the right specialist and keep the workflow moving."

    async def call_agent_model(self, user_message: str, selected_agent_name: str) -> str:
        try:
            _lineaje_obs = _lineaje_load_gr_client()
            _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:e54ae34fb18410bc70d762f1a8419d3b298aa7cbc586f959cfb3841b58490d2a', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='agent', destination_type='llm', project='lineaje-openclaw', organization='', components={'file': 'backend/agents/orchestrator_agent.py', 'line': 38, 'function': 'call_agent_model', 'agent_name': 'OrchestratorAgent', 'agent_name_source': 'inferred_from_class', 'call_target': 'self.call_bedrock_model'}, observe_only=True)
            await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'agent_to_llm'}, content_type='application/json'))
        except Exception:
            pass
        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"User request:\n{user_message or 'No user message provided.'}\n\n"
                        f"Selected agent: {selected_agent_name}\n\n"
                        "Explain the routing decision in one short paragraph."
                    ),
                },
            ],
            temperature=0.1,
            max_tokens=160,
        )

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        selected_agent = self.select_agent(
            user_message=context.get("user_message", ""),
            file_contents=context.get("file_contents", []),
        )
        selected_agent_name = selected_agent.AGENT_NAME

        # Vulnerability: the Orchestrator Agent forwards the entire context and a
        # shared internal token to downstream agents with no authentication boundary.
        forwarded_context = dict(context)
        forwarded_context["orchestrator_agent"] = self.AGENT_NAME
        forwarded_context["selected_agent"] = selected_agent_name
        forwarded_context["internal_call_chain"] = [self.AGENT_NAME, selected_agent_name]
        forwarded_context["internal_hop_token"] = "shared-orchestrator-hop-token"

        _lineaje_payload = "Orchestrator Agent routing request"
        # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:2f989c04e85ce464a8e3c6400b0a5a29a71060cd43bf9f475a3954f132ab04a0'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:2f989c04e85ce464a8e3c6400b0a5a29a71060cd43bf9f475a3954f132ab04a0', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='log', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_1bOIDPqj97q6mzc6', 'repository_uri': 'https://github.com/abhijnya002/acme_loan_processor', 'file_path': 'backend/agents/orchestrator_agent.py', 'line': 20, 'name': 'OrchestratorAgent'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'OrchestratorAgent', 'version': '1.0.0', 'purl': 'pkg:aiagent/OrchestratorAgent@1.0.0'}, 'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/agents/orchestrator_agent.py', 'line': 69, 'function': 'OrchestratorAgent.handle'}})
        try:
            _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        logger.info(
            _lineaje_payload,
            extra={
                "selected_agent": selected_agent_name,
                "internal_call_chain": forwarded_context["internal_call_chain"],
            },
        )

        # LINEAJE: enforce() `selected_agent_name` at agent->llm pre_model — scan flagged AI_APP_SEC_070 (Detect and block all forms of prompt injection attacks in user inputs and file contents). Mask/block; do not remove without review. site_id='site:sha256:d6efea20d79f7339b68de3727c847b4cb8dff8eabec9475924c2637c15605f81'
        _lineaje_selected_agent_name_evidence = {'selected_agent_name': selected_agent_name, 'model': _lineaje_current_model(), 'project': 'lineaje-openclaw'}
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:d6efea20d79f7339b68de3727c847b4cb8dff8eabec9475924c2637c15605f81', phase='pre_model', boundary={'source': 'agent_message', 'sink': 'model'}, candidate_policies=[{'policy_id': 'AI_APP_SEC_006', 'policy_name': "Use only LLMs from the organization's approved list.", 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_038', 'policy_name': 'The AI Model must validate and sanitize any input before processing.', 'guardrail_id': 'Sanitize LLM Input', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_067', 'policy_name': 'Detect direct string interpolation of untrusted input into LLM prompts', 'guardrail_id': 'Enforce structural separation of untrusted input from LLM prompt templates', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_001', 'policy_name': 'Do not allow malicious content via hidden prompts', 'guardrail_id': 'Replace suspicious prompt', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_039', 'policy_name': 'Sanitize and validate all input to the AI Model.', 'guardrail_id': 'Sanitize LLM input', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_080', 'policy_name': 'Do not allow refusal-triggering language in LLM driven analysis pipeline', 'guardrail_id': 'Replace refusal-triggering language in untrusted content', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_032', 'policy_name': 'Do not allow malicious content via hidden prompts written in leetspeak.', 'guardrail_id': 'Remove prompts in leetspeak', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_059', 'policy_name': 'Do not allow prompts that can execute malicious commands at runtime.', 'guardrail_id': 'Block runtime command execution prompts.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_028', 'policy_name': "Do not use LLMs from the organization's disallowed list", 'guardrail_id': 'Enforce Approved LLM', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_002', 'policy_name': 'Do not allow malicious content via encoded prompts', 'guardrail_id': 'Replace suspicious prompt.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_070', 'policy_name': 'Detect and block all forms of prompt injection attacks in user inputs and file contents', 'guardrail_id': 'Neutralize all detected prompt injection payloads', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_011', 'policy_name': 'Do not send PII and/or secrets to AI Models', 'guardrail_id': 'Redact PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_071', 'policy_name': 'Enforce chemical, biological, radiological, or nuclear (CBRN) threat prevention safeguards in AI-enabled systems', 'guardrail_id': 'Add CBRN screening and biological data safeguards.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'AI agent activity must be logged via OpenTelemetry.', 'guardrail_id': 'Emit Agent Activity via OpenTelemetry (single prompt)', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='llm', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_1bOIDPqj97q6mzc6', 'repository_uri': 'https://github.com/abhijnya002/acme_loan_processor', 'file_path': 'backend/agents/orchestrator_agent.py', 'line': 20, 'name': 'OrchestratorAgent'}, 'destination': {'entity_type': 'llm', 'name': 'us.anthropic.claude-3-5-sonnet-20241022-v2:0', 'version': '', 'provider': ''}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'OrchestratorAgent', 'version': '1.0.0', 'purl': 'pkg:aiagent/OrchestratorAgent@1.0.0'}, 'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}, 'destination': {'entity_type': 'aimodel', 'name': 'us.anthropic.claude-3-5-sonnet-20241022-v2:0', 'version': '', 'purl': 'pkg:aimodel/us.anthropic.claude-3-5-sonnet-20241022-v2%3A0@1.0.0'}}, 'invocation': {'file': 'backend/agents/orchestrator_agent.py', 'line': 77, 'function': 'OrchestratorAgent.handle'}})
        try:
            _lineaje_selected_agent_name_evidence = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_selected_agent_name_evidence, content_type='application/json'))
            selected_agent_name = _lineaje_selected_agent_name_evidence.get('selected_agent_name', selected_agent_name) if isinstance(_lineaje_selected_agent_name_evidence, dict) else selected_agent_name
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            raise
        routing_note = await self.call_agent_model(
            context.get("user_message", ""),
            selected_agent_name,
        )
        try:
            _lineaje_obs = _lineaje_load_gr_client()
            _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:fc3644ea812b79198b288f7175d31fd1326008d423e18a546c7618a9ecc8b9ad', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='llm', destination_type='agent', project='lineaje-openclaw', organization='', components={'file': 'backend/agents/orchestrator_agent.py', 'line': 77, 'function': 'handle', 'agent_name': 'OrchestratorAgent', 'agent_name_source': 'inferred_from_class', 'call_target': 'self.call_agent_model'}, observe_only=True, interaction_id=locals().get('_lineaje_interaction_id'))
            await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'llm_to_agent'}, content_type='application/json'))
        except Exception:
            pass
        try:
            _lineaje_obs = _lineaje_load_gr_client()
            _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:f670d5925fb98621815c619d4d7363874b7511069aa5ed18c22f472974a46474', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='agent', destination_type='agent', project='lineaje-openclaw', organization='', components={'file': 'backend/agents/orchestrator_agent.py', 'line': 81, 'function': 'handle', 'agent_name': 'OrchestratorAgent', 'agent_name_source': 'inferred_from_class', 'call_target': 'selected_agent.handle'}, observe_only=True)
            await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'agent_to_agent'}, content_type='application/json'))
        except Exception:
            pass
        response = await selected_agent.handle(forwarded_context)
        response["orchestrator"] = self.AGENT_NAME
        response["routing_note"] = routing_note
        # LINEAJE: enforce() `response` at agent->user_interface data_egress — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:728d0c5aa3c4919ecd2548d7268f00f18efd85878270cc125539b0b1d7a5762b'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:728d0c5aa3c4919ecd2548d7268f00f18efd85878270cc125539b0b1d7a5762b', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'policy_name': 'Mask PII on user interfaces', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_1bOIDPqj97q6mzc6', 'repository_uri': 'https://github.com/abhijnya002/acme_loan_processor', 'file_path': 'backend/agents/orchestrator_agent.py', 'line': 20, 'name': 'OrchestratorAgent'}, 'identity': {'source': {'entity_type': 'aiagent', 'name': 'OrchestratorAgent', 'version': '1.0.0', 'purl': 'pkg:aiagent/OrchestratorAgent@1.0.0'}, 'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/agents/orchestrator_agent.py', 'line': 84, 'function': 'OrchestratorAgent.handle'}})
        try:
            response = _gr_client.enforce(_gr_site, response, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        return response

    def select_agent(self, user_message: str, file_contents: list[dict[str, Any]]) -> AcmeLoanAgentFramework:
        text = (user_message or "").lower()

        if self._should_route_to_installed_skill(text):
            return installed_skill_agent
        if any(keyword in text for keyword in ["schedule", "meeting", "calendar", "appointment"]):
            return scheduling_agent
        if any(
            keyword in text
            for keyword in [
                "delete",
                "purge",
                "destroy",
                "remove file",
                "file management",
                "deletefile",
                "purge records",
            ]
        ):
            return file_management_agent
        if any(
            keyword in text
            for keyword in [
                "grant access",
                "deny access",
                "allow access",
                "firewall",
                "assign role",
                "assign a role",
                "grant admin",
                "privilege",
                "authorize",
                "access control",
                "security decision",
            ]
        ):
            return access_control_agent
        if any(
            keyword in text
            for keyword in [
                "environment diagnostic",
                "environment diagnostics",
                "run diagnostics",
                "diagnostic steps",
                "verify environment",
                "environment setup",
                "closing image",
            ]
        ):
            return environment_diagnostics_agent
        if self._should_route_to_rate_check(text):
            return rate_check_agent
        if any(keyword in text for keyword in ["credit", "fico", "debt-to-income", "dti", "underwrite", "loan status", "employee", "ssn", "borrower status"]):
            return credit_eval_agent
        if any(keyword in text for keyword in ["loan", "mortgage", "borrower", "application"]):
            return credit_eval_agent
        if file_contents or any(
            keyword in text
            for keyword in [
                "support document",
                "uploaded support",
                "review this uploaded",
                "summarize it's contents",
                "summarize its contents",
                "uploaded document",
                "review document",
            ]
        ):
            return file_processor_agent
        return credit_eval_agent

    @staticmethod
    def _should_route_to_installed_skill(text: str) -> bool:
        # Ambient skill loading: match task intent, not explicit "use skill" commands.
        skill_match_keywords = [
            "loan document",
            "loan documents",
            "process my loan document",
            "process loan document",
            "review my loan document",
            "review loan document",
        ]
        return any(keyword in text for keyword in skill_match_keywords)

    @staticmethod
    def _should_route_to_rate_check(text: str) -> bool:
        rate_check_keywords = [
            "interest rate",
            "mortgage rate",
            "rate check",
            "current rates",
            "average rate",
            "30-year fixed",
            "15-year fixed",
        ]
        return any(keyword in text for keyword in rate_check_keywords)


orchestrator_agent = OrchestratorAgent()
