"""
OpenAI-compatible model gateway client.

This keeps the request shape real and makes the selected model visible in each
agent file via the `model=` argument on every call.
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


import asyncio
import logging
import os
import re
import time
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

# Retry transient upstream failures (5xx / gateway timeouts / connection
# resets / empty completions). meta-llama/llama-4-scout on OpenRouter
# occasionally returns a 504 Gateway Timeout, and deepseek/deepseek-r1 (only
# served by Novita) sometimes finishes with an empty `content`.
_MAX_ATTEMPTS = 4
_RETRY_BACKOFF_SEC = 1.5
# Reasoning models such as deepseek-r1 take 15-30s per call.
_REQUEST_TIMEOUT_SEC = 90


def _extract_content(message: dict[str, Any]) -> str:
    """Return the assistant text from a chat-completions message, accepting
    either a plain string or a list of content parts."""
    content = message.get("content")
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        parts = [
            part.get("text", "") if isinstance(part, dict) else str(part)
            for part in content
        ]
        return "".join(parts).strip()
    return ""


_HERE_IS_ANSWER = re.compile(r"here(?:'s| is| are)\b", re.IGNORECASE)
_FORMATTED_PARAGRAPH = re.compile(r"(?:\*\*|#{1,6}\s|[-*]\s|\d+\.\s)")
_MIN_RECOVERED_ANSWER_CHARS = 40


def _answer_from_reasoning(reasoning: str) -> str:
    """Recover the final answer when a reasoning model returns it inside
    `reasoning` instead of `content` (Novita's deepseek-r1 does this: the
    thinking and the answer arrive as one block, answer last).

    Takes everything from the last "Here's / Here is ..." paragraph, else the
    trailing run of markdown-formatted paragraphs. Returns "" if neither is
    found, so the caller can retry."""
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", reasoning or "") if p.strip()]
    answer = ""
    for index in range(len(paragraphs) - 1, -1, -1):
        if _HERE_IS_ANSWER.match(paragraphs[index]):
            answer = "\n\n".join(paragraphs[index:])
            break
    else:
        start = len(paragraphs)
        while start > 0 and _FORMATTED_PARAGRAPH.match(paragraphs[start - 1]):
            start -= 1
        answer = "\n\n".join(paragraphs[start:])
    return answer if len(answer) >= _MIN_RECOVERED_ANSWER_CHARS else ""


class OpenAICompatibleClient:
    """Minimal async wrapper around a chat-completions style API."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        # Use OpenRouter credentials from the environment.
        self.base_url = (
            base_url
            or os.getenv("OPENROUTER_BASE_URL")
            or "https://openrouter.ai/api/v1"
        ).rstrip("/")
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")

    async def chat(
        self,
        model: str,
        messages: list[dict[str, Any]],
        temperature: float = 0.2,
        max_tokens: int = 400,
        recover_answer_from_reasoning: bool = False,
    ) -> str:
        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        def _post() -> str:
            last_exc: Optional[Exception] = None
            empty_responses = 0
            for attempt in range(1, _MAX_ATTEMPTS + 1):
                try:
                    try:
                        _lineaje_obs = _lineaje_load_gr_client()
                        _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:ea23ba201f8ac652d36f26dbf59545c489b86d8058e9da34f890a9ab089f7212', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='agent', destination_type='llm', project='lineaje-openclaw', organization='', components={'file': 'backend/llm/openai_compatible.py', 'line': 111, 'function': '_post', 'agent_name': 'OpenAICompatibleClient', 'agent_name_source': 'inferred_from_class', 'call_target': 'requests.post'}, observe_only=True)
                        _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'agent_to_llm'}, content_type='application/json')
                    except Exception:
                        pass
                    response = requests.post(
                        f"{self.base_url}/chat/completions",
                        json=payload,
                        headers=headers,
                        timeout=_REQUEST_TIMEOUT_SEC,
                    )
                    response.raise_for_status()
                    data = response.json()
                    choices = data.get("choices") or []
                    message = (choices[0].get("message") or {}) if choices else {}
                    content = _extract_content(message)
                    if not content and recover_answer_from_reasoning:
                        content = _answer_from_reasoning(message.get("reasoning") or "")
                        if content:
                            _lineaje_payload = "Recovered answer from the reasoning field"
                            # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:c3bbe445b49347f82d66ab5734bf0e9e4427ac3ddbd1047479984e61ba8762f0'
                            _gr_client = _lineaje_load_gr_client()
                            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:c3bbe445b49347f82d66ab5734bf0e9e4427ac3ddbd1047479984e61ba8762f0', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='log', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/llm/openai_compatible.py', 'line': 125, 'function': 'OpenAICompatibleClient.chat._post'}})
                            try:
                                _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
                            except _gr_client.GuardrailUnavailableError:
                                pass
                            except PermissionError:
                                pass
                            logger.info(
                                _lineaje_payload,
                                extra={"model": model, "provider": data.get("provider")},
                            )
                    if content:
                        # LINEAJE: enforce() `content` at agent->user_interface data_egress — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:f94e47468454f7b574d9016a4c29e82063aca4e1a98e820468e23728be58df80'
                        _gr_client = _lineaje_load_gr_client()
                        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:f94e47468454f7b574d9016a4c29e82063aca4e1a98e820468e23728be58df80', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'policy_name': 'Mask PII on user interfaces', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/llm/openai_compatible.py', 'line': 130, 'function': 'OpenAICompatibleClient.chat._post'}})
                        try:
                            content = _gr_client.enforce(_gr_site, content, content_type='text/plain')
                        except _gr_client.GuardrailUnavailableError:
                            pass
                        except PermissionError:
                            pass
                        return content

                    # 200 OK but no answer text: transient provider behaviour,
                    # so retry instead of surfacing an empty reply.
                    empty_responses += 1
                    last_exc = None
                    if attempt < _MAX_ATTEMPTS:
                        # LINEAJE: enforce() `attempt` at agent->log log_emit — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:5eabc0b12a1ab00b86889c52b676308ae6253da9741e402a484d8040dd3aada2'
                        _gr_client = _lineaje_load_gr_client()
                        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:5eabc0b12a1ab00b86889c52b676308ae6253da9741e402a484d8040dd3aada2', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='log', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/llm/openai_compatible.py', 'line': 137, 'function': 'OpenAICompatibleClient.chat._post'}})
                        try:
                            attempt = _gr_client.enforce(_gr_site, attempt, content_type='application/json')
                        except _gr_client.GuardrailUnavailableError:
                            pass
                        except PermissionError:
                            pass
                        logger.warning(
                            "Model returned empty content — retrying (%d/%d)",
                            attempt, _MAX_ATTEMPTS,
                            extra={
                                "model": model,
                                "provider": data.get("provider"),
                                "finish_reason": choices[0].get("finish_reason") if choices else None,
                            },
                        )
                        time.sleep(_RETRY_BACKOFF_SEC * attempt)
                        continue
                    break
                except requests.HTTPError as exc:
                    last_exc = exc
                    status = exc.response.status_code if exc.response is not None else None
                    # Retry only on transient upstream 5xx (e.g. 504 gateway
                    # timeout). 4xx are caller errors — fail fast.
                    if status is not None and 500 <= status < 600 and attempt < _MAX_ATTEMPTS:
                        # LINEAJE: enforce() `status` at agent->log log_emit — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:f0bdd91c9d5b8cd54b6ede4906e40f67beb653d46e1f54c9497e073010a0b221'
                        _gr_client = _lineaje_load_gr_client()
                        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:f0bdd91c9d5b8cd54b6ede4906e40f67beb653d46e1f54c9497e073010a0b221', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='log', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/llm/openai_compatible.py', 'line': 155, 'function': 'OpenAICompatibleClient.chat._post'}})
                        try:
                            status = _gr_client.enforce(_gr_site, status, content_type='application/json')
                        except _gr_client.GuardrailUnavailableError:
                            pass
                        except PermissionError:
                            pass
                        logger.warning(
                            "Model gateway %s — retrying (%d/%d)",
                            status, attempt, _MAX_ATTEMPTS,
                            extra={"model": model},
                        )
                        time.sleep(_RETRY_BACKOFF_SEC * attempt)
                        continue
                    break
                except (requests.Timeout, requests.ConnectionError) as exc:
                    last_exc = exc
                    if attempt < _MAX_ATTEMPTS:
                        # LINEAJE: enforce() `attempt` at agent->log log_emit — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:1a40e6203763684e2b36b717286ad396ca088de2b8b2c086d06e9d1c3c291f9c'
                        _gr_client = _lineaje_load_gr_client()
                        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:1a40e6203763684e2b36b717286ad396ca088de2b8b2c086d06e9d1c3c291f9c', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='log', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/llm/openai_compatible.py', 'line': 166, 'function': 'OpenAICompatibleClient.chat._post'}})
                        try:
                            attempt = _gr_client.enforce(_gr_site, attempt, content_type='application/json')
                        except _gr_client.GuardrailUnavailableError:
                            pass
                        except PermissionError:
                            pass
                        logger.warning(
                            "Model gateway network error — retrying (%d/%d): %s",
                            attempt, _MAX_ATTEMPTS, exc,
                            extra={"model": model},
                        )
                        time.sleep(_RETRY_BACKOFF_SEC * attempt)
                        continue
                    break
                except requests.RequestException as exc:
                    last_exc = exc
                    break

            if last_exc is None and empty_responses:
                _lineaje_payload = "Model returned empty content on every attempt"
                # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:d86e83aa13a8c555127f1f8b59c37db2680d2f31ca6ce3eb1c6290a0a9e741e7'
                _gr_client = _lineaje_load_gr_client()
                _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:d86e83aa13a8c555127f1f8b59c37db2680d2f31ca6ce3eb1c6290a0a9e741e7', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='log', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/llm/openai_compatible.py', 'line': 179, 'function': 'OpenAICompatibleClient.chat._post'}})
                try:
                    _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
                except _gr_client.GuardrailUnavailableError:
                    pass
                except PermissionError:
                    pass
                logger.warning(
                    _lineaje_payload,
                    extra={"model": model, "attempts": empty_responses},
                )
                return (
                    f"{model} returned an empty response {empty_responses} times in a row. "
                    "The upstream provider is flaky right now — please try again."
                )

            _lineaje_payload = "Model gateway request failed"
            # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:e425886b6161bf62b9b855a159624bffd5f8b41afeb155d11977b4358344590a'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:e425886b6161bf62b9b855a159624bffd5f8b41afeb155d11977b4358344590a', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='log', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/llm/openai_compatible.py', 'line': 188, 'function': 'OpenAICompatibleClient.chat._post'}})
            try:
                _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            logger.warning(
                _lineaje_payload,
                extra={"model": model, "error": str(last_exc)},
            )
            return f"Model gateway unavailable for {model}: {last_exc}"

        return await asyncio.to_thread(_post)

    async def chat_vision(
        self,
        model: str,
        image_base64: str,
        mime_type: str,
        prompt: str,
        max_tokens: int = 500,
    ) -> str:
        """Send an image to a vision-capable model as an image_url content block."""
        try:
            _lineaje_obs = _lineaje_load_gr_client()
            _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:afe5b385aea3b74c511ea6b56a036eecbcb4963c9cb4a3d9921f819d5e65d042', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='agent', destination_type='llm', project='lineaje-openclaw', organization='', components={'file': 'backend/llm/openai_compatible.py', 'line': 205, 'function': 'chat_vision', 'agent_name': 'OpenAICompatibleClient', 'agent_name_source': 'inferred_from_class'}, observe_only=True)
            await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'agent_to_llm'}, content_type='application/json'))
        except Exception:
            pass
        messages = [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt},
                    {
                        "type": "image_url",
                        "image_url": {"url": f"data:{mime_type};base64,{image_base64}"},
                    },
                ],
            }
        ]
        try:
            _lineaje_obs = _lineaje_load_gr_client()
            _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:12a3c5894678fa2b2badfac645a33085132c137d8cec5b01fd42ed23a3bd9a06', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='agent', destination_type='llm', project='lineaje-openclaw', organization='', components={'file': 'backend/llm/openai_compatible.py', 'line': 217, 'function': 'chat_vision', 'agent_name': 'OpenAICompatibleClient', 'agent_name_source': 'inferred_from_class', 'call_target': 'self.chat'}, observe_only=True)
            await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'agent_to_llm'}, content_type='application/json'))
        except Exception:
            pass
        return await self.chat(model=model, messages=messages, temperature=0.0, max_tokens=max_tokens)
