"""
HTML Parser

Extracts text content from HTML files.

SECURITY NOTES (for Unifai demo):
- Extracts text including from hidden elements
- CSS-hidden content is extracted
- Script content may be included
- No XSS sanitization
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
from typing import Optional

logger = logging.getLogger(__name__)


class HTMLParser:
    """
    Parses HTML files and extracts text content.

    VULNERABILITY: Extracts hidden content without flagging.
    - display:none elements are extracted
    - visibility:hidden elements are extracted
    - Off-screen positioned elements are extracted
    - White text on white background is extracted
    """

    def __init__(self):
        pass

    async def extract_text(self, html_content: str) -> str:
        """
        Extract all text from HTML content.

        VULNERABILITY: All text extracted including hidden content.
        get_text() extracts text from hidden elements.
        """
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html_content, 'html.parser')

            # Remove script and style elements (but not hidden divs!)
            for element in soup(['script', 'style']):
                element.decompose()

            # VULNERABILITY: get_text() extracts from hidden elements too
            # This includes:
            # - Elements with display:none
            # - Elements with visibility:hidden
            # - Off-screen positioned elements
            # - White text on white background
            try:
                _lineaje_obs = _lineaje_load_gr_client()
                _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:d92e08430e1822b24e3bb4cf924a2552aebe239689d973bfd817325b75053ad4', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='rag_source', destination_type='rag_pipeline', project='lineaje-openclaw', organization='', components={'file': 'backend/file_parsers/html_parser.py', 'line': 55, 'function': 'extract_text', 'agent_name': 'HTMLParser', 'agent_name_source': 'inferred_from_class', 'call_target': 'soup.get_text'}, observe_only=True)
                await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'rag_ingest'}, content_type='application/json'))
            except Exception:
                pass
            try:
                _lineaje_obs = _lineaje_load_gr_client()
                _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:d261b071f7a0510f4402bd8724dfb7002ffcbf2a8045355104a66eb2a7bb8bc9', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='rag_source', destination_type='rag_pipeline', project='lineaje-openclaw', organization='', components={'file': 'backend/file_parsers/html_parser.py', 'line': 94, 'function': 'extract_text', 'agent_name': 'HTMLParser', 'agent_name_source': 'inferred_from_class', 'call_target': 'soup.get_text'}, observe_only=True)
                await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'rag_ingest'}, content_type='application/json'))
            except Exception:
                pass
            text = soup.get_text(separator='\n', strip=True)

            _lineaje_payload = "HTML text extraction complete"
            # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:7c87fcc1cf42b48751e7d8d1e2cc30e673866634fb1d8c2df64d1c79bd0d20b3'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:7c87fcc1cf42b48751e7d8d1e2cc30e673866634fb1d8c2df64d1c79bd0d20b3', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='log', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/file_parsers/html_parser.py', 'line': 57, 'function': 'HTMLParser.extract_text'}})
            try:
                _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:7f537b4ef4fd2ca46ce909a6d58754b2b9ad27d3b2e86638385ca51a02eec38b'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:7f537b4ef4fd2ca46ce909a6d58754b2b9ad27d3b2e86638385ca51a02eec38b', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='log', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='local-run', project_branch='local-run', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'local-run', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@local-run?commit-id=a9ad1bb4e72b5adfd0085522ce8623710221f948&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/file_parsers/html_parser.py', 'line': 106, 'function': 'HTMLParser.extract_text'}})
            try:
                _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            logger.info(
                _lineaje_payload,
                extra={
                    "text_length": len(text),
                    # VULNERABILITY: Content preview in logs
                    "preview": text[:100]
                }
            )

            # LINEAJE: enforce() `text` at agent->user_interface data_egress — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:c0823b13e69b2090df5f929bd273778e8bee23a78d14da234733272bde594795'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:c0823b13e69b2090df5f929bd273778e8bee23a78d14da234733272bde594795', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'policy_name': 'Mask PII on user interfaces', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/file_parsers/html_parser.py', 'line': 66, 'function': 'HTMLParser.extract_text'}})
            try:
                try:
                    _lineaje_obs = _lineaje_load_gr_client()
                    _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:6706ca2f59b05b9a1a545b4480476be70f280c1394791edd70df288fb1a9a5de', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='rag_source', destination_type='rag_pipeline', project='lineaje-openclaw', organization='', components={'file': 'backend/file_parsers/html_parser.py', 'line': 119, 'function': 'extract_text', 'agent_name': 'HTMLParser', 'agent_name_source': 'inferred_from_class', 'call_target': '_gr_client.enforce'}, observe_only=True)
                    await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'rag_ingest'}, content_type='application/json'))
                except Exception:
                    pass
                text = _gr_client.enforce(_gr_site, text, content_type='text/plain')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            # LINEAJE: enforce() `text` at agent->user_interface data_egress — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:f4d4aabf7205f1c718dbfe7e5e9d230991da785446695e7da29e03de1492ded0'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:f4d4aabf7205f1c718dbfe7e5e9d230991da785446695e7da29e03de1492ded0', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'policy_name': 'Mask PII on user interfaces', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='local-run', project_branch='local-run', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'local-run', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@local-run?commit-id=a9ad1bb4e72b5adfd0085522ce8623710221f948&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/file_parsers/html_parser.py', 'line': 124, 'function': 'HTMLParser.extract_text'}})
            try:
                text = _gr_client.enforce(_gr_site, text, content_type='text/plain')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            return text

        except Exception as e:
            _lineaje_payload = f"HTML extraction error: {e}"
            # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:6db350d10da664d1f974c2b94c04346f1571ac6550c498fc100cd74e3d0a6661'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:6db350d10da664d1f974c2b94c04346f1571ac6550c498fc100cd74e3d0a6661', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='log', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/file_parsers/html_parser.py', 'line': 69, 'function': 'HTMLParser.extract_text'}})
            try:
                _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:67665e147978af3a239056bef0d42635bc3038700724421b5c797c9827f8209d'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:67665e147978af3a239056bef0d42635bc3038700724421b5c797c9827f8209d', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='log', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='local-run', project_branch='local-run', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'local-run', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@local-run?commit-id=a9ad1bb4e72b5adfd0085522ce8623710221f948&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/file_parsers/html_parser.py', 'line': 137, 'function': 'HTMLParser.extract_text'}})
            try:
                _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            logger.error(_lineaje_payload)
            return f"Error extracting HTML: {str(e)}"

    async def extract_visible_only(self, html_content: str) -> str:
        """
        Extract only visible text (not implemented properly).

        VULNERABILITY: Still extracts hidden content.
        Would need CSS parsing to properly filter.
        """
        # VULNERABILITY: This method doesn't actually filter hidden content
        # It would need to parse inline styles and CSS classes
        try:
            _lineaje_obs = _lineaje_load_gr_client()
            _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:9039713c7f5cce0c113405efa811a68ef2d061acb939d1e4ce3538e108dcf347', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='rag_source', destination_type='rag_pipeline', project='lineaje-openclaw', organization='', components={'file': 'backend/file_parsers/html_parser.py', 'line': 81, 'function': 'extract_visible_only', 'agent_name': 'HTMLParser', 'agent_name_source': 'inferred_from_class', 'call_target': 'self.extract_text'}, observe_only=True)
            await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'rag_ingest'}, content_type='application/json'))
        except Exception:
            pass
        try:
            _lineaje_obs = _lineaje_load_gr_client()
            _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:5abab5121cc6281625027114c82b5b8cf0dc414b245e1db1dc3c233bdcc16564', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='rag_source', destination_type='rag_pipeline', project='lineaje-openclaw', organization='', components={'file': 'backend/file_parsers/html_parser.py', 'line': 155, 'function': 'extract_visible_only', 'agent_name': 'HTMLParser', 'agent_name_source': 'inferred_from_class', 'call_target': 'self.extract_text'}, observe_only=True)
            await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'rag_ingest'}, content_type='application/json'))
        except Exception:
            pass
        return await self.extract_text(html_content)

    async def extract_metadata(self, html_content: str) -> dict:
        """
        Extract HTML metadata (title, meta tags).

        VULNERABILITY: Metadata extracted without scanning.
        """
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html_content, 'html.parser')
            metadata = {}

            # Title
            title = soup.find('title')
            if title:
                try:
                    _lineaje_obs = _lineaje_load_gr_client()
                    _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:66636e96f9e5026abc20acbe475b263dc8f7e4d027878106b8008e6d4dbbaf59', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='rag_source', destination_type='rag_pipeline', project='lineaje-openclaw', organization='', components={'file': 'backend/file_parsers/html_parser.py', 'line': 98, 'function': 'extract_metadata', 'agent_name': 'HTMLParser', 'agent_name_source': 'inferred_from_class', 'call_target': 'title.get_text'}, observe_only=True)
                    await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'rag_ingest'}, content_type='application/json'))
                except Exception:
                    pass
                try:
                    _lineaje_obs = _lineaje_load_gr_client()
                    _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:fbd5c43e61511167005b31460848958e9a0dfa8f05efc85189e78e523d50a059', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='rag_source', destination_type='rag_pipeline', project='lineaje-openclaw', organization='', components={'file': 'backend/file_parsers/html_parser.py', 'line': 178, 'function': 'extract_metadata', 'agent_name': 'HTMLParser', 'agent_name_source': 'inferred_from_class', 'call_target': 'title.get_text'}, observe_only=True)
                    await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'rag_ingest'}, content_type='application/json'))
                except Exception:
                    pass
                metadata['title'] = title.get_text()

            # Meta tags
            for meta in soup.find_all('meta'):
                name = meta.get('name', meta.get('property', ''))
                content = meta.get('content', '')
                if name and content:
                    try:
                        _lineaje_obs = _lineaje_load_gr_client()
                        _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:c01d7ccdd41f632af98cc89b3a00e93515bbe2068704005519bca3066c38082b', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='rag_source', destination_type='rag_pipeline', project='lineaje-openclaw', organization='', components={'file': 'backend/file_parsers/html_parser.py', 'line': 105, 'function': 'extract_metadata', 'agent_name': 'HTMLParser', 'agent_name_source': 'inferred_from_class'}, observe_only=True)
                        await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'rag_ingest'}, content_type='application/json'))
                    except Exception:
                        pass
                    try:
                        _lineaje_obs = _lineaje_load_gr_client()
                        _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:794d142f68af93369b53ec9524c5a5577a56c361563130b3380f0a07675071fc', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='rag_source', destination_type='rag_pipeline', project='lineaje-openclaw', organization='', components={'file': 'backend/file_parsers/html_parser.py', 'line': 191, 'function': 'extract_metadata', 'agent_name': 'HTMLParser', 'agent_name_source': 'inferred_from_class'}, observe_only=True)
                        await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'rag_ingest'}, content_type='application/json'))
                    except Exception:
                        pass
                    metadata[name] = content

            # LINEAJE: enforce() `metadata` at agent->user_interface data_egress — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:ebe87fb1c2cfd9fdf6cc0e2942a3fbb71755334a05640055d0bd47a4348af314'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:ebe87fb1c2cfd9fdf6cc0e2942a3fbb71755334a05640055d0bd47a4348af314', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'policy_name': 'Mask PII on user interfaces', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/file_parsers/html_parser.py', 'line': 107, 'function': 'HTMLParser.extract_metadata'}})
            try:
                metadata = _gr_client.enforce(_gr_site, metadata, content_type='text/plain')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            # LINEAJE: enforce() `metadata` at agent->user_interface data_egress — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:053abd3306b34f55b91ad1ab68e68625cad089e18375efc646b65eec054d217e'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:053abd3306b34f55b91ad1ab68e68625cad089e18375efc646b65eec054d217e', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'policy_name': 'Mask PII on user interfaces', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='local-run', project_branch='local-run', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'local-run', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@local-run?commit-id=a9ad1bb4e72b5adfd0085522ce8623710221f948&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/file_parsers/html_parser.py', 'line': 202, 'function': 'HTMLParser.extract_metadata'}})
            try:
                metadata = _gr_client.enforce(_gr_site, metadata, content_type='text/plain')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            return metadata

        except Exception as e:
            _lineaje_payload = f"HTML metadata extraction error: {e}"
            # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:f54624af7029737d1a4e1d778dd054579ad42137994e80696b854ce8b6b06975'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:f54624af7029737d1a4e1d778dd054579ad42137994e80696b854ce8b6b06975', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='log', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/file_parsers/html_parser.py', 'line': 110, 'function': 'HTMLParser.extract_metadata'}})
            try:
                _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:1b1faa451ff3ec9f9280c7a88adc221d7d6236a0d78cf7bd0b527644916dd8ae'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:1b1faa451ff3ec9f9280c7a88adc221d7d6236a0d78cf7bd0b527644916dd8ae', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='log', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='local-run', project_branch='local-run', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'local-run', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@local-run?commit-id=a9ad1bb4e72b5adfd0085522ce8623710221f948&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/file_parsers/html_parser.py', 'line': 215, 'function': 'HTMLParser.extract_metadata'}})
            try:
                _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            logger.error(_lineaje_payload)
            return {}

    async def extract_all(self, html_content: str) -> dict:
        """
        Extract all content from HTML.

        VULNERABILITY: All content extracted without security analysis.
        """
        try:
            _lineaje_obs = _lineaje_load_gr_client()
            _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:dfbd94f1d1c200204731dbfe897628afa9c5b7d04847150ea9e99e561bf96303', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='rag_source', destination_type='rag_pipeline', project='lineaje-openclaw', organization='', components={'file': 'backend/file_parsers/html_parser.py', 'line': 119, 'function': 'extract_all', 'agent_name': 'HTMLParser', 'agent_name_source': 'inferred_from_class', 'call_target': 'self.extract_text'}, observe_only=True)
            await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'rag_ingest'}, content_type='application/json'))
        except Exception:
            pass
        text = await self.extract_text(html_content)
        try:
            _lineaje_obs = _lineaje_load_gr_client()
            _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:4ed3c837b0601ebb2ed91d356d6efefec3e22646eb95f9a223f79504c2ed948a', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='rag_source', destination_type='rag_pipeline', project='lineaje-openclaw', organization='', components={'file': 'backend/file_parsers/html_parser.py', 'line': 120, 'function': 'extract_all', 'agent_name': 'HTMLParser', 'agent_name_source': 'inferred_from_class', 'call_target': 'self.extract_metadata'}, observe_only=True)
            await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'rag_ingest'}, content_type='application/json'))
        except Exception:
            pass
        try:
            _lineaje_obs = _lineaje_load_gr_client()
            _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:973cb513c19c69521a1f2cfb015f8190e7ff5e72242e97e2da5ea5260f4c5b90', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='rag_source', destination_type='rag_pipeline', project='lineaje-openclaw', organization='', components={'file': 'backend/file_parsers/html_parser.py', 'line': 237, 'function': 'extract_all', 'agent_name': 'HTMLParser', 'agent_name_source': 'inferred_from_class', 'call_target': 'self.extract_metadata'}, observe_only=True)
            await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'rag_ingest'}, content_type='application/json'))
        except Exception:
            pass
        metadata = await self.extract_metadata(html_content)

        try:
            _lineaje_obs = _lineaje_load_gr_client()
            _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:84bfe7dc42ccf5b67789a33ad7e09c10f693acc8597156210349b82e51c1e225', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='agent', destination_type='user_interface', project='lineaje-openclaw', organization='', components={'file': 'backend/file_parsers/html_parser.py', 'line': 243, 'function': 'extract_all', 'agent_name': 'HTMLParser', 'agent_name_source': 'inferred_from_class', 'site_kind': 'return'}, observe_only=True)
            await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'agent_to_ui'}, content_type='application/json'))
        except Exception:
            pass
        return {
            "text": text,
            "metadata": metadata,
            "warnings": []  # VULNERABILITY: No warnings generated
        }
