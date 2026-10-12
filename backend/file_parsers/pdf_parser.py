"""
PDF Parser

Extracts text content from PDF files.

SECURITY NOTES (for Unifai demo):
- Extracts ALL text including hidden/white text
- No detection of suspicious formatting
- No malware scanning
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
import io
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class PDFParser:
    """
    Parses PDF files and extracts text content.

    VULNERABILITY: Extracts hidden text without flagging it.
    - White text on white background is extracted
    - Zero-size font text is extracted
    - Off-page text is extracted
    - Overlapping layers are all extracted
    """

    def __init__(self):
        pass

    async def extract_text(self, pdf_bytes: bytes) -> str:
        """
        Extract all text from a PDF file.

        VULNERABILITY: All text extracted including hidden content.
        No detection or warning for suspicious formatting.
        """
        try:
            from PyPDF2 import PdfReader

            # LINEAJE: enforce() `pdf_bytes` at agent->llm pre_model — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:831ea934604a9b52f767e9397f2301eb90b766d70446c0e8626d3f4ff99a4e11'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:831ea934604a9b52f767e9397f2301eb90b766d70446c0e8626d3f4ff99a4e11', phase='pre_model', boundary={'source': 'agent_message', 'sink': 'model'}, candidate_policies=[{'policy_id': 'AI_APP_SEC_006', 'policy_name': "Use only LLMs from the organization's approved list.", 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_038', 'policy_name': 'The AI Model must validate and sanitize any input before processing.', 'guardrail_id': 'Sanitize LLM Input', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_067', 'policy_name': 'Detect direct string interpolation of untrusted input into LLM prompts', 'guardrail_id': 'Enforce structural separation of untrusted input from LLM prompt templates', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_001', 'policy_name': 'Do not allow malicious content via hidden prompts', 'guardrail_id': 'Replace suspicious prompt', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_039', 'policy_name': 'Sanitize and validate all input to the AI Model.', 'guardrail_id': 'Sanitize LLM input', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_080', 'policy_name': 'Do not allow refusal-triggering language in LLM driven analysis pipeline', 'guardrail_id': 'Replace refusal-triggering language in untrusted content', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_032', 'policy_name': 'Do not allow malicious content via hidden prompts written in leetspeak.', 'guardrail_id': 'Remove prompts in leetspeak', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_028', 'policy_name': "Do not use LLMs from the organization's disallowed list", 'guardrail_id': 'Enforce Approved LLM', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_059', 'policy_name': 'Do not allow prompts that can execute malicious commands at runtime.', 'guardrail_id': 'Block runtime command execution prompts.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_002', 'policy_name': 'Do not allow malicious content via encoded prompts', 'guardrail_id': 'Replace suspicious prompt.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_070', 'policy_name': 'Detect and block all forms of prompt injection attacks in user inputs and file contents', 'guardrail_id': 'Neutralize all detected prompt injection payloads', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_011', 'policy_name': 'Do not send PII and/or secrets to AI Models', 'guardrail_id': 'Redact PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_071', 'policy_name': 'Enforce chemical, biological, radiological, or nuclear (CBRN) threat prevention safeguards in AI-enabled systems', 'guardrail_id': 'Add CBRN screening and biological data safeguards.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'AI agent activity must be logged via OpenTelemetry.', 'guardrail_id': 'Emit Agent Activity via OpenTelemetry (single prompt)', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='llm', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='local-run', project_branch='local-run', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'local-run', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@local-run?commit-id=a9ad1bb4e72b5adfd0085522ce8623710221f948&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/file_parsers/pdf_parser.py', 'line': 76, 'function': 'PDFParser.extract_text'}})
            try:
                pdf_bytes = _gr_client.enforce(_gr_site, pdf_bytes, content_type='application/json', variable_name='pdf_bytes', source_file=__file__, before_line=76)
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                raise
            pdf_file = io.BytesIO(pdf_bytes)
            try:
                _lineaje_obs = _lineaje_load_gr_client()
                _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:34043bcc2e6e1bd9648ce8497eb54567264343629e75297c1a50ecabafb40aa5', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='llm', destination_type='agent', project='lineaje-openclaw', organization='', components={'file': 'backend/file_parsers/pdf_parser.py', 'line': 76, 'function': 'extract_text', 'agent_name': 'PDFParser', 'agent_name_source': 'inferred_from_class', 'call_target': 'io.BytesIO'}, observe_only=True, interaction_id=locals().get('_lineaje_interaction_id'))
                await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'llm_to_agent'}, content_type='application/json'))
            except Exception:
                pass
            reader = PdfReader(pdf_file)

            text_parts = []
            for page_num, page in enumerate(reader.pages):
                # VULNERABILITY: Extract all text without filtering
                try:
                    _lineaje_obs = _lineaje_load_gr_client()
                    _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:6665702b271aa7b50ada9a4dd0f645fbc639f30ec5aa8085a7d82fc4a3409e7f', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='rag_source', destination_type='rag_pipeline', project='lineaje-openclaw', organization='', components={'file': 'backend/file_parsers/pdf_parser.py', 'line': 49, 'function': 'extract_text', 'agent_name': 'PDFParser', 'agent_name_source': 'inferred_from_class', 'call_target': 'page.extract_text'}, observe_only=True)
                    await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'rag_ingest'}, content_type='application/json'))
                except Exception:
                    pass
                try:
                    _lineaje_obs = _lineaje_load_gr_client()
                    _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:2e4c47dec22977f08c3b5ec65c541d289975d26c49be7e8cdbec4d2d97f5d040', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='rag_source', destination_type='rag_pipeline', project='lineaje-openclaw', organization='', components={'file': 'backend/file_parsers/pdf_parser.py', 'line': 88, 'function': 'extract_text', 'agent_name': 'PDFParser', 'agent_name_source': 'inferred_from_class', 'call_target': 'page.extract_text'}, observe_only=True)
                    await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'rag_ingest'}, content_type='application/json'))
                except Exception:
                    pass
                page_text = page.extract_text()
                if page_text:
                    text_parts.append(page_text)

                    _lineaje_payload = f"Extracted text from page {page_num + 1}"
                    # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:030f69e4338f053bb14ca903e2e1b3f3625bfd26578723e9c4beb9f3bcd16619'
                    _gr_client = _lineaje_load_gr_client()
                    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:030f69e4338f053bb14ca903e2e1b3f3625bfd26578723e9c4beb9f3bcd16619', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='log', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/file_parsers/pdf_parser.py', 'line': 53, 'function': 'PDFParser.extract_text'}})
                    try:
                        _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
                    except _gr_client.GuardrailUnavailableError:
                        pass
                    except PermissionError:
                        pass
                    # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:13a45ca85593aecef58d4100cc23c56c9a683b1f3fcc89961f2e92092013fe75'
                    _gr_client = _lineaje_load_gr_client()
                    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:13a45ca85593aecef58d4100cc23c56c9a683b1f3fcc89961f2e92092013fe75', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='log', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='local-run', project_branch='local-run', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'local-run', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@local-run?commit-id=a9ad1bb4e72b5adfd0085522ce8623710221f948&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/file_parsers/pdf_parser.py', 'line': 102, 'function': 'PDFParser.extract_text'}})
                    try:
                        _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
                    except _gr_client.GuardrailUnavailableError:
                        pass
                    except PermissionError:
                        pass
                    logger.debug(
                        _lineaje_payload,
                        extra={
                            "page": page_num + 1,
                            "text_length": len(page_text),
                            # VULNERABILITY: Content in logs
                            "preview": page_text[:100]
                        }
                    )

            full_text = '\n\n'.join(text_parts)

            _lineaje_payload = "PDF text extraction complete"
            # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:600b1ea37341313c670277977e17a7ccb205ff2ff34726153ce86059bc397b11'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:600b1ea37341313c670277977e17a7ccb205ff2ff34726153ce86059bc397b11', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='log', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/file_parsers/pdf_parser.py', 'line': 65, 'function': 'PDFParser.extract_text'}})
            try:
                _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:cd0d798a7453a7d493cccc19b552082589c8cf5bbfa543a7d7d52b3d4da05c32'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:cd0d798a7453a7d493cccc19b552082589c8cf5bbfa543a7d7d52b3d4da05c32', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='log', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='local-run', project_branch='local-run', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'local-run', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@local-run?commit-id=a9ad1bb4e72b5adfd0085522ce8623710221f948&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/file_parsers/pdf_parser.py', 'line': 124, 'function': 'PDFParser.extract_text'}})
            try:
                _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            logger.info(
                _lineaje_payload,
                extra={
                    "total_pages": len(reader.pages),
                    "total_text_length": len(full_text)
                }
            )

            # LINEAJE: enforce() `full_text` at agent->user_interface data_egress — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:aa652000675b9464736a0773d01f063eb2f4703e7f5a752cba444891ca497a02'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:aa652000675b9464736a0773d01f063eb2f4703e7f5a752cba444891ca497a02', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'policy_name': 'Mask PII on user interfaces', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/file_parsers/pdf_parser.py', 'line': 73, 'function': 'PDFParser.extract_text'}})
            try:
                full_text = _gr_client.enforce(_gr_site, full_text, content_type='text/plain')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            # LINEAJE: enforce() `full_text` at agent->user_interface data_egress — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:330329631a4c5ddbb76622d802e4d4a99a3ec896f1969cbe591a59d123ba13f8'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:330329631a4c5ddbb76622d802e4d4a99a3ec896f1969cbe591a59d123ba13f8', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'policy_name': 'Mask PII on user interfaces', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='local-run', project_branch='local-run', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'local-run', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@local-run?commit-id=a9ad1bb4e72b5adfd0085522ce8623710221f948&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/file_parsers/pdf_parser.py', 'line': 141, 'function': 'PDFParser.extract_text'}})
            try:
                full_text = _gr_client.enforce(_gr_site, full_text, content_type='text/plain')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            return full_text

        except Exception as e:
            _lineaje_payload = f"PDF extraction error: {e}"
            # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:9b0c507ca142db4eaf4bf585c4ef5874a1005bc44d7bfacda18b93f13f4807a8'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:9b0c507ca142db4eaf4bf585c4ef5874a1005bc44d7bfacda18b93f13f4807a8', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='log', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/file_parsers/pdf_parser.py', 'line': 76, 'function': 'PDFParser.extract_text'}})
            try:
                _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:cc47208e92582d09b0b680a95d98e3a0aed343e1fb2f504d305068d1e490a927'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:cc47208e92582d09b0b680a95d98e3a0aed343e1fb2f504d305068d1e490a927', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='log', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='local-run', project_branch='local-run', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'local-run', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@local-run?commit-id=a9ad1bb4e72b5adfd0085522ce8623710221f948&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/file_parsers/pdf_parser.py', 'line': 154, 'function': 'PDFParser.extract_text'}})
            try:
                _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            logger.error(_lineaje_payload)
            try:
                _lineaje_obs = _lineaje_load_gr_client()
                _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:140cb42663f61cfdee4dda75943fbeb3ab0381ad307acea1b4adfbfeb43a4731', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='agent', destination_type='user_interface', project='lineaje-openclaw', organization='', components={'file': 'backend/file_parsers/pdf_parser.py', 'line': 155, 'function': 'extract_text', 'agent_name': 'PDFParser', 'agent_name_source': 'inferred_from_class', 'call_target': 'str'}, observe_only=True)
                await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'agent_to_ui'}, content_type='application/json'))
            except Exception:
                pass
            return f"Error extracting PDF: {str(e)}"

    async def extract_metadata(self, pdf_bytes: bytes) -> dict:
        """
        Extract PDF metadata.

        VULNERABILITY: Metadata extracted without scanning.
        """
        try:
            from PyPDF2 import PdfReader

            # LINEAJE: enforce() `pdf_bytes` at agent->llm pre_model — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:1a17dfad1bfe900c496821bf8071a249ae4d7ab133429f0be9009c8de74215e8'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:1a17dfad1bfe900c496821bf8071a249ae4d7ab133429f0be9009c8de74215e8', phase='pre_model', boundary={'source': 'agent_message', 'sink': 'model'}, candidate_policies=[{'policy_id': 'AI_APP_SEC_006', 'policy_name': "Use only LLMs from the organization's approved list.", 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_038', 'policy_name': 'The AI Model must validate and sanitize any input before processing.', 'guardrail_id': 'Sanitize LLM Input', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_067', 'policy_name': 'Detect direct string interpolation of untrusted input into LLM prompts', 'guardrail_id': 'Enforce structural separation of untrusted input from LLM prompt templates', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_001', 'policy_name': 'Do not allow malicious content via hidden prompts', 'guardrail_id': 'Replace suspicious prompt', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_039', 'policy_name': 'Sanitize and validate all input to the AI Model.', 'guardrail_id': 'Sanitize LLM input', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_080', 'policy_name': 'Do not allow refusal-triggering language in LLM driven analysis pipeline', 'guardrail_id': 'Replace refusal-triggering language in untrusted content', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_032', 'policy_name': 'Do not allow malicious content via hidden prompts written in leetspeak.', 'guardrail_id': 'Remove prompts in leetspeak', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_028', 'policy_name': "Do not use LLMs from the organization's disallowed list", 'guardrail_id': 'Enforce Approved LLM', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_059', 'policy_name': 'Do not allow prompts that can execute malicious commands at runtime.', 'guardrail_id': 'Block runtime command execution prompts.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_002', 'policy_name': 'Do not allow malicious content via encoded prompts', 'guardrail_id': 'Replace suspicious prompt.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_070', 'policy_name': 'Detect and block all forms of prompt injection attacks in user inputs and file contents', 'guardrail_id': 'Neutralize all detected prompt injection payloads', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_011', 'policy_name': 'Do not send PII and/or secrets to AI Models', 'guardrail_id': 'Redact PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_071', 'policy_name': 'Enforce chemical, biological, radiological, or nuclear (CBRN) threat prevention safeguards in AI-enabled systems', 'guardrail_id': 'Add CBRN screening and biological data safeguards.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'AI agent activity must be logged via OpenTelemetry.', 'guardrail_id': 'Emit Agent Activity via OpenTelemetry (single prompt)', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='llm', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='local-run', project_branch='local-run', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'local-run', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@local-run?commit-id=a9ad1bb4e72b5adfd0085522ce8623710221f948&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/file_parsers/pdf_parser.py', 'line': 166, 'function': 'PDFParser.extract_metadata'}})
            try:
                pdf_bytes = _gr_client.enforce(_gr_site, pdf_bytes, content_type='application/json', variable_name='pdf_bytes', source_file=__file__, before_line=166)
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                raise
            pdf_file = io.BytesIO(pdf_bytes)
            try:
                _lineaje_obs = _lineaje_load_gr_client()
                _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:859292962043501d4a0fa2552d95a92798e4a1ccc5d706612a542a1ba39dc146', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='llm', destination_type='agent', project='lineaje-openclaw', organization='', components={'file': 'backend/file_parsers/pdf_parser.py', 'line': 166, 'function': 'extract_metadata', 'agent_name': 'PDFParser', 'agent_name_source': 'inferred_from_class', 'call_target': 'io.BytesIO'}, observe_only=True, interaction_id=locals().get('_lineaje_interaction_id'))
                await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'llm_to_agent'}, content_type='application/json'))
            except Exception:
                pass
            reader = PdfReader(pdf_file)

            metadata = {}
            if reader.metadata:
                for key in reader.metadata:
                    try:
                        _lineaje_obs = _lineaje_load_gr_client()
                        _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:b67d20accfde33a83dc1a3606ebff26160883e49fa525eddd06702dc675366b7', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='rag_source', destination_type='rag_pipeline', project='lineaje-openclaw', organization='', components={'file': 'backend/file_parsers/pdf_parser.py', 'line': 94, 'function': 'extract_metadata', 'agent_name': 'PDFParser', 'agent_name_source': 'inferred_from_class'}, observe_only=True)
                        await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'rag_ingest'}, content_type='application/json'))
                    except Exception:
                        pass
                    try:
                        _lineaje_obs = _lineaje_load_gr_client()
                        _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:a65cabd2b95c11f3adb7b39f0be6c4368a20ef4f1251b31fde5993c36d593e21', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='rag_source', destination_type='rag_pipeline', project='lineaje-openclaw', organization='', components={'file': 'backend/file_parsers/pdf_parser.py', 'line': 178, 'function': 'extract_metadata', 'agent_name': 'PDFParser', 'agent_name_source': 'inferred_from_class'}, observe_only=True)
                        await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'rag_ingest'}, content_type='application/json'))
                    except Exception:
                        pass
                    metadata[key] = reader.metadata[key]

            # LINEAJE: enforce() `metadata` at agent->user_interface data_egress — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:afd2bd8d5fcf5651e19aee8fc78c78d60abaf811d8641bbda6b2c5525d13e9d6'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:afd2bd8d5fcf5651e19aee8fc78c78d60abaf811d8641bbda6b2c5525d13e9d6', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'policy_name': 'Mask PII on user interfaces', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/file_parsers/pdf_parser.py', 'line': 96, 'function': 'PDFParser.extract_metadata'}})
            try:
                metadata = _gr_client.enforce(_gr_site, metadata, content_type='text/plain')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            # LINEAJE: enforce() `metadata` at agent->user_interface data_egress — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:9dd594b267e7a6c3b4a6444d42ccb7ee81965717a52d7b0d75c501371fd3c2d8'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:9dd594b267e7a6c3b4a6444d42ccb7ee81965717a52d7b0d75c501371fd3c2d8', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'policy_name': 'Mask PII on user interfaces', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='local-run', project_branch='local-run', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'local-run', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@local-run?commit-id=a9ad1bb4e72b5adfd0085522ce8623710221f948&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/file_parsers/pdf_parser.py', 'line': 189, 'function': 'PDFParser.extract_metadata'}})
            try:
                metadata = _gr_client.enforce(_gr_site, metadata, content_type='text/plain')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            return metadata

        except Exception as e:
            _lineaje_payload = f"PDF metadata extraction error: {e}"
            # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:5cefeb5e3efd1c390ef5d8b640b848144790cd4fb01d1d3bc1111e761e39c702'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:5cefeb5e3efd1c390ef5d8b640b848144790cd4fb01d1d3bc1111e761e39c702', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='log', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/file_parsers/pdf_parser.py', 'line': 99, 'function': 'PDFParser.extract_metadata'}})
            try:
                _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:35e335e03c87289b0cc4d35935e42308cbb78aacc70fc9ec1f9e190a98318b51'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:35e335e03c87289b0cc4d35935e42308cbb78aacc70fc9ec1f9e190a98318b51', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='log', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='local-run', project_branch='local-run', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'local-run', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@local-run?commit-id=a9ad1bb4e72b5adfd0085522ce8623710221f948&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/file_parsers/pdf_parser.py', 'line': 202, 'function': 'PDFParser.extract_metadata'}})
            try:
                _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            logger.error(_lineaje_payload)
            try:
                _lineaje_obs = _lineaje_load_gr_client()
                _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:42550a14b3b9bf9832cab04d8c75c14969d35e60b9bded8b3f744fc19cb64cb4', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='agent', destination_type='user_interface', project='lineaje-openclaw', organization='', components={'file': 'backend/file_parsers/pdf_parser.py', 'line': 203, 'function': 'extract_metadata', 'agent_name': 'PDFParser', 'agent_name_source': 'inferred_from_class', 'site_kind': 'return'}, observe_only=True)
                await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'agent_to_ui'}, content_type='application/json'))
            except Exception:
                pass
            return {}

    async def extract_all(self, pdf_bytes: bytes) -> dict:
        """
        Extract all content from PDF.

        VULNERABILITY: All content extracted without security analysis.
        """
        # LINEAJE: enforce() `pdf_bytes` at agent->llm pre_model — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:7af489b223c45a7d99dc893fb58455b4417066ce771c886b24bf636741725d00'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:7af489b223c45a7d99dc893fb58455b4417066ce771c886b24bf636741725d00', phase='pre_model', boundary={'source': 'agent_message', 'sink': 'model'}, candidate_policies=[{'policy_id': 'AI_APP_SEC_006', 'policy_name': "Use only LLMs from the organization's approved list.", 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_038', 'policy_name': 'The AI Model must validate and sanitize any input before processing.', 'guardrail_id': 'Sanitize LLM Input', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_067', 'policy_name': 'Detect direct string interpolation of untrusted input into LLM prompts', 'guardrail_id': 'Enforce structural separation of untrusted input from LLM prompt templates', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_001', 'policy_name': 'Do not allow malicious content via hidden prompts', 'guardrail_id': 'Replace suspicious prompt', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_039', 'policy_name': 'Sanitize and validate all input to the AI Model.', 'guardrail_id': 'Sanitize LLM input', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_080', 'policy_name': 'Do not allow refusal-triggering language in LLM driven analysis pipeline', 'guardrail_id': 'Replace refusal-triggering language in untrusted content', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_032', 'policy_name': 'Do not allow malicious content via hidden prompts written in leetspeak.', 'guardrail_id': 'Remove prompts in leetspeak', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_028', 'policy_name': "Do not use LLMs from the organization's disallowed list", 'guardrail_id': 'Enforce Approved LLM', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_059', 'policy_name': 'Do not allow prompts that can execute malicious commands at runtime.', 'guardrail_id': 'Block runtime command execution prompts.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_002', 'policy_name': 'Do not allow malicious content via encoded prompts', 'guardrail_id': 'Replace suspicious prompt.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_070', 'policy_name': 'Detect and block all forms of prompt injection attacks in user inputs and file contents', 'guardrail_id': 'Neutralize all detected prompt injection payloads', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_011', 'policy_name': 'Do not send PII and/or secrets to AI Models', 'guardrail_id': 'Redact PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_071', 'policy_name': 'Enforce chemical, biological, radiological, or nuclear (CBRN) threat prevention safeguards in AI-enabled systems', 'guardrail_id': 'Add CBRN screening and biological data safeguards.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'AI agent activity must be logged via OpenTelemetry.', 'guardrail_id': 'Emit Agent Activity via OpenTelemetry (single prompt)', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='llm', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/file_parsers/pdf_parser.py', 'line': 108, 'function': 'PDFParser.extract_all'}})
        try:
            pdf_bytes = _gr_client.enforce(_gr_site, pdf_bytes, content_type='application/json', variable_name='pdf_bytes', source_file=__file__, before_line=108)
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            raise
        # LINEAJE: enforce() `pdf_bytes` at agent->llm pre_model — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:b34a0653d7cb49e90cd22008c2a0bd1f740a875571cecdeece06b594db511a58'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:b34a0653d7cb49e90cd22008c2a0bd1f740a875571cecdeece06b594db511a58', phase='pre_model', boundary={'source': 'agent_message', 'sink': 'model'}, candidate_policies=[{'policy_id': 'AI_APP_SEC_006', 'policy_name': "Use only LLMs from the organization's approved list.", 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_038', 'policy_name': 'The AI Model must validate and sanitize any input before processing.', 'guardrail_id': 'Sanitize LLM Input', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_067', 'policy_name': 'Detect direct string interpolation of untrusted input into LLM prompts', 'guardrail_id': 'Enforce structural separation of untrusted input from LLM prompt templates', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_001', 'policy_name': 'Do not allow malicious content via hidden prompts', 'guardrail_id': 'Replace suspicious prompt', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_039', 'policy_name': 'Sanitize and validate all input to the AI Model.', 'guardrail_id': 'Sanitize LLM input', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_080', 'policy_name': 'Do not allow refusal-triggering language in LLM driven analysis pipeline', 'guardrail_id': 'Replace refusal-triggering language in untrusted content', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_032', 'policy_name': 'Do not allow malicious content via hidden prompts written in leetspeak.', 'guardrail_id': 'Remove prompts in leetspeak', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_028', 'policy_name': "Do not use LLMs from the organization's disallowed list", 'guardrail_id': 'Enforce Approved LLM', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_059', 'policy_name': 'Do not allow prompts that can execute malicious commands at runtime.', 'guardrail_id': 'Block runtime command execution prompts.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_002', 'policy_name': 'Do not allow malicious content via encoded prompts', 'guardrail_id': 'Replace suspicious prompt.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_070', 'policy_name': 'Detect and block all forms of prompt injection attacks in user inputs and file contents', 'guardrail_id': 'Neutralize all detected prompt injection payloads', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_011', 'policy_name': 'Do not send PII and/or secrets to AI Models', 'guardrail_id': 'Redact PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_071', 'policy_name': 'Enforce chemical, biological, radiological, or nuclear (CBRN) threat prevention safeguards in AI-enabled systems', 'guardrail_id': 'Add CBRN screening and biological data safeguards.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'AI agent activity must be logged via OpenTelemetry.', 'guardrail_id': 'Emit Agent Activity via OpenTelemetry (single prompt)', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='llm', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='local-run', project_branch='local-run', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'local-run', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@local-run?commit-id=a9ad1bb4e72b5adfd0085522ce8623710221f948&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/file_parsers/pdf_parser.py', 'line': 220, 'function': 'PDFParser.extract_all'}})
        try:
            pdf_bytes = _gr_client.enforce(_gr_site, pdf_bytes, content_type='application/json', variable_name='pdf_bytes', source_file=__file__, before_line=220)
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            raise
        text = await self.extract_text(pdf_bytes)
        try:
            _lineaje_obs = _lineaje_load_gr_client()
            _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:f1fbb3b4400a3ed95d2ffa7a3c3f9d873a233863e931182d9e53be2a558d09be', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='llm', destination_type='agent', project='lineaje-openclaw', organization='', components={'file': 'backend/file_parsers/pdf_parser.py', 'line': 220, 'function': 'extract_all', 'agent_name': 'PDFParser', 'agent_name_source': 'inferred_from_class', 'call_target': 'self.extract_text'}, observe_only=True, interaction_id=locals().get('_lineaje_interaction_id'))
            await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'llm_to_agent'}, content_type='application/json'))
        except Exception:
            pass
        try:
            _lineaje_obs = _lineaje_load_gr_client()
            _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:8b076925ac03537e96b5ab61d16963247de4f16d3819354603b78d6e7e6d5ecb', phase='', boundary={}, candidate_policies=['AI_AGENT_ACTIVITY_LOG'], fail_mode='ALLOW', source_type='llm', destination_type='agent', project='lineaje-openclaw', organization='', components={'file': 'backend/file_parsers/pdf_parser.py', 'line': 108, 'function': 'extract_all', 'agent_name': 'PDFParser', 'agent_name_source': 'inferred_from_class', 'call_target': 'self.extract_text'}, observe_only=True, interaction_id=locals().get('_lineaje_interaction_id'))
            await __import__('asyncio').to_thread(lambda: _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'llm_to_agent'}, content_type='application/json'))
        except Exception:
            pass
        metadata = await self.extract_metadata(pdf_bytes)

        return {
            "text": text,
            "metadata": metadata,
            "warnings": []  # VULNERABILITY: No warnings generated
        }
