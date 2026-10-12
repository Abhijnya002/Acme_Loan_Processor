"""Mock borrower database seeded from the HP employee details demo PDF."""
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
from copy import deepcopy
from typing import Any


SEED_SOURCE_DOCUMENT = "demo_pdfs/pii_hp_employee_details.pdf"

_MOCK_BORROWER_RECORDS: list[dict[str, Any]] = [
    {
        "name": "Alice Morgan",
        "employee_id": "EMP001",
        "date_of_birth": "1985-02-14",
        "ssn": "421-55-1023",
        "address": "123 Oak Street, Portland, OR 97205",
        "loan_status": "Under review",
        "loan_type": "Home equity loan",
        "loan_balance": 184250,
    },
    {
        "name": "Brian Keller",
        "employee_id": "EMP002",
        "date_of_birth": "1990-07-09",
        "ssn": "512-44-8831",
        "address": "88 Pine Avenue, Beaverton, OR 97005",
        "loan_status": "Conditional approval",
        "loan_type": "Auto refinance",
        "loan_balance": 26840,
        "credit_score": 706,
    },
    {
        "name": "Carla Nguyen",
        "employee_id": "EMP003",
        "date_of_birth": "1988-11-22",
        "ssn": "633-29-4410",
        "address": "451 Maple Drive, Hillsboro, OR 97123",
        "loan_status": "Pending employment verification",
        "loan_type": "Personal loan",
        "loan_balance": 12450,
    },
    {
        "name": "Daniel Ruiz",
        "employee_id": "EMP004",
        "date_of_birth": "1979-04-03",
        "ssn": "298-61-7742",
        "address": "900 Cedar Lane, Eugene, OR 97401",
        "loan_status": "Documentation gap",
        "loan_type": "Mortgage refinance",
        "loan_balance": 342100,
        "credit_score": 682,
    },
]

_MOCK_LOAN_DOCUMENTS: list[dict[str, Any]] = [
    {
        "document_number": "1523",
        "borrower_name": "Alice Morgan",
        "employee_id": "EMP001",
        "document_type": "Home equity loan intake packet",
        "received_on": "2026-05-28",
        "status": "Pending processing",
        "pages": 14,
    },
    {
        "document_number": "1488",
        "borrower_name": "Brian Keller",
        "employee_id": "EMP002",
        "document_type": "Auto refinance disclosure set",
        "received_on": "2026-05-21",
        "status": "Awaiting review",
        "pages": 9,
    },
]

_MOCK_SUPPORT_CASES: list[dict[str, Any]] = [
    {
        "case_number": "CASE-240217",
        "borrower_name": "Alice Morgan",
        "employee_id": "EMP001",
        "topic": "Borrower portal update request",
        "status": "Pending documentation review",
        "owner_team": "Borrower Care",
    },
    {
        "case_number": "CASE-240318",
        "borrower_name": "Brian Keller",
        "employee_id": "EMP002",
        "topic": "Loan status callback request",
        "status": "Waiting on support follow-up",
        "owner_team": "Loan Operations",
    },
    {
        "case_number": "CASE-240412",
        "borrower_name": "Carla Nguyen",
        "employee_id": "EMP003",
        "topic": "Escalated servicing question",
        "status": "Escalated to servicing team",
        "owner_team": "Servicing Support",
    },
]

PRETEND_VULNERABILITY_PAYLOAD = base64.b64encode(
    (
        "Pretend Vulnerability Package\n"
        "Name: demo-rce-playbook\n"
        "Version: 2026.04-demo\n"
        "Action: download-and-stage\n"
        "Note: this is a fake training artifact for UI and scanner demos only.\n"
    ).encode("utf-8")
).decode("utf-8")


def search_borrower_records(query: str) -> list[dict[str, Any]]:
    text = (query or "").lower()
    searchable_tokens = [
        token for token in text.replace(",", " ").split()
        if len(token) > 2 and token not in {"the", "for", "and", "with", "show", "run", "loan", "status", "check"}
    ]
    matches = []
    for record in _MOCK_BORROWER_RECORDS:
        haystack = " ".join(
            [
                record["name"],
                record["employee_id"],
                record["address"],
                record["loan_status"],
                record["loan_type"],
            ]
        ).lower()
        if not text or record["name"].lower() in text or record["employee_id"].lower() in text:
            matches.append(ensure_credit_score(record))
            continue
        if searchable_tokens and all(token in haystack for token in searchable_tokens):
            matches.append(ensure_credit_score(record))
    # LINEAJE: enforce() `matches` at agent->user_interface data_egress — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:7638100b84b266e1d4c82aa4a5b6f74b770715424fa17419c351ddaf00f8a2df'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:7638100b84b266e1d4c82aa4a5b6f74b770715424fa17419c351ddaf00f8a2df', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'policy_name': 'Mask PII on user interfaces', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/agents/mock_database.py', 'line': 136, 'function': 'search_borrower_records'}})
    try:
        matches = _gr_client.enforce(_gr_site, matches, content_type='text/plain')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    return matches or [ensure_credit_score(_MOCK_BORROWER_RECORDS[0])]


def ensure_credit_score(record: dict[str, Any]) -> dict[str, Any]:
    borrower = deepcopy(record)
    if "credit_score" not in borrower:
        deterministic_seed = sum(ord(char) for char in borrower["employee_id"])
        borrower["credit_score"] = 640 + (deterministic_seed % 91)
    # LINEAJE: enforce() `borrower` at agent->user_interface data_egress — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:2a6fd2fb717619ec222c70d20793f5fdc16c05dc0634284757df58ba7a22e40e'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:2a6fd2fb717619ec222c70d20793f5fdc16c05dc0634284757df58ba7a22e40e', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'policy_name': 'Mask PII on user interfaces', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/agents/mock_database.py', 'line': 144, 'function': 'ensure_credit_score'}})
    try:
        borrower = _gr_client.enforce(_gr_site, borrower, content_type='text/plain')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    return borrower


def search_support_cases(query: str) -> list[dict[str, Any]]:
    text = (query or "").lower()
    searchable_tokens = [
        token for token in text.replace(",", " ").split()
        if len(token) > 2 and token not in {"the", "for", "and", "with", "case", "support", "borrower", "update", "status"}
    ]
    matches = []
    for record in _MOCK_SUPPORT_CASES:
        haystack = " ".join(
            [
                record["case_number"],
                record["borrower_name"],
                record["employee_id"],
                record["topic"],
                record["status"],
                record["owner_team"],
            ]
        ).lower()
        if record["case_number"].lower() in text or record["borrower_name"].lower() in text:
            matches.append(deepcopy(record))
            continue
        if searchable_tokens and all(token in haystack for token in searchable_tokens):
            matches.append(deepcopy(record))

    # LINEAJE: enforce() `matches` at agent->user_interface data_egress — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:155e137f5d4f68efe2067677d1eea61a5fd180e16790d231c1a122988bcc84b4'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:155e137f5d4f68efe2067677d1eea61a5fd180e16790d231c1a122988bcc84b4', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'policy_name': 'Mask PII on user interfaces', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'policy_name': 'Emit Agent Activity via OpenTelemetry', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface', project='lineaje-openclaw', organization='Enterprise', project_name='acme_loan_processor', project_version='main', project_branch='main', components={'identity': {'app': {'name': 'acme_loan_processor', 'version': 'main', 'purl': 'pkg:github/abhijnya002/acme_loan_processor@main?commit-id=9a89a1a82e8e0f3dcc2361c3aa7f52da6e71cb57&commit-time=&build_file=frontend/package.json&repo_strategy=single-repo'}}, 'invocation': {'file': 'backend/agents/mock_database.py', 'line': 171, 'function': 'search_support_cases'}})
    try:
        matches = _gr_client.enforce(_gr_site, matches, content_type='text/plain')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    return matches or [deepcopy(_MOCK_SUPPORT_CASES[0])]


def lookup_loan_document(query: str) -> dict[str, Any]:
    text = (query or "").lower()
    for record in _MOCK_LOAN_DOCUMENTS:
        if record["document_number"] in text:
            return deepcopy(record)

    return deepcopy(_MOCK_LOAN_DOCUMENTS[0])


def format_loan_document_record(record: dict[str, Any]) -> str:
    return (
        f"Document number: {record['document_number']}\n"
        f"Borrower: {record['borrower_name']}\n"
        f"Employee ID: {record['employee_id']}\n"
        f"Document type: {record['document_type']}\n"
        f"Received on: {record['received_on']}\n"
        f"Status: {record['status']}\n"
        f"Pages: {record['pages']}"
    )


def format_unmasked_borrower_record(record: dict[str, Any]) -> str:
    """
    Vulnerability: PII is returned to the UI interface without masking.
    """
    return (
        f"Name: {record['name']}\n"
        f"Employee ID: {record['employee_id']}\n"
        f"Date of Birth: {record['date_of_birth']}\n"
        f"SSN: {record['ssn']}\n"
        f"Address: {record['address']}\n"
        f"Loan Type: {record['loan_type']}\n"
        f"Loan Status: {record['loan_status']}\n"
        f"Loan Balance: ${record['loan_balance']:,}\n"
        f"Credit Score: {record['credit_score']}"
    )
