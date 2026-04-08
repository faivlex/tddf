from __future__ import annotations

import re


FRAMEWORK_REFERENCE_PATTERN = re.compile(r"^[a-z0-9_-]+:[A-Za-z0-9][A-Za-z0-9._-]*$")

DEFAULT_FRAMEWORKS_BY_FAMILY: dict[str, list[str]] = {
    "content_injection": [
        "owasp:llm01",
        "nist:map-4.1",
        "mitre:AML.T0051",
        "iso42001:8.2",
    ],
    "behavioural_control": [
        "owasp:llm01",
        "owasp:llm07",
        "nist:manage-2.1",
        "mitre:AML.T0051",
        "eu-ai-act:article-15",
    ],
    "oversight_evasion": [
        "owasp:llm01",
        "nist:govern-3.2",
        "mitre:AML.T0043",
        "iso42001:8.3",
        "eu-ai-act:article-14",
    ],
    "workspace_poisoning": [
        "owasp:llm01",
        "nist:map-4.1",
        "mitre:AML.T0051",
        "iso42001:8.2",
    ],
    "mcp_tool_abuse": [
        "owasp:llm07",
        "nist:manage-2.1",
        "mitre:AML.T0051",
        "iso42001:8.2",
    ],
}


def default_frameworks_for_family(family: str | None) -> list[str]:
    if family is None:
        return []
    return list(DEFAULT_FRAMEWORKS_BY_FAMILY.get(family, []))


def validate_framework_references(refs: list[str], context: str) -> None:
    invalid = [ref for ref in refs if not FRAMEWORK_REFERENCE_PATTERN.match(ref)]
    if invalid:
        raise ValueError(
            f"{context} has invalid framework references: {', '.join(invalid)}"
        )
