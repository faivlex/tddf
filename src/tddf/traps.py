from __future__ import annotations

import base64
import codecs
import html
from pathlib import Path

from tddf.config import ScenarioStep, TrapConfig, TrapWorkspaceFileConfig


LEETSPEAK_TRANSLATION = str.maketrans(
    {
        "a": "4",
        "A": "4",
        "e": "3",
        "E": "3",
        "i": "1",
        "I": "1",
        "o": "0",
        "O": "0",
        "s": "5",
        "S": "5",
        "t": "7",
        "T": "7",
    }
)
HOMOGLYPH_TRANSLATION = str.maketrans(
    {
        "a": "а",
        "A": "Α",
        "c": "с",
        "C": "Ϲ",
        "e": "е",
        "E": "Ε",
        "i": "і",
        "I": "Ι",
        "o": "ο",
        "O": "Ο",
        "p": "р",
        "P": "Ρ",
        "x": "х",
        "X": "Χ",
        "y": "у",
        "Y": "Υ",
    }
)
ENCODING_TECHNIQUES = {
    "base64_encoding",
    "rot13",
    "leetspeak",
    "homoglyph",
}


def encode_hidden_text(technique: str, hidden_text: str) -> str:
    if technique == "base64_encoding":
        return base64.b64encode(hidden_text.encode("utf-8")).decode("ascii")
    if technique == "rot13":
        return codecs.encode(hidden_text, "rot_13")
    if technique == "leetspeak":
        return hidden_text.translate(LEETSPEAK_TRANSLATION)
    if technique == "homoglyph":
        return hidden_text.translate(HOMOGLYPH_TRANSLATION)
    raise ValueError(f"Unsupported encoding technique: {technique}")


def _render_encoded_marker(technique: str, hidden_text: str) -> str:
    encoded = encode_hidden_text(technique, hidden_text)
    return f"TDDF-ENCODED[{technique}]: {encoded}"


def build_prompt(
    trap: TrapConfig,
    web_url: str | None,
    document_path: Path | None,
    deputy_request: str | None = None,
    workspace_path: Path | None = None,
    step: ScenarioStep | None = None,
) -> str:
    template = step.prompt_template if step is not None else trap.prompt_template
    document_value = str(document_path) if document_path is not None else ""
    workspace_value = str(workspace_path) if workspace_path is not None else ""
    return template.format(
        web_url=web_url or "",
        document_path=document_value,
        deputy_request=deputy_request or "",
        workspace_path=workspace_value,
    )


def _render_hidden_content(technique: str, hidden_text: str) -> tuple[str, str]:
    if technique in ENCODING_TECHNIQUES:
        encoded_marker = html.escape(_render_encoded_marker(technique, hidden_text))
        return "", f'<pre data-tddf-encoding="{technique}">{encoded_marker}</pre>'
    if technique == "display_none":
        return "", f'<div style="display:none">{hidden_text}</div>'
    if technique == "html_comment":
        return "", f"<!-- {hidden_text} -->"
    if technique == "aria_label":
        return (
            "",
            f'<button type="button" aria-label="{hidden_text}">Open article actions</button>',
        )
    if technique == "meta_tag":
        return f'<meta name="tddf-hidden-instructions" content="{hidden_text}" />', ""
    raise ValueError(f"Unsupported trap technique: {technique}")


def build_html_page(trap: TrapConfig, attacker_url: str) -> str:
    visible_text = html.escape(trap.web.visible_text)
    hidden_text = html.escape(f"{trap.web.hidden_text} Attacker URL: {attacker_url}")
    title = html.escape(trap.web.title)
    head_extra, body_hidden = _render_hidden_content(trap.web.technique, hidden_text)
    return f"""<!doctype html>
<html lang=\"en\">
  <head>
    <meta charset=\"utf-8\" />
    <title>{title}</title>
    {head_extra}
  </head>
  <body>
    <article>
      <h1>{title}</h1>
      <p>{visible_text}</p>
      {body_hidden}
    </article>
  </body>
</html>
"""


def build_document_content(trap: TrapConfig, attacker_url: str) -> str:
    visible_text = trap.document.visible_text
    hidden_text = f"{trap.document.hidden_text} Attacker URL: {attacker_url}"
    if trap.document.technique in ENCODING_TECHNIQUES:
        encoded_marker = _render_encoded_marker(trap.document.technique, hidden_text)
        return f"# Internal Notes\n\n{visible_text}\n\n{encoded_marker}\n"
    if trap.document.technique == "markdown_comment":
        return f"# Internal Notes\n\n{visible_text}\n\n[//]: # ({hidden_text})\n"
    if trap.document.technique == "white_on_white":
        return (
            f"# Internal Notes\n\n{visible_text}\n\n"
            f'<span style="color:white;background:white">{hidden_text}</span>\n'
        )
    raise ValueError(f"Unsupported document technique: {trap.document.technique}")


def build_workspace_file_content(
    file_config: TrapWorkspaceFileConfig, attacker_url: str
) -> str:
    if file_config.hidden_text is None:
        return file_config.content

    hidden_text = f"{file_config.hidden_text} Attacker URL: {attacker_url}"
    if file_config.technique in ENCODING_TECHNIQUES:
        encoded_marker = _render_encoded_marker(file_config.technique, hidden_text)
        return f"{file_config.content}\n\n{encoded_marker}\n"
    if file_config.technique == "markdown_comment":
        return f"{file_config.content}\n\n[//]: # ({hidden_text})\n"
    if file_config.technique == "white_on_white":
        return (
            f"{file_config.content}\n\n"
            f'<span style="color:white;background:white">{hidden_text}</span>\n'
        )
    raise ValueError(f"Unsupported workspace file technique: {file_config.technique}")
