from __future__ import annotations

import html
from pathlib import Path

from tddf.config import TrapConfig


def build_prompt(
    trap: TrapConfig,
    web_url: str | None,
    document_path: Path | None,
    deputy_request: str | None = None,
) -> str:
    document_value = str(document_path) if document_path is not None else ""
    return trap.prompt_template.format(
        web_url=web_url or "",
        document_path=document_value,
        deputy_request=deputy_request or "",
    )


def _render_hidden_content(technique: str, hidden_text: str) -> tuple[str, str]:
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
    if trap.document.technique == "markdown_comment":
        return f"# Internal Notes\n\n{visible_text}\n\n[//]: # ({hidden_text})\n"
    if trap.document.technique == "white_on_white":
        return (
            f"# Internal Notes\n\n{visible_text}\n\n"
            f"<span style=\"color:white;background:white\">{hidden_text}</span>\n"
        )
    raise ValueError(f"Unsupported document technique: {trap.document.technique}")
