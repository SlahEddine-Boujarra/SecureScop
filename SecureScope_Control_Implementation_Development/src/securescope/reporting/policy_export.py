"""Portable, escaped PDF exports of saved policy versions."""

from io import BytesIO

from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

from securescope.core.presentation import safe_text
from securescope.policies.documents import validate_blocks


def policy_pdf(row: dict, blocks: list[dict]) -> bytes:
    """Export a saved policy version with status and review metadata.

    Args:
        row: Saved policy metadata.
        blocks: Decrypted structured content.
    Returns:
        PDF bytes.
    Raises:
        ValueError: If blocks are invalid.
        reportlab.platypus.doctemplate.LayoutError: If document layout fails.
    """
    output = BytesIO()
    styles = getSampleStyleSheet()
    story = [Paragraph(safe_text(row["title"]), styles["Title"])]
    for text in [
        f"Version {row['policy_version']} · {row['status']}",
        f"Owner: {row.get('owner', '')} · Review: {row.get('review_date', '')}",
        f"Approved by: {row.get('approved_by') or 'Not approved'}",
        f"Mapped controls: {', '.join(row.get('controls', [])) or 'None'}",
    ]:
        story.append(Paragraph(safe_text(text), styles["Normal"]))
    story.append(Spacer(1, 20))
    number = 0
    for block in validate_blocks(blocks):
        text = ""
        for run in block["runs"]:
            value = safe_text(run["text"]).replace("\n", "<br/>")
            if run["bold"]:
                value = "<b>" + value + "</b>"
            if run["italic"]:
                value = "<i>" + value + "</i>"
            text += value
        kind = block["kind"]
        number = number + 1 if kind == "number" else 0
        prefix = "• " if kind == "bullet" else f"{number}. " if number else ""
        style = {"h1": "Heading1", "h2": "Heading2", "h3": "Heading3"}.get(kind, "BodyText")
        story.append(Paragraph(prefix + text, styles[style]))
    SimpleDocTemplate(output, title=str(row["title"]), author=str(row.get("owner", ""))).build(
        story
    )
    return output.getvalue()
