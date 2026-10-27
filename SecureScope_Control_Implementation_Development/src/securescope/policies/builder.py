"""Section-aware policy edits that preserve unchanged structured paragraphs."""

from __future__ import annotations

from securescope.policies.documents import plain_text, validate_blocks


def document_sections(blocks: list[dict]) -> list[dict]:
    """Locate sections without assuming uploaded documents use starter headings.

    Args:
        blocks: Validated policy paragraphs.
    Returns:
        Ordered section bounds, titles and editable plain text.
    Raises:
        ValueError: If document blocks are invalid.
    """
    blocks = validate_blocks(blocks)
    starts = [i for i, block in enumerate(blocks) if block["kind"].startswith("h")]
    if not starts or starts[0] != 0:
        starts.insert(0, 0)
    result = []
    for index, start in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else len(blocks)
        heading = blocks[start]["kind"].startswith("h")
        body = blocks[start + int(heading) : end]
        result.append(
            {
                "id": str(index),
                "start": start,
                "end": end,
                "heading": heading,
                "title": plain_text([blocks[start]]) if heading else "Document introduction",
                "text": plain_text(body) if body else "",
            }
        )
    return result


def apply_section_edits(blocks: list[dict], changes: dict[str, str]) -> list[dict]:
    """Replace edited section bodies and preserve headings and untouched formatting.

    Args:
        blocks: Original structured document.
        changes: Section IDs mapped to replacement text.
    Returns:
        Validated replacement document blocks.
    Raises:
        ValueError: If the resulting document exceeds content limits.
    """
    result = []
    for section in document_sections(blocks):
        text = changes.get(section["id"], section["text"])
        if text == section["text"]:
            result.extend(blocks[section["start"] : section["end"]])
            continue
        if section["heading"]:
            result.append(blocks[section["start"]])
        result.extend({"kind": "p", "runs": [{"text": line}]} for line in text.splitlines())
    return validate_blocks(result)
