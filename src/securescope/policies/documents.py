"""Bounded document extraction and escaped policy rendering."""

from __future__ import annotations

import io
from pathlib import PureWindowsPath
from zipfile import BadZipFile, ZipFile

from lxml import etree

from securescope.core.presentation import safe_text

MAX_BYTES = 2 * 1024 * 1024
MAX_TEXT = 300_000
KINDS = {"h1", "h2", "h3", "p", "bullet", "number"}


def validate_blocks(blocks: list[dict]) -> list[dict]:
    """Validate and normalize structured text without accepting HTML.

    Args:
        blocks: Paragraphs containing allowlisted kinds and text runs.
    Returns:
        Normalized blocks.
    Raises:
        ValueError: If shape or document size is invalid.
    """
    if not isinstance(blocks, list) or not 1 <= len(blocks) <= 1000:
        raise ValueError("A document must contain 1–1000 paragraphs.")
    clean = []
    total = 0
    for block in blocks:
        if not isinstance(block, dict) or block.get("kind") not in KINDS:
            raise ValueError("Unsupported paragraph type.")
        runs = block.get("runs")
        if not isinstance(runs, list) or len(runs) > 2000:
            raise ValueError("Invalid paragraph runs.")
        normalized = []
        for run in runs:
            if not isinstance(run, dict) or not isinstance(run.get("text"), str):
                raise ValueError("Text runs must contain plain text.")
            text = run["text"].replace("\x00", "")
            total += len(text)
            normalized.append(
                {"text": text, "bold": run.get("bold") is True, "italic": run.get("italic") is True}
            )
        clean.append({"kind": block["kind"], "runs": normalized})
    if total > MAX_TEXT:
        raise ValueError("Document text exceeds 300,000 characters.")
    return clean


def extract_document(name: str, content: bytes) -> dict:
    """Extract TXT, Markdown or DOCX into editable paragraphs.

    Args:
        name: Untrusted uploaded filename.
        content: Uploaded bytes, at most 2 MiB.
    Returns:
        Filename, title, blocks and extraction notes.
    Raises:
        ValueError: For malformed, unsupported or oversized documents.
    """
    name = PureWindowsPath(name).name
    suffix = PureWindowsPath(name).suffix.lower()
    if not content or len(content) > MAX_BYTES:
        raise ValueError("Upload a nonempty document no larger than 2 MiB.")
    blocks = []
    try:
        if suffix in {".txt", ".md"}:
            for line in content.decode("utf-8-sig").splitlines():
                if line.strip():
                    kind = "p"
                    for prefix, candidate in [
                        ("### ", "h3"),
                        ("## ", "h2"),
                        ("# ", "h1"),
                        ("- ", "bullet"),
                    ]:
                        if suffix == ".md" and line.startswith(prefix):
                            kind, line = candidate, line[len(prefix) :]
                            break
                    blocks.append({"kind": kind, "runs": [{"text": line}]})
        elif suffix == ".docx":
            with ZipFile(io.BytesIO(content)) as archive:
                if (
                    len(archive.infolist()) > 2000
                    or sum(item.file_size for item in archive.infolist()) > 20 * MAX_BYTES
                ):
                    raise ValueError("Expanded document exceeds the safe processing limit.")
                xml = archive.read("word/document.xml")
            parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
            root = etree.fromstring(xml, parser=parser)
            if root.getroottree().docinfo.doctype:
                raise ValueError("Document entity declarations are not supported.")
            ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
            for paragraph in root.findall(".//w:body//w:p", ns):
                style = paragraph.find("w:pPr/w:pStyle", ns)
                label = style.get("{" + ns["w"] + "}val", "").lower() if style is not None else ""
                kind = {"title": "h1", "heading1": "h1", "heading2": "h2", "heading3": "h3"}.get(
                    label, "p"
                )
                if paragraph.find("w:pPr/w:numPr", ns) is not None:
                    kind = "bullet"
                runs = []
                for run in paragraph.findall(".//w:r", ns):
                    text = "".join(run.xpath(".//w:t/text()", namespaces=ns))
                    if text:
                        runs.append(
                            {
                                "text": text,
                                "bold": run.find("w:rPr/w:b", ns) is not None,
                                "italic": run.find("w:rPr/w:i", ns) is not None,
                            }
                        )
                if runs:
                    blocks.append({"kind": kind, "runs": runs})
        else:
            raise ValueError(
                (
                    "Supported files: DOCX, UTF-8 TXT and Markdown. Convert scanned "
                    "PDFs before uploading."
                )
            )
    except (BadZipFile, KeyError, UnicodeError, etree.XMLSyntaxError) as exc:
        raise ValueError(
            "This document could not be read safely. Export a fresh DOCX or UTF-8 text file."
        ) from exc
    blocks = validate_blocks(blocks)
    title = "".join(run["text"] for run in blocks[0]["runs"])[:160]
    return {
        "filename": name,
        "title": title,
        "blocks": blocks,
        "notes": (
            "Text, headings and basic emphasis extracted. DOCX tables are "
            "linearized; images, page layout and exact list numbering require "
            "human review."
        ),
    }


def render_document(blocks: list[dict]) -> str:
    """Render allowlisted structure with every text run escaped.

    Args:
        blocks: Validated structured document.
    Returns:
        Safe HTML fragment.
    Raises:
        ValueError: For invalid blocks.
    """
    output = []
    number = 0
    for block in validate_blocks(blocks):
        kind = block["kind"]
        tag = kind if kind in {"h1", "h2", "h3", "p"} else "p"
        text = ""
        for run in block["runs"]:
            value = safe_text(run["text"]).replace("\n", "<br>")
            if run["bold"]:
                value = "<strong>" + value + "</strong>"
            if run["italic"]:
                value = "<em>" + value + "</em>"
            text += value
        number = number + 1 if kind == "number" else 0
        prefix = "• " if kind == "bullet" else f"{number}. " if kind == "number" else ""
        output.append(f"<{tag}>" + prefix + text + f"</{tag}>")
    return "\n".join(output)


def plain_text(blocks: list[dict]) -> str:
    """Return document text for comparisons.

    Args:
        blocks: Structured paragraphs.
    Returns:
        Newline-separated text.
    Raises:
        ValueError: For invalid blocks.
    """
    return "\n".join(
        "".join(run["text"] for run in block["runs"]) for block in validate_blocks(blocks)
    )
