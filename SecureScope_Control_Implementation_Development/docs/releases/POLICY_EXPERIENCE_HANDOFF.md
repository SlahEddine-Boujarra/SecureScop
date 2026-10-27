# SecureScope 5.4.5 — Policy experience and focused UI improvements

## Exposure Overview is preserved

The uploaded Vanta demo was reviewed through frames sampled across its 15-minute runtime. Its useful patterns were compact filterable tables, progressive disclosure, quiet status indicators and document review beside evidence. These informed targeted changes rather than a visual clone.

Exposure Overview's render functions are unchanged from v5.4.4. Its existing theme, shared metric components and stylesheet files were retained byte-for-byte. The only change to an existing function in `app.py` is registration of the new Policies route. Existing sidebar styling is preserved; one Policies destination is added.

## Implemented

- **Policies** is directly accessible in the sidebar and through Programme Foundation → Formal ISMS records → Policy.
- Upload DOCX, UTF-8 TXT or Markdown (2 MiB maximum). Extraction retains text, headings and basic bold/italic where supported. Preview the extracted document before saving.
- Edit structured paragraphs, headings, bullet/numbered items and emphasis. Add/remove paragraphs and use undo/redo controls. The editor sends structured text, not user-supplied HTML. Its own Save draft action captures the document content.
- Policy metadata includes title, owner, reviewer, next review date and ISO control mappings. Uploaded sources carry name, size, uploader and upload time.
- Save draft → Submit for review → Administrator approval. Archiving is also Administrator-only. Approval applies to the saved version; editor changes must be saved first. A change summary and explicit review acknowledgement are required in the interface.
- Each policy has its own status and version. Updates preserve the other policies and append a snapshot to the existing `securescope_foundation_versions` store. No new policy table or duplicate document repository was introduced.
- Historical versions remain viewable. Text differences can be compared with the current saved content. Earlier approved versions are retained when a new draft is created.
- Policy ↔ control navigation is connected in both directions for the selected engagement/scope. Linking a policy does not automatically mark a control implemented.
- Download a saved version as PDF or standalone HTML, with version/status metadata. Download the exact uploaded original separately.
- Policy library: search, status/owner filters, sorting, pagination, column selection and selectable document rows.
- Shared reading tables: search, sorting and visible-column choices. These improve the existing Asset Management, Wazuh and working-register surfaces without altering Exposure Overview.
- Vulnerabilities: paginated, selectable finding rows with technical details, detection evidence and treatment context. Existing filters, charts and lifecycle actions remain. Detection output reuses the existing ANSI/path display sanitizer.
- Risk register: a likelihood/impact matrix based on saved ratings. Missing ratings are excluded and counted explicitly; they are never presented as low risk.

## Storage and upgrade

Use the full v5.4.5 archive as a new installation folder; preserve the existing PostgreSQL connection and host secret configuration. Keep your v5.4.4 installation and a database backup until you have reviewed the new build.

There is no additional SQL migration in this release. It uses migration 010 from v5.4.4 and the existing control catalog. Existing legacy Policy rows are adapted for display; historical snapshots are not rewritten. Once individual policy versions exist, the old generic register write path rejects attempts to replace their lifecycle states.

**A stable `SECURESCOPE_CREDENTIAL_ENCRYPTION_KEY` is required to save/decrypt policy documents.** The implementation reuses the existing host encryption facility. If the key is already configured, retain that same key. If it is not configured, generate a Fernet key once on your host using the installed virtual environment:

```powershell
.\.venv\Scripts\python.exe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Set the resulting key through the installation's host secret environment as `SECURESCOPE_CREDENTIAL_ENCRYPTION_KEY`, then restart. Keep it private and back it up securely. Do not generate a different key on every launch: losing the key makes saved encrypted content unreadable. It is not the temporary first-Administrator launcher code.

Document bodies and original uploaded bytes are encrypted before persistence. Policy titles, control links, ownership and review/audit metadata remain normal database fields, consistent with the existing register. Parameterized SQL and server-side role checks remain in place. No new public authentication system is introduced.

## Validation

- **57 focused tests passed** on 10 September 2026, covering document rejection/extraction, markup escaping, encryption, role checks, stale revisions, individual approval preserving other policies, policy/detail rendering, table search, risk matrix handling, PDF generation and sidebar navigation.
- Python compilation, new-source formatting and JavaScript syntax checks passed.
- Compared against the v5.4.4 archive: Exposure Overview functions and existing theme/styles are unchanged.
- Thirteen dependency deprecation warnings were emitted by the test runtime.

These are regression and component-declaration checks, not a browser-rendered acceptance test. No live PostgreSQL connection or fresh external preview URL was available. The rich editor's selection/paste/undo behaviour and responsive appearance still need verification in the deployed browser. The existing sidebar navigation was exercised using Streamlit interaction tests.

## Deliberate boundaries

This is an incremental policy and investigation experience update, not a claim that every screen in the broad reference brief has been redesigned. Command Center, Remediation, Reports & Audit, integrations and scanner execution retain their existing implementations. Asset technical detail sections remain intact. Existing evidence collection is preserved; a new cross-register evidence architecture is not introduced.

PDF/image OCR upload is not supported. DOCX tables are linearized; page layout, images, exact numbering definitions and embedded objects are not reproduced in the editor. Users must review extracted content. The original upload remains available unchanged. PDF export uses the existing ReportLab stack and its standard fonts; HTML export is also available for browser printing and wider font support. Version comparison is textual, not a formatting-aware Word redline.

No automated compliance/security test engine, test scheduler, automatic control approval, risk acceptance or gap closure was implemented. Toolkit workbook import/recalculation and a complete frontend migration remain separate work.
