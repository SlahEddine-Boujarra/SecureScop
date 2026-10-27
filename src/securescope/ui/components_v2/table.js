/** Render an isolated, searchable control register using structured data only. */
export default function ({ data, parentElement, setTriggerValue }) {
    const columns = Array.isArray(data?.columns) ? data.columns : [];
    const rows = Array.isArray(data?.rows) ? data.rows : [];
    const page_size = Math.max(1, Math.min(200, Number(data?.page_size) || 15));
    const find = (selector) => parentElement.querySelector(selector);
    const head = find('#ss-table-head');
    const body = find('#ss-table-body');
    const query_input = find('#ss-table-query');
    const previous = find('#ss-prev');
    const next = find('#ss-next');
    const clear = find('#ss-clear');
    const export_button = find('#ss-export');
    const state = parentElement.__ss_table_state ??= {
        query: '', page: 0, sort_key: '', descending: false, selected_id: null,
    };
    const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });
    const tones = new Set(['success', 'warning', 'danger', 'muted']);

    find('#ss-table-title').textContent = data?.title || 'Records';
    query_input.placeholder = 'Search control, title, owner…';
    query_input.value = state.query;

    const sort_value = (row, column) => {
        const raw = row[column.key];
        if (raw === null || raw === undefined || raw === '' || raw === '—') return null;
        if (column.kind === 'progress') {
            const match = String(raw).match(/^([0-9]+(?:\.[0-9]+)?)%$/);
            return match ? Number(match[1]) : null;
        }
        return typeof raw === 'number' ? raw : String(raw);
    };

    const filtered_rows = () => {
        const query = state.query.trim().toLocaleLowerCase();
        const filtered = rows.filter((row) => !query || columns.some((column) =>
            String(row[column.key] ?? '').toLocaleLowerCase().includes(query)));
        const column = columns.find((item) => item.key === state.sort_key);
        if (column) filtered.sort((left, right) => {
            const a = sort_value(left, column);
            const b = sort_value(right, column);
            if (a === null || b === null) return a === b ? 0 : a === null ? 1 : -1;
            const order = typeof a === 'number' && typeof b === 'number'
                ? a - b : collator.compare(String(a), String(b));
            return state.descending ? -order : order;
        });
        return filtered;
    };

    const render_cell = (cell, column, row) => {
        const raw = row[column.key];
        const value = raw === null || raw === undefined || raw === '' ? '—' : String(raw);
        cell.title = value;
        if (column.kind === 'status') {
            const chip = document.createElement('span');
            chip.className = 'ss-chip';
            const tone = row.__tones?.[column.key];
            chip.dataset.tone = tones.has(tone) ? tone : 'muted';
            chip.textContent = value;
            cell.appendChild(chip);
        } else if (column.kind === 'progress' && /^([0-9]+(?:\.[0-9]+)?)%$/.test(value)) {
            const percentage = Math.max(0, Math.min(100, Number.parseFloat(value)));
            const wrap = document.createElement('div');
            wrap.className = 'ss-progress';
            const track = document.createElement('span');
            track.className = 'ss-progress-track';
            track.setAttribute('aria-hidden', 'true');
            const fill = document.createElement('span');
            fill.className = 'ss-progress-fill';
            fill.style.width = `${percentage}%`;
            track.appendChild(fill);
            const label = document.createElement('span');
            label.textContent = value;
            wrap.append(track, label);
            cell.appendChild(wrap);
        } else {
            cell.textContent = value;
        }
    };

    const render_body = () => {
        const filtered = filtered_rows();
        const pages = Math.max(1, Math.ceil(filtered.length / page_size));
        state.page = Math.max(0, Math.min(state.page, pages - 1));
        const start = state.page * page_size;
        body.replaceChildren();
        if (!filtered.length) {
            const row = document.createElement('tr');
            const cell = document.createElement('td');
            cell.colSpan = Math.max(1, columns.length);
            cell.className = 'ss-table-empty';
            cell.textContent = rows.length
                ? 'No controls match your search. Clear the search to see all controls.'
                : 'No controls match the current assessment filter.';
            row.appendChild(cell);
            body.appendChild(row);
        }
        for (const row of filtered.slice(start, start + page_size)) {
            const tr = document.createElement('tr');
            tr.tabIndex = 0;
            tr.dataset.selected = String(state.selected_id === row.__row_id);
            tr.setAttribute('aria-label', `Select ${row.Control ?? row.__row_id}`);
            const select = () => {
                state.selected_id = row.__row_id;
                body.querySelectorAll('tr').forEach((item) => { item.dataset.selected = 'false'; });
                tr.dataset.selected = 'true';
                setTriggerValue('selected_row', { row_id: row.__row_id });
            };
            tr.onclick = select;
            tr.onkeydown = (event) => {
                if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault();
                    select();
                }
            };
            for (const column of columns) {
                const cell = document.createElement('td');
                cell.dataset.kind = column.kind || 'text';
                render_cell(cell, column, row);
                tr.appendChild(cell);
            }
            body.appendChild(tr);
        }
        find('#ss-table-count').textContent = `${filtered.length} of ${rows.length} records`;
        find('#ss-page').textContent = filtered.length
            ? `${start + 1}–${Math.min(start + page_size, filtered.length)} · Page ${state.page + 1} of ${pages}`
            : '0 records';
        previous.disabled = state.page <= 0;
        next.disabled = state.page >= pages - 1;
        clear.disabled = !state.query;
        export_button.disabled = !filtered.length;
    };

    const render_head = () => {
        head.replaceChildren();
        const tr = document.createElement('tr');
        for (const column of columns) {
            const th = document.createElement('th');
            th.scope = 'col';
            const active = state.sort_key === column.key;
            th.setAttribute('aria-sort', active ? state.descending ? 'descending' : 'ascending' : 'none');
            const button = document.createElement('button');
            button.type = 'button';
            button.textContent = `${column.label || column.key}${active ? state.descending ? ' ↓' : ' ↑' : ' ↕'}`;
            button.onclick = () => {
                state.descending = active ? !state.descending : false;
                state.sort_key = column.key;
                state.page = 0;
                render_head();
                render_body();
                head.querySelectorAll('button')[columns.indexOf(column)]?.focus();
            };
            th.appendChild(button);
            tr.appendChild(th);
        }
        head.appendChild(tr);
    };

    const csv_cell = (raw) => {
        let text = raw === null || raw === undefined ? '' : String(raw);
        // Spreadsheet applications must display external text, not evaluate it.
        if (/^[\s]*[=+\-@]/.test(text)) text = `'${text}`;
        return `"${text.replaceAll('"', '""')}"`;
    };

    query_input.oninput = () => { state.query = query_input.value; state.page = 0; render_body(); };
    clear.onclick = () => { state.query = ''; query_input.value = ''; state.page = 0; render_body(); query_input.focus(); };
    previous.onclick = () => { state.page -= 1; render_body(); };
    next.onclick = () => { state.page += 1; render_body(); };
    export_button.onclick = () => {
        const lines = [columns.map((column) => csv_cell(column.label || column.key)).join(',')];
        for (const row of filtered_rows()) lines.push(columns.map((column) => csv_cell(row[column.key])).join(','));
        const url = URL.createObjectURL(new Blob(['\ufeff', lines.join('\r\n')], { type: 'text/csv;charset=utf-8' }));
        const link = document.createElement('a');
        link.href = url;
        link.download = 'securescope-controls.csv';
        link.click();
        setTimeout(() => URL.revokeObjectURL(url), 0);
    };
    render_head();
    render_body();
}
