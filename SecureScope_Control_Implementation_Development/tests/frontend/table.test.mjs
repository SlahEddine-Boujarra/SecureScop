/** DOM unit tests for the real Components v2 assets; no browser or services. */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { JSDOM } = require(process.env.SECURESCOPE_JSDOM_PATH || 'jsdom');

const component_source = readFileSync(new URL('../../src/securescope/ui/components_v2/stitch_components.py', import.meta.url), 'utf8');
const table_source = component_source.slice(component_source.indexOf('def _table_component('));
const html = table_source.match(/html="""([\s\S]*?)"""/)[1];
const script = readFileSync(new URL('../../src/securescope/ui/components_v2/table.js', import.meta.url), 'utf8');

/** Mount the production HTML and script with an isolated document and event log. */
function fixture(rows, page_size = 2) {
    const dom = new JSDOM(`<main>${html}</main>`);
    const root = dom.window.document.querySelector('main');
    const events = [];
    const exports = [];
    dom.window.HTMLAnchorElement.prototype.click = function () {};
    const render = new Function('document', 'Blob', 'URL', 'setTimeout', `return (${script.replace('export default', '')});`)(
        dom.window.document, Blob,
        { createObjectURL: (blob) => { exports.push(blob); return 'blob:unit-test'; }, revokeObjectURL: () => {} },
        (callback) => callback(),
    );
    const data = {
        rows,
        columns: [
            { key: 'Control', label: 'Control', kind: 'primary' },
            { key: 'Title', label: 'Title' },
            { key: 'Count', label: 'Count' },
            { key: 'Coverage', label: 'Coverage', kind: 'progress' },
            { key: 'Status', label: 'Status', kind: 'status' },
        ],
        page_size,
    };
    const rerender = () => render({ data, parentElement: root, setTriggerValue: (...args) => events.push(args) });
    rerender();
    const query = (text) => {
        const input = root.querySelector('#ss-table-query');
        input.value = text;
        input.dispatchEvent(new dom.window.Event('input'));
    };
    return { dom, root, data, events, exports, rerender, query };
}

const rows = [
    { __row_id: 'A.8.10', Control: 'A.8.10', Title: 'Deletion', Count: 10, Coverage: '—' },
    { __row_id: 'A.8.9', Control: 'A.8.9', Title: 'Configuration', Count: 2, Coverage: '75%' },
    { __row_id: 'A.8.8', Control: 'A.8.8', Title: 'Vulnerabilities', Count: 1, Coverage: '50%' },
];

test('pagination selects the correct stable identity', () => {
    const page = fixture(rows);
    page.root.querySelector('#ss-next').click();
    assert.match(page.root.querySelector('#ss-page').textContent, /Page 2 of 2/);
    page.root.querySelector('tbody tr').click();
    assert.deepEqual(page.events, [['selected_row', { row_id: 'A.8.8' }]]);
});

test('search survives a component rerender and has a usable empty state', () => {
    const page = fixture(rows);
    page.query('Configuration');
    page.rerender();
    assert.equal(page.root.querySelector('#ss-table-query').value, 'Configuration');
    assert.equal(page.root.querySelectorAll('tbody tr').length, 1);
    assert.match(page.root.querySelector('tbody').textContent, /A\.8\.9/);
    page.query('missing control');
    assert.match(page.root.querySelector('tbody').textContent, /No controls match/);
    assert.ok(page.root.querySelector('#ss-export').disabled);
    page.root.querySelector('#ss-clear').click();
    assert.equal(page.root.querySelector('#ss-table-count').textContent, '3 of 3 records');
});

test('natural control IDs and numeric counts sort correctly', () => {
    const page = fixture(rows, 20);
    page.root.querySelector('th button').click();
    assert.equal(page.root.querySelector('tbody tr td').textContent, 'A.8.8');
    page.root.querySelectorAll('th button')[2].click();
    assert.equal(page.root.querySelector('tbody tr td').textContent, 'A.8.8');
    page.root.querySelectorAll('th button')[2].click();
    assert.equal(page.root.querySelector('tbody tr td').textContent, 'A.8.10');
    assert.equal(page.root.querySelectorAll('th')[2].getAttribute('aria-sort'), 'descending');
});

test('space selects a row without its default scrolling action', () => {
    const page = fixture(rows);
    const event = new page.dom.window.KeyboardEvent('keydown', { key: ' ', cancelable: true });
    page.root.querySelector('tbody tr').dispatchEvent(event);
    assert.equal(event.defaultPrevented, true);
    assert.equal(page.events[0][1].row_id, 'A.8.10');
});

test('untrusted cell text never becomes markup and missing coverage has no bar', () => {
    const page = fixture([{ ...rows[0], Title: '<img src=x onerror=alert(1)>', Status: 'Validated but expired', __tones: { Status: 'danger' } }]);
    assert.equal(page.root.querySelectorAll('img, script').length, 0);
    assert.ok(page.root.querySelector('tbody').textContent.includes('<img'));
    assert.equal(page.root.querySelectorAll('.ss-progress').length, 0);
    assert.equal(page.root.querySelector('.ss-chip').dataset.tone, 'danger');
});

test('filtered export escapes spreadsheet formulas, quotes and line breaks', async () => {
    const page = fixture([
        { ...rows[0], Title: '=1+1', Status: 'A "quoted"\nline' }, rows[1],
    ]);
    page.query('=1+1');
    page.root.querySelector('#ss-export').click();
    const csv = await page.exports[0].text();
    assert.ok(csv.includes('"\'=1+1"'));
    assert.ok(csv.includes('"A ""quoted""\nline"'));
    assert.ok(!csv.includes('Configuration'));
});

test('shrinking data clamps the current page instead of showing a blank table', () => {
    const page = fixture(rows);
    page.root.querySelector('#ss-next').click();
    page.data.rows = [rows[1]];
    page.rerender();
    assert.match(page.root.querySelector('#ss-page').textContent, /Page 1 of 1/);
    assert.match(page.root.querySelector('tbody').textContent, /Configuration/);
});
