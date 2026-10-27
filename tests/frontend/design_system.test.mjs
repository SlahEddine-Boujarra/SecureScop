import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { JSDOM } = require(process.env.SECURESCOPE_JSDOM_PATH || 'jsdom');
const source = fs.readFileSync(new URL('../../src/securescope/ui/components_v2/assurance_workbench.js', import.meta.url), 'utf8');
const { default: render } = await import('data:text/javascript;base64,' + Buffer.from(source).toString('base64'));

function workspace() {
  const dom = new JSDOM('<div id="host"><main id="assurance-workbench"></main></div>');
  globalThis.document = dom.window.document;
  globalThis.window = dom.window;
  const host = document.querySelector('#host');
  return {
    root: host.querySelector('main'),
    run: data => render({ data, parentElement: host, setTriggerValue: () => {} }),
  };
}

test('reused component clears previous page styling without accumulating content', () => {
  const app = workspace();
  app.run({mode: 'foundation', title: 'Context', section: 'context', rows: [], columns: {}, add_label: 'Add issue'});
  assert.ok(app.root.classList.contains('foundation-workbench'));
  app.run({mode: 'control_profiles', rows: []});
  assert.equal(app.root.classList.contains('foundation-workbench'), false);
  assert.equal(app.root.querySelectorAll('h2').length, 1);
  assert.equal(app.root.querySelectorAll('input,select,table').length, 0);
});

test('rerender disconnects old overflow observers and retains one section bar', () => {
  const app = workspace();
  const observers = [];
  globalThis.ResizeObserver = class {
    constructor() { this.disconnected = false; observers.push(this); }
    observe() {}
    disconnect() { this.disconnected = true; }
  };
  try {
    const data = {mode: 'policy_detail', can_edit: false, is_admin: false,
      detail: {title: 'Policy', status: 'Draft', controls: [], approvers: [], approvals: {}}, controls: []};
    app.run(data);
    const previous = observers.at(-1);
    app.run(data);
    assert.ok(previous.disconnected);
    assert.equal(app.root.querySelectorAll('.section-navigation').length, 1);
    assert.equal(observers.filter(observer => !observer.disconnected).length, 1);
  } finally {
    delete globalThis.ResizeObserver;
  }
});
