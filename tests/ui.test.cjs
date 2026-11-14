// Runs the production rendering helper with a minimal DOM; no browser/network.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const makeElement = tag => ({ tag, children: [], textContent: '', handlers: {},
    appendChild(child) { this.children.push(child); },
    addEventListener(event, action) { this.handlers[event] = action; },
    set innerHTML(_) { throw new Error('HTML sink used'); }
});
const context = { document: { createElement: makeElement } };
vm.createContext(context);
vm.runInContext(fs.readFileSync('crates/beacon-admin/src/ui-safe.js', 'utf8'), context);
for (const variant of ['model', 'provider', 'operator']) {
    const parent = makeElement('div');
    const marker = `<img src=x onerror="${variant}">`;
    context.appendText(parent, 'msg', marker);
    assert.equal(parent.children.length, 1);
    assert.equal(parent.children[0].tag, 'div');
    assert.equal(parent.children[0].textContent, marker);
    assert.equal(parent.children[0].children.length, 0);
}
let clicks = 0;
const parent = makeElement('div');
context.appendButton(parent, 'Delete', () => clicks++);
parent.children[0].handlers.click();
assert.equal(clicks, 1);
console.log('4 UI checks passed; 0 failed');
