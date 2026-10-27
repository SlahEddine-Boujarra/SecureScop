/** Structured editor: document data is inserted as text, never untrusted HTML. */
export default function ({data, parentElement, setTriggerValue}) {
    const root = parentElement.querySelector('#policy-editor');
    const selectionForEditor = () => root.getRootNode().getSelection?.() ?? window.getSelection();
    const state = parentElement.__policy_state ??= {blocks: structuredClone(data.blocks), dirty: !data.saved, undo: [], redo: []};
    const snapshot = () => state.blocks = [...root.querySelectorAll('[data-block]')].map(block => {
        const runs = [];
        const content = block.querySelector('[contenteditable]');
        function walk(node, bold = false, italic = false) {
            if (node.nodeType === Node.TEXT_NODE) {
                runs.push({text: node.textContent, bold, italic});
            } else {
                for (const child of node.childNodes) walk(child, bold || ['B','STRONG'].includes(node.nodeName), italic || ['I','EM'].includes(node.nodeName));
                if (node !== content && ['DIV','BR'].includes(node.nodeName)) runs.push({text:'\n', bold, italic});
            }
        }
        walk(content);
        return {kind:block.querySelector('select').value, runs};
    });
    const render = () => {
        root.replaceChildren();
        const toolbar = document.createElement('div'); toolbar.className='policy-toolbar';
        const indicator = document.createElement('span'); indicator.textContent=state.dirty ? 'Unsaved changes' : 'Saved content';
        function button(label, callback) {
            const b=document.createElement('button'); b.type='button'; b.textContent=label;
            b.disabled=!!data.read_only; b.onclick=callback; return b;
        }
        const mark = () => {state.dirty=true; indicator.textContent='Unsaved changes';};
        const save=button('Save draft version', () => {
            setTriggerValue('save', {blocks:snapshot(), nonce:Date.now()});
            indicator.textContent='Saving…';
        }); save.className='policy-save';
        const checkpoint=()=>{state.undo.push(structuredClone(snapshot())); state.undo=state.undo.slice(-50); state.redo=[];};
        const undo=button('Undo',()=>{if(!state.undo.length)return; state.redo.push(structuredClone(snapshot())); state.blocks=state.undo.pop(); state.dirty=true; render();});
        const redo=button('Redo',()=>{if(!state.redo.length)return; state.undo.push(structuredClone(snapshot())); state.blocks=state.redo.pop(); state.dirty=true; render();});
        toolbar.append(indicator, undo, redo, save); root.append(toolbar);
        state.blocks.forEach((block,index) => {
            const row=document.createElement('section'); row.dataset.block=String(index);
            const controls=document.createElement('div'); controls.className='policy-block-actions';
            const kind=document.createElement('select'); kind.setAttribute('aria-label',`Paragraph ${index+1} style`);
            for (const [value,label] of Object.entries({h1:'Heading 1',h2:'Heading 2',h3:'Heading 3',p:'Paragraph',bullet:'Bullet item',number:'Numbered item'})) {
                const option=document.createElement('option'); option.value=value; option.textContent=label; kind.append(option);
            }
            kind.value=block.kind; kind.disabled=!!data.read_only;
            const edit=document.createElement('div'); edit.contentEditable=String(!data.read_only);
            edit.setAttribute('role','textbox'); edit.setAttribute('aria-multiline','true');
            edit.setAttribute('aria-label',`Paragraph ${index+1}`); edit.className='policy-text'; edit.dataset.kind=block.kind;
            for (const run of block.runs) {
                const span=document.createElement('span'); span.textContent=run.text;
                // Use semantic elements so serialization preserves emphasis.
                let node=span;
                if(run.bold) {const strong=document.createElement('strong'); strong.append(node); node=strong;}
                if(run.italic) {const em=document.createElement('em'); em.append(node); node=em;}
                edit.append(node);
            }
            kind.onchange=()=>{state.undo.push(structuredClone(state.blocks)); state.redo=[]; edit.dataset.kind=kind.value; snapshot(); mark();};
            for(const [label,tag] of [['Bold','strong'],['Italic','em']]) {
                const b=button(label,()=>{});
                b.onmousedown=(event)=>{
                    event.preventDefault(); const selection=selectionForEditor();
                    if(!selection || !selection.rangeCount || !edit.contains(selection.anchorNode) || !edit.contains(selection.focusNode)) return;
                    const range=selection.getRangeAt(0); if(range.collapsed) return;
                    checkpoint();
                    const wrapper=document.createElement(tag); wrapper.append(range.extractContents()); range.insertNode(wrapper); snapshot(); mark();
                }; controls.append(b);
            }
            edit.onbeforeinput=checkpoint;
            edit.oninput=()=>{snapshot(); mark();};
            edit.onpaste=(event)=>{
                event.preventDefault(); checkpoint(); const selection=selectionForEditor();
                if(!selection || !selection.rangeCount) return;
                const range=selection.getRangeAt(0); range.deleteContents();
                const text=document.createTextNode(event.clipboardData.getData('text/plain'));
                range.insertNode(text); range.setStartAfter(text); range.collapse(true); selection.removeAllRanges(); selection.addRange(range); snapshot(); mark();
            };
            edit.ondrop=event=>event.preventDefault();
            const remove=button('Remove paragraph',()=>{checkpoint(); state.blocks.splice(index,1); state.dirty=true; render();});
            controls.prepend(kind); controls.append(remove); row.append(controls,edit); root.append(row);
        });
        root.append(button('Add paragraph',()=>{checkpoint(); state.blocks.push({kind:'p',runs:[{text:''}]}); state.dirty=true;render();}));
        const hint=document.createElement('small'); hint.textContent='Select text for bold or italic. Paste inserts plain text. Save creates a new draft; review actions use the saved version.'; root.append(hint);
    };
    render();
}
