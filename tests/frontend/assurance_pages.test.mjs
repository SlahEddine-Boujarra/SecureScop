import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import test from 'node:test';
const {JSDOM}=createRequire(import.meta.url)(process.env.SECURESCOPE_JSDOM_PATH||'jsdom');
const source=readFileSync(new URL('../../src/securescope/ui/components_v2/assurance_pages.js',import.meta.url),'utf8');
function fixture(mode='soa') {
 const dom=new JSDOM('<div><main id="assurance-page"></main></div>');const root=dom.window.document.querySelector('div'),events=[];
 const data={mode,title:'Controls',rows:Array.from({length:21},(_,i)=>({control_id:`A.8.${i+1}`,title:`Control ${i+1}`,owner:i%2?'IT':'Security',attention:i%2?['Missing Evidence']:[],open_work:i%2})),filters:[{key:'owner',label:'All owners'}],columns:[{key:'control_id',label:'Control'},{key:'title',label:'Title'}]};
 const render=new Function('document',`return (${source.replace('export default','')});`)(dom.window.document);
 const rerender=()=>render({data,parentElement:root,setTriggerValue:(...args)=>events.push(args)});rerender();return{root,dom,data,events,rerender};
}
test('SoA filters and paging never mutate the full source register',()=>{const f=fixture();const input=f.root.querySelector('input');input.value='Control 21';input.dispatchEvent(new f.dom.window.Event('input'));assert.equal(f.root.querySelectorAll('tbody tr').length,1);assert.equal(f.root.querySelector('.pages'),null);f.root.querySelector('tbody button').click();assert.equal(f.events[0][1].id,'A.8.21');assert.equal(f.events[0][1].action,'edit');assert.equal(f.data.rows.length,21);f.rerender();assert.equal(f.root.querySelector('input').value,'Control 21');});
test('dashboard attention uses existing classification and navigates canonical IDs',()=>{const f=fixture('dashboard');f.data.attention=[{label:'Missing Evidence',value:10}];f.rerender();f.root.querySelector('.attention button').click();assert.equal(f.root.querySelectorAll('tbody tr').length,10);f.root.querySelector('tbody button').click();assert.equal(f.events[0][1].id,'A.8.2');assert.equal(f.events[0][1].action,'open');});
test('record HTML is escaped and empty state has no table or pagination',()=>{const f=fixture();f.data.rows=[{control_id:'A.8.1',title:'<img src=x onerror=alert(1)>'}];f.rerender();assert.equal(f.root.querySelector('img'),null);f.data.rows=[];f.rerender();assert.equal(f.root.querySelector('table'),null);assert.equal(f.root.querySelector('.pages'),null);});
