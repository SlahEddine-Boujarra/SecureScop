import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {JSDOM}=require(process.env.SECURESCOPE_JSDOM_PATH || 'jsdom');
const source=fs.readFileSync(new URL('../../src/securescope/ui/components_v2/assurance_workbench.js',import.meta.url),'utf8');
const {default:render}=await import('data:text/javascript;base64,'+Buffer.from(source).toString('base64'));
function setup(data){const dom=new JSDOM('<div id="host"><main id="assurance-workbench"></main></div>');globalThis.document=dom.window.document;globalThis.window=dom.window;globalThis.Event=dom.window.Event;const host=document.querySelector('#host'),actions=[];const run=(next=data)=>render({data:next,parentElement:host,setTriggerValue:(key,value)=>actions.push(value)});run();return {host,actions,run};}
const base={actor:'a@x',is_admin:true,can_edit:true,revision:1,members:[{email:'a@x',role:'Administrator'}],controls:[],groups:[{record_key:'default',payload:{name:'Default'}}],templates:[],rows:[],guidance:{},default_guidance:[]};
const blocks=[{kind:'h2',runs:[{text:'Password policy'}]},{kind:'p',runs:[{text:'My custom wording'}]},{kind:'h2',runs:[{text:'Other section'}]},{kind:'p',runs:[{text:'Keep unchanged'}]}];
const detail={policy_id:'p1',policy_version:1,title:'Access <img src=x onerror=alert(1)>',owner:'a@x',status:'Draft',controls:[],blocks};
const button=(host,label)=>[...host.querySelectorAll('button')].find(b=>b.textContent===label);
let test=setup({...base,mode:'policy_list',rows:[{...detail,overall:'Draft',approvers:[]}],selected:null});
assert.equal(test.host.querySelectorAll('img').length,0);test.host.querySelector('tbody tr').click();assert.equal(test.actions[0].payload.id,'p1');
test=setup({...base,mode:'policy_builder',selected:'p1',detail,guidance:{'Password policy':[{id:'unique',group:'Strength',text:'Use unique passwords.'}]}});
let check=test.host.querySelector('.question input');check.click();assert.equal(test.host.__workbench.document.length,5);assert.equal(test.host.querySelector('.question input').checked,true);
let paragraph=test.host.querySelector('[data-block-index="1"]');paragraph.textContent='Manually changed';paragraph.dispatchEvent(new Event('input'));
test.host.querySelector('.question input').click();assert.equal(test.host.__workbench.document.length,4);assert.equal(test.host.__workbench.document[1].runs[0].text,'Manually changed');assert.equal(test.host.__workbench.document[3].runs[0].text,'Keep unchanged');
button(test.host,'Next').click();button(test.host,'Previous').click();assert.match(test.host.textContent,/Manually changed/);
button(test.host,'Save draft').click();assert.equal(test.actions[0].action,'policy_save');assert.equal(test.actions[0].payload.blocks[1].runs[0].text,'Manually changed');
// Failed write preserves unsaved content and clears the in-flight lock.
test.run({...base,mode:'policy_builder',selected:'p1',detail,response:{nonce:'failure',error:'Stale version'}});assert.equal(test.host.__workbench.dirty,true);assert.match(test.host.textContent,/Manually changed/);assert.equal(button(test.host,'Save draft').disabled,false);
const risk={risk_ref:9,revision:2,threat:'Loss of service',asset:'Server',control_references:[],risk_owner:'a@x',pre_likelihood:3,pre_impact:4,review_state:'Draft'};
test=setup({...base,mode:'risk_detail',selected:9,revision:2,detail:risk,asset_groups:['Hardware'],tasks:[]});assert.match(test.host.textContent,/Treatment Plan/);assert.match(test.host.textContent,/Post-Treatment Assessment/);assert.match(test.host.querySelector('.risk-formula').textContent,/3 × 4 = 12/);
const ratings=[...test.host.querySelectorAll('label')].filter(n=>n.firstChild.textContent==='Likelihood');const rating=ratings[0].querySelector('select');rating.value='2';rating.dispatchEvent(new Event('change'));assert.match(test.host.querySelector('.risk-formula').textContent,/2 × 4 = 8/);rating.value='1';rating.dispatchEvent(new Event('change'));assert.match(test.host.querySelector('.risk-formula').textContent,/1 × 4 = 4/);
button(test.host,'Save Draft').click();assert.equal(test.actions[0].payload.record.pre_likelihood,1);assert.equal(test.actions[0].expected,2);
test=setup({...base,can_edit:false,is_admin:false,mode:'risk_detail',selected:9,detail:risk,asset_groups:[],tasks:[]});assert.equal(button(test.host,'Save Draft').disabled,true);assert.equal(test.host.querySelector('textarea').disabled,true);
test=setup({...base,mode:'risk_table',group:'default',rows:[{...risk,group:'default'}]});test.host.querySelector('tbody tr').click();assert.equal(test.actions[0].payload.id,9);
console.log('Workbench DOM interactions passed: selection, escaping, suggestions, manual editing, navigation, failed saves, live scores, readonly controls.');

// Undo/redo retain a directly edited paragraph.
test=setup({...base,mode:'policy_builder',selected:'p1',detail});paragraph=test.host.querySelector('[data-block-index="1"]');paragraph.textContent='Updated text';paragraph.dispatchEvent(new Event('input'));button(test.host,'Undo').click();assert.equal(test.host.__workbench.document[1].runs[0].text,'My custom wording');button(test.host,'Redo').click();assert.equal(test.host.__workbench.document[1].runs[0].text,'Updated text');
// Inventory choices survive tab navigation and are included in the explicit save.
test=setup({...base,mode:'risk_detail',selected:9,revision:2,detail:{...risk,asset_ids:[]},asset_groups:[],tasks:[],assets:[{id:41,asset_tag:'Server',ip:'192.0.2.4'}]});button(test.host,'Impacted assets').click();test.host.querySelector('input[type=checkbox]').click();button(test.host,'Assessment workflow').click();button(test.host,'Save Draft').click();assert.deepEqual(test.actions[0].payload.record.asset_ids,[41]);
// Date click opens the day panel; Add exposes authorized client choices.
test=setup({...base,mode:'calendar',client:'Client',clients:[{name:'Client',role:'Administrator'}],events:[]});test.host.querySelector('.date-tile').click();assert.match(test.host.textContent,/Events \(0\)/);button(test.host,'+ Add').click();const dialog=test.host.querySelector('[role=dialog]');assert.ok(dialog);assert.match(dialog.textContent,/Client workspace/);button(test.host,'Save activity').click();assert.equal(test.actions[0].action,'calendar_save');assert.equal(test.actions[0].payload.client,'Client');
// Foundation records open a detail drawer without executing content as markup.
test=setup({...base,mode:'foundation',section:'context',title:'Context',description:'Formal records',add_label:'Add issue',filter_key:'issue_type',columns:{title:'Issue',owner:'Owner'},rows:[{title:'<img src=x>',owner:'Owner',issue_type:'Internal',description:'Context details'}]});test.host.querySelector('tbody tr').click();assert.ok(test.host.querySelector('.record-drawer'));assert.equal(test.host.querySelectorAll('img').length,0);
console.log('New interactions passed: editor undo/redo, impacted assets, calendar day panel, Foundation drawer.');

// A response owns one browser download, including after intervening responses.
const downloads=[], urls=[], revoked=[];
const originalCreate=URL.createObjectURL, originalRevoke=URL.revokeObjectURL;
URL.createObjectURL=blob=>{urls.push(blob);return `blob:export-${urls.length}`;};
URL.revokeObjectURL=url=>revoked.push(url);
test=setup({...base,mode:'policy_detail',selected:'p1',detail});
window.HTMLAnchorElement.prototype.click=function(){downloads.push({name:this.download,url:this.href});};
const exportResponse={nonce:'download-1',download:{filename:'Security_Policy_v1.pdf',mime:'application/pdf',content_base64:Buffer.from('%PDF-test').toString('base64')}};
const exported={...base,mode:'policy_detail',selected:'p1',detail,response:exportResponse};
test.run(exported);test.run(exported);
assert.equal(downloads.length,1);
assert.equal(downloads[0].name,'Security_Policy_v1.pdf');
assert.equal(await urls[0].text(),'%PDF-test');
assert.equal(urls[0].type,'application/pdf');
test.run({...exported,response:{...exportResponse,nonce:'download-2'}});
assert.equal(downloads.length,2);
test.run(exported);assert.equal(downloads.length,2);
test.run({...exported,response:{nonce:'download-error',error:'Export failed'}});
assert.equal(downloads.length,2);assert.equal(test.host.__workbench.busy,false);
assert.equal(test.host.querySelectorAll('a[download]').length,0);
await new Promise(resolve=>setTimeout(resolve,1100));
assert.equal(revoked.length,2);
URL.createObjectURL=originalCreate;URL.revokeObjectURL=originalRevoke;
console.log('Policy delivery: one Blob download per nonce, exact bytes, clean failure, URL cleanup.');
