import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {JSDOM}=require(process.env.SECURESCOPE_JSDOM_PATH||'jsdom');
const source=fs.readFileSync(new URL('../../src/securescope/ui/components_v2/assurance_workbench.js',import.meta.url),'utf8');
const {default:render}=await import('data:text/javascript;base64,'+Buffer.from(source).toString('base64'));
const profile={control_id:'A.8.8',control_name:'Management of technical vulnerabilities',profile_version:3,control_owner:'owner@example.test',assessment_owner:'reviewer@example.test',scope:'Production services',measurement_model:'checklist',automation_level:'Partial',assessment_methods:'Examine\nTest',evidence_requirements:'Scan report',summary:{Control:'A.8.8',Title:'Management of technical vulnerabilities',Owner:'owner@example.test'}};
function setup(overrides={}){
 const dom=new JSDOM('<div id="host"><main id="assurance-workbench"></main></div>');
 globalThis.document=dom.window.document;globalThis.window=dom.window;
 const host=document.querySelector('#host'),actions=[];
 const data={mode:'control_profiles',models:['checklist'],can_edit:true,rows:[profile],...overrides};
 const run=(next=data)=>render({data:next,parentElement:host,setTriggerValue:(_,event)=>actions.push(event)});
 run();return {host,actions,run,data,dom};
}
const button=(host,label)=>[...host.querySelectorAll('button')].find(b=>b.textContent===label);
function open(t){const row=t.host.querySelector('tbody tr');row.focus();row.click();return t.host.querySelector('.record-drawer');}

test('profile row opens an editable, grouped drawer over its retained table',()=>{
 const t=setup();const panel=open(t);
 assert.equal(panel.getAttribute('aria-modal'),'true');
 assert.ok(t.host.querySelector('tbody tr'));
 assert.equal(panel.querySelectorAll('h3').length,6);
 assert.equal(panel.querySelector('input').value,'');
 assert.equal(panel.querySelector('input').disabled,false);
 assert.equal(t.host.querySelector('.table-wrap').parentElement.inert,true);
});
test('unsaved Escape preserves data until explicit discard, then restores row focus',()=>{
 const t=setup();const panel=open(t);const input=panel.querySelector('input');
 input.value='new@example.test';input.dispatchEvent(new t.dom.window.Event('input'));
 panel.dispatchEvent(new t.dom.window.KeyboardEvent('keydown',{key:'Escape',bubbles:true}));
 assert.ok(t.host.querySelector('.discard-notice'));
 button(t.host,'Keep editing').click();assert.equal(input.value,'new@example.test');
 button(t.host,'Close').click();button(t.host,'Discard changes').click();
 assert.equal(t.host.querySelector('.record-drawer'),null);
 assert.equal(document.activeElement,t.host.querySelector('tbody tr'));
 assert.equal(t.host.querySelector('.table-wrap').parentElement.inert,false);
});
test('save carries the opened version and failed writes retain edited values',()=>{
 const t=setup();open(t);const input=t.host.querySelector('.record-drawer input');
 input.value='new@example.test';input.dispatchEvent(new t.dom.window.Event('input'));
 button(t.host,'Save profile version').click();
 assert.equal(t.actions[0].action,'profile_save');assert.equal(t.actions[0].payload.expected_version,3);
 t.run({...t.data,response:{nonce:t.actions[0].nonce,error:'Profile changed in another session'}});
 assert.equal(t.host.querySelector('.record-drawer input').value,'new@example.test');
 assert.equal(button(t.host,'Save profile version').disabled,false);
 assert.match(t.host.querySelector('.record-drawer').textContent,/changed in another session/);
});
test('readonly profile disables all editing and keyboard selection still works',()=>{
 const t=setup({can_edit:false});const row=t.host.querySelector('tbody tr');
 row.dispatchEvent(new t.dom.window.KeyboardEvent('keydown',{key:' ',bubbles:true}));
 assert.ok(t.host.querySelector('.record-drawer'));
 assert.ok([...t.host.querySelectorAll('.record-drawer input,.record-drawer textarea,.record-drawer select')].every(e=>e.disabled));
 assert.equal(button(t.host,'Save profile version').disabled,true);
});
test('assessment navigation uses the selected control identity',()=>{
 const t=setup();open(t);button(t.host,'Assess this control').click();
 assert.equal(t.actions[0].action,'profile_assess');assert.equal(t.actions[0].payload.control_id,'A.8.8');
});
test('risk reading hides internal columns while showing full long values in its drawer',()=>{
 const narrative='Long risk rationale '.repeat(60)+'<img src=x onerror=alert(1)>';
 const t=setup({mode:'risk_reading',fields:{risk_ref:'Reference',threat:'Risk scenario',asset:'Asset',risk_owner:'Owner',pre_risk_score:'Inherent',pre_likelihood_rationale:'Likelihood rationale',treatment_option:'Treatment',treatment_action_status:'Progress',post_risk_score:'Residual'},rows:[{risk_ref:1,id:300,client_id:7,threat:'Loss of service',pre_likelihood_rationale:narrative}]});
 assert.equal(t.host.querySelectorAll('th').length,6);
 assert.doesNotMatch(t.host.querySelector('thead').textContent,/client_id/);
 open(t);assert.match(t.host.querySelector('.record-drawer').textContent,/Long risk rationale/);
 assert.equal(t.host.querySelectorAll('img').length,0);
 assert.ok(t.host.querySelector('.record-drawer').textContent.includes(narrative));
});
test('drawer keyboard focus cycles within the dialog',()=>{
 const t=setup();const panel=open(t);const buttons=panel.querySelectorAll('button');
 buttons[buttons.length-1].focus();panel.dispatchEvent(new t.dom.window.KeyboardEvent('keydown',{key:'Tab',bubbles:true,cancelable:true}));
 assert.equal(document.activeElement,buttons[0]);
});

test('risk treatment is compact and opens the selected record',()=>{
 const t=setup({mode:'risk_table',lifecycle:'Treatment plan',groups:[],group:'all',members:[],is_admin:true,rows:[{risk_ref:12,threat:'Service interruption',risk_owner:'owner@example.test',treatment_option:'Modify',treatment_action_status:'In Progress',treatment_action_timescale:'90 days'}]});
 assert.equal(t.host.querySelectorAll('th').length,7);
 assert.deepEqual([...t.host.querySelectorAll('th')].slice(-2).map(n=>n.textContent),['Due Date','Timescale']);
 assert.equal(t.host.querySelector('tbody tr').children[5].textContent,'—');
 assert.match(t.host.querySelector('tbody').textContent,/90 days/);
 assert.ok(!button(t.host,'Add Risk Register'));
 t.host.querySelector('tbody tr').click();assert.equal(t.actions[0].payload.id,12);
});
test('assessment approval never masquerades as formal risk acceptance',()=>{
 const t=setup({mode:'risk_table',lifecycle:'Risk acceptance',groups:[],group:'all',members:[],is_admin:false,rows:[{risk_ref:4,treatment_option:'Accept',review_state:'Approved'},{risk_ref:5,treatment_option:'Modify'}]});
 assert.equal(t.host.querySelectorAll('tbody tr').length,1);
 assert.match(t.host.querySelector('tbody').textContent,/Proposed · not accepted/);
});

test('implementation evaluation uses only the selected control identity',()=>{
 const t=setup();open(t);button(t.host,'Implementation evidence').click();
 assert.equal(t.actions[0].action,'profile_implementation');
 assert.deepEqual(t.actions[0].payload,{control_id:'A.8.8'});
 assert.equal(t.host.querySelector('.record-drawer'),null);
});

test('creation actions are limited to registers and assessment',()=>{
 const stages=['Treatment plan','Residual assessment','Risk acceptance','Monitoring & review'];
 for(const lifecycle of stages){
  const t=setup({mode:'risk_table',lifecycle,groups:[],rows:[],group:'all',actor:'owner',show_register_creation:false});
  assert.ok(![...t.host.querySelectorAll('button')].some(b=>/Add scenario|Add Risk Register/.test(b.textContent)),lifecycle);
 }
 const t=setup({mode:'risk_table',lifecycle:'Registers & assessment',groups:[],rows:[],group:'all',actor:'owner',show_register_creation:true});
 assert.ok(button(t.host,'Add scenario ⌄'));
 assert.ok(!button(t.host,'Add Risk Register'),'register creation belongs in the register list header');
});

test('register header creates a register using the existing dialog and event',()=>{
 const t=setup({mode:'risk_overview',groups:[],rows:[],is_admin:true,show_register_creation:true});
 button(t.host,'Add Risk Register').click();
 const name=t.host.querySelector('.modal input');name.value='Production';name.oninput();
 button(t.host,'Save register').click();
 assert.equal(t.actions[0].action,'group_save');
 assert.equal(t.actions[0].payload.name,'Production');
});

test('scope presents basic boundaries and distinct editor/history actions',()=>{
 const t=setup({mode:'foundation',section:'scope',selected:'scope',title:'ISMS Scope',description:'Controlled scope',add_label:'Add site or unit',columns:{name:'Boundary'},rows:[],scope:{id:9,name:'Production',locations:['Paris'],technologies:['Cloud'],latest_status:'Draft'}});
 assert.match(t.host.textContent,/Paris/);assert.match(t.host.textContent,/Cloud/);
 assert.ok(!button(t.host,'Previous'));
 button(t.host,'Edit scope').click();assert.equal(t.actions[0].action,'foundation_scope_edit');
 t.run({...t.data,response:{nonce:t.actions[0].nonce}});
 assert.ok(!t.host.textContent.includes('Saving / loading'));
 button(t.host,'Version history').click();assert.equal(t.actions[1].action,'foundation_history');
});

test('treatment acceptance and monitoring do not offer an irrelevant matrix',()=>{
 for(const lifecycle of ['Treatment plan','Risk acceptance','Monitoring & review']){
  const t=setup({mode:'risk_table',lifecycle,groups:[],rows:[],group:'all'});
  assert.ok(!button(t.host,'Matrix View'));assert.ok(!button(t.host,'Previous'));
 }
});
test('empty context has a useful action without empty filters or table',()=>{
 const t=setup({mode:'foundation',section:'context',title:'Context',description:'Issues',add_label:'Add issue',rows:[],columns:{title:'Issue'}});
 assert.equal(t.host.querySelector('table'),null);
 assert.equal(t.host.querySelector('.filters'),null);
 button(t.host,'+ Add issue').click();assert.equal(t.actions[0].action,'foundation_add');
});
test('single-page foundation retains records without pagination',()=>{
 const t=setup({mode:'foundation',section:'parties',title:'Interested parties',add_label:'Add party',rows:[{_row_key:'9',name:'Customer',applicable_requirement_count:0}],columns:{name:'Party',applicable_requirement_count:'Requirements'}});
 assert.equal(button(t.host,'Next'),undefined);
 assert.equal(t.host.querySelectorAll('tbody td')[1].textContent,'0');
 button(t.host,'View').click();assert.match(t.host.querySelector('.record-drawer').textContent,/Needs & expectations/);
 button(t.host,'Edit').click();assert.equal(t.actions[0].action,'foundation_edit');assert.equal(t.actions[0].payload.id,'9');
});
test('historical objective requires a visible explicit confirmation',()=>{
 const t=setup({mode:'foundation',section:'objectives',title:'Objectives',add_label:'Add objective',rows:[],columns:{title:'Objective'},fields:['title','due_date','evidence'],today:'2026-09-18'});
 button(t.host,'+ Add objective').click();const input=t.host.querySelector('input[type="date"]');input.value='2020-01-01';input.dispatchEvent(new t.dom.window.Event('input'));
 assert.match(t.host.textContent,/This due date is in the past/);
 const check=t.host.querySelector('select');check.value='historical';check.dispatchEvent(new t.dom.window.Event('change'));
 button(t.host,'Save draft version').click();assert.equal(t.actions[0].payload.historical,true);
});
