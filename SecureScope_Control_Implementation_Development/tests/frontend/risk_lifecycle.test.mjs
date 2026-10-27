import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {JSDOM}=require(process.env.SECURESCOPE_JSDOM_PATH||'jsdom');
const source=fs.readFileSync(new URL('../../src/securescope/ui/components_v2/assurance_workbench.js',import.meta.url),'utf8');
const {default:render}=await import('data:text/javascript;base64,'+Buffer.from(source).toString('base64'));
const scoring={levels:Object.fromEntries(Array.from({length:25},(_,i)=>[i+1,i<4?'Low':i<9?'Medium':i<16?'High':'Critical'])),likelihood:['Rare','Unlikely','Possible','Likely','Almost certain'],impact:['Insignificant','Minor','Moderate','Major','Severe']};
function setup(extra={}){
 const dom=new JSDOM('<div id="host"><main id="assurance-workbench"></main></div>');globalThis.document=dom.window.document;globalThis.window=dom.window;
 const host=document.querySelector('#host'),actions=[],data={mode:'risk_detail',can_edit:true,actor:'reviewer',members:[],groups:[{record_key:'default',payload:{name:'Default'}}],controls:[{control_id:'A.8.14',control_name:'Redundancy'}],asset_groups:['Software'],detail:{risk_ref:1,revision:1,group:'default',pre_likelihood:4,pre_impact:5,post_likelihood:2,post_impact:3},selected:1,revision:1,scoring,...extra};
 const run=(next=data)=>render({data:next,parentElement:host,setTriggerValue:(_,event)=>actions.push(event)});run();return {host,actions,data,run,dom};
}
const button=(t,label)=>[...t.host.querySelectorAll('button')].find(n=>n.textContent===label);
const field=(t,label)=>[...t.host.querySelectorAll('label.field')].find(n=>n.firstChild.textContent===label).querySelector('input,select,textarea');
test('seven visible workflow steps and live pre/post comparison share one draft',()=>{
 const t=setup();assert.equal(t.host.querySelectorAll('.risk-workflow>.card').length,8);
 assert.equal(t.host.querySelectorAll('.risk-workflow details').length,0);
 assert.match(t.host.textContent,/4 × 5 = 20 — Critical → 2 × 3 = 6 — Medium/);
 const input=field(t,'Likelihood');input.value='1';input.onchange();
 assert.match(t.host.textContent,/1 × 5 = 5 — Medium/);
 field(t,'Risk Summary').value='My risk';field(t,'Risk Summary').oninput();
 button(t,'Save Draft').click();assert.equal(t.actions[0].action,'risk_save');assert.equal(t.actions[0].payload.record.risk_ref,1);assert.equal(t.actions[0].payload.record.risk_summary,'My risk');assert.equal(t.actions[0].payload.record.post_impact,3);
});
test('matrix has 25 cells and distinct markers even for the same cell',()=>{
 const t=setup({detail:{risk_ref:2,pre_likelihood:3,pre_impact:4,post_likelihood:3,post_impact:4}});
 assert.equal(t.host.querySelectorAll('.matrix-cell').length,25);
 assert.match(t.host.querySelector('.matrix-cell.occupied').textContent,/●.*◆/);
 assert.match(t.host.querySelector('.matrix-cell.occupied').title,/Likelihood 3; Impact 4; Score 12; High/);
});
test('register matrix groups risks and opens the selected existing reference',()=>{
 const t=setup({mode:'risk_table',group:'default',rows:[{risk_ref:7,group:'default',pre_likelihood:3,pre_impact:4},{risk_ref:8,group:'default',pre_likelihood:3,pre_impact:4},{risk_ref:9,group:'default'}]});
 button(t,'Matrix View').click();const cell=t.host.querySelector('.matrix-cell.occupied');assert.equal(cell.textContent,'2 risks');cell.click();[...t.host.querySelectorAll('button')].find(b=>b.textContent.startsWith('R-8 · Untitled')).click();assert.equal(t.actions[0].action,'open');assert.equal(t.actions[0].payload.id,8);
});
test('completion is separate from save and read-only users cannot invoke either',()=>{
 let t=setup();button(t,'Complete Assessment').click();assert.equal(t.actions[0].action,'risk_complete');
 t=setup({can_edit:false});assert.ok(button(t,'Complete Assessment').disabled);assert.ok(button(t,'Save Draft').disabled);assert.ok(field(t,'Risk Summary').disabled);
});
test('timescale warning is non-blocking and blank progress remains null on save',()=>{
 const t=setup({detail:{risk_ref:1,revision:1,treatment_action_timescale:'90 days',treatment_action_status:'Not Started',treatment_progress_percent:null}});
 assert.match(t.host.textContent,/A timescale is set but no specific due\/review date has been recorded/);
 assert.match(t.host.textContent,/0%/);
 button(t,'Save Draft').click();
 assert.equal(t.actions[0].payload.record.treatment_progress_percent,null);
});
test('related treatments are read-only with linked references and individual control chips',()=>{
 const t=setup({mode:'related_treatments',status_labels:{'In progress':'In Progress'},rows:[{risk_ref:42,risk_summary:'Service loss',control_references:['A.5.2','A.5.24'],treatment_action_status:'In progress'}]});
 assert.equal(t.host.querySelectorAll('input,textarea,select').length,0);
 assert.equal(t.host.querySelectorAll('.chip').length,2);
 assert.match(t.host.textContent,/In Progress/);
 assert.equal(button(t,'Next'),undefined);
 button(t,'R-42').click();
 assert.equal(t.actions[0].action,'open_risk');
 assert.equal(t.actions[0].payload.id,42);
});
function controlData(extra={}) {
 return {mode:'control_workspace',control_id:'A.8.15',title:'Logging',scope:9,owner:'Security',can_edit:true,documents:[],evidence:[],risks:[],actions:[],history:[],result:{applicability:'Applicable',implementation:'Insufficient Evidence',assurance:'Needs Review',mandatory_count:1,satisfied:0,evidence_coverage:0,automation_blockers:['Mandatory evidence missing.'],requirements:[{id:'r1',title:'Logging policy',expected_result:'Document responsibilities',type:'Governance',group:'Policy / Governance',rule:'Approved policy',mandatory:true,result:'NO EVIDENCE',reason:'No approved policy',freshness:'Missing'}]},...extra};
}
test('control workspace exposes basic state and keeps requirement details in a drawer',()=>{
 const t=setup(controlData());assert.match(t.host.textContent,/Why this status/);assert.match(t.host.textContent,/Evidence/);
 assert.equal(t.host.querySelectorAll('[role=dialog]').length,0);
 button(t,'Resolve Next Gap').click();assert.ok(t.host.querySelector('.record-drawer'));
 assert.match(t.host.textContent,/Document responsibilities/);
 button(t,'Create Policy').click();assert.equal(t.actions[0].action,'requirement_policy');assert.equal(t.actions[0].payload.id,'r1');
});
test('control navigation and remediation retain canonical identifiers',()=>{
 const t=setup(controlData());button(t,'Resolve Next Gap').click();button(t,'Create Remediation').click();assert.equal(t.actions[0].action,'requirement_remediation');assert.equal(t.actions[0].payload.id,'r1');
 const risk=setup(controlData({risks:[{risk_ref:14,threat:'Undetected incidents',treatment_option:'Modify'}]}));button(risk,'Risks').click();button(risk,'Open Risk').click();assert.deepEqual(risk.actions[0].payload,{destination:'risk',id:14});
});
test('read-only control viewers cannot create policies or remediation',()=>{
 const t=setup(controlData({can_edit:false}));button(t,'Resolve Next Gap').click();assert.ok(button(t,'Create Policy').disabled);assert.ok(button(t,'Create Remediation').disabled);
});
test('missing evidence is neutral and explicit failures are red',()=>{
 const t=setup(controlData());const pill=[...t.host.querySelectorAll('.pill')].find(p=>p.textContent==='No Evidence');assert.ok(pill);assert.ok(!pill.classList.contains('red'));
});
test('control profile row opens a full workspace rather than lifecycle modal',()=>{
 const t=setup({mode:'control_profiles',full_workspace:true,rows:[{control_id:'A.8.15',control_name:'Logging',summary:{Control:'A.8.15',Title:'Logging'}}]});t.host.querySelector('tbody tr').click();assert.equal(t.actions[0].action,'profile_implementation');assert.equal(t.actions[0].payload.control_id,'A.8.15');assert.equal(t.host.querySelectorAll('.record-drawer').length,0);
});
test('an overdue objective can explicitly remain current',()=>{
 const t=setup({mode:'foundation',section:'objectives',title:'Objectives',add_label:'Add objective',rows:[],columns:{title:'Objective'},fields:['title','due_date'],today:'2026-09-19'});
 button(t,'+ Add objective').click();const date=t.host.querySelector('input[type=date]');date.value='2020-01-01';date.oninput();const intent=t.host.querySelector('select');intent.value='current';intent.onchange();button(t,'Save draft version').click();assert.equal(t.actions[0].payload.date_intent,'current');assert.equal(t.actions[0].payload.historical,false);
});
test('requirement table uses readable states and explicit failure color',()=>{
 const d=controlData();d.result.requirements[0].result='FAIL';
 const t=setup(d);const pill=[...t.host.querySelectorAll('.pill')].find(p=>p.textContent==='Fail');
 assert.ok(pill?.classList.contains('red'));
 assert.ok([...t.host.querySelectorAll('th')].some(h=>h.textContent==='Requirement'));
});


test('next gap prioritizes required policy before an earlier missing evidence row',()=>{
 const data=controlData();const policy=data.result.requirements[0];
 data.result.requirements=[{...policy,id:'missing',title:'Scan evidence',rule:'Recent vulnerability scan'},policy];
 const t=setup(data);button(t,'Resolve Next Gap').click();
 assert.match(t.host.querySelector('.record-drawer').textContent,/Logging policy/);
 button(t,'Link Existing Policy').click();assert.equal(t.actions[0].payload.id,'r1');
});
test('canonical remediation ID survives cross-module navigation',()=>{
 const t=setup(controlData({actions:[{id:27,status:'Open',priority:'High',recommended_action:'Fix logs',action_owner:'Security'}]}));
 button(t,'Remediation').click();button(t,'Open Remediation').click();
 assert.deepEqual(t.actions[0].payload,{destination:'remediation',id:27});
});

test('control header actions use existing configuration and requirement dispatch',()=>{
 const t=setup(controlData());
 assert.equal(t.host.querySelectorAll('.control-metrics>div').length,4);
 assert.equal(t.host.querySelectorAll('.control-tabs button').length,7);
 button(t,'Edit Configuration').click();assert.equal(t.actions[0].action,'control_configure');
 const u=setup(controlData());button(u,'Add Requirement').click();assert.equal(u.actions[0].action,'requirement_edit');
});

test('profile table removes Type and renders semantic status badges',()=>{
 const t=setup({mode:'control_profiles',full_workspace:true,rows:[{control_id:'A.8.16',control_name:'Monitoring',summary:{Control:'A.8.16',Title:'Monitoring',Type:'Annex A Control',Applicability:'Pending',Implementation:'Partially Implemented',Assurance:'Needs Review','Open gaps':2}}]});
 const headers=[...t.host.querySelectorAll('th')].map(n=>n.textContent);
 assert.ok(!headers.includes('Type'));
 assert.equal(headers.indexOf('Open gaps'),headers.indexOf('Assurance')+1);
 assert.equal(t.host.querySelectorAll('td .pill.orange').length,4);
 t.host.querySelector('tbody tr').click();assert.equal(t.actions[0].payload.control_id,'A.8.16');
});
