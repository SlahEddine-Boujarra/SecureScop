import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import test from 'node:test';

const {JSDOM}=createRequire(import.meta.url)(process.env.SECURESCOPE_JSDOM_PATH||'jsdom');
const source=readFileSync(new URL('../../src/securescope/ui/components_v2/assurance_workbench.js',import.meta.url),'utf8');

test('M3 separates advisory status and recorded decision and escapes source trace',()=>{
    const dom=new JSDOM('<div><main id="assurance-workbench"></main></div>');
    const host=dom.window.document.querySelector('div');
    const render=new Function('document','window',`return (${source.replace('export default','')});`)(dom.window.document,dom.window);
    const requirement={id:'criterion',title:'Approved header baseline',mandatory:true,rule:'Secure web configuration baseline',rule_version:3,
        result:'FAIL',freshness:'Current',reason:'Approved predicate matched',recommended_action:'Validate the finding and retest',
        result_layer:'Technical requirement check',expected_result:'Header required',group:'Technical',asset_ids:[42],
        expected_assets:[42],affected_assets:[42],missing_assets:[],profile_id:8,profile_version:3,scope_version_id:19,
        evidence_ids:[7],observations:[{evidence_id:7,check_id:'nuclei.web.configuration',rule_version:3,asset_id:42,
            observed_at:'2026-10-20T10:00:00Z',endpoint:'<img src=x onerror=alert(1)>'}],excluded_evidence:[]};
    const data={mode:'control_workspace',control_id:'A.8.9',title:'Configuration',scope:2,owner:'Reviewer',can_edit:false,
        documents:[],evidence:[],risks:[],actions:[],history:[],asset_labels:{42:'Approved asset'},
        result:{requirements:[requirement],implementation:'Implemented',advisory_implementation:'Not Implemented',
            human_assessment:{status:'Implemented and effective',validation_status:'Validated'},assurance:'Needs Review',
            satisfied:0,mandatory_count:1,evidence_coverage:100,automation_blockers:['Technical review required']}};
    render({data,parentElement:host,setTriggerValue:()=>{}});
    assert.match(host.textContent,/Implementation \(advisory\)/);
    assert.match(host.textContent,/Recorded human assessment: Implemented and effective/);
    [...host.querySelectorAll('button')].find(b=>b.textContent==='Resolve Next Gap').click();
    assert.match(host.textContent,/Validate the finding and retest/);
    assert.match(host.textContent,/nuclei.web.configuration v3/);
    assert.match(host.textContent,/Asset 42/);
    assert.equal(host.querySelector('img'),null);
});
