import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import test from 'node:test';
import {webcrypto} from 'node:crypto';

const {JSDOM}=createRequire(import.meta.url)(process.env.SECURESCOPE_JSDOM_PATH||'jsdom');
const script=readFileSync(new URL('../../src/securescope/ui/components_v2/monitoring_workbench.js',import.meta.url),'utf8');
function fixture(overrides={}) {
    const dom=new JSDOM('<div id="host"><section id="monitoring-workbench"></section></div>');
    const document=dom.window.document,host=document.querySelector('#host'),events=[];
    const rows=Array.from({length:31},(_,i)=>({asset_id:i+1,asset_tag:`ASSET-${i+1}`,asset_ip:`192.0.2.${i+1}`,asset_hostname:'',
        monitoring_state:'active_unverified',monitoring_reason:'No qualifying telemetry',binding_status:'Approved binding',
        source:{wazuh_agent_id:String(i+1).padStart(3,'0'),wazuh_status:'active',source_key:`source-${i+1}`},telemetry:{}}));
    let data={workspace:'Alpha',evaluated_at:new Date().toISOString(),rows,...overrides};
    const render=new Function('document','window','crypto',`return (${script.replace('export default','')});`)(document,dom.window,webcrypto);
    let dispose;
    const run=next=>{dispose?.();if(next)data=next;dispose=render({data,parentElement:host,setTriggerValue:(key,value)=>events.push(value)});};
    run();return {host,dom,events,data,run,close:()=>{dispose?.();dom.window.close();}};
}
const button=(f,text)=>[...f.host.querySelectorAll('button')].find(b=>b.textContent===text);

test('M4 table pages by stable asset ID and opens actual row provenance',()=>{
    const f=fixture();try {
        assert.equal(f.host.querySelectorAll('tbody tr').length,25);
        button(f,'Next').click();button(f,'ASSET-31').click();
        assert.match(f.host.querySelector('aside').textContent,/ASSET-31/);
        button(f,'Provenance').click();assert.match(f.host.querySelector('aside').textContent,/source-31/);
        button(f,'Open Evidence Register').click();assert.equal(f.events[0].asset_id,31);assert.equal(f.events[0].workspace,'Alpha');
    } finally {f.close();}
});
test('M4 search retains keyboard focus and state across same-workspace renders',()=>{
    const f=fixture();try {
        const input=f.host.querySelector('input');input.focus();input.value='ASSET-31';input.dispatchEvent(new f.dom.window.Event('input'));
        assert.equal(f.dom.window.document.activeElement,input);assert.equal(f.host.querySelectorAll('tbody tr').length,1);
        f.run();assert.equal(f.host.querySelector('input').value,'ASSET-31');
        assert.equal(f.host.querySelectorAll('tbody tr').length,1);
    } finally {f.close();}
});
test('M4 workspace switch clears filters, paging and selected details',()=>{
    const f=fixture();try {
        button(f,'ASSET-1').click();
        f.run({...f.data,workspace:'Beta',rows:[]});
        assert.equal(f.host.querySelector('aside').hidden,true);
        assert.match(f.host.textContent,/No inventory assets/);
        assert.doesNotMatch(f.host.textContent,/ASSET-1/);
    } finally {f.close();}
});
test('M4 source text stays inert and escape returns focus to the asset button',()=>{
    const f=fixture();try {
        f.data.rows[0].asset_tag='<img src=x onerror=alert(1)>';
        f.run();f.host.querySelector('[data-asset-id="1"]').click();
        assert.equal(f.host.querySelector('img'),null);
        f.host.querySelector('aside h3').dispatchEvent(new f.dom.window.KeyboardEvent('keydown',{key:'Escape',bubbles:true}));
        assert.equal(f.host.querySelector('aside').hidden,true);
        assert.equal(f.dom.window.document.activeElement.dataset.assetId,'1');
    } finally {f.close();}
});
test('M4 filters distinguish empty results from empty inventory and never infer monitoring from active',()=>{
    const f=fixture();try {
        const select=f.host.querySelector('select');select.value='verified';select.dispatchEvent(new f.dom.window.Event('change'));
        assert.match(f.host.textContent,/No assets match these filters/);
        assert.match(f.host.querySelector('.summary').textContent,/0Monitoring verified/);
        button(f,'Clear filters').click();assert.equal(f.host.querySelectorAll('tbody tr').length,25);
    } finally {f.close();}
});
test('M4 expired observation cannot remain current while inspector stays open',async()=>{
    const f=fixture();try {
        f.data.rows[0].monitoring_state='verified';f.data.rows[0].source.verified_until=new Date(Date.now()+200).toISOString();
        f.run();button(f,'ASSET-1').click();await new Promise(resolve=>setTimeout(resolve,1100));
        assert.match(f.host.querySelector('aside').textContent,/Verification expired/);
        assert.match(f.host.querySelector('.summary').textContent,/0Monitoring verified/);
    } finally {f.close();}
});
test('M4 a browser clock behind the server cannot prolong verification',async()=>{
    const serverNow=Date.now()+3600000;
    const f=fixture({evaluated_at:new Date(serverNow).toISOString()});try {
        f.data.rows[0].monitoring_state='verified';
        f.data.rows[0].source.verified_until=new Date(serverNow+200).toISOString();
        f.run();button(f,'ASSET-1').click();
        await new Promise(resolve=>setTimeout(resolve,1100));
        assert.match(f.host.querySelector('aside').textContent,/Verification expired/);
        f.run();assert.match(f.host.querySelector('.summary').textContent,/0Monitoring verified/);
    } finally {f.close();}
});
