export default function({data, parentElement, setTriggerValue}) {
    const root = parentElement.querySelector('#monitoring-workbench');
    if (!root) return;
    if (root.__monitoringTimer) clearInterval(root.__monitoringTimer);
    const state = root.__monitoring?.workspace === data.workspace ? root.__monitoring :
        {workspace:data.workspace, query:'', filter:'', page:0, selected:null, section:'Overview'};
    root.__monitoring = state;
    const rows = Array.isArray(data.rows) ? data.rows : [];
    if (!rows.some(r => r.asset_id === state.selected)) state.selected = null;
    const labels = {verified:'Monitoring verified',active_unverified:'Agent active — telemetry unverified',
        stale:'Monitoring stale',disconnected:'Agent disconnected',registered:'Agent registered',
        source_unavailable:'Source unavailable',not_verified:'Not verified'};
    const el = (tag, text='', className='') => {
        const node = document.createElement(tag); node.textContent = text; node.className = className; return node;
    };
    const button = (text, action, className='') => {
        const node = el('button', text, className); node.type = 'button'; node.onclick = action; return node;
    };
    const source = r => r.source || {};
    const clockKey = `${data.workspace}:${data.evaluated_at}`;
    if (root.__evaluationClock?.key !== clockKey) root.__evaluationClock = {
        key:clockKey, server:Date.parse(data.evaluated_at), wall:Date.now(), mono:window.performance.now()
    };
    const clock = root.__evaluationClock;
    const presentationNow = () => Math.max(Date.now(), Number.isFinite(clock.server) ?
        clock.server + Math.max(0, Date.now()-clock.wall, window.performance.now()-clock.mono) : Infinity);
    const currentState = r => r.monitoring_state === 'verified' &&
        (!Number.isFinite(Date.parse(source(r).verified_until)) || Date.parse(source(r).verified_until) <= presentationNow()) ?
        'stale' : (labels[r.monitoring_state] ? r.monitoring_state : 'not_verified');
    const reason = r => currentState(r) !== r.monitoring_state ?
        'Verification expired while this view was open. Refresh status from Wazuh actions.' : r.monitoring_reason;
    const statusBadge = r => el('span', labels[currentState(r)], 'badge '+currentState(r));
    const timestamp = value => value && Number.isFinite(Date.parse(value)) ? new Date(value).toLocaleString() : 'Not available';
    const field = (label, value, mono=false) => {
        const group = el('div');group.append(el('dt',label),el('dd',value || 'Not available',mono?'mono':''));return group;
    };
    root.replaceChildren();
    const summary = el('div','','summary'); summary.setAttribute('aria-label','Workspace monitoring summary');
    const layout = el('div','','layout'), register = el('section','','register');
    const toolbar = el('div','','toolbar'), heading = el('div');
    heading.append(el('h3','Asset synchronization and monitoring'),
        el('p','Workspace inventory · approved ISMS scope is not inferred','muted'));
    const filters = el('div','','filters');
    const queryLabel = el('label','Search assets'), query = el('input');
    query.type='search';query.placeholder='Asset tag, address or agent ID';query.value=state.query;
    query.setAttribute('aria-label','Search monitoring assets'); queryLabel.append(query);
    const filterLabel = el('label','Monitoring state'), filter = el('select');
    filter.setAttribute('aria-label','Filter monitoring state');
    const all = el('option','All monitoring states');all.value='';filter.append(all);
    for (const [key,label] of Object.entries(labels)) {const option=el('option',label);option.value=key;filter.append(option);}
    filter.value=state.filter;filterLabel.append(filter);filters.append(queryLabel,filterLabel);
    toolbar.append(heading,filters);register.append(toolbar);
    const list = el('div'), footer = el('div','','pagination');register.append(list,footer);
    const inspector = el('aside','','inspector');inspector.setAttribute('aria-label','Monitoring evidence inspector');
    layout.append(register,inspector);root.append(summary,layout,
        el('p',`Workspace: ${data.workspace} · Source status read at ${timestamp(data.evaluated_at)}. Technical evidence does not approve ISO implementation or effectiveness.`,'footnote'));

    function renderSummary() {
        summary.replaceChildren();
        const verified=rows.filter(r=>currentState(r)==='verified').length;
        for (const [label,value] of [['Inventory assets',rows.length],['Monitoring verified',verified],['Requires review',rows.length-verified]]) {
            const item=el('div','','summary-item');item.append(el('strong',String(value)),el('span',label));summary.append(item);
        }
    }
    function closeInspector() {
        const identity=state.selected;state.selected=null;renderRows();renderInspector();
        root.querySelector(`[data-asset-id="${identity}"]`)?.focus();
    }
    function inspect(identity) {
        state.selected=identity;state.section='Overview';renderRows();renderInspector();
        inspector.querySelector('h3')?.focus();
        if (window.innerWidth <= 1100) inspector.scrollIntoView?.({block:'nearest'});
    }
    function renderRows() {
        const term=state.query.trim().toLocaleLowerCase();
        const selected=rows.filter(r=>(!state.filter || currentState(r)===state.filter) &&
            [r.asset_tag,r.asset_ip,r.asset_hostname,source(r).wazuh_agent_id,source(r).wazuh_agent_name]
                .join(' ').toLocaleLowerCase().includes(term))
            .sort((a,b)=>String(a.asset_tag).localeCompare(String(b.asset_tag),undefined,{numeric:true}) || a.asset_id-b.asset_id);
        const pages=Math.max(1,Math.ceil(selected.length/25));state.page=Math.min(state.page,pages-1);
        list.replaceChildren();footer.replaceChildren();
        if (!selected.length) {
            const message=rows.length?'No assets match these filters.':'No inventory assets are available in this workspace. Admit assets before collecting monitoring evidence.';
            list.append(el('p',message,'empty'));
            if(rows.length)list.append(button('Clear filters',()=>{state.query='';state.filter='';state.page=0;query.value='';filter.value='';renderRows();}));
        } else {
            const scroll=el('div','','table-scroll');scroll.setAttribute('role','region');scroll.setAttribute('aria-label','Asset monitoring table');
            const table=el('table'),thead=el('thead'),header=el('tr');
            const columns=['Asset','Agent / binding','Monitoring evidence','Last verified'];
            for(const label of columns){const th=el('th',label);th.scope='col';header.append(th);}
            thead.append(header);table.append(thead);const body=el('tbody');
            for (const item of selected.slice(state.page*25,state.page*25+25)) {
                const tr=el('tr','',item.asset_id===state.selected?'selected':'');
                const values=columns.map(label=>{const td=el('td');td.dataset.label=label;return td;});
                const asset=button(item.asset_tag,()=>inspect(item.asset_id),'asset-button');asset.dataset.assetId=item.asset_id;
                asset.setAttribute('aria-label',`Inspect ${item.asset_tag}`);asset.setAttribute('aria-expanded',String(item.asset_id===state.selected));
                const assetCell=el('div');assetCell.append(asset,el('div',item.asset_ip,'mono'),el('div',item.asset_hostname,'muted'));values[0].append(assetCell);
                const agentCell=el('div');agentCell.append(el('div',source(item).wazuh_agent_id?`Agent ${source(item).wazuh_agent_id}`:'No verified agent','mono'),
                    el('div',item.binding_status,'muted'),el('div',source(item).wazuh_status||'Connection unknown','muted'));values[1].append(agentCell);
                const statusCell=el('div');statusCell.append(statusBadge(item),el('div',reason(item),'reason'));values[2].append(statusCell);
                const time=el('div',timestamp(source(item).last_verified_at));time.title=source(item).last_verified_at||'';values[3].append(time);
                tr.append(...values);body.append(tr);
            }
            table.append(body);scroll.append(table);list.append(scroll);
        }
        const count=el('span',`${selected.length} of ${rows.length} assets · Page ${state.page+1} of ${pages}`,'muted');count.setAttribute('role','status');
        const controls=el('div','','pagination-controls');
        const previous=button('Previous',()=>{state.page--;renderRows();});previous.disabled=state.page===0;
        const next=button('Next',()=>{state.page++;renderRows();});next.disabled=state.page>=pages-1;
        controls.append(previous,next);footer.append(count,controls);
    }
    function renderInspector() {
        const item=rows.find(r=>r.asset_id===state.selected);
        inspector.hidden=!item;layout.classList.toggle('inspecting',Boolean(item));inspector.replaceChildren();
        if(!item)return;
        const top=el('div','','inspector-heading'),title=el('h3',item.asset_tag);title.tabIndex=-1;
        const close=button('Close',closeInspector);close.setAttribute('aria-label','Close monitoring inspector');top.append(title,close);
        inspector.append(top,statusBadge(item),el('p',reason(item),'notice'));
        const tabs=el('div','','tabs');tabs.setAttribute('role','group');tabs.setAttribute('aria-label','Inspector sections');
        for(const name of ['Overview','Provenance','Scope']) {
            const tab=button(name,()=>{state.section=name;renderInspector();[...inspector.querySelectorAll('.tabs button')].find(b=>b.textContent===name)?.focus();});
            tab.setAttribute('aria-pressed',String(state.section===name));tabs.append(tab);
        }
        inspector.append(tabs);const details=el('dl');
        if(state.section==='Overview') {
            for(const [label,value] of [['Asset ID',String(item.asset_id)],['Address',item.asset_ip],['Hostname',item.asset_hostname],
                ['Binding',item.binding_status],['Agent connection',source(item).wazuh_status],['Collection health',source(item).source_health],
                ['Last collection',source(item).collected_at],['Last heartbeat',source(item).wazuh_last_keep_alive],
                ['Last verified observation',source(item).last_verified_at],['Verified until',source(item).verified_until],
                ['Last security alert',source(item).last_alert_time],['Operating system',source(item).wazuh_os],['Last action',source(item).last_action]]) details.append(field(label,value));
            inspector.append(details,el('p','No security alerts does not mean monitoring is absent. Active agent status alone does not establish verified telemetry.','notice'));
        } else if(state.section==='Provenance') {
            for(const [label,value] of [['Connector',source(item).connector_id],['Manager',source(item).manager_name],['Agent ID',source(item).wazuh_agent_id],
                ['Binding ID',source(item).binding_id],['Identity method',source(item).match_type],['Observation SHA-256',source(item).payload_sha256],['Source key',source(item).source_key],
                ['Heartbeat max age (seconds)',source(item).heartbeat_max_age_seconds],['Telemetry max age (seconds)',source(item).telemetry_max_age_seconds]]) details.append(field(label,value,true));
            for(const [key,value] of Object.entries(item.telemetry||{})) if(value)details.append(field(key.replaceAll('_',' '),value,true));
            inspector.append(details,el('p','This hash identifies the retained monitoring observation. Canonical evidence artifact hashes and approved requirement mappings are reviewed in Evidence Register.','notice'));
        } else {
            details.append(field('Workspace',data.workspace),field('Inventory asset',String(item.asset_id)));
            inspector.append(details,el('p','This is a workspace inventory view. An agent binding does not establish approved ISMS scope membership. Review exact engagement, scope version and Control Profile attribution in Evidence Register.','notice'),
                el('p','ISO implementation, effectiveness, SoA approval and risk acceptance remain human decisions.','muted'));
        }
        inspector.append(button('Open Evidence Register',()=>setTriggerValue('action',{
            type:'open_evidence',asset_id:item.asset_id,workspace:data.workspace,nonce:crypto.randomUUID()
        })));
        inspector.append(el('p','Opens the workspace register; no asset filter is applied.','muted'));
    }
    query.oninput=()=>{state.query=query.value;state.page=0;renderRows();};
    filter.onchange=()=>{state.filter=filter.value;state.page=0;renderRows();};
    root.onkeydown=event=>{if(event.key==='Escape' && state.selected!==null){event.preventDefault();closeInspector();}};
    renderSummary();renderRows();renderInspector();
    let signature=rows.map(r=>currentState(r)).join('|');
    const timer=setInterval(()=>{
        if(!root.isConnected){clearInterval(root.__monitoringTimer);return;}
        const next=rows.map(r=>currentState(r)).join('|');
        if(next!==signature){signature=next;renderSummary();renderRows();renderInspector();}
    },1000);
    root.__monitoringTimer=timer;
    return ()=>clearInterval(timer);
}
