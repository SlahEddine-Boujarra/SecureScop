/** SecureScope workbench. All user text enters the DOM through textContent. */
export default function ({data, parentElement, setTriggerValue}) {
    const root = parentElement.querySelector('#assurance-workbench');
    const state = parentElement.__workbench ??= {tab:0, query:'', filters:{}, page:0, section:0, dirty:false, view:'Overview'};
    const signature = [data.mode, data.selected, data.detail?.policy_version, data.detail?.revision, data.detail?.meta_revision].join(':');
    if (state.signature !== signature) {
        state.signature=signature; state.tab=0; state.section=0; state.dirty=false;
        state.document=structuredClone(data.detail?.blocks ?? []); state.risk=structuredClone(data.detail ?? {});
        state.undoStack=[structuredClone(state.document)];state.redoStack=[];state.generated={}; state.edited={}; state.reviewed=structuredClone(data.detail?.reviewed_sections||{});
    }
    if(!state.dirty&&data.detail?.asset_ids){state.risk.asset_ids=structuredClone(data.detail.asset_ids);state.risk.missing_asset_ips=structuredClone(data.detail.missing_asset_ips||[]);}
    if(data.response?.nonce !== state.responseNonce){
        state.responseNonce=data.response?.nonce; state.busy=false;
        if(data.response?.download && !data.response.error && !(state.downloadNonces??=new Set()).has(data.response.nonce)){
            state.downloadNonces.add(data.response.nonce);
            const file=data.response.download;
            try {
                const bytes=Uint8Array.from(atob(file.content_base64),c=>c.charCodeAt(0));
                const url=URL.createObjectURL(new Blob([bytes],{type:file.mime}));
                const anchor=document.createElement('a');anchor.href=url;anchor.download=file.filename;
                root.append(anchor);anchor.click();anchor.remove();
                setTimeout(()=>URL.revokeObjectURL(url),1000);
            } catch(error) {
                data.response={...data.response,error:'Document download could not be started. Please retry.'};
            }
        }
    }
    const el=(tag, text='', cls='')=>{const n=document.createElement(tag); if(text!==null)n.textContent=String(text);if(cls)n.className=cls;return n;};
    const row=(...nodes)=>{const n=el('div','','row');n.append(...nodes.filter(Boolean));return n;};
    const btn=(label, fn, cls='', disabled=false)=>{const b=el('button',label,cls);if(label.startsWith('←'))b.classList.add('back-link');b.type='button';b.disabled=disabled||!!state.busy;b.onclick=fn;return b;};
    const send=(action,payload={})=>{if(state.busy)return;state.busy=true;setTriggerValue('action',{action,payload,nonce:globalThis.crypto?.randomUUID?.()??`${Date.now()}-${Math.random()}`,expected:data.revision,meta_expected:data.detail?.meta_revision??0,selected:data.selected});render();};
    const text=(block)=>block.runs.map(r=>r.text).join('');
    const statusLabel=value=>data.status_labels?.[value]||value;
    const pill=(label)=>{const value=statusLabel(label)||'Unassigned';const tone=['OK','Approved','Complete','Completed','Pass','PASS','Effective','Implemented'].includes(value)?'green':['Fail','FAIL','Ineffective','Not Implemented','Critical'].includes(value)?'red':['Partial','PARTIAL','Needs Review','Expiring Soon','Stale','Partially Implemented','Insufficient Evidence','Pending'].includes(value)?'orange':['In review','Pending approval','Automated','Applicable'].includes(value)?'blue':'';return el('span',value,`pill ${tone}`);};
    const avatar=(name)=>{const n=el('span',(name||'?').split(/[ .@]/).filter(Boolean).slice(0,2).map(w=>w[0]).join('').toUpperCase(),'avatar');n.title=name||'Unassigned';return n;};
    const card=(title,subtitle='')=>{const c=el('section','','card'),body=el('div','','card-body');body.append(el('h3',title));if(subtitle)body.append(el('small',subtitle));c.append(body);return {card:c,body};};
    const select=(options,value,change)=>{const n=el('select');for(const option of options){const v=Array.isArray(option)?option:[option,option];const o=el('option',v[1]);o.value=v[0]??'';n.append(o);}n.value=value??'';n.onchange=()=>change(n.value);return n;};
    const field=(label,value,change,type='text',options=null)=>{const wrap=el('label',label,'field');const n=options?select(options,value,change):el(type==='textarea'?'textarea':'input');if(!options){if(type!=='textarea')n.type=type;n.value=value??'';n.oninput=()=>change(n.value);}wrap.append(n);return wrap;};
    const sectionBar=(labels,current,onchange,kind='tabs')=>{
        const nav=el('nav','','section-navigation'),rail=el('div','',kind);nav.setAttribute('aria-label','Section navigation');
        const back=btn('‹',()=>rail.scrollBy({left:-240,behavior:globalThis.matchMedia?.('(prefers-reduced-motion: reduce)')?.matches?'auto':'smooth'}),'tab-scroll'),forward=btn('›',()=>rail.scrollBy({left:240,behavior:globalThis.matchMedia?.('(prefers-reduced-motion: reduce)')?.matches?'auto':'smooth'}),'tab-scroll');
        back.setAttribute('aria-label','Scroll sections left');forward.setAttribute('aria-label','Scroll sections right');
        labels.forEach((label,i)=>{const b=btn(label,()=>onchange(i),i===current?'active':'');b.setAttribute('aria-pressed',String(i===current));
            const icon=document.createElementNS('http://www.w3.org/2000/svg','svg');icon.setAttribute('viewBox','0 0 24 24');icon.setAttribute('aria-hidden','true');icon.classList.add('section-icon');
            for(const [x,y] of [[3,3],[14,3],[3,14],[14,14]]){const square=document.createElementNS('http://www.w3.org/2000/svg','rect');for(const [k,v] of Object.entries({x,y,width:7,height:7,rx:1}))square.setAttribute(k,String(v));icon.append(square);}b.prepend(icon);rail.append(b);});
        nav.append(back,rail,forward);
        const update=()=>{const overflow=rail.scrollWidth>rail.clientWidth+1;back.hidden=forward.hidden=!overflow;back.disabled=rail.scrollLeft<=1;forward.disabled=rail.scrollLeft+rail.clientWidth>=rail.scrollWidth-1;};
        rail.addEventListener('scroll',update);queueMicrotask(update);
        if(typeof ResizeObserver!=='undefined'){const observer=new ResizeObserver(()=>{if(!nav.isConnected){observer.disconnect();return;}update();});observer.observe(rail);(state.navigationObservers??=[]).push(observer);}
        return nav;
    };
    const tabs=(labels,onchange)=>sectionBar(labels,state.tab,i=>{state.tab=i;onchange();});
    const modal=(title,body,actions=[])=>{root.querySelector('.modal-backdrop')?.remove();const bg=el('div','','modal-backdrop'),box=el('section','','modal');box.setAttribute('role','dialog');box.setAttribute('aria-modal','true');box.setAttribute('aria-label',title);const close=()=>{bg.remove();root.querySelector('button')?.focus();};const close_button=btn('×',close);close_button.setAttribute('aria-label','Close');close_button.title='Close';const header=row(el('h2',title),close_button);header.classList.add('between');box.append(header,body);const footer=row(...actions,btn('Cancel',close));footer.style.marginTop='22px';box.append(footer);bg.append(box);root.append(bg);box.tabIndex=-1;box.focus();bg.onkeydown=e=>{if(e.key==='Escape')close();if(e.key==='Tab'){const all=[...box.querySelectorAll('button,input,select,textarea,a')].filter(n=>!n.disabled);const index=all.indexOf(box.getRootNode().activeElement);if(e.shiftKey&&index<=0){e.preventDefault();all.at(-1)?.focus();}else if(!e.shiftKey&&index===all.length-1){e.preventDefault();all[0]?.focus();}}};};
    const menu=(label,items,primary=false)=>{const anchor=el('div','','menu-anchor');anchor.append(btn(label,()=>{const prior=anchor.querySelector('.menu');if(prior){prior.remove();return;}const m=el('div','','menu');items.forEach(([text,action,disabled])=>m.append(btn(text,()=>{m.remove();action();},'',disabled)));anchor.append(m);},primary?'primary':''));return anchor;};
    const leave=(action,payload={})=>{if(!state.dirty){send(action,payload);return;}modal('Unsaved changes',el('p','Save your changes first, or discard them to leave this document.'),[btn('Discard changes',()=>{state.dirty=false;send(action,payload);})]);};
    function uploadDialog(kind='policy'){
        const body=el('div');body.append(el('p',kind==='policy'?'Upload DOCX, TXT or Markdown. Each upload becomes a draft for review (maximum 2 MiB).':'Import a risk register JSON export. A preview appears before any records are saved.'));
        const input=el('input');input.type='file';input.accept=kind==='policy'?'.docx,.txt,.md':'.json';body.append(input);let file;
        input.onchange=()=>{file=input.files[0];};
        modal(kind==='policy'?'Import policy':'Import scenarios',body,[btn('Preview / upload',()=>{if(!file){body.append(el('p','Choose a file.','error'));return;}if(file.size>2*1024*1024){body.append(el('p','File exceeds 2 MiB.','error'));return;}const reader=new FileReader();reader.onload=()=>send(kind==='policy'?'upload':'import_preview',{filename:file.name,content:String(reader.result).split(',')[1]});reader.onerror=()=>body.append(el('p','The file could not be read.','error'));reader.readAsDataURL(file);},'primary',!data.can_edit)]);
    }
    function templateDialog(){const body=el('div');let name=data.templates?.[0];body.append(field('Choose a policy',name,v=>name=v,'text',data.templates||[]),el('p','Suggestions are draft wording. Tailor the content and scope before approval.','muted'));modal('Create policy from a template',body,[btn('Create draft',()=>send('template',{name}),'primary',!data.can_edit)]);}
    function metadataDialog(){const draft=structuredClone(data.detail);const body=el('div');for(const [key,label] of [['title','Policy name'],['purpose','Description'],['owner','Owner'],['review_date','Renew by'],['renewal_cadence','Renewal cadence']])body.append(field(label,draft[key],v=>draft[key]=v,key==='review_date'?'date':'text'));modal('Edit policy details',body,[btn('Save draft details',()=>send('policy_metadata',{metadata:draft}),'primary',!data.can_edit)]);}
    function approvalDialog(){const body=el('div');let names=[...(data.detail.approvers||[])],due=data.detail.review_date||'',note='';body.append(el('p','Select the Administrators who must approve this saved version. Each approval is recorded separately.'));for(const member of data.members.filter(m=>m.role==='Administrator')){const check=el('input');check.type='checkbox';check.checked=names.includes(member.email);check.onchange=()=>names=check.checked?[...names,member.email]:names.filter(n=>n!==member.email);const label=el('label','','row');label.append(check,el('span',member.email));body.append(label);}body.append(field('Renew by',due,v=>due=v,'date'),field('Submission note',note,v=>note=v,'textarea'));modal('Assign approvers and submit',body,[btn('Submit saved version',()=>send('policy_submit',{approvers:names,review_date:due,note}),'primary',!data.can_edit)]);}
    function noteDialog(title,action,payload={}){let note='';const body=field('Review note',note,v=>note=v,'textarea');modal(title,body,[btn('Confirm',()=>send(action,{...payload,note}),'primary')]);}
    function policyList(){
        const h=el('header','','head row between');h.append(el('h1','Policies'),menu('Add policy ⌄',[['Create from a template',templateDialog,!data.can_edit],['Import policy',()=>uploadDialog(),!data.can_edit]],true));root.append(h);
        const views=el('div','','row views');['All','Needs my approval','Needs approval','Needs reassignment'].forEach(label=>views.append(btn(label,()=>{state.view=label;state.page=0;render();},state.view===label?'active':'')));root.append(views);
        const filters=el('div','','filters'),search=el('input');search.placeholder='Search by name';search.setAttribute('aria-label','Search policies');search.value=state.query;search.oninput=()=>{state.query=search.value;state.page=0;renderTable();};filters.append(search);
        for(const [key,label,options] of [['overall','Overall status',['OK','Needs remediation','Draft','Expired']],['latest','Latest version',['Draft','In review','Approved','Archived']],['approver','Approver',data.members.map(m=>m.email)],['framework','Framework',['ISO/IEC 27001']],['source','Source',['Uploaded','Created in SecureScope']]])filters.append(select([['',label],...options],state.filters[key],v=>{state.filters[key]=v;state.page=0;renderTable();}));filters.append(btn('Reset view',()=>{state.filters={};state.query='';state.view='All';state.page=0;render();},'link'));root.append(filters);
        const holder=el('div');root.append(holder);
        function renderTable(){holder.replaceChildren();const rows=data.rows.filter(r=>{const a=r.approvers||[r.reviewer].filter(Boolean);return r.title.toLowerCase().includes(state.query.toLowerCase())&&(!state.filters.overall||r.overall===state.filters.overall)&&(!state.filters.latest||r.status===state.filters.latest)&&(!state.filters.approver||a.includes(state.filters.approver))&&(!state.filters.framework||r.controls.length)&&(!state.filters.source||(r.source_name?'Uploaded':'Created in SecureScope')===state.filters.source)&&((!['Needs my approval','Needs approval','Needs reassignment'].includes(state.view))||(state.view==='Needs approval'&&r.status==='In review')||(state.view==='Needs my approval'&&r.status==='In review'&&a.includes(data.actor)&&!r.approvals?.[data.actor])||(state.view==='Needs reassignment'&&(!r.owner||!a.length)));});
            const table=el('table','','wb-table'),head=el('tr');['Name','Overall status','Renew by','Latest version','Approvers','Approval status','Framework',''].forEach(x=>head.append(el('th',x)));const thead=el('thead');thead.append(head);table.append(thead);const tbody=el('tbody');
            rows.slice(state.page*15,state.page*15+15).forEach(r=>{const tr=el('tr');tr.tabIndex=0;tr.onkeydown=e=>{if(e.key==='Enter')send('open',{id:r.policy_id});};tr.onclick=()=>send('open',{id:r.policy_id});const cell=(content,cls='')=>{const td=el('td','',cls);td.append(typeof content==='string'?document.createTextNode(content):content);tr.append(td);};cell(r.title,'name');cell(pill(r.overall));cell(r.review_date||'—');cell(pill(r.status==='In review'?'Pending approval':r.status));const approvers=row(...(r.approvers||[r.reviewer].filter(Boolean)).map(avatar));cell(approvers);cell(r.approval_label||'—');cell(el('span',r.controls.length?`ISO 27001 · ${r.controls.length} controls`:'Not mapped','chip'));cell(btn('⋯',e=>{}));tr.lastChild.firstChild.onclick=e=>{e.stopPropagation();send('open',{id:r.policy_id});};tbody.append(tr);});table.append(tbody);const wrap=el('div','','table-wrap');wrap.append(table);holder.append(wrap);if(!rows.length)holder.append(el('div','No matching policies. Use Add policy to create a tailored draft.','empty'));const foot=el('div','','footer');foot.append(el('span',`${rows.length?state.page*15+1:0}–${Math.min(rows.length,(state.page+1)*15)} of ${rows.length} policies`));if(rows.length>15)foot.append(row(btn('‹',()=>{state.page--;renderTable();},'',state.page===0),btn('›',()=>{state.page++;renderTable();},'',(state.page+1)*15>=rows.length)));holder.append(foot);
        }renderTable();
    }
    function policyDetail(){const d=data.detail;root.append(btn('← Back to Policies',()=>leave('back'),'link'));const header=el('header','','head'),top=row(el('h1',d.title),row(menu('⋯',[['Download Word',()=>send('export',{format:'docx'})],['Download PDF',()=>send('export',{format:'pdf'})],['Archive policy',()=>noteDialog('Archive policy','policy_archive'),!data.is_admin]]),btn('♙',approvalDialog,'',!data.can_edit),btn('✎ Edit details',metadataDialog,'',!data.can_edit)));top.classList.add('between');header.append(top,el('p',d.purpose||'Tailor this policy to your organization.','muted'),row(pill(d.overall),el('small',`↻ ${d.renewal_cadence||'Renewal not set'}`),el('small',`☷ Frameworks (${d.controls?.length||0})`)));root.append(header,tabs(['Policy versions','Mapped elements','Audits','Comments'],render));
        if(state.tab===0){const stack=el('div','','version-stack');root.append(stack);const current=card(d.status==='Approved'?'Current approved version':'Draft version','Created in SecureScope');const titleNode=current.body.querySelector('h3');const titleRow=row(el('span','✎','icon-box'),titleNode);current.body.prepend(titleRow);const actions=row(btn('Assign approvers and submit',approvalDialog,'',!data.can_edit||!['Draft','Suggested'].includes(d.status)),menu('⋯',[['Download Word',()=>send('export',{format:'docx'})]]));current.body.append(actions);const file=row(row(el('span','▤'),(()=>{const label=el('div');label.append(el('strong','English'),el('small',`Last edited by ${d.updated_by||d.owner||'Unassigned'}`));label.className='file-label';return label;})()),btn('Edit',()=>send('edit'),'primary',!data.can_edit));file.classList.add('between','document-row');current.body.append(file);current.card.append(el('footer',d.status==='In review'?`Pending approval · ${d.approval_label}`:d.status==='Approved'?'Approved':'Approval not started','card-footer'));stack.append(current.card);
            if(d.status==='In review'&&data.is_admin&&(d.approvers||[]).includes(data.actor)&&!d.approvals?.[data.actor])stack.append(btn('Approve saved version',()=>noteDialog('Approve policy','policy_approve'),'primary'));
            if(data.approved){const approved=card(`Approved version: ${data.approved.approved_at?.slice(0,10)||''}`,'Created in SecureScope');const file=row(el('span',`▤ English · Version ${data.approved.policy_version}`),btn('View',()=>documentModal(data.approved)));file.classList.add('between','document-row');approved.body.append(file);approved.card.append(row(btn('Show approval',()=>{const body=el('div');Object.entries(data.approved.approvals||{[data.approved.approved_by]:'Recorded'}).forEach(([name,details])=>body.append(el('p',`${name} · ${typeof details==='object'?details.at:details}`)));modal('Approval history',body);},'link')));stack.append(approved.card);}else stack.append(el('p','No approved version yet.','muted'));
        }else if(state.tab===1){const c=card('Mapped controls','Mappings support traceability; they do not establish implementation.');for(const id of d.controls)c.body.append(row(btn(id,()=>send('open_control',{control_id:id}),'chip'),el('span',data.controls.find(x=>x.control_id===id)?.control_name||'')));c.body.append(btn('Edit control mappings',()=>mappingDialog(),'primary',!data.can_edit));root.append(c.card);
        }else if(state.tab===2){root.append(el('h2','Audits'));for(const link of data.links||[])root.append(el('div',data.audits.find(a=>a.id===link.payload.audit_id)?.audit_no||String(link.payload.audit_id),'register'));if(!data.links?.length)root.append(el('div','No audits linked to this policy.','empty'));let id=data.audits[0]?.id;root.append(row(select(data.audits.map(a=>[a.id,a.audit_no]),id,v=>id=Number(v)),btn('Link audit',()=>send('link_audit',{audit_id:id}),'',!data.can_edit||!id)));
        }else comments();
    }
    function mappingDialog(){let ids=[...(data.detail.controls||[])];const body=el('div');for(const c of data.controls){const check=el('input');check.type='checkbox';check.checked=ids.includes(c.control_id);check.onchange=()=>ids=check.checked?[...ids,c.control_id]:ids.filter(x=>x!==c.control_id);const label=row(check,el('span',`${c.control_id} · ${c.control_name}`));body.append(label);}modal('Mapped ISO controls',body,[btn('Save mappings',()=>send('policy_metadata',{metadata:{...data.detail,controls:ids}}),'primary',!data.can_edit)]);}
    function appendBlock(container,block,editable=false,index=null){const tag={h1:'h1',h2:'h2',h3:'h3',p:'p',bullet:'li',number:'li'}[block.kind]||'p';const node=el(tag);for(const run of block.runs){let n=el(run.bold?'strong':run.italic?'em':'span',run.text);if(run.bold&&run.italic){const inner=el('em',run.text);n.replaceChildren(inner);}node.append(n);}if(editable){node.contentEditable=String(data.can_edit);node.dataset.blockIndex=index;node.setAttribute('role','textbox');node.setAttribute('aria-label',`Document paragraph ${index+1}`);node.oninput=()=>{const runs=[];function walk(n,b=false,i=false){if(n.nodeType===3)runs.push({text:n.textContent,bold:b,italic:i});else{for(const child of n.childNodes)walk(child,b||['B','STRONG'].includes(n.nodeName),i||['I','EM'].includes(n.nodeName));if(n!==node&&['BR','DIV'].includes(n.nodeName))runs.push({text:'\n',bold:b,italic:i});}}walk(node);state.document[index]={kind:block.kind,runs};state.edited[index]=true;for(const section of sections()){if(section.indices.includes(index))state.reviewed[section.title]=false;}state.dirty=true;rememberEdit();};node.onpaste=e=>{e.preventDefault();const selection=root.getRootNode().getSelection?.()??window.getSelection();if(!selection?.rangeCount)return;const range=selection.getRangeAt(0);if(!node.contains(range.commonAncestorContainer))return;range.deleteContents();const n=document.createTextNode((e.clipboardData||e.dataTransfer).getData('text/plain'));range.insertNode(n);range.setStartAfter(n);range.collapse(true);selection.removeAllRanges();selection.addRange(range);node.dispatchEvent(new Event('input'));};node.ondrop=node.onpaste;}container.append(node);return node;}
    function documentModal(d){const body=el('div');for(const block of d.blocks)appendBlock(body,block);modal('Saved approved document',body);}
    function sections(){const result=[];state.document.forEach((b,index)=>{if(b.kind.startsWith('h')||!result.length)result.push({title:b.kind.startsWith('h')?text(b):'Introduction',start:index,indices:[]});result.at(-1).indices.push(index);});return result;}
    function rememberEdit(){const snapshot=structuredClone(state.document);if(JSON.stringify(state.undoStack.at(-1))!==JSON.stringify(snapshot)){state.undoStack.push(snapshot);if(state.undoStack.length>100)state.undoStack.shift();state.redoStack=[];}updateSaveStatus();}
    function historyEdit(redo=false){if(redo){if(!state.redoStack.length)return;const next=state.redoStack.pop();state.undoStack.push(structuredClone(next));state.document=next;}else{if(state.undoStack.length<2)return;state.redoStack.push(state.undoStack.pop());state.document=structuredClone(state.undoStack.at(-1));}state.dirty=true;render();}
    function formatSelection(kind){const selection=root.getRootNode().getSelection?.()??window.getSelection();if(!selection?.rangeCount)return;const range=selection.getRangeAt(0),node=range.commonAncestorContainer.nodeType===3?range.commonAncestorContainer.parentElement:range.commonAncestorContainer;const paragraph=node.closest('[contenteditable="true"]');if(!paragraph||!root.contains(paragraph))return;if(['bold','italic'].includes(kind)&&!range.collapsed){const wrapper=document.createElement(kind==='bold'?'strong':'em');wrapper.append(range.extractContents());range.insertNode(wrapper);range.selectNodeContents(wrapper);selection.removeAllRanges();selection.addRange(range);paragraph.dispatchEvent(new Event('input'));}else if(['p','h1','h2','h3','bullet','number'].includes(kind)){const index=Number(paragraph.dataset.blockIndex);state.document[index].kind=kind;state.dirty=true;rememberEdit();render();}}
    function updateSaveStatus(){const n=root.querySelector('[data-save-status]');if(n)n.textContent=state.dirty?'Unsaved changes':'Saved version';}
    function builder(){const d=data.detail;root.append(btn('← Back to Policy',()=>leave('detail'),'link'));const layout=el('div','','builder'),guide=el('section','','guide'),paper=el('section','','paper-stack');layout.append(guide,paper);layout.classList.add('document-editor');if(state.hideGuide){guide.hidden=true;layout.style.gridTemplateColumns='1fr';}root.append(layout);const all=sections();state.section=Math.min(state.section,all.length-1);const current=all[state.section];if(!current){root.append(el('p','This document has no editable sections.'));return;}
        guide.append(el('div',`Policies / ${d.title} / Policy Builder`,'crumb'),el('h1',current.title),el('p','Select suggestions and tailor the wording to your organization.','muted'));
        guide.append(select(all.map((s,i)=>[i,s.title]),state.section,v=>{state.section=Number(v);render();}));const guidance=el('details','','guidance');guidance.append(el('summary','Need to make edits? View guidance for this section'));const inside=el('div','','inside');inside.append(el('h3','ISO/IEC 27001:2022 editing guidance'),el('p','Define requirements appropriate to your scope and assessed risks. Confirm ownership, operation, exceptions and evidence before approval.'),el('small','Related controls'));for(const cid of d.controls||[])inside.append(el('span',cid,'chip'));inside.append(el('p','Suggestions are editable guidance, not a statement that this control is implemented.','muted'));guidance.append(inside);guide.append(guidance);
        const question=el('div','','question');question.append(el('h3',`What requirements apply to ${current.title.toLowerCase()}?`),el('p','Select a suggestion to insert it. Edit the document on the right. Your unrelated wording is preserved.','muted'));const options=data.guidance[current.title]||data.default_guidance||[];let group='';options.forEach(option=>{if(option.group!==group){group=option.group;question.append(el('h3',group));}const check=el('input');check.type='checkbox';check.disabled=!data.can_edit;const matching=current.indices.find(i=>state.document[i].kind==='bullet'&&text(state.document[i])===option.text);check.checked=matching!==undefined;check.onchange=()=>{if(check.checked){state.document.splice(current.indices.at(-1)+1,0,{kind:'bullet',runs:[{text:option.text}]});}else if(matching!==undefined){state.document.splice(matching,1);}state.dirty=true;rememberEdit();render();};const label=el('label');label.append(check,el('span',option.text));question.append(label);});guide.append(question);const confirm=el('input');confirm.type='checkbox';confirm.checked=!!state.reviewed[current.title];confirm.disabled=!data.can_edit;confirm.onchange=()=>{state.reviewed[current.title]=confirm.checked;state.dirty=true;render();};guide.append(row(confirm,el('span','I have tailored and reviewed this section.')));
        all.forEach((section,sectionIndex)=>{const page=el('article','',`paper ${sectionIndex===state.section?'active':''}`);const heading=row(el('small','Document section'),row(btn('✎ Edit',()=>{state.section=sectionIndex;render();},'link'),el('small',state.reviewed[section.title]?'✓ Completed':'Needs review')));heading.classList.add('between');page.append(heading);for(const index of section.indices){appendBlock(page,state.document[index],true,index);}page.append(btn('+ Paragraph',()=>{state.document.splice(section.indices.at(-1)+1,0,{kind:'p',runs:[{text:'New paragraph'}]});state.dirty=true;rememberEdit();render();},'link',!data.can_edit));paper.append(page);});
        const toolbar=el('div','','toolbar');toolbar.append(btn('Undo',()=>historyEdit(false),'',!data.can_edit),btn('Redo',()=>historyEdit(true),'',!data.can_edit));const style=select([['','Format'],['p','Paragraph'],['h2','Heading'],['bullet','Bullet list'],['number','Numbered list']],'',v=>formatSelection(v));style.disabled=!data.can_edit;toolbar.append(style,btn(state.hideGuide?'Show suggestions':'Hide suggestions',()=>{state.hideGuide=!state.hideGuide;render();},'link'));const status=el('span',state.dirty?'Unsaved changes':'Saved version');status.dataset.saveStatus='true';toolbar.append(status,row(btn('Previous',()=>{state.section--;render();},'',state.section===0),btn('Next',()=>{state.section++;render();},'',state.section>=all.length-1),btn('Save draft',()=>send('policy_save',{blocks:state.document,metadata:{...d,reviewed_sections:state.reviewed}}),'primary',!data.can_edit)));layout.before(toolbar);
    }
    function comments(){root.append(el('h2','Comments'));for(const c of data.comments||[]){const box=card(c.updated_by,String(c.created_at));if(c.payload.parent)box.body.append(el('small','Reply to an earlier comment'));box.body.append(el('p',c.payload.body||''),btn('Reply',()=>commentDialog(c.record_key),'link',!data.can_edit));root.append(box.card);}if(!data.comments?.length)root.append(el('div','No comments yet. Record a question or review decision.','empty'));root.append(btn('Add comment',()=>commentDialog(''),'primary',!data.can_edit));}
    function commentDialog(parent){let body='';modal('Comment',field('Your comment',body,v=>body=v,'textarea'),[btn('Post comment',()=>send('comment',{body,parent}),'primary',!data.can_edit)]);}
    function score(value){return el('span',value??'?',`score ${value==null?'':value<=4?'low':value<=9?'medium':value<=16?'high':'critical'}`);}
    function groupDialog(group=null){let name=group?.payload.name||'',description=group?.payload.description||'';const body=el('div');body.append(field('Register name',name,v=>name=v),field('Description',description,v=>description=v,'textarea'));modal(group?'Edit register details':'Create risk register',body,[btn('Save register',()=>send('group_save',{key:group?.record_key||'',revision:group?.revision||0,name,description}),'primary',!data.is_admin)]);}
    function accessDialog(){const body=el('div');body.append(el('p','This register inherits the client workspace memberships. Manage grants in Programme Foundation → Workspace access.'));data.members.forEach(m=>body.append(row(avatar(m.email),el('span',m.email),pill(m.role))));modal('Register access',body);}
    function riskOverview(){
        root.classList.add('enterprise-workbench');
        const top=row(el('h1','Risk registers'));
        if(data.show_register_creation!==false)top.append(btn('Add Risk Register',()=>groupDialog(),'primary',!data.is_admin));
        top.classList.add('between');root.append(top,el('p','Choose a register to assess scenarios, then follow treatment and review.','muted'));
        const bar=row(btn('All scenarios',()=>send('register',{group:'all'})),btn('Assigned to me',()=>send('register',{group:'all',owned:true})),menu('Export / snapshot',[['Export assessment data (JSON)',()=>send('risk_export')],['Create dated snapshot',()=>noteDialog('Create a saved risk snapshot','snapshot'),!data.can_edit]]));
        const search=el('input');search.placeholder='Search risk registers';search.setAttribute('aria-label','Search risk registers');bar.prepend(search);bar.classList.add('filters');root.append(bar);
        const holder=el('div','','table-wrap');root.append(holder);
        function draw(){
            holder.replaceChildren();const table=el('table','','wb-table register-grid'),head=el('thead'),header=el('tr'),body=el('tbody');
            ['Register','Purpose / scope','Scenarios','Actions'].forEach(label=>header.append(el('th',label)));head.append(header);table.append(head,body);
            for(const g of data.groups.filter(g=>(g.payload.name+' '+(g.payload.description||'')).toLowerCase().includes(search.value.toLowerCase()))){
                const tr=el('tr'),name=el('td'),actions=el('td'),count=data.rows.filter(r=>r.group===g.record_key).length;
                name.append(btn(g.payload.name,()=>send('register',{group:g.record_key}),'link'));
                actions.append(menu('Manage',[['Edit register details',()=>groupDialog(g),!data.is_admin||g.record_key==='default'],['Manage access',accessDialog],['Delete register',()=>{let confirmed=false;const check=el('input');check.type='checkbox';check.onchange=()=>confirmed=check.checked;modal('Delete empty register',row(check,el('span','I confirm deletion of this empty register.')),[btn('Delete register',()=>send('group_delete',{key:g.record_key,revision:g.revision,confirmed}),'danger')]);},!data.is_admin||g.record_key==='default'||count>0]]));
                tr.append(name,el('td',g.payload.description||'No purpose recorded'),el('td',count),actions);body.append(tr);
            }
            holder.append(table);if(!body.children.length)holder.append(el('p','No registers match your search.','empty'));
        }
        search.oninput=draw;draw();
    }
    function riskTable(){
        root.classList.add('enterprise-workbench');
        root.append(btn('← Back to Risk Registers',()=>send('back'),'link'));
        const stage=data.lifecycle||'Registers & assessment', group=data.groups.find(g=>g.record_key===data.group);
        const top=row(el('h1',stage==='Registers & assessment'?(group?.payload.name||'All risk scenarios'):stage));if(stage==='Registers & assessment')top.append(menu('Add scenario ⌄',[['Blank scenario',()=>send('risk_new'),!data.can_edit],['Create from a template',riskTemplateDialog,!data.can_edit],['Import from a file',()=>uploadDialog('risk'),!data.can_edit]],true));
        top.classList.add('between');root.append(top);

        const search=el('input');search.placeholder='Search risks, assets or owners';search.setAttribute('aria-label','Search risk scenarios');search.value=state.query;
        const holder=el('div'),viewBar=row(btn('Table View',()=>{state.matrixView=false;draw();}),btn('Matrix View',()=>{state.matrixView=true;draw();}));const matrixAllowed=['Registers & assessment','Residual assessment'].includes(stage);if(matrixAllowed)root.append(viewBar);const filters=row(search,select([['','All assessment states'],'Draft','In review','Approved'],state.filters.status,v=>{state.filters.status=v;state.page=0;draw();}),btn('Reset',()=>{search.value='';state.query='';state.filters.status='';state.page=0;render();}));filters.classList.add('filters');root.append(filters,holder);
        const base=[['risk_ref','ID'],['threat','Risk scenario'],['risk_owner','Owner']];
        const extra=stage==='Treatment plan'?[['treatment_option','Treatment'],['treatment_action_status','Progress'],['treatment_due_date','Due Date'],['treatment_action_timescale','Timescale']]:stage==='Residual assessment'?[['pre_risk_score','Inherent'],['post_risk_score','Residual'],['residual_verified','Verification']]:stage==='Monitoring & review'?[['review_due','Review due'],['review_state','Assessment'],['treatment_action_status','Treatment']]:stage==='Risk acceptance'?[['post_risk_score','Residual'],['acceptance','Acceptance'],['review_due','Review due']]:[['pre_risk_score','Inherent'],['treatment_option','Treatment'],['post_risk_score','Residual'],['completion_state','Assessment']];
        function draw(){
            holder.replaceChildren();const rows=data.rows.filter(r=>(data.group==='all'||r.group===data.group)&&(!data.owned||r.risk_owner===data.actor)&&`${r.risk_ref} ${r.risk_summary||''} ${r.threat} ${r.asset} ${r.risk_owner}`.toLowerCase().includes(state.query.toLowerCase())&&(!state.filters.status||r.review_state===state.filters.status)&&(stage!=='Risk acceptance'||r.treatment_option==='Accept'||['Accept residual risk','Escalate for approval'].includes(r.residual_decision)));
            if(state.matrixView&&matrixAllowed){
                const prefix=state.matrixPrefix||'pre',list=el('div');
                holder.append(select([['pre','Inherent Risk'],['post','Residual Risk']],prefix,value=>{state.matrixPrefix=value;draw();}));
                holder.append(riskMatrix(rows,prefix,false,matches=>{list.replaceChildren(el('h3',`${matches.length} risks in this cell`));for(const r of matches)list.append(btn(`R-${r.risk_ref} · ${r.risk_summary||r.threat||'Untitled'} · ${r.risk_owner||'Unassigned owner'} · ${riskLabel(r,prefix)}`,()=>send('open',{id:r.risk_ref}),'register'));}),list);
                holder.append(el('p',`${rows.filter(r=>riskValue(r,prefix)===null).length} risks lack complete ratings and are not plotted. Residual positions are planned estimates unless separately verified.`,'muted'));return;
            }
            state.page=Math.min(state.page,Math.max(0,Math.ceil(rows.length/20)-1));
            const table=el('table','',`wb-table simple-risk-grid ${stage==='Registers & assessment'?'risk-register-main':''}`),thead=el('thead'),head=el('tr'),body=el('tbody');
            for(const [,label] of [...base,...extra]){const th=el('th',label);th.scope='col';head.append(th);}thead.append(head);table.append(thead);
            for(const r of rows.slice(state.page*20,(state.page+1)*20)){
                const tr=el('tr');tr.tabIndex=0;tr.setAttribute('aria-label',`Open risk R-${r.risk_ref}`);tr.onclick=()=>send('open',{id:r.risk_ref});tr.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();tr.click();}};
                for(const [key] of [...base,...extra]){const td=el('td');let value=key==='threat'?(r.risk_summary||r.threat):r[key];if(key==='risk_ref')value=`R-${value}`;if(key==='completion_state')value=r.completion_state==='Completed'?'Completed · approval separate':'Draft';if(key==='acceptance')value='Proposed · not accepted';if(key==='residual_verified')value=value?'Verified record':'Planned estimate';td.append(key.endsWith('_score')?score(value):el('span',value||'—'));tr.append(td);}body.append(tr);
            }
            table.append(body);const wrap=el('div','','table-wrap');wrap.tabIndex=0;wrap.setAttribute('aria-label','Risk scenarios');wrap.append(table);holder.append(wrap);
            if(!rows.length)holder.append(el('p','No risks match this view. Adjust the filters or add a scenario.','empty'));
            const foot=el('div','','footer');foot.append(el('span',`${rows.length} risks`));if(rows.length>20)foot.append(row(btn('Previous',()=>{state.page--;draw();},'',state.page===0),btn('Next',()=>{state.page++;draw();},'',(state.page+1)*20>=rows.length)));if(rows.length)holder.append(foot);
        }search.oninput=()=>{state.query=search.value;state.page=0;draw();};draw();
    }

    function riskTemplateDialog(){const body=el('div');for(const [index,r] of data.templates.entries())body.append(btn(r.threat||r.asset||`Template ${index+1}`,()=>send('risk_template',{index}),'register'));modal('Choose a risk scenario template',body);}
    function taskDialog(task=null){const p={title:'',owner:data.actor,status:'Not started',due:'',...(task?.payload||{})};const body=el('div');body.append(field('Task',p.title,v=>p.title=v),field('Owner',p.owner,v=>p.owner=v),field('Due date',p.due,v=>p.due=v,'date'),field('Status',p.status,v=>p.status=v,'text',['Not started','In progress','Complete']));modal('Treatment task',body,[btn('Save task',()=>send('task_save',{key:task?.record_key||'',revision:task?.revision||0,...p}),'primary',!data.can_edit)]);}
    function riskLevel(value){return value==null?'Not assessed':(data.scoring?.levels?.[String(value)]||'Not assessed');}
    function riskValue(r,prefix){const l=Number(r[`${prefix}_likelihood`]),i=Number(r[`${prefix}_impact`]);return l>=1&&l<=5&&i>=1&&i<=5?l*i:null;}
    function riskLabel(r,prefix){const value=riskValue(r,prefix);return value===null?'Not assessed':`${r[`${prefix}_likelihood`]} × ${r[`${prefix}_impact`]} = ${value} — ${riskLevel(value)}`;}
    function riskMatrix(records,prefix='pre',both=false,onCell=null){
        const wrap=el('div','','risk-matrix-wrap'),table=el('table','','risk-matrix');table.setAttribute('aria-label',both?'Pre-treatment and residual risk matrix':`${prefix==='pre'?'Inherent':'Residual'} risk matrix`);
        const head=el('tr');head.append(el('th','Likelihood ↓ / Impact →'));for(let i=1;i<=5;i++)head.append(el('th',`${i} · ${data.scoring?.impact?.[i-1]||i}`));table.append(head);
        for(let l=5;l>=1;l--){const tr=el('tr');tr.append(el('th',`${l} · ${data.scoring?.likelihood?.[l-1]||l}`));for(let i=1;i<=5;i++){
            const td=el('td'),level=riskLevel(l*i),matches=records.filter(r=>Number(r[`${prefix}_likelihood`])===l&&Number(r[`${prefix}_impact`])===i),residual=both?records.filter(r=>Number(r.post_likelihood)===l&&Number(r.post_impact)===i):[];
            const mark=both?`${matches.length?'●':''}${residual.length?' ◆':''}`:(matches.length?`${matches.length} risk${matches.length===1?'':'s'}`:'');
            const cell=btn(mark||String(l*i),()=>{if(onCell)onCell(matches);},`matrix-cell ${matches.length||residual.length?'occupied':''}`);
            cell.style.backgroundColor=data.risk_colors?.[level]||'var(--wb-muted)';cell.title=[`Likelihood ${l}; Impact ${i}; Score ${l*i}; ${level}`,...matches.map(r=>`● R-${r.risk_ref} · ${r.risk_summary||r.threat||'Untitled'} · ${r.risk_owner||'Unassigned owner'} · ${riskLabel(r,prefix)}`),...residual.map(r=>`◆ R-${r.risk_ref} · ${r.risk_summary||r.threat||'Untitled'} · ${r.risk_owner||'Unassigned owner'} · ${riskLabel(r,prefix)}`)].join('\n');cell.setAttribute('aria-label',cell.title);td.append(cell);tr.append(td);
        }table.append(tr);}const legend=el('div','','risk-legend');for(const [level,color] of Object.entries(data.risk_colors||{})){const item=el('span',level,'chip');item.style.borderLeft=`12px solid ${color}`;legend.append(item);}wrap.append(legend,table,el('p',both?'● Pre-treatment   ◆ Residual — planned / unverified':'Select an occupied cell to inspect its risks.','muted'));return wrap;
    }
    function riskDetail(){
        root.classList.add('enterprise-workbench');
        const d=state.risk;
        const timescaleNotice=el('p','','notice');
        d.risk_summary??=d.threat||'';d.risk_description??=d.vulnerability||'';
        const save=()=>send('risk_save',{record:d});
        const header=row(btn('← Back to register',()=>leave('register'),'link'),btn('Save Draft',save,'primary',!data.can_edit));header.classList.add('between');root.append(header,el('h1',d.risk_summary||`Risk R-${d.risk_ref}`));
        const saveState=el('p',state.dirty?'Unsaved changes':(d.completion_state||'Draft'));saveState.dataset.saveStatus='true';root.append(saveState,tabs(['Assessment workflow','Impacted assets','Approval history','Comments'],render));
        if(state.tab===3){comments();return;}
        if(state.tab===2){for(const r of data.reviews||[])root.append(el('div',`${r.created_at} · ${r.updated_by} · ${r.payload.state} · ${r.payload.notes||''}`,'register'));if(!data.reviews?.length)root.append(el('p','No recorded review events yet.','empty'));return;}
        if(state.tab===1){
            root.append(el('h2','Impacted assets'),el('p','Select discovered inventory assets, then Save Draft.','muted'));if(d.missing_asset_ips?.length)root.append(el('p',`Previously linked assets absent from inventory: ${d.missing_asset_ips.join(', ')}. Their links are retained.`,'notice'));
            const search=el('input');search.placeholder='Search asset tag or IP';search.setAttribute('aria-label','Search impacted assets');const assets=el('div');root.append(search,assets);search.oninput=()=>{for(const label of assets.children)label.hidden=!label.textContent.toLowerCase().includes(search.value.toLowerCase());};const chosen=new Set(d.asset_ids||[]);for(const a of data.assets||[]){const input=el('input');input.type='checkbox';input.checked=chosen.has(a.id);input.disabled=!data.can_edit;input.onchange=()=>{input.checked?chosen.add(a.id):chosen.delete(a.id);d.asset_ids=[...chosen];state.dirty=true;updateSaveStatus();};const label=el('label','','row');label.append(input,el('span',`${a.asset_tag||'Untagged'} · ${a.ip}`));assets.append(label);}if(!data.assets?.length)root.append(el('p','No saved inventory assets are available.','empty'));return;
        }
        const layout=el('div','','risk-workflow'),statusNodes=[],scoreNodes=[],matrices=[],review=el('div');root.append(layout);
        let refresh=()=>{};
        const edit=(label,key,type='text',options=null)=>{const node=field(label,d[key],value=>{d[key]=(type==='number'||key==='primary_scope_id'||/_(likelihood|impact)$/.test(key))?(value===''?null:Number(value)):value;state.dirty=true;updateSaveStatus();refresh();},type,options);const input=node.querySelector('input,textarea,select');input.disabled=!data.can_edit;if(type==='number'){input.min='0';if(key==='treatment_progress_percent'){input.max='100';input.step='1';}}return node;};
        const section=(number,title,description,keys)=>{const c=card(`${number}. ${title}`,description),status=pill('Not Started');statusNodes.push({status,keys,number});c.body.prepend(status);layout.append(c.card);return c.body;};
        const controls=(key,label)=>{const block=el('section','','control-picker');block.append(el('h3',label));const selected=new Set(d[key]||[]),summary=el('p',selected.size?Array.from(selected).join(', '):'No controls selected','muted'),search=el('input'),list=el('div','','control-options');search.placeholder='Search Control Profiles';search.setAttribute('aria-label',label);block.append(summary,search,list);
            function draw(){list.replaceChildren();for(const c of data.controls.filter(c=>`${c.control_id} ${c.control_name}`.toLowerCase().includes(search.value.toLowerCase()))){const input=el('input');input.type='checkbox';input.checked=selected.has(c.control_id);input.disabled=!data.can_edit;input.onchange=()=>{input.checked?selected.add(c.control_id):selected.delete(c.control_id);d[key]=Array.from(selected);summary.textContent=d[key].join(', ')||'No controls selected';state.dirty=true;updateSaveStatus();refresh();};const label=el('label','','row');label.append(input,el('span',`${c.control_id} · ${c.control_name}`));list.append(label);}}search.oninput=draw;draw();return block;};
        const description=section(1,'Risk Description','Identify the scenario and the existing safeguards.',['risk_summary','risk_description','risk_owner','asset','threat','vulnerability']);
        description.append(el('p',`Reference: R-${d.risk_ref}`));const identity=el('div','','risk-field-grid');identity.append(edit('Primary ISMS Scope','primary_scope_id','text',[['','Unassigned scope'],...(data.scopes||[]).map(s=>[s.id,`${s.name} · ${s.engagement_name}${s.archived?" · Archived":""}`])]),edit('Risk Summary','risk_summary'),edit('Risk Owner','risk_owner'),edit('Category','category'),edit('Risk Description','risk_description','textarea'),edit('Register','group','text',data.groups.map(g=>[g.record_key,g.payload.name])),edit('Asset Group','asset_group','text',[['','Select asset group'],...data.asset_groups]),edit('Asset','asset'),edit('Threat','threat','textarea'),edit('Vulnerability','vulnerability','textarea'),edit('Risk Type','risk_type','text',[['','Select risk type'],['C','Confidentiality'],['I','Integrity'],['A','Availability'],['CIA','Confidentiality, integrity and availability']]),edit('Existing Controls — description','existing_controls','textarea'));description.append(identity,controls('existing_control_references','Existing Control Profiles'));
        function assessment(prefix,number,title){const body=section(number,title,prefix==='pre'?'Assess current exposure before the proposed treatment.':'Estimate risk after treatment. Completion does not verify that treatment is operating.',[`${prefix}_likelihood`,`${prefix}_impact`,`${prefix}_likelihood_rationale`,`${prefix}_impact_rationale`]),grid=el('div','','risk-field-grid'),formula=el('strong','','risk-formula');formula.setAttribute('aria-live','polite');scoreNodes.push({formula,prefix});for(const name of ['likelihood','impact']){grid.append(edit(`${prefix==='post'?'Post-Treatment ':''}${name==='likelihood'?'Likelihood':'Impact'}`,`${prefix}_${name}`,'text',[['','Not assessed'],...Array.from({length:5},(_,i)=>[i+1,`${i+1} — ${data.scoring?.[name]?.[i]||i+1}`])]),edit(`${name==='likelihood'?'Likelihood':'Impact'} Rationale`,`${prefix}_${name}_rationale`,'textarea'));}body.append(formula,grid);}
        assessment('pre',2,'Pre-Treatment Assessment');
        const treatment=section(3,'Treatment Plan','Assign controls, delivery responsibility and progress to this same scenario.',['treatment_option','treatment_action_owner','treatment_due_date']),treatmentGrid=el('div','','risk-field-grid');treatmentGrid.append(edit('Treatment Option','treatment_option','text',[['','Choose treatment'],['Modify','Mitigate / Modify'],['Avoid','Avoid'],['Transfer / Share','Transfer / Share'],['Accept','Accept']]),edit('Proposed Treatment Action','treatment_action','textarea'),edit('Treatment Cost','treatment_cost','number'),edit('Treatment Action Owner','treatment_action_owner'),edit('Treatment / Review Due Date','treatment_due_date','date'),edit('Treatment Action Timescale','treatment_action_timescale'),edit('Treatment Progress (%)','treatment_progress_percent','number'),edit('Progress Notes','treatment_action_progress','textarea'),edit('Treatment Action Status','treatment_action_status','text',['Not Started','In Progress','Completed','Blocked','Cancelled','Rejected',...(d.treatment_action_status==='Accepted risk'?['Accepted risk']:[])]));treatment.append(treatmentGrid,controls('control_references','Treatment Controls / Annex A References'));for(const id of d.control_references||[])treatment.append(btn(`Open ${id}`,()=>{if(state.dirty){modal('Save changes first',el('p','Save or discard this risk draft before opening the control.'));return;}send('open_control',{control_id:id});},'link'));for(const task of data.tasks||[])treatment.append(row(pill(task.payload.status),el('span',`${task.payload.title} · ${task.payload.owner} · ${task.payload.due||'No due date'}`),btn('Edit task',()=>taskDialog(task),'link',!data.can_edit)));treatment.append(btn('Create treatment task',()=>taskDialog(),'',!data.can_edit||!d.revision));
        assessment('post',4,'Post-Treatment Assessment');
        const matrix=section(5,'Risk Matrix / Comparison','Compare pre-treatment and residual positions using the same scoring rules.',['pre_likelihood','pre_impact','post_likelihood','post_impact']),comparison=el('strong','','risk-formula'),matrixHolder=el('div');matrix.append(comparison,matrixHolder);matrices.push(matrixHolder);
        const conclusion=section(6,'Assessment Conclusion','Record a recommendation. Accept residual risk is an intent, not formal acceptance.',['assessment_conclusion','residual_decision']);conclusion.append(edit('Comments','comments','textarea'),edit('Assessment conclusion','assessment_conclusion','textarea'),edit('Residual risk decision','residual_decision','text',[['','Choose a decision'],'Accept residual risk','Additional treatment required','Escalate for approval']),el('p','Risk appetite is not configured. Compare the remaining exposure with your approved criteria; formal risk-owner acceptance is not recorded by this form.','notice'));
        const finish=section(7,'Review & Complete','Save incomplete work at any point. Complete Assessment validates fields but does not approve or formally accept the risk.',['assessment_conclusion','residual_decision']);finish.append(review,row(btn('Save Draft',save,'',!data.can_edit),btn('Complete Assessment',()=>send('risk_complete',{record:d}),'primary',!data.can_edit)));
        refresh=()=>{timescaleNotice.textContent=d.treatment_action_timescale&&!d.treatment_due_date&&!d.review_due?'A timescale is set but no specific due/review date has been recorded.':'';timescaleNotice.hidden=!timescaleNotice.textContent;for(const {status,keys,number} of statusNodes){const n=keys.filter(k=>d[k]!=null&&String(d[k]).trim()!=='').length;status.textContent=n===keys.length?'Completed':n?'In Progress':'Not Started';if(number===3)status.textContent=d.treatment_action_status==='Blocked'?'Requires Attention':d.treatment_action_status==='Completed'&&Number(d.treatment_progress_percent)===100?'Completed':n?'In Progress':'Not Started';if(number===7)status.textContent=state.dirty?'Requires Attention':d.completion_state==='Completed'?'Completed':'In Progress';}for(const {formula,prefix} of scoreNodes)formula.textContent=riskLabel(d,prefix);comparison.textContent=`${riskLabel(d,'pre')} → ${riskLabel(d,'post')}`;for(const holder of matrices){holder.replaceChildren(riskMatrix([d],'pre',true));}review.replaceChildren(detailSection('Assessment summary',[['Risk',`R-${d.risk_ref} · ${d.risk_summary||'Untitled'}`],['Pre-treatment',riskLabel(d,'pre')],['Treatment',`${d.treatment_action||d.treatment_option||'Not recorded'} · ${d.treatment_action_owner||'Unassigned'} · due ${d.treatment_due_date||'Not set'} · ${d.treatment_progress_percent??(String(d.treatment_action_status).toLowerCase()==='not started'?0:'—')}%`],['Residual',riskLabel(d,'post')+' · planned / unverified'],['Controls',(d.control_references||[]).join(', ')],['Saved completion',d.completion_state||'Draft']]));};layout.append(timescaleNotice);refresh();
        const approval=card('Review / Approval',d.review_state||'Draft');approval.body.append(el('p',`Assigned approver: ${d.approver||'Unassigned'}`),btn('Assign approver and submit',()=>{if(state.dirty){modal('Save first',el('p','Save changes before submitting the saved revision.'));return;}let approver=d.approver||'',due=d.review_due||'';const body=el('div');body.append(field('Approver',approver,v=>approver=v,'text',[['','Select Administrator'],...data.members.filter(m=>m.role==='Administrator').map(m=>m.email)]),field('Review due',due,v=>due=v,'date'));modal('Submit for approval',body,[btn('Submit saved revision',()=>send('risk_submit',{approver,review_due:due}),'primary')]);},'',!data.can_edit||!d.revision));if(data.is_admin&&d.review_state==='In review'&&d.approver===data.actor)approval.body.append(btn('Approve saved revision',()=>noteDialog('Approve risk assessment','risk_approve'),'primary',state.dirty));layout.append(approval.card);
    }

    function calendarView(){
        root.classList.add('calendar-workbench');state.month??=new Date().toISOString().slice(0,7);state.day??=new Date().toISOString().slice(0,10);const [year,month]=state.month.split('-').map(Number),first=new Date(year,month-1,1),count=new Date(year,month,0).getDate();const top=row(el('h1','Calendar'),row(btn('‹',()=>changeMonth(-1)),btn('Today',()=>{state.month=new Date().toISOString().slice(0,7);state.day=new Date().toISOString().slice(0,10);render();}),btn('›',()=>changeMonth(1))));top.classList.add('between');root.append(top,el('p','Plan client work and review upcoming deadlines. Appointment times are UTC.','muted'),el('h2',first.toLocaleDateString('en',{month:'long',year:'numeric'})));
        let filter=state.calendarClient||'';root.append(select([['','All accessible clients'],...data.clients.map(c=>[c.name,c.name])],filter,v=>{state.calendarClient=v;render();}));const events=data.events.filter(e=>!filter||e.client===filter),grid=el('div','','month-grid');['Sun','Mon','Tue','Wed','Thu','Fri','Sat'].forEach(d=>grid.append(el('strong',d,'day-label')));for(let i=0;i<first.getDay();i++)grid.append(el('div'));for(let day=1;day<=count;day++){const date=`${state.month}-${String(day).padStart(2,'0')}`,entries=events.filter(e=>e.starts_at.slice(0,10)===date),tile=btn('',()=>{state.day=date;state.dayOpen=true;render();},`date-tile ${date===state.day?'selected':''}`);tile.setAttribute('aria-label',`${date}, ${entries.length} events`);tile.append(el('strong',day));for(const event of entries.slice(0,3))tile.append(el('span',`${event.client} · ${event.title}`,'calendar-event'));if(entries.length>3)tile.append(el('small',`+${entries.length-3} more`));grid.append(tile);}root.append(grid);
        if(state.dayOpen){const panel=el('section','','day-panel'),heading=row(el('h2',new Date(state.day+'T12:00:00').toLocaleDateString('en',{weekday:'long',month:'long',day:'numeric',year:'numeric'})),btn('×',()=>{state.dayOpen=false;render();}));heading.classList.add('between');panel.append(heading);const entries=events.filter(e=>e.starts_at.slice(0,10)===state.day);panel.append(row(el('h3',`Events (${entries.length})`),btn('+ Add',()=>calendarEdit(),'primary',!data.clients.some(c=>['Administrator','Consultant','Client contributor'].includes(c.role)))));if(!entries.length)panel.append(el('p','No events on this day.','muted'));for(const event of entries){const box=card(event.title,`${event.client} · ${event.source}`);box.body.append(el('p',event.starts_at),el('p',event.notes||''),row(btn('Open client workspace',()=>send('calendar_open',{client:event.client})),event.source==='Manual'?btn('Edit',()=>calendarEdit(event),'',!data.clients.some(c=>c.name===event.client&&['Administrator','Consultant','Client contributor'].includes(c.role))):null));panel.append(box.card);}root.append(panel);}
        function changeMonth(delta){const next=new Date(year,month-1+delta,1);state.month=`${next.getFullYear()}-${String(next.getMonth()+1).padStart(2,'0')}`;render();}
        function calendarEdit(event=null){const editable=data.clients.filter(c=>['Administrator','Consultant','Client contributor'].includes(c.role));const p={client:event?.client||(editable.find(c=>c.name===data.client)||editable[0])?.name,title:event?.title||'',starts_at:event?.starts_at?.slice(0,16)||state.day+'T09:00',notes:event?.notes||'',type:event?.type||'Work',event_id:event?.event_id||'',revision:event?.revision||0};const body=el('div');const clientField=field('Client workspace',p.client,v=>p.client=v,'text',editable.map(c=>c.name));clientField.querySelector('select').disabled=!!event;body.append(clientField,field('Activity',p.title,v=>p.title=v),field('Date and time (UTC)',p.starts_at,v=>p.starts_at=v,'datetime-local'),field('Type',p.type,v=>p.type=v,'text',['Work','Review','Meeting','Audit','Other']),field('Notes',p.notes,v=>p.notes=v,'textarea'));modal(event?'Edit client activity':'Schedule client work',body,[btn('Save activity',()=>send('calendar_save',p),'primary')]);}
    }

    function detailSection(title, values) {
        const section=el('section','','drawer-section');
        section.append(el('h3',title));
        const list=el('dl','','detail-values');
        for(const [label,value] of values) {
            const item=el('div');
            item.append(el('dt',label),el('dd',value===null||value===undefined||value===''?'Not recorded':typeof value==='boolean'?(value?'Yes':'No'):Array.isArray(value)?value.join('\n'):typeof value==='object'?JSON.stringify(value,null,2):String(value)));
            list.append(item);
        }
        section.append(list);return section;
    }
    function detailDrawer({title,subtitle='',body,actions=[],dirty=()=>false,onClose=()=>{}}) {
        root.querySelector('.drawer-layer')?.remove();
        const origin=parentElement.getRootNode().activeElement||document.activeElement;
        const layer=el('div','','drawer-layer'),shade=el('div','','drawer-shade');
        const panel=el('section','','record-drawer');
        panel.setAttribute('role','dialog');panel.setAttribute('aria-modal','true');panel.setAttribute('aria-label',title);
        panel.tabIndex=-1;
        const background=[...root.children];background.forEach(node=>node.inert=true);
        const close=()=>{background.forEach(node=>node.inert=false);layer.remove();onClose();if(origin?.isConnected)origin.focus();};
        const requestClose=()=>{
            if(state.busy)return;
            if(!dirty()){close();return;}
            if(panel.querySelector('.discard-notice'))return;
            const warning=el('div','','notice discard-notice');warning.setAttribute('role','alert');
            warning.append(el('p','You have unsaved changes.'),row(btn('Keep editing',()=>warning.remove()),btn('Discard changes',close)));
            footer.prepend(warning);warning.querySelector('button').focus();
        };
        const closeButton=btn('×',requestClose);closeButton.setAttribute('aria-label','Close details');closeButton.title='Close details';
        const heading=el('div');heading.append(el('small',subtitle,'eyebrow'),el('h2',title));
        const header=row(heading,closeButton);header.classList.add('drawer-header','between');
        const content=el('div','','drawer-content');content.append(body);
        const footer=el('footer','','drawer-footer');footer.append(...actions,btn('Close',requestClose));
        panel.append(header,content,footer);layer.append(shade,panel);root.append(layer);
        shade.onclick=requestClose;
        panel.onkeydown=e=>{
            if(e.key==='Escape'){e.preventDefault();requestClose();}
            if(e.key==='Tab'){
                const items=[...panel.querySelectorAll('button,input,select,textarea,a[href]')].filter(n=>!n.disabled&&!n.hidden);
                const active=panel.getRootNode().activeElement||document.activeElement,index=items.indexOf(active);
                if(e.shiftKey&&index<=0){e.preventDefault();items.at(-1)?.focus();}
                else if(!e.shiftKey&&(index===items.length-1||index===-1)){e.preventDefault();items[0]?.focus();}
            }
        };
        panel.focus();return panel;
    }
    function controlProfiles() {
        root.classList.add('enterprise-workbench');
        root.append(el('h2','Control profiles'),el('p','Select a control to review its scope, owners and assessment requirements.','muted'));
        if(!data.rows.length){root.append(el('p','No control profiles are available in this workspace.','empty'));return;}
        const search=el('input');search.placeholder='Search ID, title or owner';search.setAttribute('aria-label','Search control profiles');search.value=state.query;
        const filters=el('div','','filters');filters.append(search);root.append(filters);
        const selections={};for(const key of ['Type','Applicability','Implementation','Evidence','Owner']){const select=el('select');select.setAttribute('aria-label',key+' filter');for(const value of ['All',...new Set(data.rows.map(r=>r.summary?.[key]).filter(Boolean))]){const option=el('option',value);option.value=value;select.append(option);}select.onchange=()=>{selections[key]=select.value;state.page=0;draw();};filters.append(select);}
        const holder=el('div');root.append(holder);
        const columns=data.full_workspace?['Control','Title','Applicability','Implementation','Evidence','Assurance','Open gaps','Owner','Last review']:['Control','Title','Human assessment','Implementation','Evidence strength','Open gaps','Owner','Last review'];
        function draw(){
            holder.replaceChildren();
            const records=data.rows.filter(r=>[r.control_id,r.control_name,r.control_owner].join(' ').toLowerCase().includes(state.query.toLowerCase())&&Object.entries(selections).every(([k,v])=>v==='All'||r.summary?.[k]===v));
            state.page=Math.min(state.page,Math.max(0,Math.ceil(records.length/15)-1));
            if(!records.length){holder.append(el('p','No control profiles match this view.','empty'));return;}
            const table=el('table','','wb-table profile-grid'),head=el('tr'),thead=el('thead'),body=el('tbody');
            columns.forEach(label=>{const th=el('th',label);th.scope='col';head.append(th);});thead.append(head);table.append(thead);
            for(const record of records.slice(state.page*15,(state.page+1)*15)){
                const tr=el('tr');tr.tabIndex=0;tr.dataset.controlId=record.control_id;tr.setAttribute('aria-label',`Edit profile ${record.control_id}: ${record.control_name}`);
                tr.onclick=()=>{if(data.full_workspace){send('profile_implementation',{control_id:record.control_id});return;}state.profile=record.control_id;state.profileDraft=structuredClone(record);state.profileDirty=false;openProfile();};
                tr.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();tr.click();}};
                columns.forEach((key,index)=>{const value=record.summary?.[key]??'—';const td=el('td');if(['Applicability','Implementation','Assurance'].includes(key)){td.append(pill(value));}else if(key==='Open gaps'&&Number(value)>0){td.append(el('span',value,'pill orange'));}else{td.textContent=value;}if(index===0)td.className='identifier';tr.append(td);});body.append(tr);
            }
            table.append(body);const wrap=el('div','','table-wrap');wrap.tabIndex=0;wrap.setAttribute('aria-label','Control profiles, scroll horizontally for more columns');wrap.append(table);holder.append(wrap);
            if(!records.length)holder.append(el('p','No controls match your search.','empty'));
            const foot=el('div','','footer');foot.append(el('span',`${records.length} assurance items`));if(records.length>15)foot.append(row(btn('Previous',()=>{state.page--;draw();},'',state.page===0),btn('Next',()=>{state.page++;draw();},'',(state.page+1)*15>=records.length)));holder.append(foot);
        }
        search.oninput=()=>{state.query=search.value;state.page=0;draw();};draw();
        if(state.profile&&data.rows.some(r=>r.control_id===state.profile))openProfile();
        function openProfile(){
            const current=data.rows.find(r=>r.control_id===state.profile);if(!current)return;
            if(data.response?.message&&data.response.nonce!==state.profileSavedNonce){state.profileSavedNonce=data.response.nonce;state.profileDraft=structuredClone(current);state.profileDirty=false;}
            const draft=state.profileDraft||structuredClone(current),body=el('div');
            if(data.response?.error)body.append(el('p',data.response.error,'notice error'));
            if(data.response?.message)body.append(el('p',data.response.message,'notice'));
            body.append(detailSection('Fixed catalog reference',[['Control ID',current.control_id],['Reference name',current.control_name],['Reference guidance',current.control_objective]]));
            body.append(detailSection('Latest saved assessment',[['Assessment conclusion',current.assessment_status||'Not assessed'],['Evidence-based implementation',current.implementation_status||'Not Assessed'],['Measured value',current.current_value??'Not assessed'],['Assurance score',current.assurance_score??'Not assessed'],['Approved target',current.target]]));
            body.append(el('p','Use Assess this control to update implementation conclusions, measurements and evidence. Reference guidance is not implementation evidence.','muted'));
            const saveStatus=el('span',state.profileDirty?'Unsaved changes':'Saved profile','save-status');saveStatus.setAttribute('role','status');
            const edit=(label,key,type='text',options=null)=>{
                const node=field(label,draft[key],value=>{draft[key]=value;state.profileDraft=draft;state.profileDirty=true;saveStatus.textContent='Unsaved changes';},type,options);
                node.querySelector('input,textarea,select').disabled=!data.can_edit||state.busy;return node;
            };
            for(const [title,fields] of [
                ['Organization-specific control',[['Local control name','organization_name'],['Implementation description','implementation_description','textarea']]],
                ['Ownership',[['Control owner','control_owner'],['Assessment owner','assessment_owner']]],
                ['Scope and assessment approach',[['Assessment scope','scope','textarea'],['Measurement model','measurement_model','text',data.models],['Automation','automation_level','text',['Manual','Partial','Automated']]]],
                ['Evidence and methods',[['Assessment methods · one per line','assessment_methods','textarea'],['Required evidence · one per line','evidence_requirements','textarea']]]
            ]){const section=el('section','','drawer-section');section.append(el('h3',title));fields.forEach(args=>section.append(edit(...args)));body.append(section);}
            body.append(el('p','Saving creates a new draft profile version. Existing assessments remain in history; the new version requires a reviewed target.','notice'));
            const save=btn('Save profile version',()=>send('profile_save',{control_id:current.control_id,expected_version:draft.profile_version,fields:draft}),'primary',!data.can_edit);
            const assess=btn('Assess this control',()=>{if(state.profileDirty){saveStatus.textContent='Save or discard your edits before assessing this control.';return;}send('profile_assess',{control_id:current.control_id});});
            detailDrawer({title:current.organization_name||current.control_name,subtitle:`${current.control_id} · Profile v${draft.profile_version}`,body,actions:[saveStatus,save,assess,btn('Implementation evidence',()=>{if(state.profileDirty){saveStatus.textContent='Save or discard edits before evaluating.';return;}state.profile=null;state.profileDraft=null;send('profile_implementation',{control_id:current.control_id});render();})],dirty:()=>state.profileDirty,onClose:()=>{state.profile=null;state.profileDraft=null;state.profileDirty=false;}});
        }
    }
    function riskReading(){
        root.classList.add('enterprise-workbench');
        root.append(el('p','Select a risk to inspect its full assessment. Use the editor below to update saved records.','muted'));
        const holder=el('div'),search=el('input');search.placeholder='Search risks, assets or owners';search.setAttribute('aria-label','Search risk register');
        const bar=el('div','','filters');bar.append(search);root.append(bar,holder);
        function draw(){
            holder.replaceChildren();const rows=data.rows.filter(r=>JSON.stringify(r).toLowerCase().includes(search.value.toLowerCase()));
            const table=el('table','','wb-table simple-risk-grid'),head=el('tr'),thead=el('thead'),tbody=el('tbody');
            const fields=['risk_ref','threat','risk_owner','pre_risk_score','post_risk_score','treatment_action_status'];
            fields.forEach(key=>{const th=el('th',({risk_ref:'ID',threat:'Risk scenario',risk_owner:'Owner',pre_risk_score:'Inherent',post_risk_score:'Residual',treatment_action_status:'Treatment'})[key]||data.fields[key]);th.scope='col';head.append(th);});thead.append(head);table.append(thead);
            state.page=Math.min(state.page,Math.max(0,Math.ceil(rows.length/20)-1));
            for(const record of rows.slice(state.page*20,(state.page+1)*20)){
                const tr=el('tr');tr.tabIndex=0;tr.setAttribute('aria-label',`View risk R-${record.risk_ref}`);
                tr.onclick=()=>{
                    const body=el('div');
                    for(const [title,predicate] of [['Scenario and accountability',key=>!key.startsWith('pre_')&&!key.startsWith('post_')&&!key.startsWith('treatment')&&!key.startsWith('residual')],['Inherent assessment',key=>key.startsWith('pre_')],['Treatment',key=>key.startsWith('treatment')],['Residual assessment',key=>key.startsWith('post_')||key.startsWith('residual')]]){
                        body.append(detailSection(title,Object.entries(data.fields).filter(([key])=>predicate(key)).map(([key,label])=>[label,record[key]])));
                    }
                    detailDrawer({title:record.threat||`Risk R-${record.risk_ref}`,subtitle:`R-${record.risk_ref} · Saved assessment`,body});
                };
                tr.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();tr.click();}};
                fields.forEach((key,index)=>{const td=el('td');td.append(key.endsWith('_score')?score(record[key]):el('span',index===0?`R-${record[key]}`:record[key]||'—'));tr.append(td);});tbody.append(tr);
            }
            table.append(tbody);const wrap=el('div','','table-wrap');wrap.tabIndex=0;wrap.setAttribute('aria-label','Risk register, scroll horizontally for more columns');wrap.append(table);holder.append(wrap);
            if(!rows.length)holder.append(el('p','No risks match your search.','empty'));
            const foot=el('div','','footer');foot.append(el('span',`${rows.length} risks`));if(rows.length>20)foot.append(row(btn('Previous',()=>{state.page--;draw();},'',state.page===0),btn('Next',()=>{state.page++;draw();},'',(state.page+1)*20>=rows.length)));holder.append(foot);
        }search.oninput=()=>{state.page=0;draw();};draw();
    }

    function foundationView(){
        root.classList.add('foundation-workbench');
        const friendly=value=>typeof value==='string'&&value.startsWith('migration-')?'System migration':Array.isArray(value)?value.join(', '):value??'—';
        const formattedDate=value=>value?new Date(value).toLocaleDateString(undefined,{year:'numeric',month:'short',day:'numeric'}):'—';
        const add=()=>data.section==='objectives'?objectiveDialog():data.section==='scope'?boundaryDialog():send('foundation_add');
        const top=row(el('div'),btn('+ '+data.add_label,add,'primary',!data.can_edit));top.firstChild.append(el('h1',data.title),el('p',data.description,'muted'));top.classList.add('between');root.append(top);
        if(data.scope){
            const s=data.scope,scope=card(`${s.name} · v${s.latest_version_number||'—'}`);
            scope.body.append(pill(s.latest_status==='Under review'?'Submitted for Review':s.latest_status||'Draft'),el('h3','Scope statement'),el('p',s.scope_statement||'No scope statement recorded.'),row(btn('Edit scope',()=>send('foundation_scope_edit'),'primary',!data.can_edit),btn('Version history',()=>send('foundation_history')),btn('Review / approval',()=>send('foundation_review'))));
            const boundaries=el('div','','foundation-metrics');
            for(const [key,title] of [['organizational_units','Organizational units'],['locations','Locations'],['technologies','Technologies'],['products_and_services','Products / services']]){
                const items=s[key]||[],c=card(`${title} · ${items.length}`);c.body.append(el('p',items.join(', ')||'None recorded'));boundaries.append(c.card);
            }
            scope.body.append(boundaries,detailSection('Boundary definition',[['Boundaries',s.boundaries],['Dependencies & interfaces',s.interfaces_and_dependencies],['Exclusions & justification',s.exclusions]]));
            const meta=detailSection('Governance',[['Owner',friendly(s.owner)],['Prepared by',friendly(s.prepared_by)],['Created',formattedDate(s.created_at)],['Last modified',formattedDate(s.updated_at)],['Reviewer',friendly(s.reviewed_by)],['Approver',friendly(s.approved_by)],['Approved',formattedDate(s.approved_at)]]);meta.classList.add('compact-metadata');scope.body.append(meta);root.append(scope.card);
        }else if(data.section==='scope')root.append(el('p','No controlled scope yet. Prepare a draft for human review.','empty'),btn('Create scope draft',()=>send('foundation_scope_edit'),'primary',!data.can_edit));
        if(data.section==='context')root.append(row(el('span',data.climate_status||'Climate determination: Not recorded','muted'),btn('Climate determination',()=>send('foundation_tools'))));
        if(data.section==='objectives'){
            root.append(row(btn('Review / approval',()=>send('foundation_review')),btn('Version history',()=>send('foundation_history'))));
            const metrics=el('div','','foundation-metrics'),active=data.rows.filter(r=>!r.archived&&!r.historical);
            for(const [label,value] of [['Objectives',active.length],['Assigned owners',active.filter(r=>r.owner).length],['Past Due',active.filter(r=>r.due_date&&r.due_date<(data.today||new Date().toISOString().slice(0,10))).length],['Register status',data.register_status]]){const c=card(label);c.body.append(el('h2',value));metrics.append(c.card);}root.append(metrics);
        }
        if(!data.rows.length){root.append(el('p',data.section==='scope'?'No sites or organizational units recorded. Use Add boundary to define what is included.':`No ${data.section==='context'?'context issues':data.section==='parties'?'interested parties':'records'} yet. Add your first record to get started.`,'empty'));return;}
        const bar=el('div','','filters'),search=el('input');search.placeholder='Filter records…';search.value=state.query;search.setAttribute('aria-label','Search formal records');const filter=state.foundationFilter||'';
        bar.append(btn(`All (${data.rows.length})`,()=>{state.foundationFilter='';state.page=0;render();},!filter?'active':''));
        if(data.filter_key)for(const value of [...new Set(data.rows.map(r=>r[data.filter_key]).filter(Boolean))])bar.append(btn(`${value} (${data.rows.filter(r=>r[data.filter_key]===value).length})`,()=>{state.foundationFilter=value;state.page=0;render();},filter===value?'active':''));
        bar.append(search);root.append(bar);const holder=el('div');root.append(holder);search.oninput=()=>{state.query=search.value;state.page=0;draw();};
        function draw(){
            holder.replaceChildren();const rows=data.rows.filter(r=>(!state.foundationFilter||r[data.filter_key]===state.foundationFilter)&&Object.values(r).join(' ').toLowerCase().includes(state.query.toLowerCase()));state.page=Math.min(state.page,Math.max(0,Math.ceil(rows.length/10)-1));
            const table=el('table','','wb-table'),head=el('tr');Object.values(data.columns).forEach(label=>head.append(el('th',label)));head.append(el('th','Actions'));const thead=el('thead');thead.append(head);table.append(thead);const body=el('tbody');
            for(const record of rows.slice(state.page*10,(state.page+1)*10)){
                const tr=el('tr');tr.tabIndex=0;tr.onclick=()=>openRecord(record);tr.onkeydown=e=>{if(e.key==='Enter')openRecord(record);};
                for(const key of Object.keys(data.columns)){const cell=el('td');cell.append(['status','relevance','raci_type'].includes(key)?pill(record[key]):el('span',friendly(record[key])));if(key===Object.keys(data.columns)[0]&&record.description)cell.append(el('small',record.description));tr.append(cell);}
                const actions=el('td');actions.append(btn('View',e=>{e.stopPropagation();openRecord(record);},'link'));tr.append(actions);body.append(tr);
            }
            table.append(body);const wrap=el('div','','table-wrap');wrap.append(table);holder.append(wrap);if(!rows.length)holder.append(el('div','No records match this view. Adjust the filters.','empty'));
            const foot=el('div','','footer');foot.append(el('span',`${rows.length} records`));if(rows.length>10)foot.append(row(btn('Previous',()=>{state.page--;draw();},'',state.page===0),btn('Next',()=>{state.page++;draw();},'',(state.page+1)*10>=rows.length)));if(rows.length)holder.append(foot);
        }draw();
        function openRecord(record){
            const body=el('div'),actions=[];
            if(data.section==='parties'){
                for(const [title,keys] of [['Identity',['name','party_type','relationship_description']],['Needs & expectations',['needs_and_expectations']],['Requirements',['applicable_requirement_count']],['Governance',['owner','communication_method','status']]])body.append(detailSection(title,keys.map(k=>[k.replaceAll('_',' '),friendly(record[k])])));
                actions.push(btn('Requirements',()=>send('foundation_tools',{id:record._row_key})));
            }else body.append(detailSection('Record information',Object.entries(record).filter(([key,value])=>!key.startsWith('_')&&!key.endsWith('_id')&&!key.endsWith('_uuid')&&key!=='id'&&value!==null&&value!=='').map(([key,value])=>[key.replaceAll('_',' ').replace(/\b\w/g,c=>c.toUpperCase()),friendly(value)])));
            if(data.section==='objectives'){
                actions.push(btn('Edit objective',()=>{root.querySelector('.drawer-layer')?.remove();[...root.children].forEach(n=>n.inert=false);objectiveDialog(record);},'primary',!data.can_edit),btn('Evidence',()=>{body.replaceChildren(detailSection('Objective evidence',[['Evidence / references',record.evidence||'No evidence recorded. Use Edit objective to add a reference.']]));}),btn('Review',()=>send('foundation_review')),btn('History',()=>send('foundation_history')));
            }else if(['context','parties'].includes(data.section)){
                actions.push(btn('Edit',()=>send('foundation_edit',{id:record._row_key}),'primary',!data.can_edit),btn(data.section==='context'?'Review / Close':'Governance',()=>send('foundation_edit',{id:record._row_key}),'',!data.can_edit));
            }else actions.push(btn('Related records / workflow',()=>send('foundation_tools',{id:record._row_key})));
            detailDrawer({title:record.title||record.name||record.role_name||'Record details',subtitle:data.title,body,actions});
        }
        function objectiveDialog(record=null){
            const draft={...(record||{})},body=el('div'),warning=el('div'),today=data.today||new Date().toISOString().slice(0,10);let historical=!!record?.historical;
            let dateIntent=record?(record.historical?'historical':'current'):null;
            const label=field('Objective timing',dateIntent||'',v=>{dateIntent=v;historical=v==='historical';},'text',[['','Choose how to record this objective'],['current','A current objective that is already overdue'],['historical','A historical objective']]);
            function dateNotice(){warning.replaceChildren();if(draft.due_date&&draft.due_date<today)warning.append(el('p','This due date is in the past. Is this a current overdue objective or a historical objective?','notice'),label);}
            for(const key of data.fields)body.append(field(key.replaceAll('_',' ').replace(/\b\w/g,c=>c.toUpperCase()),draft[key]||'',v=>{draft[key]=v;if(key==='due_date')dateNotice();},key==='due_date'?'date':['action_plan','resources','evidence'].includes(key)?'textarea':'text'));
            body.append(warning);dateNotice();const actions=[btn('Save draft version',()=>send('foundation_objective_save',{index:record?._index??null,record:draft,historical,date_intent:dateIntent,archived:!!record?.archived}),'primary',!data.can_edit)];
            if(record)actions.push(btn(record.archived?'Restore objective':'Archive objective',()=>send('foundation_objective_save',{index:record._index,record:draft,historical,date_intent:dateIntent,archived:!record.archived}),'',!data.can_edit));modal(record?'Edit objective':'Add objective',body,actions);
        }
        function boundaryDialog(){
            const body=el('div');let type='Organizational unit';body.append(field('Boundary type',type,v=>type=v,'text',['Organizational unit','Site / location','Technology','Product / service','Other boundary']));
            modal('Add boundary',body,[btn('Continue',()=>send(type==='Organizational unit'||type==='Site / location'?'foundation_add':'foundation_scope_edit',{boundary_type:type}),'primary',!data.can_edit)]);
        }
    }
    function controlWorkspace(){
        root.classList.add('enterprise-workbench','control-detail');
        const r=data.result,requirements=r.requirements||[],m3= requirements.some(q=>q.rule_version===3);
        root.append(el('p',`Control Assurance / ISO/IEC 27001 / ${data.control_id}`,'crumb'));
        const heading=row(el('h1',`${data.control_id} — ${data.title}`),pill(r.applicability));heading.classList.add('control-title');
        const actions=row(btn('Edit Configuration',()=>send('control_configure'),'',!data.can_edit),btn('Add Requirement',()=>send('requirement_edit',{}),'primary',!data.can_edit));
        const header=row(heading,actions);header.classList.add('control-header');
        root.append(header,el('p',`ISMS Scope #${data.scope} · Owner: ${data.owner} · Last assessment: ${data.assessment_date||'Not assessed'}`,'muted'));
        const metrics=el('div','','control-metrics');
        for(const [label,value] of [[m3?'Implementation (advisory)':'Implementation',m3?r.advisory_implementation||r.implementation:r.implementation],['Requirements Met',`${r.satisfied} / ${r.mandatory_count} verified`],['Evidence',r.evidence_coverage==null?'Not configured':`${r.evidence_coverage}%`],[m3?'Assurance review':'Assurance',r.assurance]]){
            const c=el('div');c.append(el('span',label),el('strong',value));metrics.append(c);
        }root.append(metrics);
        const why=card('Why this status?');why.card.classList.add('control-reasons');
        if(m3)why.body.append(el('p',`Recorded human assessment: ${r.human_assessment?.status||'Not assessed'} · ${r.human_assessment?.validation_status||'Not assessed'}. Technical results do not approve this control.`));
        const priority=q=>q.rule==='Approved policy'?0:q.result==='FAIL'?1:q.result==='NO EVIDENCE'?2:q.freshness==='Stale'?3:4;
        const unresolved=requirements.filter(q=>q.mandatory&&q.result!=='PASS').sort((a,b)=>priority(a)-priority(b)||String(a.id).localeCompare(String(b.id)));
        const actionLabel=q=>q.rule==='Approved policy'?'Link Policy':q.result==='FAIL'?'Create Remediation':q.freshness==='Stale'?'Refresh Evidence':q.result==='NO EVIDENCE'?'Collect Evidence':'Review Requirement';
        why.body.append(el('span',`${unresolved.length} gaps identified`,'gap-count'));
        if(!requirements.length)why.body.append(el('p','No structured requirements configured. Existing assessments and history remain available. Add criteria to explain and evaluate this control.','muted'));
        for(const q of (unresolved.length?unresolved:requirements).slice(0,5))why.body.append(row(pill(requirementLabel(q.result)),el('span',`${q.title} — ${q.reason}`)));
        if(unresolved.length>5)why.body.append(btn(`View all ${unresolved.length} unresolved requirements`,()=>showTab('Requirements'),'link'));
        why.body.append(btn(unresolved.length?'Resolve Next Gap':'Review requirements',()=>unresolved.length?requirementDrawer(unresolved[0],true):showTab('Requirements'),'primary'),btn('Assess Control',()=>navigate('assessment')),btn('Refresh Evidence',()=>send('refresh_assurance'),'',!data.can_edit));
        if(r.policy_changed)why.body.append(el('p','Policy changed since the last assessment. Review recommended.','notice'));
        if(r.auto_verified)why.body.append(el('p','Automatically Verified · Continuous Assurance Healthy','notice'));
        else if(r.automation_blockers?.length){const details=el('details'),summary=el('summary','Automatic verification conditions');details.append(summary);r.automation_blockers.forEach(x=>details.append(el('p',x)));why.body.append(details);}root.append(why.card);
        const tabs=el('div'),content=el('section','','control-content');root.append(tabs,content);
        const names=['Overview','Requirements','Evidence','Policies','Risks','Remediation','History'];
        function navigate(destination,id){send('control_navigate',{destination,id});}
        function showTab(name){state.controlTab=name;tabs.replaceChildren(sectionBar(names,names.indexOf(name),i=>showTab(names[i]),'control-tabs'));content.replaceChildren();
            if(name==='Overview'||name==='Requirements'){
                content.append(row(el('h2','Associated Requirements'),btn('Add Organization Requirement',()=>send('requirement_edit',{}),'',!data.can_edit)));
                if(!requirements.length)content.append(el('p','No requirements yet. Define observable outcomes, supporting sources and the evidence needed.','empty'));
                const groups=[...new Set(requirements.map(q=>q.group||'Control Implementation'))];
                for(const group of groups){const items=requirements.filter(q=>(q.group||'Control Implementation')===group),section=el('section','','card');section.append(el('h3',`${group} · ${items.length}`));
                    const table=el('table','','wb-table'),head=el('tr');
                    for(const label of ['Requirement','Type','Result','Evidence','Policy','Action'])head.append(el('th',label));
                    const thead=el('thead');thead.append(head);table.append(thead);const body=el('tbody');
                    for(const q of items){const line=el('tr'),title=el('td');title.append(btn(q.title,()=>requirementDrawer(q),'link'));line.append(title,el('td',q.type));const status=el('td');status.append(pill(requirementLabel(q.result)));line.append(status,el('td',q.applicable_assets!=null?`${q.verified_assets||0} / ${q.applicable_assets} assets · ${q.evidence_ids?.length||0} evidence`:`${q.evidence_ids?.length||0} items`),el('td',q.policy_ids?.length?`${q.policy_ids.length} linked`:q.rule==='Approved policy'?'Missing':'Not Required'));const action=el('td');action.append(btn(q.result==='PASS'?'View':q.rule==='Approved policy'?'Link Policy':q.result==='FAIL'?'Remediate':'Assess',()=>requirementDrawer(q,q.result!=='PASS')));line.append(action);body.append(line);}
                    table.append(body);const wrap=el('div','','table-wrap');wrap.append(table);section.append(wrap);content.append(section);
                }
                if(name==='Requirements'&&data.baseline_review_pending)content.append(el('p','Review the authored requirements for this scope.'),btn('Confirm requirements for this scope',()=>send('confirm_requirements'),'',!data.can_edit));
                if(name==='Overview'){const summary=card('Next Recommended Action');summary.card.classList.add('control-next');const next=unresolved[0];summary.body.append(el('p',next?next.reason:'Review the assessment and confirm the control conclusion.'),next?btn(actionLabel(next),()=>requirementDrawer(next,true),'primary'):btn('Assess Control',()=>navigate('assessment')));if(r.applicability==='Pending')summary.body.append(btn('Review applicability',()=>navigate('soa')));content.append(summary.card);}
            }else if(name==='Evidence'){
                content.append(row(el('h2','Evidence'),btn('Collect / Link Evidence',()=>navigate('evidence'),'primary'),btn('Collect Inventory Evidence',()=>send('collect_inventory'),'',!data.can_edit)));
                for(const e of data.evidence){const c=card(e.title);c.body.append(row(pill(e.tool_id),pill(e.verification_origin==='System collector'?'System verified':e.validation_status)),el('p',`EV-${e.id} · ${e.asset_tag||e.source_asset_or_system||''} · ${e.observation_count??0} observations · Collected ${e.collected_at}`));
                    for(const check of e.automated_checks||[])c.body.append(el('p',`${check.effect==='gap'?'⚠':'Supports:'} ${check.display_name}`));
                    for(const observation of e.automated_observations||[])c.body.append(el('p',`⚠ ${observation.title}`));
                    c.body.append(btn('View Evidence',()=>evidenceDrawer(e)),btn('Why linked?',()=>evidenceDrawer(e)));content.append(c.card);}
                if(!data.evidence.length)content.append(el('p','No scoped evidence linked. Collect or explicitly link evidence in the Evidence workspace.','empty'));
                for(const q of unresolved.filter(q=>q.result==='NO EVIDENCE'))content.append(row(el('span',q.title),btn('Collect',()=>navigate('evidence'))));
            }else if(name==='Policies'){
                const ids=new Set(requirements.flatMap(q=>q.policy_ids||[]));const docs=data.documents.filter(d=>ids.has(d.policy_id)||d.controls?.includes(data.control_id));
                if(!docs.length)content.append(el('p','No supporting policy linked. A policy is required only where the requirement expects one.','empty'));
                for(const d of docs){const c=card(d.title);c.body.append(row(pill(d.status),el('span',`Version ${d.policy_version} · Covers ${requirements.filter(q=>q.policy_ids?.includes(d.policy_id)).length} requirements`)),btn('Open Policy',()=>navigate('policy',d.policy_id)));content.append(c.card);}
                for(const q of requirements.filter(q=>q.rule==='Approved policy'))content.append(row(el('span',q.title),btn('Create Policy',()=>send('requirement_policy',{id:q.id}),'',!data.can_edit),btn('Link Existing Policy',()=>send('requirement_edit',{id:q.id}),'',!data.can_edit)));
            }else if(name==='Risks'){
                if(!data.risks.length)content.append(el('p','No current-scope risk treatments link this control.','empty'));
                for(const risk of data.risks){const c=card(`R-${risk.risk_ref} · ${risk.threat}`);c.body.append(el('p',risk.treatment_action||risk.treatment_option||'Treatment not recorded'),el('p',`Owner: ${risk.risk_owner||'Unassigned'}`),btn('Open Risk',()=>navigate('risk',risk.risk_ref)));content.append(c.card);}content.append(btn('Open Risk Management',()=>navigate('risk')));
            }else if(name==='Remediation'){
                const open=data.actions.filter(a=>!['Completed','Cancelled'].includes(a.status));
                if(!open.length)content.append(el('p','No open remediation actions. Resolve an unmet requirement to create canonical work.','empty'));
                for(const a of open){const c=card(`#${a.id} · ${a.recommended_action}`);c.body.append(row(pill(a.priority),pill(a.status)),el('p',`${a.action_owner} · Due ${a.due_date}`),btn('Open Remediation',()=>navigate('remediation',a.id)));content.append(c.card);}
                const closed=data.actions.filter(a=>['Completed','Cancelled'].includes(a.status));if(closed.length){const details=el('details');details.append(el('summary',`Resolved / cancelled · ${closed.length}`));closed.forEach(a=>details.append(el('p',`#${a.id} · ${a.recommended_action} · ${a.status}`)));content.append(details);}
            }else{
                if(!data.history.length)content.append(el('p','No requirement evaluations recorded yet. Existing human assessments remain in Assess Control history.','empty'));
                for(const h of data.history){const c=card(h.summary);c.body.append(el('p',`${h.created_at} · ${h.actor}`));content.append(c.card);}content.append(btn('Assessment history',()=>navigate('assessment')));
            }
        }
        function evidenceDrawer(e){const body=detailSection('Evidence provenance',[['Evidence',`EV-${e.id}`],['Provider',e.tool_id],['Collected',e.collected_at],['Scope',e.scope_name||`ISMS Scope #${e.scope_id}`],['Mapping origin',e.mapping_origin||'Not recorded'],['Why linked',e.rationale||'Not recorded'],['Automated check',(e.automated_checks||[]).map(c=>c.display_name).join('; ')||'None'],['Asset',e.asset_tag||e.source_asset_or_system||'Not recorded'],['Verification',e.verification_origin==='System collector'?'System verified':e.validation_status],['Verified by',e.validator||'Not reviewed'],['Validated at',e.validated_at||'Not reviewed'],['Source reference',e.source_asset_or_system||'Not recorded']]);detailDrawer({title:e.title,subtitle:'Canonical evidence',body,actions:[btn('Open Evidence',()=>navigate('evidence')),btn('View Assets',()=>navigate('assets'))]});}
        function requirementDrawer(q,resolve=false){
            const body=el('div');
            body.append(detailSection('Requirement gap',[
                ['Status',requirementLabel(q.result)],['What is required',q.expected_result],
                ['Why this status',q.reason],['What to do next',q.recommended_action||actionLabel(q)],
                ['Evidence freshness',q.freshness]]));
            if(q.rule==='Recent vulnerability scan'&&q.affected_assets?.length)body.append(el('p',`No current scan: ${q.affected_assets.map(id=>data.asset_labels?.[String(id)]||`Asset ${id}`).join(', ')}`));
            if(q.asset_results&&Object.keys(q.asset_results).length){
                const assets=el('section');assets.append(el('h3','Asset results'));
                for(const [id,status] of Object.entries(q.asset_results)){
                    const row=el('p');row.append(el('span',`${data.asset_labels?.[String(id)]||`Asset ${id}`} · `),pill(({PASS:'Pass',FAIL:'Gap','NOT COLLECTED':'Not Collected'})[status]||status));assets.append(row);
                }
                body.append(assets);
            }
            const technical=el('details');technical.append(el('summary','Technical details'),
                detailSection('Assessment context',[
                ['Type',q.type],['Mandatory',q.mandatory?'Yes':'No'],['Method',q.rule],
                ['Applicable assets',q.applicable_assets??q.asset_ids?.length??0],
                ['Verified',q.verified_assets??'Not measured'],['Source',q.source||'Organization-defined'],
                ['Interested Party requirement',q.party_requirement_id?`REQ-${q.party_requirement_id}`:'None']]));
            if(q.affected_assets?.length)technical.append(el('p',`Affected asset IDs: ${q.affected_assets.join(', ')}`));
            if(q.result_layer)technical.append(detailSection('Technical check trace',[
                ['Result meaning',q.result_layer],['Rule version',q.rule_version],
                ['Control Profile',q.profile_id?`#${q.profile_id} · v${q.profile_version}`:'Current scoped profile'],
                ['Approved scope version',q.scope_version_id||'Not recorded'],
                ['Reason code',q.reason_code||'Not recorded'],
                ['Missing asset IDs',(q.missing_assets||[]).join(', ')||'None'],
                ['Human decision','Separate assessment; this result does not approve the control']]));
            for(const fact of q.observations||[]){if(fact.check_id)technical.append(el('p',`EV-${fact.evidence_id} · ${fact.check_id} v${fact.rule_version} · Asset ${fact.asset_id} · ${fact.observed_at} · ${fact.endpoint||fact.source_key}`));}
            for(const item of q.excluded_evidence||[])technical.append(el('p',`EV-${item.evidence_id} excluded: ${item.reason}`));
            body.append(technical);
            const policy=q.rule==='Approved policy';
            const actions=[btn('Link Existing Evidence',()=>send('requirement_link',{id:q.id}),'',!data.can_edit),
                btn('Create Remediation',()=>send('requirement_remediation',{id:q.id}),!policy&&q.result==='FAIL'?'primary':'',!data.can_edit),
                btn('View Assets',()=>navigate('assets'))];
            if(policy)actions.unshift(btn('Create Policy',()=>send('requirement_policy',{id:q.id}),'',!data.can_edit),
                btn('Link Existing Policy',()=>send('requirement_edit',{id:q.id}),'primary',!data.can_edit));
            else if(['Recent vulnerability scan','Secure web configuration baseline','Transport encryption configuration','No default credentials on in-scope services','Log source coverage','Monitoring coverage','Clock synchronization','Explicit configuration test'].includes(q.rule))actions.unshift(btn('Collect New Evidence',()=>send('requirement_collect',{id:q.id}),q.result!=='FAIL'?'primary':'',!data.can_edit));
            if(!policy)actions.push(btn('Manual Evidence',()=>send('requirement_manual',{id:q.id}),'',!data.can_edit),btn('Request Evidence',()=>send('requirement_request',{id:q.id}),'',!data.can_edit));
            actions.push(btn('Edit Requirement',()=>send('requirement_edit',{id:q.id}),'',!data.can_edit));
            if(q.machine_verifiable&&!q.asset_ids?.length)actions.push(btn('Use in-scope assets',()=>send('requirement_scope_assets',{id:q.id}),'',!data.can_edit));
            detailDrawer({title:resolve?'Resolve Gap':q.title,subtitle:resolve?q.title:`${data.control_id} · ${q.id}`,body,actions});
        }
        showTab(state.controlTab||'Overview');
    }

    function requirementLabel(value){
        return ({PASS:'Pass',FAIL:'Fail',PARTIAL:'Partial',UNKNOWN:'Not Reviewed','NO EVIDENCE':'No Evidence','NOT APPLICABLE':'Not Applicable'})[value]||value;
    }

    function relatedTreatments(){
        root.append(el('h3','Canonical risk treatments'));
        const table=el('table','','wb-table simple-risk-grid'),head=el('tr');
        for(const label of ['Risk','Scenario','Treatment','Action','Controls','Owner','Status'])head.append(el('th',label));
        const thead=el('thead');thead.append(head);table.append(thead);const body=el('tbody');
        for(const r of data.rows){const tr=el('tr');
            for(const text of [`R-${r.risk_ref}`,r.risk_summary||r.threat||'Untitled']){const td=el('td');td.append(btn(text,()=>send('open_risk',{id:r.risk_ref}),'link'));tr.append(td);}
            tr.append(el('td',r.treatment_option||'Not recorded'),el('td',r.treatment_action||'Not recorded'));
            const controls=el('td');for(const ref of r.control_references||[])controls.append(el('span',ref,'chip'));if(!controls.children.length)controls.append(el('span','None linked'));tr.append(controls,el('td',r.treatment_action_owner||'Unassigned'));const status=el('td');status.append(pill(r.treatment_action_status||'Not Started'));tr.append(status);body.append(tr);
        }
        table.append(body);const wrap=el('div','','table-wrap');wrap.append(table);root.append(wrap);
    }
    function render(){for(const observer of state.navigationObservers||[])observer.disconnect();state.navigationObservers=[];root.classList.toggle('foundation-workbench',data.mode==='foundation');root.classList.toggle('calendar-workbench',data.mode==='calendar');root.classList.toggle('enterprise-workbench',['risk_overview','risk_table','risk_detail','control_profiles','risk_reading','control_workspace'].includes(data.mode));root.classList.toggle('control-detail',data.mode==='control_workspace');root.classList.toggle('client-workbench',data.mode!=='policy_builder');root.replaceChildren();if(data.response?.error)root.append(el('div',data.response.error,'error'));else if(data.response?.message)root.append(el('div',data.response.message,'notice'));if(data.mode==='policy_list')policyList();else if(data.mode==='policy_detail')policyDetail();else if(data.mode==='policy_builder')builder();else if(data.mode==='risk_overview')riskOverview();else if(data.mode==='risk_table')riskTable();else if(data.mode==='risk_detail')riskDetail();else if(data.mode==='calendar')calendarView();else if(data.mode==='foundation')foundationView();else if(data.mode==='control_profiles')controlProfiles();else if(data.mode==='risk_reading')riskReading();else if(data.mode==='related_treatments')relatedTreatments();else if(data.mode==='control_workspace')controlWorkspace();if(state.busy)root.append(el('p','Saving / loading…','notice'));}
    render();
}
