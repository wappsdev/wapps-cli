"""Field-by-field comparison of the plugin's 26 MCP inputSchemas with the cloud broker's request bodies.

usage: schema_diff.py <tools.json> <body.rs>
  tools.json  output of tools_list.ts (the plugin's tools/list, in memory)
  body.rs     wapps-platform/crates/core/src/broker/body.rs

Only fields that exist on both sides and carry a length or count ceiling are compared (the table
below names each pairing). Fields that exist on one side only are listed in the document by hand.
"""
import json,re,sys
tools=json.load(open(sys.argv[1]))
P={}
def walk(tool,sch,pre=''):
    for k,p in sch.get('properties',{}).items():
        P[(tool,pre+k)]=p
        if p.get('type')=='object': walk(tool,p,pre+k+'.')
        if p.get('type')=='array' and p['items'].get('type')=='object': walk(tool,p['items'],pre+k+'[].')
for t in tools: walk(t['name'],t['inputSchema'])
# cloud side: parse body.rs
src=open(sys.argv[2]).read().split('// ─── the schemas')[1].split('/// One of the 25 bodies')[0]
C={}
def balanced(t,i):
    d=0
    for j in range(i,len(t)):
        if t[j]=='(': d+=1
        elif t[j]==')':
            d-=1
            if d==0: return j
for m in re.finditer(r'const (\w+): (?:&\[Field\]|Kind) = (.*?);\n', src, re.S):
    name,body=m.group(1),m.group(2)
    for mm in re.finditer(r'(required|optional)\(',body):
        e=balanced(body,mm.end()-1)
        inner=body[mm.end():e]
        key,kind=inner.split(',',1)
        C[(name,key.strip().strip('"'))]=' '.join(kind.split())
def lim(kind):
    k=kind
    mt=re.match(r'trimmed\(([\d_]+)\)',k)
    if mt: return dict(trim=True,min=1,max=int(mt.group(1).replace('_','')))
    mt=re.match(r'text\((\w+), (None|Some\((\d+)\)), (None|Some\(([\d_]+)\))\)',k)
    if mt: return dict(trim=mt.group(1)=='true',min=int(mt.group(3)) if mt.group(3) else None,max=int(mt.group(5).replace('_','')) if mt.group(5) else None)
    mt=re.match(r'Kind::List \{ item: &\w+, min: (None|Some\((\d+)\)), max: (None|Some\(([\d_]+)\)) \}',k)
    if mt: return dict(items_min=int(mt.group(2)) if mt.group(2) else None,items_max=int(mt.group(4).replace('_','')) if mt.group(4) else None)
    return dict(raw=k[:40])
# pairing: (tool, plugin field) -> (cloud const, cloud field). Written by hand from §3.2's route column.
M=[]
def m(tool,pf,cc,cf): M.append((tool,pf,cc,cf))
m('orchestrator_heartbeat','capability','AUTHORITY','capability')
for t in ['orchestrator_prepare_handoff','orchestrator_release','work_add','work_adopt','work_close','work_move','work_ask','work_relay_answer','work_withdraw','work_delegate','agent_submit','agent_cancel']:
    m(t,'capability','AUTHORITY','capability')
m('agent_attach','attachCapability','JOB_AUTHORITY','capability')
m('orchestrator_prepare_handoff','targetSessionId','HANDOFF','targetPrincipal')
m('orchestrator_takeover','handoffPackageId','TAKEOVER','handoffId')
for f in ['laneId','dispatchKey','base','head','task','workItemId','reviewsJobId','resumesJobId']:
    m('agent_submit',f,'DISPATCH',f)
m('agent_submit','role','DISPATCH','role')
m('work_add','items','WORK_ITEMS','items')
m('work_add','items[].title','NEW_ITEM','title');m('work_add','items[].intent','NEW_ITEM','intent')
m('work_add','items[].parentId','NEW_ITEM','parentId');m('work_add','items[].discoveredFrom','NEW_ITEM','discoveredFrom')
m('work_move','moves','WORK_MOVE','moves')
m('work_adopt','items','ADOPT','items');m('work_adopt','jobId','ADOPT','jobId')
m('work_adopt','items[].title','PROPOSED','title');m('work_adopt','items[].intent','PROPOSED','intent')
m('work_close','workItemId','WORK_CLOSE','workItemId')
m('work_ask','workItemId','ASK','workItemId');m('work_ask','question','ASK','question');m('work_ask','proposal','ASK','proposal')
m('work_relay_answer','questionId','RELAY','questionId');m('work_relay_answer','answer','RELAY','answer')
m('work_withdraw','questionId','WITHDRAW','questionId');m('work_withdraw','reason','WITHDRAW','reason')
m('work_delegate','questionId','DELEGATE','questionId')
m('agent_attach','providerRunId','ATTACH','providerRunId')
m('agent_report','output','FINISH','output');m('agent_report','error','FINISH','error')
m('agent_cancel','jobId','CANCEL_JOB','jobId')
m('work_move','moves[].workItemId','MOVE','workItemId')
m('agent_attach','jobId','JOB_AUTHORITY','jobId')
m('agent_report','jobId','JOB_AUTHORITY','jobId')
same=diff=0;rows=[]
for tool,pf,cc,cf in M:
    p=P[(tool,pf)]
    if pf=='items' or pf=='moves':
        pl=(p.get('minItems'),p.get('maxItems'))
        c=lim(C[(cc,cf)]); cl=(c['items_min'],c['items_max'])
    else:
        pl=(p.get('minLength'),p.get('maxLength'))
        if cc=='AUTHORITY' or cc=='JOB_AUTHORITY':
            c=lim(C[(cc,cf)])
        else: c=lim(C[(cc,cf)])
        cl=(c.get('min'),c.get('max'))
        if 'raw' in c: cl=('raw',c['raw'])
    flag='SAME' if pl==cl else 'DIFF'
    if flag=='SAME': same+=1
    else: diff+=1
    rows.append((flag,tool,pf,pl,cl)); print(f"{flag} {tool:28} {pf:22} plugin(min,max)={pl} cloud={cl}")
print(same,diff)

from collections import Counter
cnt=Counter()
for flag,tool,pf,pl,cl in rows:
    if flag=='SAME': cnt['same']+=1; continue
    if pf in('capability','attachCapability'): cnt['capability 32->1']+=1
    elif pl==(1,256) and cl==(1,128): cnt['id 256->128']+=1
    elif pl==(1,256) and cl==(1,200): cnt['id 256->200']+=1
    else: cnt['other:'+tool+'.'+pf]+=1
for k,v in cnt.items(): print(v,k)
print(len(rows))
