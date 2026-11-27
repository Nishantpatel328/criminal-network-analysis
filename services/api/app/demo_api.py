"""Local demo API for the merged Kimi + Claude project.

This API intentionally serves the fictional Kimi dataset so the complete
frontend can be exercised end-to-end before a real evidence store is connected.
It is for local demonstration only; it is not a production evidence backend.
"""
from __future__ import annotations
from pathlib import Path
from typing import Any
from copy import deepcopy
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

DATA = __import__("json").loads((Path(__file__).parent / "demo_data.json").read_text(encoding="utf-8"))

app = FastAPI(title="CNA Demo API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"], allow_methods=["*"], allow_headers=["*"])


def page(rows: list[Any], page_num: int = 1, page_size: int = 25):
    page_num = max(1, page_num)
    page_size = min(max(1, page_size), 200)
    start = (page_num - 1) * page_size
    return {"data": rows[start:start + page_size], "total": len(rows), "page": page_num, "pageSize": page_size}


def rows(name: str):
    return DATA[name]


def find_entity(eid: str):
    return next((e for e in rows("entities") if e["id"] == eid), None)


def contains_entity(e: dict, q: str):
    q = q.lower()
    return q in e.get("id", "").lower() or q in e.get("label", "").lower() or any(q in a.lower() for a in e.get("aliases", []))


@app.get("/api/health")
def health():
    return {"status": "ok", "mode": "demo", "dataset": "Kimi fictional demo data"}


@app.post("/api/login")
def login(body: dict):
    inv = next((i for i in rows("investigators") if i["email"] == body.get("email")), None)
    if not inv or body.get("password") != "demo1234":
        raise HTTPException(401, "Invalid credentials.")
    return {"token": "demo.%s" % inv["id"], "profile": inv, "expiresAt": "2099-12-31T23:59:59Z"}


@app.get("/api/profile")
def profile():
    return rows("investigators")[0]


@app.get("/api/dashboard")
def dashboard():
    cases = rows("cases"); entities = rows("entities"); rels = rows("relationships"); alerts = rows("alerts"); events = rows("events")
    return {
        "activeCases": sum(c.get("status") == "ACTIVE" for c in cases),
        "entitiesAnalyzed": len(entities),
        "highRiskConnections": sum(r.get("strength", 0) >= 8 for r in rels),
        "suspiciousPatterns": sum(a.get("status") in ("NEW", "INVESTIGATING") for a in alerts),
        "recentEvents": sorted(events, key=lambda x: x.get("occurredAt", ""), reverse=True)[:6],
        "recentCases": sorted(cases, key=lambda x: x.get("updatedAt", ""), reverse=True)[:5],
        "openAlerts": [a for a in sorted(alerts, key=lambda x: x.get("createdAt", ""), reverse=True) if a.get("status") == "NEW"][:6],
    }


@app.get("/api/cases")
def list_cases(q: str | None = None, status: str | None = None, priority: str | None = None, page_num: int = Query(1, alias="page"), page_size: int = Query(25, alias="pageSize")):
    out = rows("cases")[:]
    if status: out = [c for c in out if c.get("status") == status]
    if priority: out = [c for c in out if c.get("priority") == priority]
    if q:
        s=q.lower(); out=[c for c in out if s in (c.get("title","")+c.get("code","")+c.get("summary","")).lower()]
    out.sort(key=lambda x:x.get("updatedAt", ""), reverse=True)
    return page(out, page_num, page_size)


@app.get("/api/cases/{cid}")
def get_case(cid: str):
    c = next((x for x in rows("cases") if x["id"] == cid), None)
    if not c: raise HTTPException(404, "Case not found.")
    return c


@app.get("/api/entities")
def list_entities(q: str | None=None, type: str | None=None, status: str | None=None, riskMin: float | None=None, page_num: int=Query(1, alias="page"), page_size: int=Query(25, alias="pageSize")):
    out=rows("entities")[:]
    if type: out=[e for e in out if e.get("type")==type]
    if status: out=[e for e in out if e.get("status")==status]
    if riskMin is not None: out=[e for e in out if e.get("riskScore",0)>=riskMin]
    if q: out=[e for e in out if contains_entity(e,q)]
    out.sort(key=lambda x:x.get("riskScore",0), reverse=True)
    return page(out,page_num,page_size)


@app.get("/api/entities/{eid}")
def get_entity(eid: str):
    e=find_entity(eid)
    if not e: raise HTTPException(404,"Entity not found.")
    return e


@app.get("/api/search")
def search(q: str=""):
    s=q.lower()
    return {
      "entities":[e for e in rows("entities") if contains_entity(e,q)][:20],
      "cases":[c for c in rows("cases") if s in (c.get("title","")+c.get("code","")+" ".join(c.get("tags",[]))).lower()][:10],
      "events":[e for e in rows("events") if s in (e.get("title","")+e.get("description","")).lower()][:10],
    }


@app.get("/api/network/{eid}")
def network(eid: str, depth: int=1, types: str|None=None):
    if not find_entity(eid): raise HTTPException(404,"Entity not found.")
    depth=max(1,min(depth,2)); allowed=set(types.split(",")) if types else None
    seen={eid}; frontier=[eid]
    for _ in range(depth):
        nxt=[]
        for fid in frontier:
            for r in rows("relationships"):
                other=r["targetId"] if r["sourceId"]==fid else r["sourceId"] if r["targetId"]==fid else None
                if other and other not in seen and (not allowed or r.get("type") in allowed): seen.add(other); nxt.append(other)
        frontier=nxt
    nodes=[find_entity(x) for x in seen]; nodes=[x for x in nodes if x]
    edges=[r for r in rows("relationships") if r["sourceId"] in seen and r["targetId"] in seen and (not allowed or r.get("type") in allowed)]
    return {"centerId":eid,"nodes":nodes,"edges":edges}


def filtered(name, params, date_field=None):
    out=rows(name)[:]
    for key,val in params.items():
        if val is not None and key in ("entityId","caseId","type","severity","status","kind","number","direction","channel","accountId"):
            if key=="number": out=[x for x in out if val in x.get("callerNumber","") or val in x.get("calleeNumber","")]
            else: out=[x for x in out if x.get(key)==val]
    if params.get("q"):
        q=params["q"].lower(); out=[x for x in out if q in str(x).lower()]
    if params.get("minAmount") is not None: out=[x for x in out if x.get("amount",0)>=float(params["minAmount"])]
    if date_field:
        if params.get("from"): out=[x for x in out if x.get(date_field,"")>=params["from"]]
        if params.get("to"): out=[x for x in out if x.get(date_field,"")<=params["to"]+"T23:59:59"]
    return out


@app.get("/api/relationships")
def relationships(entityId:str|None=None,type:str|None=None,page_num:int=Query(1,alias="page"),page_size:int=Query(25,alias="pageSize")):
    out=filtered("relationships",{"entityId":None})
    if entityId: out=[r for r in out if r["sourceId"]==entityId or r["targetId"]==entityId]
    if type: out=[r for r in out if r.get("type")==type]
    out.sort(key=lambda x:x.get("strength",0),reverse=True); return page(out,page_num,page_size)


@app.get("/api/events")
def events(entityId:str|None=None,caseId:str|None=None,type:str|None=None,severity:str|None=None,from_:str|None=Query(None,alias="from"),to:str|None=None,page_num:int=Query(1,alias="page"),page_size:int=Query(50,alias="pageSize")):
    out=filtered("events",{"entityId":None,"caseId":caseId,"type":type,"severity":severity,"from":from_,"to":to},"occurredAt")
    if entityId: out=[e for e in out if entityId in e.get("entityIds",[])]
    out.sort(key=lambda x:x.get("occurredAt", ""),reverse=True); return page(out,page_num,page_size)


@app.get("/api/locations")
def locations(q:str|None=None,type:str|None=None,page_num:int=Query(1,alias="page"),page_size:int=Query(25,alias="pageSize")):
    out=rows("locations")[:]
    if type: out=[x for x in out if x.get("type")==type]
    if q: out=[x for x in out if q.lower() in (x.get("name","")+x.get("address","")).lower()]
    return page(out,page_num,page_size)


@app.get("/api/transactions")
def transactions(accountId:str|None=None,direction:str|None=None,channel:str|None=None,minAmount:float|None=None,from_:str|None=Query(None,alias="from"),to:str|None=None,page_num:int=Query(1,alias="page"),page_size:int=Query(50,alias="pageSize")):
    out=filtered("transactions",{"accountId":accountId,"direction":direction,"channel":channel,"minAmount":minAmount,"from":from_,"to":to},"occurredAt")
    out.sort(key=lambda x:x.get("occurredAt", ""),reverse=True); return page(out,page_num,page_size)


@app.get("/api/cdr")
def cdr(number:str|None=None,kind:str|None=None,from_:str|None=Query(None,alias="from"),to:str|None=None,page_num:int=Query(1,alias="page"),page_size:int=Query(50,alias="pageSize")):
    out=filtered("cdrRecords",{"number":number,"kind":kind,"from":from_,"to":to},"startedAt")
    out.sort(key=lambda x:x.get("startedAt", ""),reverse=True); return page(out,page_num,page_size)


@app.get("/api/alerts")
def alerts(severity:str|None=None,status:str|None=None,page_num:int=Query(1,alias="page"),page_size:int=Query(25,alias="pageSize")):
    out=filtered("alerts",{"severity":severity,"status":status}); out.sort(key=lambda x:x.get("createdAt", ""),reverse=True); return page(out,page_num,page_size)


@app.post("/api/alerts/{aid}/ack")
def ack(aid:str):
    a=next((x for x in rows("alerts") if x["id"]==aid),None)
    if not a: raise HTTPException(404,"Alert not found.")
    if a["status"]=="NEW": a["status"]="ACKNOWLEDGED"
    return a


@app.get("/api/sources")
def sources(): return rows("dataSources")


class ImportBody(BaseModel): records:int=0

@app.post("/api/sources/{source_id}/import")
def import_data(source_id:str, body:ImportBody):
    source=next((x for x in rows("dataSources") if x["id"]==source_id),None)
    if not source: raise HTTPException(404,"Data source not found.")
    source["recordsIngested"] += max(0, body.records)
    return {"sourceId":source_id,"status":"IMPORTED","recordsImported":max(0,body.records),"recordsIngested":source["recordsIngested"]}


@app.post("/api/reports")
def report(body:dict):
    cid=body.get("caseId"); c=next((x for x in rows("cases") if x["id"]==cid),None)
    if not c: raise HTTPException(404,"Case not found.")
    ents=[e for e in rows("entities") if e["id"] in c.get("entityIds",[])]
    evs=[e for e in rows("events") if e.get("caseId")==cid]
    als=[a for a in rows("alerts") if a.get("caseId")==cid]
    return {"caseId":cid,"title":f"{c['code']} — Intelligence Summary","generatedAt":"2026-09-11T00:00:00Z","sections":[
      {"heading":"1. Case Overview","body":c.get("summary","")},
      {"heading":"2. Principal Subjects","body":"Highest-risk linked entities by composite risk score.","table":{"columns":["Entity","Type","Risk","Status"],"rows":[[e["label"],e["type"],str(e["riskScore"]),e["status"]] for e in sorted(ents,key=lambda x:x["riskScore"],reverse=True)[:10]]}},
      {"heading":"3. Key Findings","bullets":[f"{sum(a.get('severity')=='CRITICAL' for a in als)} critical and {sum(a.get('severity')=='HIGH' for a in als)} high-severity alerts associated with this case.",f"{len(evs)} events are present on the case timeline."]},
    ]}
