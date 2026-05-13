from fastapi import FastAPI, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from .collector import ingest_tail
from .db import query_events, summary
from .config import APP_NAME

app = FastAPI(title=APP_NAME)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    ingest_tail(2000)
    data = summary()
    events = query_events(limit=100)
    return templates.TemplateResponse("index.html", {"request": request, "data": data, "events": events, "app_name": APP_NAME})

@app.get("/api/ingest")
def api_ingest(lines: int = 2000):
    return {"ingested_lines_checked": ingest_tail(lines)}

@app.get("/api/events")
def api_events(limit: int = Query(200, le=2000), source: str | None = None, severity: str | None = None, ip: str | None = None):
    return JSONResponse(query_events(limit=limit, source=source, severity=severity, ip=ip))

@app.get("/api/summary")
def api_summary():
    ingest_tail(2000)
    return summary()
