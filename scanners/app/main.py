
import json
from pathlib import Path

from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .scanners.safety import TargetError
from .scanners.web import scan_website
from .scanners.network import scan_tcp
from .scanners.code import analyze_source

BASE = Path(__file__).resolve().parent

app = FastAPI(title="Karina VulnScanner", version="0.1.0")
app.mount(
    "/static",
    StaticFiles(directory=BASE / "static"),
    name="static",
)


class WebsiteRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)
    authorized: bool


class NetworkRequest(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    ports: list[int] = Field(min_length=1, max_length=12)
    authorized: bool


def check_authorization(authorized: bool):
    if not authorized:
        raise HTTPException(
            400,
            "أكد أنك تملك الهدف أو لديك تصريح بفحصه.",
        )


@app.get("/", response_class=HTMLResponse)
async def home():
    return (BASE / "static" / "index.html").read_text(
        encoding="utf-8"
    )


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}


@app.post("/api/scan/website")
async def website(body: WebsiteRequest):
    check_authorization(body.authorized)
    try:
        return await scan_website(body.url)
    except TargetError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            500, f"فشل الفحص: {type(exc).__name__}"
        ) from exc


@app.post("/api/scan/network")
async def network(body: NetworkRequest):
    check_authorization(body.authorized)
    try:
        return scan_tcp(body.host, body.ports)
    except TargetError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            500, f"فشل الفحص: {type(exc).__name__}"
        ) from exc


@app.post("/api/scan/code")
async def code(
    file: UploadFile = File(...),
    authorized: bool = Form(...),
):
    check_authorization(authorized)

    filename = Path(file.filename or "source.txt").name
    allowed = {
        ".py", ".js", ".ts", ".tsx", ".jsx", ".java",
        ".go", ".php", ".rb", ".cs", ".cpp", ".c",
        ".h", ".yaml", ".yml", ".json", ".txt", ".sql",
    }

    if Path(filename).suffix.lower() not in allowed:
        raise HTTPException(415, "امتداد الملف غير مدعوم.")

    raw = await file.read(1_000_001)

    if len(raw) > 1_000_000:
        raise HTTPException(413, "الحد الأقصى 1 ميغابايت.")

    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(
            415, "الملف يجب أن يكون نص UTF-8."
        ) from exc

    return analyze_source(filename, content)


@app.post("/api/report/export")
async def export_report(payload: dict):
    content = json.dumps(
        payload, ensure_ascii=False, indent=2
    )
    return Response(
        content=content,
        media_type="application/json",
        headers={
            "Content-Disposition":
                'attachment; filename="karina-report.json"'
        },
    )
