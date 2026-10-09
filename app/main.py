cat > app/main.py <<'PY'
from pathlib import Path
import json
import re
import socket
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
MAX_FILE_SIZE = 1_000_000

app = FastAPI(
    title="Karina VulnScanner",
    description="Security checks for authorized systems",
    version="0.1.0",
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

SECURITY_HEADERS = {
    "content-security-policy": "Content Security Policy",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def public_host(host):
    try:
        ip = ipaddress.ip_address(host)
        addresses = [ip]
    except ValueError:
        try:
            records = socket.getaddrinfo(
                host, None, type=socket.SOCK_STREAM
            )
            addresses = [
                ipaddress.ip_address(record[4][0])
                for record in records
            ]
        except socket.gaierror:
            raise ValueError("تعذر حل اسم المضيف")

    if not addresses or any(not address.is_global for address in addresses):
        raise ValueError(
            "الهدف غير عام أو يتضمن عنواناً غير مسموح به"
        )

    return addresses


def validate_url(value):
    parsed = urlparse(value.strip())

    if parsed.scheme not in ("http", "https"):
        raise ValueError("استخدم عنوان HTTP أو HTTPS")

    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("عنوان URL غير صالح")

    public_host(parsed.hostname)

    return parsed


@app.get("/", response_class=HTMLResponse)
async def home():
    return (STATIC_DIR / "index.html").read_text(encoding="utf-8")


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "name": "Karina VulnScanner",
        "version": "0.1.0",
    }


@app.post("/api/scan/website")
async def scan_website(url: str = Form(...), authorized: bool = Form(False)):
    if not authorized:
        raise HTTPException(400, "أكد امتلاكك إذناً لفحص الهدف")

    try:
        parsed = validate_url(url)
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    findings = []

    try:
        # Do not follow redirects: each redirect needs independent validation.
        async with httpx.AsyncClient(
            timeout=8,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            response = await client.get(
                url,
                headers={"User-Agent": "KarinaVulnScanner/0.1"},
            )

        headers = {
            key.lower(): value
            for key, value in response.headers.items()
        }

        for key, name in SECURITY_HEADERS.items():
            if key not in headers:
                findings.append({
                    "severity": "info",
                    "title": f"ترويسة غير موجودة: {name}",
                    "detail": "راجع ما إذا كانت هذه الترويسة مناسبة لتطبيقك.",
                })

        if parsed.scheme == "https" and "strict-transport-security" not in headers:
            findings.append({
                "severity": "low",
                "title": "ترويسة HSTS غير موجودة",
                "detail": "راجع سياسة HTTPS المناسبة لخادمك.",
            })

        if parsed.scheme == "http":
            findings.append({
                "severity": "medium",
                "title": "الاتصال يستخدم HTTP",
                "detail": "استخدم HTTPS لحماية البيانات أثناء النقل.",
            })

        if (
            headers.get("access-control-allow-origin") == "*"
            and headers.get("access-control-allow-credentials", "").lower() == "true"
        ):
            findings.append({
                "severity": "medium",
                "title": "إعدادات CORS تستحق المراجعة",
                "detail": "تحقق من سياسة مشاركة الموارد بين المصادر.",
            })

        return {
            "target": url,
            "timestamp": timestamp(),
            "http_status": response.status_code,
            "findings": findings,
            "note": "هذه مؤشرات إعدادات وليست إثباتاً على وجود ثغرة.",
        }

    except httpx.HTTPError as exc:
        raise HTTPException(502, f"تعذر إكمال طلب HTTP: {type(exc).__name__}")


@app.post("/api/scan/network")
async def scan_network(
    host: str = Form(...),
    ports: str = Form("80,443"),
    authorized: bool = Form(False),
):
    if not authorized:
        raise HTTPException(400, "أكد امتلاكك إذناً لفحص الهدف")

    try:
        addresses = public_host(host.strip())
        parsed_ports = [int(p.strip()) for p in ports.split(",") if p.strip()]
    except (ValueError, TypeError) as exc:
        raise HTTPException(400, str(exc))

    allowed_ports = {22, 53, 80, 443, 445, 3306, 5432, 6379, 8080, 8443, 27017}

    if not parsed_ports or len(parsed_ports) > 12:
        raise HTTPException(400, "حدد من 1 إلى 12 منفذاً")

    if any(port not in allowed_ports for port in parsed_ports):
        raise HTTPException(400, "يوجد منفذ خارج قائمة المنافذ المسموحة")

    results = []

    for port in sorted(set(parsed_ports)):
        try:
            with socket.create_connection((str(addresses[0]), port), timeout=1.5):
                state = "open"
        except ConnectionRefusedError:
            state = "closed"
        except (TimeoutError, OSError):
            state = "unknown"

        results.append({"port": port, "state": state})

    return {
        "target": host,
        "timestamp": timestamp(),
        "results": results,
        "note": "وجود منفذ مفتوح لا يعني بحد ذاته وجود ثغرة.",
    }


@app.post("/api/scan/code")
async def scan_code(
    file: UploadFile = File(...),
    authorized: bool = Form(False),
):
    if not authorized:
        raise HTTPException(400, "أكد أن لديك الحق بتحليل هذا الملف")

    allowed_extensions = {".py", ".js", ".ts", ".java", ".php", ".go", ".txt"}
    suffix = Path(file.filename or "").suffix.lower()

    if suffix not in allowed_extensions:
        raise HTTPException(400, "امتداد الملف غير مدعوم")

    raw = await file.read(MAX_FILE_SIZE + 1)
    if len(raw) > MAX_FILE_SIZE:
        raise HTTPException(413, "الحد الأقصى لحجم الملف هو 1MB")

    try:
        source = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(400, "يجب أن يكون الملف نصياً بترميز UTF-8")

    rules = [
        (
            "possible_secret",
            re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
            "قد يحتوي السطر على سر ثابت؛ تحقق منه ولا تشارك قيمته.",
        ),
        (
            "dangerous_eval",
            re.compile(r"\beval\s*\("),
            "استخدام eval قد يكون خطراً مع مدخلات غير موثوقة.",
        ),
        (
            "disabled_tls_check",
            re.compile(r"verify\s*=\s*False|CERT_NONE"),
            "تعطيل التحقق من شهادة TLS قد يضعف أمان الاتصال.",
        ),
        (
            "sql_string_interpolation",
            re.compile(r"execute\s*\(\s*f['\"]"),
            "راجع بناء استعلام SQL؛ استخدم الاستعلامات المعلّمة.",
        ),
    ]

    findings = []
    for line_number, line in enumerate(source.splitlines(), start=1):
        for rule_id, pattern, description in rules:
            if pattern.search(line):
                findings.append({
                    "rule": rule_id,
                    "line": line_number,
                    "detail": description,
                    "confidence": "pattern-match; manual review required",
                })

    return {
        "filename": Path(file.filename or "uploaded").name,
        "timestamp": timestamp(),
        "lines_analyzed": len(source.splitlines()),
        "findings": findings,
        "note": "تحليل أنماط أولي؛ قد ينتج عنه إنذارات كاذبة أو يفوّت مشكلات.",
    }


@app.post("/api/report/export")
async def export_report(report: dict):
    return JSONResponse(
        content={
            "tool": "Karina VulnScanner",
            "exported_at": timestamp(),
            "report": report,
        },
        headers={"Content-Disposition": 'attachment; filename="karina-report.json"'},
    )
PY
