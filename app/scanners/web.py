
import asyncio
import socket
import ssl
from datetime import datetime, timezone

import httpx

from .safety import validate_host, validate_url

HEADERS = {
    "content-security-policy": (
        "متوسط",
        "راجع إضافة سياسة CSP مناسبة للتطبيق."
    ),
    "x-content-type-options": (
        "منخفض",
        "أضف X-Content-Type-Options: nosniff."
    ),
    "x-frame-options": (
        "منخفض",
        "اضبط سياسة منع تضمين الصفحات حسب الحاجة."
    ),
    "referrer-policy": (
        "منخفض",
        "اضبط سياسة Referrer-Policy."
    ),
    "permissions-policy": (
        "منخفض",
        "راجع الميزات المتاحة عبر Permissions-Policy."
    ),
}


async def scan_website(raw_url: str) -> dict:
    url, host = validate_url(raw_url)
    findings = []
    errors = []
    response_data = {}

    try:
        async with httpx.AsyncClient(
            timeout=8.0,
            follow_redirects=False,
            trust_env=False,
            headers={
                "User-Agent": "KarinaVulnScanner/0.1"
            },
        ) as client:
            response = await client.get(url)

        headers = {
            key.lower(): value
            for key, value in response.headers.items()
        }

        response_data = {
            "status_code": response.status_code,
            "redirect_not_followed": response.is_redirect,
            "server_header": headers.get("server"),
        }

        for name, (severity, recommendation) in HEADERS.items():
            if name not in headers:
                findings.append({
                    "severity": severity,
                    "title": f"ترويسة مفقودة: {name}",
                    "evidence": "لم تظهر الترويسة في الاستجابة.",
                    "recommendation": recommendation,
                    "confidence": "مؤشر إعداد، وليس إثبات ثغرة",
                })

        if url.startswith("https://"):
            if "strict-transport-security" not in headers:
                findings.append({
                    "severity": "متوسط",
                    "title": "ترويسة HSTS غير موجودة",
                    "evidence": "لم تظهر Strict-Transport-Security.",
                    "recommendation": (
                        "راجع تفعيل HSTS بعد التأكد من جاهزية HTTPS."
                    ),
                    "confidence": "مؤشر إعداد",
                })
        else:
            findings.append({
                "severity": "متوسط",
                "title": "الرابط يستخدم HTTP",
                "evidence": "الاتصال المطلوب غير مشفر.",
                "recommendation": "استخدم HTTPS بشهادة صحيحة.",
                "confidence": "مؤكد للرابط المقدم",
            })

        origin = headers.get("access-control-allow-origin")
        credentials = headers.get(
            "access-control-allow-credentials", ""
        ).lower()

        if origin == "*" and credentials == "true":
            findings.append({
                "severity": "متوسط",
                "title": "إعداد CORS يحتاج مراجعة",
                "evidence": (
                    "ظهرت قيمة origin عامة مع credentials=true."
                ),
                "recommendation": (
                    "راجع إعداد CORS وسلوك المتصفح الفعلي."
                ),
                "confidence": "مؤشر يحتاج تحقق",
            })

    except (httpx.HTTPError, OSError, ValueError) as exc:
        errors.append(
            f"{type(exc).__name__}: {str(exc)[:180]}"
        )

    tls = {"checked": False}

    if url.startswith("https://"):
        try:
            # تحقق من شهادة TLS باستخدام مخزن الشهادات الموثوق.
            def inspect_tls():
                validate_host(host)
                context = ssl.create_default_context()
                with socket.create_connection(
                    (host, 443), timeout=5
                ) as raw:
                    with context.wrap_socket(
                        raw, server_hostname=host
                    ) as secure:
                        cert = secure.getpeercert()
                        return {
                            "checked": True,
                            "version": secure.version(),
                            "expires": cert.get("notAfter"),
                        }

            tls = await asyncio.to_thread(inspect_tls)

        except Exception as exc:
            tls = {
                "checked": False,
                "error": type(exc).__name__,
            }

    return {
        "scan_type": "website",
        "target": url,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "response": response_data,
        "tls": tls,
        "findings": findings,
        "errors": errors,
        "note": "غياب ترويسة لا يثبت وحده وجود ثغرة قابلة للاستغلال.",
    }
