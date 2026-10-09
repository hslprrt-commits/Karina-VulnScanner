
import re
from datetime import datetime, timezone

RULES = [
    (
        "critical",
        "مفتاح خاص محتمل",
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "إذا كان المفتاح حقيقياً ومكشوفاً، أبطله ودوّره.",
    ),
    (
        "high",
        "سر محتمل داخل الكود",
        r"""(?i)\b(?:api_key|secret_key|access_token|password)\b\s*[:=]\s*['"][^'"]{8,}['"]""",
        "استخدم مدير أسرار ودوّر الأسرار الحقيقية المكشوفة.",
    ),
    (
        "high",
        "استدعاء eval",
        r"\beval\s*\(",
        "راجع المصدر والمدخلات؛ تجنب تقييم مدخلات غير موثوقة.",
    ),
    (
        "medium",
        "تعطيل تحقق TLS",
        r"(?i)(verify\s*=\s*False|CERT_NONE)",
        "لا تعطّل التحقق من الشهادات في بيئة الإنتاج.",
    ),
    (
        "medium",
        "أمر SQL مركب نصياً",
        r"""(?i)execute\s*\(\s*f['"]""",
        "استخدم استعلامات SQL ذات المعاملات.",
    ),
]


def analyze_source(filename: str, content: str) -> dict:
    findings = []

    for number, line in enumerate(content.splitlines(), 1):
        for severity, title, pattern, fix in RULES:
            if re.search(pattern, line):
                findings.append({
                    "severity": severity,
                    "title": title,
                    "evidence": f"{filename}:{number}: {line.strip()[:180]}",
                    "line": number,
                    "recommendation": fix,
                    "confidence": "مطابقة نمطية تحتاج مراجعة بشرية",
                })

    return {
        "scan_type": "code",
        "target": filename,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "lines": len(content.splitlines()),
            "findings": len(findings),
        },
        "findings": findings,
        "note": "النتائج مؤشرات وليست إثباتاً لقابلية الاستغلال.",
    }
