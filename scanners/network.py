
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from .safety import validate_host, TargetError

ALLOWED_PORTS = {
    22, 53, 80, 443, 445, 3306, 5432,
    6379, 8080, 8443, 27017,
}


def scan_tcp(host: str, ports: list[int]) -> dict:
    addresses = validate_host(host)

    if not ports or len(ports) > 12:
        raise TargetError("اختر من منفذ واحد إلى 12 منفذاً.")

    if any(port not in ALLOWED_PORTS for port in ports):
        raise TargetError("يوجد منفذ خارج القائمة المسموحة.")

    def probe(port: int) -> dict:
        try:
            with socket.create_connection(
                (addresses[0], port), timeout=1.5
            ):
                state = "open"
                evidence = "نجح اتصال TCP."
        except ConnectionRefusedError:
            state = "closed"
            evidence = "رفض الهدف الاتصال."
        except (TimeoutError, socket.timeout):
            state = "unknown"
            evidence = "انتهت المهلة؛ الحالة غير مؤكدة."
        except OSError as exc:
            state = "error"
            evidence = type(exc).__name__

        return {
            "port": port,
            "state": state,
            "evidence": evidence,
        }

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(probe, sorted(set(ports))))

    return {
        "scan_type": "network",
        "target": host,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "resolved_addresses": addresses,
        "ports": results,
        "note": "المنفذ المفتوح ليس ثغرة بحد ذاته.",
    }
