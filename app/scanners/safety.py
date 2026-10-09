
import ipaddress
import socket
from urllib.parse import urlparse


class TargetError(ValueError):
    pass


def validate_host(host: str) -> list[str]:
    if not host or host.strip() != host:
        raise TargetError("اسم المضيف غير صالح.")

    try:
        addresses = [str(ipaddress.ip_address(host))]
    except ValueError:
        try:
            addresses = sorted({
                item[4][0]
                for item in socket.getaddrinfo(
                    host, None, type=socket.SOCK_STREAM
                )
            })
        except socket.gaierror as exc:
            raise TargetError("تعذر العثور على عنوان المضيف.") from exc

    if not addresses:
        raise TargetError("لم يتم العثور على عنوان.")

    for address in addresses:
        ip = ipaddress.ip_address(address.split("%")[0])
        if not ip.is_global:
            raise TargetError(
                "مرفوض: الهدف يحل إلى عنوان IP غير عام."
            )

    return addresses


def validate_url(value: str) -> tuple[str, str]:
    parsed = urlparse(value.strip())

    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise TargetError("أدخل رابط HTTP أو HTTPS صالحاً.")

    if parsed.username or parsed.password:
        raise TargetError("لا تضع بيانات الدخول داخل الرابط.")

    try:
        host = parsed.hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise TargetError("اسم النطاق غير صالح.") from exc

    validate_host(host)
    return parsed.geturl(), host
