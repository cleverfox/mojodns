"""Reachability checks for an A/AAAA record's IP, run from the panel.

  check_tcp   — raw TCP connect to ip:port
  check_http  — HTTP/1.1 GET to ip:80 with Host: <record name>
  check_https — TLS to ip:443 with SNI=<record name>, capture the peer cert
                *even if invalid*, analyze it, then do the HTTP request anyway

All best-effort and time-bounded. IPv6 literals are handled (the panel needs
IPv6 egress for AAAA targets).
"""

import datetime as dt
import socket
import ssl
import time

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

from .config import settings


def _timeout() -> float:
    return settings().check_timeout


def _family(ip: str) -> int:
    return socket.AF_INET6 if ":" in ip else socket.AF_INET


def _http_request(sock, host: str) -> dict:
    """Send a minimal HTTP/1.1 GET over an (optionally TLS) socket and parse
    the status line + a couple of headers."""
    req = (f"GET / HTTP/1.1\r\nHost: {host}\r\n"
           "User-Agent: mojodns-check/1\r\nAccept: */*\r\nConnection: close\r\n\r\n")
    sock.sendall(req.encode())
    buf = b""
    try:
        while b"\r\n\r\n" not in buf and len(buf) < 16384:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
    except (socket.timeout, OSError):
        pass
    if not buf:
        return {"http_status": None, "server": None, "location": None, "detail": "no HTTP response"}
    head = buf.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
    lines = head.split("\r\n")
    status_line = lines[0] if lines else ""
    http_status = None
    parts = status_line.split(" ", 2)
    if len(parts) >= 2 and parts[1].isdigit():
        http_status = int(parts[1])
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return {"http_status": http_status, "status_line": status_line,
            "server": headers.get("server"), "location": headers.get("location"),
            "detail": None}


def check_tcp(ip: str, port: int) -> dict:
    t0 = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=_timeout()):
            return {"kind": "tcp", "ip": ip, "port": port, "status": "ok",
                    "latency_ms": round((time.monotonic() - t0) * 1000),
                    "detail": "connection established"}
    except (ConnectionRefusedError,) as e:
        return {"kind": "tcp", "ip": ip, "port": port, "status": "refused", "detail": "connection refused"}
    except (socket.timeout, TimeoutError):
        return {"kind": "tcp", "ip": ip, "port": port, "status": "timeout", "detail": "timed out"}
    except OSError as e:
        return {"kind": "tcp", "ip": ip, "port": port, "status": "error", "detail": str(e)}


def check_http(ip: str, host: str, port: int = 80) -> dict:
    host = host.rstrip(".")  # SNI / Host header / cert names carry no trailing dot
    t0 = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=_timeout()) as s:
            s.settimeout(_timeout())
            r = _http_request(s, host)
    except (ConnectionRefusedError,):
        return {"kind": "http", "ip": ip, "host": host, "port": port, "status": "refused", "detail": "connection refused"}
    except (socket.timeout, TimeoutError):
        return {"kind": "http", "ip": ip, "host": host, "port": port, "status": "timeout", "detail": "timed out"}
    except OSError as e:
        return {"kind": "http", "ip": ip, "host": host, "port": port, "status": "error", "detail": str(e)}
    status = "ok" if r["http_status"] else "error"
    return {"kind": "http", "ip": ip, "host": host, "port": port, "status": status,
            "latency_ms": round((time.monotonic() - t0) * 1000), **r}


def _name(cert_name) -> str:
    try:
        cn = cert_name.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn:
            return cn[0].value
    except Exception:
        pass
    return cert_name.rfc4514_string()


def _sans(cert) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        return ext.value.get_values_for_type(x509.DNSName)
    except Exception:
        return []


def _host_matches(host: str, names: list[str]) -> bool:
    host = host.rstrip(".").lower()
    for n in names:
        n = n.rstrip(".").lower()
        if n == host:
            return True
        if n.startswith("*.") and "." in host and host.split(".", 1)[1] == n[2:]:
            return True
    return False


def _analyze_cert(der: bytes, host: str) -> dict:
    cert = x509.load_der_x509_certificate(der)
    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:  # older cryptography
        not_before = cert.not_valid_before.replace(tzinfo=dt.timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=dt.timezone.utc)
    now = dt.datetime.now(dt.timezone.utc)
    sans = _sans(cert)
    subject = _name(cert.subject)
    issuer = _name(cert.issuer)
    return {
        "subject": subject,
        "issuer": issuer,
        "sans": sans,
        "not_before": not_before,
        "not_after": not_after,
        "days_left": (not_after - now).days,
        "expired": now > not_after,
        "not_yet_valid": now < not_before,
        "self_signed": cert.subject == cert.issuer,
        "hostname_match": _host_matches(host, sans or [subject]),
    }


def check_https(ip: str, host: str, port: int = 443) -> dict:
    host = host.rstrip(".")  # SNI / Host header / cert names carry no trailing dot
    t0 = time.monotonic()
    out = {"kind": "https", "ip": ip, "host": host, "port": port,
           "status": "error", "tls_ok": False, "cert": None,
           "http_status": None, "server": None, "location": None, "detail": None}

    # 1) lenient connection: capture cert (even if invalid) + do the HTTP request.
    # Verification is intentionally OFF here — this is a diagnostic probe whose
    # whole purpose is to inspect expired / self-signed / wrong-host certs and
    # still report the HTTP result. The real trust verdict comes from the
    # verifying handshake in step 2; no secrets are sent over this socket.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        raw = socket.create_connection((ip, port), timeout=_timeout())
    except (ConnectionRefusedError,):
        out["status"] = "refused"; out["detail"] = "connection refused"; return out
    except (socket.timeout, TimeoutError):
        out["status"] = "timeout"; out["detail"] = "timed out"; return out
    except OSError as e:
        out["status"] = "error"; out["detail"] = str(e); return out
    try:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            tls.settimeout(_timeout())
            out["tls_ok"] = True
            der = tls.getpeercert(binary_form=True)
            if der:
                try:
                    out["cert"] = _analyze_cert(der, host)
                except Exception as e:
                    out["cert"] = {"error": f"cert parse failed: {e}"}
            r = _http_request(tls, host)
            out.update({k: r.get(k) for k in ("http_status", "status_line", "server", "location")})
    except ssl.SSLError as e:
        out["status"] = "error"; out["detail"] = f"TLS error: {e.reason or e}"; return out
    except OSError as e:
        out["status"] = "error"; out["detail"] = str(e); return out

    # 2) best-effort verifying handshake → trust verdict
    trusted, trust_error = False, None
    try:
        vctx = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout=_timeout()) as vraw:
            with vctx.wrap_socket(vraw, server_hostname=host):
                trusted = True
    except ssl.SSLCertVerificationError as e:
        trust_error = e.verify_message or str(e)
    except Exception as e:
        trust_error = str(e)
    if isinstance(out["cert"], dict):
        out["cert"]["trusted"] = trusted
        out["cert"]["trust_error"] = trust_error

    out["status"] = "ok" if out["http_status"] else ("tls-only" if out["tls_ok"] else "error")
    out["latency_ms"] = round((time.monotonic() - t0) * 1000)
    return out
