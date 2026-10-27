#!/usr/bin/env python3
"""
php2shell_version_scanner.py — Scanner PASIVO de versiones de PHP
=================================================================
CVE-2026-109618 / CVE-2026-109619 (php2shell)   ·   v1.2

Autor:  Manuel Moreno — CEO, GLOBALSECURE
Web:    https://www.globalsecure.cl

Qué hace
--------
Comprueba, de forma NO intrusiva, si la versión de PHP anunciada por un host
es vulnerable a php2shell. SOLO lee cabeceras HTTP (`Server`, `X-Powered-By`)
y compara la versión contra las versiones parcheadas. No envía exploits, no
sube ficheros, no toca sesiones ni ejecuta ninguna de las cadenas de la PoC.

Es un simple "banner / version check": el mismo tipo de verificación que hace
cualquier inventario de activos.

Entradas admitidas
------------------
  * IP o dominio sueltos            --target 10.0.0.5  (repetible)
  * Segmento de red (CIDR)          --cidr 10.0.0.0/24 (repetible)
  * Fichero con una IP/host por línea  --file objetivos.txt
    (admite "ip:puerto", comentarios con # y líneas en blanco)

Salida
------
  * Tabla en consola con color
  * Veredicto: VULNERABLE / PARCHEADO / DESCONOCIDO / SIN-PHP / SIN-RESPUESTA
  * Versión de PHP detectada + versión parcheada recomendada
  * Datos extra: esquema, puerto, código HTTP, cabecera Server, si la versión
    está oculta (expose_php Off), estado EOL de la rama, latencia
  * Exportación opcional a CSV (--csv) y JSON (--json)

Uso
---
  python3 php2shell_version_scanner.py --target www.cliente.com
  python3 php2shell_version_scanner.py --cidr 192.168.1.0/24 --ports 80,443,8080
  python3 php2shell_version_scanner.py --file objetivos.txt --json salida.json --csv salida.csv

SOLO para evaluaciones de seguridad autorizadas sobre activos propios o de
clientes con permiso por escrito.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import csv
import datetime
import http.client
import ipaddress
import json
import re
import socket
import ssl
import sys
import threading
import uuid
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict, field
from typing import Optional

__version__ = "1.2"

# ───────────────────────── Base de conocimiento ─────────────────────────
# Versiones donde se corrige php2shell (CVE-2026-109618 / 109619).
# Dentro de cada rama, < versión_fijada  => VULNERABLE.
FIXED_BY_BRANCH: dict[tuple[int, int], tuple[int, int, int]] = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}

# Rango afectado declarado por el advisory del repo: PHP 5.4 – 8.5.
AFFECTED_FLOOR = (5, 4)          # primera versión dentro del rango vulnerable
AFFECTED_CEIL_BRANCH = (8, 5)    # última rama con parche conocido

# Ramas EOL (sin soporte): aunque la versión instalada sea "la última de su
# rama", esa rama no recibirá el parche, por lo que se considera vulnerable.
EOL_BRANCHES = {
    (5, 4), (5, 5), (5, 6),
    (7, 0), (7, 1), (7, 2), (7, 3), (7, 4),
    (8, 0), (8, 1),
}

PHP_VERSION_RE = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)", re.IGNORECASE)

# Señales de que el backend es PHP aunque oculte la versión.
PHP_COOKIE_RE = re.compile(r"\bPHPSESSID\s*=", re.IGNORECASE)

# Firmas de CDN/WAF: (nombre_producto, subcadenas_en_Server, cabeceras_delatoras).
# El resultado SIEMPRE es el nombre del producto, nunca el nombre de la cabecera.
CDN_WAF_SIGNATURES = (
    ("Cloudflare",       ("cloudflare",),            ("cf-ray", "cf-cache-status", "cf-mitigated", "cf-request-id")),
    ("Akamai",           ("akamaighost", "akamai"),  ("x-akamai-transformed", "akamai-grn", "x-akamai-request-id")),
    ("Fastly",           ("fastly",),                ("x-served-by", "x-fastly-request-id", "fastly-io-info")),
    ("Sucuri",           ("sucuri",),                ("x-sucuri-id", "x-sucuri-cache")),
    ("Imperva/Incapsula",("incapsula", "imperva"),   ("x-iinfo", "x-cdn")),
    ("AWS CloudFront",   ("cloudfront",),            ("x-amz-cf-id", "x-amz-cf-pop")),
    ("AWS ELB",          ("awselb", "amazon"),       ("x-amzn-trace-id",)),
    ("Varnish",          ("varnish",),               ()),
    ("F5 BIG-IP",        ("big-ip", "bigip", "f5 "), ()),
    ("Barracuda",        ("barracuda",),             ()),
)

# Rangos IPv4 publicados de Cloudflare (https://www.cloudflare.com/ips/).
# Sirven para descartar que una IP "descubierta" siga siendo del CDN.
CLOUDFLARE_V4 = tuple(ipaddress.ip_network(c) for c in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
))

# Subdominios que con frecuencia apuntan al ORIGEN real (no al CDN), porque
# suelen quedarse "grises"/sin proxy en el panel DNS.
COMMON_ORIGIN_SUBDOMAINS = (
    "", "www", "direct", "direct-connect", "origin", "origin-www", "cpanel",
    "whm", "webmail", "mail", "mail1", "smtp", "pop", "imap", "ftp", "sftp",
    "server", "host", "vps", "web", "portal", "dev", "development", "staging",
    "stage", "test", "qa", "old", "legacy", "backup", "cpcalendars",
    "autodiscover", "ns1", "ns2", "shop", "api",
)


def is_cloudflare_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in CLOUDFLARE_V4)


# Otros rangos de CDN frecuentes (subconjunto estable) para no confundir una IP
# del CDN con el origen. Para CDNs sin lista compacta (p. ej. Akamai) se usa
# además la verificación por cabeceras del candidato (ver auto-origin).
OTHER_CDN_V4 = tuple(ipaddress.ip_network(c) for c in (
    # Fastly
    "151.101.0.0/16", "199.232.0.0/16",
    # AWS CloudFront (bloques principales)
    "13.32.0.0/15", "13.224.0.0/14", "52.46.0.0/18", "52.84.0.0/15",
    "54.182.0.0/16", "54.192.0.0/16", "54.230.0.0/16", "54.239.128.0/18",
    "99.84.0.0/16", "205.251.192.0/19", "216.137.32.0/19",
    # Google (Cloud CDN / GFE)
    "34.96.0.0/20", "34.98.64.0/18", "35.190.0.0/17",
))


def is_cdn_ip(ip: str) -> bool:
    """¿La IP pertenece a un rango conocido de CDN (Cloudflare u otros)?"""
    if is_cloudflare_ip(ip):
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in OTHER_CDN_V4)


def is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def base_domain(host: str) -> str:
    """Quita un 'www.' inicial para construir subdominios candidatos."""
    return host[4:] if host.lower().startswith("www.") else host


def discover_origin_candidates(domain: str, subdomains, timeout: float,
                               max_candidates: int = 6) -> list[tuple[str, str]]:
    """Resuelve subdominios comunes y devuelve IPs que NO sean de Cloudflare.

    Devuelve lista de (ip, fuente) sin duplicados, en orden de aparición.
    Solo hace resoluciones DNS (A records) — reconocimiento pasivo estándar.
    """
    base = base_domain(domain)
    seen_ips: set[str] = set()
    out: list[tuple[str, str]] = []
    for sub in subdomains:
        fqdn = base if sub == "" else f"{sub}.{base}"
        try:
            infos = socket.getaddrinfo(fqdn, None, family=socket.AF_INET,
                                       type=socket.SOCK_STREAM)
        except Exception:
            continue
        for info in infos:
            ip = info[4][0]
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            if is_cdn_ip(ip) or is_private_ip(ip):
                continue  # sigue siendo el CDN o es interno, no sirve como origen
            out.append((ip, f"{fqdn} → {ip}"))
            if len(out) >= max_candidates:
                return out
    return out


# Caché compartida de endpoints (ip, puerto) que no responden, para no
# re-sondear la misma IP de origen muerta en el auto-origin per-host.
_DEAD_ENDPOINTS: set = set()
_DEAD_LOCK = threading.Lock()


def _is_dead_endpoint(ip: str, port: int) -> bool:
    with _DEAD_LOCK:
        return (ip, port) in _DEAD_ENDPOINTS


def _mark_dead_endpoint(ip: str, port: int) -> None:
    with _DEAD_LOCK:
        _DEAD_ENDPOINTS.add((ip, port))


# Veredictos
V_VULN = "VULNERABLE"
V_PATCHED = "PARCHEADO"
V_UNKNOWN = "DESCONOCIDO"   # responde PHP pero no revela versión (expose_php Off)
V_NO_PHP = "SIN-PHP"        # responde pero no parece PHP
V_NO_DNS = "NO-DNS"         # el nombre no resuelve en DNS público
V_PRIVATE = "IP-PRIVADA"    # resuelve a RFC1918 — interno, no escaneable desde aquí
V_FILTERED = "FILTRADO"     # conexión agota timeout (puerto filtrado / DROP)
V_CLOSED = "CERRADO"        # conexión rechazada (RST) — puerto cerrado
V_NO_RESP = "SIN-RESPUESTA" # otra causa sin respuesta HTTP


def is_private_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private or a.is_loopback or a.is_link_local

# Colores ANSI (se desactivan con --no-color o si no es TTY)
class C:
    RED = "\033[91m"
    GRN = "\033[92m"
    YEL = "\033[93m"
    CYN = "\033[96m"
    GRY = "\033[90m"
    BLD = "\033[1m"
    RST = "\033[0m"


def disable_colors() -> None:
    for name in ("RED", "GRN", "YEL", "CYN", "GRY", "BLD", "RST"):
        setattr(C, name, "")


VERDICT_COLOR = {
    V_VULN: lambda: C.RED,
    V_PATCHED: lambda: C.GRN,
    V_UNKNOWN: lambda: C.YEL,
    V_NO_PHP: lambda: C.GRY,
    V_NO_DNS: lambda: C.GRY,
    V_PRIVATE: lambda: C.GRY,
    V_FILTERED: lambda: C.GRY,
    V_CLOSED: lambda: C.GRY,
    V_NO_RESP: lambda: C.GRY,
}


# ───────────────────────── Modelo de resultado ─────────────────────────
@dataclass
class Result:
    target: str
    ip: str = ""
    port: int = 0
    scheme: str = ""
    http_status: Optional[int] = None
    php_version: str = ""
    verdict: str = V_NO_RESP
    fixed_version: str = ""
    branch_eol: bool = False
    version_hidden: bool = False
    behind_cdn_waf: bool = False
    cdn_waf: str = ""
    php_signal: str = ""      # de dónde salió la señal de PHP (header / cookie / body)
    connect_ip: str = ""      # a qué IP/host se conectó realmente (puede ser --origin-ip)
    host_header: str = ""     # valor de la cabecera Host enviada
    origin_auto: bool = False # True si la IP de origen se descubrió automáticamente
    origin_source: str = ""   # cómo se descubrió (subdominio → ip)
    server_header: str = ""
    powered_by: str = ""
    set_cookie: str = ""
    confidence: str = ""      # nivel de confianza: "solo-versión" (N0) o "activa: ..." (N1)
    active_note: str = ""     # detalle de la validación activa (Nivel 1, --confirm)
    latency_ms: Optional[int] = None
    detail: str = ""
    checked_at: str = field(default_factory=lambda: datetime.datetime.now().isoformat(timespec="seconds"))


# ───────────────────────── Lógica de versiones ─────────────────────────
def classify_version(major: int, minor: int, patch: int) -> tuple[str, str, bool]:
    """Devuelve (veredicto, versión_parcheada_recomendada, rama_eol)."""
    ver = (major, minor, patch)
    branch = (major, minor)
    eol = branch in EOL_BRANCHES

    # Por debajo del rango afectado (p.ej. PHP 5.3 o menor) → no aplica.
    if ver < (AFFECTED_FLOOR[0], AFFECTED_FLOOR[1], 0):
        return V_PATCHED, "", eol  # "no vulnerable a php2shell" (fuera de rango)

    # Rama con parche conocido: comparar contra la versión fijada.
    if branch in FIXED_BY_BRANCH:
        fixed = FIXED_BY_BRANCH[branch]
        rec = "%d.%d.%d" % fixed
        return (V_VULN if ver < fixed else V_PATCHED), rec, eol

    # Rama dentro del rango afectado pero sin parche (EOL: 5.4–8.1) → vulnerable.
    if AFFECTED_FLOOR <= branch <= AFFECTED_CEIL_BRANCH:
        return V_VULN, "Actualizar a una rama soportada (>= 8.2.35)", True

    # Rama más nueva que la última conocida (p.ej. 8.6+) → asumimos parcheada.
    return V_PATCHED, "", eol


def extract_php_version(*headers: str) -> Optional[tuple[int, int, int]]:
    for h in headers:
        if not h:
            continue
        m = PHP_VERSION_RE.search(h)
        if m:
            return int(m.group(1)), int(m.group(2)), int(m.group(3))
    return None


def php_signal_source(server: str, powered_by: str, set_cookie: str,
                      body_snippet: str = "") -> str:
    """Devuelve de dónde proviene la evidencia de PHP, o '' si no hay."""
    if "php" in (server + " " + powered_by).lower():
        return "header"
    if PHP_COOKIE_RE.search(set_cookie or ""):
        return "cookie (PHPSESSID)"
    if ".php" in (body_snippet or "").lower() or "php" in (body_snippet or "").lower():
        return "body"
    return ""


def detect_cdn_waf(server: str, headers: dict) -> str:
    """Identifica el/los CDN/WAF por delante. Devuelve NOMBRES DE PRODUCTO.

    Una firma casa si la palabra clave aparece en el `Server` O si está presente
    alguna de sus cabeceras delatoras (p.ej. 'cf-ray' ⇒ Cloudflare aunque el
    Server venga personalizado y no diga 'cloudflare').
    """
    server_l = (server or "").lower()
    header_keys = {k.lower() for k in headers.keys()}
    found: list[str] = []
    for product, server_hints, header_hints in CDN_WAF_SIGNATURES:
        hit = any(h in server_l for h in server_hints) or \
              any(h in header_keys for h in header_hints)
        if hit and product not in found:
            found.append(product)
    return ", ".join(found)


# ───────────────────────── Sondeo HTTP ─────────────────────────
def probe(connect_host: str, port: int, scheme: str, timeout: float,
          host_header: str) -> tuple[Optional[int], dict, str, int, Optional[str]]:
    """Sondea el host. Devuelve (status, headers, body, latencia_ms, fail_reason).

    fail_reason: None si hubo respuesta; "timeout" (puerto filtrado/DROP),
    "refused" (RST, puerto cerrado) u "other" (TLS u otro) si no la hubo.

    `connect_host` es a dónde se abre la conexión TCP (puede ser una IP de origen).
    `host_header` es el valor de la cabecera Host / vhost que se anuncia.
    Clave de eficiencia: si la conexión TCP falla con HEAD, NO se reintenta GET
    (el puerto está muerto) — así no se duplica la espera del timeout.
    """
    start = datetime.datetime.now()
    conn_cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
    kwargs = {"timeout": timeout}
    if scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # scanning: no validamos cert
        kwargs["context"] = ctx

    def _do(method):
        conn = conn_cls(connect_host, port, **kwargs)
        try:
            # Host explícito evita que http.client lo autogenere (permite apuntar
            # a una IP de origen anunciando el vhost del dominio).
            conn.request(method, "/", headers={
                "User-Agent": "GlobalSecure-Scan-v1.2",
                "Accept": "*/*",
                "Connection": "close",
                "Host": host_header,
            })
            resp = conn.getresponse()
            headers = {k.lower(): v for k, v in resp.getheaders()}
            body = ""
            if method == "GET":
                try:
                    body = resp.read(2048).decode("latin-1", "replace")
                except Exception:
                    body = ""
            return resp.status, headers, body, None
        except socket.timeout:
            return None, {}, "", "timeout"
        except ConnectionRefusedError:
            return None, {}, "", "refused"
        except (TimeoutError,) as e:
            return None, {}, "", "timeout"
        except OSError as e:
            reason = "refused" if isinstance(e, ConnectionRefusedError) else "other"
            return None, {}, "", reason
        except Exception:
            return None, {}, "", "other"
        finally:
            try:
                conn.close()
            except Exception:
                pass

    status, headers, body, reason = _do("HEAD")
    lat = lambda: int((datetime.datetime.now() - start).total_seconds() * 1000)

    if status is None:
        # Conexión muerta: no reintentar GET en el mismo puerto.
        return None, {}, "", lat(), reason

    # HEAD respondió. Si no se vio versión de PHP, un GET para leer cuerpo/cookies.
    if not extract_php_version(headers.get("server", ""), headers.get("x-powered-by", "")):
        g_status, g_headers, g_body, _g_reason = _do("GET")
        if g_status is not None:
            status, headers, body = g_status, g_headers, g_body

    return status, headers, body, lat(), None


def apply_headers(r: Result, headers: dict, body: str) -> None:
    """Rellena r (server/cookie/cdn/versión/veredicto/detalle) a partir de un sondeo."""
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    set_cookie = headers.get("set-cookie", "")
    r.server_header = server
    r.powered_by = powered
    r.set_cookie = set_cookie[:200]

    cdn = detect_cdn_waf(server, headers)
    r.cdn_waf = cdn
    r.behind_cdn_waf = bool(cdn)

    # La versión puede venir en Server, X-Powered-By o incluso en la cookie.
    ver = extract_php_version(server, powered, set_cookie)
    if ver:
        major, minor, patch = ver
        r.php_version = "%d.%d.%d" % ver
        r.php_signal = "header"
        verdict, fixed, eol = classify_version(major, minor, patch)
        r.verdict = verdict
        r.fixed_version = fixed
        r.branch_eol = eol
        if verdict == V_VULN:
            r.detail = ("Rama EOL sin parche — actualizar a una rama soportada"
                        if eol and (major, minor) not in FIXED_BY_BRANCH
                        else "Versión por debajo de la versión parcheada de su rama")
        else:
            r.detail = "Versión igual o superior a la parcheada" if fixed else "Fuera del rango afectado"
        return

    # Responde PHP pero no revela versión.
    signal = php_signal_source(server, powered, set_cookie, body)
    if signal:
        r.verdict = V_UNKNOWN
        r.version_hidden = True
        r.php_signal = signal
        if cdn:
            r.detail = (f"PHP detectado vía {signal}, pero la versión está oculta tras "
                        f"CDN/WAF ({cdn}). El número de versión del origen no es visible "
                        f"externamente — verificar con acceso al origen, 'php -v', SBOM o credenciales.")
        else:
            r.detail = (f"PHP detectado vía {signal} pero versión oculta (expose_php=Off). "
                        f"Verificar con 'php -v' local, SBOM o credenciales.")
    else:
        r.verdict = V_NO_PHP
        if cdn:
            r.detail = (f"No se observa PHP en las cabeceras; el origen está tras CDN/WAF "
                        f"({cdn}), que puede enmascararlo. Verificar directamente contra el origen.")
        else:
            r.detail = "No se detecta PHP en las cabeceras de este puerto"


def _probe_with_fallback(connect_host, port, timeout, host_header):
    """Sondea respetando el puerto; reintenta el esquema alterno si procede.

    Devuelve (scheme, status, headers, body, latency, fail_reason).
    """
    scheme = "https" if port in (443, 8443) else "http"
    status, headers, body, latency, reason = probe(connect_host, port, scheme, timeout, host_header)
    if status is None and port not in (443, 8443, 80):
        alt = "https" if scheme == "http" else "http"
        status, headers, body, latency, reason = probe(connect_host, port, alt, timeout, host_header)
        if status is not None:
            scheme = alt
    return scheme, status, headers, body, latency, reason


def _reason_verdict(reason: Optional[str]) -> tuple[str, str]:
    """Traduce la causa de fallo de conexión a (veredicto, detalle)."""
    if reason == "timeout":
        return V_FILTERED, "La conexión agotó el timeout (puerto filtrado / DROP por firewall)"
    if reason == "refused":
        return V_CLOSED, "Conexión rechazada (RST): el puerto está cerrado"
    return V_NO_RESP, "Sin respuesta HTTP/HTTPS en el puerto"


def scan_one(target: str, port: int, timeout: float,
             host_header_arg: str = "", origin_ip: str = "",
             auto_origin: bool = True, origin_subdomains=COMMON_ORIGIN_SUBDOMAINS,
             from_discovery: bool = False) -> Result:
    host = target

    # --origin-ip: conectar a la IP de origen (bypass del CDN) y anunciar el
    # dominio como vhost. Si no, resolvemos el dominio normalmente.
    if origin_ip:
        connect_host = origin_ip
        ip = origin_ip
    else:
        connect_host = host
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            ip = ""  # no resuelve

    host_header = host_header_arg or host
    r = Result(target=target, ip=ip, port=port,
               connect_ip=connect_host, host_header=host_header)

    # ── Pre-filtros (evitan gastar un timeout completo) ──
    # NO-DNS: el nombre no resolvió (solo aplica a nombres, no a IPs literales).
    if not origin_ip and not ip and not is_ip_literal(host):
        r.verdict = V_NO_DNS
        r.detail = "El nombre no resuelve en DNS público (posible host interno / registro obsoleto)"
        return r

    # IP-PRIVADA: resuelve a RFC1918. Solo se descarta para hosts descubiertos
    # por --domain; en --target/--cidr/--file el usuario pudo pedir red interna.
    effective_ip = ip or (connect_host if is_ip_literal(connect_host) else "")
    if from_discovery and effective_ip and is_private_ip(effective_ip):
        r.verdict = V_PRIVATE
        r.detail = f"Resuelve a IP privada ({effective_ip}) — interno, no escaneable desde esta red"
        return r

    scheme, status, headers, body, latency, reason = _probe_with_fallback(
        connect_host, port, timeout, host_header)
    r.scheme = scheme
    r.http_status = status
    r.latency_ms = latency

    if status is None:
        r.verdict, r.detail = _reason_verdict(reason)
        return r

    apply_headers(r, headers, body)

    # ── Auto-origin: si hay CUALQUIER CDN y no vemos versión, buscar el origen ──
    # IMPORTANTE: NO se ejecuta para hosts descubiertos por --domain (from_discovery).
    # Atribuir la versión de una IP de origen compartida a muchos hosts produce
    # falsos positivos masivos cuando el origen sirve un vhost por defecto. En un
    # escaneo -d, los orígenes ya se escanean directamente como sus propios nombres.
    need_version = r.verdict in (V_NO_PHP, V_UNKNOWN)
    attempted_origin = False
    if (auto_origin and r.behind_cdn_waf and need_version
            and not origin_ip and not is_ip_literal(host) and not from_discovery):
        # Búsqueda per-host: solo subdominios comunes del propio objetivo.
        candidates = discover_origin_candidates(host, origin_subdomains, timeout)
        attempted_origin = True
        # Acotar: como mucho unos pocos candidatos por host.
        for cand_ip, source in candidates[:6]:
            if _is_dead_endpoint(cand_ip, port):
                continue  # ya se comprobó muerto para otro host: saltar
            o_scheme, o_status, o_headers, o_body, o_latency, _o_reason = _probe_with_fallback(
                cand_ip, port, timeout, host)
            if o_status is None:
                # IP:puerto no da HTTP (independiente del Host): marcar muerto.
                _mark_dead_endpoint(cand_ip, port)
                continue
            tmp = Result(target=target, ip=cand_ip, port=port, scheme=o_scheme,
                         http_status=o_status, latency_ms=o_latency,
                         connect_ip=cand_ip, host_header=host,
                         origin_auto=True, origin_source=source)
            apply_headers(tmp, o_headers, o_body)
            # El candidato podría estar también tras un CDN: si es así (y no da
            # versión), no sirve como origen real.
            cand_behind_cdn = tmp.behind_cdn_waf
            improved = bool(tmp.php_version) or (
                not cand_behind_cdn and r.verdict == V_NO_PHP
                and tmp.verdict in (V_VULN, V_PATCHED, V_UNKNOWN))
            if improved:
                prefix = (f"[auto-origin: {source}] "
                          f"Origen alcanzado saltando el CDN ({r.cdn_waf}). ")
                tmp.detail = prefix + tmp.detail
                tmp.behind_cdn_waf = True   # delante sigue habiendo CDN
                tmp.cdn_waf = r.cdn_waf
                return tmp
            if tmp.php_version:
                break

    # ── Nota honesta: CDN sin versión observable ni origen hallado ──
    if r.behind_cdn_waf and r.verdict in (V_NO_PHP, V_UNKNOWN) and not r.php_version:
        suffix = (f" La versión del backend NO es observable pasivamente tras "
                  f"{r.cdn_waf}" + (" y no se halló IP de origen expuesta" if attempted_origin else "") +
                  f": requiere la IP de origen (inventario) o verificación autenticada "
                  f"('php -v' / SBOM).")
        r.detail = r.detail.rstrip() + suffix
    return r


# ───────────────────────── Nivel 1: validación activa ─────────────────────────
# Confianza (no crea ni cambia veredictos; solo anota el VULNERABLE por versión).
CONF_VERSION_ONLY = "solo-versión"
CONF_SESSION_FIXATION = "activa: upload_progress + fijación confirmadas"
CONF_SESSION_ONLY = "activa: sesión PHP presente, fijación no adoptada"
CONF_NO_SESSION = "activa: sin señal de sesión PHP"
CONF_INCONCLUSIVE = "activa: inconcluso (sin respuesta)"

# SID propio, bien formado (minúsculas+dígitos, 26 chars) para la prueba de fijación.
_CONFIRM_SID = "gs0confirm00000000000000aa"

# Rutas comunes que suelen arrancar sesión PHP (se prueban en el Nivel 1 hasta
# hallar señal). El upload_progress inicia sesión a nivel de SAPI si la ruta
# enruta a PHP; estas son las que más a menudo tocan $_SESSION.
COMMON_SESSION_PATHS = (
    "/", "/index.php", "/login", "/login.php", "/signin", "/admin", "/admin/",
    "/administrator/", "/wp-login.php", "/user/login", "/users/login",
    "/account", "/dashboard", "/panel", "/auth", "/session.php", "/api/login",
)


def _http_request(connect_host, port, scheme, timeout, method, path, headers, body=None):
    """Petición HTTP cruda. Devuelve (ok, status, set_cookies[list], server, powered)."""
    conn_cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
    kwargs = {"timeout": timeout}
    if scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        kwargs["context"] = ctx
    conn = conn_cls(connect_host, port, **kwargs)
    try:
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        hdrs = resp.getheaders()
        set_cookies = [v for (k, v) in hdrs if k.lower() == "set-cookie"]
        low = {k.lower(): v for k, v in hdrs}
        try:
            resp.read(1024)
        except Exception:
            pass
        return True, resp.status, set_cookies, low.get("server", ""), low.get("x-powered-by", "")
    except Exception:
        return False, None, [], "", ""
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _upload_progress_probe(connect_host, port, scheme, timeout, host_header, sid, path="/"):
    """POST multipart BENIGNO con PHP_SESSION_UPLOAD_PROGRESS y PHPSESSID en el BODY.

    Replica la ruta de la PoC (session.upload_progress) que inicia la sesión a
    nivel de SAPI aunque la app NO llame a session_start(), y que acepta el SID
    del cuerpo (bypass de use_only_cookies). Filename y contenido inofensivos:
    NO inyecta PHP ni objetos serializados — solo comprueba la precondición.
    """
    boundary = "GSb0undaryC0nfirm2026"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nglobalsecure\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="probe.txt"\r\n'
        f"Content-Type: text/plain\r\n\r\nZ\r\n"
        f"--{boundary}--\r\n"
    ).encode("latin-1")
    headers = {
        "User-Agent": "GlobalSecure-Scan-v1.2",
        "Accept": "*/*",
        "Connection": "close",
        "Host": host_header,
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Content-Length": str(len(body)),
    }
    return _http_request(connect_host, port, scheme, timeout, "POST", path, headers, body)


def _fresh_sid() -> str:
    """SID nuevo, válido (minúsculas+dígitos, 26 chars)."""
    return "gs" + uuid.uuid4().hex[:24]


def _cookie_sid(set_cookies) -> Optional[str]:
    m = re.search(r"PHPSESSID=([^;,\s]+)", " ; ".join(set_cookies), re.IGNORECASE)
    return m.group(1) if m else None


def _adopted(sent_sid: str, set_cookies) -> bool:
    """PHP ADOPTA un id cuando NO reemite una cookie distinta (solo reemite al
    rechazar/regenerar). Ausencia de Set-Cookie nuevo, o mismo id = adoptado."""
    got = _cookie_sid(set_cookies)
    return got is None or got == sent_sid


def _get_with_cookie(connect_host, port, scheme, timeout, host_header, path, sid):
    return _http_request(connect_host, port, scheme, timeout, "GET", path, {
        "User-Agent": "GlobalSecure-Scan-v1.2", "Accept": "*/*",
        "Connection": "close", "Host": host_header, "Cookie": f"PHPSESSID={sid}",
    })


def _differential_fixation(connect_host, port, scheme, timeout, host_header, path):
    """Prueba diferencial (derivada de verify_session_injection.py), SIN payloads:

      baseline: GET path con Cookie=B (B sin crear) →
        - adoptado  ⇒ 'cookie'  (use_strict_mode=0, fijación por cookie)
        - rechazado ⇒ strict mode activo → seguimos
      inyección: POST upload_progress con PHPSESSID=B en el body (crea sess_B)
      confirm:   GET path con Cookie=B →
        - adoptado ahora ⇒ 'upload_progress'  (bypass de strict confirmado)
        - sigue rechazado ⇒ 'no'
    Devuelve 'cookie' | 'upload_progress' | 'no' | 'error'.
    """
    B = _fresh_sid()
    okA, _s, scA, _sv, _pw = _get_with_cookie(
        connect_host, port, scheme, timeout, host_header, path, B)
    if not okA:
        return "error"
    if _adopted(B, scA):
        return "cookie"          # strict off: adopta cualquier SID de cookie
    # strict on → inyectar sess_B vía upload_progress y reintentar
    _upload_progress_probe(connect_host, port, scheme, timeout, host_header, B, path)
    okC, _s2, scC, _sv2, _pw2 = _get_with_cookie(
        connect_host, port, scheme, timeout, host_header, path, B)
    if okC and _adopted(B, scC):
        return "upload_progress"
    return "no"


def active_confirm(r: Result, timeout: float) -> None:
    """Nivel 1 (--confirm): valida precondiciones de forma ACTIVA y BENIGNA.

    1. Re-confirma la versión de PHP.
    2. Descubre un endpoint que inicie sesión PHP (barrido de rutas comunes con un
       POST upload_progress benigno; endpoint = responde con Set-Cookie PHPSESSID).
    3. Prueba diferencial de fijación en ese endpoint (ver _differential_fixation):
       confirma si se puede fijar un SID arbitrario — por cookie (use_strict_mode=0)
       o vía upload_progress (bypass de use_strict_mode).
    NO inyecta código ni objetos serializados, no dispara OOM/UAF, no explota.
    Solo ANOTA la confianza; nunca cambia el veredicto (cero falsos positivos).
    """
    connect_host = r.connect_ip or r.target
    scheme = r.scheme or ("https" if r.port in (443, 8443) else "http")
    host_header = r.host_header or r.target

    any_response = False
    server = powered = ""
    sess_path = None
    paths_tried = 0

    # Descubrir endpoint de sesión: la ruta que emite Set-Cookie PHPSESSID al
    # recibir el POST upload_progress (= el script llamó session_start()).
    for path in COMMON_SESSION_PATHS:
        ok, _st, set_cookies, srv, pwd = _upload_progress_probe(
            connect_host, r.port, scheme, timeout, host_header, _CONFIRM_SID, path)
        paths_tried += 1
        if not ok:
            continue
        any_response = True
        server = server or srv
        powered = powered or pwd
        if _cookie_sid(set_cookies):
            sess_path = path
            break

    rever = extract_php_version(server, powered)
    ver_note = (f"versión re-confirmada {rever[0]}.{rever[1]}.{rever[2]}; " if rever
                else "versión no re-leída; ")

    if not any_response:
        r.confidence = CONF_INCONCLUSIVE
        r.active_note = f"No se obtuvo respuesta en la validación activa ({paths_tried} ruta(s))."
        return

    if sess_path is None:
        r.confidence = CONF_NO_SESSION
        r.active_note = (ver_note + f"ningún endpoint de sesión en {paths_tried} ruta(s) comunes. "
                         "INCONCLUSO (la inyección vía upload_progress es a nivel de SAPI y puede "
                         "no ser observable en remoto): NO descarta la vulnerabilidad; manda la versión.")
        return

    # Prueba diferencial de fijación en el endpoint de sesión hallado.
    outcome = _differential_fixation(connect_host, r.port, scheme, timeout, host_header, sess_path)
    if outcome == "cookie":
        r.confidence = CONF_SESSION_FIXATION
        r.active_note = (ver_note + f"en {sess_path} el servidor adopta un SID arbitrario de "
                         "cookie (use_strict_mode=0) → fijación de sesión CONFIRMADA.")
    elif outcome == "upload_progress":
        r.confidence = CONF_SESSION_FIXATION
        r.active_note = (ver_note + f"en {sess_path} un SID arbitrario es rechazado en frío pero "
                         "ADOPTADO tras crearlo vía upload_progress → bypass de use_strict_mode "
                         "CONFIRMADO (precondición de fijación de php2shell).")
    elif outcome == "no":
        r.confidence = CONF_SESSION_ONLY
        r.active_note = (ver_note + f"sesión PHP activa en {sess_path}, pero no se pudo fijar un "
                         "SID arbitrario (strict mode no eludido por esta vía).")
    else:  # error
        r.confidence = CONF_SESSION_ONLY
        r.active_note = (ver_note + f"sesión PHP activa en {sess_path}; la prueba diferencial de "
                         "fijación no obtuvo respuesta.")


# ───────────────────────── Expansión de objetivos ─────────────────────────
VALID_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")


def _http_get(url: str, timeout: float, headers: dict = None,
              attempts: int = 3, backoff: float = 3.0, label: str = "") -> Optional[str]:
    """GET con reintentos. Devuelve el cuerpo como texto, o None si falla."""
    import time as _t
    hdrs = {"User-Agent": "GlobalSecure-Scan-v1.2",
            "Accept": "application/json, text/plain, */*"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)
    last_err = None
    for i in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", "replace")
        except Exception as e:
            last_err = e
            if i < attempts:
                _t.sleep(backoff)
    print(f"  [{label}] error: {last_err}", file=sys.stderr)
    return None


def _sanitize_names(raw_names, domain: str) -> set[str]:
    """Normaliza nombres y los filtra al dominio pedido."""
    out: set[str] = set()
    for n in raw_names:
        if not n:
            continue
        n = str(n).strip().lower()
        if n.startswith("*."):
            n = n[2:]
        n = n.strip(".")
        if not n:
            continue
        if (n == domain or n.endswith("." + domain)) and VALID_HOST_RE.match(n):
            out.add(n)
    return out


# ── Fuentes de descubrimiento (cada una devuelve set de subdominios) ──

def src_crtsh(domain, timeout):
    raw = _http_get(f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json",
                    timeout, label="crt.sh")
    if not raw:
        return set()
    try:
        data = json.loads(raw)
    except Exception:
        return set()
    names = []
    for row in data:
        if isinstance(row, dict):
            for fld in ("name_value", "common_name"):
                val = row.get(fld) or ""
                names.extend(str(val).split("\n"))
    return _sanitize_names(names, domain)


def src_hackertarget(domain, timeout):
    # HackerTarget opera DNSDumpster; su API hostsearch da datos equivalentes.
    raw = _http_get(f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(domain)}",
                    timeout, label="hackertarget")
    if not raw:
        return set()
    low = raw.lower()
    if "api count exceeded" in low or "error" in low[:40]:
        print("  [hackertarget] límite de API alcanzado o error", file=sys.stderr)
        return set()
    names = [line.split(",")[0] for line in raw.splitlines() if line.strip()]
    return _sanitize_names(names, domain)


def src_otx(domain, timeout):
    # AlienVault OTX passive DNS (sin key).
    raw = _http_get(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{urllib.parse.quote(domain)}/passive_dns",
        timeout, label="otx")
    if not raw:
        return set()
    try:
        data = json.loads(raw)
    except Exception:
        return set()
    names = [rec.get("hostname", "") for rec in data.get("passive_dns", [])
             if isinstance(rec, dict)]
    return _sanitize_names(names, domain)


def src_certspotter(domain, timeout):
    # CertSpotter (Certificate Transparency, nivel gratuito sin key).
    raw = _http_get(
        f"https://api.certspotter.com/v1/issuances?domain={urllib.parse.quote(domain)}"
        f"&include_subdomains=true&expand=dns_names",
        timeout, label="certspotter")
    if not raw:
        return set()
    try:
        data = json.loads(raw)
    except Exception:
        return set()
    names = []
    for cert in data:
        if isinstance(cert, dict):
            names.extend(cert.get("dns_names", []) or [])
    return _sanitize_names(names, domain)


def src_rapiddns(domain, timeout):
    # RapidDNS (rapiddns.io) — base de datos pública de DNS, respuesta HTML.
    raw = _http_get(f"https://rapiddns.io/subdomain/{urllib.parse.quote(domain)}?full=1",
                    timeout, headers={"Accept": "text/html"}, label="rapiddns")
    if not raw:
        return set()
    # Extraemos nombres host del HTML y filtramos por dominio.
    candidates = re.findall(r"[a-z0-9_.-]+\." + re.escape(domain), raw, re.IGNORECASE)
    return _sanitize_names(candidates + [domain], domain)


# Todas gratuitas y sin API key.
SOURCES = {
    "crtsh": src_crtsh,                # Certificate Transparency
    "hackertarget": src_hackertarget,  # datos equivalentes a DNSDumpster, sin key
    "otx": src_otx,                    # AlienVault OTX passive DNS
    "certspotter": src_certspotter,    # Certificate Transparency
    "rapiddns": src_rapiddns,          # base de datos DNS pública
}


def discover_subdomains(domain: str, timeout: float, sources) -> list[str]:
    """Agrega subdominios de varias fuentes públicas. Devuelve lista única ordenada."""
    domain = domain.strip().lower().strip(".")
    all_names: set[str] = {domain}  # incluir el apex
    for name in sources:
        fn = SOURCES.get(name)
        if fn is None:
            print(f"  [!] fuente desconocida: {name}", file=sys.stderr)
            continue
        try:
            got = fn(domain, timeout)
        except Exception as e:
            print(f"  [{name}] excepción: {e}", file=sys.stderr)
            got = set()
        print(f"  [{name}] {len(got)} subdominio(s)", file=sys.stderr)
        all_names |= got
    return sorted(all_names)


def parse_file_targets(path: str) -> list[tuple[str, Optional[int]]]:
    out: list[tuple[str, Optional[int]]] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            if ":" in line and not line.count(":") > 1:  # host:puerto (ignora IPv6 con varios ':')
                h, _, p = line.partition(":")
                try:
                    out.append((h.strip(), int(p.strip())))
                    continue
                except ValueError:
                    pass
            out.append((line, None))
    return out


def expand_cidr(cidr: str) -> list[str]:
    net = ipaddress.ip_network(cidr, strict=False)
    if net.num_addresses <= 2:
        return [str(h) for h in net]
    return [str(h) for h in net.hosts()]


def build_jobs(args):
    """Devuelve (jobs, discovered_by_domain)."""
    ports = [int(p) for p in args.ports.split(",") if p.strip()]
    file_port_overrides: dict[str, int] = {}
    hosts: list[str] = []
    explicit: set[str] = set()      # objetivos pedidos a mano
    discovery: set[str] = set()     # objetivos hallados por --domain
    discovered_by_domain: dict = {}

    for t in args.target or []:
        hosts.append(t)
        explicit.add(t)
    for c in args.cidr or []:
        for ip in expand_cidr(c):
            hosts.append(ip)
            explicit.add(ip)
    if args.file:
        for host, port in parse_file_targets(args.file):
            hosts.append(host)
            explicit.add(host)
            if port is not None:
                file_port_overrides[host] = port
    if args.domain:
        sources = [s.strip().lower() for s in args.sources.split(",") if s.strip()]
        for d in args.domain:
            print(f"[discovery] {d} — fuentes: {', '.join(sources)}", file=sys.stderr)
            subs = discover_subdomains(d, args.crtsh_timeout, sources)
            print(f"[discovery] {d}: {len(subs)} subdominio(s) únicos en total",
                  file=sys.stderr)
            hosts.extend(subs)
            discovery.update(subs)
            discovered_by_domain[d.strip().lower().strip(".")] = subs

    jobs: list[tuple[str, int, bool]] = []
    seen = set()
    for h in hosts:
        from_disc = (h in discovery) and (h not in explicit)
        if h in file_port_overrides:
            port_list = [file_port_overrides[h]]
        else:
            port_list = ports
        for p in port_list:
            if (h, p) not in seen:
                seen.add((h, p))
                jobs.append((h, p, from_disc))
    return jobs, discovered_by_domain


# ───────────────────────── Presentación ─────────────────────────
def print_row(r: Result) -> None:
    col = VERDICT_COLOR.get(r.verdict, lambda: "")()
    ver = r.php_version or "-"
    extra = ""
    if r.verdict == V_VULN and r.fixed_version:
        extra = f"→ fija: {r.fixed_version}"
    elif r.verdict == V_UNKNOWN:
        extra = "versión oculta"
    elif r.verdict in (V_NO_RESP, V_NO_PHP, V_NO_DNS, V_PRIVATE, V_FILTERED, V_CLOSED):
        extra = r.detail
    eol = f" {C.YEL}[EOL]{C.RST}" if r.branch_eol else ""
    cdn = f" {C.CYN}[{r.cdn_waf}]{C.RST}" if r.behind_cdn_waf else ""
    if r.origin_auto:
        via = f" {C.CYN}via origen {r.connect_ip} (auto){C.RST}"
    elif r.connect_ip and r.connect_ip != r.target:
        via = f" {C.GRY}via {r.connect_ip}{C.RST}"
    else:
        via = ""
    print(f"  {col}{r.verdict:<13}{C.RST} {r.target:<28} {r.scheme}:{r.port:<5} "
          f"PHP {ver:<9}{eol}{cdn}{via} {C.GRY}{extra}{C.RST}")


def print_summary(results: list[Result]) -> None:
    counts: dict[str, int] = {}
    for r in results:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    print()
    print(f"{C.BLD}── Resumen ──{C.RST}")
    order = [V_VULN, V_UNKNOWN, V_PATCHED, V_NO_PHP,
             V_FILTERED, V_CLOSED, V_NO_DNS, V_PRIVATE, V_NO_RESP]
    for v in order:
        if v in counts:
            col = VERDICT_COLOR.get(v, lambda: "")()
            print(f"  {col}{v:<13}{C.RST} {counts[v]}")
    vuln = counts.get(V_VULN, 0)
    if vuln:
        print(f"\n  {C.RED}{C.BLD}⚠ {vuln} objetivo(s) con PHP vulnerable a php2shell.{C.RST}")
    unk = counts.get(V_UNKNOWN, 0)
    if unk:
        print(f"  {C.YEL}ℹ {unk} objetivo(s) con versión oculta — requieren verificación manual/local.{C.RST}")


def export_csv(results: list[Result], path: str) -> None:
    fields = list(asdict(results[0]).keys()) if results else []
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for r in results:
            w.writerow(asdict(r))


def export_json(results: list[Result], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([asdict(r) for r in results], fh, indent=2, ensure_ascii=False)


def _ask_yes_no(prompt: str) -> bool:
    """Pregunta sí/no por consola. Default = No. Robusto ante EOF/Ctrl-C."""
    try:
        ans = input(prompt).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return ans in ("s", "si", "sí", "y", "yes")


def run_level1(vuln: list, timeout: float, threads: int) -> None:
    """Ejecuta la validación activa (Nivel 1) sobre los hosts ya marcados VULNERABLE."""
    print(f"\n{C.BLD}── Validación activa (Nivel 1) sobre {len(vuln)} host(s) VULNERABLE ──{C.RST}")
    print(f"{C.YEL}Enviando pruebas benignas de sesión/fijación (no explota, no ejecuta código)...{C.RST}\n")
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(threads, 20)) as ex:
        list(ex.map(lambda r: active_confirm(r, timeout), vuln))
    col = VERDICT_COLOR.get(V_VULN, lambda: "")()
    for r in vuln:
        print(f"  {col}{r.target:<32}{C.RST} {r.scheme}:{r.port:<5} {C.CYN}{r.confidence}{C.RST}")
        print(f"      {C.GRY}{r.active_note}{C.RST}")
    strong = [r for r in vuln if r.confidence == CONF_SESSION_FIXATION]
    if strong:
        print(f"\n  {C.RED}{C.BLD}⚠ {len(strong)} host(s) con precondiciones de explotación "
              f"CONFIRMADAS activamente.{C.RST}")


# ───────────────────────── Main ─────────────────────────
def main() -> int:
    ap = argparse.ArgumentParser(
        description="Scanner PASIVO de versiones de PHP vulnerables a php2shell "
                    "(CVE-2026-109618 / CVE-2026-109619). Solo lee cabeceras, no explota.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--version", action="version",
                    version=f"php2shell-version-scanner {__version__}")
    ap.add_argument("--target", action="append", help="IP o dominio (repetible)")
    ap.add_argument("-d", "--domain", action="append",
                    help="Dominio: descubre TODOS sus subdominios desde múltiples fuentes públicas y "
                    "gratuitas (crt.sh, HackerTarget/DNSDumpster, AlienVault OTX, CertSpotter, "
                    "RapidDNS) y los escanea. Repetible. Ej: -d empresa.com")
    ap.add_argument("--sources", default="crtsh,hackertarget,otx,certspotter,rapiddns",
                    help="Fuentes de descubrimiento para --domain, separadas por coma "
                    "(crtsh, hackertarget, otx, certspotter, rapiddns). Todas libres y sin API key. "
                    "Def: todas.")
    ap.add_argument("--cidr", action="append", help="Segmento de red CIDR, p.ej. 10.0.0.0/24 (repetible)")
    ap.add_argument("--file", help="Fichero con una IP/host por línea (admite host:puerto y # comentarios)")
    ap.add_argument("--crtsh-timeout", type=float, default=30.0,
                    help="Timeout en segundos para cada consulta de descubrimiento (def: 30)")
    ap.add_argument("--ports", default="80,443", help="Puertos a sondear, separados por coma (def: 80,443)")
    ap.add_argument("--host-header", help="Valor de la cabecera Host (vhost) a anunciar. Útil al "
                    "apuntar a la IP de origen tras un CDN para que el servidor sirva el sitio correcto.")
    ap.add_argument("--origin-ip", help="Conecta a esta IP de origen en lugar de resolver el dominio "
                    "(bypass de CDN/WAF). Se usa normalmente con un único --target; la cabecera Host "
                    "será el dominio objetivo (o --host-header si se indica).")
    ap.add_argument("--no-auto-origin", action="store_true",
                    help="Desactiva el descubrimiento automático de la IP de origen cuando se "
                    "detecta Cloudflare. Por defecto está ACTIVADO: si hay CDN y no se ve la "
                    "versión, el scanner resuelve subdominios comunes (mail, direct, cpanel, "
                    "apex...), descarta rangos de Cloudflare y reintenta contra el origen.")
    ap.add_argument("--origin-subdomains",
                    help="Lista propia de prefijos de subdominio para el auto-origin, separados "
                    "por coma (usa '' para el apex). Si se omite, se usa una lista por defecto.")
    ap.add_argument("--timeout", type=float, default=6.0, help="Timeout por conexión en segundos (def: 6)")
    ap.add_argument("--threads", type=int, default=50, help="Hilos concurrentes (def: 50)")
    ap.add_argument("--csv", help="Exportar resultados a CSV")
    ap.add_argument("--json", help="Exportar resultados a JSON")
    ap.add_argument("--only-vuln", action="store_true", help="Mostrar solo objetivos VULNERABLES")
    ap.add_argument("--confirm", action="store_true",
                    help="NIVEL 1 — Validación ACTIVA de precondiciones sobre los hosts VULNERABLE "
                    "(sesión PHP + fijación/adopción de SID). Benigna: NO explota ni ejecuta código, "
                    "pero envía peticiones de prueba y crea estado de sesión. REQUIERE AUTORIZACIÓN "
                    "EXPLÍCITA del cliente. Sin este flag, el scanner trabaja en Nivel 0 (pasivo).")
    ap.add_argument("--no-color", action="store_true", help="Desactivar color ANSI")
    args = ap.parse_args()

    if not (args.target or args.cidr or args.file or args.domain):
        ap.error("Indica al menos --target, --domain/-d, --cidr o --file")

    # En Windows la consola suele usar cp1252 y no puede imprimir glifos Unicode;
    # forzamos UTF-8 para que las tablas y símbolos no rompan la ejecución.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass

    if args.no_color or not sys.stdout.isatty():
        disable_colors()

    try:
        jobs, discovered_by_domain = build_jobs(args)
    except (ValueError, OSError) as e:
        print(f"{C.RED}Error procesando objetivos: {e}{C.RST}", file=sys.stderr)
        return 2

    if not jobs:
        print("No hay objetivos que escanear.", file=sys.stderr)
        return 2

    # NOTA: el auto-origin solo actúa sobre objetivos sueltos (--target), no sobre
    # hosts descubiertos por -d. Atribuir la versión de una IP de origen compartida
    # a muchos hosts tras CDN producía falsos positivos, así que en -d los orígenes
    # se escanean directamente como sus propios nombres.
    _DEAD_ENDPOINTS.clear()

    print(f"{C.BLD}php2shell — Scanner pasivo de versiones PHP v{__version__}{C.RST}")
    print(f"{C.GRY}CVE-2026-109618 / CVE-2026-109619 · "
          f"Manuel Moreno · GLOBALSECURE · www.globalsecure.cl{C.RST}")
    print(f"{C.GRY}{len(jobs)} sondeo(s) · {args.threads} hilos · "
          f"timeout {args.timeout}s{C.RST}\n")

    results: list[Result] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        if args.origin_subdomains is not None:
            subs = tuple(s.strip() for s in args.origin_subdomains.split(","))
        else:
            subs = COMMON_ORIGIN_SUBDOMAINS
        auto_origin = not args.no_auto_origin
        futs = {ex.submit(scan_one, h, p, args.timeout,
                          args.host_header or "", args.origin_ip or "",
                          auto_origin, subs, from_disc): (h, p)
                for h, p, from_disc in jobs}
        for fut in concurrent.futures.as_completed(futs):
            try:
                r = fut.result()
            except Exception as e:
                h, p = futs[fut]
                r = Result(target=h, port=p, verdict=V_NO_RESP, detail=f"error: {e}")
            results.append(r)
            if not args.only_vuln or r.verdict == V_VULN:
                print_row(r)

    # Orden final para exportes: vulnerables primero.
    verdict_rank = {V_VULN: 0, V_UNKNOWN: 1, V_PATCHED: 2, V_NO_PHP: 3,
                    V_FILTERED: 4, V_CLOSED: 5, V_NO_DNS: 6, V_PRIVATE: 7, V_NO_RESP: 8}
    results.sort(key=lambda r: (verdict_rank.get(r.verdict, 9), r.target, r.port))

    vuln = [r for r in results if r.verdict == V_VULN]

    # Marca de confianza por defecto (Nivel 0) para todos los vulnerables.
    for r in vuln:
        if not r.confidence:
            r.confidence = CONF_VERSION_ONLY

    print_summary(results)

    # ── Nivel 1: validación ACTIVA de precondiciones ──
    if vuln:
        interactive = sys.stdin.isatty() and sys.stdout.isatty()
        do_level1 = False

        if args.confirm:
            # Pre-autorizado por flag: ejecutar directo.
            do_level1 = True
        elif interactive:
            # Preguntar al operador, con confirmación de autorización.
            print(f"\n  {C.YEL}{C.BLD}▶ {len(vuln)} host(s) VULNERABLE por versión "
                  f"(confianza: {CONF_VERSION_ONLY}).{C.RST}")
            print(f"  {C.GRY}La validación activa (Nivel 1) envía peticiones benignas de "
                  f"sesión/fijación y crea estado de sesión en el objetivo.{C.RST}")
            print(f"  {C.GRY}NO explota ni ejecuta código.{C.RST}")
            if _ask_yes_no(f"\n  ¿Ejecutar validación activa (Nivel 1) sobre esos "
                           f"{len(vuln)} host(s)? [s/N]: "):
                if _ask_yes_no("  Confirma que cuentas con AUTORIZACIÓN EXPLÍCITA del "
                               "cliente para pruebas activas [s/N]: "):
                    do_level1 = True
                else:
                    print(f"  {C.YEL}Sin autorización confirmada — se omite el Nivel 1.{C.RST}")
            else:
                print(f"  {C.GRY}Nivel 1 omitido. Resultados en confianza '{CONF_VERSION_ONLY}'.{C.RST}")
        else:
            # No interactivo (pipeline): no bloquear, solo avisar.
            print(f"\n  {C.YEL}{C.BLD}▶ {len(vuln)} host(s) VULNERABLE por versión "
                  f"(confianza: {CONF_VERSION_ONLY}).{C.RST}")
            print(f"  {C.YEL}  Para la validación ACTIVA (Nivel 1) ejecuta con "
                  f"{C.BLD}--confirm{C.RST}{C.YEL} (requiere autorización del cliente).{C.RST}")

        if do_level1:
            run_level1(vuln, args.timeout, args.threads)

    if args.csv and results:
        export_csv(results, args.csv)
        print(f"\n  {C.CYN}CSV → {args.csv}{C.RST}")
    if args.json and results:
        export_json(results, args.json)
        print(f"  {C.CYN}JSON → {args.json}{C.RST}")

    # Código de salida: 1 si hubo al menos un vulnerable (útil para CI/automatización).
    return 1 if any(r.verdict == V_VULN for r in results) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrumpido.", file=sys.stderr)
        sys.exit(130)
