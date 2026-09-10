import streamlit as st
import pandas as pd
import sqlite3
import socket
import ssl
import ipaddress
import datetime
import requests
import json
import io
import base64
import html
from urllib.parse import urlparse, urljoin
from docx import Document
from docx.shared import Inches, Pt, RGBColor
import matplotlib.pyplot as plt
import psycopg2
from weasyprint import HTML

st.set_page_config(page_title="CyberAudits | Security Posture", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

st.markdown("""
<style>
    .stApp {
        background: #f6f8fc;
        color: #172033;
        font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }

    [data-testid="stSidebar"] {
        background: #ffffff !important;
        border-right: 1px solid #e7ebf3;
    }

    [data-testid="stSidebar"] > div:first-child {
        padding-top: 1.35rem;
    }

    .block-container {
        max-width: 1450px;
        padding-top: 1.8rem;
        padding-bottom: 4rem;
    }

    .ca-brand {
        background: linear-gradient(115deg, #0b1220 0%, #13264b 55%, #215ee9 100%);
        border-radius: 18px;
        padding: 24px 28px;
        color: white;
        margin-bottom: 18px;
        box-shadow: 0 14px 34px rgba(15, 23, 42, 0.14);
    }

    .ca-brand h1 {
        margin: 0;
        font-size: 28px;
        line-height: 1.1;
        letter-spacing: -0.5px;
    }

    .ca-brand p {
        margin: 8px 0 0 0;
        color: #dbe7ff;
        font-size: 14px;
    }

    .ca-kicker {
        font-size: 12px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 1.2px;
        color: #8fb5ff;
        margin-bottom: 8px;
    }

    .score-shell {
        background: #ffffff;
        border: 1px solid #e3e8f2;
        border-radius: 18px;
        padding: 24px;
        min-height: 220px;
        box-shadow: 0 8px 24px rgba(15, 23, 42, 0.05);
    }

    .score-number {
        font-size: 72px;
        line-height: 0.95;
        font-weight: 800;
        letter-spacing: -4px;
        color: #111827;
    }

    .score-denom {
        font-size: 22px;
        color: #7b8496;
        font-weight: 600;
        letter-spacing: -1px;
    }

    .score-label {
        display: inline-block;
        margin-top: 14px;
        padding: 6px 10px;
        border-radius: 999px;
        background: #eef4ff;
        color: #2057c8;
        font-size: 12px;
        font-weight: 800;
    }

    .muted {
        color: #687386;
        font-size: 13px;
    }

    .pass-card {
        background: linear-gradient(145deg, #0d172a, #122a57);
        color: white;
        border-radius: 20px;
        padding: 24px;
        min-height: 260px;
        box-shadow: 0 16px 34px rgba(15, 23, 42, 0.16);
        position: relative;
        overflow: hidden;
    }

    .pass-card:after {
        content: "";
        width: 180px;
        height: 180px;
        position: absolute;
        right: -60px;
        top: -60px;
        border-radius: 50%;
        background: rgba(59,130,246,0.18);
    }

    .pass-pill {
        display: inline-block;
        padding: 5px 9px;
        border-radius: 999px;
        background: rgba(255,255,255,0.12);
        font-size: 11px;
        font-weight: 800;
        letter-spacing: .7px;
    }

    .pass-score {
        font-size: 48px;
        line-height: 1;
        font-weight: 800;
        margin-top: 22px;
    }

    .finding-card {
        background: white;
        border: 1px solid #e4e9f2;
        border-radius: 14px;
        padding: 16px 18px;
        margin-bottom: 10px;
        box-shadow: 0 3px 12px rgba(15, 23, 42, 0.035);
    }

    .finding-title {
        font-weight: 750;
        font-size: 15px;
        color: #1a2334;
        margin-bottom: 5px;
    }

    .finding-meta {
        font-size: 12px;
        color: #758096;
    }

    .sev-critical { border-left: 5px solid #dc2626; }
    .sev-medium   { border-left: 5px solid #d97706; }
    .sev-low      { border-left: 5px solid #2563eb; }
    .sev-info     { border-left: 5px solid #64748b; }

    .small-note {
        background: #f7f9fd;
        border: 1px solid #e6ebf4;
        border-radius: 12px;
        padding: 12px 14px;
        font-size: 12px;
        color: #657087;
    }

    div[data-testid="stMetric"] {
        background: #ffffff;
        border: 1px solid #e4e9f2;
        padding: 14px 16px;
        border-radius: 14px;
        box-shadow: 0 3px 12px rgba(15, 23, 42, 0.035);
    }

    div[data-testid="stMetricLabel"] {
        color: #677288;
    }

    button[kind="primary"] {
        border-radius: 10px !important;
        font-weight: 700 !important;
    }

    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        border-bottom: 1px solid #e4e9f2;
    }

    .stTabs [data-baseweb="tab"] {
        border-radius: 10px 10px 0 0;
        padding-left: 16px;
        padding-right: 16px;
    }

    .ticket-card {
        background: white;
        border: 1px solid #e4e9f2;
        border-radius: 14px;
        padding: 16px;
        margin-bottom: 12px;
        box-shadow: 0 3px 12px rgba(15, 23, 42, 0.035);
    }

    code {
        white-space: pre-wrap !important;
    }
</style>
""", unsafe_allow_html=True)

# ==========================================
# BASE DE DATOS
# ==========================================
def get_db_connection():
    if "postgres" in st.secrets and "url" in st.secrets["postgres"]:
        conn = psycopg2.connect(st.secrets["postgres"]["url"])
        conn.autocommit = True
        return conn
    else:
        return sqlite3.connect("cyber_audits_enterprise.db")

def init_db():
    conn = get_db_connection()
    conn.autocommit = True
    c = conn.cursor()
    is_pg = "postgres" in st.secrets
    
    if is_pg:
        c.execute("""CREATE TABLE IF NOT EXISTS organizations (id SERIAL PRIMARY KEY, name TEXT UNIQUE NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        c.execute("""CREATE TABLE IF NOT EXISTS history (id SERIAL PRIMARY KEY, timestamp TEXT, hostname TEXT, ip TEXT, risk_score INTEGER, findings_count INTEGER, report_type TEXT, organization_id INTEGER, findings_json TEXT, scan_meta_json TEXT)""")
        c.execute("ALTER TABLE history ADD COLUMN IF NOT EXISTS organization_id INTEGER;")
        c.execute("ALTER TABLE history ADD COLUMN IF NOT EXISTS findings_json TEXT;")
        c.execute("ALTER TABLE history ADD COLUMN IF NOT EXISTS scan_meta_json TEXT;")
        c.execute("""CREATE TABLE IF NOT EXISTS remediation_tasks (id SERIAL PRIMARY KEY, organization_id INTEGER, scan_id INTEGER, hostname TEXT, finding_vector TEXT, severity TEXT DEFAULT 'MEDIO', status TEXT DEFAULT 'Pendiente', notes TEXT)""")
        c.execute("ALTER TABLE remediation_tasks ADD COLUMN IF NOT EXISTS organization_id INTEGER;")
        c.execute("ALTER TABLE remediation_tasks ADD COLUMN IF NOT EXISTS scan_id INTEGER;")
        c.execute("ALTER TABLE remediation_tasks ADD COLUMN IF NOT EXISTS severity TEXT;")
        c.execute("""CREATE TABLE IF NOT EXISTS remediation_logs (id SERIAL PRIMARY KEY, task_id INTEGER, timestamp TEXT, status TEXT, notes TEXT)""")
    else:
        c.execute("""CREATE TABLE IF NOT EXISTS organizations (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        c.execute("""CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, hostname TEXT, ip TEXT, risk_score INTEGER, findings_count INTEGER, report_type TEXT, organization_id INTEGER, findings_json TEXT, scan_meta_json TEXT)""")
        try: c.execute("ALTER TABLE history ADD COLUMN organization_id INTEGER;")
        except: pass
        try: c.execute("ALTER TABLE history ADD COLUMN findings_json TEXT;")
        except: pass
        try: c.execute("ALTER TABLE history ADD COLUMN scan_meta_json TEXT;")
        except: pass
        c.execute("""CREATE TABLE IF NOT EXISTS remediation_tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, organization_id INTEGER, scan_id INTEGER, hostname TEXT, finding_vector TEXT, severity TEXT DEFAULT 'MEDIO', status TEXT DEFAULT 'Pendiente', notes TEXT)""")
        try:
            c.execute("ALTER TABLE remediation_tasks ADD COLUMN organization_id INTEGER;")
            c.execute("ALTER TABLE remediation_tasks ADD COLUMN scan_id INTEGER;")
            c.execute("ALTER TABLE remediation_tasks ADD COLUMN severity TEXT;")
        except: pass
        c.execute("""CREATE TABLE IF NOT EXISTS remediation_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, task_id INTEGER, timestamp TEXT, status TEXT, notes TEXT)""")
        conn.commit()
    c.close()
    conn.close()

init_db()

def save_scan_to_db(
    hostname,
    ip,
    risk_score,
    findings_count,
    report_type_val,
    organization_id=None,
    findings=None,
    scan_meta=None
):
    conn = get_db_connection()
    c = conn.cursor()

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    findings_str = json.dumps(findings or [], ensure_ascii=False)
    meta_str = json.dumps(scan_meta or {}, ensure_ascii=False)

    is_pg = "postgres" in st.secrets
    ph = "%s" if is_pg else "?"

    if is_pg:
        c.execute(
            f"""
            INSERT INTO history
            (
                timestamp,
                hostname,
                ip,
                risk_score,
                findings_count,
                report_type,
                organization_id,
                findings_json,
                scan_meta_json
            )
            VALUES
            ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})
            RETURNING id
            """,
            (
                timestamp,
                hostname,
                ip,
                risk_score,
                findings_count,
                report_type_val,
                organization_id,
                findings_str,
                meta_str
            )
        )
        scan_id = c.fetchone()[0]
    else:
        c.execute(
            f"""
            INSERT INTO history
            (
                timestamp,
                hostname,
                ip,
                risk_score,
                findings_count,
                report_type,
                organization_id,
                findings_json,
                scan_meta_json
            )
            VALUES
            ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})
            """,
            (
                timestamp,
                hostname,
                ip,
                risk_score,
                findings_count,
                report_type_val,
                organization_id,
                findings_str,
                meta_str
            )
        )
        scan_id = c.lastrowid

    if findings:
        for finding in findings:
            if (
                finding.get("is_vulnerability", True)
                and finding.get("severity") != "INFORMATIVO"
            ):
                c.execute(
                    f"""
                    INSERT INTO remediation_tasks
                    (
                        organization_id,
                        scan_id,
                        hostname,
                        finding_vector,
                        severity,
                        status
                    )
                    VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, 'Pendiente')
                    """,
                    (
                        organization_id,
                        scan_id,
                        hostname,
                        finding["vector"],
                        finding.get("severity", "MEDIO")
                    )
                )

    if not is_pg:
        conn.commit()

    c.close()
    conn.close()
    return scan_id


def delete_scan(scan_id):
    conn = get_db_connection()
    conn.autocommit = True
    c = conn.cursor()
    ph = "%s" if "postgres" in st.secrets else "?"
    c.execute(f"DELETE FROM remediation_logs WHERE task_id IN (SELECT id FROM remediation_tasks WHERE scan_id = {ph})", (scan_id,))
    c.execute(f"DELETE FROM remediation_tasks WHERE scan_id = {ph}", (scan_id,))
    c.execute(f"DELETE FROM history WHERE id = {ph}", (scan_id,))
    c.close()
    conn.close()

def delete_organization(org_id):
    conn = get_db_connection()
    conn.autocommit = True
    c = conn.cursor()
    ph = "%s" if "postgres" in st.secrets else "?"
    c.execute(f"DELETE FROM remediation_logs WHERE task_id IN (SELECT id FROM remediation_tasks WHERE organization_id = {ph})", (org_id,))
    c.execute(f"DELETE FROM remediation_tasks WHERE organization_id = {ph}", (org_id,))
    c.execute(f"DELETE FROM history WHERE organization_id = {ph}", (org_id,))
    c.execute(f"DELETE FROM organizations WHERE id = {ph}", (org_id,))
    c.close()
    conn.close()

# ==========================================
# MOTOR DE ESCANEO
# ==========================================
def get_geolocation(hostname):
    geo_data = {"ip": "N/A", "country": "Desconocido", "city": "Desconocido", "org": "Desconocido"}
    try:
        ip = socket.gethostbyname(hostname)
        geo_data["ip"] = ip
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,org,isp", timeout=3)
        if response.status_code == 200 and response.json().get("status") == "success":
            data = response.json()
            geo_data.update({"country": data.get("country", ""), "city": data.get("city", ""), "org": data.get("org", "")})
    except: pass
    return geo_data

def _normalize_target(raw_url):
    raw_url = (raw_url or "").strip()

    if not raw_url:
        raise ValueError("Objetivo vacío.")

    if "://" not in raw_url:
        raw_url = "https://" + raw_url

    parsed = urlparse(raw_url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Solo se permiten URLs HTTP/HTTPS.")

    if not parsed.hostname:
        raise ValueError("No se pudo identificar el dominio.")

    if parsed.username or parsed.password:
        raise ValueError("No se permiten credenciales dentro de la URL.")

    if parsed.port not in (None, 80, 443):
        raise ValueError(
            "En esta versión solo se permiten los puertos web 80 y 443."
        )

    return raw_url, parsed.hostname.lower()


def _validate_public_host(hostname):
    try:
        results = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        raise ValueError("El dominio no resuelve por DNS.")

    addresses = {
        item[4][0].split("%")[0]
        for item in results
    }

    if not addresses:
        raise ValueError("No se encontraron direcciones IP para el dominio.")

    for addr in addresses:
        ip = ipaddress.ip_address(addr)

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise ValueError(
                "El objetivo resuelve a una dirección no pública y fue bloqueado."
            )

    return addresses


def _safe_get(url, timeout=8, max_redirects=10):
    """
    Realiza solicitudes HTTP/HTTPS siguiendo redirecciones de forma controlada.

    - Mantiene cookies entre saltos usando requests.Session().
    - Valida nuevamente cada destino antes de conectarse.
    - Impide redirecciones hacia localhost, redes privadas o direcciones reservadas.
    - Detecta bucles de redirección.
    """
    current = url
    visited = set()

    session = requests.Session()
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (compatible; CyberAudits/2.2; "
            "+https://cyberaudits.local/security-check)"
        ),
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        "Accept-Language": "es-419,es;q=0.9,en;q=0.7",
    })

    try:
        for _ in range(max_redirects + 1):
            current, hostname = _normalize_target(current)
            _validate_public_host(hostname)

            # IMPORTANTE:
            # https://dominio.com y https://dominio.com/ pueden formar parte
            # de una redirección normal. No quitamos la barra final porque
            # eso generaba falsos positivos de "bucle de redirección".
            canonical = current

            if canonical in visited:
                raise ValueError(
                    "Se detectó un bucle de redirección HTTP en el objetivo."
                )

            visited.add(canonical)

            response = session.get(
                current,
                timeout=timeout,
                allow_redirects=False,
                stream=True
            )

            # No descargamos cuerpos grandes: solo necesitamos estado y cabeceras.
            response.close()

            if response.status_code not in (301, 302, 303, 307, 308):
                return response, current

            location = response.headers.get("Location")

            if not location:
                return response, current

            next_url = urljoin(current, location)

            # Validamos el siguiente salto ANTES de solicitarlo.
            next_normalized, next_hostname = _normalize_target(next_url)
            _validate_public_host(next_hostname)

            current = next_normalized

        raise ValueError(
            f"El objetivo requiere más de {max_redirects} redirecciones HTTP."
        )

    finally:
        session.close()


def _tls_certificate_info(hostname):
    _validate_public_host(hostname)

    context = ssl.create_default_context()

    with socket.create_connection((hostname, 443), timeout=6) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
            cert = tls_sock.getpeercert()
            cipher = tls_sock.cipher()
            tls_version = tls_sock.version()

    not_after_raw = cert.get("notAfter")
    expires_at = None
    days_left = None

    if not_after_raw:
        expires_ts = ssl.cert_time_to_seconds(not_after_raw)

        expires_at = datetime.datetime.fromtimestamp(
            expires_ts,
            tz=datetime.timezone.utc
        )

        days_left = (
            expires_at
            - datetime.datetime.now(datetime.timezone.utc)
        ).days

    issuer = dict(x[0] for x in cert.get("issuer", []))

    return {
        "tls_version": tls_version or "Desconocido",
        "cipher": cipher[0] if cipher else "Desconocido",
        "expires_at": expires_at.isoformat() if expires_at else "Desconocido",
        "days_left": days_left,
        "issuer": (
            issuer.get("organizationName")
            or issuer.get("commonName")
            or "Desconocido"
        ),
    }


def scan_target(url):
    findings = []

    stats = {
        "Críticas": 0,
        "Medias": 0,
        "Bajas": 0,
        "Seguras": 0
    }

    def add_finding(
        vector,
        severity,
        desc,
        impact,
        fix,
        compliance,
        snippet="",
        category="Web",
        evidence=""
    ):
        severity = severity.upper()

        if severity == "CRÍTICO":
            stats["Críticas"] += 1
        elif severity == "MEDIO":
            stats["Medias"] += 1
        else:
            stats["Bajas"] += 1

        findings.append({
            "vector": vector,
            "severity": severity,
            "desc": desc,
            "impact": impact,
            "fix": fix,
            "compliance": compliance,
            "snippet": snippet,
            "category": category,
            "evidence": evidence,
            "verified": True
        })

    try:
        normalized_url, hostname = _normalize_target(url)
        _validate_public_host(hostname)

    except Exception as e:
        hostname = urlparse(
            url if "://" in url else "https://" + url
        ).hostname or "desconocido"

        geo = {
            "ip": "N/A",
            "country": "Desconocido",
            "city": "Desconocido",
            "org": "Desconocido"
        }

        add_finding(
            "Objetivo rechazado por validación de seguridad",
            "CRÍTICO",
            f"CyberAudits no inició el análisis: {e}",
            "La validación evita analizar destinos internos o URLs no permitidas.",
            "Ingresar un dominio público válido usando HTTP o HTTPS.",
            "Control interno CyberAudits",
            category="Validación"
        )

        return findings, stats, hostname, geo, 0

    geo = get_geolocation(hostname)

    # =====================================
    # TLS / CERTIFICADO
    # =====================================

    try:
        tls = _tls_certificate_info(hostname)
        days_left = tls["days_left"]

        if days_left is None:
            add_finding(
                "No se pudo determinar la expiración del certificado",
                "MEDIO",
                "El servidor respondió por TLS, pero no fue posible determinar la fecha de expiración.",
                "Dificulta validar correctamente la vigencia del certificado.",
                "Revisar la cadena y configuración TLS.",
                "OWASP / buenas prácticas TLS",
                category="TLS",
                evidence=f"TLS={tls['tls_version']} | Emisor={tls['issuer']}"
            )

        elif days_left < 0:
            add_finding(
                "Certificado TLS vencido",
                "CRÍTICO",
                f"El certificado está vencido desde hace {abs(days_left)} días.",
                "Los navegadores pueden bloquear el sitio o mostrar advertencias.",
                "Renovar e instalar un certificado TLS válido.",
                "OWASP / buenas prácticas TLS",
                category="TLS",
                evidence=f"Vencimiento={tls['expires_at']}"
            )

        elif days_left <= 7:
            add_finding(
                "Certificado TLS próximo a vencer",
                "CRÍTICO",
                f"El certificado vence en {days_left} días.",
                "Existe riesgo inmediato de interrupción o advertencias.",
                "Renovar el certificado antes del vencimiento.",
                "OWASP / buenas prácticas TLS",
                category="TLS",
                evidence=f"Vencimiento={tls['expires_at']}"
            )

        elif days_left <= 30:
            add_finding(
                "Certificado TLS vence pronto",
                "MEDIO",
                f"El certificado vence en {days_left} días.",
                "Puede afectar disponibilidad y confianza si no se renueva.",
                "Programar la renovación del certificado.",
                "OWASP / buenas prácticas TLS",
                category="TLS",
                evidence=f"Vencimiento={tls['expires_at']}"
            )
        else:
            stats["Seguras"] += 1

        if tls["tls_version"] in ("TLSv1", "TLSv1.1"):
            add_finding(
                "Versión TLS obsoleta",
                "CRÍTICO",
                f"Se negoció {tls['tls_version']}.",
                "Las versiones antiguas de TLS tienen debilidades conocidas.",
                "Permitir únicamente TLS 1.2 y TLS 1.3.",
                "OWASP TLS Cheat Sheet",
                category="TLS",
                evidence=f"Versión={tls['tls_version']}"
            )
        else:
            stats["Seguras"] += 1

    except Exception as e:
        add_finding(
            "Problema en HTTPS/TLS",
            "CRÍTICO",
            f"No se pudo establecer correctamente una conexión TLS válida: {e}",
            "El sitio puede presentar problemas de certificado, cifrado o HTTPS.",
            "Revisar certificado, cadena de confianza y configuración TLS.",
            "OWASP TLS Cheat Sheet",
            category="TLS"
        )

    # =====================================
    # CABECERAS HTTP
    # =====================================

    try:
        response, final_url = _safe_get(normalized_url)
        headers = response.headers

        if final_url.lower().startswith("https://"):
            stats["Seguras"] += 1
        else:
            add_finding(
                "Navegación final sin HTTPS",
                "CRÍTICO",
                f"La navegación terminó en {final_url}.",
                "El tráfico podría viajar sin cifrado.",
                "Forzar HTTPS para todo el sitio.",
                "OWASP / NIST",
                category="Transporte",
                evidence=f"URL final={final_url}"
            )

        hsts = headers.get("Strict-Transport-Security", "")
        if hsts:
            stats["Seguras"] += 1
        else:
            add_finding(
                "HTTP Strict Transport Security (HSTS) ausente",
                "MEDIO",
                "No se detectó la cabecera HSTS.",
                "El navegador no queda obligado a usar HTTPS en futuras visitas.",
                "Configurar HSTS después de confirmar que todo el sitio funciona por HTTPS.",
                "OWASP Secure Headers",
                "Strict-Transport-Security: max-age=31536000; includeSubDomains",
                "Headers"
            )

        csp = headers.get("Content-Security-Policy", "")
        if csp:
            stats["Seguras"] += 1
        else:
            add_finding(
                "Content Security Policy (CSP) ausente",
                "MEDIO",
                "No se detectó una política CSP.",
                "Aumenta la exposición ante determinados ataques de inyección de contenido y XSS.",
                "Implementar una CSP adaptada al sitio.",
                "OWASP Secure Headers",
                "Content-Security-Policy: default-src 'self'",
                "Headers"
            )

        xfo = headers.get("X-Frame-Options", "")
        if xfo or "frame-ancestors" in csp.lower():
            stats["Seguras"] += 1
        else:
            add_finding(
                "Protección contra Clickjacking no detectada",
                "BAJO",
                "No se detectó X-Frame-Options ni frame-ancestors.",
                "El sitio podría ser embebido dentro de marcos de terceros.",
                "Configurar frame-ancestors o X-Frame-Options.",
                "OWASP Secure Headers",
                "X-Frame-Options: SAMEORIGIN",
                "Headers"
            )

        if headers.get("X-Content-Type-Options", "").lower() == "nosniff":
            stats["Seguras"] += 1
        else:
            add_finding(
                "X-Content-Type-Options ausente o débil",
                "BAJO",
                "No se detectó el valor recomendado nosniff.",
                "El navegador podría intentar interpretar contenido con un tipo diferente.",
                "Configurar X-Content-Type-Options.",
                "OWASP Secure Headers",
                "X-Content-Type-Options: nosniff",
                "Headers"
            )

        if headers.get("Referrer-Policy"):
            stats["Seguras"] += 1
        else:
            add_finding(
                "Referrer-Policy ausente",
                "BAJO",
                "No se detectó una política explícita para Referer.",
                "Puede enviarse más información de navegación de la necesaria.",
                "Definir Referrer-Policy.",
                "OWASP Secure Headers",
                "Referrer-Policy: strict-origin-when-cross-origin",
                "Headers"
            )

        if headers.get("Permissions-Policy"):
            stats["Seguras"] += 1
        else:
            add_finding(
                "Permissions-Policy ausente",
                "BAJO",
                "No se detectó una política de permisos del navegador.",
                "Funciones del navegador pueden quedar menos restringidas.",
                "Definir Permissions-Policy.",
                "OWASP Secure Headers",
                "Permissions-Policy: camera=(), microphone=(), geolocation=()",
                "Headers"
            )

        set_cookie = headers.get("Set-Cookie", "")
        if set_cookie:
            cookie_lower = set_cookie.lower()

            if "secure" not in cookie_lower:
                add_finding(
                    "Cookie sin atributo Secure",
                    "MEDIO",
                    "Se observó al menos una cookie sin evidencia del atributo Secure.",
                    "Una cookie sensible podría enviarse sin cifrado.",
                    "Aplicar Secure a cookies de sesión.",
                    "OWASP Session Management",
                    "Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax",
                    "Cookies"
                )
            else:
                stats["Seguras"] += 1

            if "httponly" not in cookie_lower:
                add_finding(
                    "Cookie sin atributo HttpOnly",
                    "BAJO",
                    "Se observó al menos una cookie sin evidencia del atributo HttpOnly.",
                    "JavaScript podría acceder a cookies sensibles.",
                    "Aplicar HttpOnly a cookies de sesión.",
                    "OWASP Session Management",
                    "Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax",
                    "Cookies"
                )
            else:
                stats["Seguras"] += 1

        server = headers.get("Server", "")
        if server and any(ch.isdigit() for ch in server):
            add_finding(
                "Información de versión del servidor expuesta",
                "BAJO",
                f"El servidor publica: {server}",
                "La divulgación de versiones puede facilitar ataques dirigidos.",
                "Reducir información de versión innecesaria.",
                "OWASP Information Exposure",
                category="Exposición",
                evidence=f"Server={server}"
            )
        else:
            stats["Seguras"] += 1

    except Exception as e:
        # Un error del propio proceso de evaluación NO demuestra una vulnerabilidad.
        # Lo registramos como resultado no concluyente sin penalizar el CyberScore.
        findings.append({
            "vector": "Evaluación HTTP/HTTPS no concluyente",
            "severity": "INFORMATIVO",
            "desc": f"No se pudo completar esta parte de la evaluación: {e}",
            "impact": (
                "Este resultado no implica por sí mismo una vulnerabilidad. "
                "CyberAudits no pudo verificar todos los controles HTTP/HTTPS."
            ),
            "fix": (
                "Reintentar el análisis. Si persiste, revisar redirecciones, "
                "protecciones anti-bot o disponibilidad del sitio."
            ),
            "compliance": "Control de calidad CyberAudits",
            "snippet": "",
            "category": "Diagnóstico",
            "evidence": str(e),
            "verified": False,
            "is_vulnerability": False
        })

    # =====================================
    # REDIRECCIÓN HTTP -> HTTPS
    # =====================================

    try:
        http_url = f"http://{hostname}/"
        _, http_final = _safe_get(http_url)

        if http_final.lower().startswith("https://"):
            stats["Seguras"] += 1
        else:
            add_finding(
                "HTTP no fuerza redirección a HTTPS",
                "MEDIO",
                f"El acceso HTTP terminó en {http_final}.",
                "Un usuario podría permanecer en una conexión sin cifrar.",
                "Redirigir HTTP hacia HTTPS.",
                "OWASP / buenas prácticas TLS",
                category="Transporte",
                evidence=f"URL final={http_final}"
            )

    except Exception:
        # Si HTTP está cerrado, no se considera una vulnerabilidad.
        stats["Seguras"] += 1

    # =====================================
    # CYBERSCORE V2
    # =====================================

    penalty = (
        stats["Críticas"] * 25
        + stats["Medias"] * 8
        + stats["Bajas"] * 3
    )

    risk_score = max(0, 100 - min(100, penalty))

    return findings, stats, hostname, geo, risk_score


# ==========================================
# GENERADORES DE REPORTES (PDF Y DOCX DIFERENCIADOS)
# ==========================================
def generate_chart(stats):
    labels, sizes, colors = list(stats.keys()), list(stats.values()), ['#dc2626', '#f59e0b', '#3b82f6', '#10b981']
    non_zero = [(l, s, c) for l, s, c in zip(labels, sizes, colors) if s > 0]
    if not non_zero: non_zero = [("Seguras", 1, "#10b981")]
    l_f, s_f, c_f = zip(*non_zero)
    fig, ax = plt.subplots(figsize=(4.5, 2.8))
    ax.pie(s_f, labels=l_f, colors=c_f, autopct='%1.1f%%', startangle=90, textprops={'fontsize': 8, 'weight': 'bold'})
    ax.axis('equal')
    plt.tight_layout()
    chart_path = "vulnerability_chart.png"
    plt.savefig(chart_path, dpi=300, bbox_inches='tight', transparent=True)
    plt.close()
    with open(chart_path, "rb") as f: return base64.b64encode(f.read()).decode("utf-8")

def generate_docx(hostname, findings, risk_score, agency_name, agency_tagline, report_type, recipient_name, report_subject):
    doc = Document()
    for section in doc.sections: section.top_margin = section.bottom_margin = section.left_margin = section.right_margin = Inches(1)
    
    run_title = doc.add_paragraph().add_run(f"INFORME: {report_type.upper()}")
    run_title.font.size, run_title.font.bold, run_title.font.color.rgb = Pt(15), True, RGBColor(15, 23, 42)
    
    doc.add_paragraph(f"Emitido por: {agency_name} ({agency_tagline})\nDirigido a: {recipient_name} | Asunto: {report_subject}\nObjetivo analizado: {hostname} | CyberScore de Seguridad: {risk_score}/100")
    
    if "Técnico" in report_type:
        doc.add_heading("Detalle Técnico y Bloques de Configuración", level=2)
        for idx, f in enumerate(findings, 1):
            h = doc.add_paragraph().add_run(f"#{idx} - {f['vector']} [{f['severity']}]")
            h.font.bold = True
            doc.add_paragraph(f"Descripción técnica: {f['desc']}")
            doc.add_paragraph(f"Impacto operativo: {f['impact']}")
            p_fix = doc.add_paragraph()
            p_fix.add_run(f"Remediación técnica / Snippet:\n{f.get('snippet', 'N/A')}").font.bold = True
            
    elif "Narrativo" in report_type:
        doc.add_heading("Informe Ejecutivo y Situación Actual", level=2)
        doc.add_paragraph(f"Estimado/a {recipient_name},\n\nPor medio del presente documento, el equipo de auditoría emite el dictamen gerencial respecto al análisis perimetral realizado sobre el objetivo {hostname}. Tras la evaluación, se ha determinado un CyberScore global de {risk_score} sobre 100, donde una puntuación mayor representa una mejor postura de seguridad.")
        doc.add_heading("Análisis de Riesgos y Consecuencias", level=3)
        doc.add_paragraph("A continuación se detallan las situaciones detectadas y el impacto crítico para la continuidad del negocio en caso de no aplicarse las medidas correctivas:")
        for idx, f in enumerate(findings, 1):
            h = doc.add_paragraph().add_run(f"• {f['vector']} ({f['severity']})")
            h.font.bold = True
            doc.add_paragraph(f"Lo que está pasando: {f['desc']}\nEn qué impacta si no se resuelve: {f['impact']}\nAcción recomendada: {f['fix']}")
        doc.add_paragraph("\nQuedamos a su entera disposición para notificar y coordinar las acciones correctivas con las áreas involucradas.")
        
    else: # ISO / Compliance
        doc.add_heading("Mapa Orientativo de Controles (ISO / NIST)", level=2)
        doc.add_paragraph(f"Este reporte relaciona los hallazgos técnicos observados en {hostname} con referencias de buenas prácticas. No constituye una certificación ni determina por sí solo el cumplimiento integral de una norma.")
        for idx, f in enumerate(findings, 1):
            h = doc.add_paragraph().add_run(f"Control #{idx} - {f['vector']} [{f['severity']}]")
            h.font.bold = True
            doc.add_paragraph(f"Referencia de buenas prácticas / control: {f.get('compliance', 'ISO 27001')}")
            doc.add_paragraph(f"Hallazgo de Auditoría: {f['desc']}")
            doc.add_paragraph(f"Impacto potencial: {f['impact']}")
            p_fix = doc.add_paragraph()
            p_fix.add_run(f"Recomendación de remediación: {f['fix']}").font.bold = True
            
    buffer = io.BytesIO()
    doc.save(buffer)
    buffer.seek(0)
    return buffer.getvalue()

def generate_pdf(findings, chart_b64, hostname, risk_score, agency_name, agency_tagline, report_type, recipient_name, report_subject, output_filename):
    css_base = """
        @page { size: A4; margin: 15mm; }
        body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; font-size: 9.5pt; color: #1e293b; line-height: 1.5; }
        .header { background-color: #0f172a; color: #ffffff; padding: 15px 20px; border-radius: 6px; margin-bottom: 20px; }
        .header h1 { margin: 0; font-size: 16pt; letter-spacing: 0.5px; }
        .header p { margin: 4px 0 0 0; color: #94a3b8; font-size: 9pt; }
        .meta-box { border: 1px solid #cbd5e1; padding: 10px; border-radius: 6px; margin-bottom: 20px; background-color: #f8fafc; }
        .title { color: #0f172a; border-bottom: 2px solid #3b82f6; padding-bottom: 5px; margin-top: 25px; font-size: 13pt; }
        .card { border: 1px solid #cbd5e1; border-radius: 6px; margin-bottom: 12px; page-break-inside: avoid; }
        .card-header { background-color: #f1f5f9; padding: 8px 12px; font-weight: bold; border-bottom: 1px solid #cbd5e1; }
        .card-body { padding: 10px 12px; }
        .badge { float: right; padding: 2px 8px; border-radius: 12px; font-size: 7.5pt; color: white; }
        .bg-crit { background-color: #dc2626; } .bg-med { background-color: #f59e0b; } .bg-low { background-color: #3b82f6; }
    """

    if "Narrativo" in report_type:
        header_html = f"""
            <div class="header" style="text-align: center;">
                <h1 style="margin: 0; font-size: 16pt; letter-spacing: 0.5px;">INFORME EJECUTIVO</h1>
                <p style="margin: 4px 0 0 0; color: #94a3b8; font-size: 9pt;">Emitido por: {agency_name} | {agency_tagline}</p>
            </div>
            <div class="meta-box">
                <table style="width: 100%; border: none;">
                    <tr>
                        <td style="width: 50%;"><strong>Dirigido a:</strong> {recipient_name}</td>
                        <td style="width: 50%;"><strong>Asunto:</strong> {report_subject}</td>
                    </tr>
                    <tr>
                        <td><strong>Objetivo Analizado:</strong> {hostname}</td>
                        <td><strong>Fecha:</strong> {datetime.datetime.now().strftime('%Y-%m-%d')}</td>
                    </tr>
                </table>
            </div>
        """
    else:
        header_html = f"""
            <div class="header">
                <h1>{report_type.upper()}</h1>
                <p>Emitido por: {agency_name} | {agency_tagline}</p>
            </div>
            <div class="meta-box">
                <table style="width: 100%; border: none;">
                    <tr>
                        <td style="width: 50%;"><strong>Dirigido a:</strong> {recipient_name}</td>
                        <td style="width: 50%;"><strong>Asunto:</strong> {report_subject}</td>
                    </tr>
                    <tr>
                        <td><strong>Objetivo Analizado:</strong> {hostname}</td>
                        <td><strong>Fecha:</strong> {datetime.datetime.now().strftime('%Y-%m-%d')}</td>
                    </tr>
                </table>
            </div>
        """

    if "Técnico" in report_type:
        content = header_html + f"""
            <h2 class="title">1. Resumen Técnico de Postura</h2>
            <p>CyberScore Técnico: <strong>{risk_score}/100</strong>.</p>
            <div style="text-align: center; margin: 15px 0;"><img src="data:image/png;base64,{chart_b64}" style="width: 250px;"></div>
            <h2 class="title">2. Evidencia de Vulnerabilidades y Bloques de Configuración</h2>
        """
        for i, f in enumerate(findings, 1):
            bg = "bg-crit" if f["severity"] == "CRÍTICO" else ("bg-med" if f["severity"] == "MEDIO" else "bg-low")
            content += f"""
            <div class="card">
                <div class="card-header">#{i} - {f['vector']} <span class="badge {bg}">{f['severity']}</span></div>
                <div class="card-body">
                    <p><strong>Descripción Técnica:</strong> {f['desc']}</p>
                    <p><strong>Impacto Operativo:</strong> {f['impact']}</p>
                    <div style="background:#f0f9ff; border-left:3px solid #0284c7; padding:8px; margin-top:8px;">
                        <strong>Remediación Técnica (Snippet / Config):</strong><br>
                        <code>{f.get('snippet', 'N/A')}</code>
                    </div>
                </div>
            </div>
            """
            
    elif "Narrativo" in report_type:
        content = header_html + f"""
            <h2 class="title">Informe Ejecutivo y Situación Actual</h2>
            <p>Estimado/a <strong>{recipient_name}</strong>,</p>
            <p>Por medio del presente documento, el equipo de auditoría emite el dictamen gerencial respecto al análisis perimetral realizado sobre el objetivo <strong>{hostname}</strong>. Tras la evaluación, se ha determinado un CyberScore global de <strong>{risk_score} sobre 100</strong>, donde una puntuación mayor representa una mejor postura de seguridad.</p>
            <h2 class="title">Análisis de Riesgos y Consecuencias</h2>
            <p>A continuación se detallan las situaciones detectadas, lo que está pasando y el impacto crítico para la continuidad del negocio en caso de no aplicarse las medidas correctivas:</p>
        """
        for i, f in enumerate(findings, 1):
            bg = "bg-crit" if f["severity"] == "CRÍTICO" else ("bg-med" if f["severity"] == "MEDIO" else "bg-low")
            content += f"""
            <div class="card">
                <div class="card-header">Hallazgo #{i}: {f['vector']} <span class="badge {bg}">{f['severity']}</span></div>
                <div class="card-body">
                    <p><strong>Lo que está pasando:</strong> {f['desc']}</p>
                    <p><strong>En qué impacta si no se resuelve:</strong> {f['impact']}</p>
                    <p><strong>Acción recomendada / Notificación:</strong> {f['fix']}</p>
                </div>
            </div>
            """
        content += "<p style='margin-top:15px;'>Quedamos a su entera disposición para coordinar y notificar las acciones correctivas con las áreas responsables.</p>"
        
    else: # ISO / Compliance
        content = header_html + f"""
            <h2 class="title">1. Mapa Orientativo de Controles (ISO 27001 / NIST)</h2>
            <p>CyberScore Técnico: <strong>{risk_score}/100</strong>. Este informe relaciona hallazgos técnicos con referencias de buenas prácticas y no constituye una certificación de cumplimiento.</p>
            <div style="text-align: center; margin: 15px 0;"><img src="data:image/png;base64,{chart_b64}" style="width: 220px;"></div>
            <h2 class="title">2. Análisis de Controles Incumplidos y Marcos Regulatorios</h2>
        """
        for i, f in enumerate(findings, 1):
            bg = "bg-crit" if f["severity"] == "CRÍTICO" else ("bg-med" if f["severity"] == "MEDIO" else "bg-low")
            content += f"""
            <div class="card">
                <div class="card-header">Control #{i}: {f['vector']} <span class="badge {bg}">Riesgo {f['severity']}</span></div>
                <div class="card-body">
                    <p><strong>Referencia de buenas prácticas / control:</strong> <code>{f.get('compliance', 'ISO 27001')}</code></p>
                    <p><strong>Hallazgo de Auditoría:</strong> {f['desc']}</p>
                    <p><strong>Impacto potencial:</strong> {f['impact']}</p>
                    <div style="background:#f8fafc; border-left:3px solid #0f172a; padding:8px; margin-top:8px;">
                        <strong>Recomendación de remediación:</strong> {f['fix']}
                    </div>
                </div>
            </div>
            """

    HTML(string=f"<html><head><style>{css_base}</style></head><body>{content}</body></html>").write_pdf(output_filename)


# ==========================================
# UI CYBERAUDITS 2.3
# ==========================================

if "scanned" not in st.session_state:
    st.session_state.scanned = False

if "toast_msg" not in st.session_state:
    st.session_state.toast_msg = ""

if "toast_type" not in st.session_state:
    st.session_state.toast_type = "success"

if "cyberpass_ready" not in st.session_state:
    st.session_state.cyberpass_ready = False


def safe_findings(value):
    if isinstance(value, list):
        return value

    if not value:
        return []

    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, list) else []
    except Exception:
        return []


def safe_meta(value):
    if isinstance(value, dict):
        return value

    if not value:
        return {}

    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def is_actionable(finding):
    return (
        finding.get("severity") in {"CRÍTICO", "MEDIO", "BAJO"}
        and finding.get("is_vulnerability", True)
    )


def finding_weight(finding):
    return {
        "CRÍTICO": 25,
        "MEDIO": 8,
        "BAJO": 3,
        "INFORMATIVO": 0
    }.get(finding.get("severity", "INFORMATIVO"), 0)


def finding_type(finding):
    severity = finding.get("severity", "INFORMATIVO")
    category = finding.get("category", "")

    if severity == "INFORMATIVO":
        return "Informativo"

    if category == "Exposición":
        return "Exposición de información"

    if category == "TLS":
        return "Seguridad criptográfica"

    if category == "Transporte":
        return "Configuración de transporte"

    if category == "Cookies":
        return "Configuración de sesión"

    if category == "Headers":
        if severity == "BAJO":
            return "Hardening recomendado"
        return "Configuración de seguridad"

    if category == "Disponibilidad":
        return "Disponibilidad"

    if category == "Validación":
        return "Validación del objetivo"

    return "Hallazgo de seguridad"


def score_status(score):
    score = int(score or 0)

    if score >= 90:
        return "EXCELENTE", "Postura sólida en los controles verificados."

    if score >= 80:
        return "BUENA", "Buena postura, con algunas mejoras recomendadas."

    if score >= 65:
        return "MEJORABLE", "Hay controles que conviene corregir para reducir exposición."

    if score >= 40:
        return "RIESGO ALTO", "La postura requiere atención prioritaria."

    return "CRÍTICA", "Se detectaron riesgos que requieren revisión inmediata."


def category_scores(findings):
    groups = {
        "TLS & Certificado": {"TLS"},
        "Seguridad Web": {"Headers", "Cookies"},
        "Transporte": {"Transporte"},
        "Exposición": {"Exposición"}
    }

    result = {}

    for label, categories in groups.items():
        penalty = sum(
            finding_weight(f)
            for f in findings
            if f.get("category") in categories and is_actionable(f)
        )
        result[label] = max(0, 100 - min(100, penalty))

    return result


def build_scan_meta(stats, findings):
    informational = sum(
        1
        for f in findings
        if f.get("severity") == "INFORMATIVO"
    )

    verified_checks = int(sum(stats.values()))
    total_checks = verified_checks + informational

    if total_checks <= 0:
        coverage = 0
    else:
        coverage = round((verified_checks / total_checks) * 100)

    if coverage >= 90:
        confidence = "ALTA"
    elif coverage >= 70:
        confidence = "MEDIA"
    else:
        confidence = "BAJA"

    return {
        "verified_checks": verified_checks,
        "total_checks": total_checks,
        "coverage": coverage,
        "confidence": confidence,
        "category_scores": category_scores(findings)
    }


def fallback_scan_meta(findings):
    informational = sum(
        1
        for f in findings
        if f.get("severity") == "INFORMATIVO"
    )

    coverage = 100 if informational == 0 else 80

    return {
        "verified_checks": None,
        "total_checks": None,
        "coverage": coverage,
        "confidence": "ALTA" if coverage >= 90 else "MEDIA",
        "category_scores": category_scores(findings)
    }


def load_history(organization_id):
    conn = get_db_connection()
    ph = "%s" if "postgres" in st.secrets else "?"

    columns = """
        id,
        timestamp,
        hostname,
        ip,
        risk_score,
        findings_count,
        report_type,
        findings_json,
        scan_meta_json
    """

    if organization_id is not None:
        df = pd.read_sql_query(
            f"""
            SELECT {columns}
            FROM history
            WHERE organization_id = {ph}
            ORDER BY id DESC
            """,
            conn,
            params=(organization_id,)
        )
    else:
        df = pd.read_sql_query(
            f"""
            SELECT {columns}
            FROM history
            WHERE organization_id IS NULL
            ORDER BY id DESC
            """,
            conn
        )

    conn.close()
    return df


def count_actionable(findings):
    return sum(1 for f in findings if is_actionable(f))


def severity_class(severity):
    return {
        "CRÍTICO": "sev-critical",
        "MEDIO": "sev-medium",
        "BAJO": "sev-low",
        "INFORMATIVO": "sev-info"
    }.get(severity, "sev-info")


def render_finding_card(finding):
    severity = finding.get("severity", "INFORMATIVO")
    vector = html.escape(str(finding.get("vector", "Hallazgo")))
    kind = html.escape(finding_type(finding))
    category = html.escape(str(finding.get("category", "General")))

    st.markdown(
        f"""
        <div class="finding-card {severity_class(severity)}">
            <div class="finding-title">{vector}</div>
            <div class="finding-meta">
                {kind} · {category} · Severidad {html.escape(severity)}
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )


# ==========================================
# SIDEBAR / WORKSPACE
# ==========================================

st.sidebar.markdown("## 🛡️ CyberAudits")
st.sidebar.caption("Security Posture Workspace")
st.sidebar.markdown("---")

st.sidebar.markdown("### Organización")

try:
    conn_org = get_db_connection()
    org_df = pd.read_sql_query(
        "SELECT id, name FROM organizations ORDER BY name ASC",
        conn_org
    )
    conn_org.close()
except Exception:
    org_df = pd.DataFrame(columns=["id", "name"])

org_options = {"General / Sin asignar": None}

for _, row in org_df.iterrows():
    org_options[row["name"]] = row["id"]

selected_org_name = st.sidebar.selectbox(
    "Workspace activo",
    list(org_options.keys())
)

selected_org_id = org_options[selected_org_name]

if st.session_state.toast_msg:
    if st.session_state.toast_type == "error":
        st.sidebar.error(st.session_state.toast_msg)
    else:
        st.sidebar.success(st.session_state.toast_msg)

    st.session_state.toast_msg = ""


with st.sidebar.expander("➕ Añadir organización"):
    with st.form("add_org_form", clear_on_submit=True):
        new_org = st.text_input("Nombre")

        if st.form_submit_button("Guardar") and new_org:
            try:
                conn_add = get_db_connection()
                c_add = conn_add.cursor()

                ph_add = "%s" if "postgres" in st.secrets else "?"

                c_add.execute(
                    f"INSERT INTO organizations (name) VALUES ({ph_add})",
                    (new_org.strip(),)
                )

                if "postgres" not in st.secrets:
                    conn_add.commit()

                c_add.close()
                conn_add.close()

                st.session_state.toast_msg = (
                    f"Organización '{new_org.strip()}' creada."
                )
                st.session_state.toast_type = "success"
                st.rerun()

            except Exception:
                st.error("No se pudo crear. Puede que el nombre ya exista.")


st.sidebar.markdown("---")

with st.sidebar.expander("🧾 Branding de informes"):
    agency_name = st.text_input(
        "Agencia",
        value="CyberAudits Security"
    )

    agency_tagline = st.text_input(
        "Subtítulo",
        value="Security Posture & Remediation"
    )

    recipient_name = st.text_input(
        "Dirigido a",
        value="Dirección General"
    )

    report_subject = st.text_input(
        "Asunto",
        value="Evaluación de Postura de Ciberseguridad"
    )


if selected_org_id is not None:
    with st.sidebar.expander("⚠️ Zona de administración"):
        st.warning(
            "Eliminar una organización también elimina su historial "
            "y sus tickets asociados."
        )

        if st.button(
            "Eliminar organización actual",
            type="secondary",
            use_container_width=True
        ):
            delete_organization(selected_org_id)

            st.session_state.toast_msg = (
                f"Organización '{selected_org_name}' eliminada."
            )
            st.session_state.toast_type = "error"
            st.rerun()


# ==========================================
# HEADER
# ==========================================

st.markdown(
    """
    <div class="ca-brand">
        <div class="ca-kicker">CYBERAUDITS 2.3 · SECURITY POSTURE</div>
        <h1>Descubrí el riesgo. Corregí lo importante. Demostralo.</h1>
        <p>
            Evaluación verificable de postura de seguridad,
            priorización de hallazgos y seguimiento de remediación.
        </p>
    </div>
    """,
    unsafe_allow_html=True
)


tab_dashboard, tab_scan, tab_reports, tab_history, tab_remediation = st.tabs(
    [
        "🏠 Dashboard",
        "🔎 Security Scan",
        "📄 Reports",
        "📈 History",
        "🛠 Remediation"
    ]
)


# ==========================================
# DASHBOARD
# ==========================================

with tab_dashboard:
    history_df = load_history(selected_org_id)

    if history_df.empty:
        st.subheader("Tu postura de seguridad empieza acá")

        st.write(
            "Todavía no hay evaluaciones para este workspace. "
            "Ejecutá el primer Security Scan para generar el CyberScore."
        )

        st.info(
            "El CyberScore resume únicamente los controles que CyberAudits "
            "puede verificar. No representa una garantía de seguridad absoluta."
        )

    else:
        latest = history_df.iloc[0]
        latest_findings = safe_findings(latest["findings_json"])

        latest_meta = safe_meta(latest.get("scan_meta_json"))
        if not latest_meta:
            latest_meta = fallback_scan_meta(latest_findings)

        score = int(latest["risk_score"])
        status_label, status_description = score_status(score)

        actionable = [
            f for f in latest_findings
            if is_actionable(f)
        ]

        actionable_sorted = sorted(
            actionable,
            key=lambda f: {
                "CRÍTICO": 0,
                "MEDIO": 1,
                "BAJO": 2
            }.get(f.get("severity"), 9)
        )

        previous_score = None

        if len(history_df) > 1:
            previous_score = int(history_df.iloc[1]["risk_score"])

        delta = None
        if previous_score is not None:
            delta = score - previous_score

        st.caption(
            f"Workspace: {selected_org_name} · "
            f"Último objetivo: {latest['hostname']} · "
            f"Evaluado: {latest['timestamp']}"
        )

        left_score, right_metrics = st.columns([1.1, 2.2])

        with left_score:
            st.markdown(
                f"""
                <div class="score-shell">
                    <div class="muted">CyberScore</div>
                    <div style="margin-top:14px;">
                        <span class="score-number">{score}</span>
                        <span class="score-denom">/100</span>
                    </div>
                    <span class="score-label">{status_label}</span>
                    <p class="muted" style="margin-top:16px;">
                        {html.escape(status_description)}
                    </p>
                </div>
                """,
                unsafe_allow_html=True
            )

        with right_metrics:
            m1, m2, m3 = st.columns(3)

            m1.metric(
                "Cobertura",
                f"{latest_meta.get('coverage', 0)}%"
            )

            m2.metric(
                "Confianza",
                latest_meta.get("confidence", "N/D")
            )

            m3.metric(
                "Hallazgos a atender",
                len(actionable)
            )

            n1, n2, n3 = st.columns(3)

            n1.metric(
                "Críticos",
                sum(
                    1 for f in actionable
                    if f.get("severity") == "CRÍTICO"
                )
            )

            n2.metric(
                "Medios",
                sum(
                    1 for f in actionable
                    if f.get("severity") == "MEDIO"
                )
            )

            n3.metric(
                "Bajos",
                sum(
                    1 for f in actionable
                    if f.get("severity") == "BAJO"
                )
            )

            if delta is not None:
                st.caption(
                    f"Variación respecto al escaneo anterior: "
                    f"{delta:+d} puntos."
                )

        st.markdown("### Postura por categoría")

        cats = latest_meta.get(
            "category_scores",
            category_scores(latest_findings)
        )

        cat_cols = st.columns(4)

        ordered_categories = [
            "TLS & Certificado",
            "Seguridad Web",
            "Transporte",
            "Exposición"
        ]

        for col, label in zip(cat_cols, ordered_categories):
            with col:
                st.metric(
                    label,
                    f"{int(cats.get(label, 100))}/100"
                )

        st.markdown("### Qué corregir primero")

        if actionable_sorted:
            for finding in actionable_sorted[:3]:
                render_finding_card(finding)

                with st.expander(
                    f"Ver solución · {finding.get('vector', 'Hallazgo')}"
                ):
                    st.write(
                        f"**Qué detectamos:** "
                        f"{finding.get('desc', 'Sin descripción.')}"
                    )

                    st.write(
                        f"**Impacto:** "
                        f"{finding.get('impact', 'Sin detalle.')}"
                    )

                    st.info(
                        f"**Qué hacer:** "
                        f"{finding.get('fix', 'Sin recomendación.')}"
                    )

                    if finding.get("evidence"):
                        st.caption(
                            f"Evidencia: {finding.get('evidence')}"
                        )

                    if finding.get("snippet"):
                        st.code(finding.get("snippet"))
        else:
            st.success(
                "No hay hallazgos accionables en los controles "
                "que pudieron verificarse."
            )

        st.markdown("### Verificar correcciones")

        verify_col, verify_info = st.columns([1, 2.4])

        with verify_col:
            if st.button(
                "🔄 Verificar ahora",
                type="primary",
                use_container_width=True
            ):
                verify_url = f"https://{latest['hostname']}"

                with st.spinner(
                    "Reevaluando los controles verificados..."
                ):
                    (
                        new_findings,
                        new_stats,
                        new_hostname,
                        new_geo,
                        new_score
                    ) = scan_target(verify_url)

                    new_meta = build_scan_meta(
                        new_stats,
                        new_findings
                    )

                    new_count = count_actionable(
                        new_findings
                    )

                    save_scan_to_db(
                        new_hostname,
                        new_geo.get("ip", "N/A"),
                        new_score,
                        new_count,
                        "Security Posture Assessment",
                        selected_org_id,
                        new_findings,
                        new_meta
                    )

                change = new_score - score

                st.session_state.toast_msg = (
                    f"Verificación completada. "
                    f"CyberScore {score} → {new_score} "
                    f"({change:+d})."
                )

                st.session_state.toast_type = "success"
                st.rerun()

        with verify_info:
            st.caption(
                "CyberAudits vuelve a ejecutar los controles sobre el mismo "
                "objetivo y genera un nuevo registro. Así podemos comprobar "
                "si una remediación realmente mejoró la postura."
            )

        st.markdown("---")
        st.markdown("### CyberPass · vista privada")

        pass_left, pass_right = st.columns([1.35, 1])

        with pass_left:
            pass_org = (
                selected_org_name
                if selected_org_name != "General / Sin asignar"
                else latest["hostname"]
            )

            st.markdown(
                f"""
                <div class="pass-card">
                    <span class="pass-pill">PRIVATE PREVIEW</span>
                    <div style="margin-top:20px;font-size:13px;color:#b9c9e8;">
                        CYBERPASS BY CYBERAUDITS
                    </div>
                    <div style="font-size:22px;font-weight:800;margin-top:5px;">
                        {html.escape(str(pass_org))}
                    </div>
                    <div class="pass-score">{score}/100</div>
                    <div style="margin-top:8px;color:#d8e4fb;">
                        {status_label} · Cobertura {latest_meta.get('coverage', 0)}%
                        · Confianza {latest_meta.get('confidence', 'N/D')}
                    </div>
                    <div style="margin-top:24px;font-size:12px;color:#9fb4d9;">
                        Última verificación: {html.escape(str(latest['timestamp']))}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with pass_right:
            st.write(
                "**¿Qué será el CyberPass?** Una vista compartible que "
                "permita demostrar qué controles fueron verificados, sin "
                "exponer detalles técnicos sensibles."
            )

            st.write(
                "En esta fase permanece **privado**. La publicación con URL, "
                "verificación de propiedad y controles de privacidad se "
                "implementará después de validar este dashboard."
            )

            if st.button(
                "Preparar CyberPass",
                use_container_width=True
            ):
                st.session_state.cyberpass_ready = True

            if st.session_state.cyberpass_ready:
                st.success(
                    "Vista preparada. Todavía no se creó ningún enlace público."
                )

            st.caption(
                "CyberPass no será una certificación ni una garantía de "
                "seguridad; mostrará evidencia verificable y fecha de revisión."
            )


# ==========================================
# SECURITY SCAN
# ==========================================

with tab_scan:
    st.subheader("Security Scan")

    st.write(
        "Evaluá una URL pública mediante controles HTTP/HTTPS y TLS "
        "de bajo impacto."
    )

    st.caption(
        "Esta fase no realiza explotación, fuerza bruta ni pruebas intrusivas. "
        "Los análisis activos más profundos requerirán verificación de propiedad."
    )

    with st.form("security_scan_form"):
        target_url = st.text_input(
            "URL o dominio",
            value="https://",
            placeholder="https://empresa.com"
        )

        run_scan = st.form_submit_button(
            "🚀 Ejecutar análisis",
            type="primary",
            use_container_width=True
        )

    if run_scan:
        if target_url and target_url.strip() not in {"http://", "https://"}:
            with st.spinner(
                "Analizando TLS, HTTPS, headers y exposición observable..."
            ):
                (
                    findings,
                    stats,
                    hostname,
                    geo,
                    risk_score
                ) = scan_target(target_url)

                scan_meta = build_scan_meta(
                    stats,
                    findings
                )

                findings_count = count_actionable(
                    findings
                )

                scan_id = save_scan_to_db(
                    hostname,
                    geo.get("ip", "N/A"),
                    risk_score,
                    findings_count,
                    "Security Posture Assessment",
                    selected_org_id,
                    findings,
                    scan_meta
                )

                st.session_state.update(
                    scanned=True,
                    findings=findings,
                    hostname=hostname,
                    risk_score=risk_score,
                    scan_meta=scan_meta,
                    scan_id=scan_id
                )

            st.success(
                f"Análisis completado para {hostname}."
            )

        else:
            st.error("Ingresá una URL o dominio válido.")

    if st.session_state.scanned:
        scan_findings = st.session_state.get(
            "findings",
            []
        )

        scan_meta = st.session_state.get(
            "scan_meta",
            fallback_scan_meta(scan_findings)
        )

        s1, s2, s3, s4 = st.columns(4)

        s1.metric(
            "CyberScore",
            f"{st.session_state.risk_score}/100"
        )

        s2.metric(
            "Hallazgos a atender",
            count_actionable(scan_findings)
        )

        s3.metric(
            "Cobertura",
            f"{scan_meta.get('coverage', 0)}%"
        )

        s4.metric(
            "Confianza",
            scan_meta.get("confidence", "N/D")
        )

        st.markdown("#### Resultados")

        if scan_findings:
            for finding in scan_findings:
                severity = finding.get(
                    "severity",
                    "INFORMATIVO"
                )

                with st.expander(
                    f"{'ℹ️' if severity == 'INFORMATIVO' else '📌'} "
                    f"{finding.get('vector', 'Hallazgo')} "
                    f"[{severity}] · {finding_type(finding)}"
                ):
                    st.write(
                        f"**Descripción:** "
                        f"{finding.get('desc', 'N/A')}"
                    )

                    st.write(
                        f"**Impacto:** "
                        f"{finding.get('impact', 'N/A')}"
                    )

                    st.info(
                        f"**Remediación:** "
                        f"{finding.get('fix', 'N/A')}"
                    )

                    if finding.get("evidence"):
                        st.caption(
                            f"Evidencia: {finding.get('evidence')}"
                        )

                    if finding.get("snippet"):
                        st.code(finding.get("snippet"))
        else:
            st.success(
                "No se encontraron hallazgos en los controles evaluados."
            )


# ==========================================
# REPORTS
# ==========================================

with tab_reports:
    st.subheader("Reports")

    reports_history = load_history(selected_org_id)

    if reports_history.empty:
        st.info("Primero ejecutá un Security Scan.")

    else:
        reports_history = reports_history.copy()
        reports_history["Escaneo #"] = range(
            len(reports_history),
            0,
            -1
        )

        report_options = {
            (
                f"{row['timestamp']} · "
                f"{row['hostname']} · "
                f"CyberScore {row['risk_score']}/100"
            ): row
            for _, row in reports_history.iterrows()
        }

        selected_report_label = st.selectbox(
            "Seleccionar evaluación",
            list(report_options.keys()),
            key="reports_scan_select"
        )

        selected_scan_row = report_options[
            selected_report_label
        ]

        stored_findings = safe_findings(
            selected_scan_row["findings_json"]
        )

        st.caption(
            f"Objetivo: {selected_scan_row['hostname']} · "
            f"IP: {selected_scan_row['ip']} · "
            f"CyberScore: {selected_scan_row['risk_score']}/100"
        )

        stats_dummy = {
            "Críticas": sum(
                1 for x in stored_findings
                if x.get("severity") == "CRÍTICO"
            ),
            "Medias": sum(
                1 for x in stored_findings
                if x.get("severity") == "MEDIO"
            ),
            "Bajas": sum(
                1 for x in stored_findings
                if x.get("severity") == "BAJO"
            ),
            "Seguras": max(
                1,
                10 - count_actionable(stored_findings)
            )
        }

        chart_b64 = generate_chart(stats_dummy)

        col_rep1, col_rep2, col_rep3 = st.columns(3)

        with col_rep1:
            st.markdown("#### 📄 Informe Técnico")

            pdf_tech = (
                f"cyberaudits_technical_"
                f"{selected_scan_row['id']}.pdf"
            )

            generate_pdf(
                stored_findings,
                chart_b64,
                selected_scan_row["hostname"],
                selected_scan_row["risk_score"],
                agency_name,
                agency_tagline,
                "Informe Técnico Exhaustivo",
                recipient_name,
                report_subject,
                pdf_tech
            )

            docx_tech = generate_docx(
                selected_scan_row["hostname"],
                stored_findings,
                selected_scan_row["risk_score"],
                agency_name,
                agency_tagline,
                "Informe Técnico Exhaustivo",
                recipient_name,
                report_subject
            )

            with open(pdf_tech, "rb") as f:
                st.download_button(
                    "Descargar PDF técnico",
                    f,
                    file_name=pdf_tech,
                    mime="application/pdf",
                    key=f"pdf_t_{selected_scan_row['id']}",
                    use_container_width=True
                )

            st.download_button(
                "Descargar Word técnico",
                docx_tech,
                file_name=(
                    f"cyberaudits_technical_"
                    f"{selected_scan_row['hostname']}.docx"
                ),
                mime=(
                    "application/vnd.openxmlformats-officedocument."
                    "wordprocessingml.document"
                ),
                key=f"doc_t_{selected_scan_row['id']}",
                use_container_width=True
            )

        with col_rep2:
            st.markdown("#### 📈 Informe Ejecutivo")

            pdf_exec = (
                f"cyberaudits_executive_"
                f"{selected_scan_row['id']}.pdf"
            )

            generate_pdf(
                stored_findings,
                chart_b64,
                selected_scan_row["hostname"],
                selected_scan_row["risk_score"],
                agency_name,
                agency_tagline,
                "Informe Narrativo (Ejecutivo)",
                recipient_name,
                report_subject,
                pdf_exec
            )

            docx_exec = generate_docx(
                selected_scan_row["hostname"],
                stored_findings,
                selected_scan_row["risk_score"],
                agency_name,
                agency_tagline,
                "Informe Narrativo (Ejecutivo)",
                recipient_name,
                report_subject
            )

            with open(pdf_exec, "rb") as f:
                st.download_button(
                    "Descargar PDF ejecutivo",
                    f,
                    file_name=pdf_exec,
                    mime="application/pdf",
                    key=f"pdf_e_{selected_scan_row['id']}",
                    use_container_width=True
                )

            st.download_button(
                "Descargar Word ejecutivo",
                docx_exec,
                file_name=(
                    f"cyberaudits_executive_"
                    f"{selected_scan_row['hostname']}.docx"
                ),
                mime=(
                    "application/vnd.openxmlformats-officedocument."
                    "wordprocessingml.document"
                ),
                key=f"doc_e_{selected_scan_row['id']}",
                use_container_width=True
            )

        with col_rep3:
            st.markdown("#### 📋 Mapa de Controles")

            pdf_controls = (
                f"cyberaudits_controls_"
                f"{selected_scan_row['id']}.pdf"
            )

            control_report_type = (
                "Mapa Orientativo de Controles (ISO/NIST)"
            )

            generate_pdf(
                stored_findings,
                chart_b64,
                selected_scan_row["hostname"],
                selected_scan_row["risk_score"],
                agency_name,
                agency_tagline,
                control_report_type,
                recipient_name,
                report_subject,
                pdf_controls
            )

            docx_controls = generate_docx(
                selected_scan_row["hostname"],
                stored_findings,
                selected_scan_row["risk_score"],
                agency_name,
                agency_tagline,
                control_report_type,
                recipient_name,
                report_subject
            )

            with open(pdf_controls, "rb") as f:
                st.download_button(
                    "Descargar PDF de controles",
                    f,
                    file_name=pdf_controls,
                    mime="application/pdf",
                    key=f"pdf_c_{selected_scan_row['id']}",
                    use_container_width=True
                )

            st.download_button(
                "Descargar Word de controles",
                docx_controls,
                file_name=(
                    f"cyberaudits_controls_"
                    f"{selected_scan_row['hostname']}.docx"
                ),
                mime=(
                    "application/vnd.openxmlformats-officedocument."
                    "wordprocessingml.document"
                ),
                key=f"doc_c_{selected_scan_row['id']}",
                use_container_width=True
            )

        st.markdown(
            """
            <div class="small-note">
                <strong>Nota:</strong> El mapa ISO/NIST es orientativo.
                Un escaneo técnico aislado no certifica el cumplimiento
                integral de una norma.
            </div>
            """,
            unsafe_allow_html=True
        )

        st.markdown("### Hallazgos incluidos")

        if stored_findings:
            for finding in stored_findings:
                render_finding_card(finding)
        else:
            st.success(
                "No hay hallazgos registrados para esta evaluación."
            )


# ==========================================
# HISTORY
# ==========================================

with tab_history:
    st.subheader("History")

    history_tab_df = load_history(selected_org_id)

    if history_tab_df.empty:
        st.info("No hay evaluaciones registradas.")

    else:
        trend = history_tab_df.copy()
        trend["timestamp_dt"] = pd.to_datetime(
            trend["timestamp"],
            errors="coerce"
        )

        trend = trend.sort_values(
            by="timestamp_dt",
            ascending=True
        )

        if len(trend) >= 2:
            st.markdown("#### Evolución del CyberScore")

            chart_df = (
                trend[["timestamp_dt", "risk_score"]]
                .dropna()
                .set_index("timestamp_dt")
                .rename(columns={"risk_score": "CyberScore"})
            )

            st.line_chart(chart_df)

        display_history = history_tab_df[
            [
                "id",
                "timestamp",
                "hostname",
                "ip",
                "risk_score",
                "findings_count"
            ]
        ].copy()

        display_history.columns = [
            "ID",
            "Fecha",
            "Objetivo",
            "IP",
            "CyberScore",
            "Hallazgos"
        ]

        st.dataframe(
            display_history,
            hide_index=True,
            use_container_width=True
        )

        st.markdown("#### Eliminar una evaluación")

        delete_options = {
            (
                f"{row['timestamp']} · "
                f"{row['hostname']} · "
                f"CyberScore {row['risk_score']}/100"
            ): row["id"]
            for _, row in history_tab_df.iterrows()
        }

        scan_to_delete_label = st.selectbox(
            "Evaluación",
            list(delete_options.keys()),
            key="history_delete_select"
        )

        confirm_delete = st.checkbox(
            "Confirmo que deseo eliminar esta evaluación "
            "y sus tickets asociados.",
            key="history_delete_confirm"
        )

        if st.button(
            "Eliminar evaluación",
            type="secondary"
        ):
            if confirm_delete:
                delete_scan(
                    delete_options[scan_to_delete_label]
                )

                st.session_state.scanned = False
                st.success("Evaluación eliminada.")
                st.rerun()
            else:
                st.error(
                    "Marcá la confirmación antes de eliminar."
                )


# ==========================================
# REMEDIATION CENTER
# ==========================================

with tab_remediation:
    st.subheader("Remediation Center")

    remediation_history = load_history(
        selected_org_id
    )

    if remediation_history.empty:
        st.info(
            "Ejecutá un Security Scan para generar tareas "
            "de remediación."
        )

    else:
        ticket_scan_options = {
            (
                f"{row['timestamp']} · "
                f"{row['hostname']} · "
                f"CyberScore {row['risk_score']}/100"
            ): row["id"]
            for _, row in remediation_history.iterrows()
        }

        selected_ticket_label = st.selectbox(
            "Evaluación",
            list(ticket_scan_options.keys()),
            key="remediation_scan_select"
        )

        selected_scan_id = ticket_scan_options[
            selected_ticket_label
        ]

        ph = "%s" if "postgres" in st.secrets else "?"

        conn_cnt = get_db_connection()
        c_cnt = conn_cnt.cursor()

        counts = {}

        for state in [
            "Pendiente",
            "En Proceso",
            "Solucionado"
        ]:
            c_cnt.execute(
                f"""
                SELECT COUNT(*)
                FROM remediation_tasks
                WHERE scan_id = {ph}
                AND status = {ph}
                """,
                (selected_scan_id, state)
            )

            counts[state] = c_cnt.fetchone()[0]

        c_cnt.close()
        conn_cnt.close()

        r1, r2, r3 = st.columns(3)
        r1.metric("Pendientes", counts["Pendiente"])
        r2.metric("En proceso", counts["En Proceso"])
        r3.metric("Solucionados", counts["Solucionado"])

        t_pending, t_progress, t_done = st.tabs(
            [
                f"🟡 Pendientes ({counts['Pendiente']})",
                f"🔄 En proceso ({counts['En Proceso']})",
                f"✅ Solucionados ({counts['Solucionado']})"
            ]
        )

        def render_tickets(status_filter, closed=False):
            conn = get_db_connection()

            tasks_df = pd.read_sql_query(
                f"""
                SELECT
                    id,
                    hostname,
                    finding_vector,
                    severity,
                    status
                FROM remediation_tasks
                WHERE scan_id = {ph}
                AND status = {ph}
                ORDER BY id ASC
                """,
                conn,
                params=(
                    selected_scan_id,
                    status_filter
                )
            )

            conn.close()

            if tasks_df.empty:
                st.info(
                    f"No hay tareas en estado '{status_filter}'."
                )
                return

            for _, row in tasks_df.iterrows():
                ticket_id = row["id"]
                ticket_host = row["hostname"]
                ticket_vector = row["finding_vector"]
                ticket_severity = row["severity"]
                ticket_status = row["status"]

                sev_css = severity_class(
                    ticket_severity
                )

                st.markdown(
                    f"""
                    <div class="ticket-card {sev_css}">
                        <div style="font-weight:800;font-size:15px;">
                            {'✅' if closed else '📌'}
                            Ticket #{ticket_id} ·
                            {html.escape(str(ticket_vector))}
                        </div>
                        <div class="finding-meta" style="margin-top:5px;">
                            {html.escape(str(ticket_host))}
                            · {html.escape(str(ticket_severity))}
                            · {html.escape(str(ticket_status))}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

                if not closed:
                    with st.form(
                        key=f"ticket_form_{ticket_id}",
                        clear_on_submit=True
                    ):
                        c1, c2 = st.columns([1, 2])

                        with c1:
                            statuses = [
                                "Pendiente",
                                "En Proceso",
                                "Solucionado"
                            ]

                            new_status = st.selectbox(
                                "Estado",
                                statuses,
                                index=statuses.index(
                                    ticket_status
                                )
                            )

                        with c2:
                            new_note = st.text_input(
                                "Nota / evidencia",
                                placeholder=(
                                    "Ej.: cabecera aplicada y "
                                    "configuración desplegada"
                                )
                            )

                        if st.form_submit_button(
                            "Guardar actualización"
                        ):
                            conn_u = get_db_connection()
                            c_u = conn_u.cursor()

                            c_u.execute(
                                f"""
                                UPDATE remediation_tasks
                                SET status = {ph}
                                WHERE id = {ph}
                                """,
                                (
                                    new_status,
                                    ticket_id
                                )
                            )

                            c_u.execute(
                                f"""
                                INSERT INTO remediation_logs
                                (
                                    task_id,
                                    timestamp,
                                    status,
                                    notes
                                )
                                VALUES
                                ({ph}, {ph}, {ph}, {ph})
                                """,
                                (
                                    ticket_id,
                                    datetime.datetime.now().strftime(
                                        "%Y-%m-%d %H:%M:%S"
                                    ),
                                    new_status,
                                    new_note
                                )
                            )

                            if "postgres" not in st.secrets:
                                conn_u.commit()

                            c_u.close()
                            conn_u.close()

                            st.success(
                                "Actualización registrada."
                            )
                            st.rerun()

                with st.expander(
                    f"Bitácora · Ticket #{ticket_id}"
                ):
                    conn_l = get_db_connection()

                    logs_df = pd.read_sql_query(
                        f"""
                        SELECT timestamp, status, notes
                        FROM remediation_logs
                        WHERE task_id = {ph}
                        ORDER BY id DESC
                        """,
                        conn_l,
                        params=(ticket_id,)
                    )

                    conn_l.close()

                    if logs_df.empty:
                        st.caption(
                            "Todavía no hay movimientos registrados."
                        )
                    else:
                        for _, log in logs_df.iterrows():
                            st.markdown(
                                f"**{log['timestamp']}** · "
                                f"`{log['status']}`  \n"
                                f"{log['notes'] or 'Sin comentarios.'}"
                            )

        with t_pending:
            render_tickets("Pendiente")

        with t_progress:
            render_tickets("En Proceso")

        with t_done:
            render_tickets(
                "Solucionado",
                closed=True
            )

        st.markdown("---")

        st.info(
            "Cuando termines una remediación, volvé al Dashboard y usá "
            "“Verificar ahora”. CyberAudits generará una nueva evaluación "
            "para comprobar si el CyberScore mejoró."
        )

