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
import hmac
import secrets
import re
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

    .public-hero {
        background:
            radial-gradient(circle at 86% 15%, rgba(59,130,246,.28), transparent 24%),
            linear-gradient(120deg, #08111f 0%, #10244a 58%, #1f5de7 100%);
        border-radius: 24px;
        padding: 48px 46px;
        color: white;
        margin: 8px 0 28px 0;
        box-shadow: 0 20px 55px rgba(15, 23, 42, 0.18);
    }

    .public-hero h1 {
        font-size: 48px;
        line-height: 1.03;
        letter-spacing: -1.8px;
        max-width: 860px;
        margin: 8px 0 14px 0;
    }

    .public-hero p {
        max-width: 780px;
        color: #d8e5ff;
        font-size: 17px;
        line-height: 1.6;
        margin-bottom: 0;
    }

    .public-pill {
        display: inline-block;
        padding: 6px 10px;
        border-radius: 999px;
        background: rgba(255,255,255,.12);
        border: 1px solid rgba(255,255,255,.12);
        color: #e7efff;
        font-size: 12px;
        font-weight: 800;
        letter-spacing: .8px;
    }

    .public-card {
        background: white;
        border: 1px solid #e4e9f2;
        border-radius: 18px;
        padding: 22px;
        min-height: 165px;
        box-shadow: 0 8px 24px rgba(15,23,42,.05);
    }

    .public-card h3 {
        margin: 0 0 8px 0;
        font-size: 17px;
    }

    .public-card p {
        margin: 0;
        color: #6c778c;
        font-size: 13px;
        line-height: 1.55;
    }

    .public-score-card {
        background: white;
        border: 1px solid #e1e7f0;
        border-radius: 20px;
        padding: 24px;
        box-shadow: 0 12px 32px rgba(15,23,42,.06);
    }

    .public-score {
        font-size: 68px;
        line-height: .95;
        font-weight: 850;
        letter-spacing: -4px;
        color: #111827;
    }

    .public-footer {
        margin-top: 40px;
        padding: 20px 0;
        border-top: 1px solid #e4e9f2;
        color: #7a8496;
        font-size: 12px;
    }

    .trust-shell {
        max-width: 920px;
        margin: 30px auto 0 auto;
    }

    .trust-hero {
        background: linear-gradient(145deg, #0b1220, #17366f);
        color: #ffffff;
        border-radius: 24px;
        padding: 34px;
        box-shadow: 0 20px 50px rgba(15, 23, 42, 0.16);
    }

    .trust-domain {
        font-size: 27px;
        font-weight: 850;
        margin-top: 10px;
        letter-spacing: -0.4px;
    }

    .verified-pill {
        display: inline-block;
        border-radius: 999px;
        padding: 6px 10px;
        background: rgba(34,197,94,0.16);
        color: #bbf7d0;
        font-size: 12px;
        font-weight: 800;
    }

    .auth-shell {
        max-width: 520px;
        margin: 9vh auto 0 auto;
        background: #ffffff;
        border: 1px solid #e4e9f2;
        border-radius: 20px;
        padding: 28px;
        box-shadow: 0 18px 44px rgba(15, 23, 42, 0.08);
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
        background: #215ee9 !important;
        border-color: #215ee9 !important;
        color: #ffffff !important;
    }

    button[kind="primary"]:hover {
        background: #174fcf !important;
        border-color: #174fcf !important;
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

    .history-row {
        background: #ffffff;
        border: 1px solid #e4e9f2;
        border-radius: 14px;
        padding: 14px 16px;
        margin: 0;
        min-height: 78px;
        box-shadow: 0 3px 12px rgba(15, 23, 42, 0.035);
        display: flex;
        align-items: center;
    }

    .history-title {
        font-size: 14px;
        font-weight: 800;
        color: #182235;
        margin-bottom: 5px;
    }

    .history-meta {
        font-size: 12px;
        color: #718096;
        line-height: 1.45;
    }

    div[data-testid="stButton"] > button[kind="secondary"] {
        border-radius: 10px !important;
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
        c.execute("""CREATE TABLE IF NOT EXISTS domain_verifications (id SERIAL PRIMARY KEY, organization_id INTEGER, domain TEXT UNIQUE NOT NULL, token TEXT NOT NULL, status TEXT DEFAULT 'pending', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, verified_at TIMESTAMP)""")
        c.execute("""CREATE TABLE IF NOT EXISTS cyberpasses (id SERIAL PRIMARY KEY, organization_id INTEGER, domain TEXT UNIQUE NOT NULL, slug TEXT UNIQUE NOT NULL, is_public INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        c.execute("""CREATE TABLE IF NOT EXISTS public_leads (id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, domain TEXT, cyber_score INTEGER, source TEXT DEFAULT 'free_cybercheck', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
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
        c.execute("""CREATE TABLE IF NOT EXISTS domain_verifications (id INTEGER PRIMARY KEY AUTOINCREMENT, organization_id INTEGER, domain TEXT UNIQUE NOT NULL, token TEXT NOT NULL, status TEXT DEFAULT 'pending', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, verified_at TIMESTAMP)""")
        c.execute("""CREATE TABLE IF NOT EXISTS cyberpasses (id INTEGER PRIMARY KEY AUTOINCREMENT, organization_id INTEGER, domain TEXT UNIQUE NOT NULL, slug TEXT UNIQUE NOT NULL, is_public INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        c.execute("""CREATE TABLE IF NOT EXISTS public_leads (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, domain TEXT, cyber_score INTEGER, source TEXT DEFAULT 'free_cybercheck', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
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
def _secret_value(section, key, default=""):
    try:
        return str(st.secrets[section][key])
    except Exception:
        return default


def _db_ph():
    return "%s" if "postgres" in st.secrets else "?"


def _safe_domain_slug(domain):
    base = re.sub(r"[^a-z0-9]+", "-", domain.lower()).strip("-")
    return base[:70] or "company"



def _valid_email_address(value):
    value = (value or "").strip().lower()

    if len(value) > 254:
        return False

    pattern = r"^[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}$"
    return bool(re.match(pattern, value, flags=re.IGNORECASE))


def save_public_lead(email, domain="", cyber_score=None):
    email = (email or "").strip().lower()

    if not _valid_email_address(email):
        raise ValueError("Ingresá un email válido.")

    domain = (domain or "").strip().lower()

    conn = get_db_connection()
    c = conn.cursor()
    ph = _db_ph()

    try:
        if "postgres" in st.secrets:
            c.execute(
                f"""
                INSERT INTO public_leads
                (email, domain, cyber_score, source)
                VALUES ({ph}, {ph}, {ph}, 'free_cybercheck')
                ON CONFLICT (email)
                DO UPDATE SET
                    domain = EXCLUDED.domain,
                    cyber_score = EXCLUDED.cyber_score
                """,
                (email, domain, cyber_score)
            )
        else:
            c.execute(
                """
                INSERT INTO public_leads
                (email, domain, cyber_score, source)
                VALUES (?, ?, ?, 'free_cybercheck')
                ON CONFLICT(email)
                DO UPDATE SET
                    domain = excluded.domain,
                    cyber_score = excluded.cyber_score
                """,
                (email, domain, cyber_score)
            )
            conn.commit()
    finally:
        c.close()
        conn.close()


def load_public_leads():
    conn = get_db_connection()

    try:
        df = pd.read_sql_query(
            """
            SELECT id, email, domain, cyber_score, source, created_at
            FROM public_leads
            ORDER BY id DESC
            """,
            conn
        )
    finally:
        conn.close()

    return df


def get_domain_verification(domain):
    domain = _clean_domain(domain)
    conn = get_db_connection()
    c = conn.cursor()
    ph = _db_ph()
    c.execute(
        f"SELECT id, organization_id, domain, token, status, created_at, verified_at FROM domain_verifications WHERE domain = {ph}",
        (domain,)
    )
    row = c.fetchone()
    c.close()
    conn.close()

    if not row:
        return None

    return {
        "id": row[0],
        "organization_id": row[1],
        "domain": row[2],
        "token": row[3],
        "status": row[4],
        "created_at": row[5],
        "verified_at": row[6]
    }


def get_or_create_domain_verification(domain, organization_id=None):
    domain = _clean_domain(domain)
    existing = get_domain_verification(domain)

    if existing:
        # A verified domain remains verified. For a pending record we keep the
        # same token so the user does not have to keep changing DNS.
        return existing

    token = "CA-" + secrets.token_hex(8).upper()
    conn = get_db_connection()
    c = conn.cursor()
    ph = _db_ph()

    c.execute(
        f"INSERT INTO domain_verifications (organization_id, domain, token, status) VALUES ({ph}, {ph}, {ph}, 'pending')",
        (organization_id, domain, token)
    )

    if "postgres" not in st.secrets:
        conn.commit()

    c.close()
    conn.close()
    return get_domain_verification(domain)


def verify_domain_ownership(domain):
    domain = _clean_domain(domain)
    record = get_domain_verification(domain)

    if not record:
        return False, [], "Primero generá el código de verificación."

    lookup_name = f"_cyberaudits.{domain}"

    try:
        txt_values, _ = _dns_txt_records(lookup_name)
    except Exception as e:
        return False, [], f"No se pudo consultar el DNS: {e}"

    expected = f"cyberaudits-verification={record['token']}"
    normalized = [value.strip() for value in txt_values]
    matched = any(
        hmac.compare_digest(value, expected)
        for value in normalized
    )

    if not matched:
        return False, normalized, (
            "El registro TXT todavía no coincide. Los cambios DNS pueden "
            "tardar unos minutos en propagarse."
        )

    conn = get_db_connection()
    c = conn.cursor()
    ph = _db_ph()
    verified_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    c.execute(
        f"UPDATE domain_verifications SET status = 'verified', verified_at = {ph} WHERE domain = {ph}",
        (verified_at, domain)
    )

    if "postgres" not in st.secrets:
        conn.commit()

    c.close()
    conn.close()
    return True, normalized, "Dominio verificado correctamente."


def get_cyberpass_by_domain(domain):
    domain = _clean_domain(domain)
    conn = get_db_connection()
    c = conn.cursor()
    ph = _db_ph()
    c.execute(
        f"SELECT id, organization_id, domain, slug, is_public, created_at, updated_at FROM cyberpasses WHERE domain = {ph}",
        (domain,)
    )
    row = c.fetchone()
    c.close()
    conn.close()

    if not row:
        return None

    return {
        "id": row[0],
        "organization_id": row[1],
        "domain": row[2],
        "slug": row[3],
        "is_public": bool(row[4]),
        "created_at": row[5],
        "updated_at": row[6]
    }


def get_cyberpass_by_slug(slug):
    slug = (slug or "").strip()
    if not slug:
        return None

    conn = get_db_connection()
    c = conn.cursor()
    ph = _db_ph()
    c.execute(
        f"SELECT id, organization_id, domain, slug, is_public, created_at, updated_at FROM cyberpasses WHERE slug = {ph}",
        (slug,)
    )
    row = c.fetchone()
    c.close()
    conn.close()

    if not row:
        return None

    return {
        "id": row[0],
        "organization_id": row[1],
        "domain": row[2],
        "slug": row[3],
        "is_public": bool(row[4]),
        "created_at": row[5],
        "updated_at": row[6]
    }


def ensure_cyberpass(domain, organization_id=None):
    domain = _clean_domain(domain)
    existing = get_cyberpass_by_domain(domain)

    if existing:
        return existing

    slug = f"{_safe_domain_slug(domain)}-{secrets.token_hex(3)}"
    conn = get_db_connection()
    c = conn.cursor()
    ph = _db_ph()

    c.execute(
        f"INSERT INTO cyberpasses (organization_id, domain, slug, is_public, updated_at) VALUES ({ph}, {ph}, {ph}, 0, CURRENT_TIMESTAMP)",
        (organization_id, domain, slug)
    )

    if "postgres" not in st.secrets:
        conn.commit()

    c.close()
    conn.close()
    return get_cyberpass_by_domain(domain)


def set_cyberpass_visibility(domain, make_public):
    domain = _clean_domain(domain)
    verification = get_domain_verification(domain)

    if make_public and (
        not verification
        or verification.get("status") != "verified"
    ):
        raise ValueError("El dominio debe estar verificado antes de publicar el CyberPass.")

    pass_record = ensure_cyberpass(domain)
    conn = get_db_connection()
    c = conn.cursor()
    ph = _db_ph()
    value = 1 if make_public else 0

    c.execute(
        f"UPDATE cyberpasses SET is_public = {ph}, updated_at = CURRENT_TIMESTAMP WHERE domain = {ph}",
        (value, domain)
    )

    if "postgres" not in st.secrets:
        conn.commit()

    c.close()
    conn.close()
    return get_cyberpass_by_domain(domain)


def _hostname_matches_domain(hostname, domain):
    try:
        hostname = _clean_domain(hostname)
        domain = _clean_domain(domain)
    except Exception:
        return False

    return hostname == domain or hostname.endswith("." + domain)


def get_latest_scan_for_verified_domain(domain, organization_id=None):
    domain = _clean_domain(domain)
    conn = get_db_connection()
    ph = _db_ph()

    columns = """
        id, timestamp, hostname, ip, risk_score, findings_count,
        report_type, organization_id, findings_json, scan_meta_json
    """

    params = []
    clauses = []

    if organization_id is not None:
        clauses.append(f"organization_id = {ph}")
        params.append(organization_id)

    clauses.append(
        f"(hostname = {ph} OR hostname LIKE {ph})"
    )
    params.extend([domain, f"%.{domain}"])

    where_sql = " AND ".join(clauses)

    df = pd.read_sql_query(
        f"SELECT {columns} FROM history WHERE {where_sql} ORDER BY id DESC LIMIT 1",
        conn,
        params=tuple(params)
    )
    conn.close()

    if df.empty:
        return None

    return df.iloc[0]


def get_public_base_url():
    configured = _secret_value("app", "public_url", "").strip().rstrip("/")
    if configured:
        return configured

    try:
        current_url = str(st.context.url).strip().rstrip("/")
        if current_url.startswith("http://") or current_url.startswith("https://"):
            return current_url.split("?")[0].rstrip("/")
    except Exception:
        pass

    try:
        headers = st.context.headers
        host = headers.get("Host")
        proto = (headers.get("X-Forwarded-Proto") or "https").split(",")[0].strip()
        if host:
            return f"{proto}://{host}"
    except Exception:
        pass

    return ""


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



def _clean_domain(raw_domain):
    raw_domain = (raw_domain or "").strip().lower()

    if not raw_domain:
        return ""

    if "://" in raw_domain:
        parsed = urlparse(raw_domain)
        raw_domain = parsed.hostname or ""

    raw_domain = raw_domain.strip().strip(".")

    if not raw_domain:
        raise ValueError("Dominio vacío.")

    try:
        ascii_domain = raw_domain.encode("idna").decode("ascii")
    except Exception:
        raise ValueError("El dominio contiene caracteres no válidos.")

    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-.")

    if any(ch not in allowed for ch in ascii_domain):
        raise ValueError("El dominio contiene caracteres no permitidos.")

    labels = ascii_domain.split(".")

    if len(labels) < 2:
        raise ValueError("Se requiere un dominio público válido.")

    for label in labels:
        if (
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
        ):
            raise ValueError("El dominio contiene una etiqueta no válida.")

    return ascii_domain


def _dns_query(name, record_type, timeout=6):
    """
    Consulta DNS mediante DNS-over-HTTPS.
    Devuelve un dict normalizado y evita depender de binarios o paquetes extra.
    """
    name = _clean_domain(name)

    response = requests.get(
        "https://dns.google/resolve",
        params={
            "name": name,
            "type": record_type,
            "do": "1",
            "cd": "0"
        },
        headers={
            "Accept": "application/dns-json",
            "User-Agent": "CyberAudits/2.4 DNS Security Check"
        },
        timeout=timeout
    )

    response.raise_for_status()
    data = response.json()

    return {
        "status": data.get("Status"),
        "ad": bool(data.get("AD", False)),
        "answers": data.get("Answer", []) or [],
        "authority": data.get("Authority", []) or [],
        "raw": data
    }


def _dns_answer_data(result):
    values = []

    for answer in result.get("answers", []):
        value = str(answer.get("data", "")).strip()

        if value:
            values.append(value)

    return values


def _normalize_txt_value(value):
    """
    DNS JSON puede devolver TXT como:
    "parte 1" "parte 2"
    Lo normalizamos para facilitar análisis SPF/DMARC.
    """
    value = (value or "").strip()

    if not value:
        return ""

    pieces = []
    current = ""
    in_quotes = False
    escape = False

    for ch in value:
        if escape:
            current += ch
            escape = False
            continue

        if ch == "\\":
            escape = True
            continue

        if ch == '"':
            if in_quotes:
                pieces.append(current)
                current = ""
                in_quotes = False
            else:
                in_quotes = True
            continue

        if in_quotes:
            current += ch
        else:
            current += ch

    if current:
        pieces.append(current)

    return "".join(pieces).strip()


def _dns_txt_records(name):
    result = _dns_query(name, "TXT")

    return (
        [_normalize_txt_value(x) for x in _dns_answer_data(result)],
        result
    )


def _dns_mx_records(name):
    result = _dns_query(name, "MX")
    values = _dns_answer_data(result)

    mx = []

    for value in values:
        parts = value.split(maxsplit=1)

        if len(parts) == 2:
            try:
                priority = int(parts[0])
            except ValueError:
                priority = 0

            host = parts[1].rstrip(".")
            mx.append((priority, host))
        elif value:
            mx.append((0, value.rstrip(".")))

    return mx, result


def _find_effective_caa(name):
    """
    CAA hereda hacia nombres padre.
    Buscamos desde el hostname hacia arriba para no marcar ausencia
    cuando existe política CAA efectiva en un ancestro.
    """
    domain = _clean_domain(name)
    labels = domain.split(".")

    # Nunca consultamos solamente el TLD.
    candidates = [
        ".".join(labels[i:])
        for i in range(0, max(1, len(labels) - 1))
        if len(labels[i:]) >= 2
    ]

    for candidate in candidates:
        try:
            result = _dns_query(candidate, "CAA")
            values = _dns_answer_data(result)

            if values:
                return {
                    "found": True,
                    "at": candidate,
                    "records": values,
                    "ad": result.get("ad", False)
                }
        except Exception:
            continue

    return {
        "found": False,
        "at": None,
        "records": [],
        "ad": False
    }


def scan_target(url, email_domain=""):
    findings = []

    stats = {
        "Críticas": 0,
        "Medias": 0,
        "Bajas": 0,
        "Seguras": 0
    }

    passed_by_category = {}
    evaluated_by_category = {}
    inconclusive_by_category = {}

    def mark_evaluated(category):
        evaluated_by_category[category] = (
            evaluated_by_category.get(category, 0) + 1
        )

    def mark_safe(category):
        stats["Seguras"] += 1
        mark_evaluated(category)
        passed_by_category[category] = (
            passed_by_category.get(category, 0) + 1
        )

    def add_inconclusive(
        vector,
        desc,
        category,
        evidence="",
        fix="Reintentar la evaluación más tarde."
    ):
        inconclusive_by_category[category] = (
            inconclusive_by_category.get(category, 0) + 1
        )

        findings.append({
            "vector": vector,
            "severity": "INFORMATIVO",
            "desc": desc,
            "impact": (
                "Este resultado no implica por sí mismo una vulnerabilidad. "
                "El control no pudo verificarse de forma concluyente."
            ),
            "fix": fix,
            "compliance": "Control de calidad CyberAudits",
            "snippet": "",
            "category": category,
            "evidence": evidence,
            "verified": False,
            "is_vulnerability": False
        })

    def add_finding(
        vector,
        severity,
        desc,
        impact,
        fix,
        compliance,
        snippet="",
        category="Web",
        evidence="",
        is_vulnerability=True
    ):
        severity = severity.upper()

        if severity == "INFORMATIVO":
            findings.append({
                "vector": vector,
                "severity": "INFORMATIVO",
                "desc": desc,
                "impact": impact,
                "fix": fix,
                "compliance": compliance,
                "snippet": snippet,
                "category": category,
                "evidence": evidence,
                "verified": True,
                "is_vulnerability": False
            })
            mark_evaluated(category)
            return

        if severity == "CRÍTICO":
            stats["Críticas"] += 1
        elif severity == "MEDIO":
            stats["Medias"] += 1
        else:
            stats["Bajas"] += 1

        mark_evaluated(category)

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
            "verified": True,
            "is_vulnerability": is_vulnerability
        })

    # =====================================
    # TARGET VALIDATION
    # =====================================

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

        scan_details = {
            "passed_by_category": passed_by_category,
            "evaluated_by_category": evaluated_by_category,
            "inconclusive_by_category": inconclusive_by_category,
            "email_domain": "",
            "dnssec_ad": None
        }

        return findings, stats, hostname, geo, 0, scan_details

    geo = get_geolocation(hostname)

    # =====================================
    # TLS / CERTIFICATE
    # =====================================

    try:
        tls = _tls_certificate_info(hostname)
        days_left = tls["days_left"]

        if days_left is None:
            add_inconclusive(
                "Expiración del certificado no concluyente",
                "El servidor respondió por TLS, pero no fue posible determinar "
                "la fecha de expiración.",
                "TLS",
                evidence=f"TLS={tls['tls_version']} | Emisor={tls['issuer']}",
                fix="Revisar la cadena y configuración TLS."
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
            mark_safe("TLS")

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
            mark_safe("TLS")

    except Exception as e:
        add_inconclusive(
            "Evaluación TLS no concluyente",
            f"No se pudo completar correctamente la conexión TLS: {e}",
            "TLS",
            evidence=str(e),
            fix=(
                "Revisar certificado, cadena de confianza, disponibilidad "
                "del puerto 443 y configuración TLS."
            )
        )

    # =====================================
    # HTTP / SECURITY HEADERS
    # =====================================

    try:
        response, final_url = _safe_get(normalized_url)
        headers = response.headers

        if final_url.lower().startswith("https://"):
            mark_safe("Transporte")
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
            mark_safe("Headers")
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
            mark_safe("Headers")
        else:
            add_finding(
                "Content Security Policy (CSP) ausente",
                "MEDIO",
                "No se detectó una política CSP.",
                "Aumenta la exposición ante determinados ataques de inyección "
                "de contenido y XSS.",
                "Implementar una CSP adaptada al sitio.",
                "OWASP Secure Headers",
                "Content-Security-Policy: default-src 'self'",
                "Headers"
            )

        xfo = headers.get("X-Frame-Options", "")

        if xfo or "frame-ancestors" in csp.lower():
            mark_safe("Headers")
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
            mark_safe("Headers")
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
            mark_safe("Headers")
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
            mark_safe("Headers")
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
                mark_safe("Cookies")

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
                mark_safe("Cookies")

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
            mark_safe("Exposición")

    except Exception as e:
        add_inconclusive(
            "Evaluación HTTP/HTTPS no concluyente",
            f"No se pudo completar esta parte de la evaluación: {e}",
            "Headers",
            evidence=str(e),
            fix=(
                "Reintentar el análisis. Si persiste, revisar redirecciones, "
                "protecciones anti-bot o disponibilidad del sitio."
            )
        )

    # =====================================
    # HTTP -> HTTPS REDIRECT
    # =====================================

    try:
        http_url = f"http://{hostname}/"
        _, http_final = _safe_get(http_url)

        if http_final.lower().startswith("https://"):
            mark_safe("Transporte")
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
        # Puerto HTTP cerrado / no disponible no es por sí solo una vulnerabilidad.
        mark_safe("Transporte")

    # =====================================
    # DNS SECURITY OF THE WEB HOST
    # =====================================

    dnssec_ad = None

    try:
        a_result = _dns_query(hostname, "A")
        dnssec_ad = a_result.get("ad", False)

        # DNSSEC is useful, but absence is treated as information rather than
        # a vulnerability because deployment requirements vary.
        if dnssec_ad:
            mark_safe("DNS")
        else:
            add_finding(
                "DNSSEC no validado para el hostname",
                "INFORMATIVO",
                (
                    "La consulta DNS no llegó con la bandera AD de validación "
                    "DNSSEC activa."
                ),
                (
                    "DNSSEC puede ayudar a proteger la autenticidad de las "
                    "respuestas DNS, pero su ausencia no demuestra una "
                    "vulnerabilidad explotable por sí sola."
                ),
                "Evaluar DNSSEC con el proveedor DNS si aplica al entorno.",
                "Buenas prácticas DNS",
                category="DNS",
                evidence=f"AD={dnssec_ad}",
                is_vulnerability=False
            )

    except Exception as e:
        add_inconclusive(
            "Validación DNSSEC no concluyente",
            f"No se pudo consultar la señal DNSSEC: {e}",
            "DNS",
            evidence=str(e)
        )

    try:
        caa = _find_effective_caa(hostname)

        if caa.get("found"):
            mark_safe("DNS")
        else:
            add_finding(
                "Política CAA no detectada",
                "BAJO",
                (
                    "No se encontró una política CAA efectiva para limitar "
                    "qué autoridades certificadoras pueden emitir certificados."
                ),
                (
                    "CAA reduce el riesgo operativo de emisión no deseada "
                    "de certificados, aunque su ausencia no implica por sí sola "
                    "que un certificado pueda emitirse fraudulentamente."
                ),
                "Evaluar la publicación de registros CAA apropiados.",
                "RFC 8659 / buenas prácticas PKI",
                category="DNS"
            )

    except Exception as e:
        add_inconclusive(
            "Evaluación CAA no concluyente",
            f"No se pudo evaluar CAA: {e}",
            "DNS",
            evidence=str(e)
        )

    # =====================================
    # EMAIL DOMAIN SECURITY (OPTIONAL)
    # =====================================

    normalized_email_domain = ""

    if email_domain:
        try:
            normalized_email_domain = _clean_domain(email_domain)

        except Exception as e:
            add_inconclusive(
                "Dominio de correo no válido",
                f"No se pudo evaluar el dominio de correo ingresado: {e}",
                "Email",
                evidence=str(email_domain),
                fix="Ingresar solamente el dominio, por ejemplo: empresa.com"
            )

    if normalized_email_domain:
        # MX
        mx_records = []

        try:
            mx_records, mx_result = _dns_mx_records(
                normalized_email_domain
            )

            if mx_records:
                mark_safe("Email")
            else:
                add_finding(
                    "Registros MX no detectados",
                    "INFORMATIVO",
                    (
                        f"No se encontraron registros MX para "
                        f"{normalized_email_domain}."
                    ),
                    (
                        "El dominio puede no recibir correo o utilizar una "
                        "arquitectura no detectable mediante MX estándar."
                    ),
                    "Confirmar si el dominio debe recibir correo electrónico.",
                    "Buenas prácticas de correo",
                    category="Email",
                    evidence="MX=none",
                    is_vulnerability=False
                )

        except Exception as e:
            add_inconclusive(
                "Consulta MX no concluyente",
                f"No se pudieron consultar los registros MX: {e}",
                "Email",
                evidence=str(e)
            )

        # SPF
        try:
            root_txt, _ = _dns_txt_records(
                normalized_email_domain
            )

            spf_records = [
                value
                for value in root_txt
                if value.lower().startswith("v=spf1")
            ]

            if len(spf_records) == 0:
                add_finding(
                    "SPF no detectado",
                    "MEDIO",
                    (
                        f"No se encontró un registro SPF en "
                        f"{normalized_email_domain}."
                    ),
                    (
                        "La ausencia de SPF dificulta que los receptores "
                        "distingan servidores autorizados para enviar correo "
                        "en nombre del dominio."
                    ),
                    (
                        "Publicar una política SPF acorde a los proveedores "
                        "reales de correo. No copiar una política genérica."
                    ),
                    "RFC 7208 / Email Authentication",
                    category="Email",
                    evidence="SPF=none"
                )

            elif len(spf_records) > 1:
                add_finding(
                    "Múltiples registros SPF detectados",
                    "MEDIO",
                    "Se detectó más de un registro SPF en el dominio.",
                    (
                        "SPF espera una única política; múltiples registros "
                        "pueden producir errores de validación."
                    ),
                    "Consolidar la política en un único registro SPF válido.",
                    "RFC 7208",
                    category="Email",
                    evidence=" | ".join(spf_records[:3])
                )

            else:
                spf = spf_records[0]
                spf_lower = spf.lower()

                if "+all" in spf_lower:
                    add_finding(
                        "SPF excesivamente permisivo (+all)",
                        "CRÍTICO",
                        f"Se detectó la política: {spf}",
                        (
                            "La directiva +all autoriza prácticamente a cualquier "
                            "origen a superar SPF para el dominio."
                        ),
                        (
                            "Revisar los remitentes legítimos y sustituir +all "
                            "por una política restrictiva apropiada."
                        ),
                        "RFC 7208",
                        category="Email",
                        evidence=spf
                    )

                elif "?all" in spf_lower:
                    add_finding(
                        "SPF con política neutral (?all)",
                        "MEDIO",
                        f"Se detectó la política: {spf}",
                        (
                            "La política neutral aporta poca señal de autenticación "
                            "a los receptores."
                        ),
                        "Revisar SPF y aplicar una política final acorde al entorno.",
                        "RFC 7208",
                        category="Email",
                        evidence=spf
                    )

                else:
                    mark_safe("Email")

        except Exception as e:
            add_inconclusive(
                "Evaluación SPF no concluyente",
                f"No se pudo evaluar SPF: {e}",
                "Email",
                evidence=str(e)
            )

        # DMARC
        try:
            dmarc_name = f"_dmarc.{normalized_email_domain}"
            dmarc_txt, _ = _dns_txt_records(dmarc_name)

            dmarc_records = [
                value
                for value in dmarc_txt
                if value.lower().startswith("v=dmarc1")
            ]

            if not dmarc_records:
                add_finding(
                    "DMARC no detectado",
                    "MEDIO",
                    (
                        f"No se encontró una política DMARC en "
                        f"{dmarc_name}."
                    ),
                    (
                        "Sin DMARC, el dominio tiene menos capacidad para "
                        "indicar a los receptores cómo tratar mensajes que "
                        "fallen autenticación y alineación."
                    ),
                    (
                        "Implementar DMARC de forma gradual, comenzando con "
                        "monitorización y avanzando a enforcement cuando la "
                        "legitimidad del correo esté validada."
                    ),
                    "RFC 7489 / Email Authentication",
                    category="Email",
                    evidence="DMARC=none"
                )

            else:
                dmarc = dmarc_records[0]
                dmarc_lower = dmarc.lower().replace(" ", "")

                if "p=reject" in dmarc_lower:
                    mark_safe("Email")
                elif "p=quarantine" in dmarc_lower:
                    mark_safe("Email")
                elif "p=none" in dmarc_lower:
                    add_finding(
                        "DMARC en modo monitorización (p=none)",
                        "BAJO",
                        f"Se detectó la política: {dmarc}",
                        (
                            "La política recopila señal pero no solicita cuarentena "
                            "ni rechazo de mensajes que fallen DMARC."
                        ),
                        (
                            "Cuando SPF/DKIM y los flujos legítimos estén validados, "
                            "evaluar una transición gradual a quarantine o reject."
                        ),
                        "RFC 7489",
                        category="Email",
                        evidence=dmarc
                    )
                else:
                    add_inconclusive(
                        "Política DMARC no interpretada",
                        "Se encontró DMARC, pero CyberAudits no pudo identificar "
                        "una política p=none/quarantine/reject.",
                        "Email",
                        evidence=dmarc,
                        fix="Revisar la sintaxis del registro DMARC."
                    )

        except Exception as e:
            add_inconclusive(
                "Evaluación DMARC no concluyente",
                f"No se pudo evaluar DMARC: {e}",
                "Email",
                evidence=str(e)
            )

        # CAA at email/corporate domain
        try:
            email_caa = _find_effective_caa(
                normalized_email_domain
            )

            if email_caa.get("found"):
                mark_safe("DNS")
            else:
                add_finding(
                    "CAA no detectado para el dominio corporativo",
                    "BAJO",
                    (
                        "No se detectó una política CAA efectiva en el "
                        "dominio corporativo."
                    ),
                    (
                        "CAA permite limitar qué autoridades certificadoras "
                        "pueden emitir certificados para el dominio."
                    ),
                    "Evaluar registros CAA apropiados para el dominio.",
                    "RFC 8659",
                    category="DNS"
                )

        except Exception as e:
            add_inconclusive(
                "CAA corporativo no concluyente",
                f"No se pudo evaluar CAA del dominio corporativo: {e}",
                "DNS",
                evidence=str(e)
            )

        # MTA-STS - informational/hardening signal only
        if mx_records:
            try:
                mta_txt, _ = _dns_txt_records(
                    f"_mta-sts.{normalized_email_domain}"
                )

                has_mta_sts = any(
                    value.lower().startswith("v=stsv1")
                    for value in mta_txt
                )

                if has_mta_sts:
                    mark_safe("Email")
                else:
                    add_finding(
                        "MTA-STS no detectado",
                        "INFORMATIVO",
                        (
                            "No se detectó el registro DNS de MTA-STS "
                            "para el dominio de correo."
                        ),
                        (
                            "MTA-STS puede reforzar el transporte TLS entre "
                            "servidores de correo compatibles."
                        ),
                        (
                            "Evaluar MTA-STS si el proveedor de correo y la "
                            "operación del dominio lo permiten."
                        ),
                        "RFC 8461",
                        category="Email",
                        is_vulnerability=False
                    )

            except Exception as e:
                add_inconclusive(
                    "Evaluación MTA-STS no concluyente",
                    f"No se pudo evaluar MTA-STS: {e}",
                    "Email",
                    evidence=str(e)
                )

            # TLS Reporting - informational
            try:
                tlsrpt_txt, _ = _dns_txt_records(
                    f"_smtp._tls.{normalized_email_domain}"
                )

                has_tlsrpt = any(
                    value.lower().startswith("v=tlsrptv1")
                    for value in tlsrpt_txt
                )

                if has_tlsrpt:
                    mark_safe("Email")
                else:
                    add_finding(
                        "SMTP TLS Reporting no detectado",
                        "INFORMATIVO",
                        (
                            "No se detectó una política TLS-RPT para "
                            "el dominio de correo."
                        ),
                        (
                            "TLS-RPT aporta visibilidad sobre fallos de "
                            "entrega relacionados con TLS."
                        ),
                        "Evaluar TLS-RPT junto con la estrategia MTA-STS.",
                        "RFC 8460",
                        category="Email",
                        is_vulnerability=False
                    )

            except Exception as e:
                add_inconclusive(
                    "Evaluación TLS-RPT no concluyente",
                    f"No se pudo evaluar TLS-RPT: {e}",
                    "Email",
                    evidence=str(e)
                )

    # =====================================
    # CYBERSCORE V2.4
    # =====================================

    penalty = (
        stats["Críticas"] * 25
        + stats["Medias"] * 8
        + stats["Bajas"] * 3
    )

    risk_score = max(
        0,
        100 - min(100, penalty)
    )

    scan_details = {
        "passed_by_category": passed_by_category,
        "evaluated_by_category": evaluated_by_category,
        "inconclusive_by_category": inconclusive_by_category,
        "email_domain": normalized_email_domain,
        "dnssec_ad": dnssec_ad
    }

    return (
        findings,
        stats,
        hostname,
        geo,
        risk_score,
        scan_details
    )


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
        doc.add_heading("Análisis de Hallazgos y Consecuencias", level=3)
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
            <h2 class="title">2. Evidencia de Hallazgos y Bloques de Configuración</h2>
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
            <h2 class="title">Análisis de Hallazgos y Consecuencias</h2>
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

    if category == "DNS":
        if severity == "INFORMATIVO":
            return "Señal DNS"
        return "Configuración DNS"

    if category == "Email":
        if severity == "INFORMATIVO":
            return "Señal de correo"
        return "Autenticación de correo"

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


def category_scores(findings, scan_details=None):
    groups = {
        "TLS & Certificado": {"TLS"},
        "Seguridad Web": {"Headers", "Cookies"},
        "Transporte": {"Transporte"},
        "Exposición": {"Exposición"},
        "DNS Security": {"DNS"},
        "Email Security": {"Email"}
    }

    evaluated = (
        (scan_details or {}).get("evaluated_by_category", {})
    )

    result = {}

    for label, categories in groups.items():
        evaluated_count = sum(
            int(evaluated.get(category, 0) or 0)
            for category in categories
        )

        if scan_details is not None and evaluated_count <= 0:
            result[label] = None
            continue

        penalty = sum(
            finding_weight(f)
            for f in findings
            if (
                f.get("category") in categories
                and is_actionable(f)
            )
        )

        result[label] = max(
            0,
            100 - min(100, penalty)
        )

    return result


def build_scan_meta(stats, findings, scan_details=None):
    scan_details = scan_details or {}

    inconclusive = sum(
        int(v or 0)
        for v in scan_details.get(
            "inconclusive_by_category",
            {}
        ).values()
    )

    # Backward-compatible fallback for older scan engine behavior.
    if not scan_details:
        inconclusive = sum(
            1
            for f in findings
            if (
                f.get("severity") == "INFORMATIVO"
                and not f.get("verified", True)
            )
        )

    verified_checks = int(sum(stats.values()))
    total_checks = verified_checks + inconclusive

    if total_checks <= 0:
        coverage = 0
    else:
        coverage = round(
            (verified_checks / total_checks) * 100
        )

    if coverage >= 90 and verified_checks >= 8:
        confidence = "ALTA"
    elif coverage >= 70 and verified_checks >= 4:
        confidence = "MEDIA"
    else:
        confidence = "BAJA"

    return {
        "verified_checks": verified_checks,
        "total_checks": total_checks,
        "coverage": coverage,
        "confidence": confidence,
        "category_scores": category_scores(
            findings,
            scan_details
        ),
        "email_domain": scan_details.get(
            "email_domain",
            ""
        ),
        "evaluated_by_category": scan_details.get(
            "evaluated_by_category",
            {}
        ),
        "inconclusive_by_category": scan_details.get(
            "inconclusive_by_category",
            {}
        ),
        "dnssec_ad": scan_details.get(
            "dnssec_ad"
        )
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
        "category_scores": category_scores(findings, None)
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


def _cyberpass_public_url(slug):
    base = get_public_base_url()
    if base:
        return f"{base}/?pass={slug}"
    return f"/?pass={slug}"


def render_public_cyberpass(slug):
    pass_record = get_cyberpass_by_slug(slug)

    if not pass_record or not pass_record.get("is_public"):
        st.error("Este CyberPass no existe o actualmente es privado.")
        st.caption("El propietario puede haberlo despublicado.")
        st.stop()

    domain = pass_record["domain"]
    verification = get_domain_verification(domain)

    if not verification or verification.get("status") != "verified":
        st.error("Este CyberPass no tiene una verificación de dominio válida.")
        st.stop()

    latest = get_latest_scan_for_verified_domain(
        domain,
        pass_record.get("organization_id")
    )

    if latest is None:
        st.error("Este CyberPass todavía no tiene una evaluación compatible publicada.")
        st.stop()

    findings = safe_findings(latest["findings_json"])
    meta = safe_meta(latest.get("scan_meta_json"))

    if not meta:
        meta = fallback_scan_meta(findings)

    score = int(latest["risk_score"] or 0)
    status_label, status_description = score_status(score)
    categories = meta.get("category_scores", {})

    # Public mode must not expose internal workspace navigation or findings.
    st.markdown(
        """
        <style>
            [data-testid="stSidebar"] { display: none !important; }
            .block-container { max-width: 980px; }
        </style>
        """,
        unsafe_allow_html=True
    )

    st.markdown('<div class="trust-shell">', unsafe_allow_html=True)
    st.markdown(
        f"""
        <div class="trust-hero">
            <span class="verified-pill">✓ DOMAIN OWNERSHIP VERIFIED</span>
            <div style="margin-top:20px;color:#9fb7df;font-size:12px;font-weight:800;letter-spacing:1px;">
                CYBERPASS BY CYBERAUDITS
            </div>
            <div class="trust-domain">{html.escape(domain)}</div>
            <div style="display:flex;align-items:flex-end;gap:12px;margin-top:24px;">
                <div style="font-size:64px;font-weight:900;line-height:.95;letter-spacing:-3px;">{score}</div>
                <div style="font-size:20px;color:#b7c8e6;margin-bottom:7px;">/100</div>
            </div>
            <div style="margin-top:12px;font-weight:800;">{html.escape(status_label)}</div>
            <div style="margin-top:6px;color:#d8e4f8;font-size:13px;">{html.escape(status_description)}</div>
        </div>
        """,
        unsafe_allow_html=True
    )

    m1, m2, m3 = st.columns(3)
    m1.metric("Cobertura", f"{meta.get('coverage', 0)}%")
    m2.metric("Confianza", meta.get("confidence", "N/D"))
    m3.metric("Última evaluación", str(latest["timestamp"])[:10])

    st.markdown("### Controles evaluados")
    public_categories = [
        "TLS & Certificado",
        "Seguridad Web",
        "Transporte",
        "Exposición",
        "DNS Security",
        "Email Security"
    ]

    for start in (0, 3):
        cols = st.columns(3)
        for col, label in zip(cols, public_categories[start:start + 3]):
            value = categories.get(label)
            with col:
                if value is None:
                    st.metric(label, "N/D")
                else:
                    st.metric(label, f"{int(value)}/100")

    st.markdown(
        """
        <div class="small-note" style="margin-top:18px;">
            <strong>Qué significa:</strong> este CyberPass muestra una fotografía de controles
            técnicos que CyberAudits pudo verificar en la fecha indicada. No es una certificación,
            no garantiza ausencia de vulnerabilidades y no publica IPs, hallazgos concretos,
            puertos ni evidencia técnica sensible.
        </div>
        """,
        unsafe_allow_html=True
    )

    if st.button("Analizar mi empresa con CyberAudits", type="primary", use_container_width=True):
        try:
            st.query_params.clear()
        except Exception:
            pass
        st.rerun()

    st.markdown('</div>', unsafe_allow_html=True)
    st.stop()



def render_public_home():
    # Public landing intentionally contains only low-impact checks.
    st.markdown(
        """
        <div class="public-hero">
            <span class="public-pill">CYBERAUDITS · FREE CYBERCHECK</span>
            <h1>Descubrí qué tan expuesta está tu empresa antes de que sea un problema.</h1>
            <p>
                Revisamos señales públicas de HTTPS, TLS, cabeceras y DNS,
                las convertimos en un CyberScore entendible y te mostramos
                dónde conviene empezar a mejorar.
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    c1, c2, c3 = st.columns(3)

    with c1:
        st.markdown(
            """
            <div class="public-card">
                <h3>⚡ Resultado rápido</h3>
                <p>
                    Un diagnóstico inicial de bajo impacto sin instalar agentes
                    ni dar acceso a infraestructura interna.
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )

    with c2:
        st.markdown(
            """
            <div class="public-card">
                <h3>🧭 Priorización</h3>
                <p>
                    CyberAudits separa configuraciones, hardening y señales
                    técnicas para evitar alarmas exageradas.
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )

    with c3:
        st.markdown(
            """
            <div class="public-card">
                <h3>🛡️ De detectar a demostrar</h3>
                <p>
                    El objetivo final es corregir, volver a verificar y
                    publicar un CyberPass solo para dominios controlados.
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("## Probá el Free CyberCheck")
    st.write(
        "Ingresá un sitio que administrás o para el cual tenés autorización de evaluación."
    )

    if "public_scan_result" not in st.session_state:
        st.session_state.public_scan_result = None

    with st.form("public_free_scan"):
        public_target = st.text_input(
            "Sitio web",
            placeholder="https://empresa.com"
        )

        authorized = st.checkbox(
            "Confirmo que administro este sitio o tengo autorización para evaluarlo."
        )

        launch_public_scan = st.form_submit_button(
            "Obtener CyberScore gratis",
            type="primary",
            use_container_width=True
        )

    if launch_public_scan:
        if not authorized:
            st.error("Necesitás confirmar que tenés autorización para evaluar el sitio.")

        elif not public_target.strip():
            st.error("Ingresá un dominio o URL.")

        else:
            now = datetime.datetime.now(datetime.timezone.utc)
            last_scan = st.session_state.get("public_last_scan_at")

            if last_scan and (now - last_scan).total_seconds() < 30:
                st.warning("Esperá unos segundos antes de ejecutar otro análisis.")
            else:
                with st.spinner(
                    "Revisando HTTPS, TLS, cabeceras y DNS público..."
                ):
                    (
                        findings,
                        stats,
                        hostname,
                        geo,
                        score,
                        scan_details
                    ) = scan_target(
                        public_target,
                        ""
                    )

                    meta = build_scan_meta(
                        stats,
                        findings,
                        scan_details
                    )

                    st.session_state.public_scan_result = {
                        "hostname": hostname,
                        "score": score,
                        "findings": findings,
                        "meta": meta
                    }

                    st.session_state.public_last_scan_at = now

    public_result = st.session_state.get("public_scan_result")

    if public_result:
        score = int(public_result["score"])
        findings = public_result["findings"]
        meta = public_result["meta"]
        hostname = public_result["hostname"]

        actionable = [
            f for f in findings
            if is_actionable(f)
        ]

        status_label, status_description = score_status(score)

        st.markdown("---")
        st.markdown("## Resultado preliminar")

        score_col, info_col = st.columns([1, 2])

        with score_col:
            st.markdown(
                f"""
                <div class="public-score-card">
                    <div class="muted">CyberScore preliminar</div>
                    <div style="margin-top:14px;">
                        <span class="public-score">{score}</span>
                        <span class="score-denom">/100</span>
                    </div>
                    <span class="score-label">{html.escape(status_label)}</span>
                    <p class="muted" style="margin-top:14px;">
                        {html.escape(status_description)}
                    </p>
                </div>
                """,
                unsafe_allow_html=True
            )

        with info_col:
            m1, m2, m3 = st.columns(3)
            m1.metric("Cobertura", f"{meta.get('coverage', 0)}%")
            m2.metric("Confianza", meta.get("confidence", "N/D"))
            m3.metric("Señales a revisar", len(actionable))

            st.caption(
                f"Objetivo evaluado: {hostname}. "
                "Este resultado es una evaluación externa preliminar, "
                "no una certificación ni una garantía de seguridad."
            )

        st.markdown("### Postura observable")

        categories = meta.get("category_scores", {})

        visible_categories = [
            "TLS & Certificado",
            "Seguridad Web",
            "Transporte",
            "Exposición",
            "DNS Security"
        ]

        cols = st.columns(5)

        for col, label in zip(cols, visible_categories):
            value = categories.get(label)

            with col:
                if value is None:
                    st.metric(label, "N/D")
                else:
                    st.metric(label, f"{int(value)}/100")

        st.info(
            "La versión pública no muestra hallazgos técnicos detallados, "
            "IPs, evidencias ni configuraciones sensibles."
        )

        st.markdown("### ¿Querés acceso al informe completo cuando abramos la beta?")

        with st.form("public_beta_lead"):
            lead_email = st.text_input(
                "Email de contacto",
                placeholder="vos@empresa.com"
            )

            consent = st.checkbox(
                "Acepto que CyberAudits use este email para contactarme sobre la beta."
            )

            send_lead = st.form_submit_button(
                "Solicitar acceso beta",
                use_container_width=True
            )

        if send_lead:
            if not consent:
                st.error("Necesitamos tu consentimiento para guardar el contacto.")
            else:
                try:
                    save_public_lead(
                        lead_email,
                        hostname,
                        score
                    )
                    st.success(
                        "Listo. Guardamos tu solicitud de acceso a la beta."
                    )
                except Exception as e:
                    st.error(str(e))

    st.markdown("---")

    left, right = st.columns([2, 1])

    with left:
        st.markdown("### ¿Ya sos administrador de CyberAudits?")
        st.caption(
            "El workspace privado contiene historial, reportes, "
            "remediación y administración de CyberPass."
        )

    with right:
        if st.button(
            "Entrar al workspace privado",
            use_container_width=True
        ):
            st.query_params["admin"] = "1"
            st.rerun()

    st.markdown(
        """
        <div class="public-footer">
            CyberAudits Free CyberCheck realiza verificaciones externas y de bajo impacto.
            Los análisis avanzados requerirán verificación de propiedad o autorización adicional.
        </div>
        """,
        unsafe_allow_html=True
    )

    st.stop()


def require_private_beta_login():
    configured_password = _secret_value("auth", "admin_password", "")

    if not configured_password:
        st.markdown(
            """
            <div class="auth-shell">
                <div class="ca-kicker">CYBERAUDITS PRIVATE BETA</div>
                <h2 style="margin-top:6px;">Configuración de acceso requerida</h2>
                <p class="muted">
                    La aplicación administrativa está bloqueada hasta configurar
                    una contraseña en Streamlit Secrets.
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )
        st.error(
            'Agregá en Streamlit Secrets: [auth] admin_password = "TU_CLAVE_SEGURA"'
        )
        st.stop()

    if st.session_state.get("authenticated", False):
        return

    st.markdown(
        """
        <div class="auth-shell">
            <div class="ca-kicker">CYBERAUDITS 2.6 · PRIVATE BETA</div>
            <h2 style="margin-top:6px;">Acceso al workspace</h2>
            <p class="muted">
                Esta instancia contiene historial, reportes y controles administrativos.
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    with st.form("private_beta_login"):
        candidate = st.text_input("Contraseña", type="password")
        submit = st.form_submit_button("Entrar", type="primary", use_container_width=True)

    if submit:
        if hmac.compare_digest(candidate, configured_password):
            st.session_state.authenticated = True
            st.rerun()
        else:
            st.error("Contraseña incorrecta.")

    st.stop()


# Public CyberPass routes are intentionally available without admin login.
try:
    public_pass_slug = st.query_params.get("pass", "")
    admin_mode = st.query_params.get("admin", "")
except Exception:
    public_pass_slug = ""
    admin_mode = ""

if isinstance(public_pass_slug, list):
    public_pass_slug = public_pass_slug[0] if public_pass_slug else ""

if isinstance(admin_mode, list):
    admin_mode = admin_mode[0] if admin_mode else ""

if public_pass_slug:
    render_public_cyberpass(public_pass_slug)

# Root URL is now the public marketing/free-check surface.
# Authenticated admins keep access without needing ?admin=1.
if (
    not st.session_state.get("authenticated", False)
    and str(admin_mode) != "1"
):
    render_public_home()

# Everything below this point is administrative/private-beta functionality.
require_private_beta_login()

# ==========================================
# SIDEBAR / WORKSPACE
# ==========================================

st.sidebar.markdown("## 🛡️ CyberAudits")
st.sidebar.caption("Security Posture Workspace · Private Beta")

if st.sidebar.button("Cerrar sesión", use_container_width=True):
    st.session_state.authenticated = False

    try:
        st.query_params.clear()
    except Exception:
        pass

    st.rerun()

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
        <div class="ca-kicker">CYBERAUDITS 2.6 · PRIVATE BETA</div>
        <h1>Descubrí el riesgo. Corregí lo importante. Demostralo.</h1>
        <p>
            Evaluación verificable de postura de seguridad,
            priorización de hallazgos y seguimiento de remediación.
        </p>
    </div>
    """,
    unsafe_allow_html=True
)


tab_dashboard, tab_scan, tab_reports, tab_history, tab_remediation, tab_leads = st.tabs(
    [
        "🏠 Dashboard",
        "🔎 Security Scan",
        "📄 Reports",
        "📈 History",
        "🛠 Remediation",
        "👥 Leads"
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

        ordered_categories = [
            "TLS & Certificado",
            "Seguridad Web",
            "Transporte",
            "Exposición",
            "DNS Security",
            "Email Security"
        ]

        for row_start in (0, 3):
            cat_cols = st.columns(3)

            for col, label in zip(
                cat_cols,
                ordered_categories[row_start:row_start + 3]
            ):
                value = cats.get(label)

                with col:
                    if value is None:
                        st.metric(label, "N/D")
                    else:
                        st.metric(
                            label,
                            f"{int(value)}/100"
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
                    email_domain_for_verify = (
                        latest_meta.get("email_domain", "")
                    )

                    (
                        new_findings,
                        new_stats,
                        new_hostname,
                        new_geo,
                        new_score,
                        new_scan_details
                    ) = scan_target(
                        verify_url,
                        email_domain_for_verify
                    )

                    new_meta = build_scan_meta(
                        new_stats,
                        new_findings,
                        new_scan_details
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
        st.markdown("### CyberPass · Trust Profile")

        st.write(
            "El CyberPass puede hacerse público **solo después de demostrar control del dominio**. "
            "La vista pública nunca muestra IPs, hallazgos concretos, puertos ni evidencia sensible."
        )

        suggested_domain = latest_meta.get("email_domain") or latest["hostname"]

        pass_domain = st.text_input(
            "Dominio que querés verificar",
            value=str(suggested_domain),
            key="cyberpass_domain_input",
            help=(
                "Debe ser el dominio que controlás. Si verificás empresa.com, "
                "el CyberPass puede usar evaluaciones de empresa.com o de sus subdominios."
            )
        )

        try:
            clean_pass_domain = _clean_domain(pass_domain)
        except Exception:
            clean_pass_domain = ""

        verification = None
        pass_record = None
        matching_scan = None

        if clean_pass_domain:
            verification = get_domain_verification(clean_pass_domain)
            pass_record = get_cyberpass_by_domain(clean_pass_domain)
            matching_scan = get_latest_scan_for_verified_domain(
                clean_pass_domain,
                selected_org_id
            )

        verify_left, verify_right = st.columns([1.15, 1])

        with verify_left:
            if not verification:
                if st.button(
                    "Generar verificación DNS",
                    type="primary",
                    use_container_width=True,
                    disabled=not bool(clean_pass_domain)
                ):
                    verification = get_or_create_domain_verification(
                        clean_pass_domain,
                        selected_org_id
                    )
                    st.rerun()

            else:
                is_verified = verification.get("status") == "verified"

                if is_verified:
                    st.success(
                        f"✅ Dominio verificado: {clean_pass_domain}"
                    )
                    st.caption(
                        f"Verificado: {verification.get('verified_at') or 'fecha no disponible'}"
                    )
                else:
                    st.info("Agregá este registro en el DNS del dominio:")
                    st.code(
                        f"Tipo: TXT\n"
                        f"Nombre/Host: _cyberaudits\n"
                        f"Nombre completo: _cyberaudits.{clean_pass_domain}\n"
                        f"Valor: cyberaudits-verification={verification['token']}",
                        language="text"
                    )

                    if st.button(
                        "Comprobar DNS ahora",
                        use_container_width=True
                    ):
                        ok, found_records, message = verify_domain_ownership(
                            clean_pass_domain
                        )

                        if ok:
                            ensure_cyberpass(
                                clean_pass_domain,
                                selected_org_id
                            )
                            st.success(message)
                            st.rerun()
                        else:
                            st.warning(message)
                            if found_records:
                                st.caption(
                                    "TXT encontrados: " + " | ".join(found_records[:5])
                                )

        with verify_right:
            if clean_pass_domain and matching_scan is None:
                st.warning(
                    "Todavía no existe un Security Scan compatible con este dominio. "
                    "Escaneá el dominio o uno de sus subdominios antes de publicar el CyberPass."
                )
            elif matching_scan is not None:
                st.success(
                    f"Evaluación compatible encontrada · CyberScore "
                    f"{int(matching_scan['risk_score'])}/100"
                )

            if verification and verification.get("status") == "verified":
                pass_record = ensure_cyberpass(
                    clean_pass_domain,
                    selected_org_id
                )

                if pass_record.get("is_public"):
                    st.success("🌎 CyberPass público")

                    public_url = _cyberpass_public_url(
                        pass_record["slug"]
                    )
                    st.text_input(
                        "Enlace público",
                        value=public_url,
                        disabled=True,
                        key=f"pass_url_{pass_record['id']}"
                    )

                    badge_html = (
                        f'<a href="{public_url}" target="_blank" '
                        f'rel="noopener noreferrer">'
                        f'🛡 Security posture verified by CyberAudits</a>'
                    )

                    with st.expander("Código del badge para tu web"):
                        st.code(badge_html, language="html")

                    if st.button(
                        "🔒 Hacer privado",
                        use_container_width=True
                    ):
                        set_cyberpass_visibility(
                            clean_pass_domain,
                            False
                        )
                        st.rerun()

                else:
                    st.info("🔒 CyberPass privado")

                    if matching_scan is not None:
                        if st.button(
                            "🌎 Publicar CyberPass",
                            type="primary",
                            use_container_width=True
                        ):
                            set_cyberpass_visibility(
                                clean_pass_domain,
                                True
                            )
                            st.rerun()
                    else:
                        st.button(
                            "🌎 Publicar CyberPass",
                            disabled=True,
                            use_container_width=True
                        )

        st.caption(
            "Importante: verificar el dominio demuestra control técnico del DNS; "
            "no convierte el CyberPass en una certificación de seguridad ni identidad legal."
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
            "URL o dominio web",
            value="https://",
            placeholder="https://empresa.com"
        )

        email_domain = st.text_input(
            "Dominio corporativo de correo · opcional",
            value="",
            placeholder="empresa.com"
        )

        st.caption(
            "Si completás el dominio corporativo, CyberAudits también "
            "revisará SPF, DMARC, MX y señales de seguridad de correo. "
            "No ingreses una dirección de email: solo el dominio."
        )

        run_scan = st.form_submit_button(
            "🚀 Ejecutar análisis",
            type="primary",
            use_container_width=True
        )

    if run_scan:
        if target_url and target_url.strip() not in {"http://", "https://"}:
            with st.spinner(
                "Analizando TLS, HTTPS, headers, DNS y seguridad de correo..."
            ):
                (
                    findings,
                    stats,
                    hostname,
                    geo,
                    risk_score,
                    scan_details
                ) = scan_target(
                    target_url,
                    email_domain
                )

                scan_meta = build_scan_meta(
                    stats,
                    findings,
                    scan_details
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

        st.markdown("#### Postura por categoría")

        scan_categories = scan_meta.get(
            "category_scores",
            {}
        )

        scan_category_labels = [
            "TLS & Certificado",
            "Seguridad Web",
            "Transporte",
            "Exposición",
            "DNS Security",
            "Email Security"
        ]

        for row_start in (0, 3):
            result_cols = st.columns(3)

            for col, label in zip(
                result_cols,
                scan_category_labels[row_start:row_start + 3]
            ):
                value = scan_categories.get(label)

                with col:
                    if value is None:
                        st.metric(label, "N/D")
                    else:
                        st.metric(
                            label,
                            f"{int(value)}/100"
                        )

        if scan_meta.get("email_domain"):
            st.caption(
                f"Dominio de correo evaluado: "
                f"{scan_meta.get('email_domain')}"
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

        report_select_col, report_delete_col = st.columns(
            [12, 1],
            vertical_alignment="bottom"
        )

        with report_select_col:
            selected_report_label = st.selectbox(
                "Seleccionar evaluación",
                list(report_options.keys()),
                key="reports_scan_select"
            )

        selected_scan_row = report_options[
            selected_report_label
        ]

        with report_delete_col:
            if st.button(
                "✕",
                key=f"delete_report_scan_{int(selected_scan_row['id'])}",
                help="Eliminar este escaneo",
                type="secondary",
                use_container_width=True
            ):
                deleted_scan_id = int(selected_scan_row["id"])
                deleted_hostname = str(selected_scan_row["hostname"])

                delete_scan(deleted_scan_id)

                if st.session_state.get("scan_id") == deleted_scan_id:
                    st.session_state.scanned = False
                    st.session_state.pop("scan_id", None)
                    st.session_state.pop("findings", None)
                    st.session_state.pop("hostname", None)
                    st.session_state.pop("risk_score", None)
                    st.session_state.pop("scan_meta", None)

                st.session_state.toast_msg = (
                    f"Escaneo de {deleted_hostname} eliminado."
                )
                st.session_state.toast_type = "success"
                st.rerun()

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

        st.markdown("#### Escaneos guardados")

        st.caption(
            "Usá la ✕ de la derecha para eliminar un escaneo. "
            "También se eliminarán sus tareas y bitácoras de remediación asociadas."
        )

        for _, row in history_tab_df.iterrows():
            scan_id = int(row["id"])
            scan_score = int(row["risk_score"] or 0)
            scan_findings = int(row["findings_count"] or 0)

            row_col, delete_col = st.columns(
                [12, 1],
                vertical_alignment="center"
            )

            with row_col:
                st.markdown(
                    f"""
                    <div class="history-row">
                        <div>
                            <div class="history-title">
                                {html.escape(str(row['hostname']))}
                            </div>
                            <div class="history-meta">
                                {html.escape(str(row['timestamp']))}
                                &nbsp; · &nbsp;
                                IP: {html.escape(str(row['ip']))}
                                &nbsp; · &nbsp;
                                CyberScore: <strong>{scan_score}/100</strong>
                                &nbsp; · &nbsp;
                                Hallazgos: <strong>{scan_findings}</strong>
                            </div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

            with delete_col:
                if st.button(
                    "✕",
                    key=f"quick_delete_scan_{scan_id}",
                    help=f"Eliminar escaneo #{scan_id}",
                    type="secondary",
                    use_container_width=True
                ):
                    delete_scan(scan_id)

                    if st.session_state.get("scan_id") == scan_id:
                        st.session_state.scanned = False
                        st.session_state.pop("scan_id", None)
                        st.session_state.pop("findings", None)
                        st.session_state.pop("hostname", None)
                        st.session_state.pop("risk_score", None)
                        st.session_state.pop("scan_meta", None)

                    st.session_state.toast_msg = (
                        f"Escaneo de {row['hostname']} eliminado."
                    )
                    st.session_state.toast_type = "success"
                    st.rerun()

        st.markdown("---")
        st.caption(
            "Consejo: conservá al menos dos evaluaciones si querés ver "
            "la evolución del CyberScore y comprobar mejoras después de una remediación."
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

        remediation_select_col, remediation_delete_col = st.columns(
            [12, 1],
            vertical_alignment="bottom"
        )

        with remediation_select_col:
            selected_ticket_label = st.selectbox(
                "Evaluación",
                list(ticket_scan_options.keys()),
                key="remediation_scan_select"
            )

        selected_scan_id = ticket_scan_options[
            selected_ticket_label
        ]

        with remediation_delete_col:
            if st.button(
                "✕",
                key=f"delete_remediation_scan_{int(selected_scan_id)}",
                help="Eliminar este escaneo y sus tareas",
                type="secondary",
                use_container_width=True
            ):
                deleted_scan_id = int(selected_scan_id)

                delete_scan(deleted_scan_id)

                if st.session_state.get("scan_id") == deleted_scan_id:
                    st.session_state.scanned = False
                    st.session_state.pop("scan_id", None)
                    st.session_state.pop("findings", None)
                    st.session_state.pop("hostname", None)
                    st.session_state.pop("risk_score", None)
                    st.session_state.pop("scan_meta", None)

                st.session_state.toast_msg = "Escaneo eliminado."
                st.session_state.toast_type = "success"
                st.rerun()

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


# ==========================================
# PUBLIC BETA LEADS
# ==========================================

with tab_leads:
    st.subheader("Public Beta Leads")

    st.write(
        "Contactos que llegaron desde el Free CyberCheck público."
    )

    try:
        leads_df = load_public_leads()
    except Exception as e:
        leads_df = pd.DataFrame()
        st.error(f"No se pudieron cargar los leads: {e}")

    if leads_df.empty:
        st.info(
            "Todavía no hay solicitudes de acceso beta."
        )
    else:
        l1, l2 = st.columns(2)
        l1.metric("Leads", len(leads_df))
        l2.metric(
            "Dominios únicos",
            leads_df["domain"].nunique()
            if "domain" in leads_df.columns
            else 0
        )

        display_leads = leads_df.copy()

        display_leads = display_leads.rename(
            columns={
                "email": "Email",
                "domain": "Dominio",
                "cyber_score": "CyberScore",
                "created_at": "Fecha",
                "source": "Origen"
            }
        )

        visible = [
            col
            for col in [
                "Email",
                "Dominio",
                "CyberScore",
                "Fecha",
                "Origen"
            ]
            if col in display_leads.columns
        ]

        st.dataframe(
            display_leads[visible],
            hide_index=True,
            use_container_width=True
        )

        st.caption(
            "Estos contactos aceptaron ser contactados sobre la beta. "
            "No compartas ni publiques esta información."
        )

