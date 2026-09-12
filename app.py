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
import string
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
        padding: 42px 42px 40px 42px;
        color: white;
        margin: 26px 0 28px 0;
        box-shadow: 0 20px 55px rgba(15, 23, 42, 0.18);
        overflow: visible;
    }

    .public-hero h1 {
        font-size: 42px;
        line-height: 1.08;
        letter-spacing: -1.4px;
        max-width: 900px;
        margin: 12px 0 14px 0;
        padding-top: 4px;
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


    div[data-testid="stFormSubmitButton"] button,
    div[data-testid="stButton"] button[kind="primary"],
    button[kind="primary"] {
        background: #215ee9 !important;
        border-color: #215ee9 !important;
        color: #ffffff !important;
    }

    div[data-testid="stFormSubmitButton"] button:hover,
    div[data-testid="stButton"] button[kind="primary"]:hover,
    button[kind="primary"]:hover {
        background: #174fcf !important;
        border-color: #174fcf !important;
        color: #ffffff !important;
    }


    .lead-status {
        display: inline-block;
        border-radius: 999px;
        padding: 5px 9px;
        font-size: 11px;
        font-weight: 800;
        letter-spacing: .25px;
    }

    .status-pending {
        background: #fff7ed;
        color: #b45309;
    }

    .status-invited {
        background: #eff6ff;
        color: #1d4ed8;
    }

    .status-confirmed {
        background: #ecfeff;
        color: #0f766e;
    }

    .status-active {
        background: #ecfdf5;
        color: #047857;
    }

    .status-suspended {
        background: #fef2f2;
        color: #b91c1c;
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
        c.execute("ALTER TABLE history ADD COLUMN IF NOT EXISTS target_url TEXT;")
        c.execute("""CREATE TABLE IF NOT EXISTS remediation_tasks (id SERIAL PRIMARY KEY, organization_id INTEGER, scan_id INTEGER, hostname TEXT, finding_vector TEXT, severity TEXT DEFAULT 'MEDIO', status TEXT DEFAULT 'Pendiente', notes TEXT)""")
        c.execute("ALTER TABLE remediation_tasks ADD COLUMN IF NOT EXISTS organization_id INTEGER;")
        c.execute("ALTER TABLE remediation_tasks ADD COLUMN IF NOT EXISTS scan_id INTEGER;")
        c.execute("ALTER TABLE remediation_tasks ADD COLUMN IF NOT EXISTS severity TEXT;")
        c.execute("""CREATE TABLE IF NOT EXISTS remediation_logs (id SERIAL PRIMARY KEY, task_id INTEGER, timestamp TEXT, status TEXT, notes TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS domain_verifications (id SERIAL PRIMARY KEY, organization_id INTEGER, domain TEXT UNIQUE NOT NULL, token TEXT NOT NULL, status TEXT DEFAULT 'pending', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, verified_at TIMESTAMP)""")
        c.execute("""CREATE TABLE IF NOT EXISTS cyberpasses (id SERIAL PRIMARY KEY, organization_id INTEGER, domain TEXT UNIQUE NOT NULL, slug TEXT UNIQUE NOT NULL, is_public INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        c.execute("""CREATE TABLE IF NOT EXISTS public_leads (id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, domain TEXT, cyber_score INTEGER, source TEXT DEFAULT 'free_cybercheck', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        c.execute("ALTER TABLE public_leads ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'Pendiente';")
        c.execute("ALTER TABLE public_leads ADD COLUMN IF NOT EXISTS organization_id INTEGER;")
        c.execute("ALTER TABLE public_leads ADD COLUMN IF NOT EXISTS auth_user_id TEXT;")
        c.execute("ALTER TABLE public_leads ADD COLUMN IF NOT EXISTS invited_at TIMESTAMP;")
        c.execute("ALTER TABLE public_leads ADD COLUMN IF NOT EXISTS last_error TEXT;")
        c.execute("""CREATE TABLE IF NOT EXISTS organization_members (
            id SERIAL PRIMARY KEY,
            organization_id INTEGER NOT NULL,
            email TEXT UNIQUE NOT NULL,
            auth_user_id TEXT,
            role TEXT DEFAULT 'CLIENT',
            status TEXT DEFAULT 'Invitado',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS organization_profiles (
            id SERIAL PRIMARY KEY,
            organization_id INTEGER UNIQUE NOT NULL,
            display_name TEXT,
            legal_name TEXT,
            department TEXT,
            report_recipient TEXT,
            report_title TEXT,
            confidentiality_footer TEXT,
            logo_b64 TEXT,
            logo_mime TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
        c.execute("ALTER TABLE organization_members ADD COLUMN IF NOT EXISTS must_change_password INTEGER DEFAULT 1;")
        c.execute("ALTER TABLE organization_members ADD COLUMN IF NOT EXISTS last_login TIMESTAMP;")
    else:
        c.execute("""CREATE TABLE IF NOT EXISTS organizations (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        c.execute("""CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, hostname TEXT, ip TEXT, risk_score INTEGER, findings_count INTEGER, report_type TEXT, organization_id INTEGER, findings_json TEXT, scan_meta_json TEXT)""")
        try: c.execute("ALTER TABLE history ADD COLUMN organization_id INTEGER;")
        except: pass
        try: c.execute("ALTER TABLE history ADD COLUMN findings_json TEXT;")
        except: pass
        try: c.execute("ALTER TABLE history ADD COLUMN scan_meta_json TEXT;")
        except: pass
        try: c.execute("ALTER TABLE history ADD COLUMN target_url TEXT;")
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
        try: c.execute("ALTER TABLE public_leads ADD COLUMN status TEXT DEFAULT 'Pendiente';")
        except: pass
        try: c.execute("ALTER TABLE public_leads ADD COLUMN organization_id INTEGER;")
        except: pass
        try: c.execute("ALTER TABLE public_leads ADD COLUMN auth_user_id TEXT;")
        except: pass
        try: c.execute("ALTER TABLE public_leads ADD COLUMN invited_at TIMESTAMP;")
        except: pass
        try: c.execute("ALTER TABLE public_leads ADD COLUMN last_error TEXT;")
        except: pass
        c.execute("""CREATE TABLE IF NOT EXISTS organization_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id INTEGER NOT NULL,
            email TEXT UNIQUE NOT NULL,
            auth_user_id TEXT,
            role TEXT DEFAULT 'CLIENT',
            status TEXT DEFAULT 'Invitado',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS organization_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id INTEGER UNIQUE NOT NULL,
            display_name TEXT,
            legal_name TEXT,
            department TEXT,
            report_recipient TEXT,
            report_title TEXT,
            confidentiality_footer TEXT,
            logo_b64 TEXT,
            logo_mime TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
        try: c.execute("ALTER TABLE organization_members ADD COLUMN must_change_password INTEGER DEFAULT 1;")
        except: pass
        try: c.execute("ALTER TABLE organization_members ADD COLUMN last_login TIMESTAMP;")
        except: pass
        conn.commit()

    try:
        c.execute(
            "UPDATE public_leads SET status = 'Pendiente' "
            "WHERE status IS NULL OR status = ''"
        )
        if not is_pg:
            conn.commit()
    except Exception:
        pass

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
    scan_meta=None,
    target_url=None
):
    conn = get_db_connection()
    c = conn.cursor()

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    findings_str = json.dumps(findings or [], ensure_ascii=False)
    meta_str = json.dumps(scan_meta or {}, ensure_ascii=False)

    is_pg = "postgres" in st.secrets
    ph = "%s" if is_pg else "?"

    stored_target_url = (target_url or "").strip()
    if not stored_target_url and hostname:
        stored_target_url = f"https://{hostname}"

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
                scan_meta_json,
                target_url
            )
            VALUES
            ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})
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
                meta_str,
                stored_target_url
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
                scan_meta_json,
                target_url
            )
            VALUES
            ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})
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
                meta_str,
                stored_target_url
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


def delete_client_scan(organization_id, scan_id):
    """
    Elimina una evaluación y sus tickets solamente si pertenecen
    a la organización autenticada del cliente.
    """
    conn = get_db_connection()
    c = conn.cursor()
    ph = _db_ph()
    is_pg = "postgres" in st.secrets

    try:
        c.execute(
            f"""
            DELETE FROM remediation_logs
            WHERE task_id IN (
                SELECT id
                FROM remediation_tasks
                WHERE scan_id = {ph}
                  AND organization_id = {ph}
            )
            """,
            (int(scan_id), int(organization_id))
        )

        c.execute(
            f"""
            DELETE FROM remediation_tasks
            WHERE scan_id = {ph}
              AND organization_id = {ph}
            """,
            (int(scan_id), int(organization_id))
        )

        c.execute(
            f"""
            DELETE FROM history
            WHERE id = {ph}
              AND organization_id = {ph}
            """,
            (int(scan_id), int(organization_id))
        )

        if not is_pg:
            conn.commit()
    finally:
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
                    cyber_score = EXCLUDED.cyber_score,
                    source = EXCLUDED.source
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
                    cyber_score = excluded.cyber_score,
                    source = excluded.source
                """,
                (email, domain, cyber_score)
            )
            conn.commit()
    finally:
        c.close()
        conn.close()



def delete_public_lead(lead_id):
    conn = get_db_connection()
    c = conn.cursor()
    ph = _db_ph()

    try:
        c.execute(
            f"DELETE FROM public_leads WHERE id = {ph}",
            (int(lead_id),)
        )

        if "postgres" not in st.secrets:
            conn.commit()
    finally:
        c.close()
        conn.close()


def load_public_leads():
    conn = get_db_connection()

    try:
        df = pd.read_sql_query(
            """
            SELECT
                id,
                email,
                domain,
                cyber_score,
                source,
                created_at,
                status,
                organization_id,
                auth_user_id,
                invited_at,
                last_error
            FROM public_leads
            ORDER BY id DESC
            """,
            conn
        )
    finally:
        conn.close()

    return df



def _supabase_admin_config():
    supabase_url = _secret_value(
        "supabase",
        "url",
        ""
    ).strip().rstrip("/")

    secret_key = _secret_value(
        "supabase",
        "secret_key",
        ""
    ).strip()

    if not supabase_url or not secret_key:
        raise RuntimeError(
            "Falta configurar [supabase] url y secret_key "
            "en Streamlit Secrets."
        )

    if not secret_key.startswith("sb_secret_"):
        raise RuntimeError(
            "La clave configurada no parece ser una Supabase Secret key."
        )

    return supabase_url, secret_key


def _supabase_admin_headers():
    _, secret_key = _supabase_admin_config()

    # sb_secret_ is an API key, not a JWT. It remains server-side
    # and is sent through Supabase's apikey header.
    return {
        "apikey": secret_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "CyberAudits-Backend/2.8.2"
    }


def supabase_invite_user(email, organization_id=None, role="CLIENT"):
    email = (email or "").strip().lower()

    if not _valid_email_address(email):
        raise ValueError("Email inválido.")

    supabase_url, _ = _supabase_admin_config()

    payload = {
        "email": email,
        "data": {
            "role": role,
            "organization_id": organization_id,
            "source": "cyberaudits"
        }
    }

    response = requests.post(
        f"{supabase_url}/auth/v1/invite",
        headers=_supabase_admin_headers(),
        json=payload,
        timeout=12
    )

    try:
        data = response.json()
    except Exception:
        data = {}

    if response.status_code not in (200, 201):
        message = (
            data.get("msg")
            or data.get("message")
            or data.get("error_description")
            or data.get("error")
            or f"Supabase respondió HTTP {response.status_code}."
        )

        raise RuntimeError(str(message))

    return data


def supabase_get_user(user_id):
    if not user_id:
        return None

    supabase_url, _ = _supabase_admin_config()

    response = requests.get(
        f"{supabase_url}/auth/v1/admin/users/{user_id}",
        headers=_supabase_admin_headers(),
        timeout=12
    )

    if response.status_code == 404:
        return None

    try:
        data = response.json()
    except Exception:
        data = {}

    if response.status_code != 200:
        message = (
            data.get("msg")
            or data.get("message")
            or data.get("error")
            or f"Supabase respondió HTTP {response.status_code}."
        )
        raise RuntimeError(str(message))

    return data


def ensure_organization_for_lead(domain, email):
    domain = (domain or "").strip().lower()
    email = (email or "").strip().lower()

    if domain:
        org_name = domain
    else:
        org_name = email.split("@")[-1] if "@" in email else email

    org_name = org_name[:180] or "Cliente CyberAudits"

    conn = get_db_connection()
    c = conn.cursor()
    ph = _db_ph()
    is_pg = "postgres" in st.secrets

    try:
        c.execute(
            f"SELECT id FROM organizations WHERE name = {ph}",
            (org_name,)
        )
        row = c.fetchone()

        if row:
            org_id = int(row[0])
        else:
            if is_pg:
                c.execute(
                    f"""
                    INSERT INTO organizations (name)
                    VALUES ({ph})
                    RETURNING id
                    """,
                    (org_name,)
                )
                org_id = int(c.fetchone()[0])
            else:
                c.execute(
                    "INSERT INTO organizations (name) VALUES (?)",
                    (org_name,)
                )
                org_id = int(c.lastrowid)
                conn.commit()

        return org_id

    finally:
        c.close()
        conn.close()


def upsert_organization_member(
    organization_id,
    email,
    auth_user_id,
    role="CLIENT",
    status="Invitado"
):
    conn = get_db_connection()
    c = conn.cursor()
    ph = _db_ph()
    is_pg = "postgres" in st.secrets

    try:
        if is_pg:
            c.execute(
                f"""
                INSERT INTO organization_members
                (
                    organization_id,
                    email,
                    auth_user_id,
                    role,
                    status,
                    updated_at
                )
                VALUES
                ({ph}, {ph}, {ph}, {ph}, {ph}, CURRENT_TIMESTAMP)
                ON CONFLICT (email)
                DO UPDATE SET
                    organization_id = EXCLUDED.organization_id,
                    auth_user_id = EXCLUDED.auth_user_id,
                    role = EXCLUDED.role,
                    status = EXCLUDED.status,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    organization_id,
                    email,
                    auth_user_id,
                    role,
                    status
                )
            )
        else:
            c.execute(
                """
                INSERT INTO organization_members
                (
                    organization_id,
                    email,
                    auth_user_id,
                    role,
                    status,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(email)
                DO UPDATE SET
                    organization_id = excluded.organization_id,
                    auth_user_id = excluded.auth_user_id,
                    role = excluded.role,
                    status = excluded.status,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    organization_id,
                    email,
                    auth_user_id,
                    role,
                    status
                )
            )
            conn.commit()
    finally:
        c.close()
        conn.close()


def update_lead_invitation(
    lead_id,
    status,
    organization_id=None,
    auth_user_id=None,
    invited=False,
    last_error=None
):
    conn = get_db_connection()
    c = conn.cursor()
    ph = _db_ph()
    is_pg = "postgres" in st.secrets

    try:
        invited_expr = "CURRENT_TIMESTAMP" if invited else "invited_at"

        c.execute(
            f"""
            UPDATE public_leads
            SET
                status = {ph},
                organization_id = {ph},
                auth_user_id = {ph},
                invited_at = {invited_expr},
                last_error = {ph}
            WHERE id = {ph}
            """,
            (
                status,
                organization_id,
                auth_user_id,
                last_error,
                int(lead_id)
            )
        )

        if not is_pg:
            conn.commit()
    finally:
        c.close()
        conn.close()


def refresh_lead_auth_status(lead_id, auth_user_id, organization_id, email):
    user = supabase_get_user(auth_user_id)

    if not user:
        update_lead_invitation(
            lead_id,
            "Pendiente",
            organization_id=organization_id,
            auth_user_id=None,
            invited=False,
            last_error="El usuario ya no existe en Supabase Auth."
        )
        return "Pendiente"

    confirmed_at = (
        user.get("email_confirmed_at")
        or user.get("confirmed_at")
    )

    last_sign_in_at = user.get("last_sign_in_at")

    if last_sign_in_at:
        new_status = "Activo"
    elif confirmed_at:
        new_status = "Confirmado"
    else:
        new_status = "Invitado"

    update_lead_invitation(
        lead_id,
        new_status,
        organization_id=organization_id,
        auth_user_id=auth_user_id,
        invited=False,
        last_error=None
    )

    upsert_organization_member(
        organization_id,
        email,
        auth_user_id,
        role="CLIENT",
        status=new_status
    )

    return new_status


def approve_and_invite_lead(lead):
    lead_id = int(lead["id"])
    email = str(lead["email"]).strip().lower()
    domain = str(lead.get("domain") or "").strip().lower()

    organization_id = ensure_organization_for_lead(
        domain,
        email
    )

    try:
        user_data = supabase_invite_user(
            email,
            organization_id=organization_id,
            role="CLIENT"
        )

        auth_user_id = (
            user_data.get("id")
            or (user_data.get("user") or {}).get("id")
        )

        if not auth_user_id:
            raise RuntimeError(
                "Supabase envió una respuesta sin identificador de usuario."
            )

        update_lead_invitation(
            lead_id,
            "Invitado",
            organization_id=organization_id,
            auth_user_id=auth_user_id,
            invited=True,
            last_error=None
        )

        upsert_organization_member(
            organization_id,
            email,
            auth_user_id,
            role="CLIENT",
            status="Invitado"
        )

        return {
            "ok": True,
            "organization_id": organization_id,
            "auth_user_id": auth_user_id
        }

    except Exception as exc:
        update_lead_invitation(
            lead_id,
            "Pendiente",
            organization_id=organization_id,
            auth_user_id=None,
            invited=False,
            last_error=str(exc)
        )
        raise



def _generate_temporary_password(length=18):
    """
    Genera una contraseña temporal fuerte.
    Se muestra al administrador y nunca se persiste en nuestra base.
    """
    length = max(int(length or 18), 14)

    alphabet = (
        string.ascii_letters
        + string.digits
        + "!@#$%_-"
    )

    while True:
        value = "".join(
            secrets.choice(alphabet)
            for _ in range(length)
        )

        if (
            any(c.islower() for c in value)
            and any(c.isupper() for c in value)
            and any(c.isdigit() for c in value)
            and any(c in "!@#$%_-" for c in value)
        ):
            return value


def supabase_admin_set_password(user_id, password):
    if not user_id:
        raise ValueError("Falta el identificador del usuario.")

    if len(password or "") < 12:
        raise ValueError("La contraseña temporal es demasiado corta.")

    supabase_url, _ = _supabase_admin_config()

    response = requests.put(
        f"{supabase_url}/auth/v1/admin/users/{user_id}",
        headers=_supabase_admin_headers(),
        json={"password": password},
        timeout=12
    )

    try:
        data = response.json()
    except Exception:
        data = {}

    if response.status_code not in (200, 201, 204):
        message = (
            data.get("msg")
            or data.get("message")
            or data.get("error_description")
            or data.get("error")
            or f"Supabase respondió HTTP {response.status_code}."
        )
        raise RuntimeError(str(message))

    return data


def set_member_password_change_required(email, required=True):
    email = (email or "").strip().lower()

    conn = get_db_connection()
    c = conn.cursor()
    ph = _db_ph()

    try:
        c.execute(
            f"""
            UPDATE organization_members
            SET must_change_password = {ph},
                updated_at = CURRENT_TIMESTAMP
            WHERE LOWER(email) = LOWER({ph})
            """,
            (1 if required else 0, email)
        )

        if "postgres" not in st.secrets:
            conn.commit()
    finally:
        c.close()
        conn.close()



def set_client_access_status(lead_id, email, status):
    """
    Cambia el estado de acceso tanto en el lead como en la membresía.
    No elimina datos históricos del cliente.
    """
    email = (email or "").strip().lower()
    status = (status or "").strip()

    if status not in {"Activo", "Suspendido"}:
        raise ValueError("Estado de acceso no permitido.")

    conn = get_db_connection()
    c = conn.cursor()
    ph = _db_ph()

    try:
        c.execute(
            f"""
            UPDATE public_leads
            SET status = {ph},
                last_error = NULL
            WHERE id = {ph}
            """,
            (status, int(lead_id))
        )

        c.execute(
            f"""
            UPDATE organization_members
            SET status = {ph},
                updated_at = CURRENT_TIMESTAMP
            WHERE LOWER(email) = LOWER({ph})
            """,
            (status, email)
        )

        if "postgres" not in st.secrets:
            conn.commit()

    finally:
        c.close()
        conn.close()


def mark_member_login(email):
    email = (email or "").strip().lower()

    conn = get_db_connection()
    c = conn.cursor()
    ph = _db_ph()

    try:
        c.execute(
            f"""
            UPDATE organization_members
            SET last_login = CURRENT_TIMESTAMP,
                status = 'Activo',
                updated_at = CURRENT_TIMESTAMP
            WHERE LOWER(email) = LOWER({ph})
            """,
            (email,)
        )

        if "postgres" not in st.secrets:
            conn.commit()
    finally:
        c.close()
        conn.close()


def get_member_for_identity(user_id=None, email=None):
    conn = get_db_connection()
    ph = _db_ph()

    try:
        if user_id:
            df = pd.read_sql_query(
                f"""
                SELECT
                    om.id,
                    om.organization_id,
                    om.email,
                    om.auth_user_id,
                    om.role,
                    om.status,
                    om.must_change_password,
                    om.last_login,
                    o.name AS organization_name
                FROM organization_members om
                LEFT JOIN organizations o
                    ON o.id = om.organization_id
                WHERE om.auth_user_id = {ph}
                LIMIT 1
                """,
                conn,
                params=(str(user_id),)
            )
        else:
            df = pd.read_sql_query(
                f"""
                SELECT
                    om.id,
                    om.organization_id,
                    om.email,
                    om.auth_user_id,
                    om.role,
                    om.status,
                    om.must_change_password,
                    om.last_login,
                    o.name AS organization_name
                FROM organization_members om
                LEFT JOIN organizations o
                    ON o.id = om.organization_id
                WHERE LOWER(om.email) = LOWER({ph})
                LIMIT 1
                """,
                conn,
                params=((email or "").strip().lower(),)
            )
    finally:
        conn.close()

    if df.empty:
        return None

    return df.iloc[0].to_dict()


def supabase_password_login(email, password):
    email = (email or "").strip().lower()

    if not _valid_email_address(email):
        raise ValueError("Email inválido.")

    if not password:
        raise ValueError("Ingresá tu contraseña.")

    supabase_url, _ = _supabase_admin_config()

    response = requests.post(
        f"{supabase_url}/auth/v1/token",
        params={"grant_type": "password"},
        headers={
            "apikey": _supabase_admin_config()[1],
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "CyberAudits-Backend/2.8"
        },
        json={
            "email": email,
            "password": password
        },
        timeout=12
    )

    try:
        data = response.json()
    except Exception:
        data = {}

    if response.status_code != 200:
        message = (
            data.get("msg")
            or data.get("message")
            or data.get("error_description")
            or data.get("error")
            or "Email o contraseña incorrectos."
        )
        raise RuntimeError(str(message))

    user = data.get("user") or {}
    access_token = data.get("access_token")
    refresh_token = data.get("refresh_token")

    if not user.get("id") or not access_token:
        raise RuntimeError(
            "Supabase autenticó la solicitud pero no devolvió una sesión válida."
        )

    return {
        "user": user,
        "access_token": access_token,
        "refresh_token": refresh_token
    }


def supabase_user_change_password(access_token, new_password):
    if not access_token:
        raise RuntimeError("La sesión del cliente no es válida.")

    if len(new_password or "") < 12:
        raise ValueError(
            "La nueva contraseña debe tener al menos 12 caracteres."
        )

    supabase_url, secret_key = _supabase_admin_config()

    response = requests.put(
        f"{supabase_url}/auth/v1/user",
        headers={
            "apikey": secret_key,
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "CyberAudits-Client/2.8"
        },
        json={"password": new_password},
        timeout=12
    )

    try:
        data = response.json()
    except Exception:
        data = {}

    if response.status_code != 200:
        message = (
            data.get("msg")
            or data.get("message")
            or data.get("error_description")
            or data.get("error")
            or f"No se pudo cambiar la contraseña (HTTP {response.status_code})."
        )
        raise RuntimeError(str(message))

    return data



def get_organization_profile(organization_id, fallback_name=""):
    conn = get_db_connection()
    ph = _db_ph()
    try:
        df = pd.read_sql_query(
            f"""
            SELECT
                organization_id,
                display_name,
                legal_name,
                department,
                report_recipient,
                report_title,
                confidentiality_footer,
                logo_b64,
                logo_mime,
                updated_at
            FROM organization_profiles
            WHERE organization_id = {ph}
            LIMIT 1
            """,
            conn,
            params=(int(organization_id),)
        )
    finally:
        conn.close()

    defaults = {
        "organization_id": int(organization_id),
        "display_name": fallback_name or "",
        "legal_name": "",
        "department": "",
        "report_recipient": "Dirección General",
        "report_title": "Evaluación de Postura de Ciberseguridad",
        "confidentiality_footer": (
            "Documento confidencial. Uso exclusivo de la organización evaluada."
        ),
        "logo_b64": "",
        "logo_mime": "image/png"
    }

    if df.empty:
        return defaults

    profile = df.iloc[0].to_dict()
    for key, default in defaults.items():
        if profile.get(key) is None:
            profile[key] = default
    return profile


def save_organization_profile(
    organization_id,
    display_name,
    legal_name,
    department,
    report_recipient,
    report_title,
    confidentiality_footer,
    logo_b64,
    logo_mime
):
    conn = get_db_connection()
    c = conn.cursor()
    ph = _db_ph()
    is_pg = "postgres" in st.secrets

    values = (
        int(organization_id),
        (display_name or "").strip(),
        (legal_name or "").strip(),
        (department or "").strip(),
        (report_recipient or "").strip(),
        (report_title or "").strip(),
        (confidentiality_footer or "").strip(),
        logo_b64 or "",
        logo_mime or "image/png"
    )

    try:
        if is_pg:
            c.execute(
                f"""
                INSERT INTO organization_profiles
                (
                    organization_id,
                    display_name,
                    legal_name,
                    department,
                    report_recipient,
                    report_title,
                    confidentiality_footer,
                    logo_b64,
                    logo_mime,
                    updated_at
                )
                VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, CURRENT_TIMESTAMP)
                ON CONFLICT (organization_id)
                DO UPDATE SET
                    display_name = EXCLUDED.display_name,
                    legal_name = EXCLUDED.legal_name,
                    department = EXCLUDED.department,
                    report_recipient = EXCLUDED.report_recipient,
                    report_title = EXCLUDED.report_title,
                    confidentiality_footer = EXCLUDED.confidentiality_footer,
                    logo_b64 = EXCLUDED.logo_b64,
                    logo_mime = EXCLUDED.logo_mime,
                    updated_at = CURRENT_TIMESTAMP
                """,
                values
            )
        else:
            c.execute(
                """
                INSERT INTO organization_profiles
                (
                    organization_id,
                    display_name,
                    legal_name,
                    department,
                    report_recipient,
                    report_title,
                    confidentiality_footer,
                    logo_b64,
                    logo_mime,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(organization_id)
                DO UPDATE SET
                    display_name = excluded.display_name,
                    legal_name = excluded.legal_name,
                    department = excluded.department,
                    report_recipient = excluded.report_recipient,
                    report_title = excluded.report_title,
                    confidentiality_footer = excluded.confidentiality_footer,
                    logo_b64 = excluded.logo_b64,
                    logo_mime = excluded.logo_mime,
                    updated_at = CURRENT_TIMESTAMP
                """,
                values
            )
            conn.commit()
    finally:
        c.close()
        conn.close()


def _logo_upload_to_b64(uploaded_file):
    if uploaded_file is None:
        return None, None

    raw = uploaded_file.getvalue()
    if len(raw) > 350_000:
        raise ValueError("El logo supera 350 KB. Reducí el archivo antes de subirlo.")

    mime = uploaded_file.type or ""
    if mime not in {"image/png", "image/jpeg"}:
        raise ValueError("Para informes usá un logo PNG o JPG.")

    return base64.b64encode(raw).decode("utf-8"), mime


def _profile_logo_uri(profile):
    data = str(profile.get("logo_b64") or "").strip()
    if not data:
        return ""
    mime = str(profile.get("logo_mime") or "image/png")
    return f"data:{mime};base64,{data}"


def get_client_remediation_tasks(organization_id, scan_id):
    conn = get_db_connection()
    ph = _db_ph()
    try:
        df = pd.read_sql_query(
            f"""
            SELECT id, organization_id, scan_id, hostname,
                   finding_vector, severity, status, notes
            FROM remediation_tasks
            WHERE organization_id = {ph}
              AND scan_id = {ph}
            ORDER BY id ASC
            """,
            conn,
            params=(int(organization_id), int(scan_id))
        )
    finally:
        conn.close()
    return df


def update_client_remediation_task(organization_id, task_id, new_status, note):
    if new_status not in {"Pendiente", "En Proceso", "Solucionado"}:
        raise ValueError("Estado no permitido.")

    conn = get_db_connection()
    c = conn.cursor()
    ph = _db_ph()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        c.execute(
            f"""
            UPDATE remediation_tasks
            SET status = {ph}, notes = {ph}
            WHERE id = {ph} AND organization_id = {ph}
            """,
            (new_status, (note or "").strip(), int(task_id), int(organization_id))
        )

        c.execute(
            f"""
            INSERT INTO remediation_logs (task_id, timestamp, status, notes)
            SELECT id, {ph}, {ph}, {ph}
            FROM remediation_tasks
            WHERE id = {ph} AND organization_id = {ph}
            """,
            (timestamp, new_status, (note or "").strip(), int(task_id), int(organization_id))
        )

        if "postgres" not in st.secrets:
            conn.commit()
    finally:
        c.close()
        conn.close()


def verify_solved_tasks_after_rescan(
    organization_id,
    source_scan_id,
    new_findings
):
    """Solo CyberAudits puede asignar Verificado."""
    remaining_vectors = {
        str(f.get("vector") or "").strip()
        for f in (new_findings or [])
        if is_actionable(f)
    }

    conn = get_db_connection()
    c = conn.cursor()
    ph = _db_ph()
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        c.execute(
            f"""
            SELECT id, finding_vector
            FROM remediation_tasks
            WHERE organization_id = {ph}
              AND scan_id = {ph}
              AND status = 'Solucionado'
            """,
            (int(organization_id), int(source_scan_id))
        )

        rows = c.fetchall()
        verified = 0

        for task_id, finding_vector in rows:
            if str(finding_vector or "").strip() in remaining_vectors:
                continue

            c.execute(
                f"""
                UPDATE remediation_tasks
                SET status = 'Verificado'
                WHERE id = {ph}
                  AND organization_id = {ph}
                """,
                (int(task_id), int(organization_id))
            )

            c.execute(
                f"""
                INSERT INTO remediation_logs
                (task_id, timestamp, status, notes)
                VALUES ({ph}, {ph}, 'Verificado', {ph})
                """,
                (
                    int(task_id),
                    now,
                    "CyberAudits volvió a evaluar el objetivo y el hallazgo ya no fue detectado."
                )
            )
            verified += 1

        if "postgres" not in st.secrets:
            conn.commit()

        return verified

    finally:
        c.close()
        conn.close()


def generate_client_docx(hostname, findings, cyber_score, profile, scan_meta=None):
    doc = Document()
    for section in doc.sections:
        section.top_margin = Inches(0.7)
        section.bottom_margin = Inches(0.7)
        section.left_margin = Inches(0.8)
        section.right_margin = Inches(0.8)

    logo_b64 = str(profile.get("logo_b64") or "")
    if logo_b64:
        try:
            logo_bytes = base64.b64decode(logo_b64)
            doc.add_picture(io.BytesIO(logo_bytes), width=Inches(1.45))
        except Exception:
            pass

    display_name = profile.get("display_name") or "Organización"
    recipient = profile.get("report_recipient") or "Dirección General"
    title = profile.get("report_title") or "Evaluación de Postura de Ciberseguridad"
    legal_name = profile.get("legal_name") or ""
    department = profile.get("department") or ""

    p = doc.add_paragraph()
    r = p.add_run(display_name)
    r.bold = True
    r.font.size = Pt(18)
    r.font.color.rgb = RGBColor(15, 23, 42)

    doc.add_paragraph(title)
    scan_meta = scan_meta or {}
    eval_state, eval_message = evaluation_status(scan_meta, findings)

    meta = (
        f"Dirigido a: {recipient}\n"
        f"Objetivo analizado: {hostname}\n"
        f"CyberScore técnico: {cyber_score}/100\n"
        f"Estado de evaluación: {eval_state}\n"
        f"Cobertura: {scan_meta.get('coverage', 'N/D')}%\n"
        f"Confianza: {scan_meta.get('confidence', 'N/D')}\n"
        f"Fecha: {datetime.datetime.now().strftime('%Y-%m-%d')}"
    )
    if legal_name:
        meta += f"\nRazón social: {legal_name}"
    if department:
        meta += f"\nÁrea responsable: {department}"
    doc.add_paragraph(meta)

    if eval_state != "COMPLETA":
        doc.add_paragraph(
            f"Nota de integridad: {eval_message} "
            "Un control no concluyente no se considera seguro ni vulnerable."
        )

    doc.add_heading("Resumen de hallazgos", level=2)
    if not findings:
        doc.add_paragraph("No se registraron hallazgos en esta evaluación.")
    else:
        for idx, f in enumerate(findings, 1):
            h = doc.add_paragraph().add_run(
                f"#{idx} · {f.get('vector', 'Hallazgo')} [{f.get('severity', 'INFORMATIVO')}]"
            )
            h.bold = True
            doc.add_paragraph(f"Descripción: {f.get('desc', 'N/A')}")
            doc.add_paragraph(f"Impacto: {f.get('impact', 'N/A')}")
            doc.add_paragraph(f"Recomendación: {f.get('fix', 'N/A')}")

    doc.add_paragraph()
    footer_text = profile.get("confidentiality_footer") or ""
    for section in doc.sections:
        footer = section.footer.paragraphs[0]
        footer.text = f"{footer_text} | Powered by CyberAudits"
        footer.alignment = 1

    buffer = io.BytesIO()
    doc.save(buffer)
    buffer.seek(0)
    return buffer.getvalue()


def generate_client_pdf(findings, hostname, cyber_score, profile, output_filename, scan_meta=None):
    scan_meta = scan_meta or {}
    eval_state, eval_message = evaluation_status(scan_meta, findings)

    display_name = html.escape(str(profile.get("display_name") or "Organización"))
    recipient = html.escape(str(profile.get("report_recipient") or "Dirección General"))
    title = html.escape(str(profile.get("report_title") or "Evaluación de Postura de Ciberseguridad"))
    legal_name = html.escape(str(profile.get("legal_name") or ""))
    department = html.escape(str(profile.get("department") or ""))
    footer_text = html.escape(str(profile.get("confidentiality_footer") or ""))
    logo_uri = _profile_logo_uri(profile)

    logo_html = (
        f'<img src="{logo_uri}" style="max-height:62px;max-width:190px;object-fit:contain;">'
        if logo_uri else ""
    )

    cards = ""
    if findings:
        for i, f in enumerate(findings, 1):
            severity = html.escape(str(f.get("severity", "INFORMATIVO")))
            cards += f"""
            <div class="card">
                <div class="card-title">#{i} · {html.escape(str(f.get('vector', 'Hallazgo')))} <span>{severity}</span></div>
                <p><strong>Descripción:</strong> {html.escape(str(f.get('desc', 'N/A')))}</p>
                <p><strong>Impacto:</strong> {html.escape(str(f.get('impact', 'N/A')))}</p>
                <p><strong>Recomendación:</strong> {html.escape(str(f.get('fix', 'N/A')))}</p>
            </div>
            """
    else:
        cards = "<p>No se registraron hallazgos en esta evaluación.</p>"

    extra_meta = ""
    if legal_name:
        extra_meta += f"<div><strong>Razón social:</strong> {legal_name}</div>"
    if department:
        extra_meta += f"<div><strong>Área responsable:</strong> {department}</div>"

    html_doc = f"""
    <html>
    <head>
    <style>
        @page {{ size: A4; margin: 14mm; @bottom-center {{ content: "Powered by CyberAudits"; color:#64748b; font-size:8pt; }} }}
        body {{ font-family: Arial, sans-serif; color:#172033; font-size:10pt; line-height:1.5; }}
        .header {{ background:#0b1220; color:white; padding:20px; border-radius:10px; }}
        .header h1 {{ margin:8px 0 3px 0; font-size:20pt; }}
        .header p {{ margin:0; color:#dbe7ff; }}
        .meta {{ margin-top:16px; padding:12px; border:1px solid #dfe5ef; border-radius:8px; background:#f8fafc; }}
        .score {{ font-size:25pt; font-weight:800; color:#174fcf; }}
        .card {{ border:1px solid #e1e7f0; border-radius:8px; padding:11px 13px; margin-top:10px; page-break-inside:avoid; }}
        .card-title {{ font-weight:700; margin-bottom:7px; }}
        .card-title span {{ float:right; font-size:8pt; background:#eef4ff; padding:2px 7px; border-radius:12px; }}
        .footer-note {{ margin-top:22px; color:#64748b; font-size:8.5pt; border-top:1px solid #e1e7f0; padding-top:9px; }}
        .trust-note {{ margin-top:12px; padding:10px 12px; border-left:4px solid #f59e0b; background:#fffbeb; border-radius:6px; }}
    </style>
    </head>
    <body>
        <div class="header">
            {logo_html}
            <h1>{display_name}</h1>
            <p>{title}</p>
        </div>
        <div class="meta">
            <div><strong>Dirigido a:</strong> {recipient}</div>
            <div><strong>Objetivo:</strong> {html.escape(str(hostname))}</div>
            <div><strong>Fecha:</strong> {datetime.datetime.now().strftime('%Y-%m-%d')}</div>
            <div><strong>Estado de evaluación:</strong> {html.escape(eval_state)}</div>
            <div><strong>Cobertura:</strong> {scan_meta.get('coverage', 'N/D')}%</div>
            <div><strong>Confianza:</strong> {html.escape(str(scan_meta.get('confidence', 'N/D')))}</div>
            {extra_meta}
            <div style="margin-top:8px;">CyberScore técnico <span class="score">{int(cyber_score)}/100</span></div>
        </div>
        {
            (
                '<div class="trust-note"><strong>Nota de integridad:</strong> '
                + html.escape(eval_message)
                + ' Un control no concluyente no se considera seguro ni vulnerable.</div>'
            )
            if eval_state != "COMPLETA"
            else ""
        }
        <h2>Hallazgos y recomendaciones</h2>
        {cards}
        <div class="footer-note">{footer_text}<br>Powered by CyberAudits</div>
    </body>
    </html>
    """

    HTML(string=html_doc).write_pdf(output_filename)


def get_client_primary_domain(organization_id, email):
    conn = get_db_connection()
    ph = _db_ph()

    try:
        df = pd.read_sql_query(
            f"""
            SELECT domain
            FROM public_leads
            WHERE organization_id = {ph}
               OR LOWER(email) = LOWER({ph})
            ORDER BY id DESC
            LIMIT 1
            """,
            conn,
            params=(organization_id, email)
        )
    finally:
        conn.close()

    if not df.empty:
        domain = str(df.iloc[0].get("domain") or "").strip().lower()
        if domain:
            return domain

    member = get_member_for_identity(email=email)
    if member:
        return str(member.get("organization_name") or "").strip().lower()

    return ""


def get_client_latest_lead(organization_id, email):
    conn = get_db_connection()
    ph = _db_ph()

    try:
        df = pd.read_sql_query(
            f"""
            SELECT
                id,
                email,
                domain,
                cyber_score,
                created_at,
                status
            FROM public_leads
            WHERE organization_id = {ph}
               OR LOWER(email) = LOWER({ph})
            ORDER BY id DESC
            LIMIT 1
            """,
            conn,
            params=(organization_id, email)
        )
    finally:
        conn.close()

    if df.empty:
        return None

    return df.iloc[0].to_dict()


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
    palette = {
        "Críticas": "#dc2626",
        "Medias": "#f59e0b",
        "Bajas": "#3b82f6",
        "Seguras": "#10b981",
        "Seguras verificadas": "#10b981",
        "No concluyentes": "#94a3b8"
    }

    non_zero = [
        (label, value, palette.get(label, "#64748b"))
        for label, value in stats.items()
        if int(value or 0) > 0
    ]

    if not non_zero:
        non_zero = [("Sin datos concluyentes", 1, "#94a3b8")]

    labels, sizes, colors = zip(*non_zero)
    fig, ax = plt.subplots(figsize=(4.5, 2.8))
    ax.pie(
        sizes,
        labels=labels,
        colors=colors,
        autopct='%1.1f%%',
        startangle=90,
        textprops={'fontsize': 8, 'weight': 'bold'}
    )
    ax.axis('equal')
    plt.tight_layout()

    chart_path = "vulnerability_chart.png"
    plt.savefig(chart_path, dpi=300, bbox_inches='tight', transparent=True)
    plt.close()

    with open(chart_path, "rb") as f:
        return base64.b64encode(f.read()).decode("utf-8")

def generate_docx(hostname, findings, risk_score, agency_name, agency_tagline, report_type, recipient_name, report_subject, scan_meta=None):
    scan_meta = scan_meta or {}
    eval_state, eval_message = evaluation_status(scan_meta, findings)

    doc = Document()
    for section in doc.sections: section.top_margin = section.bottom_margin = section.left_margin = section.right_margin = Inches(1)
    
    run_title = doc.add_paragraph().add_run(f"INFORME: {report_type.upper()}")
    run_title.font.size, run_title.font.bold, run_title.font.color.rgb = Pt(15), True, RGBColor(15, 23, 42)
    
    doc.add_paragraph(
        f"Emitido por: {agency_name} ({agency_tagline})\n"
        f"Dirigido a: {recipient_name} | Asunto: {report_subject}\n"
        f"Objetivo analizado: {hostname}\n"
        f"CyberScore técnico: {risk_score}/100 | Estado: {eval_state} | "
        f"Cobertura: {scan_meta.get('coverage', 'N/D')}% | "
        f"Confianza: {scan_meta.get('confidence', 'N/D')}"
    )

    if eval_state != "COMPLETA":
        doc.add_paragraph(
            f"Nota de integridad: {eval_message} "
            "Los controles no concluyentes no se contabilizan como seguros."
        )
    
    trust_note_html = (
        ""
        if eval_state == "COMPLETA"
        else (
            '<div class="trust-note"><strong>Nota de integridad:</strong> '
            + html.escape(eval_message)
            + ' Los controles no concluyentes no se contabilizan como seguros.</div>'
        )
    )

    if "Técnico" in report_type:
        doc.add_heading("Detalle Técnico y Bloques de Configuración", level=2)
        for idx, f in enumerate(findings, 1):
            h = doc.add_paragraph().add_run(f"#{idx} - {f['vector']} [{f['severity']}]")
            h.font.bold = True
            doc.add_paragraph(f"Descripción técnica: {f['desc']}")
            doc.add_paragraph(f"Impacto operativo: {f['impact']}")
            p_fix = doc.add_paragraph()
            snippet_text = (
                f.get("snippet")
                or (
                    "No aplica: el control no pudo verificarse de forma concluyente."
                    if not f.get("verified", True)
                    else f.get("fix", "Sin bloque de configuración específico.")
                )
            )
            p_fix.add_run(
                f"Remediación técnica / Snippet:\n{snippet_text}"
            ).font.bold = True
            
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

def generate_pdf(findings, chart_b64, hostname, risk_score, agency_name, agency_tagline, report_type, recipient_name, report_subject, output_filename, scan_meta=None):
    scan_meta = scan_meta or {}
    eval_state, eval_message = evaluation_status(scan_meta, findings)

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
        td { vertical-align: top; word-break: break-word; overflow-wrap: anywhere; }
        .trust-note { margin: 10px 0 16px 0; padding: 9px 11px; background:#fffbeb; border-left:4px solid #f59e0b; border-radius:5px; }
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
                    <tr>
                        <td><strong>Estado:</strong> {eval_state} · <strong>Cobertura:</strong> {scan_meta.get('coverage', 'N/D')}%</td>
                        <td><strong>Confianza:</strong> {scan_meta.get('confidence', 'N/D')}</td>
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
                    <tr>
                        <td><strong>Estado:</strong> {eval_state} · <strong>Cobertura:</strong> {scan_meta.get('coverage', 'N/D')}%</td>
                        <td><strong>Confianza:</strong> {scan_meta.get('confidence', 'N/D')}</td>
                    </tr>
                </table>
            </div>
        """

    if "Técnico" in report_type:
        content = header_html + trust_note_html + f"""
            <h2 class="title">1. Resumen Técnico de Postura</h2>
            <p>CyberScore técnico sobre controles verificados: <strong>{risk_score}/100</strong>.</p>
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
                        <code>{html.escape(str(
                            f.get('snippet')
                            or (
                                "No aplica: el control no pudo verificarse de forma concluyente."
                                if not f.get("verified", True)
                                else f.get("fix", "Sin bloque de configuración específico.")
                            )
                        ))}</code>
                    </div>
                </div>
            </div>
            """
            
    elif "Narrativo" in report_type:
        content = header_html + trust_note_html + f"""
            <h2 class="title">Informe Ejecutivo y Situación Actual</h2>
            <p>Estimado/a <strong>{recipient_name}</strong>,</p>
            <p>Por medio del presente documento, el equipo de auditoría emite el dictamen gerencial respecto al análisis perimetral realizado sobre el objetivo <strong>{hostname}</strong>. Tras la evaluación, se ha calculado un CyberScore técnico de <strong>{risk_score} sobre 100</strong> sobre los controles que pudieron verificarse de forma concluyente.</p>
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
        content = header_html + trust_note_html + f"""
            <h2 class="title">1. Mapa Orientativo de Controles (ISO 27001 / NIST)</h2>
            <p>CyberScore técnico sobre controles verificados: <strong>{risk_score}/100</strong>. Este informe relaciona hallazgos técnicos con referencias de buenas prácticas y no constituye una certificación de cumplimiento.</p>
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


def evaluation_status(meta, findings=None):
    """Clasifica la completitud sin confundir no-concluyente con seguro."""
    meta = meta or {}
    findings = findings or []

    if meta.get("legacy_meta"):
        return (
            "PARCIAL",
            "Este registro histórico no contiene el detalle completo de cobertura de las versiones actuales."
        )

    for finding in findings:
        if (
            finding.get("category") == "Validación"
            and finding.get("severity") == "CRÍTICO"
        ):
            return (
                "FALLIDA",
                "La evaluación no pudo iniciarse o completarse de forma válida."
            )

    evaluated = meta.get("evaluated_by_category") or {}
    inconclusive_map = meta.get("inconclusive_by_category") or {}

    verified_checks = meta.get("verified_checks")
    if verified_checks is None:
        verified_checks = sum(int(v or 0) for v in evaluated.values())

    inconclusive = sum(int(v or 0) for v in inconclusive_map.values())
    coverage = int(meta.get("coverage", 0) or 0)

    if int(verified_checks or 0) <= 0:
        return (
            "FALLIDA",
            "No hubo controles suficientes verificados para emitir una evaluación."
        )

    if inconclusive > 0 or coverage < 100:
        return (
            "PARCIAL",
            "El CyberScore se calcula únicamente sobre los controles que pudieron verificarse."
        )

    return (
        "COMPLETA",
        "Todos los controles intentados en esta evaluación fueron concluyentes."
    )


def trusted_score_status(score, meta, findings=None):
    state, message = evaluation_status(meta, findings)

    if state == "FALLIDA":
        return "EVALUACIÓN FALLIDA", message

    if state == "PARCIAL":
        return "EVALUACIÓN PARCIAL", message

    return score_status(score)


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
    inconclusive = (
        (scan_details or {}).get("inconclusive_by_category", {})
    )

    result = {}

    for label, categories in groups.items():
        evaluated_count = sum(
            int(evaluated.get(category, 0) or 0)
            for category in categories
        )
        inconclusive_count = sum(
            int(inconclusive.get(category, 0) or 0)
            for category in categories
        )

        # Un control inconcluso nunca se presenta como 100/100.
        if scan_details is not None and inconclusive_count > 0:
            result[label] = None
            continue

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

    evaluated_map = scan_details.get("evaluated_by_category", {})
    inconclusive_map = scan_details.get("inconclusive_by_category", {})

    inconclusive = sum(
        int(v or 0)
        for v in inconclusive_map.values()
    )

    if scan_details:
        # Incluye controles informativos que sí fueron verificados.
        verified_checks = sum(
            int(v or 0)
            for v in evaluated_map.values()
        )
    else:
        verified_checks = int(sum(stats.values()))
        inconclusive = sum(
            1
            for f in findings
            if (
                f.get("severity") == "INFORMATIVO"
                and not f.get("verified", True)
            )
        )

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

    meta = {
        "verified_checks": verified_checks,
        "total_checks": total_checks,
        "coverage": coverage,
        "confidence": confidence,
        "category_scores": category_scores(findings, scan_details),
        "email_domain": scan_details.get("email_domain", ""),
        "evaluated_by_category": evaluated_map,
        "inconclusive_by_category": inconclusive_map,
        "dnssec_ad": scan_details.get("dnssec_ad")
    }

    state, _ = evaluation_status(meta, findings)
    meta["evaluation_status"] = state
    return meta


def fallback_scan_meta(findings):
    inconclusive = sum(
        1
        for f in findings
        if (
            f.get("severity") == "INFORMATIVO"
            and not f.get("verified", True)
        )
    )

    groups = {
        "TLS & Certificado": {"TLS"},
        "Seguridad Web": {"Headers", "Cookies"},
        "Transporte": {"Transporte"},
        "Exposición": {"Exposición"},
        "DNS Security": {"DNS"},
        "Email Security": {"Email"}
    }

    legacy_scores = {}
    for label, categories in groups.items():
        category_findings = [
            f for f in findings
            if f.get("category") in categories
        ]
        if not category_findings:
            legacy_scores[label] = None
            continue

        if any(not f.get("verified", True) for f in category_findings):
            legacy_scores[label] = None
            continue

        penalty = sum(
            finding_weight(f)
            for f in category_findings
            if is_actionable(f)
        )
        legacy_scores[label] = max(0, 100 - min(100, penalty))

    return {
        "verified_checks": max(1, len(findings) - inconclusive),
        "total_checks": max(1, len(findings)),
        "coverage": 80 if inconclusive else 100,
        "confidence": "BAJA",
        "category_scores": legacy_scores,
        "evaluated_by_category": {},
        "inconclusive_by_category": (
            {"Legacy": inconclusive}
            if inconclusive
            else {}
        ),
        "legacy_meta": True,
        "evaluation_status": "PARCIAL"
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
        scan_meta_json,
        target_url
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


def evaluation_target(row):
    try:
        target = row.get("target_url")
    except Exception:
        target = None

    if target is not None:
        try:
            if not pd.isna(target) and str(target).strip():
                return str(target).strip()
        except Exception:
            if str(target).strip():
                return str(target).strip()

    try:
        hostname = str(row.get("hostname") or "").strip()
    except Exception:
        hostname = ""

    return f"https://{hostname}" if hostname else "Objetivo sin identificar"


def evaluation_label(row):
    findings = safe_findings(row.get("findings_json"))
    meta = safe_meta(row.get("scan_meta_json")) or fallback_scan_meta(findings)
    state, _ = evaluation_status(meta, findings)

    return (
        f"#{int(row['id'])} · {row['timestamp']} · "
        f"{evaluation_target(row)} · "
        f"CyberScore {int(row['risk_score'])}/100 · {state}"
    )


def history_row_by_id(history_df, scan_id):
    if history_df is None or history_df.empty:
        return None

    match = history_df[
        history_df["id"].astype(int) == int(scan_id)
    ]

    if match.empty:
        return None

    return match.iloc[0]


def normalize_client_target_url(raw_url, authorized_domain):
    normalized, hostname = _normalize_target(raw_url)

    authorized = (authorized_domain or "").strip().lower()
    if not authorized:
        raise ValueError("La organización no tiene un dominio autorizado.")

    allowed_hosts = {authorized}
    if authorized.startswith("www."):
        allowed_hosts.add(authorized[4:])
    else:
        allowed_hosts.add("www." + authorized)

    if hostname not in allowed_hosts:
        raise ValueError(
            "Solo podés evaluar páginas del dominio autorizado "
            f"({authorized})."
        )

    parsed = urlparse(normalized)

    # Fragmentos (#...) son solo del navegador y no forman parte
    # del recurso HTTP que CyberAudits evalúa.
    clean_url = parsed._replace(fragment="").geturl()

    return clean_url, hostname


def prepare_scan_selector_state(key, scan_ids):
    """
    Mantiene los selectores consistentes después de crear o borrar escaneos.
    """
    if not scan_ids:
        st.session_state.pop(key, None)
        return

    current = st.session_state.get(key)

    try:
        current = int(current)
    except Exception:
        current = None

    if current not in scan_ids:
        st.session_state[key] = int(scan_ids[0])



def queue_client_scan_selection(scan_id):
    """
    Programa qué evaluación debe quedar seleccionada en Hallazgos,
    Remediación e Informes para el SIGUIENTE rerun.

    No modifica directamente claves de widgets ya instanciados.
    """
    st.session_state[
        "client_pending_scan_selection_v210"
    ] = int(scan_id)


def apply_client_scan_selection_queue():
    """
    Aplica la selección pendiente antes de crear los selectbox del portal.
    """
    pending = st.session_state.pop(
        "client_pending_scan_selection_v210",
        None
    )

    if pending is None:
        return

    pending = int(pending)

    for selector_key in (
        "client_findings_scan_v210",
        "client_remediation_scan_v210",
        "client_report_scan_v210"
    ):
        st.session_state[selector_key] = pending



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
    status_label, status_description = trusted_score_status(score, meta, findings)
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
            <h1>Descubrí qué ve Internet de tu empresa antes de que se convierta en un problema.</h1>
            <p>
                Analizamos señales públicas de HTTPS, TLS, cabeceras y DNS,
                las convertimos en un CyberScore fácil de entender y te mostramos
                qué conviene revisar primero.
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

        status_label, status_description = trusted_score_status(score, meta, findings)

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

    st.markdown("### Accesos")

    client_access_col, admin_access_col = st.columns(2)

    with client_access_col:
        st.markdown("#### 👤 Soy cliente")
        st.caption(
            "Ingresá a tu organización, revisá tu CyberScore, "
            "hallazgos e informes."
        )

        if st.button(
            "Entrar al portal cliente",
            type="primary",
            use_container_width=True,
            key="public_client_login"
        ):
            st.query_params["client"] = "1"
            st.rerun()

    with admin_access_col:
        st.markdown("#### 🛠️ Administración")
        st.caption(
            "Workspace privado para gestionar clientes, leads, "
            "reportes y CyberPass."
        )

        if st.button(
            "Entrar al workspace privado",
            use_container_width=True,
            key="public_admin_login"
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



def _clear_client_session():
    for key in [
        "client_authenticated",
        "client_email",
        "client_user_id",
        "client_access_token",
        "client_refresh_token",
        "client_organization_id",
        "client_organization_name",
        "client_role",
        "client_must_change_password"
    ]:
        st.session_state.pop(key, None)


def render_client_login():
    st.markdown(
        """
        <div style="max-width:760px;margin:55px auto 20px auto;">
            <div class="public-score-card">
                <div class="ca-kicker">CYBERAUDITS CLIENT PORTAL</div>
                <h1 style="margin:10px 0 6px 0;">Acceso de cliente</h1>
                <p class="muted">
                    Ingresá con el email aprobado y la contraseña de acceso
                    entregada para tu organización.
                </p>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    with st.form("client_login_form"):
        email = st.text_input(
            "Email",
            placeholder="vos@empresa.com"
        )

        password = st.text_input(
            "Contraseña",
            type="password"
        )

        login = st.form_submit_button(
            "Entrar a mi organización",
            type="primary",
            use_container_width=True
        )

    if login:
        try:
            with st.spinner("Validando acceso..."):
                session = supabase_password_login(
                    email,
                    password
                )

                user = session["user"]

                member = get_member_for_identity(
                    user_id=user.get("id"),
                    email=email
                )

                if not member:
                    raise RuntimeError(
                        "Tu usuario existe, pero todavía no está asociado "
                        "a una organización de CyberAudits."
                    )

                if str(member.get("status")) not in {
                    "Activo",
                    "Confirmado",
                    "Invitado"
                }:
                    raise RuntimeError(
                        "Tu acceso todavía no está habilitado."
                    )

                st.session_state.client_authenticated = True
                st.session_state.client_email = (
                    str(member.get("email") or email).strip().lower()
                )
                st.session_state.client_user_id = str(user.get("id"))
                st.session_state.client_access_token = session["access_token"]
                st.session_state.client_refresh_token = session.get("refresh_token")
                st.session_state.client_organization_id = int(
                    member["organization_id"]
                )
                st.session_state.client_organization_name = str(
                    member.get("organization_name")
                    or "Mi organización"
                )
                st.session_state.client_role = str(
                    member.get("role")
                    or "CLIENT"
                )
                st.session_state.client_must_change_password = bool(
                    int(member.get("must_change_password") or 0)
                )

                mark_member_login(
                    st.session_state.client_email
                )

            st.rerun()

        except Exception as e:
            st.error(
                f"No se pudo iniciar sesión: {e}"
            )

    st.markdown("---")

    left, right = st.columns(2)

    with left:
        if st.button(
            "← Volver al CyberCheck",
            use_container_width=True
        ):
            try:
                st.query_params.clear()
            except Exception:
                pass
            st.rerun()

    with right:
        st.caption(
            "¿Todavía no tenés acceso? Ejecutá el Free CyberCheck "
            "y solicitá acceso a la beta."
        )

    st.stop()


def render_client_password_change():
    st.markdown(
        """
        <div style="max-width:760px;margin:45px auto 20px auto;">
            <div class="public-score-card">
                <div class="ca-kicker">PRIMER ACCESO</div>
                <h1 style="margin:10px 0 6px 0;">Creá tu contraseña personal</h1>
                <p class="muted">
                    La contraseña temporal solo sirve para el primer ingreso.
                    Elegí ahora una contraseña que solo vos conozcas.
                </p>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    with st.form("client_force_password_change"):
        new_password = st.text_input(
            "Nueva contraseña",
            type="password",
            help="Mínimo 12 caracteres."
        )

        repeat_password = st.text_input(
            "Repetir nueva contraseña",
            type="password"
        )

        save = st.form_submit_button(
            "Guardar mi contraseña",
            type="primary",
            use_container_width=True
        )

    if save:
        if new_password != repeat_password:
            st.error("Las contraseñas no coinciden.")
        elif len(new_password) < 12:
            st.error(
                "Usá una contraseña de al menos 12 caracteres."
            )
        else:
            try:
                supabase_user_change_password(
                    st.session_state.client_access_token,
                    new_password
                )

                set_member_password_change_required(
                    st.session_state.client_email,
                    False
                )

                st.session_state.client_must_change_password = False

                st.success(
                    "Contraseña actualizada. Tu portal ya está habilitado."
                )
                st.rerun()

            except Exception as e:
                st.error(
                    f"No se pudo cambiar la contraseña: {e}"
                )

    if st.button(
        "Cerrar sesión",
        use_container_width=True
    ):
        _clear_client_session()

        try:
            st.query_params.clear()
        except Exception:
            pass

        st.rerun()

    st.stop()


def render_client_portal():
    if not st.session_state.get("client_authenticated", False):
        render_client_login()

    current_member = get_member_for_identity(
        user_id=st.session_state.get("client_user_id"),
        email=st.session_state.get("client_email")
    )

    if (
        not current_member
        or str(current_member.get("status") or "") == "Suspendido"
    ):
        _clear_client_session()
        st.error("Tu acceso a CyberAudits fue suspendido por un administrador.")
        st.caption(
            "Tus evaluaciones e informes no fueron eliminados. "
            "Contactá al administrador si necesitás recuperar el acceso."
        )
        if st.button("Volver a la página pública", use_container_width=True):
            try:
                st.query_params.clear()
            except Exception:
                pass
            st.rerun()
        st.stop()

    if st.session_state.get("client_must_change_password", False):
        render_client_password_change()

    org_id = int(st.session_state.client_organization_id)
    org_name = st.session_state.get("client_organization_name", "Mi organización")
    client_email = st.session_state.get("client_email", "")
    primary_domain = get_client_primary_domain(org_id, client_email)

    org_profile = get_organization_profile(org_id, fallback_name=org_name)
    display_org_name = str(org_profile.get("display_name") or org_name).strip()
    logo_uri = _profile_logo_uri(org_profile)

    # Important: apply a queued scan selection BEFORE any selectbox
    # using these session-state keys is instantiated.
    apply_client_scan_selection_queue()

    st.sidebar.markdown("## 🛡️ CyberAudits")
    st.sidebar.caption("Portal Cliente")
    st.sidebar.markdown(f"**{display_org_name}**")
    if primary_domain:
        st.sidebar.caption(primary_domain)
    st.sidebar.caption(client_email)

    if st.sidebar.button("Cerrar sesión", use_container_width=True):
        _clear_client_session()
        try:
            st.query_params.clear()
        except Exception:
            pass
        st.rerun()

    logo_html = (
        f'<img src="{logo_uri}" style="max-height:58px;max-width:180px;object-fit:contain;background:white;border-radius:10px;padding:6px;margin-bottom:12px;">'
        if logo_uri else ""
    )

    # Build the header without Markdown-sensitive blank lines.
    # When logo_html was empty, Markdown could interpret the following
    # indented <h1>/<p> tags as a code block.
    brand_html = (
        '<div class="ca-brand">'
        '<div class="ca-kicker">CYBERAUDITS · PORTAL CLIENTE PRO</div>'
        f'{logo_html}'
        f'<h1>{html.escape(display_org_name)}</h1>'
        f'<p>{html.escape(primary_domain or "Dominio pendiente")} · '
        'Seguridad, remediación e informes en un único lugar.</p>'
        '</div>'
    )

    st.markdown(
        brand_html,
        unsafe_allow_html=True
    )

    (
        tab_summary,
        tab_scan,
        tab_findings,
        tab_remediation,
        tab_reports,
        tab_org,
        tab_account
    ) = st.tabs([
        "🏠 Resumen",
        "🔎 Evaluaciones",
        "🧭 Hallazgos",
        "🛠 Remediación",
        "📄 Informes",
        "🏢 Organización",
        "👤 Cuenta"
    ])

    # --------------------------------------------------------
    # RESUMEN
    # --------------------------------------------------------
    with tab_summary:
        history_df = load_history(org_id)
        lead = get_client_latest_lead(org_id, client_email)

        if history_df.empty:
            baseline_score = None
            if lead and lead.get("cyber_score") is not None and pd.notna(lead.get("cyber_score")):
                baseline_score = int(lead["cyber_score"])

            st.subheader("Bienvenido a CyberAudits")
            c1, c2, c3 = st.columns(3)
            c1.metric("CyberScore preliminar", f"{baseline_score}/100" if baseline_score is not None else "N/D")
            c2.metric("Dominio", primary_domain or "N/D")
            c3.metric("Evaluación completa", "Pendiente")
            st.info(
                "Tu resultado actual proviene del Free CyberCheck. Ejecutá una evaluación "
                "desde la pestaña Evaluaciones para crear historial, hallazgos y reportes."
            )
        else:
            latest = history_df.iloc[0]
            findings = safe_findings(latest["findings_json"])
            meta = safe_meta(latest.get("scan_meta_json")) or fallback_scan_meta(findings)
            score = int(latest["risk_score"])
            label, description = trusted_score_status(
                score,
                meta,
                findings
            )
            eval_state, eval_message = evaluation_status(
                meta,
                findings
            )
            actionable = [f for f in findings if is_actionable(f)]

            score_col, info_col = st.columns([1.05, 2.2])
            with score_col:
                st.markdown(
                    f"""
                    <div class="score-shell">
                        <div class="muted">CyberScore</div>
                        <div style="margin-top:14px;"><span class="score-number">{score}</span><span class="score-denom">/100</span></div>
                        <span class="score-label">{html.escape(label)}</span>
                        <p class="muted" style="margin-top:16px;">{html.escape(description)}</p>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

            with info_col:
                m1, m2, m3 = st.columns(3)
                m1.metric("Cobertura", f"{meta.get('coverage', 0)}%")
                m2.metric("Confianza", meta.get("confidence", "N/D"))
                m3.metric("Hallazgos a atender", len(actionable))

                s1, s2, s3 = st.columns(3)
                s1.metric("Críticos", sum(1 for f in actionable if f.get("severity") == "CRÍTICO"))
                s2.metric("Medios", sum(1 for f in actionable if f.get("severity") == "MEDIO"))
                s3.metric("Bajos", sum(1 for f in actionable if f.get("severity") == "BAJO"))

                st.caption(
                    f"Última evaluación #{int(latest['id'])}: "
                    f"{latest['timestamp']} · {evaluation_target(latest)}"
                )

            if eval_state == "PARCIAL":
                st.warning("⚠️ Evaluación parcial: " + eval_message)
            elif eval_state == "FALLIDA":
                st.error("❌ Evaluación fallida: " + eval_message)
            else:
                st.success("✅ Evaluación completa: " + eval_message)

            st.markdown("### Postura por categoría")
            categories = meta.get("category_scores", {}) if isinstance(meta, dict) else {}
            labels = [
                "TLS & Certificado", "Seguridad Web", "Transporte",
                "Exposición", "DNS Security", "Email Security"
            ]
            for start in (0, 3):
                cols = st.columns(3)
                for col, name in zip(cols, labels[start:start+3]):
                    value = categories.get(name)
                    with col:
                        st.metric(name, "N/D" if value is None else f"{int(value)}/100")

            st.markdown("### Prioridades")
            if actionable:
                ordered = sorted(
                    actionable,
                    key=lambda f: {"CRÍTICO": 0, "MEDIO": 1, "BAJO": 2}.get(f.get("severity"), 9)
                )
                for finding in ordered[:3]:
                    render_finding_card(finding)
            else:
                st.success("No hay hallazgos accionables en los controles verificados.")

            if len(history_df) >= 2:
                trend = history_df.copy()
                trend["timestamp_dt"] = pd.to_datetime(trend["timestamp"], errors="coerce")
                trend = trend.sort_values("timestamp_dt")
                chart_df = (
                    trend[["timestamp_dt", "risk_score"]]
                    .dropna()
                    .set_index("timestamp_dt")
                    .rename(columns={"risk_score": "CyberScore"})
                )
                st.markdown("### Evolución")
                st.line_chart(chart_df)

    # --------------------------------------------------------
    # EVALUACIONES
    # --------------------------------------------------------
    with tab_scan:
        st.subheader("Evaluaciones")

        scan_notice = st.session_state.pop("client_scan_notice_v210", None)
        if scan_notice:
            st.success(scan_notice)

        if not primary_domain:
            st.error(
                "No hay un dominio asociado a tu organización. "
                "Contactá al administrador."
            )
        else:
            st.write(f"Dominio autorizado: **{primary_domain}**")
            st.caption(
                "Podés evaluar distintas páginas/URLs dentro de este dominio. "
                "Cada ejecución queda guardada como una evaluación independiente."
            )

            target_url_input = st.text_input(
                "Página o URL a evaluar",
                value=f"https://{primary_domain}/",
                placeholder=f"https://{primary_domain}/ruta",
                key="client_target_url_v210",
                help=(
                    "Podés cambiar la ruta (/login, /contacto, /app, etc.). "
                    "Por seguridad no se permiten otros dominios desde este portal."
                )
            )

            email_domain = st.text_input(
                "Dominio corporativo de correo · opcional",
                value="",
                placeholder="empresa.com",
                key="client_email_domain_v210",
                help=(
                    "Completalo únicamente si ese dominio realmente se usa "
                    "para el correo de la empresa."
                )
            )

            if st.button(
                "🚀 Ejecutar evaluación",
                type="primary",
                use_container_width=True,
                key="client_run_scan_v210"
            ):
                try:
                    normalized_target, _ = normalize_client_target_url(
                        target_url_input,
                        primary_domain
                    )

                    with st.spinner("Analizando postura de seguridad..."):
                        (
                            findings,
                            stats,
                            hostname,
                            geo,
                            risk_score,
                            scan_details
                        ) = scan_target(
                            normalized_target,
                            email_domain
                        )

                        scan_meta = build_scan_meta(
                            stats,
                            findings,
                            scan_details
                        )

                        findings_count = count_actionable(findings)

                        scan_id = save_scan_to_db(
                            hostname,
                            geo.get("ip", "N/A"),
                            risk_score,
                            findings_count,
                            "Client Security Assessment",
                            org_id,
                            findings,
                            scan_meta,
                            target_url=normalized_target
                        )

                    # La evaluación recién creada quedará seleccionada
                    # en el próximo rerun, antes de instanciar los selectbox.
                    queue_client_scan_selection(scan_id)

                    st.session_state[
                        "client_scan_notice_v210"
                    ] = (
                        f"Evaluación #{scan_id} completada · "
                        f"{normalized_target} · CyberScore {risk_score}/100"
                    )

                    st.rerun()

                except Exception as e:
                    st.error(
                        f"No se pudo completar la evaluación: {e}"
                    )

        history_df = load_history(org_id)

        st.markdown("---")
        st.markdown("### Evaluaciones guardadas")

        if history_df.empty:
            st.info(
                "Todavía no hay evaluaciones guardadas para esta organización."
            )
        else:
            st.caption(
                f"{len(history_df)} evaluación(es), ordenadas de la más nueva "
                "a la más antigua."
            )

            pending_delete = st.session_state.get(
                "client_pending_delete_scan_v210"
            )

            if pending_delete is not None:
                pending_row = history_row_by_id(
                    history_df,
                    pending_delete
                )

                if pending_row is None:
                    st.session_state.pop(
                        "client_pending_delete_scan_v210",
                        None
                    )
                else:
                    st.warning(
                        "Vas a eliminar únicamente esta evaluación y sus "
                        "tickets de remediación asociados:\n\n"
                        f"**{evaluation_label(pending_row)}**"
                    )

                    confirm_col, cancel_col = st.columns(2)

                    with confirm_col:
                        if st.button(
                            "🗑️ Sí, eliminar evaluación",
                            type="primary",
                            use_container_width=True,
                            key="client_confirm_delete_scan_v210"
                        ):
                            delete_client_scan(
                                org_id,
                                int(pending_row["id"])
                            )

                            deleted_id = int(pending_row["id"])

                            for selector_key in (
                                "client_findings_scan_v210",
                                "client_remediation_scan_v210",
                                "client_report_scan_v210"
                            ):
                                try:
                                    if int(
                                        st.session_state.get(
                                            selector_key,
                                            -1
                                        )
                                    ) == deleted_id:
                                        st.session_state.pop(
                                            selector_key,
                                            None
                                        )
                                except Exception:
                                    st.session_state.pop(
                                        selector_key,
                                        None
                                    )

                            st.session_state.pop(
                                "client_pending_delete_scan_v210",
                                None
                            )

                            st.session_state[
                                "client_scan_notice_v210"
                            ] = (
                                f"Evaluación #{deleted_id} eliminada "
                                "junto con sus tickets asociados."
                            )

                            st.rerun()

                    with cancel_col:
                        if st.button(
                            "Cancelar",
                            use_container_width=True,
                            key="client_cancel_delete_scan_v210"
                        ):
                            st.session_state.pop(
                                "client_pending_delete_scan_v210",
                                None
                            )
                            st.rerun()

            with st.expander(
                "🗂️ Gestionar historial de evaluaciones",
                expanded=True
            ):
                for _, scan_row in history_df.iterrows():
                    scan_id = int(scan_row["id"])
                    info_col, delete_col = st.columns(
                        [8.6, 1.4],
                        vertical_alignment="center"
                    )

                    with info_col:
                        st.markdown(
                            f"**#{scan_id} · "
                            f"{html.escape(evaluation_target(scan_row))}**"
                        )
                        st.caption(
                            f"{scan_row['timestamp']} · "
                            f"CyberScore {int(scan_row['risk_score'])}/100 · "
                            f"{int(scan_row['findings_count'] or 0)} hallazgo(s) · "
                            f"{scan_row['report_type']}"
                        )

                    with delete_col:
                        if st.button(
                            "🗑️ Eliminar",
                            key=f"client_delete_scan_{scan_id}_v210",
                            use_container_width=True
                        ):
                            st.session_state[
                                "client_pending_delete_scan_v210"
                            ] = scan_id
                            st.rerun()

    # --------------------------------------------------------
    # HALLAZGOS
    # --------------------------------------------------------
    with tab_findings:
        st.subheader("Hallazgos")

        history_df = load_history(org_id)

        if history_df.empty:
            st.info(
                "Ejecutá tu primera evaluación para ver sus hallazgos."
            )
        else:
            scan_ids = [
                int(value)
                for value in history_df["id"].tolist()
            ]

            prepare_scan_selector_state(
                "client_findings_scan_v210",
                scan_ids
            )

            selected_scan_id = st.selectbox(
                "Seleccioná la evaluación",
                options=scan_ids,
                format_func=lambda scan_id: evaluation_label(
                    history_row_by_id(history_df, scan_id)
                ),
                key="client_findings_scan_v210"
            )

            selected_scan = history_row_by_id(
                history_df,
                selected_scan_id
            )

            st.info(
                f"Mostrando solamente la evaluación "
                f"**#{int(selected_scan['id'])}** · "
                f"**{evaluation_target(selected_scan)}** · "
                f"{selected_scan['timestamp']} · "
                f"CyberScore {int(selected_scan['risk_score'])}/100"
            )

            findings = safe_findings(
                selected_scan["findings_json"]
            )

            actionable = [
                f for f in findings
                if is_actionable(f)
            ]

            if not actionable:
                st.success(
                    "No hay hallazgos accionables en esta evaluación."
                )
            else:
                c1, c2, c3 = st.columns(3)
                c1.metric(
                    "Críticos",
                    sum(
                        1 for f in actionable
                        if f.get("severity") == "CRÍTICO"
                    )
                )
                c2.metric(
                    "Medios",
                    sum(
                        1 for f in actionable
                        if f.get("severity") == "MEDIO"
                    )
                )
                c3.metric(
                    "Bajos",
                    sum(
                        1 for f in actionable
                        if f.get("severity") == "BAJO"
                    )
                )

                for finding in sorted(
                    actionable,
                    key=lambda f: {
                        "CRÍTICO": 0,
                        "MEDIO": 1,
                        "BAJO": 2
                    }.get(f.get("severity"), 9)
                ):
                    render_finding_card(finding)

                    with st.expander(
                        f"Cómo corregir · "
                        f"{finding.get('vector', 'Hallazgo')}"
                    ):
                        st.write(
                            f"**Qué detectamos:** "
                            f"{finding.get('desc', 'N/A')}"
                        )
                        st.write(
                            f"**Impacto:** "
                            f"{finding.get('impact', 'N/A')}"
                        )
                        st.info(
                            f"**Recomendación:** "
                            f"{finding.get('fix', 'N/A')}"
                        )
                        if finding.get("snippet"):
                            st.code(finding.get("snippet"))

    # --------------------------------------------------------
    # REMEDIACION
    # --------------------------------------------------------
    with tab_remediation:
        st.subheader("Remediación")

        verify_notice = st.session_state.pop(
            "client_verify_notice_v210",
            None
        )
        if verify_notice:
            notice_type = verify_notice.get("type")
            notice_text = verify_notice.get("text", "")
            if notice_type == "success":
                st.success(notice_text)
            elif notice_type == "warning":
                st.warning(notice_text)
            else:
                st.info(notice_text)

        history_df = load_history(org_id)

        if history_df.empty:
            st.info(
                "Ejecutá una evaluación para generar tareas de remediación."
            )
        else:
            scan_ids = [
                int(value)
                for value in history_df["id"].tolist()
            ]

            prepare_scan_selector_state(
                "client_remediation_scan_v210",
                scan_ids
            )

            selected_scan_id = st.selectbox(
                "Seleccioná la evaluación",
                options=scan_ids,
                format_func=lambda scan_id: evaluation_label(
                    history_row_by_id(history_df, scan_id)
                ),
                key="client_remediation_scan_v210"
            )

            selected_scan = history_row_by_id(
                history_df,
                selected_scan_id
            )

            scan_id = int(selected_scan["id"])
            selected_target = evaluation_target(selected_scan)

            st.info(
                f"Gestionando solamente la evaluación **#{scan_id}** · "
                f"**{selected_target}** · "
                f"{selected_scan['timestamp']}"
            )

            tasks_df = get_client_remediation_tasks(
                org_id,
                scan_id
            )

            if tasks_df.empty:
                st.success(
                    "No hay tickets de remediación asociados "
                    "a esta evaluación."
                )
            else:
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Pendientes", int((tasks_df["status"] == "Pendiente").sum()))
                c2.metric("En proceso", int((tasks_df["status"] == "En Proceso").sum()))
                c3.metric("Solucionados", int((tasks_df["status"] == "Solucionado").sum()))
                c4.metric("Verificados", int((tasks_df["status"] == "Verificado").sum()))

                for _, task in tasks_df.iterrows():
                    task_id = int(task["id"])
                    current_status = str(
                        task["status"] or "Pendiente"
                    )
                    severity = str(
                        task["severity"] or "MEDIO"
                    )

                    st.markdown(
                        f"""
                        <div class="ticket-card {severity_class(severity)}">
                            <div class="finding-title">
                                {html.escape(str(task['finding_vector']))}
                            </div>
                            <div class="finding-meta">
                                Severidad {html.escape(severity)}
                                · Estado {html.escape(current_status)}
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )

                    if current_status == "Verificado":
                        st.success(
                            "✅ Verificado por CyberAudits mediante una evaluación posterior."
                        )
                        continue

                    with st.form(
                        f"client_task_{task_id}_v210"
                    ):
                        statuses = [
                            "Pendiente",
                            "En Proceso",
                            "Solucionado"
                        ]

                        new_status = st.selectbox(
                            "Estado",
                            statuses,
                            index=(
                                statuses.index(current_status)
                                if current_status in statuses
                                else 0
                            ),
                            key=f"client_task_status_{task_id}_v210"
                        )

                        note = st.text_input(
                            "Nota / evidencia",
                            value=str(
                                task.get("notes") or ""
                            ),
                            placeholder=(
                                "Ej.: configuración aplicada "
                                "en producción"
                            ),
                            key=f"client_task_note_{task_id}_v210"
                        )

                        save_task = st.form_submit_button(
                            "Guardar actualización",
                            use_container_width=True
                        )

                    if save_task:
                        try:
                            update_client_remediation_task(
                                org_id,
                                task_id,
                                new_status,
                                note
                            )
                            st.success(
                                "Tarea actualizada."
                            )
                            st.rerun()
                        except Exception as e:
                            st.error(
                                f"No se pudo actualizar: {e}"
                            )

            st.markdown("---")
            st.markdown("### Verificar esta evaluación")

            st.caption(
                "CyberAudits volverá a analizar exactamente la misma "
                "URL seleccionada y guardará la verificación como una "
                "nueva evaluación."
            )

            if st.button(
                "🔄 Verificar correcciones de esta evaluación",
                type="primary",
                use_container_width=True,
                key="client_verify_fix_v210"
            ):
                try:
                    previous_score = int(
                        selected_scan["risk_score"]
                    )

                    previous_meta = safe_meta(
                        selected_scan.get("scan_meta_json")
                    )

                    verify_email_domain = (
                        previous_meta.get("email_domain", "")
                        if isinstance(previous_meta, dict)
                        else ""
                    )

                    normalized_target, _ = normalize_client_target_url(
                        selected_target,
                        primary_domain
                    )

                    with st.spinner(
                        "Reevaluando exactamente la URL seleccionada..."
                    ):
                        (
                            new_findings,
                            new_stats,
                            new_hostname,
                            new_geo,
                            new_score,
                            new_details
                        ) = scan_target(
                            normalized_target,
                            verify_email_domain
                        )

                        new_meta = build_scan_meta(
                            new_stats,
                            new_findings,
                            new_details
                        )

                        new_scan_id = save_scan_to_db(
                            new_hostname,
                            new_geo.get("ip", "N/A"),
                            new_score,
                            count_actionable(new_findings),
                            "Client Verification Assessment",
                            org_id,
                            new_findings,
                            new_meta,
                            target_url=normalized_target
                        )

                        verified_count = verify_solved_tasks_after_rescan(
                            org_id,
                            scan_id,
                            new_findings
                        )

                    # Do not mutate widget-backed keys here: Hallazgos and
                    # Remediación selectboxes have already been instantiated
                    # during this Streamlit run. Queue the selection and apply
                    # it at the beginning of the next rerun.
                    queue_client_scan_selection(new_scan_id)

                    delta = int(new_score) - previous_score

                    if delta > 0:
                        notice_type = "success"
                        notice_text = (
                            f"Verificación #{new_scan_id}: "
                            f"{previous_score} → {new_score} "
                            f"(+{delta} puntos)."
                        )
                    elif delta < 0:
                        notice_type = "warning"
                        notice_text = (
                            f"Verificación #{new_scan_id}: "
                            f"{previous_score} → {new_score} "
                            f"({delta} puntos)."
                        )
                    else:
                        notice_type = "info"
                        notice_text = (
                            f"Verificación #{new_scan_id}: "
                            f"CyberScore sin cambios "
                            f"({new_score}/100)."
                        )

                    if verified_count:
                        notice_text += (
                            f" · {verified_count} ticket(s) quedaron "
                            "Verificados por CyberAudits."
                        )

                    st.session_state[
                        "client_verify_notice_v210"
                    ] = {
                        "type": notice_type,
                        "text": notice_text
                    }

                    st.rerun()

                except Exception as e:
                    st.error(
                        f"No se pudo verificar: {e}"
                    )

    # --------------------------------------------------------
    # INFORMES
    # --------------------------------------------------------
    with tab_reports:
        st.subheader("Informes")

        history_df = load_history(org_id)

        if history_df.empty:
            st.info(
                "Todavía no hay evaluaciones para generar informes."
            )
        else:
            scan_ids = [
                int(value)
                for value in history_df["id"].tolist()
            ]

            prepare_scan_selector_state(
                "client_report_scan_v210",
                scan_ids
            )

            selected_scan_id = st.selectbox(
                "Seleccioná la evaluación",
                options=scan_ids,
                format_func=lambda scan_id: evaluation_label(
                    history_row_by_id(history_df, scan_id)
                ),
                key="client_report_scan_v210"
            )

            row = history_row_by_id(
                history_df,
                selected_scan_id
            )

            selected_target = evaluation_target(row)
            findings = safe_findings(
                row["findings_json"]
            )
            report_meta = (
                safe_meta(row.get("scan_meta_json"))
                or fallback_scan_meta(findings)
            )

            org_profile = get_organization_profile(
                org_id,
                fallback_name=org_name
            )

            st.info(
                f"El informe se generará únicamente para "
                f"**#{int(row['id'])} · {selected_target}** · "
                f"{row['timestamp']} · "
                f"CyberScore {int(row['risk_score'])}/100"
            )

            st.markdown("#### Cabecera del informe")
            st.caption(
                f"Empresa: "
                f"{org_profile.get('display_name') or org_name} · "
                f"Destinatario: "
                f"{org_profile.get('report_recipient') or 'Dirección General'} · "
                f"Título: "
                f"{org_profile.get('report_title') or 'Evaluación de Postura de Ciberseguridad'}"
            )

            st.info(
                "Podés personalizar los datos corporativos desde Organización. "
                "CyberScore, hallazgos, severidades, evidencia y fecha "
                "permanecen protegidos."
            )

            pdf_name = (
                f"cyberaudits_evaluacion_{int(row['id'])}.pdf"
            )

            generate_client_pdf(
                findings,
                selected_target,
                row["risk_score"],
                org_profile,
                pdf_name,
                scan_meta=report_meta
            )

            docx_data = generate_client_docx(
                selected_target,
                findings,
                row["risk_score"],
                org_profile,
                scan_meta=report_meta
            )

            d1, d2 = st.columns(2)

            with d1:
                with open(pdf_name, "rb") as f:
                    st.download_button(
                        "⬇️ Descargar PDF",
                        data=f,
                        file_name=pdf_name,
                        mime="application/pdf",
                        use_container_width=True,
                        key=f"client_pdf_v210_{row['id']}"
                    )

            with d2:
                st.download_button(
                    "⬇️ Descargar Word",
                    data=docx_data,
                    file_name=(
                        f"cyberaudits_evaluacion_"
                        f"{int(row['id'])}.docx"
                    ),
                    mime=(
                        "application/vnd.openxmlformats-officedocument."
                        "wordprocessingml.document"
                    ),
                    use_container_width=True,
                    key=f"client_docx_v210_{row['id']}"
                )

    # --------------------------------------------------------
    # ORGANIZACION
    # --------------------------------------------------------
    with tab_org:
        st.subheader("Organización")
        st.write(
            "Personalizá la identidad de tu empresa y la cabecera de los informes. "
            "Los resultados técnicos no se pueden editar."
        )

        current_profile = get_organization_profile(org_id, fallback_name=org_name)
        with st.form("client_org_profile_v29"):
            display_name = st.text_input("Nombre comercial", value=str(current_profile.get("display_name") or org_name))
            legal_name = st.text_input("Razón social · opcional", value=str(current_profile.get("legal_name") or ""))
            department = st.text_input(
                "Área responsable · opcional",
                value=str(current_profile.get("department") or ""),
                placeholder="Tecnología / Seguridad"
            )
            report_recipient = st.text_input(
                "Destinatario de los informes",
                value=str(current_profile.get("report_recipient") or "Dirección General")
            )
            report_title = st.text_input(
                "Título de los informes",
                value=str(current_profile.get("report_title") or "Evaluación de Postura de Ciberseguridad")
            )
            confidentiality_footer = st.text_area(
                "Texto de confidencialidad",
                value=str(current_profile.get("confidentiality_footer") or "Documento confidencial. Uso exclusivo de la organización evaluada."),
                max_chars=500
            )
            logo_upload = st.file_uploader("Logo · PNG/JPG, máximo 350 KB", type=["png", "jpg", "jpeg"])
            remove_logo = st.checkbox("Quitar logo actual")
            save_profile = st.form_submit_button("Guardar perfil", type="primary", use_container_width=True)

        if current_profile.get("logo_b64"):
            st.caption("Logo actual")
            try:
                st.image(base64.b64decode(current_profile.get("logo_b64")), width=180)
            except Exception:
                st.caption("No se pudo previsualizar el logo guardado.")

        if save_profile:
            try:
                next_logo = str(current_profile.get("logo_b64") or "")
                next_mime = str(current_profile.get("logo_mime") or "image/png")
                if remove_logo:
                    next_logo = ""
                    next_mime = "image/png"
                if logo_upload is not None:
                    next_logo, next_mime = _logo_upload_to_b64(logo_upload)
                save_organization_profile(
                    org_id,
                    display_name,
                    legal_name,
                    department,
                    report_recipient,
                    report_title,
                    confidentiality_footer,
                    next_logo,
                    next_mime
                )
                st.success("Perfil actualizado.")
                st.rerun()
            except Exception as e:
                st.error(f"No se pudo guardar el perfil: {e}")

        st.info(
            "Integridad protegida: CyberScore, fecha, hallazgos, severidades, evidencia y metodología no son editables por el cliente."
        )

    # --------------------------------------------------------
    # CUENTA
    # --------------------------------------------------------
    with tab_account:
        st.subheader("Cuenta")
        st.write(f"**Email:** {client_email}")
        st.write(f"**Organización:** {display_org_name}")
        st.write(f"**Rol:** {st.session_state.get('client_role', 'CLIENT')}")

        st.markdown("### Cambiar contraseña")
        with st.form("client_account_password_v29"):
            new_password = st.text_input("Nueva contraseña", type="password")
            repeat_password = st.text_input("Repetir contraseña", type="password")
            change = st.form_submit_button("Actualizar contraseña", use_container_width=True)
        if change:
            if new_password != repeat_password:
                st.error("Las contraseñas no coinciden.")
            elif len(new_password) < 12:
                st.error("La contraseña debe tener al menos 12 caracteres.")
            else:
                try:
                    supabase_user_change_password(st.session_state.client_access_token, new_password)
                    st.success("Contraseña actualizada.")
                except Exception as e:
                    st.error(f"No se pudo cambiar la contraseña: {e}")

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
            <div class="ca-kicker">CYBERAUDITS 2.10.2 · PRIVATE BETA</div>
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
    client_mode = st.query_params.get("client", "")
except Exception:
    public_pass_slug = ""
    admin_mode = ""
    client_mode = ""

if isinstance(public_pass_slug, list):
    public_pass_slug = public_pass_slug[0] if public_pass_slug else ""

if isinstance(admin_mode, list):
    admin_mode = admin_mode[0] if admin_mode else ""

if isinstance(client_mode, list):
    client_mode = client_mode[0] if client_mode else ""

if public_pass_slug:
    render_public_cyberpass(public_pass_slug)

if (
    st.session_state.get("client_authenticated", False)
    or str(client_mode) == "1"
):
    render_client_portal()

# Root URL is the public marketing/free-check surface.
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
        <div class="ca-kicker">CYBERAUDITS 2.10.2 · PRIVATE BETA</div>
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
        status_label, status_description = trusted_score_status(
            score,
            latest_meta,
            latest_findings
        )
        eval_state, eval_message = evaluation_status(
            latest_meta,
            latest_findings
        )

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
            f"Evaluación #{int(latest['id'])} · "
            f"Objetivo: {evaluation_target(latest)} · "
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

        if eval_state == "PARCIAL":
            st.warning("⚠️ Evaluación parcial: " + eval_message)
        elif eval_state == "FALLIDA":
            st.error("❌ Evaluación fallida: " + eval_message)
        else:
            st.success("✅ Evaluación completa: " + eval_message)

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
        selected_scan_meta = (
            safe_meta(selected_scan_row.get("scan_meta_json"))
            or fallback_scan_meta(stored_findings)
        )
        selected_eval_state, selected_eval_message = evaluation_status(
            selected_scan_meta,
            stored_findings
        )

        st.caption(
            f"Objetivo: {evaluation_target(selected_scan_row)} · "
            f"IP: {selected_scan_row['ip']} · "
            f"CyberScore técnico: {selected_scan_row['risk_score']}/100 · "
            f"Estado: {selected_eval_state} · "
            f"Cobertura: {selected_scan_meta.get('coverage', 'N/D')}%"
        )

        if selected_eval_state != "COMPLETA":
            st.warning(selected_eval_message)

        inconclusive_count = sum(
            int(v or 0)
            for v in (
                selected_scan_meta.get("inconclusive_by_category", {})
                or {}
            ).values()
        )
        verified_checks = int(selected_scan_meta.get("verified_checks") or 0)
        actionable_count = count_actionable(stored_findings)
        safe_verified = max(0, verified_checks - actionable_count)

        stats_dummy = {
            "Críticas": sum(1 for x in stored_findings if x.get("severity") == "CRÍTICO"),
            "Medias": sum(1 for x in stored_findings if x.get("severity") == "MEDIO"),
            "Bajas": sum(1 for x in stored_findings if x.get("severity") == "BAJO"),
            "Seguras verificadas": safe_verified,
            "No concluyentes": inconclusive_count
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
                pdf_tech,
                scan_meta=selected_scan_meta
            )

            docx_tech = generate_docx(
                selected_scan_row["hostname"],
                stored_findings,
                selected_scan_row["risk_score"],
                agency_name,
                agency_tagline,
                "Informe Técnico Exhaustivo",
                recipient_name,
                report_subject,
                scan_meta=selected_scan_meta
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
                pdf_exec,
                scan_meta=selected_scan_meta
            )

            docx_exec = generate_docx(
                selected_scan_row["hostname"],
                stored_findings,
                selected_scan_row["risk_score"],
                agency_name,
                agency_tagline,
                "Informe Narrativo (Ejecutivo)",
                recipient_name,
                report_subject,
                scan_meta=selected_scan_meta
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
                pdf_controls,
                scan_meta=selected_scan_meta
            )

            docx_controls = generate_docx(
                selected_scan_row["hostname"],
                stored_findings,
                selected_scan_row["risk_score"],
                agency_name,
                agency_tagline,
                control_report_type,
                recipient_name,
                report_subject,
                scan_meta=selected_scan_meta
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
            "Solucionado",
            "Verificado"
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

        r1, r2, r3, r4 = st.columns(4)
        r1.metric("Pendientes", counts["Pendiente"])
        r2.metric("En proceso", counts["En Proceso"])
        r3.metric("Solucionados", counts["Solucionado"])
        r4.metric("Verificados", counts["Verificado"])

        t_pending, t_progress, t_done, t_verified = st.tabs(
            [
                f"🟡 Pendientes ({counts['Pendiente']})",
                f"🔄 En proceso ({counts['En Proceso']})",
                f"✅ Solucionados ({counts['Solucionado']})",
                f"🛡️ Verificados ({counts['Verificado']})"
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

        with t_verified:
            render_tickets(
                "Verificado",
                closed=True
            )

        st.markdown("---")

        st.info(
            "Cuando termines una remediación, volvé al Dashboard y usá "
            "“Verificar ahora”. CyberAudits generará una nueva evaluación "
            "para comprobar si el CyberScore mejoró."
        )


# ==========================================
# PUBLIC BETA LEADS / ACCESS APPROVAL
# ==========================================

with tab_leads:
    st.subheader("Public Beta Leads")

    st.write(
        "Convertí solicitudes del Free CyberCheck en usuarios invitados "
        "de CyberAudits."
    )

    temp_access_payload = st.session_state.get(
        "temp_access_payload"
    )

    if temp_access_payload:
        st.success(
            "🔑 Acceso temporal generado correctamente. "
            "Copialo antes de ocultarlo."
        )

        st.code(
            (
                f"Email: {temp_access_payload['email']}\n"
                f"Contraseña temporal: {temp_access_payload['password']}"
            ),
            language="text"
        )

        st.warning(
            "Esta contraseña temporal no se guarda en la base de datos. "
            "Compartila por un canal privado. El cliente deberá cambiarla "
            "en su primer ingreso."
        )

        if st.button(
            "Ocultar credencial temporal",
            key="hide_temp_access_payload"
        ):
            st.session_state.pop(
                "temp_access_payload",
                None
            )
            st.rerun()

    try:
        leads_df = load_public_leads()
    except Exception as e:
        leads_df = pd.DataFrame()
        st.error(f"No se pudieron cargar los leads: {e}")

    if leads_df.empty:
        st.info("Todavía no hay solicitudes de acceso beta.")

    else:
        l1, l2, l3, l4, l5 = st.columns(5)

        l1.metric("Leads", len(leads_df))

        l2.metric(
            "Pendientes",
            int((leads_df["status"] == "Pendiente").sum())
            if "status" in leads_df.columns
            else 0
        )

        l3.metric(
            "Invitados",
            int((leads_df["status"] == "Invitado").sum())
            if "status" in leads_df.columns
            else 0
        )

        l4.metric(
            "Activos",
            int((leads_df["status"] == "Activo").sum())
            if "status" in leads_df.columns
            else 0
        )

        l5.metric(
            "Suspendidos",
            int((leads_df["status"] == "Suspendido").sum())
            if "status" in leads_df.columns
            else 0
        )

        st.markdown("#### Solicitudes")

        for _, lead in leads_df.iterrows():
            lead_id = int(lead["id"])
            email = str(lead["email"])
            domain = str(lead.get("domain") or "N/D")
            score = (
                str(int(lead["cyber_score"]))
                if pd.notna(lead.get("cyber_score"))
                else "N/D"
            )

            status = str(
                lead.get("status")
                or "Pendiente"
            )

            status_class = {
                "Pendiente": "status-pending",
                "Invitado": "status-invited",
                "Confirmado": "status-confirmed",
                "Activo": "status-active",
                "Suspendido": "status-suspended"
            }.get(status, "status-pending")

            (
                info_col,
                action_col,
                access_col,
                revoke_col,
                delete_col
            ) = st.columns(
                [6.8, 2.0, 2.2, 2.1, 0.7],
                vertical_alignment="center"
            )

            with info_col:
                st.markdown(
                    f"""
                    <div class="history-row">
                        <div>
                            <div class="history-title">
                                {html.escape(email)}
                            </div>
                            <div class="history-meta">
                                Dominio:
                                {html.escape(domain)}
                                &nbsp; · &nbsp;
                                CyberScore:
                                <strong>{html.escape(score)}</strong>
                                &nbsp; · &nbsp;
                                <span class="lead-status {status_class}">
                                    {html.escape(status)}
                                </span>
                            </div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

            with action_col:
                if status == "Pendiente":
                    if st.button(
                        "✅ Aprobar e invitar",
                        key=f"approve_lead_{lead_id}",
                        type="primary",
                        use_container_width=True
                    ):
                        try:
                            with st.spinner(
                                f"Enviando invitación a {email}..."
                            ):
                                result = approve_and_invite_lead(
                                    lead
                                )

                            st.success(
                                "Invitación enviada y acceso registrado."
                            )
                            st.rerun()

                        except Exception as e:
                            st.error(
                                f"No se pudo enviar la invitación: {e}"
                            )

                elif status != "Suspendido":
                    if st.button(
                        "🔄 Actualizar estado",
                        key=f"refresh_lead_{lead_id}",
                        use_container_width=True
                    ):
                        try:
                            auth_user_id = (
                                str(lead.get("auth_user_id") or "")
                            )

                            organization_id = (
                                int(lead["organization_id"])
                                if pd.notna(
                                    lead.get("organization_id")
                                )
                                else None
                            )

                            if not auth_user_id:
                                raise RuntimeError(
                                    "Este lead no tiene un usuario Auth asociado."
                                )

                            new_status = refresh_lead_auth_status(
                                lead_id,
                                auth_user_id,
                                organization_id,
                                email
                            )

                            st.success(
                                f"Estado actualizado: {new_status}"
                            )
                            st.rerun()

                        except Exception as e:
                            st.error(
                                f"No se pudo actualizar el estado: {e}"
                            )

            with access_col:
                if status in {"Activo", "Confirmado"}:
                    if st.button(
                        "🔑 Generar acceso temporal",
                        key=f"temp_access_{lead_id}",
                        use_container_width=True
                    ):
                        try:
                            auth_user_id = str(
                                lead.get("auth_user_id") or ""
                            )

                            if not auth_user_id:
                                raise RuntimeError(
                                    "El usuario no tiene un Auth ID asociado."
                                )

                            temporary_password = (
                                _generate_temporary_password()
                            )

                            supabase_admin_set_password(
                                auth_user_id,
                                temporary_password
                            )

                            set_member_password_change_required(
                                email,
                                True
                            )

                            st.session_state[
                                "temp_access_payload"
                            ] = {
                                "lead_id": lead_id,
                                "email": email,
                                "password": temporary_password
                            }

                            st.rerun()

                        except Exception as e:
                            error_text = str(e)

                            st.error(
                                f"No se pudo generar el acceso: {error_text}"
                            )

                            if "API key not found" in error_text:
                                st.info(
                                    "CyberAudits no pudo autenticar la operación "
                                    "administrativa de Supabase. Esta versión ya "
                                    "envía la Secret key con los headers requeridos; "
                                    "si el error persiste, reiniciá la app para que "
                                    "Streamlit vuelva a cargar los Secrets."
                                )

                elif status == "Invitado":
                    st.caption(
                        "Primero debe aceptar la invitación."
                    )

            with revoke_col:
                if status in {"Activo", "Confirmado"}:
                    if st.button(
                        "⛔ Suspender acceso",
                        key=f"suspend_access_{lead_id}",
                        help=(
                            "Bloquea el Portal Cliente sin eliminar "
                            "la organización ni su historial."
                        ),
                        use_container_width=True
                    ):
                        try:
                            set_client_access_status(
                                lead_id,
                                email,
                                "Suspendido"
                            )

                            payload = st.session_state.get(
                                "temp_access_payload"
                            )

                            if (
                                payload
                                and int(payload.get("lead_id", -1)) == lead_id
                            ):
                                st.session_state.pop(
                                    "temp_access_payload",
                                    None
                                )

                            st.success(
                                f"Acceso suspendido para {email}."
                            )
                            st.rerun()

                        except Exception as e:
                            st.error(
                                f"No se pudo suspender el acceso: {e}"
                            )

                elif status == "Suspendido":
                    if st.button(
                        "✅ Restaurar acceso",
                        key=f"restore_access_{lead_id}",
                        type="primary",
                        help="Vuelve a habilitar el Portal Cliente.",
                        use_container_width=True
                    ):
                        try:
                            set_client_access_status(
                                lead_id,
                                email,
                                "Activo"
                            )

                            st.success(
                                f"Acceso restaurado para {email}."
                            )
                            st.rerun()

                        except Exception as e:
                            st.error(
                                f"No se pudo restaurar el acceso: {e}"
                            )

                elif status == "Invitado":
                    st.caption("Esperando activación")

            with delete_col:
                # Once invited, deleting the lead alone would NOT revoke Auth access.
                # We therefore only allow quick deletion while it is still pending.
                if status == "Pendiente":
                    if st.button(
                        "✕",
                        key=f"delete_lead_{lead_id}",
                        help="Eliminar este lead pendiente",
                        type="secondary",
                        use_container_width=True
                    ):
                        delete_public_lead(lead_id)
                        st.success("Lead eliminado.")
                        st.rerun()
                else:
                    st.caption("🔒")

            if lead.get("invited_at") and pd.notna(
                lead.get("invited_at")
            ):
                st.caption(
                    f"Invitación enviada: {lead.get('invited_at')}"
                )

            if lead.get("last_error") and pd.notna(
                lead.get("last_error")
            ):
                st.warning(
                    f"Último error: {lead.get('last_error')}"
                )

            st.markdown("")

        st.markdown("---")

        csv_export = leads_df.to_csv(
            index=False
        ).encode("utf-8-sig")

        st.download_button(
            "⬇️ Exportar leads a CSV",
            data=csv_export,
            file_name="cyberaudits_beta_leads.csv",
            mime="text/csv",
            use_container_width=True
        )

        st.info(
            "Los usuarios Activos pueden recibir un acceso temporal. "
            "También podés suspender y restaurar el acceso sin borrar "
            "la organización, los escaneos ni los reportes del cliente."
        )

        st.caption(
            "Importante: borrar un lead invitado no equivale a revocar "
            "su cuenta de autenticación. La revocación se implementará "
            "como acción separada."
        )

