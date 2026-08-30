import streamlit as st
import pandas as pd
import sqlite3
import socket
import ssl
import datetime
import hashlib
import requests
import io
import base64
import re
import os
import csv
from urllib.parse import urlparse
from docx import Document
from docx.shared import Inches, Pt, RGBColor
import matplotlib.pyplot as plt
import psycopg2
from weasyprint import HTML

st.set_page_config(page_title="CyberAudits - Escáner Perimetral", page_icon="🛡️", layout="wide")

st.markdown("""
    <style>
        .stApp { background-color: #f8fafc; color: #1e293b; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        [data-testid="stSidebar"] { background-color: #f0f2f6 !important; border-right: 1px solid #e2e8f0; }
        .enterprise-banner { background: linear-gradient(90deg, #1e3a8a, #3b82f6); padding: 12px 20px; border-radius: 8px; color: white; text-align: center; margin-bottom: 20px; font-weight: 500; }
        .ticket-card { background: white; border: 1px solid #cbd5e1; border-radius: 8px; padding: 16px; margin-bottom: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
        .sev-critical { border-left: 5px solid #dc2626; }
        .sev-medium { border-left: 5px solid #f59e0b; }
        .sev-low { border-left: 5px solid #3b82f6; }
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
        return sqlite3.connect("cyber_audits.db")

def init_db():
    conn = get_db_connection()
    conn.autocommit = True
    c = conn.cursor()
    is_pg = "postgres" in st.secrets
    
    if is_pg:
        c.execute("""CREATE TABLE IF NOT EXISTS organizations (id SERIAL PRIMARY KEY, name TEXT UNIQUE NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        c.execute("""CREATE TABLE IF NOT EXISTS history (id SERIAL PRIMARY KEY, timestamp TEXT, hostname TEXT, ip TEXT, risk_score INTEGER, findings_count INTEGER, report_type TEXT, organization_id INTEGER)""")
        c.execute("ALTER TABLE history ADD COLUMN IF NOT EXISTS organization_id INTEGER;")
        c.execute("""CREATE TABLE IF NOT EXISTS remediation_tasks (id SERIAL PRIMARY KEY, organization_id INTEGER, scan_id INTEGER, hostname TEXT, finding_vector TEXT, severity TEXT DEFAULT 'MEDIO', status TEXT DEFAULT 'Pendiente', notes TEXT)""")
        c.execute("ALTER TABLE remediation_tasks ADD COLUMN IF NOT EXISTS organization_id INTEGER;")
        c.execute("ALTER TABLE remediation_tasks ADD COLUMN IF NOT EXISTS scan_id INTEGER;")
        c.execute("ALTER TABLE remediation_tasks ADD COLUMN IF NOT EXISTS severity TEXT;")
        c.execute("""CREATE TABLE IF NOT EXISTS remediation_logs (id SERIAL PRIMARY KEY, task_id INTEGER, timestamp TEXT, status TEXT, notes TEXT)""")
    else:
        c.execute("""CREATE TABLE IF NOT EXISTS organizations (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        c.execute("""CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, hostname TEXT, ip TEXT, risk_score INTEGER, findings_count INTEGER, report_type TEXT, organization_id INTEGER)""")
        try: c.execute("ALTER TABLE history ADD COLUMN organization_id INTEGER;")
        except Exception: pass
        c.execute("""CREATE TABLE IF NOT EXISTS remediation_tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, organization_id INTEGER, scan_id INTEGER, hostname TEXT, finding_vector TEXT, severity TEXT DEFAULT 'MEDIO', status TEXT DEFAULT 'Pendiente', notes TEXT)""")
        try:
            c.execute("ALTER TABLE remediation_tasks ADD COLUMN organization_id INTEGER;")
            c.execute("ALTER TABLE remediation_tasks ADD COLUMN scan_id INTEGER;")
            c.execute("ALTER TABLE remediation_tasks ADD COLUMN severity TEXT;")
        except Exception: pass
        c.execute("""CREATE TABLE IF NOT EXISTS remediation_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, task_id INTEGER, timestamp TEXT, status TEXT, notes TEXT)""")
        conn.commit()
    c.close()
    conn.close()

init_db()

def save_scan_to_db(hostname, ip, risk_score, findings_count, report_type_val, organization_id=None, findings=None):
    try:
        conn = get_db_connection()
        conn.autocommit = True
        c = conn.cursor()
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        is_pg = "postgres" in st.secrets
        ph = "%s" if is_pg else "?"
        
        if is_pg:
            if organization_id is not None:
                c.execute(f"INSERT INTO history (timestamp, hostname, ip, risk_score, findings_count, report_type, organization_id) VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}) RETURNING id", (timestamp, hostname, ip, risk_score, findings_count, report_type_val, organization_id))
            else:
                c.execute(f"INSERT INTO history (timestamp, hostname, ip, risk_score, findings_count, report_type) VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}) RETURNING id", (timestamp, hostname, ip, risk_score, findings_count, report_type_val))
            scan_id = c.fetchone()[0]
        else:
            if organization_id is not None:
                c.execute(f"INSERT INTO history (timestamp, hostname, ip, risk_score, findings_count, report_type, organization_id) VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})", (timestamp, hostname, ip, risk_score, findings_count, report_type_val, organization_id))
            else:
                c.execute(f"INSERT INTO history (timestamp, hostname, ip, risk_score, findings_count, report_type) VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph})", (timestamp, hostname, ip, risk_score, findings_count, report_type_val))
            scan_id = c.lastrowid
            
        if findings:
            for f in findings:
                vec = f['vector']
                sev = f.get('severity', 'MEDIO')
                if organization_id is not None:
                    c.execute(f"INSERT INTO remediation_tasks (organization_id, scan_id, hostname, finding_vector, severity, status) VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, 'Pendiente')", (organization_id, scan_id, hostname, vec, sev))
                else:
                    c.execute(f"INSERT INTO remediation_tasks (organization_id, scan_id, hostname, finding_vector, severity, status) VALUES (NULL, {ph}, {ph}, {ph}, {ph}, 'Pendiente')", (scan_id, hostname, vec, sev))
        c.close()
        conn.close()
    except Exception as e:
        st.error(f"Error al guardar escaneo: {e}")

def get_scan_history(org_id=None):
    conn = get_db_connection()
    is_pg = "postgres" in st.secrets
    ph = "%s" if is_pg else "?"
    if org_id is not None:
        query = f'SELECT id AS "ID Escaneo", timestamp AS "Fecha y Hora", hostname AS "Dominio / Host", ip AS "IP", risk_score AS "Risk Score (/100)", findings_count AS "Vulnerabilidades", report_type AS "Plantilla" FROM history WHERE organization_id = {ph} ORDER BY id DESC'
        df = pd.read_sql_query(query, conn, params=(org_id,))
    else:
        query = f'SELECT id AS "ID Escaneo", timestamp AS "Fecha y Hora", hostname AS "Dominio / Host", ip AS "IP", risk_score AS "Risk Score (/100)", findings_count AS "Vulnerabilidades", report_type AS "Plantilla" FROM history WHERE organization_id IS NULL ORDER BY id DESC'
        df = pd.read_sql_query(query, conn)
    conn.close()
    return df

# ==========================================
# ESCÁNER CON TEXTOS ENRIQUECIDOS
# ==========================================
def get_geolocation(hostname):
    geo_data = {"ip": "N/A", "country": "Desconocido", "city": "Desconocido", "org": "Desconocido"}
    try:
        ip = socket.gethostbyname(hostname)
        geo_data["ip"] = ip
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city,org,isp"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                geo_data.update({"country": data.get("country", "Desconocido"), "city": data.get("city", "Desconocido"), "org": data.get("org", data.get("isp", "Desconocido"))})
    except Exception: pass
    return geo_data

def check_ssl_certificate(hostname):
    ssl_info = {"valid": False, "issuer": "Desconocido", "expires_soon": False, "days_remaining": 0, "details": "No se pudo verificar el certificado SSL/TLS."}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after_str = cert.get('notAfter')
                if not_after_str:
                    expires_date = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expires_date - datetime.datetime.utcnow()).days
                    ssl_info.update({"days_remaining": days_left, "valid": True})
                    if days_left < 30:
                        ssl_info.update({"expires_soon": True, "details": f"Certificado válido pero expira pronto ({days_left} días restantes). Requiere renovación inmediata."})
                    else:
                        ssl_info["details"] = f"Certificado SSL válido. Cifrado seguro activo. Expira en {days_left} días."
    except Exception as e: ssl_info["details"] = f"Error al verificar SSL: {str(e)}"
    return ssl_info

def check_email_security(hostname):
    email_sec = {"spf": False, "dmarc": False}
    try:
        res_spf = requests.get(f"https://cloudflare-dns.com/dns-query?name={hostname}&type=TXT", headers={"Accept": "application/dns-json"}, timeout=4)
        if res_spf.status_code == 200:
            for ans in res_spf.json().get("Answer", []):
                if "v=spf1" in ans.get("data", ""): email_sec["spf"] = True
        res_dmarc = requests.get(f"https://cloudflare-dns.com/dns-query?name=_dmarc.{hostname}&type=TXT", headers={"Accept": "application/dns-json"}, timeout=4)
        if res_dmarc.status_code == 200:
            for ans in res_dmarc.json().get("Answer", []):
                if "v=DMARC1" in ans.get("data", ""): email_sec["dmarc"] = True
    except Exception: pass
    return email_sec

def scan_target(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or url.replace("https://", "").replace("http://", "").split("/")[0]
    
    findings = []
    stats = {"Críticas": 0, "Medias": 0, "Bajas": 0, "Seguras": 0}
    
    geo = get_geolocation(hostname)
    email_sec = check_email_security(hostname)
    ssl_info = check_ssl_certificate(hostname)
    
    # Textos Enriquecidos
    if not ssl_info["valid"]:
        stats["Críticas"] += 1
        findings.append({
            "vector": "Certificado SSL/TLS Inválido o Ausente", "severity": "CRÍTICO", "badge": "badge-critical",
            "desc": "El dominio carece de un certificado SSL/TLS válido o está mal configurado. El tráfico entre el usuario y el servidor viaja en texto plano (HTTP), lo que permite que actores maliciosos en la red intercepten credenciales, datos personales o información financiera mediante ataques Man-in-the-Middle (MitM).", 
            "impact": "Los navegadores modernos (Chrome, Firefox) bloquearán el acceso a la web mostrando una advertencia de 'Sitio no seguro', provocando pérdida de confianza, abandono de clientes y un impacto negativo severo en el posicionamiento SEO.", 
            "fix": "Se requiere instalar y configurar un certificado SSL/TLS (RSA o ECC) emitido por una Autoridad Certificadora (CA) de confianza como Let's Encrypt o DigiCert. Además, se debe forzar la redirección automática de todo el tráfico del puerto 80 (HTTP) al 443 (HTTPS).", 
            "compliance": "PCI-DSS 4.1 / ISO 27001", "snippet": f"certbot --nginx -d {hostname}"})
    elif ssl_info["expires_soon"]:
        stats["Medias"] += 1
        findings.append({"vector": f"Certificado SSL/TLS próximo a expirar ({ssl_info['days_remaining']} días)", "severity": "MEDIO", "badge": "badge-medium", "desc": f"El certificado SSL actual es válido pero caducará en {ssl_info['days_remaining']} días. Si expira, los usuarios enfrentarán errores de privacidad infranqueables.", "impact": "Interrupción total del servicio web y caída operativa.", "fix": "Configurar una tarea programada (cron job) en el servidor para automatizar la renovación del certificado antes de los últimos 15 días de vigencia.", "compliance": "ISO 27001 A.12.1", "snippet": "certbot renew --dry-run"})
    else:
        stats["Seguras"] += 1

    if email_sec["spf"]: stats["Seguras"] += 1
    else:
        stats["Medias"] += 1
        findings.append({
            "vector": "Ausencia de Registro SPF (Vulnerabilidad de Spoofing)", "severity": "MEDIO", "badge": "badge-medium",
            "desc": "El dominio carece de un registro SPF (Sender Policy Framework) configurado en sus zonas DNS. Este mecanismo de seguridad especifica de forma pública qué direcciones IP o servicios de terceros (como Google Workspace o Microsoft 365) están autorizados para enviar correos electrónicos usando tu nombre de dominio.", 
            "impact": "Facilita la suplantación de identidad. Los atacantes pueden enviar correos de phishing haciéndose pasar por tu empresa para engañar a empleados o clientes. Además, tus correos legítimos tienen alta probabilidad de caer en la bandeja de SPAM.", 
            "fix": "Acceder al panel de administración del dominio (DNS) y publicar un registro tipo TXT con directivas SPF estrictas (usando el flag '-all' o '~all' para fallos suaves), listando únicamente las IPs y servicios oficiales de la compañía.", 
            "compliance": "ISO 27001 A.13.2 / GDPR", "snippet": f'{hostname}. 3600 IN TXT "v=spf1 include:_spf.tuproveedor.com ~all"'})

    if email_sec["dmarc"]: stats["Seguras"] += 1
    else:
        stats["Medias"] += 1
        findings.append({
            "vector": "Ausencia de Política DMARC", "severity": "MEDIO", "badge": "badge-medium", 
            "desc": "No se detectó un registro DMARC (Domain-based Message Authentication, Reporting, and Conformance). DMARC unifica SPF y DKIM, indicándole a los servidores receptores (como Gmail u Outlook) qué hacer exactamente si un correo falla las pruebas de autenticación (ej. rechazarlo o enviarlo a cuarentena).", 
            "impact": "Ceguera operativa ante abusos de marca. Sin DMARC, la organización no recibe reportes sobre quién está intentando suplantar su dominio en campañas maliciosas globales.", 
            "fix": "Implementar un registro TXT en '_dmarc' comenzando con una política de monitoreo (p=none) para analizar el tráfico, y posteriormente escalar a una política de bloqueo (p=reject) para neutralizar los fraudes.", 
            "compliance": "ISO 27001 A.13.1", "snippet": f'_dmarc.{hostname}. 3600 IN TXT "v=DMARC1; p=reject; rua=mailto:seguridad@{hostname};"'})

    try:
        response = requests.get(url, timeout=10)
        headers = response.headers
        if "Strict-Transport-Security" in headers: stats["Seguras"] += 1
        else:
            stats["Críticas"] += 1
            findings.append({
                "vector": "HTTP Strict Transport Security (HSTS) Ausente", "severity": "CRÍTICO", "badge": "badge-critical", 
                "desc": "La cabecera de seguridad HSTS no está presente en la respuesta del servidor. Esta directiva obliga criptográficamente a los navegadores a conectarse exclusivamente a través de HTTPS durante un tiempo determinado (max-age), bloqueando cualquier intento de rebajar la conexión a HTTP (ataques SSL Stripping).", 
                "impact": "Abre una ventana de oportunidad crítica en redes Wi-Fi públicas, donde un atacante puede interceptar la primera conexión del usuario y robar la sesión completa antes de que se establezca el túnel cifrado.", 
                "fix": "Modificar la configuración del servidor web (Nginx/Apache/IIS) para inyectar la cabecera 'Strict-Transport-Security' con un tiempo de vida (max-age) prolongado, e incluir los subdominios.", 
                "compliance": "PCI-DSS 4.1 / HIPAA", "snippet": 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;'})
        
        if "Content-Security-Policy" in headers: stats["Seguras"] += 1
        else:
            stats["Medias"] += 1
            findings.append({
                "vector": "Content Security Policy (CSP) Ausente", "severity": "MEDIO", "badge": "badge-medium", 
                "desc": "El servidor no devuelve la cabecera Content-Security-Policy. El CSP es una capa de defensa fundamental que le indica al navegador del cliente desde qué dominios específicos está permitido cargar recursos (como scripts de JavaScript, imágenes u hojas de estilo).", 
                "impact": "Aumenta drásticamente la vulnerabilidad ante ataques de inyección (Cross-Site Scripting - XSS). Un atacante podría lograr que el sitio ejecute código malicioso externo en el navegador de los usuarios.", 
                "fix": "Implementar una política CSP estricta basada en el principio de menor privilegio, definiendo explícitamente orígenes de confianza (por ejemplo, 'self' para el mismo dominio) mediante directivas como default-src y script-src.", 
                "compliance": "OWASP Top 10", "snippet": 'add_header Content-Security-Policy "default-src \'self\'; script-src \'self\' https://apis-confiables.com;";'})
    except Exception: pass

    penalty = (stats["Críticas"] * 25) + (stats["Medias"] * 10) + (stats["Bajas"] * 5)
    return findings, stats, [], hostname, [], geo, email_sec, ssl_info, max(0, 100 - penalty)


# ==========================================
# REPORTES Y GRÁFICOS
# ==========================================
def generate_chart(stats):
    labels, sizes, colors = list(stats.keys()), list(stats.values()), ['#dc2626', '#f59e0b', '#3b82f6', '#10b981']
    non_zero_data = [(l, s, c) for l, s, c in zip(labels, sizes, colors) if s > 0]
    if not non_zero_data: non_zero_data = [("Seguras", 1, "#10b981")]
    l_filt, s_filt, c_filt = zip(*non_zero_data)
    fig, ax = plt.subplots(figsize=(4.5, 2.8))
    ax.pie(s_filt, labels=l_filt, colors=c_filt, autopct='%1.1f%%', startangle=90, textprops={'fontsize': 8.5, 'weight': 'bold'})
    ax.axis('equal')
    plt.title("Distribución de Riesgos en la Infraestructura", fontsize=9.5, fontweight='bold', color="#1e293b")
    plt.tight_layout()
    chart_path = "vulnerability_chart.png"
    plt.savefig(chart_path, dpi=300, bbox_inches='tight', transparent=True)
    plt.close()
    with open(chart_path, "rb") as f: return base64.b64encode(f.read()).decode("utf-8")

def generate_docx(hostname, geo, email_sec, ssl_info, findings, risk_score, agency_name, agency_tagline, report_type, recipient_name, report_subject):
    doc = Document()
    for section in doc.sections: section.top_margin = section.bottom_margin = section.left_margin = section.right_margin = Inches(1)
    run_title = doc.add_paragraph().add_run(f"INFORME: {report_type.upper()}")
    run_title.font.size, run_title.font.bold, run_title.font.color.rgb = Pt(15), True, RGBColor(15, 23, 42)
    doc.add_paragraph(f"Emitido por: {agency_name} ({agency_tagline})\nObjetivo analizado: {hostname} | Risk Score: {risk_score}/100")
    doc.add_heading("Detalle de Hallazgos y Guía de Remediación", level=2)
    for idx, f in enumerate(findings, 1):
        h = doc.add_paragraph().add_run(f"#{idx} - {f['vector']} [{f['severity']}]")
        h.font.bold = True
        doc.add_paragraph(f"Descripción: {f['desc']}")
        doc.add_paragraph(f"Impacto: {f['impact']}")
        doc.add_paragraph().add_run(f"Remediación recomendada: {f['fix']}").font.bold = True
    buffer = io.BytesIO()
    doc.save(buffer)
    return buffer.getvalue()

def generate_pdf(findings, chart_base64, hostname, risk_score, agency_name, output_filename):
    html_content = f"""
    <html><body style="font-family: Arial; padding: 20px;">
        <h1 style="background: #0f172a; color: white; padding: 10px;">Informe: {hostname} - Score: {risk_score}</h1>
        <p>Agencia: {agency_name}</p>
        <img src="data:image/png;base64,{chart_base64}" style="width: 250px;">
        <h2>Hallazgos y Remediación Técnica</h2>
        {''.join([f'<div style="margin-bottom:15px; border-bottom:1px solid #ccc; padding-bottom:10px;"><p><strong>{f["vector"]} [{f["severity"]}]</strong><br><em>Descripción:</em> {f["desc"]}<br><em>Impacto:</em> {f["impact"]}<br><strong>Solución:</strong> {f["fix"]}</div>' for f in findings])}
    </body></html>
    """
    HTML(string=html_content).write_pdf(output_filename)


# ==========================================
# UI DE LA APLICACIÓN
# ==========================================
if "scanned" not in st.session_state: st.session_state.scanned = False
st.markdown('<div class="enterprise-banner">🚀 <strong>CyberAudits Enterprise Suite:</strong> Plataforma perimetral de consultoría activa.</div>', unsafe_allow_html=True)
st.sidebar.header("🏢 Organización / Cliente")
try:
    conn_org = get_db_connection()
    org_df = pd.read_sql_query("SELECT id, name FROM organizations", conn_org)
    conn_org.close()
except Exception: org_df = pd.DataFrame(columns=["id", "name"])
org_options = {"General / Sin Asignar": None}
for _, row in org_df.iterrows(): org_options[row["name"]] = row["id"]
selected_org_name = st.sidebar.selectbox("Cliente Objetivo", list(org_options.keys()))
selected_org_id = org_options[selected_org_name]

st.sidebar.markdown("---")
st.sidebar.header("⚙️ Configuración de Informe")
agency_name = st.sidebar.text_input("Agencia", value="SecOps Global Partners")
agency_tagline = st.sidebar.text_input("Subtítulo", value="Consultoría y Ciberseguridad")
report_type = st.sidebar.selectbox("Plantilla", ["Informe Técnico Exhaustivo", "Informe Narrativo", "Normativa (ISO/Compliance)"])
recipient_name = st.sidebar.text_input("Dirigido a", value="Dirección General")
report_subject = st.sidebar.text_input("Asunto", value="Evaluación de Riesgos")

tab1, tab2, tab3, tab4, tab5 = st.tabs(["🔍 Perimeter Scan", "📊 Security Analytics", "📜 Historial de Escaneos", "🛠️ Ticketera Jira-Style", "📖 Centro de Ayuda"])

with tab1:
    target_url = st.text_input("URL Objetivo", value="https://")
    if st.button("🚀 Ejecutar Análisis", type="primary"):
        if not target_url or target_url == "https://": st.error("URL inválida.")
        else:
            if not target_url.startswith("http"): target_url = "https://" + target_url
            with st.status("🔍 Analizando infraestructura y generando reportes...", expanded=True) as status:
                findings, stats, open_ports, hostname, subdomains, geo, email_sec, ssl_info, risk_score = scan_target(target_url)
                save_scan_to_db(hostname, geo["ip"], risk_score, len(findings), report_type, selected_org_id, findings)
                chart_b64 = generate_chart(stats)
                pdf_filename = f"auditoria_{hostname}.pdf"
                generate_pdf(findings, chart_b64, hostname, risk_score, agency_name, pdf_filename)
                docx_bytes = generate_docx(hostname, geo, email_sec, ssl_info, findings, risk_score, agency_name, agency_tagline, report_type, recipient_name, report_subject)
                status.update(label="✅ ¡Análisis completado!", state="complete", expanded=False)
                st.session_state.update(scanned=True, findings=findings, hostname=hostname, risk_score=risk_score, pdf_filename=pdf_filename, docx_bytes=docx_bytes)

    if st.session_state.scanned:
        st.success(f"¡Análisis completado para {st.session_state.hostname}!")
        st.markdown("<br>", unsafe_allow_html=True)
        # BOTONES CENTRADOS
        col_spacer1, col_dl1, col_dl2, col_dl3, col_spacer2 = st.columns([1.5, 3, 3, 3, 1.5])
        with col_dl1:
            if os.path.exists(st.session_state.pdf_filename):
                with open(st.session_state.pdf_filename, "rb") as pdf_file:
                    st.download_button("📥 PDF Ejecutivo", pdf_file, file_name=st.session_state.pdf_filename, mime="application/pdf", type="primary", use_container_width=True)
        with col_dl2:
            if "docx_bytes" in st.session_state:
                st.download_button("📝 DOCX Editable", st.session_state.docx_bytes, file_name=f"auditoria_{st.session_state.hostname}.docx", mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document", type="primary", use_container_width=True)
        with col_dl3:
            df_findings = pd.DataFrame(st.session_state.findings)
            st.download_button("📊 Exportar Hallazgos (CSV)", df_findings.to_csv(index=False, sep=";").encode("utf-8-sig"), file_name=f"hallazgos_{st.session_state.hostname}.csv", mime="text/csv", use_container_width=True)

with tab2:
    if st.session_state.scanned:
        st.subheader("Hallazgos con Descripciones y Remediación Enriquecida")
        for f in st.session_state.findings:
            with st.expander(f"📌 {f['vector']} [{f['severity']}]"):
                st.write(f"**Descripción del Problema:**\n {f['desc']}")
                st.write(f"**Impacto Potencial:**\n {f['impact']}")
                st.info(f"**Guía de Remediación Técnica:**\n {f['fix']}")
                if 'snippet' in f: st.code(f['snippet'])
    else: st.info("Ejecuta un escaneo primero.")

with tab3:
    history_df = get_scan_history(org_id=selected_org_id)
    if not history_df.empty: 
        # Mostramos la tabla ocultando el índice automático de Pandas y mostrando el ID real de BD
        st.dataframe(history_df, hide_index=True, use_container_width=True)
    else: st.info("No hay historial para este cliente.")

with tab4:
    st.subheader(f"🛠️ Tablero de Remediación (Ticketera Jira-Style) — {selected_org_name}")
    st.write("Selecciona el **ID de Escaneo** específico (el mismo que aparece en la pestaña de Historial) para gestionar sus incidentes.")
    try:
        conn = get_db_connection()
        ph = "%s" if "postgres" in st.secrets else "?"
        if selected_org_id is not None:
            scans_query = f"SELECT id, timestamp, hostname, risk_score FROM history WHERE organization_id = {ph} ORDER BY id DESC"
            scans_df = pd.read_sql_query(scans_query, conn, params=(selected_org_id,))
        else:
            scans_query = "SELECT id, timestamp, hostname, risk_score FROM history WHERE organization_id IS NULL ORDER BY id DESC"
            scans_df = pd.read_sql_query(scans_query, conn)
        conn.close()
    except Exception: scans_df = pd.DataFrame()
        
    if not scans_df.empty:
        scan_options = {f"ID Escaneo #{r['id']} - {r['hostname']} ({r['timestamp']})": r["id"] for _, r in scans_df.iterrows()}
        selected_scan_id = scan_options[st.selectbox("Seleccionar Escaneo a Trabajar", list(scan_options.keys()))]
        
        try:
            conn_cnt = get_db_connection()
            c_cnt = conn_cnt.cursor()
            c_cnt.execute(f"SELECT COUNT(*) FROM remediation_tasks WHERE scan_id = {ph} AND status = 'Pendiente'", (selected_scan_id,))
            count_pending = c_cnt.fetchone()[0]
            c_cnt.execute(f"SELECT COUNT(*) FROM remediation_tasks WHERE scan_id = {ph} AND status = 'En Proceso'", (selected_scan_id,))
            count_progress = c_cnt.fetchone()[0]
            c_cnt.execute(f"SELECT COUNT(*) FROM remediation_tasks WHERE scan_id = {ph} AND status = 'Solucionado'", (selected_scan_id,))
            count_resolved = c_cnt.fetchone()[0]
            c_cnt.close(); conn_cnt.close()
        except Exception: count_pending = count_progress = count_resolved = 0

        st.markdown("---")
        t_pend, t_prog, t_res = st.tabs([f"🟡 Pendientes ({count_pending})", f"🔄 En Proceso ({count_progress})", f"✅ Solucionados ({count_resolved})"])
        
        def render_tickets_for_status(status_filter, is_closed_tab=False):
            conn = get_db_connection()
            tasks_df = pd.read_sql_query(f"SELECT id, hostname, finding_vector, severity, status FROM remediation_tasks WHERE scan_id = {ph} AND status = {ph} ORDER BY id ASC", conn, params=(selected_scan_id, status_filter))
            conn.close()
                
            if not tasks_df.empty:
                for _, row in tasks_df.iterrows():
                    t_id, t_host, t_vec, t_sev, t_status = row["id"], row["hostname"], row["finding_vector"], row.get("severity", "MEDIO"), row["status"]
                    sev_class = "sev-critical" if "CRÍTICO" in t_sev.upper() else "sev-low" if "BAJO" in t_sev.upper() else "sev-medium"
                    st.markdown(f"""
                        <div class="ticket-card {sev_class if not is_closed_tab else 'sev-low'}">
                            <h3 style="margin-top:0; font-size:16px;">{'✅' if is_closed_tab else '📌'} Ticket #{t_id} | {t_vec}</h3>
                            <p style="margin:4px 0; color:#64748b;"><strong>Host:</strong> {t_host} | <strong>Severidad:</strong> {t_sev} | <strong>Estado:</strong> {t_status}</p>
                        </div>
                    """, unsafe_allow_html=True)

                    with st.container():
                        if not is_closed_tab:
                            col_t1, col_t2 = st.columns([2, 3])
                            with col_t1: new_status = st.selectbox("Mover a Estado", ["Pendiente", "En Proceso", "Solucionado"], index=["Pendiente", "En Proceso", "Solucionado"].index(t_status), key=f"s_{t_id}")
                            with col_t2: new_note = st.text_input("Nota de Avance / Bitácora", key=f"n_{t_id}", placeholder="Ej. Se aplicó regla en firewall...")
                                
                            if st.button("Actualizar y Guardar Nota", key=f"b_{t_id}"):
                                conn_u = get_db_connection(); conn_u.autocommit = True; c_u = conn_u.cursor()
                                c_u.execute(f"UPDATE remediation_tasks SET status = {ph} WHERE id = {ph}", (new_status, t_id))
                                c_u.execute(f"INSERT INTO remediation_logs (task_id, timestamp, status, notes) VALUES ({ph}, {ph}, {ph}, {ph})", (t_id, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), new_status, new_note))
                                c_u.close(); conn_u.close()
                                st.success("¡Ticket actualizado! Se movió de pestaña automáticamente."); st.rerun()
                                    
                        with st.expander(f"🕒 Ver Bitácora e Historial (Ticket #{t_id})"):
                            conn_l = get_db_connection()
                            logs_df = pd.read_sql_query(f"SELECT timestamp, status, notes FROM remediation_logs WHERE task_id = {ph} ORDER BY id DESC", conn_l, params=(t_id,))
                            conn_l.close()
                            if not logs_df.empty:
                                for _, log_row in logs_df.iterrows():
                                    st.markdown(f"**{log_row['timestamp']}** — Estado: `{log_row['status']}`\n> _{log_row['notes'] or 'Cambio de estado sin comentarios'}_")
                            else: st.info("Sin registros.")
                        st.markdown("---")
            else: st.info(f"No hay tickets en estado '{status_filter}'.")

        with t_pend: render_tickets_for_status("Pendiente")
        with t_prog: render_tickets_for_status("En Proceso")
        with t_res: render_tickets_for_status("Solucionado", is_closed_tab=True)
    else: st.info("Realiza un escaneo primero para generar tickets.")

with tab5:
    st.subheader("📖 Centro de Operaciones y Ayuda")
    st.markdown("""
    **Bienvenido al entorno Enterprise de CyberAudits.**
    
    Este panel está diseñado para que el equipo de ciberseguridad gestione el ciclo de vida completo de las vulnerabilidades:
    
    1. **Auditoría (Tab 1 y 2):** Ingresa un dominio y obtén al instante un Risk Score ejecutivo y un detalle técnico enriquecido de los hallazgos (SSL, Headers, Correos, Puertos).
    2. **Historial Centralizado (Tab 3):** Todos los escaneos quedan guardados en la base de datos bajo el `ID Escaneo` y asociados al cliente que seleccionaste en la barra lateral.
    3. **Resolución Ágil (Tab 4):** Ve al Tablero de Remediación, selecciona el escaneo por su ID y usa el flujo de trabajo estilo Kanban (Jira). 
        * Mueve los tickets a **En Proceso** mientras trabajas.
        * Deja documentado en la **Bitácora** los comandos que usaste.
        * Al pasarlo a **Solucionado**, el ticket se cierra y se archiva en su propia pestaña para facilitar futuras auditorías (Compliance).
    """)
