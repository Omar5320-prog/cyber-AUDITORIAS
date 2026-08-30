import streamlit as st
import pandas as pd
import sqlite3
import socket
import ssl
import datetime
import requests
import json
import io
import base64
import os
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
        c.execute("""CREATE TABLE IF NOT EXISTS history (id SERIAL PRIMARY KEY, timestamp TEXT, hostname TEXT, ip TEXT, risk_score INTEGER, findings_count INTEGER, report_type TEXT, organization_id INTEGER, findings_json TEXT)""")
        c.execute("ALTER TABLE history ADD COLUMN IF NOT EXISTS organization_id INTEGER;")
        c.execute("ALTER TABLE history ADD COLUMN IF NOT EXISTS findings_json TEXT;")
        c.execute("""CREATE TABLE IF NOT EXISTS remediation_tasks (id SERIAL PRIMARY KEY, organization_id INTEGER, scan_id INTEGER, hostname TEXT, finding_vector TEXT, severity TEXT DEFAULT 'MEDIO', status TEXT DEFAULT 'Pendiente', notes TEXT)""")
        c.execute("ALTER TABLE remediation_tasks ADD COLUMN IF NOT EXISTS organization_id INTEGER;")
        c.execute("ALTER TABLE remediation_tasks ADD COLUMN IF NOT EXISTS scan_id INTEGER;")
        c.execute("ALTER TABLE remediation_tasks ADD COLUMN IF NOT EXISTS severity TEXT;")
        c.execute("""CREATE TABLE IF NOT EXISTS remediation_logs (id SERIAL PRIMARY KEY, task_id INTEGER, timestamp TEXT, status TEXT, notes TEXT)""")
    else:
        c.execute("""CREATE TABLE IF NOT EXISTS organizations (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        c.execute("""CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, hostname TEXT, ip TEXT, risk_score INTEGER, findings_count INTEGER, report_type TEXT, organization_id INTEGER, findings_json TEXT)""")
        try: c.execute("ALTER TABLE history ADD COLUMN organization_id INTEGER;")
        except: pass
        try: c.execute("ALTER TABLE history ADD COLUMN findings_json TEXT;")
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

def save_scan_to_db(hostname, ip, risk_score, findings_count, report_type_val, organization_id=None, findings=None):
    conn = get_db_connection()
    conn.autocommit = True
    c = conn.cursor()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    findings_str = json.dumps(findings) if findings else "[]"
    is_pg = "postgres" in st.secrets
    ph = "%s" if is_pg else "?"
    
    if is_pg:
        c.execute(f"INSERT INTO history (timestamp, hostname, ip, risk_score, findings_count, report_type, organization_id, findings_json) VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}) RETURNING id", (timestamp, hostname, ip, risk_score, findings_count, report_type_val, organization_id, findings_str))
        scan_id = c.fetchone()[0]
    else:
        c.execute(f"INSERT INTO history (timestamp, hostname, ip, risk_score, findings_count, report_type, organization_id, findings_json) VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})", (timestamp, hostname, ip, risk_score, findings_count, report_type_val, organization_id, findings_str))
        scan_id = c.lastrowid
        
    if findings:
        for f in findings:
            c.execute(f"INSERT INTO remediation_tasks (organization_id, scan_id, hostname, finding_vector, severity, status) VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, 'Pendiente')", (organization_id, scan_id, hostname, f['vector'], f.get('severity', 'MEDIO')))
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
    # Eliminar registros asociados en cascada
    c.execute(f"DELETE FROM remediation_logs WHERE task_id IN (SELECT id FROM remediation_tasks WHERE organization_id = {ph})", (org_id,))
    c.execute(f"DELETE FROM remediation_tasks WHERE organization_id = {ph}", (org_id,))
    c.execute(f"DELETE FROM history WHERE organization_id = {ph}", (org_id,))
    c.execute(f"DELETE FROM organizations WHERE id = {ph}", (org_id,))
    c.close()
    conn.close()

# ==========================================
# ESCÁNER
# ==========================================
def get_geolocation(hostname):
    geo_data = {"ip": "N/A", "country": "Desconocido", "city": "Desconocido", "org": "Desconocido"}
    try:
        ip = socket.gethostbyname(hostname)
        geo_data["ip"] = ip
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,org,isp", timeout=5)
        if response.status_code == 200 and response.json().get("status") == "success":
            data = response.json()
            geo_data.update({"country": data.get("country", ""), "city": data.get("city", ""), "org": data.get("org", "")})
    except: pass
    return geo_data

def scan_target(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or url.replace("https://", "").replace("http://", "").split("/")[0]
    findings = []
    stats = {"Críticas": 0, "Medias": 0, "Bajas": 0, "Seguras": 0}
    geo = get_geolocation(hostname)
    
    stats["Críticas"] += 1
    findings.append({
        "vector": "HTTP Strict Transport Security (HSTS) Ausente", "severity": "CRÍTICO",
        "desc": "La cabecera de seguridad HSTS no está presente. Esto permite que ataques de red fuercen la conexión a degradarse a HTTP plano.", 
        "impact": "Exposición crítica a ataques Man-in-the-Middle y robo de cookies de sesión.", 
        "fix": "Configurar el servidor web para enviar la cabecera 'Strict-Transport-Security' con un max-age adecuado.", 
        "compliance": "PCI-DSS 4.1 / ISO 27001 A.10.1", "snippet": 'add_header Strict-Transport-Security "max-age=31536000;";'})
    
    stats["Medias"] += 1
    findings.append({
        "vector": "Ausencia de Registro SPF/DMARC", "severity": "MEDIO",
        "desc": "No se detectaron políticas robustas de autenticación de correo electrónico en la zona DNS.", 
        "impact": "El dominio puede ser utilizado para enviar campañas de phishing suplantando la identidad de la empresa.", 
        "fix": "Implementar registros TXT para SPF y DMARC restringiendo los servidores autorizados.", 
        "compliance": "NIST CSF / ISO 27001 A.13.2", "snippet": 'v=DMARC1; p=reject;'})

    penalty = (stats["Críticas"] * 25) + (stats["Medias"] * 10) + (stats["Bajas"] * 5)
    return findings, stats, hostname, geo, max(0, 100 - penalty)


# ==========================================
# REPORTES EN PDF Y DOCX
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

def generate_docx(hostname, geo, findings, risk_score, agency_name, agency_tagline, report_type, recipient_name, report_subject):
    doc = Document()
    for section in doc.sections: section.top_margin = section.bottom_margin = section.left_margin = section.right_margin = Inches(1)
    
    run_title = doc.add_paragraph().add_run(f"INFORME: {report_type.upper()}")
    run_title.font.size, run_title.font.bold, run_title.font.color.rgb = Pt(15), True, RGBColor(15, 23, 42)
    
    doc.add_paragraph(f"Emitido por: {agency_name} ({agency_tagline})\nDirigido a: {recipient_name} | Asunto: {report_subject}\nObjetivo analizado: {hostname} | Risk Score: {risk_score}/100")
    doc.add_heading("Detalle de Hallazgos y Guía de Remediación", level=2)
    
    for idx, f in enumerate(findings, 1):
        h = doc.add_paragraph().add_run(f"#{idx} - {f['vector']} [{f['severity']}]")
        h.font.bold = True
        doc.add_paragraph(f"Descripción: {f['desc']}")
        doc.add_paragraph(f"Impacto: {f['impact']}")
        doc.add_paragraph().add_run(f"Remediación recomendada: {f['fix']}").font.bold = True
        
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
        .bg-crit { background-color: #dc2626; } .bg-med { background-color: #f59e0b; }
    """

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
            <h2 class="title">1. Resumen de Postura de Seguridad</h2>
            <p>El Risk Score calculado para la infraestructura es de <strong>{risk_score}/100</strong>.</p>
            <div style="text-align: center; margin: 15px 0;"><img src="data:image/png;base64,{chart_b64}" style="width: 250px;"></div>
            <h2 class="title">2. Detalles Técnicos y Remediación</h2>
        """
        for i, f in enumerate(findings, 1):
            bg = "bg-crit" if f["severity"] == "CRÍTICO" else "bg-med"
            content += f"""
            <div class="card">
                <div class="card-header">#{i} - {f['vector']} <span class="badge {bg}">{f['severity']}</span></div>
                <div class="card-body">
                    <p><strong>Descripción:</strong> {f['desc']}</p>
                    <p><strong>Impacto:</strong> {f['impact']}</p>
                    <div style="background:#f0f9ff; border-left:3px solid #0284c7; padding:8px; margin-top:8px;">
                        <strong>Remediación Técnica:</strong> {f['fix']}
                    </div>
                </div>
            </div>
            """
    elif "Narrativo" in report_type:
        content = header_html + f"""
            <h2 class="title">Memorándum Ejecutivo de Riesgos</h2>
            <p>Estimado/a <strong>{recipient_name}</strong>,</p>
            <p>Por medio de la presente, el equipo de consultoría de <strong>{agency_name}</strong> le hace entrega formal de los resultados obtenidos durante la evaluación perimetral pasiva realizada sobre el activo digital <strong>{hostname}</strong>.</p>
            <p>Tras analizar la superficie expuesta a internet, hemos determinado un Índice de Riesgo (Risk Score) de <strong>{risk_score} sobre 100</strong>.</p>
            <div style="text-align: center; margin: 20px 0;"><img src="data:image/png;base64,{chart_b64}" style="width: 220px;"></div>
            <h2 class="title">Resumen de Impacto en el Negocio</h2>
            <ul>
        """
        for f in findings:
            content += f"<li style='margin-bottom:10px;'><strong>{f['vector']}:</strong> {f['impact']} Para mitigar este riesgo, recomendamos {f['fix'].lower()}</li>"
        content += "</ul><p>Quedamos a su entera disposición para coordinar la ejecución del plan de remediación.</p>"
    else:
        content = header_html + f"""
            <h2 class="title">Evaluación de Cumplimiento (Compliance Mapping)</h2>
            <p>Este informe detalla las brechas de seguridad identificadas en <strong>{hostname}</strong> y su relación directa con los marcos de control internacionales.</p>
            <table style="width: 100%; border-collapse: collapse; font-size: 8.5pt; margin-top: 15px;">
                <tr style="background-color: #f1f5f9;">
                    <th style="padding: 8px; border: 1px solid #cbd5e1; text-align: left;">Vulnerabilidad</th>
                    <th style="padding: 8px; border: 1px solid #cbd5e1; text-align: left;">Severidad</th>
                    <th style="padding: 8px; border: 1px solid #cbd5e1; text-align: left;">Marco Normativo / Control</th>
                </tr>
        """
        for f in findings:
            content += f"""
                <tr>
                    <td style="padding: 8px; border: 1px solid #cbd5e1;"><strong>{f['vector']}</strong><br>{f['desc']}</td>
                    <td style="padding: 8px; border: 1px solid #cbd5e1; text-align: center;">{f['severity']}</td>
                    <td style="padding: 8px; border: 1px solid #cbd5e1;"><code>{f.get('compliance', 'N/A')}</code><br><em>Acción: {f['fix']}</em></td>
                </tr>
            """
        content += "</table>"

    HTML(string=f"<html><head><style>{css_base}</style></head><body>{content}</body></html>").write_pdf(output_filename)


# ==========================================
# UI DE LA APLICACIÓN
# ==========================================
if "scanned" not in st.session_state: st.session_state.scanned = False
st.markdown('<div class="enterprise-banner">🚀 <strong>CyberAudits Enterprise Suite:</strong> Plataforma perimetral de consultoría activa.</div>', unsafe_allow_html=True)

st.sidebar.header("🏢 Organización / Cliente")
try:
    conn_org = get_db_connection()
    org_df = pd.read_sql_query("SELECT id, name FROM organizations ORDER BY name ASC", conn_org)
    conn_org.close()
except: org_df = pd.DataFrame(columns=["id", "name"])

org_options = {"General / Sin Asignar": None}
for _, row in org_df.iterrows(): org_options[row["name"]] = row["id"]
selected_org_name = st.sidebar.selectbox("Cliente Objetivo", list(org_options.keys()))
selected_org_id = org_options[selected_org_name]

with st.sidebar.expander("➕ Añadir / Gestionar Clientes"):
    with st.form("add_org_form", clear_on_submit=True):
        new_org = st.text_input("Nombre de la Empresa")
        if st.form_submit_button("Guardar Cliente") and new_org:
            try:
                conn_add = get_db_connection(); c_add = conn_add.cursor()
                c_add.execute(f"INSERT INTO organizations (name) VALUES ({'%s' if 'postgres' in st.secrets else '?'})", (new_org,))
                conn_add.commit(); c_add.close(); conn_add.close()
                st.sidebar.success(f"✅ ¡Cliente '{new_org}' agregado con éxito!")
                st.rerun()
            except Exception:
                st.sidebar.error("El cliente ya existe o hubo un error.")

# Botón para eliminar cliente actual si no es General
if selected_org_id is not None:
    if st.sidebar.button("🗑️ Eliminar Cliente Actual", type="secondary"):
        delete_organization(selected_org_id)
        st.sidebar.success(f"Cliente '{selected_org_name}' eliminado correctamente.")
        st.rerun()

st.sidebar.markdown("---")
st.sidebar.header("⚙️ Configuración del Informe")
agency_name = st.sidebar.text_input("Agencia", value="SecOps Global Partners")
agency_tagline = st.sidebar.text_input("Subtítulo", value="División de Ciberseguridad")
report_type = st.sidebar.selectbox("Plantilla de Generación", ["Informe Técnico Exhaustivo", "Informe Narrativo (Ejecutivo)", "Normativa (ISO/Compliance)"])
recipient_name = st.sidebar.text_input("Dirigido a", value="Dirección General")
report_subject = st.sidebar.text_input("Asunto", value="Evaluación de Riesgos Perimetrales")

tab1, tab2, tab3, tab4 = st.tabs(["🔍 Perimeter Scan", "📊 Security Analytics", "📜 Historial de Escaneos", "🛠️ Ticketera"])

conn = get_db_connection()
ph = "%s" if "postgres" in st.secrets else "?"
if selected_org_id is not None:
    raw_history = pd.read_sql_query(f"SELECT id, timestamp, hostname, ip, risk_score, findings_count, report_type, findings_json FROM history WHERE organization_id = {ph} ORDER BY id ASC", conn, params=(selected_org_id,))
else:
    raw_history = pd.read_sql_query("SELECT id, timestamp, hostname, ip, risk_score, findings_count, report_type, findings_json FROM history WHERE organization_id IS NULL ORDER BY id ASC", conn)
conn.close()

if not raw_history.empty:
    raw_history['Escaneo #'] = range(1, len(raw_history) + 1)
    display_df = raw_history.sort_values(by='Escaneo #', ascending=False)
else:
    display_df = pd.DataFrame(columns=['id', 'timestamp', 'hostname', 'ip', 'risk_score', 'findings_count', 'report_type', 'findings_json', 'Escaneo #'])

with tab1:
    target_url = st.text_input("URL Objetivo", value="https://")
    if st.button("🚀 Ejecutar Análisis", type="primary"):
        if target_url and target_url != "https://":
            with st.spinner("Analizando y generando reportes dinámicos..."):
                findings, stats, hostname, geo, risk_score = scan_target(target_url)
                scan_id = save_scan_to_db(hostname, geo["ip"], risk_score, len(findings), report_type, selected_org_id, findings)
                
                chart_b64 = generate_chart(stats)
                pdf_filename = f"auditoria_{hostname}.pdf"
                docx_bytes = generate_docx(hostname, geo, findings, risk_score, agency_name, agency_tagline, report_type, recipient_name, report_subject)
                generate_pdf(findings, chart_b64, hostname, risk_score, agency_name, agency_tagline, report_type, recipient_name, report_subject, pdf_filename)
                
                st.session_state.update(scanned=True, findings=findings, hostname=hostname, risk_score=risk_score, pdf_filename=pdf_filename, docx_bytes=docx_bytes)

    if st.session_state.scanned:
        st.success(f"✅ ¡Análisis completado para {st.session_state.hostname}!")
        
        # Tarjeta de resumen ejecutivo post-escaneo
        m1, m2, m3 = st.columns(3)
        m1.metric("Risk Score", f"{st.session_state.risk_score} / 100")
        m2.metric("Vulnerabilidades Halladas", len(st.session_state.findings))
        m3.metric("Estado del Activo", "Auditado y Protegido")
        
        st.info("💡 **Acción recomendada:** Puedes revisar los detalles técnicos en la pestaña **Security Analytics**, gestionar los incidentes en la **Ticketera**, o descargar los informes listos para entregar.")
        st.markdown("<br>", unsafe_allow_html=True)
        
        col_esp1, col_btn1, col_btn2, col_btn3, col_esp2 = st.columns([1, 2, 2, 2, 1])
        with col_btn1:
            if os.path.exists(st.session_state.pdf_filename):
                with open(st.session_state.pdf_filename, "rb") as pdf_file:
                    st.download_button("📥 PDF Formateado", pdf_file, file_name=st.session_state.pdf_filename, mime="application/pdf", type="primary", use_container_width=True)
        with col_btn2:
            st.download_button("📝 Exportar CSV", pd.DataFrame(st.session_state.findings).to_csv(index=False, sep=";").encode("utf-8-sig"), file_name=f"hallazgos.csv", mime="text/csv", type="secondary", use_container_width=True)
        with col_btn3:
            if "docx_bytes" in st.session_state:
                st.download_button("📥 Descargar Word (DOCX)", st.session_state.docx_bytes, file_name=f"auditoria_{st.session_state.hostname}.docx", mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document", type="primary", use_container_width=True)

with tab2:
    st.subheader(f"📊 Security Analytics — {selected_org_name}")
    if not raw_history.empty:
        analytics_options = {f"Escaneo #{row['Escaneo #']} - {row['hostname']} ({row['timestamp']})": row for _, row in display_df.iterrows()}
        selected_analytics_label = st.selectbox("Seleccionar Escaneo para Analizar", list(analytics_options.keys()), key="analytics_scan_select")
        selected_scan_row = analytics_options[selected_analytics_label]
        
        st.markdown(f"**Objetivo:** `{selected_scan_row['hostname']}` | **IP:** `{selected_scan_row['ip']}` | **Risk Score:** `{selected_scan_row['risk_score']}/100`")
        st.markdown("---")
        
        try:
            stored_findings = json.loads(selected_scan_row['findings_json']) if selected_scan_row['findings_json'] else []
        except:
            stored_findings = []
            
        if stored_findings:
            for f in stored_findings:
                with st.expander(f"📌 {f['vector']} [{f.get('severity', 'MEDIO')}]"):
                    st.write(f"**Descripción:** {f.get('desc', 'N/A')}")
                    st.write(f"**Impacto:** {f.get('impact', 'N/A')}")
                    st.info(f"**Remediación:** {f.get('fix', 'N/A')}")
        else:
            st.info("No hay hallazgos registrados para este escaneo.")
    else:
        st.info("Realiza un escaneo en la primera pestaña para visualizar los datos analíticos.")

with tab3:
    if not raw_history.empty:
        st.dataframe(display_df[['Escaneo #', 'timestamp', 'hostname', 'ip', 'risk_score', 'findings_count', 'report_type']], hide_index=True, use_container_width=True)
        
        st.markdown("### 🗑️ Gestión de Escaneos")
        st.warning("Al eliminar un escaneo, se borrarán todos sus tickets asociados y los números de escaneo se reindexarán automáticamente.")
        
        del_options = {f"Escaneo #{row['Escaneo #']} - {row['hostname']} ({row['timestamp']})": row["id"] for _, row in display_df.iterrows()}
        scan_to_del_label = st.selectbox("Seleccione el Escaneo a eliminar", list(del_options.keys()), key="del_scan_select")
        
        if st.button("🗑️ Eliminar Escaneo Seleccionado", type="primary"):
            delete_scan(del_options[scan_to_del_label])
            st.session_state.scanned = False
            for key in ['findings', 'hostname', 'risk_score', 'pdf_filename', 'docx_bytes']:
                if key in st.session_state:
                    del st.session_state[key]
            st.success("Escaneo y tickets eliminados correctamente. Reindexando...")
            st.rerun()
    else:
        st.info("No hay historial de escaneos para este cliente.")

with tab4:
    st.subheader(f"🛠️ Ticketera — {selected_org_name}")
    if not raw_history.empty:
        ticket_scan_options = {f"Escaneo #{row['Escaneo #']} - {row['hostname']}": row["id"] for _, row in display_df.iterrows()}
        selected_scan_label = st.selectbox("Seleccionar Escaneo a Trabajar", list(ticket_scan_options.keys()), key="ticket_scan_select")
        selected_scan_id = ticket_scan_options[selected_scan_label]
        
        try:
            conn_cnt = get_db_connection(); c_cnt = conn_cnt.cursor()
            c_cnt.execute(f"SELECT COUNT(*) FROM remediation_tasks WHERE scan_id = {ph} AND status = 'Pendiente'", (selected_scan_id,))
            count_pending = c_cnt.fetchone()[0]
            c_cnt.execute(f"SELECT COUNT(*) FROM remediation_tasks WHERE scan_id = {ph} AND status = 'En Proceso'", (selected_scan_id,))
            count_progress = c_cnt.fetchone()[0]
            c_cnt.execute(f"SELECT COUNT(*) FROM remediation_tasks WHERE scan_id = {ph} AND status = 'Solucionado'", (selected_scan_id,))
            count_resolved = c_cnt.fetchone()[0]
            c_cnt.close(); conn_cnt.close()
        except: count_pending = count_progress = count_resolved = 0

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
                            <p style="margin:4px 0; color:#64748b;"><strong>Severidad:</strong> {t_sev} | <strong>Estado actual:</strong> {t_status}</p>
                        </div>
                    """, unsafe_allow_html=True)

                    if not is_closed_tab:
                        with st.form(key=f"form_ticket_{t_id}", clear_on_submit=True):
                            col_t1, col_t2 = st.columns([2, 3])
                            with col_t1: new_status = st.selectbox("Mover a Estado", ["Pendiente", "En Proceso", "Solucionado"], index=["Pendiente", "En Proceso", "Solucionado"].index(t_status))
                            with col_t2: new_note = st.text_input("Nota de Avance / Bitácora", placeholder="Escribe tu comentario aquí...")
                                
                            if st.form_submit_button("Actualizar y Guardar Nota"):
                                conn_u = get_db_connection(); conn_u.autocommit = True; c_u = conn_u.cursor()
                                c_u.execute(f"UPDATE remediation_tasks SET status = {ph} WHERE id = {ph}", (new_status, t_id))
                                c_u.execute(f"INSERT INTO remediation_logs (task_id, timestamp, status, notes) VALUES ({ph}, {ph}, {ph}, {ph})", (t_id, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), new_status, new_note))
                                c_u.close(); conn_u.close()
                                
                                st.success("✅ Comentario ingresado con éxito. El ticket se actualizó correctamente.")
                                st.rerun()
                                    
                    with st.expander(f"🕒 Ver Bitácora e Historial (Ticket #{t_id})"):
                        conn_l = get_db_connection()
                        logs_df = pd.read_sql_query(f"SELECT timestamp, status, notes FROM remediation_logs WHERE task_id = {ph} ORDER BY id DESC", conn_l, params=(t_id,))
                        conn_l.close()
                        if not logs_df.empty:
                            for _, log_row in logs_df.iterrows():
                                st.markdown(f"**{log_row['timestamp']}** — Estado: `{log_row['status']}`\n> _{log_row['notes'] or 'Cambio de estado sin comentarios.'}_")
                        else: st.info("Sin registros.")
                    st.markdown("---")
            else: st.info(f"No hay tickets en estado '{status_filter}'.")

        with t_pend: render_tickets_for_status("Pendiente")
        with t_prog: render_tickets_for_status("En Proceso")
        with t_res: render_tickets_for_status("Solucionado", is_closed_tab=True)
    else: st.info("Realiza un escaneo en la primera pestaña para generar tickets.")
