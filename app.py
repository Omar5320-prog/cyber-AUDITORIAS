import base64
import datetime
import io
import json
import os
import socket
import ssl
import sqlite3
from urllib.parse import urlparse
from docx import Document
from docx.shared import Inches, Pt, RGBColor
import matplotlib.pyplot as plt
import pandas as pd
import requests
from weasyprint import HTML
import streamlit as st

st.set_page_config(
    page_title="CyberAudits - Escáner Perimetral",
    page_icon="🛡️",
    layout="wide",
)


def init_db():
  conn = sqlite3.connect("cyber_audits.db")
  c = conn.cursor()
  c.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            hostname TEXT,
            ip TEXT,
            risk_score INTEGER,
            findings_count INTEGER,
            report_type TEXT
        )
    """)
  c.execute("PRAGMA table_info(history)")
  columns = [col[1] for col in c.fetchall()]
  if "risk_score" not in columns:
    try:
      c.execute("ALTER TABLE history ADD COLUMN risk_score INTEGER DEFAULT 0")
    except Exception:
      pass
  conn.commit()
  conn.close()


init_db()


def save_scan_to_db(
    hostname, ip, risk_score, findings_count, report_type_val
):
  try:
    conn = sqlite3.connect("cyber_audits.db")
    c = conn.cursor()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute(
        "INSERT INTO history (timestamp, hostname, ip, risk_score,"
        " findings_count, report_type) VALUES (?, ?, ?, ?, ?, ?)",
        (timestamp, hostname, ip, risk_score, findings_count, report_type_val),
    )
    conn.commit()
    conn.close()
  except Exception:
    pass


def get_scan_history():
  conn = sqlite3.connect("cyber_audits.db")
  df = pd.read_sql_query(
      "SELECT timestamp AS 'Fecha y Hora', hostname AS 'Dominio / Host', ip AS"
      " 'IP', risk_score AS 'Risk Score (/100)', findings_count AS"
      " 'Vulnerabilidades', report_type AS 'Plantilla' FROM history ORDER BY id"
      " DESC",
      conn,
  )
  conn.close()
  return df


st.markdown(
    """
    <style>
        .stApp { background-color: #f8fafc; color: #1e293b; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        [data-testid="stSidebar"] { background-color: #f0f2f6 !important; border-right: 1px solid #e2e8f0; }
        [data-testid="stSidebar"] label, [data-testid="stSidebar"] .stMarkdown, [data-testid="stSidebar"] span, [data-testid="stSidebar"] p, [data-testid="stSidebar"] h2 { color: #1e293b !important; }
        [data-testid="stSidebar"] input, [data-testid="stSidebar"] div[data-baseweb="select"] > div { background-color: #ffffff !important; color: #1e293b !important; border-color: #cbd5e1 !important; }
        .enterprise-banner { background: linear-gradient(90deg, #1e3a8a, #3b82f6); padding: 12px 20px; border-radius: 8px; color: white; text-align: center; margin-bottom: 20px; font-weight: 500; }
    </style>
    """,
    unsafe_allow_html=True,
)


def get_geolocation(hostname):
  geo_data = {
      "ip": "N/A",
      "country": "Desconocido",
      "city": "Desconocido",
      "org": "Desconocido",
  }
  try:
    ip = socket.gethostbyname(hostname)
    geo_data["ip"] = ip
    url = f"http://ip-api.com/json/{ip}?fields=status,country,city,org,isp"
    response = requests.get(url, timeout=5)
    if response.status_code == 200:
      data = response.json()
      if data.get("status") == "success":
        geo_data["country"] = data.get("country", "Desconocido")
        geo_data["city"] = data.get("city", "Desconocido")
        geo_data["org"] = data.get("org", data.get("isp", "Desconocido"))
  except Exception:
    pass
  return geo_data


def check_ssl_certificate(hostname):
  ssl_info = {
      "valid": False,
      "issuer": "Desconocido",
      "expires_soon": False,
      "days_remaining": 0,
      "details": "No se pudo verificar el certificado SSL/TLS.",
  }
  try:
    context = ssl.create_default_context()
    with socket.create_connection((hostname, 443), timeout=5) as sock:
      with context.wrap_socket(sock, server_hostname=hostname) as ssock:
        cert = ssock.getpeercert()
        not_after_str = cert.get("notAfter")
        if not_after_str:
          expires_date = datetime.datetime.strptime(
              not_after_str, "%b %d %H:%M:%S %Y %Z"
          )
          days_left = (expires_date - datetime.datetime.utcnow()).days
          ssl_info["days_remaining"] = days_left
          ssl_info["valid"] = True
          issuer_dict = dict(
              x[0] for x in cert.get("issuer", ((("commonName", ""),),))
          )
          ssl_info["issuer"] = issuer_dict.get(
              "commonName", issuer_dict.get("organizationName", "Desconocido")
          )
          if days_left < 30:
            ssl_info["expires_soon"] = True
            ssl_info["details"] = (
                f"Certificado válido pero expira pronto ({days_left} días"
                " restantes)."
            )
          else:
            ssl_info["details"] = (
                f"Certificado SSL válido. Expira en {days_left} días."
            )
  except Exception as e:
    ssl_info["details"] = f"Error al verificar SSL: {str(e)}"
  return ssl_info


def check_email_security(hostname):
  email_sec = {"spf": False, "dmarc": False}
  try:
    res_spf = requests.get(
        f"https://cloudflare-dns.com/dns-query?name={hostname}&type=TXT",
        headers={"Accept": "application/dns-json"},
        timeout=4,
    )
    if res_spf.status_code == 200:
      for ans in res_spf.json().get("Answer", []):
        if "v=spf1" in ans.get("data", ""):
          email_sec["spf"] = True

    res_dmarc = requests.get(
        f"https://cloudflare-dns.com/dns-query?name=_dmarc.{hostname}&type=TXT",
        headers={"Accept": "application/dns-json"},
        timeout=4,
    )
    if res_dmarc.status_code == 200:
      for ans in res_dmarc.json().get("Answer", []):
        if "v=DMARC1" in ans.get("data", ""):
          email_sec["dmarc"] = True
  except Exception:
    pass
  return email_sec


def discover_subdomains(domain):
  subdomains = set()
  try:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    response = requests.get(url, timeout=10)
    if response.status_code == 200:
      data = response.json()
      for entry in data:
        name_value = entry.get("name_value", "")
        for sub in name_value.split("\n"):
          sub = sub.strip().lower()
          if domain in sub and "*" not in sub and "@" not in sub:
            subdomains.add(sub)
  except Exception:
    pass
  return sorted(list(subdomains))[:12]


def scan_ports(hostname):
  common_ports = {
      21: "FTP",
      22: "SSH",
      80: "HTTP",
      443: "HTTPS",
      3306: "MySQL",
      8080: "HTTP-Proxy",
      8443: "HTTPS-Panel",
  }
  open_ports = []
  for port, service in common_ports.items():
    try:
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      s.settimeout(1.0)
      result = s.connect_ex((hostname, port))
      if result == 0:
        open_ports.append({"port": port, "service": service})
      s.close()
    except Exception:
      pass
  return open_ports


def scan_target(url):
  parsed_url = urlparse(url)
  hostname = parsed_url.hostname or url.replace("https://", "").replace(
      "http://", ""
  ).split("/")[0]

  findings = []
  stats = {"Críticas": 0, "Medias": 0, "Bajas": 0, "Seguras": 0}

  open_ports = scan_ports(hostname)
  subdomains = discover_subdomains(hostname)
  geo = get_geolocation(hostname)
  email_sec = check_email_security(hostname)
  ssl_info = check_ssl_certificate(hostname)

  if not ssl_info["valid"]:
    stats["Críticas"] += 1
    findings.append({
        "vector": "Certificado SSL/TLS Inválido o Ausente",
        "severity": "CRÍTICO",
        "badge": "badge-critical",
        "exec_title": "Fallo Crítico en Cifrado HTTPS",
        "desc": ssl_info["details"],
        "impact": "Bloqueo de navegación y alertas de fraude.",
        "fix": "Instalar certificado SSL válido.",
        "compliance": "PCI-DSS 4.1 / ISO 27001 A.10.1",
        "snippet": f"certbot --nginx -d {hostname}",
    })
  elif ssl_info["expires_soon"]:
    stats["Medias"] += 1
    findings.append({
        "vector": (
            f"Certificado SSL/TLS próximo a expirar"
            f" ({ssl_info['days_remaining']} días)"
        ),
        "severity": "MEDIO",
        "badge": "badge-medium",
        "exec_title": "Riesgo de Expiración SSL",
        "desc": ssl_info["details"],
        "impact": "Caída temporal de servicios seguros.",
        "fix": "Renovar certificado.",
        "compliance": "ISO 27001 A.12.1",
        "snippet": "certbot renew --dry-run",
    })
  else:
    stats["Seguras"] += 1

  if email_sec["spf"]:
    stats["Seguras"] += 1
  else:
    stats["Medias"] += 1
    findings.append({
        "vector": "Ausencia de Registro SPF (Phishing)",
        "severity": "MEDIO",
        "badge": "badge-medium",
        "exec_title": "Vulnerabilidad en Postura de Correo",
        "desc": "El dominio carece de registro SPF.",
        "impact": "Riesgo alto de suplantación y phishing.",
        "fix": "Publicar registro TXT SPF.",
        "compliance": "ISO 27001 A.13.2",
        "snippet": (
            f"{hostname}. 3600 IN TXT \"v=spf1 include:_spf.example.com ~all\""
        ),
    })

  if email_sec["dmarc"]:
    stats["Seguras"] += 1
  else:
    stats["Medias"] += 1
    findings.append({
        "vector": "Ausencia de Política DMARC",
        "severity": "MEDIO",
        "badge": "badge-medium",
        "exec_title": "Falta de Autenticación DMARC",
        "desc": "El dominio carece de política DMARC.",
        "impact": "Falta de control ante fraude de correo.",
        "fix": "Configurar TXT _dmarc.",
        "compliance": "ISO 27001 A.13.1",
        "snippet": (
            f"_dmarc.{hostname}. 3600 IN TXT \"v=DMARC1; p=reject;\""
        ),
    })

  for p in open_ports:
    if p["port"] in [21, 3306, 8080, 8443]:
      stats["Medias"] += 1
      findings.append({
          "port": p["port"],
          "service": p["service"],
          "vector": f"Puerto {p['port']} ({p['service']}) Abierto al Público",
          "severity": "MEDIO",
          "badge": "badge-medium",
          "exec_title": f"Servicio Expuesto en Puerto {p['port']}",
          "desc": f"El puerto {p['port']} es accesible desde internet.",
          "impact": "Riesgo de ataques de fuerza bruta.",
          "fix": "Restringir acceso por Firewall.",
          "compliance": "PCI-DSS 1.3 / ISO 27001 A.13.1",
          "snippet": f"sudo ufw deny {p['port']}/tcp",
      })

  try:
    response = requests.get(url, timeout=10)
    headers = response.headers
    if "Strict-Transport-Security" in headers:
      stats["Seguras"] += 1
    else:
      stats["Críticas"] += 1
      findings.append({
          "vector": "HTTP Strict Transport Security (HSTS) Ausente",
          "severity": "CRÍTICO",
          "badge": "badge-critical",
          "exec_title": "Ausencia de HSTS",
          "desc": "Cabecera HSTS no configurada.",
          "impact": "Intercepción de tráfico en redes públicas.",
          "fix": "Añadir cabecera HSTS.",
          "compliance": "PCI-DSS 4.1 / ISO 27001 A.14.1",
          "snippet": (
              'add_header Strict-Transport-Security "max-age=31536000;" always;'
          ),
      })
    if "Server" in headers:
      stats["Medias"] += 1
      findings.append({
          "vector": "Exposición de Versión del Servidor",
          "severity": "MEDIO",
          "badge": "badge-medium",
          "exec_title": "Server Banner Leak",
          "desc": f"Cabecera expone: {headers.get('Server')}",
          "impact": "Facilita ataques orientados a versiones.",
          "fix": "Ocultar firma del servidor.",
          "compliance": "ISO 27001 A.12.6",
          "snippet": "server_tokens off;",
      })
    else:
      stats["Seguras"] += 1
    if "X-Frame-Options" in headers or "Content-Security-Policy" in headers:
      stats["Seguras"] += 1
    else:
      stats["Bajas"] += 1
      findings.append({
          "vector": "Protección Clickjacking Ausente",
          "severity": "BAJO",
          "badge": "badge-low",
          "exec_title": "Riesgo Clickjacking",
          "desc": "Falta de control en marcos externos.",
          "impact": "Carga maliciosa bajo botones trampa.",
          "fix": "Añadir X-Frame-Options.",
          "compliance": "OWASP / ISO 27001 A.14.1",
          "snippet": 'add_header X-Frame-Options "SAMEORIGIN";',
      })
  except Exception:
    pass

  penalty = (
      (stats["Críticas"] * 25) + (stats["Medias"] * 10) + (stats["Bajas"] * 5)
  )
  risk_score = max(0, 100 - penalty)
  return (
      findings,
      stats,
      open_ports,
      hostname,
      subdomains,
      geo,
      email_sec,
      ssl_info,
      risk_score,
  )


def generate_chart(stats):
  labels = list(stats.keys())
  sizes = list(stats.values())
  colors = ["#dc2626", "#f59e0b", "#3b82f6", "#10b981"]
  non_zero_data = [
      (l, s, c) for l, s, c in zip(labels, sizes, colors) if s > 0
  ]
  if not non_zero_data:
    non_zero_data = [("Seguras", 1, "#10b981")]
  l_filt, s_filt, c_filt = zip(*non_zero_data)
  fig, ax = plt.subplots(figsize=(4.5, 2.8))
  ax.pie(
      s_filt,
      labels=l_filt,
      colors=c_filt,
      autopct="%1.1f%%",
      startangle=90,
      textprops={"fontsize": 8.5, "weight": "bold"},
  )
  ax.axis("equal")
  plt.title(
      "Distribución de Riesgos",
      fontsize=9.5,
      fontweight="bold",
      color="#1e293b",
  )
  plt.tight_layout()
  chart_path = "vulnerability_chart.png"
  plt.savefig(chart_path, dpi=300, bbox_inches="tight", transparent=True)
  plt.close()
  with open(chart_path, "rb") as f:
    return base64.b64encode(f.read()).decode("utf-8")


def generate_docx(
    hostname,
    geo,
    email_sec,
    ssl_info,
    open_ports,
    subdomains,
    findings,
    risk_score,
    agency_name,
    agency_tagline,
    report_type,
    recipient_name,
    report_subject,
):
  doc = Document()
  for section in doc.sections:
    section.top_margin = Inches(1)
    section.bottom_margin = Inches(1)
    section.left_margin = Inches(1)
    section.right_margin = Inches(1)

  doc.add_paragraph().add_run(f"INFORME: {report_type.upper()}").font.size = (
      Pt(14)
  )
  doc.add_paragraph().add_run(
      f"Objetivo: {hostname} | Risk Score: {risk_score}/100 | Emitido por:"
      f" {agency_name}"
  )

  doc.add_heading("Resumen y Metadatos", level=2)
  doc.add_paragraph(
      f"IP: {geo['ip']} | Ubicación: {geo['city']}, {geo['country']}"
  )

  doc.add_heading("Hallazgos de Seguridad", level=2)
  for idx, f in enumerate(findings, 1):
    doc.add_paragraph(
        f"#{idx} - {f['vector']} [{f['severity']}] (Norma:"
        f" {f.get('compliance', 'N/A')})"
    )
    doc.add_paragraph(f"Impacto: {f['impact']}")
    if "Informe de Normativa" in report_type and "snippet" in f:
      doc.add_paragraph(f"Configuración: {f['snippet']}")

  buffer = io.BytesIO()
  doc.save(buffer)
  buffer.seek(0)
  return buffer.getvalue()


def generate_pdf(
    url,
    findings,
    stats,
    chart_base64,
    open_ports,
    hostname,
    subdomains,
    geo,
    email_sec,
    ssl_info,
    risk_score,
    agency_name,
    agency_tagline,
    report_type,
    recipient_name,
    report_subject,
    logo_b64,
    output_filename,
):
  logo_html = (
      f'<img src="data:image/png;base64,{logo_b64}" style="max-height: 50px;'
      ' float: right;" alt="Logo">'
      if logo_b64
      else ""
  )

  # Filtrar o adaptar según el tipo de informe seleccionado
  if "Narrativo" in report_type:
    # Formato corto y entendible para gerencia / no técnicos
    content_html = f"""
        <h2>Resumen Ejecutivo</h2>
        <p>Estimado equipo de <strong>{recipient_name}</strong>,</p>
        <p>Se ha realizado una evaluación perimetral sobre el dominio <strong>{hostname}</strong> por parte de <em>{agency_name}</em>. El objetivo de este informe es presentar de manera clara y sin tecnicismos complejos el estado actual de seguridad.</p>
        <div style="background:#eff6ff; border-left:4px solid #3b82f6; padding:10px; margin:10px 0;">
            <p style="margin:0;"><strong>Calificación de Riesgo (Risk Score):</strong> <span style="font-size:14pt; font-weight:bold; color: {'#10b981' if risk_score > 70 else '#f59e0b' if risk_score > 40 else '#dc2626'};">{risk_score} / 100</span></p>
            <p style="margin:5px 0 0 0;">Se detectaron un total de <strong>{len(findings)} áreas de mejora</strong> que deben ser atendidas para proteger la reputación y continuidad del negocio.</p>
        </div>
        <h3>Puntos Clave a Considerar:</h3>
        <ul>
            <li><strong>Cifrado Web (SSL/TLS):</strong> {ssl_info['details']}</li>
            <li><strong>Protección de Correo:</strong> {'Los registros de correo están seguros.' if email_sec['spf'] and email_sec['dmarc'] else 'Se detectó ausencia de protecciones de correo, lo que facilita el phishing a nombre de su marca.'}</li>
            <li><strong>Superficie Expuesta:</strong> Se identificaron puertos abiertos accesibles desde internet que incrementan el riesgo de accesos no autorizados.</li>
        </ul>
        <p>Recomendamos autorizar al equipo técnico la aplicación de las medidas correctivas correspondientes.</p>
        """
  elif "Normativa" in report_type:
    # Formato enfocado en normas ISO/PCI y remediación técnica pura
    items_html = ""
    for idx, f in enumerate(findings, 1):
      items_html += f"""
            <div style="border:1px solid #cbd5e1; padding:8px; margin-bottom:8px; border-radius:4px;">
                <strong>#{idx} {f['vector']}</strong> [{f['severity']}]<br>
                <strong>Norma Asociada:</strong> <code>{f.get('compliance', 'N/A')}</code><br>
                <strong>Remediación:</strong> {f['fix']}<br>
                <pre style="background:#f1f5f9; padding:4px; font-size:7pt;"><code>{f.get('snippet', '')}</code></pre>
            </div>
            """
    content_html = f"""
        <h2>Matriz de Compliance y Guía de Remediación</h2>
        <p>Objetivo: <strong>{hostname}</strong> | Risk Score: <strong>{risk_score}/100</strong></p>
        {items_html}
        """
  else:
    # Informe Técnico Completo Estándar
    items_html = ""
    for idx, f in enumerate(findings, 1):
      items_html += f"""
            <div style="border:1px solid #cbd5e1; padding:6px; margin-bottom:5px;">
                <strong>#{idx} {f['vector']}</strong> [{f['severity']}]<br>
                Descripción: {f['desc']}<br>Impacto: {f['impact']}<br>Remediación: {f['fix']}
            </div>
            """
    content_html = f"""
        <h2>Informe Técnico Exhaustivo</h2>
        <p>Objetivo: <strong>{hostname}</strong> | IP: {geo['ip']}</p>
        <div style="text-align:center;"><img src="data:image/png;base64,{chart_base64}" style="max-width:50%;"></div>
        <h3>Hallazgos Técnicos Detallados:</h3>
        {items_html}
        """

  html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <style>
            @page {{ size: A4; margin: 12mm; @bottom-right {{ content: "Página " counter(page); font-size: 8pt; color: #64748b; }} }}
            body {{ font-family: Helvetica, Arial, sans-serif; color: #334155; font-size: 8.5pt; line-height: 1.4; }}
            .header {{ background: #0f172a; color: white; padding: 12px; border-radius: 4px; overflow: hidden; }}
            .header h1 {{ margin: 0; font-size: 12pt; }}
        </style>
    </head>
    <body>
        <div class="header">
            <div style="float:left;"><h1>{report_type}</h1><p style="margin:0; font-size:7.5pt; color:#94a3b8;">{agency_name}</p></div>
            <div style="float:right;">{logo_html}</div>
        </div>
        {content_html}
    </body>
    </html>
    """
  HTML(string=html_content).write_pdf(output_filename)


if "scanned" not in st.session_state:
  st.session_state.scanned = False

st.markdown(
    """
    <div class="enterprise-banner">
        🚀 <strong>CyberAudits Enterprise:</strong> 3 Modelos de Informe Activos (Completo, Narrativo y Normativa).
    </div>
    """,
    unsafe_allow_html=True,
)

st.title("🛡️ CyberAudits - Escáner Perimetral")
st.write(
    "Selecciona el modelo de informe deseado en la barra lateral y ejecuta el"
    " análisis."
)

st.sidebar.header("⚙️ Configuración del Informe")
agency_name = st.sidebar.text_input(
    "Nombre de la Agencia", value="SecOps Global Partners"
)
agency_tagline = st.sidebar.text_input(
    "Subtítulo / Área", value="División de Ciberseguridad"
)
logo_file = st.sidebar.file_uploader(
    "Logo (PNG / JPG)", type=["png", "jpg", "jpeg"]
)

# ÚNICAMENTE TRES TIPOS DE INFORMES
report_type = st.sidebar.selectbox(
    "Plantilla / Modelo de Informe",
    [
        "Informe Técnico Completo (Estándar)",
        "Informe Ejecutivo Narrativo",
        "Informe de Normativa y Remediación (ISO / Compliance)",
    ],
)

recipient_name = st.sidebar.text_input(
    "Dirigido a (Gerencia / Cliente)",
    value="Dirección General / Junta Directiva",
)
report_subject = st.sidebar.text_input(
    "Asunto", value="Evaluación de Riesgos Perimetrales"
)

tab1, tab2, tab3, tab4 = st.tabs([
    "🔍 Perimeter Scan",
    "📊 Security Analytics",
    "📜 Historial de Escaneos",
    "ℹ️ About CyberAudits",
])

with tab1:
  st.markdown("### 🎯 Quick Test Targets")
  col_btn1, col_btn2, col_btn3 = st.columns(3)
  quick_domain = ""
  if col_btn1.button("🌐 example.com"):
    quick_domain = "example.com"
  if col_btn2.button("🌐 scanme.nmap.org"):
    quick_domain = "scanme.nmap.org"
  if col_btn3.button("🌐 testphp.vulnweb.com"):
    quick_domain = "testphp.vulnweb.com"

  target_url = st.text_input(
      "URL Objetivo", value=quick_domain if quick_domain else "https://"
  )

  if st.button("🚀 Ejecutar Análisis Completo"):
    if not target_url or target_url == "https://":
      st.error("Introduce una URL válida.")
    else:
      if not target_url.startswith("http"):
        target_url = "https://" + target_url

      with st.status(
          "🔍 Analizando objetivo y generando reporte...", expanded=True
      ) as status:
        (
            findings,
            stats,
            open_ports,
            hostname,
            subdomains,
            geo,
            email_sec,
            ssl_info,
            risk_score,
        ) = scan_target(target_url)
        save_scan_to_db(
            hostname,
            geo["ip"],
            risk_score,
            len(findings),
            report_type,
        )

        chart_b64 = generate_chart(stats)
        logo_b64 = (
            base64.b64encode(logo_file.getvalue()).decode("utf-8")
            if logo_file
            else ""
        )

        pdf_filename = f"auditoria_{hostname}.pdf"
        generate_pdf(
            target_url,
            findings,
            stats,
            chart_b64,
            open_ports,
            hostname,
            subdomains,
            geo,
            email_sec,
            ssl_info,
            risk_score,
            agency_name,
            agency_tagline,
            report_type,
            recipient_name,
            report_subject,
            logo_b64,
            pdf_filename,
        )

        docx_bytes = generate_docx(
            hostname,
            geo,
            email_sec,
            ssl_info,
            open_ports,
            subdomains,
            findings,
            risk_score,
            agency_name,
            agency_tagline,
            report_type,
            recipient_name,
            report_subject,
        )

        status.update(label="✅ ¡Análisis completado!", state="complete")

      st.session_state.scanned = True
      st.session_state.findings = findings
      st.session_state.hostname = hostname
      st.session_state.risk_score = risk_score
      st.session_state.pdf_filename = pdf_filename
      st.session_state.docx_bytes = docx_bytes

  if st.session_state.scanned:
    st.success(
        f"Análisis finalizado para {st.session_state.hostname} usando el modelo"
        f" '{report_type}'."
    )
    col1, col2 = st.columns(2)
    with col1:
      if os.path.exists(st.session_state.pdf_filename):
        with open(st.session_state.pdf_filename, "rb") as f:
          st.download_button(
              "📥 Descargar PDF",
              f,
              file_name=st.session_state.pdf_filename,
              mime="application/pdf",
              type="primary",
          )
    with col2:
      if "docx_bytes" in st.session_state:
        st.download_button(
            "📝 Descargar Word",
            st.session_state.docx_bytes,
            file_name=f"auditoria_{st.session_state.hostname}.docx",
            mime=(
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            ),
            type="primary",
        )

with tab2:
  st.subheader("Security Analytics")
  if st.session_state.scanned:
    st.write(f"Risk Score: **{st.session_state.risk_score} / 100**")
    st.dataframe(pd.DataFrame(st.session_state.findings))
  else:
    st.info("Ejecuta un escaneo primero.")

with tab3:
  st.subheader("Historial de Escaneos")
  st.dataframe(get_scan_history(), use_container_width=True)

with tab4:
  st.subheader("About")
  st.markdown("CyberAudits Enterprise - Versión optimizada con 3 plantillas.")
