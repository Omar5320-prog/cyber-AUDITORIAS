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
    page_title="CyberAudits - Escáner Perimetral Enterprise",
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
  c.execute("""
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            department TEXT,
            status TEXT DEFAULT 'Pendiente',
            score INTEGER DEFAULT 0,
            last_completed TEXT
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


def get_employees_df():
  conn = sqlite3.connect("cyber_audits.db")
  df = pd.read_sql_query(
      "SELECT email AS 'Correo Electrónico', department AS 'Departamento',"
      " status AS 'Estado', score AS 'Calificación (%)', last_completed AS"
      " 'Última Evaluación' FROM employees",
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
        "impact": "Los navegadores bloquearán el acceso a la web.",
        "fix": "Instalar certificado SSL/TLS válido.",
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
        "exec_title": "Riesgo de Expiración Próxima",
        "desc": ssl_info["details"],
        "impact": "Los servicios web dejarán de operar al caducar.",
        "fix": "Renovar el certificado.",
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
        "desc": "El dominio carece de un registro SPF válido.",
        "impact": "Facilita la suplantación de identidad (phishing).",
        "fix": "Publicar registro TXT con directivas SPF.",
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
        "exec_title": "Falta de Control DMARC",
        "desc": "El dominio carece de una política DMARC.",
        "impact": "Pérdida de visibilidad sobre intentos de fraude.",
        "fix": "Configurar registro TXT en _dmarc.",
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
          "impact": "Expuesto a ataques de fuerza bruta.",
          "fix": "Restringir el acceso mediante Firewall.",
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
          "desc": "La cabecera HSTS no está configurada.",
          "impact": "Riesgo de intercepción de tráfico.",
          "fix": "Configurar la cabecera HSTS.",
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
          "desc": f"La cabecera expone: {headers.get('Server')}",
          "impact": "Facilita la búsqueda de exploits.",
          "fix": "Ocultar la firma del servidor.",
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
          "desc": "Falta de control de marcos externos.",
          "impact": "Carga maliciosa en sitios terceros.",
          "fix": "Añadir cabecera X-Frame-Options.",
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
      "Distribución de Riesgos en la Infraestructura",
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

  p_title = doc.add_paragraph()
  run_title = p_title.add_run(f"INFORME: {report_type.upper()}")
  run_title.font.size = Pt(15)
  run_title.font.bold = True
  run_title.font.color.rgb = RGBColor(15, 23, 42)

  p_sub = doc.add_paragraph()
  run_sub = p_sub.add_run(
      f"Emitido por: {agency_name} ({agency_tagline})\nObjetivo analizado:"
      f" {hostname} | Risk Score: {risk_score}/100"
  )
  run_sub.font.size = Pt(10)
  run_sub.font.color.rgb = RGBColor(100, 116, 139)

  doc.add_heading("1. Datos Generales y Metadatos del Objetivo", level=2)
  table = doc.add_table(rows=6, cols=2)
  table.style = "Table Grid"
  data = [
      ("Dominio / Hostname", hostname),
      ("Dirección IP", geo["ip"]),
      ("Risk Score Global", f"{risk_score} / 100"),
      (
          "Ubicación Geográfica",
          f"{geo['city']}, {geo['country']} ({geo['org']})",
      ),
      (
          "Seguridad de Correo",
          f"SPF: {'OK' if email_sec['spf'] else 'Ausente'} | DMARC:"
          f" {'OK' if email_sec['dmarc'] else 'Ausente'}",
      ),
      ("Certificado SSL/TLS", f"{ssl_info['details']}"),
  ]
  for i, (k, v) in enumerate(data):
    table.cell(i, 0).text = k
    table.cell(i, 1).text = str(v)

  doc.add_heading("2. Detalle de Hallazgos y Guía de Remediación", level=2)
  for idx, f in enumerate(findings, 1):
    h = doc.add_paragraph()
    run_h = h.add_run(
        f"#{idx} - {f['vector']} [{f['severity']}] | Norma:"
        f" {f.get('compliance', 'N/A')}"
    )
    run_h.font.bold = True
    run_h.font.size = Pt(11)
    doc.add_paragraph(f"Descripción: {f['desc']}")
    doc.add_paragraph(f"Impacto de Negocio: {f['impact']}")
    p_fix = doc.add_paragraph()
    p_fix.add_run("Remediación: ").font.bold = True
    p_fix.add_run(f"{f['fix']}")
    if "snippet" in f:
      p_snip = doc.add_paragraph()
      p_snip.add_run("Configuración sugerida:\n").font.bold = True
      run_code = p_snip.add_run(f"{f['snippet']}")
      run_code.font.name = "Courier New"
      run_code.font.size = Pt(9.5)

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
      f'<img src="data:image/png;base64,{logo_b64}" style="max-height: 55px;'
      ' width: auto; float: right; margin-top: 2px;" alt="Logo">'
      if logo_b64
      else ""
  )
  ports_html = (
      "".join([
          (
              f"<tr><td><code>{p['port']}</code></td><td><strong>{p['service']}</strong>"
              " (Open)</td></tr>"
          )
          for p in open_ports
      ])
      or "<tr><td colspan='2' style='text-align:center;'>No ports detected.</td></tr>"
  )
  sub_html = (
      "".join([f"<li><code>{sub}</code></li>" for sub in subdomains])
      or "<li>No subdomains found.</li>"
  )

  spf_badge = (
      "<span style='color:green;'><b>OK</b></span>"
      if email_sec["spf"]
      else "<span style='color:red;'><b>Ausente</b></span>"
  )
  dmarc_badge = (
      "<span style='color:green;'><b>OK</b></span>"
      if email_sec["dmarc"]
      else "<span style='color:red;'><b>Ausente</b></span>"
  )
  ssl_badge = (
      "<span style='color:green;'><b>Válido</b></span>"
      if ssl_info["valid"] and not ssl_info["expires_soon"]
      else "<span style='color:orange;'><b>Revisar</b></span>"
  )

  if "Narrativo" in report_type:
    content_html = f"""
        <div class="header-banner">
            <div class="banner-left">
                <h1>Informe Ejecutivo Narrativo</h1>
                <p>Elaborado por: <strong>{agency_name}</strong> ({agency_tagline})</p>
            </div>
            <div class="banner-right">{logo_html}</div>
        </div>
        
        <table style="width: 100%; margin-bottom: 12px; border: 1px solid #cbd5e1; border-collapse: collapse; background: #ffffff; font-size: 8.5pt;">
            <tr>
                <td style="padding: 6px; border: 1px solid #cbd5e1; width: 15%; background: #f1f5f9;"><strong>Para:</strong></td>
                <td style="padding: 6px; border: 1px solid #cbd5e1; width: 35%;">{recipient_name}</td>
                <td style="padding: 6px; border: 1px solid #cbd5e1; width: 15%; background: #f1f5f9;"><strong>Fecha:</strong></td>
                <td style="padding: 6px; border: 1px solid #cbd5e1; width: 35%;">{datetime.datetime.now().strftime('%Y-%m-%d')}</td>
            </tr>
            <tr>
                <td style="padding: 6px; border: 1px solid #cbd5e1; background: #f1f5f9;"><strong>Asunto:</strong></td>
                <td style="padding: 6px; border: 1px solid #cbd5e1;" colspan="3">{report_subject}</td>
            </tr>
            <tr>
                <td style="padding: 6px; border: 1px solid #cbd5e1; background: #f1f5f9;"><strong>Objetivo:</strong></td>
                <td style="padding: 6px; border: 1px solid #cbd5e1;" colspan="3">{hostname} (IP: {geo['ip']})</td>
            </tr>
        </table>

        <h2>1. Resumen Ejecutivo y Visión General</h2>
        <div class="executive-box">
            <p style="margin:0;">El presente documento detalla la evaluación perimetral llevada a cabo sobre el activo digital <strong>{hostname}</strong>. Se ha determinado una calificación de riesgo corporativo (Risk Score) de <strong style="color: {'#10b981' if risk_score > 70 else '#f59e0b' if risk_score > 40 else '#dc2626'};">{risk_score} / 100</strong>.</p>
        </div>

        <h2>2. Análisis del Impacto en el Negocio</h2>
        <p>La revisión de la superficie expuesta a internet permite identificar puntos clave que afectan la seguridad operacional:</p>
        <ul>
            <li><strong>Cifrado y Transporte (SSL/TLS):</strong> {ssl_info['details']}</li>
            <li><strong>Autenticación de Correo:</strong> {'Los mecanismos de correo protegen adecuadamente la marca.' if email_sec['spf'] and email_sec['dmarc'] else 'Carencia de controles SPF/DMARC, incrementando el riesgo de phishing.'}</li>
            <li><strong>Superficie Perimetral:</strong> Se identificaron puertos expuestos que requieren supervisión.</li>
        </ul>
        """
  elif "Normativa" in report_type:
    items_html_norm = ""
    for idx, f in enumerate(findings, 1):
      snippet_box = (
          f"<pre"
          f' style="background:#f1f5f9;padding:6px;border-radius:4px;font-size:7pt;color:#0369a1;overflow-x:auto;"><code>{f.get("snippet", "")}</code></pre>'
          if "snippet" in f
          else ""
      )
      items_html_norm += f"""
            <div class="finding-card">
                <div class="finding-header">
                    <span class="finding-num">#{idx}</span>
                    <span class="finding-title">{f['vector']}</span>
                    <span class="{f['badge']}">{f['severity']}</span>
                </div>
                <div class="finding-body">
                    <p><strong>Compliance:</strong> <code>{f.get('compliance', 'N/A')}</code></p>
                    <p><strong>Descripción:</strong> {f['desc']}</p>
                    <div class="solution-box"><p><strong>Remediación:</strong></p><code>{f['fix']}</code></div>
                    {snippet_box}
                </div>
            </div>
            """
    content_html = f"""
        <div class="header-banner">
            <div class="banner-left">
                <h1>Informe de Normativa, Remediación y Recomendaciones</h1>
                <p>Elaborado por: <strong>{agency_name}</strong></p>
            </div>
            <div class="banner-right">{logo_html}</div>
        </div>
        <h2>Matriz de Cumplimiento Normativo y Guía Técnica</h2>
        <div class="executive-box"><p style="margin:0;">Objetivo: <strong>{hostname}</strong> | Risk Score: <strong>{risk_score}/100</strong>.</p></div>
        {items_html_norm}
        """
  else:
    items_html_full = ""
    for idx, f in enumerate(findings, 1):
      snippet_box = (
          f"<pre"
          f' style="background:#f1f5f9;padding:6px;border-radius:4px;font-size:7pt;color:#0369a1;overflow-x:auto;"><code>{f.get("snippet", "")}</code></pre>'
          if "snippet" in f
          else ""
      )
      items_html_full += f"""
            <div class="finding-card">
                <div class="finding-header">
                    <span class="finding-num">#{idx}</span>
                    <span class="finding-title">{f['vector']}</span>
                    <span class="{f['badge']}">{f['severity']}</span>
                </div>
                <div class="finding-body">
                    <p><strong>Norma:</strong> <code>{f.get('compliance', 'N/A')}</code></p>
                    <p><strong>Descripción:</strong> {f['desc']}</p>
                    <p><strong>Impacto:</strong> {f['impact']}</p>
                    <div class="solution-box"><p><strong>Remediación:</strong> <code>{f['fix']}</code></p></div>
                    {snippet_box}
                </div>
            </div>
            """
    content_html = f"""
        <div class="header-banner">
            <div class="banner-left">
                <h1>Informe Técnico Exhaustivo (Completo)</h1>
                <p>Elaborado por: <strong>{agency_name}</strong> ({agency_tagline})</p>
            </div>
            <div class="banner-right">{logo_html}</div>
        </div>
        <table style="width: 100%; margin-bottom: 6px; border: none;">
            <tr>
                <td style="border: none; width: 25%;"><div class="meta-item"><div class="meta-label">Objetivo</div><div class="meta-value">{hostname}</div></div></td>
                <td style="border: none; width: 25%;"><div class="meta-item"><div class="meta-label">Risk Score</div><div class="meta-value" style="color: {'#10b981' if risk_score > 70 else '#f59e0b' if risk_score > 40 else '#dc2626'};">{risk_score} / 100</div></div></td>
                <td style="border: none; width: 25%;"><div class="meta-item"><div class="meta-label">SSL</div><div class="meta-value">{ssl_badge}</div></div></td>
                <td style="border: none; width: 25%;"><div class="meta-item"><div class="meta-label">SPF / DMARC</div><div class="meta-value">{spf_badge} / {dmarc_badge}</div></div></td>
            </tr>
        </table>
        <h2>1. Visión e Infraestructura</h2>
        <div class="executive-box"><p style="margin:0;">Risk Score corporativo: <strong>{risk_score}/100</strong>.</p></div>
        <table style="width: 100%; border: none; margin-bottom: 6px;">
            <tr>
                <td style="width: 50%; vertical-align: top; border: none;">
                    <div class="card"><h3 style="margin:0; font-size:8.5pt;">Puertos Críticos:</h3>
                    <table class="ports-table"><thead><tr><th>Puerto</th><th>Servicio</th></tr></thead><tbody>{ports_html}</tbody></table></div>
                </td>
                <td style="width: 50%; vertical-align: top; border: none;">
                    <div class="card"><h3 style="margin:0; font-size:8.5pt;">Subdominios:</h3>
                    <ul style="margin:0; padding-left:14px; font-size:7pt; max-height:75px; overflow:hidden;">{sub_html}</ul></div>
                </td>
            </tr>
        </table>
        <div class="card" style="text-align: center; padding: 4px;">
            <div class="chart-container"><img src="data:image/png;base64,{chart_base64}" alt="Gráfico"></div>
        </div>
        <div style="page-break-after: always;"></div>
        <h2>2. Hallazgos Detallados</h2>
        {items_html_full}
        """

  html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <style>
            @page {{ size: A4; margin: 10mm 12mm; background-color: #f8fafc; @bottom-right {{ content: "Page " counter(page) " of " counter(pages); font-size: 8pt; color: #64748b; }} }}
            body {{ font-family: Helvetica, Arial, sans-serif; color: #334155; margin: 0; padding: 0; font-size: 8.5pt; line-height: 1.35; }}
            .header-banner {{ background: #0f172a; color: white; padding: 10px 15px; border-radius: 5px; margin-bottom: 6px; overflow: hidden; }}
            .banner-left {{ float: left; width: 70%; }}
            .banner-right {{ float: right; width: 28%; text-align: right; }}
            .header-banner h1 {{ margin: 0; font-size: 13pt; }}
            .header-banner p {{ margin: 0; color: #94a3b8; font-size: 8pt; }}
            .meta-item {{ background: white; padding: 4px 8px; border: 1px solid #e2e8f0; border-radius: 4px; }}
            .meta-label {{ font-size: 6pt; color: #64748b; text-transform: uppercase; }}
            .meta-value {{ font-size: 8pt; font-weight: 600; color: #0f172a; }}
            h2 {{ color: #0f172a; font-size: 9.5pt; border-left: 3px solid #3b82f6; padding-left: 5px; margin-top: 6px; margin-bottom: 4px; }}
            .card {{ background: white; border: 1px solid #e2e8f0; border-radius: 5px; padding: 6px 8px; margin-bottom: 5px; }}
            .badge-critical {{ background-color: #fee2e2; color: #991b1b; padding: 2px 4px; border-radius: 3px; font-size: 6.5pt; float: right; }}
            .badge-medium {{ background-color: #fef3c7; color: #92400e; padding: 2px 4px; border-radius: 3px; font-size: 6.5pt; float: right; }}
            .badge-low {{ background-color: #dbeafe; color: #1e40af; padding: 2px 4px; border-radius: 3px; font-size: 6.5pt; float: right; }}
            .chart-container {{ text-align: center; }}
            .chart-container img {{ max-width: 65%; height: auto; }}
            .executive-box {{ background-color: #eff6ff; border-left: 3px solid #3b82f6; padding: 5px 8px; margin-bottom: 5px; }}
            table.ports-table {{ width: 100%; border-collapse: collapse; font-size: 7.5pt; }}
            table.ports-table th {{ background-color: #f1f5f9; padding: 2px; border-bottom: 2px solid #cbd5e1; text-align: left; }}
            table.ports-table td {{ padding: 2px; border-bottom: 1px solid #e2e8f0; }}
            .finding-card {{ background: white; border: 1px solid #cbd5e1; border-radius: 4px; margin-bottom: 5px; page-break-inside: avoid; }}
            .finding-header {{ background-color: #f1f5f9; padding: 4px 6px; border-bottom: 1px solid #cbd5e1; overflow: hidden; }}
            .finding-title {{ font-weight: bold; color: #0f172a; font-size: 8pt; }}
            .finding-body {{ padding: 5px 6px; }}
            .solution-box {{ background-color: #f8fafc; border-left: 3px solid #0284c7; padding: 4px 6px; margin-top: 3px; }}
            .solution-box code {{ color: #0369a1; font-size: 7pt; }}
            .disclaimer {{ font-size: 7pt; color: #64748b; margin-top: 6px; text-align: center; font-style: italic; }}
        </style>
    </head>
    <body>
        {content_html}
        <div class="disclaimer">Nota: Evaluaciones perimetrales externas en tiempo real.</div>
    </body>
    </html>
    """
  HTML(string=html_content).write_pdf(output_filename)


if "scanned" not in st.session_state:
  st.session_state.scanned = False

st.markdown(
    """
    <div class="enterprise-banner">
        🚀 <strong>CyberAudits Enterprise Suite:</strong> Plataforma perimetral de consultoría activa.
    </div>
    """,
    unsafe_allow_html=True,
)

st.title("🛡️ CyberAudits - Suite Enterprise")
st.write(
    "Plataforma integral de ciberseguridad: Auditoría perimetral y gestión de"
    " informes ejecutivos."
)

st.sidebar.header("⚙️ Configuración del Informe")
agency_name = st.sidebar.text_input(
    "Nombre de la Agencia", value="SecOps Global Partners"
)
agency_tagline = st.sidebar.text_input(
    "Subtítulo / Área de la Agencia",
    value="División de Consultoría y Ciberseguridad",
)
logo_file = st.sidebar.file_uploader(
    "Logo de la Agencia (PNG / JPG)", type=["png", "jpg", "jpeg"]
)

report_type = st.sidebar.selectbox(
    "Plantilla / Modelo de Informe",
    [
        "Informe Técnico Exhaustivo (Completo)",
        "Informe Ejecutivo Narrativo",
        "Informe de Normativa, Remediación y Recomendaciones (ISO / Compliance)",
    ],
)

recipient_name = st.sidebar.text_input(
    "Dirigido a (Gerencia / Cliente)",
    value="Dirección General / Junta Directiva",
)
report_subject = st.sidebar.text_input(
    "Asunto del Informe",
    value="Evaluación de Riesgos Perimetrales y Postura de Negocio",
)

st.sidebar.markdown("---")
# INTERRUPTOR PRIVADO PARA MANTENER OCULTO EL MÓDULO EN PRODUCCIÓN
st.sidebar.subheader("🔒 Panel de Administración")
admin_mode = st.sidebar.checkbox(
    "Activar Modo Desarrollador (Concienciación)", value=False
)

st.sidebar.markdown("---")
st.sidebar.caption("CyberAudits Enterprise v4.1 • Producción Segura.")

# GESTIÓN DINÁMICA DE TABS SEGÚN MODO ADMIN
if admin_mode:
  tab1, tab2, tab3, tab4, tab5 = st.tabs([
      "🔍 Perimeter Scan",
      "📊 Security Analytics",
      "📜 Historial de Escaneos",
      "🎓 Concienciación (Quiz - En Desarrollo)",
      "ℹ️ About CyberAudits",
  ])
else:
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
      "URL Objetivo (ej. mi-empresa.com)",
      value=quick_domain if quick_domain else "https://",
  )

  if st.button("🚀 Ejecutar Análisis Completo"):
    if not target_url or target_url == "https://":
      st.error("Por favor, introduce una URL válida.")
    else:
      if not target_url.startswith("http"):
        target_url = "https://" + target_url

      with st.status(
          "🔍 Analizando perímetro, SSL/TLS, Compliance y Risk Score...",
          expanded=True,
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

        status.update(
            label="✅ ¡Análisis corporativo completado!",
            state="complete",
            expanded=False,
        )

      st.session_state.scanned = True
      st.session_state.findings = findings
      st.session_state.stats = stats
      st.session_state.open_ports = open_ports
      st.session_state.hostname = hostname
      st.session_state.subdomains = subdomains
      st.session_state.geo = geo
      st.session_state.email_sec = email_sec
      st.session_state.ssl_info = ssl_info
      st.session_state.risk_score = risk_score
      st.session_state.pdf_filename = pdf_filename
      st.session_state.docx_bytes = docx_bytes

  if st.session_state.scanned:
    st.success(f"¡Análisis completado para {st.session_state.hostname}!")
    g1, g2, g3, g4, g5 = st.columns(5)
    g1.metric("Dirección IP", st.session_state.geo["ip"])
    g2.metric("Risk Score", f"{st.session_state.risk_score} / 100")
    g3.metric(
        "Certificado SSL",
        (
            "Válido"
            if st.session_state.ssl_info["valid"]
            and not st.session_state.ssl_info["expires_soon"]
            else "Revisar"
        ),
    )
    g4.metric(
        "Registro SPF",
        "Protegido" if st.session_state.email_sec["spf"] else "Ausente",
    )
    g5.metric(
        "DMARC",
        "Protegido" if st.session_state.email_sec["dmarc"] else "Ausente",
    )

    st.markdown("---")
    col_dl1, col_dl2, col_dl3 = st.columns(3)
    with col_dl1:
      if os.path.exists(st.session_state.pdf_filename):
        with open(st.session_state.pdf_filename, "rb") as pdf_file:
          st.download_button(
              "📥 Descargar PDF Ejecutivo",
              pdf_file,
              file_name=st.session_state.pdf_filename,
              mime="application/pdf",
              type="primary",
          )
    with col_dl2:
      if "docx_bytes" in st.session_state:
        st.download_button(
            "📝 Descargar Word Editable",
            st.session_state.docx_bytes,
            file_name=f"auditoria_{st.session_state.hostname}.docx",
            mime=(
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            ),
            type="primary",
        )
    with col_dl3:
      df_findings = pd.DataFrame(st.session_state.findings)
      if not df_findings.empty:
        st.download_button(
            "📊 Exportar Hallazgos (CSV)",
            df_findings.to_csv(index=False, sep=";").encode("utf-8-sig"),
            file_name=f"hallazgos_{st.session_state.hostname}.csv",
            mime="text/csv",
        )

with tab2:
  st.subheader("Infrastructure Health & Risk Score Analytics")
  if st.session_state.scanned:
    st.write(f"Risk Score: **{st.session_state.risk_score} / 100**")
    for f in st.session_state.findings:
      with st.expander(f"📌 {f['vector']} [{f['severity']}]"):
        st.write(f"**Norma / Compliance:** `{f.get('compliance', 'N/A')}`")
        st.write(f"**Descripción:** {f['desc']}")
        st.write(f"**Remediación:** {f['fix']}")
  else:
    st.info("Ejecuta un escaneo en la primera pestaña.")

with tab3:
  st.subheader("📜 Historial de Escaneos Corporativos (SQLite)")
  history_df = get_scan_history()
  if not history_df.empty:
    st.dataframe(history_df, use_container_width=True)
    if st.button("🗑️ Limpiar Historial"):
      conn = sqlite3.connect("cyber_audits.db")
      conn.execute("DELETE FROM history")
      conn.commit()
      conn.close()
      st.rerun()
  else:
    st.info("Aún no hay escaneos guardados.")

# PESTAÑA CONDICIONAL DE CONCIENCIACIÓN (SOLO SE MUESTRA SI ADMIN_MODE ESTÁ ACTIVO)
if admin_mode:
  with tab4:
    st.subheader(
        "🎓 Módulo de Concienciación y Cultura de Seguridad (En Desarrollo)"
    )
    st.write(
        "Módulo interno en pruebas. Los clientes externos no pueden ver esta"
        " sección."
    )

    col_emp1, col_emp2 = st.columns(2)
    with col_emp1:
      st.markdown("### ➕ Registrar Empleado / Destinatario")
      with st.form("add_employee_form"):
        new_email = st.text_input("Correo Electrónico Corporativo")
        new_dept = st.selectbox(
            "Departamento",
            [
                "Administración",
                "Tecnología / TI",
                "Finanzas",
                "Ventas",
                "General",
            ],
        )
        submitted = st.form_submit_button("Registrar Empleado")
        if submitted and new_email:
          try:
            conn = sqlite3.connect("cyber_audits.db")
            conn.execute(
                "INSERT INTO employees (email, department) VALUES (?, ?)",
                (new_email, new_dept),
            )
            conn.commit()
            conn.close()
            st.success(f"Empleado {new_email} registrado correctamente.")
            st.rerun()
          except Exception:
            st.error(
                "El correo ya se encuentra registrado en la base de datos."
            )

    with col_emp2:
      st.markdown("### 📊 Panel de Control y Métricas (Dashboard)")
      emp_df = get_employees_df()
      if not emp_df.empty:
        st.dataframe(emp_df, use_container_width=True)
        if st.button("🗑️ Vaciar Lista de Empleados"):
          conn = sqlite3.connect("cyber_audits.db")
          conn.execute("DELETE FROM employees")
          conn.commit()
          conn.close()
          st.rerun()
      else:
        st.info("No hay empleados registrados.")

    st.markdown("---")
    st.markdown("### 📝 Simulación de Cuestionario Interactivo")
    test_email = st.selectbox(
        "Seleccionar Empleado a Evaluar",
        [
            row["Correo Electrónico"]
            for _, row in get_employees_df().iterrows()
            if not get_employees_df().empty
        ],
    )

    if test_email:
      with st.form("quiz_simulation_form"):
        st.write(f"Evaluando a: **{test_email}**")
        q1 = st.radio(
            "1. ¿Qué debe hacer si recibe un correo urgente del banco pidiendo"
            " verificar su contraseña?",
            [
                "Hacer clic en el enlace y cambiarla inmediatamente",
                "Ignorarlo o reportarlo al área de TI sin hacer clic",
                "Responder con los datos solicitados",
            ],
        )
        q2 = st.radio(
            "2. ¿Cuál es una característica clave de una contraseña robusta?",
            [
                "Usar fechas importantes fáciles de recordar",
                "Una sola palabra larga sin números",
                "Combinación de mayúsculas, minúsculas, números y símbolos",
            ],
        )

        submit_quiz = st.form_submit_button("Enviar Respuestas del Quiz")
        if submit_quiz:
          score = 0
          if "Ignorarlo" in q1:
            score += 50
          if "Combinación" in q2:
            score += 50

          timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
          conn = sqlite3.connect("cyber_audits.db")
          conn.execute(
              "UPDATE employees SET status = 'Completado', score = ?,"
              " last_completed = ? WHERE email = ?",
              (score, timestamp, test_email),
          )
          conn.commit()
          conn.close()
          st.success(
              f"¡Evaluación enviada con éxito! Calificación obtenida: {score}%"
          )
          st.rerun()

  # Última pestaña (About) pasa a ser la quinta si el modo admin está activo
  with tab5:
    st.subheader("About CyberAudits Enterprise Suite")
    st.markdown("""
        **CyberAudits Enterprise Suite** es una plataforma integral orientada a consultorías de ciberseguridad corporativa.
        * **Módulos:** Auditoría perimetral y gestión del factor humano.
        * **Arquitectura:** Desarrollado bajo estándares modulares con persistencia local en SQLite.
        """)
else:
  # Si el modo admin está apagado, la última pestaña (About) es la cuarta
  with tab4:
    st.subheader("About CyberAudits Enterprise Suite")
    st.markdown("""
        **CyberAudits Enterprise Suite** es una plataforma integral orientada a consultorías de ciberseguridad corporativa.
        * **Módulos:** Auditoría perimetral y gestión del factor humano.
        * **Arquitectura:** Desarrollado bajo estándares modulares con persistencia local en SQLite.
        """)
