import base64
import datetime
import io
import json
import os
import socket
import ssl
from urllib.parse import urlparse
from docx import Document
from docx.shared import Inches, Pt, RGBColor
import matplotlib.pyplot as plt
import pandas as pd
import requests
from weasyprint import HTML
import streamlit as st

# Configuración de la página web
st.set_page_config(
    page_title="CyberAudits - Escáner Perimetral",
    page_icon="🛡️",
    layout="wide",
)

# Estilos CSS limpios y profesionales (Barra lateral clara y moderna)
st.markdown(
    """
    <style>
        /* Fondo general y barra lateral en modo claro impecable */
        .stApp {
            background-color: #f8fafc;
            color: #1e293b;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        }
        
        [data-testid="stSidebar"] {
            background-color: #f0f2f6 !important;
            border-right: 1px solid #e2e8f0;
        }
        
        [data-testid="stSidebar"] label, 
        [data-testid="stSidebar"] .stMarkdown, 
        [data-testid="stSidebar"] span, 
        [data-testid="stSidebar"] p,
        [data-testid="stSidebar"] h2 {
            color: #1e293b !important;
        }

        [data-testid="stSidebar"] input, 
        [data-testid="stSidebar"] div[data-baseweb="select"] > div,
        [data-testid="stSidebar"] textarea {
            background-color: #ffffff !important;
            color: #1e293b !important;
            border-color: #cbd5e1 !important;
        }

        /* Banner superior corporativo */
        .enterprise-banner {
            background: linear-gradient(90deg, #1e3a8a, #3b82f6);
            padding: 12px 20px;
            border-radius: 8px;
            color: white;
            text-align: center;
            margin-bottom: 20px;
            font-weight: 500;
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.15);
        }
    </style>
    """,
    unsafe_allow_html=True,
)


def get_geolocation(hostname):
  """Obtiene la IP, país, ciudad y proveedor usando ip-api.com."""
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
  """Inspección profunda del certificado SSL/TLS (Emisor y Expiración)."""
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
  """Verifica la existencia de registros SPF y DMARC para prevenir Email Spoofing."""
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

  # Análisis de SSL/TLS
  if not ssl_info["valid"]:
    stats["Críticas"] += 1
    findings.append({
        "vector": "Certificado SSL/TLS Inválido o Ausente",
        "severity": "CRÍTICO",
        "badge": "badge-critical",
        "exec_title": "Fallo Crítico en Cifrado HTTPS (Certificado No Confiable)",
        "desc": ssl_info["details"],
        "impact": (
            "Los navegadores bloquearán el acceso a la web advirtiendo a los"
            " usuarios sobre fraude o suplantación."
        ),
        "fix": (
            "Renovar o instalar un certificado SSL/TLS válido emitido por una"
            " Autoridad de Certificación reconocida."
        ),
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
        "exec_title": "Riesgo de Expiración Próxima de Certificado SSL",
        "desc": ssl_info["details"],
        "impact": (
            "Si el certificado expira, los servicios web dejarán de estar"
            " disponibles de forma segura."
        ),
        "fix": "Renovar el certificado SSL antes de la fecha límite.",
    })
  else:
    stats["Seguras"] += 1

  if email_sec["spf"]:
    stats["Seguras"] += 1
  else:
    stats["Medias"] += 1
    findings.append({
        "vector": "Ausencia de Registro SPF (Riesgo de Phishing)",
        "severity": "MEDIO",
        "badge": "badge-medium",
        "exec_title": "Vulnerabilidad en la Postura de Correo (Sin SPF)",
        "desc": (
            "El dominio no cuenta con un registro SPF válido que autorice qué"
            " servidores pueden enviar correos en su nombre."
        ),
        "impact": (
            "Facilita que actores maliciosos envíen correos fraudulentos de"
            " suplantación de identidad (phishing)."
        ),
        "fix": (
            "Publicar un registro TXT con directivas SPF (ej: v=spf1"
            " include:_spf.example.com ~all)."
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
        "exec_title": "Falta de Control de Autenticación de Correo (DMARC)",
        "desc": (
            "El dominio carece de una política DMARC para indicar qué hacer"
            " con los correos que fallan las validaciones."
        ),
        "impact": (
            "La organización pierde visibilidad sobre intentos de fraude y"
            " aumenta el riesgo de suplantación."
        ),
        "fix": (
            "Configurar un registro TXT en _dmarc con directivas de monitoreo o"
            " rechazo."
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
          "exec_title": (
              f"Servicio Administrativo / Base de Datos Expuesto en Puerto"
              f" {p['port']}"
          ),
          "desc": (
              f"El puerto {p['port']} ({p['service']}) se encuentra accesible"
              " de forma directa desde internet sin restricciones."
          ),
          "impact": (
              "Invita a atacantes a realizar ataques de fuerza bruta para"
              " adivinar credenciales."
          ),
          "fix": (
              f"Restringir el acceso al puerto {p['port']} mediante un Firewall"
              " de Red o Grupos de Seguridad."
          ),
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
          "exec_title": (
              "Ausencia de Encriptación Forzada (Riesgo de Intercepción)"
          ),
          "desc": (
              "La cabecera HSTS no está configurada en la respuesta del"
              " servidor web."
          ),
          "impact": (
              "Un atacante en una red Wi-Fi pública puede interceptar la"
              " conexión y robar contraseñas o tokens."
          ),
          "fix": (
              "Configurar la cabecera: Strict-Transport-Security:"
              " max-age=31536000; includeSubDomains; preload."
          ),
      })

    if "Server" in headers:
      stats["Medias"] += 1
      findings.append({
          "vector": "Exposición de Versión del Servidor (Server Banner)",
          "severity": "MEDIO",
          "badge": "badge-medium",
          "exec_title": "Fuga de Información Tecnológica del Servidor",
          "desc": (
              "La cabecera HTTP expone el software y versión exacta:"
              f" {headers.get('Server')}"
          ),
          "impact": (
              "Facilita que actores maliciosos busquen vulnerabilidades"
              " públicas asociadas."
          ),
          "fix": (
              "Ocultar o enmascarar la firma del servidor en la configuración"
              " global."
          ),
      })
    else:
      stats["Seguras"] += 1

    if "X-Frame-Options" in headers or "Content-Security-Policy" in headers:
      stats["Seguras"] += 1
    else:
      stats["Bajas"] += 1
      findings.append({
          "vector": (
              "Protección contra Clickjacking Ausente (X-Frame-Options)"
          ),
          "severity": "BAJO",
          "badge": "badge-low",
          "exec_title": "Riesgo de Secuestro de Clics (Clickjacking)",
          "desc": (
              "El sitio web no emite directivas para evitar su carga dentro de"
              " marcos externos."
          ),
          "impact": (
              "Un sitio malicioso externo puede cargar tu web bajo un botón"
              " trampa para engañar al usuario."
          ),
          "fix": (
              "Añadir la cabecera de seguridad X-Frame-Options: DENY o"
              " SAMEORIGIN."
          ),
      })

  except Exception:
    pass

  return (
      findings,
      stats,
      open_ports,
      hostname,
      subdomains,
      geo,
      email_sec,
      ssl_info,
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
    agency_name,
    agency_tagline,
    report_type,
    recipient_name,
    report_subject,
):
  """Genera un documento Word (.docx) editable con el informe ejecutivo."""
  doc = Document()
  for section in doc.sections:
    section.top_margin = Inches(1)
    section.bottom_margin = Inches(1)
    section.left_margin = Inches(1)
    section.right_margin = Inches(1)

  p_title = doc.add_paragraph()
  run_title = p_title.add_run("INFORME EJECUTIVO DE CIBERSEGURIDAD")
  run_title.font.size = Pt(15)
  run_title.font.bold = True
  run_title.font.color.rgb = RGBColor(15, 23, 42)

  p_sub = doc.add_paragraph()
  run_sub = p_sub.add_run(
      f"Emitido por: {agency_name} ({agency_tagline})\nObjetivo analizado:"
      f" {hostname}"
  )
  run_sub.font.size = Pt(10)
  run_sub.font.color.rgb = RGBColor(100, 116, 139)

  doc.add_heading("1. Datos Generales y Metadatos del Objetivo", level=2)
  table = doc.add_table(rows=6, cols=2)
  table.style = "Table Grid"
  data = [
      ("Dominio / Hostname", hostname),
      ("Dirección IP", geo["ip"]),
      (
          "Ubicación Geográfica",
          f"{geo['city']}, {geo['country']} ({geo['org']})",
      ),
      (
          "Seguridad de Correo",
          f"SPF: {'Configurado' if email_sec['spf'] else 'Ausente'} | DMARC:"
          f" {'Configurado' if email_sec['dmarc'] else 'Ausente'}",
      ),
      ("Certificado SSL/TLS", f"{ssl_info['details']}"),
      ("Emisor SSL", ssl_info["issuer"]),
  ]
  for i, (k, v) in enumerate(data):
    table.cell(i, 0).text = k
    table.cell(i, 1).text = str(v)

  doc.add_heading("2. Resumen Gerencial y Hallazgos", level=2)
  doc.add_paragraph(
      f"El análisis perimetral automatizado realizado sobre {hostname} bajo el"
      f" estándar '{report_type}' ha identificado un total de {len(findings)}"
      " áreas de vulnerabilidad o exposición que requieren atención"
      " gerencial y técnica."
  )

  doc.add_heading("3. Detalle de Hallazgos y Guía de Remediación", level=2)
  for idx, f in enumerate(findings, 1):
    h = doc.add_paragraph()
    run_h = h.add_run(f"#{idx} - {f['vector']} [{f['severity']}]")
    run_h.font.bold = True
    run_h.font.size = Pt(11)

    doc.add_paragraph(f"Descripción Técnica: {f['desc']}")
    doc.add_paragraph(f"Impacto de Negocio: {f['impact']}")
    p_fix = doc.add_paragraph()
    run_fix_label = p_fix.add_run("Remediación sugerida: ")
    run_fix_label.font.bold = True
    p_fix.add_run(f"{f['fix']}")

  buffer = io.BytesIO()
  doc.save(buffer)
  buffer.seek(0)
  return buffer.getvalue()


def translate_finding_en(f):
  vec = f["vector"]
  sev = f["severity"]
  sev_en = (
      "CRITICAL" if sev == "CRÍTICO" else ("MEDIUM" if sev == "MEDIO" else "LOW")
  )
  if "SSL" in vec:
    title_en = "SSL/TLS Certificate Invalid or Missing"
    exec_t_en = "HTTPS Encryption Critical Failure (Untrusted Cert)"
    desc_en = f.get("desc", "")
    impact_en = f.get("impact", "")
    fix_en = f.get("fix", "")
  elif "SPF" in vec:
    title_en = "SPF Record Missing (Phishing Risk)"
    exec_t_en = "Email Security Posture Vulnerability (No SPF)"
    desc_en = (
        "The domain lacks a valid SPF record authorizing sending servers."
    )
    impact_en = (
        "Allows malicious actors to send fraudulent phishing emails"
        " impersonating the organization."
    )
    fix_en = "Publish a TXT record with SPF policies."
  elif "DMARC" in vec:
    title_en = "DMARC Policy Missing"
    exec_t_en = "Lack of Email Authentication Control (DMARC)"
    desc_en = "The domain lacks a DMARC policy for validation failures."
    impact_en = (
        "Increases the risk of unnoticed email spoofing and fraud attempts."
    )
    fix_en = "Configure a TXT record in _dmarc."
  elif "Puerto" in vec:
    title_en = (
        f"Port {f.get('port', '')} ({f.get('service', '')}) Open to Public"
    )
    exec_t_en = (
        f"Administrative Service / Database Exposed on Port {f.get('port', '')}"
    )
    desc_en = (
        f"Port {f.get('port', '')} ({f.get('service', '')}) is directly"
        " accessible from the internet without visible perimeter"
        " restrictions."
    )
    impact_en = (
        "Invites attackers to perform brute-force attacks to guess"
        " credentials and gain full control of the platform."
    )
    fix_en = (
        f"Restrict access to port {f.get('port', '')} using a Network Firewall"
        " or Security Groups."
    )
  elif "HSTS" in vec:
    title_en = "HTTP Strict Transport Security (HSTS) Missing"
    exec_t_en = "Lack of Forced Encryption (Interception Risk)"
    desc_en = "The HSTS header is not configured in the web server response."
    impact_en = (
        "An attacker on a public Wi-Fi network can intercept the connection"
        " and steal passwords or tokens in real time."
    )
    fix_en = (
        "Configure header: Strict-Transport-Security: max-age=31536000;"
        " includeSubDomains; preload."
    )
  elif "Servidor" in vec or "Server" in vec:
    title_en = "Server Version Disclosure (Server Banner)"
    exec_t_en = "Technological Information Leak from Server"
    desc_en = f"The HTTP header exposes the exact software and version."
    impact_en = (
        "Facilitates malicious actors in searching for public vulnerabilities"
        " associated with that exact software version."
    )
    fix_en = "Hide or mask the server signature in global configuration."
  elif "Clickjacking" in vec:
    title_en = "Clickjacking Protection Missing (X-Frame-Options)"
    exec_t_en = "Clickjacking Risk"
    desc_en = (
        "The website does not issue directives to prevent loading inside"
        " external frames."
    )
    impact_en = (
        "An external malicious site can invisibly load your web under a trap"
        " button to trick the user."
    )
    fix_en = "Add security header X-Frame-Options: DENY or SAMEORIGIN."
  else:
    title_en = vec
    exec_t_en = f.get("exec_title", "")
    desc_en = f.get("desc", "")
    impact_en = f.get("impact", "")
    fix_en = f.get("fix", "")

  return {
      "vector": title_en,
      "severity": sev_en,
      "badge": f["badge"],
      "exec_title": exec_t_en,
      "desc": desc_en,
      "impact": impact_en,
      "fix": fix_en,
  }


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

  if "Carta" in report_type or "Narrativo" in report_type:
    html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                @page {{ size: A4; margin: 10mm 12mm; background-color: #ffffff; @bottom-right {{ content: "Page / Página " counter(page); font-size: 7.5pt; color: #64748b; }} }}
                body {{ font-family: Helvetica, Arial, sans-serif; color: #1e293b; margin: 0; padding: 0; font-size: 9pt; line-height: 1.35; }}
                .memo-header {{ border-bottom: 2px solid #0f172a; padding-bottom: 8px; margin-bottom: 12px; overflow: hidden; }}
                .memo-header-left {{ float: left; width: 70%; }}
                .memo-header-right {{ float: right; width: 28%; text-align: right; }}
                .memo-header h1 {{ margin: 0; font-size: 13pt; color: #0f172a; text-transform: uppercase; letter-spacing: 0.5px; }}
                .memo-header p {{ margin: 2px 0; color: #64748b; font-size: 8.5pt; }}
                .meta-table {{ width: 100%; margin-bottom: 12px; border-collapse: collapse; font-size: 8.5pt; }}
                .meta-table td {{ padding: 3px 0; border-bottom: 1px solid #e2e8f0; }}
                .meta-table td.label {{ font-weight: bold; color: #475569; width: 20%; }}
                .memo-body h2 {{ color: #0f172a; font-size: 9.5pt; border-left: 3px solid #3b82f6; padding-left: 6px; margin-top: 10px; margin-bottom: 4px; }}
                .memo-body p {{ margin: 4px 0; }}
                .memo-body ul {{ margin: 4px 0; padding-left: 15px; }}
                .memo-body li {{ margin-bottom: 3px; }}
                .highlight-box {{ background-color: #f8fafc; border: 1px solid #cbd5e1; border-left: 4px solid #3b82f6; padding: 8px 12px; border-radius: 4px; margin: 8px 0; }}
                .signature-section {{ margin-top: 20px; page-break-inside: avoid; }}
                .disclaimer {{ font-size: 7.5pt; color: #94a3b8; margin-top: 15px; text-align: center; border-top: 1px solid #e2e8f0; padding-top: 6px; }}
            </style>
        </head>
        <body>
            <div class="memo-header">
                <div class="memo-header-left">
                    <h1>Informe Ejecutivo de Seguridad</h1>
                    <p>Emitido por: <strong>{agency_name}</strong></p>
                    <p>{agency_tagline}</p>
                </div>
                <div class="memo-header-right">
                    {logo_html}
                </div>
            </div>
            
            <table class="meta-table">
                <tr><td class="label">PARA:</td><td>{recipient_name}</td></tr>
                <tr><td class="label">DE:</td><td>{agency_name} ({agency_tagline})</td></tr>
                <tr><td class="label">ASUNTO:</td><td>{report_subject}</td></tr>
                <tr><td class="label">OBJETIVO:</td><td>{hostname} ({geo['city']}, {geo['country']} - IP: {geo['ip']})</td></tr>
            </table>

            <div class="memo-body">
                <h2>1. Resumen Gerencial y Hallazgo General</h2>
                <p>Por medio del presente informe, nos dirigimos a usted para presentar las conclusiones gerenciales derivadas del análisis de seguridad perimetral realizado sobre el dominio <strong>{hostname}</strong>.</p>
                
                <div class="highlight-box">
                    <p style="margin:0;"><strong>Estado Actual de Riesgo:</strong> La infraestructura evaluada presenta un total de <strong>{len(findings)} áreas de vulnerabilidad y exposición perimetral</strong> que requieren atención prioritaria.</p>
                </div>

                <h2>2. Análisis de Riesgos Críticos para el Negocio</h2>
                <ul>
                    <li><strong>Certificado SSL/TLS:</strong> {ssl_info['details']} (Emisor: {ssl_info['issuer']})</li>
                    <li><strong>Protección de Correo (SPF / DMARC):</strong> {"Configurado correctamente." if email_sec['spf'] and email_sec['dmarc'] else "Ausencia de directivas estrictas. Riesgo de phishing y suplantación de identidad."}</li>
                    <li><strong>Exposición Perimetral:</strong> Presencia de puertos y servicios con exposición directa a internet.</li>
                </ul>
            </div>

            <div class="signature-section">
                <p style="margin:2px 0;">Atentamente,</p>
                <p style="margin:2px 0;"><strong>Equipo de Ciberseguridad y Riesgos</strong><br>{agency_name}</p>
            </div>
            <div class="disclaimer">Documento confidencial preparado para la gerencia de {hostname}.</div>
        </body>
        </html>
        """
  else:
    active_findings = findings
    if "Correo" in report_type:
      active_findings = [
          f
          for f in findings
          if "SPF" in f["vector"] or "DMARC" in f["vector"]
      ]
    elif "Ejecutivo" in report_type:
      active_findings = findings[:3]

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

    items_html_en = ""
    for idx, f in enumerate(active_findings, 1):
      f_en = translate_finding_en(f)
      items_html_en += f"""
            <div class="finding-card">
                <div class="finding-header">
                    <span class="finding-num">#{idx}</span>
                    <span class="finding-title">{f_en['vector']}</span>
                    <span class="{f_en['badge']}">{f_en['severity']}</span>
                </div>
                <div class="finding-body">
                    <p><strong>Technical Description:</strong> {f_en['desc']}</p>
                    <p><strong>Business Impact:</strong> {f_en['impact']}</p>
                    <div class="solution-box"><p><strong>Remediation:</strong> <code>{f_en['fix']}</code></p></div>
                </div>
            </div>
            """
    exec_bullets_en = "".join([
        (
            f"<li><strong>{translate_finding_en(f)['exec_title']}</strong>:"
            f" {translate_finding_en(f)['impact']}</li>"
        )
        for f in active_findings
    ])

    items_html_es = ""
    for idx, f in enumerate(active_findings, 1):
      items_html_es += f"""
            <div class="finding-card">
                <div class="finding-header">
                    <span class="finding-num">#{idx}</span>
                    <span class="finding-title">{f['vector']}</span>
                    <span class="{f['badge']}">{f['severity']}</span>
                </div>
                <div class="finding-body">
                    <p><strong>Descripción Técnica:</strong> {f['desc']}</p>
                    <p><strong>Impacto de Negocio:</strong> {f['impact']}</p>
                    <div class="solution-box"><p><strong>Remediación:</strong> <code>{f['fix']}</code></p></div>
                </div>
            </div>
            """
    exec_bullets_es = "".join([
        f"<li><strong>{f['exec_title']}</strong>: {f['impact']}</li>"
        for f in active_findings
    ])

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
            <!-- ENGLISH REPORT -->
            <div class="header-banner">
                <div class="banner-left">
                    <h1>Cybersecurity Assessment Report</h1>
                    <p>Prepared by: <strong>{agency_name}</strong> ({agency_tagline})</p>
                </div>
                <div class="banner-right">{logo_html}</div>
            </div>
            <table style="width: 100%; margin-bottom: 6px; border: none;">
                <tr>
                    <td style="border: none; width: 25%;"><div class="meta-item"><div class="meta-label">Target</div><div class="meta-value">{hostname}</div></div></td>
                    <td style="border: none; width: 25%;"><div class="meta-item"><div class="meta-label">Location</div><div class="meta-value">{geo['city']}, {geo['country']}</div></div></td>
                    <td style="border: none; width: 25%;"><div class="meta-item"><div class="meta-label">SSL Status</div><div class="meta-value">{ssl_badge}</div></div></td>
                    <td style="border: none; width: 25%;"><div class="meta-item"><div class="meta-label">SPF / DMARC</div><div class="meta-value">{spf_badge} / {dmarc_badge}</div></div></td>
                </tr>
            </table>
            <h2>1. Management Vision & Infrastructure</h2>
            <div class="executive-box"><p style="margin:0;">The exposed perimeter of <strong>{hostname}</strong> was assessed under the <em>{report_type}</em> standard.</p></div>
            <table style="width: 100%; border: none; margin-bottom: 6px;">
                <tr>
                    <td style="width: 50%; vertical-align: top; border: none;">
                        <div class="card"><h3 style="margin:0; font-size:8.5pt;">Critical Ports:</h3>
                        <table class="ports-table"><thead><tr><th>Port</th><th>Service</th></tr></thead><tbody>{ports_html}</tbody></table></div>
                    </td>
                    <td style="width: 50%; vertical-align: top; border: none;">
                        <div class="card"><h3 style="margin:0; font-size:8.5pt;">Subdomains:</h3>
                        <ul style="margin:0; padding-left:14px; font-size:7pt; max-height:75px; overflow:hidden;">{sub_html}</ul></div>
                    </td>
                </tr>
            </table>
            <div class="card" style="text-align: center; padding: 4px;">
                <div class="chart-container"><img src="data:image/png;base64,{chart_base64}" alt="Chart"></div>
            </div>
            <div class="card">
                <h3 style="margin:0; font-size:8.5pt;">Impact Analysis:</h3>
                <ul style="margin:0; padding-left:14px; font-size:7.5pt;">{exec_bullets_en}</ul>
            </div>
            <div style="page-break-after: always;"></div>
            
            <div class="header-banner">
                <div class="banner-left">
                    <h1>Technical Annex & Remediation</h1>
                    <p>Prepared by: {agency_name}</p>
                </div>
                <div class="banner-right">{logo_html}</div>
            </div>
            <h2>2. Actionable Findings & Fixes</h2>
            {items_html_en}
            <div class="disclaimer">Real-time external perimeter assessment.</div>

            <!-- SPANISH REPORT -->
            <div style="page-break-after: always;"></div>
            <div class="header-banner">
                <div class="banner-left">
                    <h1>Informe Ejecutivo de Ciberseguridad</h1>
                    <p>Elaborado por: <strong>{agency_name}</strong> ({agency_tagline})</p>
                </div>
                <div class="banner-right">{logo_html}</div>
            </div>
            <table style="width: 100%; margin-bottom: 6px; border: none;">
                <tr>
                    <td style="border: none; width: 25%;"><div class="meta-item"><div class="meta-label">Objetivo / IP</div><div class="meta-value">{hostname}</div></div></td>
                    <td style="border: none; width: 25%;"><div class="meta-item"><div class="meta-label">Ubicación</div><div class="meta-value">{geo['city']}, {geo['country']}</div></div></td>
                    <td style="border: none; width: 25%;"><div class="meta-item"><div class="meta-label">Certificado SSL</div><div class="meta-value">{ssl_badge}</div></div></td>
                    <td style="border: none; width: 25%;"><div class="meta-item"><div class="meta-label">SPF / DMARC</div><div class="meta-value">{spf_badge} / {dmarc_badge}</div></div></td>
                </tr>
            </table>
            <h2>1. Visión Gerencial e Infraestructura</h2>
            <div class="executive-box"><p style="margin:0;">Se analizó la superficie expuesta de <strong>{hostname}</strong> bajo el estándar de <em>{report_type}</em>.</p></div>
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
            <div class="card">
                <h3 style="margin:0; font-size:8.5pt;">Análisis de Impacto:</h3>
                <ul style="margin:0; padding-left:14px; font-size:7.5pt;">{exec_bullets_es}</ul>
            </div>
            <div style="page-break-after: always;"></div>
            <div class="header-banner">
                <div class="banner-left">
                    <h1>Anexo Técnico y Guía de Remediación</h1>
                    <p>Elaborado por: {agency_name}</p>
                </div>
                <div class="banner-right">{logo_html}</div>
            </div>
            <h2>2. Detalle Exhaustivo de Hallazgos</h2>
            {items_html_es}
            <div class="disclaimer">Nota: Hallazgos perimetrales externos en tiempo real.</div>
        </body>
        </html>
        """

  HTML(string=html_content).write_pdf(output_filename)


# Inicializar sesión
if "scanned" not in st.session_state:
  st.session_state.scanned = False

# Banner superior limpio
st.markdown(
    """
    <div class="enterprise-banner">
        🚀 <strong>CyberAudits Security Suite:</strong> SSL Inspection & Word (.docx) Export <b>Active & Ready</b>.
    </div>
    """,
    unsafe_allow_html=True,
)

st.title("🛡️ CyberAudits - Escáner Perimetral")
st.write(
    "Plataforma de inteligencia perimetral, inspección SSL y auditoría"
    " automatizada."
)

# Panel de Configuración Comercial (Sidebar)
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
        "Informe Ejecutivo (Solo Gerencia)",
        "Informe de Postura de Correo y DNS",
        "Informe Ejecutivo Narrativo (Formato Carta)",
    ],
)

recipient_name = st.sidebar.text_input(
    "Dirigido a (Destinatario / Gerencia)",
    value="Dirección General / Junta Directiva",
)
report_subject = st.sidebar.text_input(
    "Asunto del Informe",
    value="Evaluación de Riesgos Perimetrales y Postura de Negocio",
)

st.sidebar.markdown("---")
st.sidebar.caption(
    "Personaliza la identidad visual, subtítulos y destinatarios de los"
    " reportes."
)

tab1, tab2, tab3 = st.tabs(
    ["🔍 Perimeter Scan", "📊 Security Analytics", "ℹ️ About CyberAudits"]
)

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
          "🔍 Analizando perímetro, SSL/TLS, DNS y puertos...", expanded=True
      ) as status:
        st.write("Inspeccionando certificado SSL/TLS y emisor...")
        st.write("Verificando registros DNS (SPF y DMARC)...")
        st.write("Escaneando puertos y descubriendo subdominios...")

        (
            findings,
            stats,
            open_ports,
            hostname,
            subdomains,
            geo,
            email_sec,
            ssl_info,
        ) = scan_target(target_url)

        st.write(
            f"Generando plantillas y reportes para {agency_name}..."
        )
        chart_b64 = generate_chart(stats)

        logo_b64 = ""
        if logo_file is not None:
          logo_b64 = base64.b64encode(logo_file.getvalue()).decode("utf-8")

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
            agency_name,
            agency_tagline,
            report_type,
            recipient_name,
            report_subject,
        )

        status.update(
            label="✅ ¡Análisis perimetral y SSL completado!",
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
      st.session_state.agency_name = agency_name
      st.session_state.agency_tagline = agency_tagline
      st.session_state.report_type = report_type
      st.session_state.recipient_name = recipient_name
      st.session_state.report_subject = report_subject
      st.session_state.logo_b64 = logo_b64
      st.session_state.pdf_filename = pdf_filename
      st.session_state.docx_bytes = docx_bytes

  if st.session_state.scanned:
    st.success(
        f"¡Análisis completado para {st.session_state.hostname}!"
    )

    st.markdown("### 📍 Inteligencia de Servidor, SSL y DNS")
    g1, g2, g3, g4, g5 = st.columns(5)
    g1.metric("Dirección IP", st.session_state.geo["ip"])
    g2.metric("Ubicación", st.session_state.geo["country"])
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
    st.subheader("📊 Resumen del Estado de Seguridad")

    col1, col2, col3 = st.columns(3)
    col1.metric("Vulnerabilidades", len(st.session_state.findings))
    col2.metric("Puertos Abiertos", len(st.session_state.open_ports))
    col3.metric("Subdominios", len(st.session_state.subdomains))

    st.markdown("---")
    st.markdown("### 📥 Descarga de Informes y Datos (Workflow Pentest)")
    st.success(
        "💎 **Promoción de Lanzamiento:** ¡La descarga de reportes ejecutivos en"
        " PDF, Word editable y datos es **100% GRATIS**!"
    )

    col_dl1, col_dl2, col_dl3, col_dl4 = st.columns(4)

    with col_dl1:
      if os.path.exists(st.session_state.pdf_filename):
        with open(st.session_state.pdf_filename, "rb") as pdf_file:
          st.download_button(
              label="📥 Descargar PDF Ejecutivo",
              data=pdf_file,
              file_name=st.session_state.pdf_filename,
              mime="application/pdf",
              type="primary",
          )

    with col_dl2:
      if "docx_bytes" in st.session_state:
        st.download_button(
            label="📝 Descargar Word (.docx)",
            data=st.session_state.docx_bytes,
            file_name=f"auditoria_{st.session_state.hostname}.docx",
            mime=(
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            ),
            type="primary",
        )

    with col_dl3:
      export_data = {
          "target": st.session_state.hostname,
          "ip": st.session_state.geo["ip"],
          "location": st.session_state.geo["country"],
          "hosting": st.session_state.geo["org"],
          "ssl_inspection": st.session_state.ssl_info,
          "email_security": st.session_state.email_sec,
          "open_ports": st.session_state.open_ports,
          "subdomains": st.session_state.subdomains,
          "findings": st.session_state.findings,
      }
      json_str = json.dumps(export_data, indent=4, ensure_ascii=False)
      st.download_button(
          label="📦 Exportar JSON",
          data=json_str,
          file_name=f"auditoria_{st.session_state.hostname}.json",
          mime="application/json",
      )

    with col_dl4:
      df_findings = pd.DataFrame(st.session_state.findings)
      if not df_findings.empty:
        csv_data = df_findings.to_csv(index=False, sep=";").encode("utf-8-sig")
        st.download_button(
            label="📊 Exportar CSV",
            data=csv_data,
            file_name=f"hallazgos_{st.session_state.hostname}.csv",
            mime="text/csv",
        )

with tab2:
  st.subheader("Infrastructure Health, SSL & DNS Posture")
  if st.session_state.scanned:
    st.write(f"Target: **{st.session_state.hostname}**")
    st.write(f"Resolved IP: `{st.session_state.geo['ip']}`")
    st.write(f"Hosting Provider: `{st.session_state.geo['org']}`")
    st.write(f"SSL Status: `{st.session_state.ssl_info['details']}`")
    st.write(f"SSL Issuer: `{st.session_state.ssl_info['issuer']}`")
    st.write(
        "SPF Status:"
        f" `{'Configured' if st.session_state.email_sec['spf'] else 'Missing'}`"
    )
    st.write(
        "DMARC Status:"
        f" `{'Configured' if st.session_state.email_sec['dmarc'] else 'Missing'}`"
    )
    st.write(f"Open ports count: {len(st.session_state.open_ports)}")
    st.write(f"Subdomains discovered: {len(st.session_state.subdomains)}")

    if st.session_state.findings:
      st.markdown("### Raw Findings Table")
      st.dataframe(pd.DataFrame(st.session_state.findings))
  else:
    st.info(
        "Run a scan in the first tab to view infrastructure and SSL details."
    )

with tab3:
  st.subheader("About CyberAudits")
  st.markdown("""
    **CyberAudits** is an automated perimeter security platform built for fast infrastructure auditing, SSL verification, and executive reporting.
    * **Tech Stack:** Python, Streamlit, WeasyPrint, Python-Docx, Socket, SSL, Cloudflare DoH API, crt.sh, Pandas.
    * **Reporting:** Fully customizable white-label corporate delivery with PDF executive reports and fully editable Word (`.docx`) documents.
    """)
