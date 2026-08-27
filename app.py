import base64
import json
import os
import socket
from urllib.parse import urlparse
import matplotlib.pyplot as plt
import pandas as pd
import requests
from weasyprint import HTML
import streamlit as st

# Configuración de la página web
st.set_page_config(
    page_title="CyberAudits - Escáner Perimetral",
    page_icon="🛡️",
    layout="centered",
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

    cookies = response.cookies
    if cookies:
      for cookie in cookies:
        has_httponly = False
        if hasattr(cookie, "_rest") and any(
            attr.lower() == "httponly" for attr in cookie._rest
        ):
          has_httponly = True

        if not cookie.secure or not has_httponly:
          stats["Medias"] += 1
          findings.append({
              "vector": f"Cookie de Sesión Insegura ({cookie.name})",
              "severity": "MEDIO",
              "badge": "badge-medium",
              "exec_title": (
                  f"Vulnerabilidad en Cookie de Sesión ({cookie.name})"
              ),
              "desc": (
                  f"La cookie '{cookie.name}' carece de los atributos de"
                  " protección Secure u HttpOnly."
              ),
              "impact": (
                  "Scripts maliciosos (XSS) pueden robar la sesión activa del"
                  " usuario."
              ),
              "fix": (
                  "Emitir cookies con los atributos: Secure; HttpOnly;"
                  " SameSite=Strict."
              ),
          })
        else:
          stats["Seguras"] += 1
    else:
      stats["Seguras"] += 2

  except Exception:
    pass

  return findings, stats, open_ports, hostname, subdomains, geo, email_sec


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


def translate_finding_en(f):
  vec = f["vector"]
  sev = f["severity"]
  sev_en = (
      "CRITICAL" if sev == "CRÍTICO" else ("MEDIUM" if sev == "MEDIO" else "LOW")
  )
  if "SPF" in vec:
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
  elif "Cookie" in vec:
    title_en = vec.replace("Cookie de Sesión Insegura", "Insecure Session Cookie")
    exec_t_en = "Session Cookie Vulnerability"
    desc_en = (
        "The session cookie lacks Secure or HttpOnly protection attributes."
    )
    impact_en = (
        "Malicious scripts (XSS) can steal the active user session and hijack"
        " their identity."
    )
    fix_en = "Emit cookies with attributes: Secure; HttpOnly; SameSite=Strict."
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
    agency_name,
    agency_tagline,
    report_type,
    recipient_name,
    report_subject,
    logo_b64,
    output_filename,
):
  # Logo más grande (max-height: 65px)
  logo_html = (
      f'<img src="data:image/png;base64,{logo_b64}" style="max-height: 65px;'
      ' width: auto; float: right; margin-top: 2px;" alt="Logo">'
      if logo_b64
      else ""
  )

  # Si se seleccionó el formato Carta / Informe Ejecutivo Narrativo
  if "Carta" in report_type or "Narrativo" in report_type:
    html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                @page {{ size: A4; margin: 15mm 15mm; background-color: #ffffff; @bottom-right {{ content: "Page / Página " counter(page); font-size: 8pt; color: #64748b; }} }}
                body {{ font-family: Helvetica, Arial, sans-serif; color: #1e293b; margin: 0; padding: 0; font-size: 10pt; line-height: 1.6; }}
                .memo-header {{ border-bottom: 2px solid #0f172a; padding-bottom: 10px; margin-bottom: 20px; overflow: hidden; }}
                .memo-header-left {{ float: left; width: 70%; }}
                .memo-header-right {{ float: right; width: 28%; text-align: right; }}
                .memo-header h1 {{ margin: 0; font-size: 15pt; color: #0f172a; text-transform: uppercase; letter-spacing: 0.5px; }}
                .memo-header p {{ margin: 3px 0; color: #64748b; font-size: 9pt; }}
                .meta-table {{ width: 100%; margin-bottom: 20px; border-collapse: collapse; font-size: 9.5pt; }}
                .meta-table td {{ padding: 5px 0; border-bottom: 1px solid #e2e8f0; }}
                .meta-table td.label {{ font-weight: bold; color: #475569; width: 20%; }}
                .memo-body h2 {{ color: #0f172a; font-size: 11pt; border-left: 3px solid #3b82f6; padding-left: 8px; margin-top: 15px; margin-bottom: 8px; }}
                .highlight-box {{ background-color: #f8fafc; border: 1px solid #cbd5e1; border-left: 4px solid #3b82f6; padding: 12px 15px; border-radius: 4px; margin: 15px 0; }}
                .signature-section {{ margin-top: 40px; page-break-inside: avoid; }}
                .disclaimer {{ font-size: 8pt; color: #94a3b8; margin-top: 30px; text-align: center; border-top: 1px solid #e2e8f0; padding-top: 10px; }}
            </style>
        </head>
        <body>
            <!-- INFORME EJECUTIVO EN FORMATO CARTA -->
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
                <p>Por medio del presente informe, nos dirigimos a usted para presentar las conclusiones gerenciales derivadas del análisis de seguridad perimetral realizado sobre el dominio <strong>{hostname}</strong>. El propósito de este documento es traducir los indicadores técnicos a un lenguaje de impacto estratégico y financiero para la toma oportuna de decisiones.</p>
                
                <div class="highlight-box">
                    <p style="margin:0;"><strong>Estado Actual de Riesgo:</strong> La infraestructura evaluada presenta un total de <strong>{len(findings)} áreas de vulnerabilidad y exposición perimetral</strong> que requieren atención prioritaria por parte del equipo técnico para salvaguardar la reputación de la organización.</p>
                </div>

                <h2>2. Análisis de Riesgos Críticos para el Negocio</h2>
                <p>Durante la auditoría, se detectaron factores clave que impactan directamente la operación y seguridad institucional:</p>
                <ul>
                    <li><strong>Protección de Correo y Fraude (SPF / DMARC):</strong> {"Los mecanismos de autenticación de correo se encuentran configurados correctamente." if email_sec['spf'] and email_sec['dmarc'] else "Se identificó la ausencia de directivas estrictas de autenticación de correo (SPF/DMARC). Esto expone a la entidad a que terceros maliciosos envíen correos masivos de suplantación de identidad (phishing) a nombre de su marca."}</li>
                    <li><strong>Exposición de Servicios y Puertos:</strong> La presencia de puertos operativos accesibles de forma directa desde internet incrementa la superficie de ataque ante intentos automatizados de intrusión y ataques de fuerza bruta.</li>
                    <li><strong>Seguridad en Tránsito y Cifrado:</strong> La falta de políticas de cabeceras seguras (como HSTS) en los servidores web deja abierta una ventana para la intercepción de tráfico en redes no confiables.</li>
                </ul>

                <h2>3. Recomendaciones y Siguiente Paso Ejecutivo</h2>
                <p>Recomendamos encarecidamente autorizar de manera inmediata al equipo de tecnología la aplicación de los planes de remediación técnica incluidos en los anexos correspondientes. Mantener un perímetro blindado es indispensable para garantizar la confianza de sus clientes y socios comerciales.</p>
            </div>

            <div class="signature-section">
                <p>Atentamente,</p>
                <p><strong>Equipo de Ciberseguridad y Riesgos</strong><br>{agency_name} — {agency_tagline}</p>
            </div>

            <div class="disclaimer">Documento confidencial preparado para la gerencia de {hostname}. Todos los derechos reservados.</div>
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
                " (Open / Abierto)</td></tr>"
            )
            for p in open_ports
        ])
        or "<tr><td colspan='2' style='text-align:center;'>No common ports"
        " detected.</td></tr>"
    )
    sub_html = (
        "".join([f"<li><code>{sub}</code></li>" for sub in subdomains])
        or "<li>No additional subdomains found.</li>"
    )

    spf_badge = (
        "<span style='color:green;'><b>Configurado (OK)</b></span>"
        if email_sec["spf"]
        else "<span style='color:red;'><b>Ausente (Riesgo)</b></span>"
    )
    dmarc_badge = (
        "<span style='color:green;'><b>Configurado (OK)</b></span>"
        if email_sec["dmarc"]
        else "<span style='color:red;'><b>Ausente (Riesgo)</b></span>"
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
                    <div class="solution-box">
                        <p><strong>Remediation:</strong> <code>{f_en['fix']}</code></p>
                    </div>
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
                    <div class="solution-box">
                        <p><strong>Remediación:</strong> <code>{f['fix']}</code></p>
                    </div>
                </div>
            </div>
            """
    exec_bullets_es = "".join([
        f"<li><strong>{f['exec_title']}</strong>: {f['impact']}</li>"
        for f in active_findings
    ])

    report_title_en = (
        "Cybersecurity Executive Report"
        if "Ejecutivo" in report_type
        else (
            "Email & DNS Posture Report"
            if "Correo" in report_type
            else "Comprehensive Cybersecurity Assessment"
        )
    )
    report_title_es = (
        "Informe Ejecutivo de Ciberseguridad"
        if "Ejecutivo" in report_type
        else (
            "Informe de Postura de Correo y DNS"
            if "Correo" in report_type
            else "Informe Técnico Exhaustivo de Ciberseguridad"
        )
    )

    html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                @page {{ size: A4; margin: 10mm 12mm; background-color: #f8fafc; @bottom-right {{ content: "Page / Página " counter(page) " of / de " counter(pages); font-size: 8pt; color: #64748b; }} }}
                body {{ font-family: Helvetica, Arial, sans-serif; color: #334155; margin: 0; padding: 0; font-size: 8.5pt; line-height: 1.35; }}
                .header-banner {{ background: #0f172a; color: white; padding: 10px 15px; border-radius: 5px; margin-bottom: 6px; overflow: hidden; }}
                .banner-left {{ float: left; width: 70%; }}
                .banner-right {{ float: right; width: 28%; text-align: right; }}
                .header-banner h1 {{ margin: 0; font-size: 14pt; }}
                .header-banner p {{ margin: 0; color: #94a3b8; font-size: 8.5pt; }}
                .meta-item {{ background: white; padding: 4px 8px; border: 1px solid #e2e8f0; border-radius: 4px; }}
                .meta-label {{ font-size: 6pt; color: #64748b; text-transform: uppercase; }}
                .meta-value {{ font-size: 8.5pt; font-weight: 600; color: #0f172a; }}
                h2 {{ color: #0f172a; font-size: 10pt; border-left: 3px solid #3b82f6; padding-left: 5px; margin-top: 6px; margin-bottom: 4px; }}
                .card {{ background: white; border: 1px solid #e2e8f0; border-radius: 5px; padding: 6px 8px; margin-bottom: 5px; }}
                .badge-critical {{ background-color: #fee2e2; color: #991b1b; padding: 2px 4px; border-radius: 3px; font-size: 6.5pt; float: right; }}
                .badge-medium {{ background-color: #fef3c7; color: #92400e; padding: 2px 4px; border-radius: 3px; font-size: 6.5pt; float: right; }}
                .badge-low {{ background-color: #dbeafe; color: #1e40af; padding: 2px 4px; border-radius: 3px; font-size: 6.5pt; float: right; }}
                .chart-container {{ text-align: center; }}
                .chart-container img {{ max-width: 70%; height: auto; }}
                .executive-box {{ background-color: #eff6ff; border-left: 3px solid #3b82f6; padding: 5px 8px; margin-bottom: 5px; }}
                .cta-box {{ background-color: #f0fdf4; border: 1px solid #bbf7d0; padding: 8px 12px; border-radius: 5px; margin-top: 8px; text-align: center; page-break-inside: avoid; }}
                .cta-box h3 {{ margin: 0; color: #166534; font-size: 9.5pt; }}
                .cta-box p {{ margin: 0; color: #15803d; font-size: 8pt; }}
                table.ports-table {{ width: 100%; border-collapse: collapse; font-size: 7.5pt; }}
                table.ports-table th {{ background-color: #f1f5f9; padding: 2px; border-bottom: 2px solid #cbd5e1; text-align: left; }}
                table.ports-table td {{ padding: 2px; border-bottom: 1px solid #e2e8f0; }}
                .finding-card {{ background: white; border: 1px solid #cbd5e1; border-radius: 4px; margin-bottom: 5px; page-break-inside: avoid; }}
                .finding-header {{ background-color: #f1f5f9; padding: 4px 6px; border-bottom: 1px solid #cbd5e1; overflow: hidden; }}
                .finding-title {{ font-weight: bold; color: #0f172a; font-size: 8.5pt; }}
                .finding-body {{ padding: 5px 6px; }}
                .solution-box {{ background-color: #f8fafc; border-left: 3px solid #0284c7; padding: 4px 6px; margin-top: 3px; }}
                .solution-box code {{ color: #0369a1; font-size: 7pt; }}
                .disclaimer {{ font-size: 7pt; color: #64748b; margin-top: 6px; text-align: center; font-style: italic; }}
            </style>
        </head>
        <body>
            <!-- INGLÉS -->
            <div class="header-banner">
                <div class="banner-left">
                    <h1>{report_title_en}</h1>
                    <p>Prepared by: <strong>{agency_name}</strong> ({agency_tagline})</p>
                </div>
                <div class="banner-right">
                    {logo_html}
                </div>
            </div>
            <table style="width: 100%; margin-bottom: 6px; border: none;">
                <tr>
                    <td style="border: none; width: 25%;"><div class="meta-item"><div class="meta-label">Target / IP</div><div class="meta-value">{hostname}</div></div></td>
                    <td style="border: none; width: 25%;"><div class="meta-item"><div class="meta-label">Location</div><div class="meta-value">{geo['city']}, {geo['country']}</div></div></td>
                    <td style="border: none; width: 25%;"><div class="meta-item"><div class="meta-label">SPF Record</div><div class="meta-value">{spf_badge}</div></div></td>
                    <td style="border: none; width: 25%;"><div class="meta-item"><div class="meta-label">DMARC</div><div class="meta-value">{dmarc_badge}</div></div></td>
                </tr>
            </table>
            <h2>1. Management Vision & Infrastructure</h2>
            <div class="executive-box"><p style="margin:0;">The exposed surface of <strong>{hostname}</strong> was analyzed under the <em>{report_type}</em> standard.</p></div>
            <table style="width: 100%; border: none; margin-bottom: 6px;">
                <tr>
                    <td style="width: 50%; vertical-align: top; border: none;">
                        <div class="card"><h3 style="margin:0; font-size:9pt;">Critical Ports:</h3>
                        <table class="ports-table"><thead><tr><th>Port</th><th>Service</th></tr></thead><tbody>{ports_html}</tbody></table></div>
                    </td>
                    <td style="width: 50%; vertical-align: top; border: none;">
                        <div class="card"><h3 style="margin:0; font-size:9pt;">Subdomains:</h3>
                        <ul style="margin:0; padding-left:14px; font-size:7.5pt; max-height:80px; overflow:hidden;">{sub_html}</ul></div>
                    </td>
                </tr>
            </table>
            <div class="card" style="text-align: center; padding: 4px;">
                <div class="chart-container"><img src="data:image/png;base64,{chart_base64}" alt="Chart"></div>
            </div>
            <div class="card">
                <h3 style="margin:0; font-size:9pt;">Impact Analysis:</h3>
                <ul style="margin:0; padding-left:14px; font-size:8pt;">{exec_bullets_en}</ul>
            </div>
            <div style="page-break-after: always;"></div>
            
            <div class="header-banner">
                <div class="banner-left">
                    <h1>Technical Annex & Remediation Guide</h1>
                    <p>Prepared by: {agency_name} ({agency_tagline})</p>
                </div>
                <div class="banner-right">
                    {logo_html}
                </div>
            </div>
            <h2>2. Exhaustive Details & Actionable Findings</h2>
            {items_html_en}
            <div class="disclaimer">Note: External perimeter findings generated in real time.</div>

            <!-- ESPAÑOL -->
            <div style="page-break-after: always;"></div>
            <div class="header-banner">
                <div class="banner-left">
                    <h1>{report_title_es}</h1>
                    <p>Elaborado por: <strong>{agency_name}</strong> ({agency_tagline})</p>
                </div>
                <div class="banner-right">
                    {logo_html}
                </div>
            </div>
            <table style="width: 100%; margin-bottom: 6px; border: none;">
                <tr>
                    <td style="border: none; width: 25%;"><div class="meta-item"><div class="meta-label">Objetivo / IP</div><div class="meta-value">{hostname}</div></div></td>
                    <td style="border: none; width: 25%;"><div class="meta-item"><div class="meta-label">Ubicación</div><div class="meta-value">{geo['city']}, {geo['country']}</div></div></td>
                    <td style="border: none; width: 25%;"><div class="meta-item"><div class="meta-label">Registro SPF</div><div class="meta-value">{spf_badge}</div></div></td>
                    <td style="border: none; width: 25%;"><div class="meta-item"><div class="meta-label">DMARC</div><div class="meta-value">{dmarc_badge}</div></div></td>
                </tr>
            </table>
            <h2>1. Visión Gerencial e Infraestructura</h2>
            <div class="executive-box"><p style="margin:0;">Se analizó la superficie expuesta de <strong>{hostname}</strong> bajo el estándar de <em>{report_type}</em>.</p></div>
            <table style="width: 100%; border: none; margin-bottom: 6px;">
                <tr>
                    <td style="width: 50%; vertical-align: top; border: none;">
                        <div class="card"><h3 style="margin:0; font-size:9pt;">Puertos Críticos:</h3>
                        <table class="ports-table"><thead><tr><th>Puerto</th><th>Servicio</th></tr></thead><tbody>{ports_html}</tbody></table></div>
                    </td>
                    <td style="width: 50%; vertical-align: top; border: none;">
                        <div class="card"><h3 style="margin:0; font-size:9pt;">Subdominios:</h3>
                        <ul style="margin:0; padding-left:14px; font-size:7.5pt; max-height:80px; overflow:hidden;">{sub_html}</ul></div>
                    </td>
                </tr>
            </table>
            <div class="card" style="text-align: center; padding: 4px;">
                <div class="chart-container"><img src="data:image/png;base64,{chart_base64}" alt="Gráfico"></div>
            </div>
            <div class="card">
                <h3 style="margin:0; font-size:9pt;">Análisis de Impacto:</h3>
                <ul style="margin:0; padding-left:14px; font-size:8pt;">{exec_bullets_es}</ul>
            </div>
            <div style="page-break-after: always;"></div>
            <div class="header-banner">
                <div class="banner-left">
                    <h1>Anexo Técnico y Guía de Remediación</h1>
                    <p>Elaborado por: {agency_name} ({agency_tagline})</p>
                </div>
                <div class="banner-right">
                    {logo_html}
                </div>
            </div>
            <h2>2. Detalle Exhaustivo de Hallazgos</h2>
            {items_html_es}
            <div class="disclaimer">Nota: Hallazgos perimetrales externos en tiempo real.</div>
            <div class="cta-box">
                <h3>¿Cómo proteger su empresa?</h3>
                <p>Contáctenos hoy mismo para implementar la remediación inmediata y blindar su seguridad.</p>
            </div>
        </body>
        </html>
        """

  HTML(string=html_content).write_pdf(output_filename)


# Inicializar sesión
if "scanned" not in st.session_state:
  st.session_state.scanned = False

# Banner superior
st.markdown(
    """
    <div style="background: linear-gradient(90deg, #1e3a8a, #3b82f6); padding: 12px; border-radius: 8px; color: white; text-align: center; margin-bottom: 20px; font-family: sans-serif;">
        🚀 <strong>Product Hunt Launch Special:</strong> Full Executive PDF Reports are <b>100% FREE</b> for a limited time! Enjoy your audit.
    </div>
    """,
    unsafe_allow_html=True,
)

st.title("🛡️ CyberAudits - Escáner Perimetral")
st.write(
    "Analiza la seguridad de cualquier dominio web y evalúa la postura de"
    " correo y servidores."
)

# Panel de Configuración Comercial y Modelos de Informe (White-Label + Templates)
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
          "🔍 Analizando perímetro, geolocalización y DNS...", expanded=True
      ) as status:
        st.write("Verificando registros DNS (SPF y DMARC anti-spoofing)...")
        st.write("Resolviendo geolocalización y puertos expuestos...")
        findings, stats, open_ports, hostname, subdomains, geo, email_sec = (
            scan_target(target_url)
        )
        st.write(
            f"Generando plantilla '{report_type}' para {agency_name}..."
        )
        chart_b64 = generate_chart(stats)

        # Procesar logo en base64 si el usuario cargó uno
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
            agency_name,
            agency_tagline,
            report_type,
            recipient_name,
            report_subject,
            logo_b64,
            pdf_filename,
        )
        status.update(
            label="✅ ¡Análisis de pentest completado!",
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
      st.session_state.agency_name = agency_name
      st.session_state.agency_tagline = agency_tagline
      st.session_state.report_type = report_type
      st.session_state.recipient_name = recipient_name
      st.session_state.report_subject = report_subject
      st.session_state.logo_b64 = logo_b64
      st.session_state.pdf_filename = pdf_filename

  if st.session_state.scanned:
    st.success(
        f"¡Análisis completado para {st.session_state.hostname} usando el"
        f" modelo '{st.session_state.report_type}'!"
    )

    st.markdown("### 📍 Inteligencia de Servidor y DNS")
    g1, g2, g3, g4 = st.columns(4)
    g1.metric("Dirección IP", st.session_state.geo["ip"])
    g2.metric("Ubicación", st.session_state.geo["country"])
    g3.metric(
        "Registro SPF",
        "Protegido" if st.session_state.email_sec["spf"] else "Ausente",
    )
    g4.metric(
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
        "💎 **Promoción de Lanzamiento Product Hunt:** ¡La descarga de reportes"
        " y datos en bruto es **100% GRATIS**!"
    )

    col_dl1, col_dl2, col_dl3 = st.columns(3)

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
      export_data = {
          "target": st.session_state.hostname,
          "ip": st.session_state.geo["ip"],
          "location": st.session_state.geo["country"],
          "hosting": st.session_state.geo["org"],
          "email_security": st.session_state.email_sec,
          "open_ports": st.session_state.open_ports,
          "subdomains": st.session_state.subdomains,
          "findings": st.session_state.findings,
          "prepared_by": st.session_state.agency_name,
          "agency_tagline": st.session_state.agency_tagline,
          "report_model": st.session_state.report_type,
          "recipient": st.session_state.recipient_name,
          "subject": st.session_state.report_subject,
      }
      json_str = json.dumps(export_data, indent=4, ensure_ascii=False)
      st.download_button(
          label="📦 Exportar Datos (JSON)",
          data=json_str,
          file_name=f"auditoria_{st.session_state.hostname}.json",
          mime="application/json",
      )

    with col_dl3:
      df_findings = pd.DataFrame(st.session_state.findings)
      if not df_findings.empty:
        csv_data = df_findings.to_csv(index=False, sep=";").encode("utf-8-sig")
        st.download_button(
            label="📊 Exportar Hallazgos (CSV)",
            data=csv_data,
            file_name=f"hallazgos_{st.session_state.hostname}.csv",
            mime="text/csv",
        )

with tab2:
  st.subheader("Infrastructure Health & DNS Posture")
  if st.session_state.scanned:
    st.write(f"Target: **{st.session_state.hostname}**")
    st.write(f"Resolved IP: `{st.session_state.geo['ip']}`")
    st.write(f"Hosting Provider: `{st.session_state.geo['org']}`")
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
        "Run a scan in the first tab to view infrastructure and DNS security"
        " details."
    )

with tab3:
  st.subheader("About CyberAudits")
  st.markdown("""
    **CyberAudits** is an automated perimeter security platform built for fast infrastructure auditing and executive reporting.
    * **Tech Stack:** Python, Streamlit, WeasyPrint, Socket, Cloudflare DoH API, crt.sh, Pandas.
    * **Reporting:** Fully customizable white-label corporate delivery with large logos, custom taglines, and editable subjects.
    """)
