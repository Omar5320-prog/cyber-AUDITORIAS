import base64
import os
import socket
from urllib.parse import urlparse
import matplotlib.pyplot as plt
import requests
from weasyprint import HTML
import streamlit as st

# Configuración de la página web
st.set_page_config(
    page_title="CyberAudits - Escáner Perimetral",
    page_icon="🛡️",
    layout="centered",
)


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
              " de forma directa desde internet sin restricciones perimetrales"
              " visibles."
          ),
          "impact": (
              "Invita a atacantes a realizar ataques de fuerza bruta para"
              " adivinar credenciales y lograr control total de la plataforma."
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
              " conexión y robar contraseñas o tokens en tiempo real."
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
              " públicas asociadas a esa versión exacta de software."
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
              "Un sitio malicioso externo puede cargar tu web de forma"
              " invisible bajo un botón trampa para engañar al usuario."
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
                  " usuario y suplantar su identidad."
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

  return findings, stats, open_ports, hostname, subdomains


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
  if "Puerto" in vec:
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
    output_filename,
):
  # Tablas y listas comunes
  ports_html = (
      "".join([
          f"<tr><td><code>{p['port']}</code></td><td><strong>{p['service']}</strong>"
          " (Open / Abierto)</td></tr>"
          for p in open_ports
      ])
      or "<tr><td colspan='2' style='text-align:center;'>No common ports"
      " detected.</td></tr>"
  )
  sub_html = (
      "".join([f"<li><code>{sub}</code></li>" for sub in subdomains])
      or "<li>No additional subdomains found.</li>"
  )

  # HTML de hallazgos en INGLÉS (Páginas 1 y 2)
  items_html_en = ""
  for idx, f in enumerate(findings, 1):
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
      f"<li><strong>{translate_finding_en(f)['exec_title']}</strong>:"
      f" {translate_finding_en(f)['impact']}</li>"
      for f in findings
  ])

  # HTML de hallazgos en ESPAÑOL (Páginas 3 y 4)
  items_html_es = ""
  for idx, f in enumerate(findings, 1):
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
  exec_bullets_es = "".join(
      [f"<li><strong>{f['exec_title']}</strong>: {f['impact']}</li>" for f in findings]
  )

  html_content = f"""
    <!DOCTYPE html>
    html>
    <head>
        <meta charset="UTF-8">
        <style>
            @page {{ size: A4; margin: 10mm 12mm; background-color: #f8fafc; @bottom-right {{ content: "Page / Página " counter(page) " of / de " counter(pages); font-size: 8pt; color: #64748b; }} }}
            body {{ font-family: Helvetica, Arial, sans-serif; color: #334155; margin: 0; padding: 0; font-size: 8.5pt; line-height: 1.35; }}
            .header-banner {{ background: #0f172a; color: white; padding: 10px 15px; border-radius: 5px; margin-bottom: 6px; }}
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
        <!-- ========================================== -->
        <!-- BLOQUE 1: INGLÉS (Páginas 1 y 2)           -->
        <!-- ========================================== -->
        <div class="header-banner">
            <h1>Cybersecurity Executive Report</h1>
            <p>Perimeter Diagnosis, Ports, Subdomains & Business Exposure</p>
        </div>
        <table style="width: 100%; margin-bottom: 6px; border: none;">
            <tr>
                <td style="border: none; width: 50%;">
                    <div class="meta-item"><div class="meta-label">Target</div><div class="meta-value">{hostname}</div></div>
                </td>
                <td style="border: none; width: 50%;">
                    <div class="meta-item"><div class="meta-label">Findings</div><div class="meta-value" style="color: #dc2626;">{len(findings)} vulnerabilities</div></div>
                </td>
            </tr>
        </table>
        <h2>1. Management Vision & Infrastructure</h2>
        <div class="executive-box"><p style="margin:0;">The exposed surface of the domain <strong>{hostname}</strong> was analyzed combining web security, open ports, and subdomains.</p></div>
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
        
        <div class="header-banner"><h1>Technical Annex & Remediation Guide</h1><p>Engineering Specifications</p></div>
        <h2>2. Exhaustive Details</h2>
        {items_html_en}
        <div class="disclaimer">Note: External perimeter findings in real time.</div>

        <!-- ========================================== -->
        <!-- SALTO DE PÁGINA PARA PASAR AL ESPAÑOL    -->
        <!-- ========================================== -->
        <div style="page-break-after: always;"></div>

        <!-- ========================================== -->
        <!-- BLOQUE 2: ESPAÑOL (Páginas 3 y 4)          -->
        <!-- ========================================== -->
        <div class="header-banner">
            <h1>Informe Ejecutivo de Ciberseguridad</h1>
            <p>Diagnóstico Perimetral, Puertos, Subdominios y Exposición de Negocio</p>
        </div>
        <table style="width: 100%; margin-bottom: 6px; border: none;">
            <tr>
                <td style="border: none; width: 50%;">
                    <div class="meta-item"><div class="meta-label">Objetivo</div><div class="meta-value">{hostname}</div></div>
                </td>
                <td style="border: none; width: 50%;">
                    <div class="meta-item"><div class="meta-label">Hallazgos</div><div class="meta-value" style="color: #dc2626;">{len(findings)} vulnerabilidades</div></div>
                </td>
            </tr>
        </table>
        <h2>1. Visión Gerencial e Infraestructura</h2>
        <div class="executive-box"><p style="margin:0;">Se analizó la superficie expuesta del dominio <strong>{hostname}</strong> combinando seguridad web, puertos abiertos y subdominios.</p></div>
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
        <div class="header-banner"><h1>Anexo Técnico y Guía de Remediación</h1><p>Especificaciones de Ingeniería</p></div>
        <h2>2. Detalle Exhaustivo</h2>
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


# Inicializar memoria de sesión
if "scanned" not in st.session_state:
  st.session_state.scanned = False

st.title("🛡️ CyberAudits - Escáner Perimetral")
st.write(
    "Analiza la seguridad de cualquier dominio web y obtén métricas de"
    " exposición de infraestructura."
)

target_url = st.text_input("URL Objetivo (ej. mi-empresa.com)", "https://")

if st.button("🚀 Ejecutar Análisis Gratuito"):
  if not target_url or target_url == "https://":
    st.error("Por favor, introduce una URL válida.")
  else:
    if not target_url.startswith("http"):
      target_url = "https://" + target_url

    with st.spinner("🔍 Analizando superficie perimetral..."):
      findings, stats, open_ports, hostname, subdomains = scan_target(target_url)
      chart_b64 = generate_chart(stats)

      pdf_filename = f"auditoria_{hostname}.pdf"
      generate_pdf(
          target_url,
          findings,
          stats,
          chart_b64,
          open_ports,
          hostname,
          subdomains,
          pdf_filename,
      )

      # Guardar en la sesión de Streamlit
      st.session_state.scanned = True
      st.session_state.findings = findings
      st.session_state.stats = stats
      st.session_state.open_ports = open_ports
      st.session_state.hostname = hostname
      st.session_state.subdomains = subdomains
      st.session_state.pdf_filename = pdf_filename

# Mostrar resultados si ya se realizó el análisis
if st.session_state.scanned:
  st.success(
      f"¡Análisis preliminar completado para {st.session_state.hostname}!"
  )

  st.markdown("---")
  st.subheader("📊 Resumen del Estado de Seguridad")

  col1, col2, col3 = st.columns(3)
  col1.metric("Vulnerabilidades Detectadas", len(st.session_state.findings))
  col2.metric("Puertos Abiertos", len(st.session_state.open_ports))
  col3.metric("Subdominios Encontrados", len(st.session_state.subdomains))

  if len(st.session_state.findings) > 0:
    st.warning(
        "⚠️ ¡Atención! Se han detectado"
        f" **{len(st.session_state.findings)} riesgos de seguridad** que"
        " exponen este dominio a ataques automatizados."
    )
  else:
    st.info(
        "✅ El dominio muestra una superficie perimetral controlada en los"
        " vectores básicos analizados."
    )

  st.markdown("---")
  st.markdown("### 📥 Descarga el Informe Ejecutivo y Técnico Completo")
  st.markdown(
      "Obtén el documento en PDF bilingüe listo para gerencia internacional,"
      " con gráficos detallados, impacto de negocio y las **guías exactas de"
      " remediación paso a paso**."
  )

  st.info("💎 **Precio del Reporte Completo:** $9.00 USD / Equivalente local")

  col_mp, col_paypal = st.columns(2)

  with col_mp:
    st.markdown("🇦🇷 **Mercado Pago** (Pesos / LatAm)")
    st.markdown(
        "[👉 Pagar con Mercado"
        " Pago](https://mpago.li/2RNZnfh)",
        unsafe_allow_html=True,
    )

  with col_paypal:
    st.markdown("🅿️ **PayPal** (Saldo / USD)")
    st.markdown(
        "[👉 Pagar con"
        " PayPal](https://www.paypal.me/nielsen1989/9USD)",
        unsafe_allow_html=True,
    )

  st.markdown("")
  st.write("---")
  st.markdown("#### 🔓 ¿Ya realizaste el pago o quieres probar la descarga?")

  pago_verificado = st.checkbox(
      "Simular que el pago fue exitoso (Modo de prueba local)"
  )

  if pago_verificado:
    if os.path.exists(st.session_state.pdf_filename):
      with open(st.session_state.pdf_filename, "rb") as pdf_file:
        st.download_button(
            label="📥 Descargar tu PDF Bilingüe Completo Ahora",
            data=pdf_file,
            file_name=st.session_state.pdf_filename,
            mime="application/pdf",
            type="primary",
        )
    else:
      st.error(
          "El archivo PDF no se encuentra disponible. Vuelve a ejecutar el"
          " escaneo."
      )
