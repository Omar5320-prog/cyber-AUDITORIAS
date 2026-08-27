import base64
import datetime
import hashlib
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
            topic TEXT DEFAULT 'Phishing e Ingeniería Social',
            status TEXT DEFAULT 'Pendiente',
            score INTEGER DEFAULT 0,
            last_completed TEXT
        )
    """)
  c.execute("PRAGMA table_info(employees)")
  columns = [col[1] for col in c.fetchall()]
  if "topic" not in columns:
    try:
      c.execute(
          "ALTER TABLE employees ADD COLUMN topic TEXT DEFAULT 'Phishing e"
          " Ingeniería Social'"
      )
    except Exception:
      pass

  c.execute("PRAGMA table_info(history)")
  hist_cols = [col[1] for col in c.fetchall()]
  if "risk_score" not in hist_cols:
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
      " topic AS 'Campaña / Tema', status AS 'Estado', score AS 'Calificación"
      " (%)', last_completed AS 'Última Evaluación' FROM employees",
      conn,
  )
  conn.close()
  return df


# BANCO DE CONTENIDOS AMPLIADOS Y PROFUNDOS (7 PREGUNTAS POR TEMA)
TRAINING_TOPICS = {
    "Phishing e Ingeniería Social": {
        "title": "Módulo Avanzado: Detección y Defensa contra Phishing",
        "theory": """
            <div class="training-card">
                <h4>🎯 Anatomía de un Ataque de Phishing Corporativo</h4>
                <p>El <strong>Phishing</strong> representa el vector inicial de compromiso más utilizado por los ciberdelincuentes a nivel global. No busca vulnerar sistemas mediante fuerza bruta técnica, sino manipular la psicología humana para inducir errores críticos.</p>
                
                <hr style="margin: 10px 0; border:0; border-top:1px solid #e2e8f0;">
                
                <h5>1. Tipos Principales de Fraude por Correo</h5>
                <ul>
                    <li><strong>Deception Phishing (Masivo):</strong> Campañas genéricas enviadas a miles de cuentas corporativas simulando bancos, servicios de paquetería o plataformas de streaming empresarial.</li>
                    <li><strong>Spear Phishing (Dirigido):</strong> Ataques altamente personalizados donde el atacantes investiga previamente redes sociales y organigramas para suplantar a un ejecutivo de alta gerencia (CEO Fraud).</li>
                    <li><strong>Whaling:</strong> Variante de spear phishing dirigida exclusivamente a directores, miembros de juntas directivas o directores financieros.</li>
                </ul>

                <h5>2. Indicadores Técnicos de Alerta Temprana (Red Flags)</h5>
                <ul>
                    <li><strong>Spoofing de Remitente:</strong> Discrepancias evidentes entre el nombre visible del remitente y la dirección de correo real subyacente (ej: <code>soporte@micros0ft-security.com</code>).</li>
                    <li><strong>Ingeniería de Urgencia:</strong> Uso deliberado de lenguaje alarmista ("Su cuenta será suspendida en 2 horas", "Factura impaga con riesgo legal") para bloquear el pensamiento crítico del colaborador.</li>
                    <li><strong>Enlaces Enmascarados:</strong> Textos ancla engañosos que al posicionar el cursor revelan un destino web completamente ajeno a la organización legítima.</li>
                </ul>

                <h5>3. Protocolo de Actuación y Buenas Prácticas</h5>
                <p>Ante cualquier sospecha: <strong>No haga clic en enlaces</strong>, no descargue archivos adjuntos inesperados y reporte inmediatamente el correo utilizando el botón de reporte corporativo o derivándolo al equipo de Ciberseguridad.</p>
            </div>
            """,
        "questions": [
            {
                "q": (
                    "1. ¿Cuál es el propósito fundamental de un ataque de"
                    " phishing?"
                ),
                "options": [
                    "Optimizar el rendimiento de la red corporativa",
                    (
                        "Manipular al usuario para extraer credenciales, datos"
                        " financieros o instalar malware"
                    ),
                    "Verificar el estado de las licencias de software",
                ],
                "correct": 1,
            },
            {
                "q": (
                    "2. Si recibe un correo urgente del departamento legal"
                    " exigiendo abrir un archivo adjunto bajo amenaza de"
                    " despido, ¿qué debe hacer?"
                ),
                "options": [
                    "Abrir el archivo inmediatamente por miedo a represalias",
                    (
                        "Verificar la autenticidad contactando al área por canales"
                        " internos oficiales"
                    ),
                    "Reenviar el archivo a todos sus compañeros",
                ],
                "correct": 1,
            },
            {
                "q": (
                    "3. ¿Qué caracteriza a un ataque de 'Spear Phishing'?"
                    ""
                ),
                "options": [
                    "Es un correo masivo enviado de forma aleatoria",
                    (
                        "Está altamente personalizado y dirigido a una persona o"
                        " cargo específico"
                    ),
                    "Utiliza virus informáticos de tipo físico",
                ],
                "correct": 1,
            },
            {
                "q": (
                    "4. ¿Por qué los atacantes suplantan dominios legítimos"
                    " usando ligeras alteraciones tipográficas (ej."
                    " banc0nacion.com)?"
                ),
                "options": [
                    "Para ahorrar costos de servidores",
                    (
                        "Para engañar visualmente al usuario haciéndole creer"
                        " que es un sitio oficial"
                    ),
                    "Es un error automático de los servidores de correo",
                ],
                "correct": 1,
            },
            {
                "q": (
                    "5. Al pasar el cursor sobre un enlace en un correo dudoso,"
                    " la dirección web mostrada no coincide con la institución"
                    " citada. Esto indica:"
                ),
                "options": [
                    "Una redirección segura oficial",
                    (
                        "Un claro indicio de intento de fraude o enlace"
                        " malicioso"
                    ),
                    "Un problema temporal de conectividad",
                ],
                "correct": 1,
            },
            {
                "q": (
                    "6. ¿Cuál es el canal adecuado para notificar la recepción"
                    " de un correo sospechoso?"
                ),
                "options": [
                    "Responder al atacante solicitando más información",
                    (
                        "Reportar el correo mediante la herramienta interna de"
                        " seguridad o al equipo de TI"
                    ),
                    "Publicarlo en redes sociales corporativas",
                ],
                "correct": 1,
            },
            {
                "q": (
                    "7. ¿Qué rol desempeña el factor humano en la estrategia"
                    " de defensa contra el phishing?"
                ),
                "options": [
                    "Ninguno, la seguridad depende 100% de los antivirus",
                    (
                        "Es la primera línea de defensa corporativa ante"
                        " ataques de ingeniería social"
                    ),
                    "Es el principal punto débil sin posibilidad de mejora",
                ],
                "correct": 1,
            },
        ],
    },
    "Gestión de Contraseñas Robustas": {
        "title": "Módulo Avanzado: Arquitectura y Fortaleza de Contraseñas",
        "theory": """
            <div class="training-card">
                <h4>🔒 Seguridad de Credenciales y Autenticación Multifactor</h4>
                <p>Las contraseñas débiles o reutilizadas facilitan ataques automatizados de fuerza bruta y relleno de credenciales (Credential Stuffing). Proteger el acceso es blindar el perímetro corporativo.</p>

                <hr style="margin: 10px 0; border:0; border-top:1px solid #e2e8f0;">

                <h5>1. Principios de Complejidad de Claves</h5>
                <ul>
                    <li><strong>Longitud sobre Complejidad Simple:</strong> Una clave de 14-16 caracteres que combine frases aleatorias resulta exponencialmente más segura y fácil de recordar que claves cortas con símbolos complejos.</li>
                    <li><strong>Prohibición de Datos Personales:</strong> Nunca incluir nombres de familiares, mascotas, fechas de nacimiento o números de documento identificativos.</li>
                    <li><strong>Cero Reutilización:</strong> La filtración de credenciales en servicios externos no corporativos no debe comprometer jamás el acceso a los sistemas de la empresa.</li>
                </ul>

                <h5>2. El Rol del Doble Factor de Autenticación (2FA / MFA)</h5>
                <p>Contar con una contraseña robusta ya no es suficiente. El uso obligatorio de aplicaciones autenticadoras (como Google Authenticator, Microsoft Authenticator o tokens físicos) añade una capa indispensable que frena el acceso aun si la clave principal es comprometida.</p>
            </div>
            """,
        "questions": [
            {
                "q": (
                    "1. ¿Cuál es la recomendación actual de longitud para"
                    " garantizar una contraseña corporativa robusta?"
                ),
                "options": [
                    "Entre 4 y 6 caracteres",
                    "Exactamente 8 caracteres alfanuméricos",
                    "De 12 a 16 caracteres combinando diversos elementos",
                ],
                "correct": 2,
            },
            {
                "q": (
                    "2. ¿Qué es el fenómeno de 'Credential Stuffing'?"
                    ""
                ),
                "options": [
                    "Llenar formularios de contacto automáticamente",
                    (
                        "Utilizar credenciales filtradas en una web para"
                        " intentar acceder masivamente a otras plataformas"
                    ),
                    "Un respaldo de datos en la nube",
                ],
                "correct": 1,
            },
            {
                "q": (
                    "3. ¿Por qué es crítico implementar la Autenticación"
                    " Multifactor (MFA)?"
                ),
                "options": [
                    "Porque acelera el inicio de sesión en el equipo",
                    (
                        "Porque añade una segunda verificación independiente"
                        " que protege la cuenta ante robos de claves"
                    ),
                    "Es un requisito estético sin utilidad práctica",
                ],
                "correct": 1,
            },
            {
                "q": (
                    "4. ¿Cuál de los siguientes ejemplos representa una"
                    " práctica totalmente insegura?"
                ),
                "options": [
                    "Utilizar un gestor de contraseñas cifrado",
                    (
                        "Anotar contraseñas en notas adhesivas físicas pegadas"
                        " en el monitor"
                    ),
                    "Cambiar periódicamente las claves maestras",
                ],
                "correct": 1,
            },
            {
                "q": (
                    "5. Si un supuesto técnico de soporte le pide su"
                    " contraseña temporal para solucionar un fallo, usted"
                    " debe:"
                ),
                "options": [
                    "Proporcionársela de inmediato por confianza",
                    (
                        "Negarse; ningún técnico legítimo está autorizado a"
                        " solicitar su contraseña personal"
                    ),
                    "Escribirla en el chat general",
                ],
                "correct": 1,
            },
            {
                "q": (
                    "6. ¿Qué ventaja principal ofrecen los gestores de"
                    " contraseñas profesionales?"
                ),
                "options": [
                    "Permiten compartir claves abiertamente en redes sociales",
                    (
                        "Generan y almacenan de forma cifrada claves únicas y"
                        " complejas para cada servicio"
                    ),
                    "Eliminan la necesidad de usar computadoras",
                ],
                "correct": 1,
            },
            {
                "q": (
                    "7. ¿Por qué se desaconseja el uso de datos personales"
                    " (como aniversarios) en las contraseñas?"
                ),
                "options": [
                    "Porque son fáciles de adivinar mediante ingeniería"
                    " social y OSINT"
                    " (Inteligencia de Fuentes Abiertas)",
                    "Porque ocupan mucho espacio en memoria",
                    "Porque los teclados modernos no los aceptan",
                ],
                "correct": 0,
            },
        ],
    },
    "Seguridad en Dispositivos y Remoto": {
        "title": "Módulo Avanzado: Protección de Endpoints y Trabajo Remoto",
        "theory": """
            <div class="training-card">
                <h4>🛡️ Seguridad en Dispositivos y Movilidad Corporativa</h4>
                <p>El modelo de trabajo híbrido desplaza la infraestructura fuera del perímetro físico seguro de la oficina. Los equipos portátiles y dispositivos móviles constituyen puntos críticos de exposición.</p>

                <hr style="margin: 10px 0; border:0; border-top:1px solid #e2e8f0;">

                <h5>1. Buenas Prácticas de Higiene Digital</h5>
                <ul>
                    <li><strong>Bloqueo Activo de Sesión:</strong> Todo colaborador debe bloquear obligatoriamente su pantalla (atajo <code>Windows + L</code> o <code>Control + Cmd + Q</code>) cada vez que se ausente del equipo.</li>
                    <li><strong>Restricción de Periféricos USB:</strong> Conectar memorias USB ajenas o no verificadas expone al sistema operativo a la ejecución automatizada de código malicioso o malware de tipo Stuxnet/BadUSB.</li>
                    <li><strong>Actualizaciones del Sistema:</strong> Los parches de seguridad liberados por los fabricantes solucionan fallos críticos que son explotados activamente por ciberdelincuentes.</li>
                </ul>
            </div>
            """,
        "questions": [
            {
                "q": (
                    "1. ¿Por qué es obligatorio bloquear la sesión de pantalla"
                    " al alejarse del equipo de trabajo?"
                ),
                "options": [
                    "Para ahorrar energía eléctrica en la oficina",
                    (
                        "Para evitar accesos físicos no autorizados u"
                        " 'observación por encima del hombro'"
                    ),
                    "Para reiniciar las aplicaciones lentas",
                ],
                "correct": 1,
            },
            {
                "q": (
                    "2. ¿Qué riesgo implica conectar una memoria USB de origen"
                    " desconocido a un ordenador corporativo?"
                ),
                "options": [
                    "Ninguno, los puertos USB son totalmente seguros",
                    (
                        "Infección potencial con malware, ransomware o"
                        " troyanos ocultos en el dispositivo"
                    ),
                    "Aumento inmediato de la velocidad del disco",
                ],
                "correct": 1,
            },
            {
                "q": (
                    "3. ¿Cuál es el propósito fundamental de una red VPN"
                    " corporativa al teletrabajar?"
                ),
                "options": [
                    "Navegar más rápido por páginas de entretenimiento",
                    (
                        "Establecer un túnel de cifrado seguro entre el equipo"
                        " remoto y la red interna de la empresa"
                    ),
                    "Ocultar la ubicación geográfica personal",
                ],
                "correct": 1,
            },
            {
                "q": (
                    "4. ¿Qué debe hacer si su dispositivo corporativo sufre"
                    " robo o extravío fuera de la oficina?"
                ),
                "options": [
                    "Esperar unos días por si aparece",
                    (
                        "Reportarlo de inmediato a TI para activar protocolos"
                        " de bloqueo y borrado remoto"
                    ),
                    "Comprar un repuesto personal en el mercado",
                ],
                "correct": 1,
            },
            {
                "q": (
                    "5. ¿Por qué se consideran vulnerables las redes Wi-Fi"
                    " públicas abiertas?"
                ),
                "options": [
                    "Porque la señal suele ser débil",
                    (
                        "Porque carecen de cifrado robusto y permiten la"
                        " intercepción de tráfico de red"
                    ),
                    "Porque cobran tarifas ocultas",
                ],
                "correct": 1,
            },
            {
                "q": (
                    "6. ¿Cuál es la importancia de aplicar actualizaciones de"
                    " software puntualmente?"
                ),
                "options": [
                    "Cambiar el diseño visual de los menús",
                    (
                        "Parchar vulnerabilidades de seguridad conocidas y"
                        " explotables"
                    ),
                    "Ocupar espacio de almacenamiento disponible",
                ],
                "correct": 1,
            },
            {
                "q": (
                    "7. ¿Es adecuado utilizar equipos corporativos para"
                    " actividades personales sensibles (banca personal, etc.)?"
                    ""
                ),
                "options": [
                    "Sí, está totalmente permitido y recomendado",
                    (
                        "No es aconsejable, ya que los equipos están"
                        " monitoreados por políticas de seguridad de la"
                        " empresa"
                    ),
                    "Obligatorio por normativas internas",
                ],
                "correct": 1,
            },
        ],
    },
    "Prevención de Ransomware": {
        "title": "Módulo Avanzado: Mitigación y Respuesta ante Ransomware",
        "theory": """
            <div class="training-card">
                <h4>💥 Prevención y Contención de Ataques de Ransomware</h4>
                <p>El <strong>Ransomware</strong> representa una amenaza destructiva capaz de paralizar las operaciones de una organización en minutos mediante el cifrado masivo de discos y recursos compartidos.</p>

                <hr style="margin: 10px 0; border:0; border-top:1px solid #e2e8f0;">

                <h5>1. Dinámica de Infección y Propagación</h5>
                <p>Los códigos maliciosos ingresan típicamente mediante adjuntos de correo maliciosos o vulnerabilidades perimetrales abiertas. Una vez dentro, buscan cuentas con privilegios elevados para mapear y cifrar tanto unidades locales como servidores de respaldo conectados a la red.</p>

                <h5>2. Protocolo Crítico de Respuesta (Kill Switch)</h5>
                <ul>
                    <li><strong>Desconexión Física Inmediata:</strong> Si un equipo muestra indicios de cifrado (archivos con extensiones anómalas, lentitud extrema, avisos en pantalla), desconecte el cable de red y desactive el Wi-Fi al instante.</li>
                    <li><strong>Aviso a TI:</strong> La rapidez en la contención evita que el software malicioso salte a otros equipos de la red corporativa.</li>
                    <li><strong>No Pagar Rescates:</strong> Las organizaciones internacionales de seguridad desaconsejan abonar extorsiones económicas ya que no garantizan la recuperación de los datos y financian redes delictivas.</li>
                </ul>
            </div>
            """,
        "questions": [
            {
                "q": (
                    "1. ¿Cómo opera esencialmente un ataque de Ransomware en"
                    " una red corporativa?"
                ),
                "options": [
                    "Optimiza las bases de datos de la compañía",
                    (
                        "Cifra de forma irreversible los archivos del sistema"
                        " exigiendo un rescate económico"
                    ),
                    "Elimina los virus informáticos previos",
                ],
                "correct": 1,
            },
            {
                "q": (
                    "2. ¿Cuál debe ser su reacción inmediata si detecta que"
                    " su equipo está sufriendo un ataque de cifrado?"
                ),
                "options": [
                    "Continuar trabajando con normalidad",
                    (
                        "Desconectar físicamente el equipo de la red (Ethernet y"
                        " Wi-Fi) y reportar a TI"
                    ),
                    "Reiniciar la computadora tres veces seguidas",
                ],
                "correct": 1,
            },
            {
                "q": (
                    "3. ¿Cuál es el mecanismo de defensa más sólido frente a"
                    " un incidente de Ransomware?"
                ),
                "options": [
                    "Tener respaldos (backups) frecuentes, offline e"
                    " inmutables",
                    "Apagar los equipos a las 18:00 horas",
                    "Utilizar un navegador web diferente",
                ],
                "correct": 0,
            },
            {
                "q": (
                    "4. ¿Qué recomiendan los organismos internacionales de"
                    " seguridad respecto al pago de rescates?"
                ),
                "options": [
                    "Pagar inmediatamente para recuperar los archivos",
                    (
                        "No pagar jamás, ya que fomenta el delito y no asegura"
                        " la restitución de la información"
                    ),
                    "Pagar únicamente si se realiza mediante criptomonedas"
                    " estables",
                ],
                "correct": 1,
            },
            {
                "q": (
                    "5. ¿Por qué las copias de seguridad de respaldo deben"
                    " mantenerse aisladas de la red principal?"
                ),
                "options": [
                    "Para ahorrar espacio en disco duro",
                    (
                        "Para impedir que el Ransomware alcance y destruya"
                        " también los backups"
                    ),
                    "Para que no consuman ancho de banda diario",
                ],
                "correct": 1,
            },
            {
                "q": (
                    "6. ¿Cuál suele ser el vector inicial más común de"
                    " infección por Ransomware?"
                ),
                "options": [
                    "Visitar portales de noticias oficiales",
                    (
                        "Apertura de correos de phishing con archivos adjuntos"
                        " maliciosos"
                    ),
                    "Imprimir documentos corporativos en red",
                ],
                "correct": 1,
            },
            {
                "q": (
                    "7. ¿Qué responsabilidad tiene el usuario final ante esta"
                    " amenaza?"
                ),
                "options": [
                    "Desarrollar parches de software avanzado",
                    (
                        "Actuar como filtro preventivo evitando abrir correos"
                        " o ficheros sospechosos"
                    ),
                    "Ninguna, la seguridad es invisible",
                ],
                "correct": 1,
            },
        ],
    },
}

st.markdown(
    """
    <style>
        .stApp { background-color: #f8fafc; color: #1e293b; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        [data-testid="stSidebar"] { background-color: #f0f2f6 !important; border-right: 1px solid #e2e8f0; }
        [data-testid="stSidebar"] label, [data-testid="stSidebar"] .stMarkdown, [data-testid="stSidebar"] span, [data-testid="stSidebar"] p, [data-testid="stSidebar"] h2 { color: #1e293b !important; }
        [data-testid="stSidebar"] input, [data-testid="stSidebar"] div[data-baseweb="select"] > div { background-color: #ffffff !important; color: #1e293b !important; border-color: #cbd5e1 !important; }
        .enterprise-banner { background: linear-gradient(90deg, #1e3a8a, #3b82f6); padding: 12px 20px; border-radius: 8px; color: white; text-align: center; margin-bottom: 20px; font-weight: 500; }
        .training-card { background: #ffffff; border: 1px solid #cbd5e1; border-left: 4px solid #3b82f6; padding: 20px; border-radius: 6px; margin-bottom: 20px; line-height: 1.6; }
        .employee-portal-banner { background: linear-gradient(90deg, #0f172a, #1e3a8a); padding: 20px; border-radius: 8px; color: white; text-align: center; margin-bottom: 25px; }
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


# DETECCIÓN DE PARÁMETROS EN URL (PORTAL DEL EMPLEADO CON TEMA)
query_params = st.query_params
employee_token = query_params.get("empleado")
topic_token = query_params.get("tema", "Phishing e Ingeniería Social")

if employee_token:
  st.markdown(
      """
        <div class="employee-portal-banner">
            <h2>🎓 Portal Corporativo de Concienciación en Ciberseguridad</h2>
            <p>Capacitación obligatoria y evaluación de competencias técnicas</p>
        </div>
        """,
      unsafe_allow_html=True,
  )

  selected_topic_data = TRAINING_TOPICS.get(
      topic_token, TRAINING_TOPICS["Phishing e Ingeniería Social"]
  )

  st.info(
      f"👤 Colaborador: **{employee_token}** | Campaña Asignada:"
      f" **{topic_token}**"
  )

  conn = sqlite3.connect("cyber_audits.db")
  c = conn.cursor()
  c.execute(
      "SELECT status, score FROM employees WHERE email = ? AND topic = ?",
      (employee_token, topic_token),
  )
  row = c.fetchone()
  if not row:
    try:
      c.execute(
          "INSERT INTO employees (email, department, topic, status) VALUES (?,"
          " ?, ?, ?)",
          (employee_token, "General", topic_token, "Pendiente"),
      )
      conn.commit()
    except Exception:
      pass
    current_status = "Pendiente"
    current_score = 0
  else:
    current_status, current_score = row
  conn.close()

  if current_status == "Completado":
    st.success(
        f"✅ ¡Ya has completado satisfactoriamente esta capacitación de"
        f" **{topic_token}**! Tu calificación registrada es de **{current_score}%**."
    )
  else:
    st.markdown(f"### 📚 Material Formativo Completo: {topic_token}")
    st.markdown(selected_topic_data["theory"], unsafe_allow_html=True)

    st.markdown("---")
    st.markdown(
        "### 📝 Cuestionario de Evaluación Técnica (7 Preguntas Obligatorias)"
    )

    with st.form("employee_deep_quiz_form"):
      user_answers = {}
      for idx, q_item in enumerate(selected_topic_data["questions"]):
        st.write(f"**{q_item['q']}**")
        user_choice = st.radio(
            "Seleccione una opción:",
            q_item["options"],
            key=f"q_{idx}",
            label_visibility="collapsed",
        )
        user_answers[idx] = (user_choice, q_item["correct"])
        st.markdown("")

      submit_emp_quiz = st.form_submit_button(
          "Enviar Examen y Registrar Resultados"
      )
      if submit_emp_quiz:
        score_points = 0
        total_qs = len(selected_topic_data["questions"])
        for idx, (chosen_text, correct_idx) in user_answers.items():
          correct_text = selected_topic_data["questions"][idx]["options"][
              correct_idx
          ]
          if chosen_text == correct_text:
            score_points += 1

        final_score = int((score_points / total_qs) * 100)

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        conn = sqlite3.connect("cyber_audits.db")
        conn.execute(
            "UPDATE employees SET status = 'Completado', score = ?,"
            " last_completed = ? WHERE email = ? AND topic = ?",
            (final_score, timestamp, employee_token, topic_token),
        )
        conn.commit()
        conn.close()

        st.success(
            f"🎉 ¡Examen enviado con éxito! Has obtenido una calificación de"
            f" **{final_score}%** ({score_points}/{total_qs} aciertos)."
            " Resultados sincronizados con el panel corporativo."
        )
        st.rerun()

else:
  # VISTA PRINCIPAL DEL SAAS (ADMIN Y AUDITORÍA)
  if "scanned" not in st.session_state:
    st.session_state.scanned = False
  if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

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
      " campañas de concienciación."
  )

  # BARRA LATERAL: NAVEGACIÓN Y CONTRASEÑA BLINDADA
  st.sidebar.header("🧭 Módulos de la Plataforma")

  modules_list = ["Auditoría Perimetral"]
  is_admin = False

  if st.session_state.failed_attempts >= 5:
    st.sidebar.error("⚠️ Acceso de administrador bloqueado temporalmente.")
  else:
    admin_password_input = st.sidebar.text_input(
        "🔑 Contraseña de Administrador", type="password"
    )

    MASTER_HASH = (
        "b1db078a7a989c545804a3ed56cc961d11c35885cb3848dffaff39a2ea6b468e"
    )

    if admin_password_input:
      input_hash = hashlib.sha256(admin_password_input.encode()).hexdigest()
      if input_hash == MASTER_HASH:
        is_admin = True
        st.session_state.failed_attempts = 0
      else:
        st.session_state.failed_attempts += 1
        st.sidebar.error("Contraseña incorrecta.")

  if is_admin:
    modules_list.append("🎓 Concienciación (Privado - En Desarrollo)")

  selected_module = st.sidebar.radio(
      "Seleccionar Módulo Disponible", modules_list
  )
  st.sidebar.markdown("---")

  # CONFIGURACIÓN DEL INFORME
  if selected_module == "Auditoría Perimetral":
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
            (
                "Informe de Normativa, Remediación y Recomendaciones (ISO /"
                " Compliance)"
            ),
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
  else:
    agency_name = "SecOps Global Partners"
    agency_tagline = "División de Consultoría y Ciberseguridad"
    logo_file = None
    report_type = "Informe Técnico Exhaustivo (Completo)"
    recipient_name = "Dirección General"
    report_subject = "Evaluación de Riesgos"

  st.sidebar.markdown("---")
  st.sidebar.caption("CyberAudits Enterprise v4.9 • Módulos Ampliados.")

  if is_admin and selected_module == "🎓 Concienciación (Privado - En Desarrollo)":
    st.markdown("---")
    st.markdown(
        "## 🎓 Gestión de Campañas de Concienciación y Directorio Corporativo"
    )
    st.info(
        "Asigna temas específicos, sincroniza con tu directorio corporativo o"
        " genera enlaces con parámetros personalizados."
    )

    sub_tab1, sub_tab2, sub_tab3 = st.tabs([
        "👥 Registro, AD Sync y Campañas",
        "📊 Dashboard de Resultados",
        "🔗 Generador de Enlaces de Campaña",
    ])

    with sub_tab1:
      col_add1, col_add2 = st.columns(2)
      with col_add1:
        st.markdown("### ➕ Asignar Campaña a Colaborador")
        with st.form("single_assign_form"):
          emp_mail_input = st.text_input("Correo Electrónico")
          emp_dept_input = st.selectbox(
              "Departamento",
              [
                  "Administración",
                  "Tecnología / TI",
                  "Finanzas",
                  "Ventas",
                  "Operaciones",
              ],
          )
          chosen_campaign = st.selectbox(
              "Seleccionar Tema / Campaña de Capacitación",
              list(TRAINING_TOPICS.keys()),
          )
          submit_single = st.form_submit_button(
              "Registrar y Asignar Campaña"
          )
          if submit_single and emp_mail_input:
            try:
              conn = sqlite3.connect("cyber_audits.db")
              conn.execute(
                  "INSERT INTO employees (email, department, topic) VALUES (?,"
                  " ?, ?)",
                  (emp_mail_input, emp_dept_input, chosen_campaign),
              )
              conn.commit()
              conn.close()
              st.success(
                  f"Campaña '{chosen_campaign}' asignada a {emp_mail_input}."
              )
              st.rerun()
            except Exception:
              st.error(
                  "El correo ya se encuentra registrado con esa campaña o en la"
                  " base de datos."
              )

      with col_add2:
        st.markdown("### 🔄 Sincronización Masiva (Simulador Active Directory / Azure"
                    " AD)")
        st.write(
            "Importa automáticamente el listado de colaboradores desde tu"
            " directorio corporativo en lote:"
        )
        if st.button("🌐 Sincronizar Directorio Activo (Mock AD Sync)", type="primary"):
          mock_directory = [
              ("carlos.gomez@empresa.com", "Tecnología / TI", "Phishing e Ingeniería Social"),
              ("ana.martinez@empresa.com", "Finanzas", "Gestión de Contraseñas Robustas"),
              ("lucas.pereira@empresa.com", "Ventas", "Seguridad en Dispositivos y Remoto"),
              ("sofia.benitez@empresa.com", "Operaciones", "Prevención de Ransomware"),
          ]
          conn = sqlite3.connect("cyber_audits.db")
          added_count = 0
          skipped_count = 0
          for mail, dept, top in mock_directory:
            try:
              conn.execute(
                  "INSERT INTO employees (email, department, topic) VALUES (?,"
                  " ?, ?)",
                  (mail, dept, top),
              )
              added_count += 1
            except Exception:
              skipped_count += 1
          conn.commit()
          conn.close()
          st.success(
              f"¡Sincronización AD ejecutada! Se añadieron {added_count}"
              f" nuevos colaboradores ({skipped_count} ya existían en la base"
              " de datos)."
          )
          st.rerun()

    with sub_tab2:
      st.markdown("### 📊 Panel de Control y Métricas Globales")
      emp_df = get_employees_df()
      if not emp_df.empty:
        st.dataframe(emp_df, use_container_width=True)
        if st.button("🗑️ Vaciar Base de Datos de Empleados"):
          conn = sqlite3.connect("cyber_audits.db")
          conn.execute("DELETE FROM employees")
          conn.commit()
          conn.close()
          st.rerun()
      else:
        st.info("No hay registros en el dashboard de empleados.")

    with sub_tab3:
      st.markdown("### 🔗 Enlaces Únicos Personalizados por Campaña")
      st.write(
          "Copia el enlace exacto con el parámetro `&tema=...` para enviar a"
          " cada colaborador:"
      )

      conn = sqlite3.connect("cyber_audits.db")
      c = conn.cursor()
      c.execute("SELECT email, topic FROM employees")
      records = c.fetchall()
      conn.close()

      if records:
        for mail, top in records:
          link = f"https://cyber-auditorias-2gc3l28n5gmeajtui9d9a6.streamlit.app/?empleado={mail}&tema={top}"
          st.text_input(f"{mail} -> [{top}]", value=link, key=f"url_{mail}_{top}")
      else:
        st.info("Registra colaboradores en la primera sub-pestaña para ver sus enlaces.")

  else:
    # PESTAÑAS PÚBLICAS DE AUDITORÍA PERIMETRAL
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

    with tab4:
      st.subheader("About CyberAudits Enterprise Suite")
      st.markdown("""
            **CyberAudits Enterprise Suite** es una plataforma integral orientada a consultorías de ciberseguridad corporativa.
            * **Módulos:** Auditoría perimetral y gestión del factor humano.
            * **Arquitectura:** Desarrollado bajo estándares modulares con persistencia local en SQLite.
            """)
