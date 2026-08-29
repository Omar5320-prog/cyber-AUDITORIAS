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

st.set_page_config(
    page_title="CyberAudits - Escáner Perimetral Enterprise",
    page_icon="🛡️",
    layout="wide"
)

# ========== FUNCIONES AUXILIARES PARA REMEDIACIÓN ==========
def update_ticket_status(ticket_id, new_status, note):
    """Actualiza el estado de un ticket y registra en bitácora"""
    try:
        conn = get_db_connection()
        conn.autocommit = True
        c = conn.cursor()
        is_pg = "postgres" in st.secrets
        ph = "%s" if is_pg else "?"
        
        now_ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Actualizar estado y nota
        c.execute(f"UPDATE remediation_tasks SET status = {ph}, notes = {ph} WHERE id = {ph}", 
                 (new_status, note, ticket_id))
        
        # Registrar en bitácora
        log_note = f"Estado: {new_status}. {note}" if note else f"Estado: {new_status}"
        c.execute(f"INSERT INTO remediation_logs (task_id, timestamp, status, notes) VALUES ({ph}, {ph}, {ph}, {ph})", 
                 (ticket_id, now_ts, new_status, log_note))
        
        c.close()
        conn.close()
        return True
    except Exception as e:
        st.error(f"Error al actualizar ticket {ticket_id}: {e}")
        return False

def display_ticket_logs(ticket_id):
    """Muestra la bitácora de un ticket en formato bonito"""
    try:
        conn = get_db_connection()
        is_pg = "postgres" in st.secrets
        ph = "%s" if is_pg else "?"
        
        logs_query = f"SELECT timestamp, status, notes FROM remediation_logs WHERE task_id = {ph} ORDER BY id DESC"
        logs_df = pd.read_sql_query(logs_query, conn, params=(ticket_id,))
        conn.close()
    except Exception:
        logs_df = pd.DataFrame()
        
    if not logs_df.empty:
        for _, log_row in logs_df.iterrows():
            status_emoji = "🟡" if log_row['status'] == "Pendiente" else "🔄" if log_row['status'] == "En Proceso" else "✅"
            border_color = "#f59e0b" if log_row['status'] == "Pendiente" else "#3b82f6" if log_row['status'] == "En Proceso" else "#10b981"
            st.markdown(f"""
                <div style="background:#f8fafc; padding:6px 12px; border-radius:6px; margin-bottom:4px; border-left:3px solid {border_color}; font-size:13px;">
                    <span style="font-weight:bold; color:#1e293b;">{status_emoji} {log_row['timestamp']}</span>
                    <span style="background:#e2e8f0; padding:1px 8px; border-radius:10px; font-size:11px; margin-left:8px;">{log_row['status']}</span>
                    <p style="margin:4px 0 0 0; color:#475569;">{log_row['notes']}</p>
                </div>
            """, unsafe_allow_html=True)
    else:
        st.info("📭 No hay registros en la bitácora.")

# ========== FUNCIONES DE BASE DE DATOS ==========
def get_db_connection():
    if "postgres" in st.secrets and "url" in st.secrets["postgres"]:
        conn = psycopg2.connect(st.secrets["postgres"]["url"])
        conn.autocommit = True
        return conn
    else:
        import sqlite3
        conn = sqlite3.connect("cyber_audits.db")
        return conn

def init_db():
    conn = get_db_connection()
    conn.autocommit = True
    c = conn.cursor()
    is_pg = "postgres" in st.secrets
    
    if is_pg:
        c.execute("""
            CREATE TABLE IF NOT EXISTS organizations (
                id SERIAL PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS history (
                id SERIAL PRIMARY KEY,
                timestamp TEXT,
                hostname TEXT,
                ip TEXT,
                risk_score INTEGER,
                findings_count INTEGER,
                report_type TEXT,
                organization_id INTEGER
            )
        """)
        c.execute("ALTER TABLE history ADD COLUMN IF NOT EXISTS organization_id INTEGER;")
        
        c.execute("""
            CREATE TABLE IF NOT EXISTS employees (
                id SERIAL PRIMARY KEY,
                organization_id INTEGER,
                email TEXT NOT NULL,
                department TEXT,
                topic TEXT DEFAULT 'Módulo 1 — Phishing',
                status TEXT DEFAULT 'Pendiente',
                score INTEGER DEFAULT 0,
                last_completed TEXT,
                UNIQUE(email, topic)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS remediation_tasks (
                id SERIAL PRIMARY KEY,
                organization_id INTEGER,
                scan_id INTEGER,
                hostname TEXT,
                finding_vector TEXT,
                severity TEXT DEFAULT 'MEDIO',
                status TEXT DEFAULT 'Pendiente',
                notes TEXT
            )
        """)
        c.execute("ALTER TABLE remediation_tasks ADD COLUMN IF NOT EXISTS organization_id INTEGER;")
        c.execute("ALTER TABLE remediation_tasks ADD COLUMN IF NOT EXISTS scan_id INTEGER;")
        c.execute("ALTER TABLE remediation_tasks ADD COLUMN IF NOT EXISTS severity TEXT;")
        c.execute("ALTER TABLE remediation_tasks ADD COLUMN IF NOT EXISTS notes TEXT;")
        
        c.execute("""
            CREATE TABLE IF NOT EXISTS remediation_logs (
                id SERIAL PRIMARY KEY,
                task_id INTEGER,
                timestamp TEXT,
                status TEXT,
                notes TEXT
            )
        """)
    else:
        c.execute("""
            CREATE TABLE IF NOT EXISTS organizations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                hostname TEXT,
                ip TEXT,
                risk_score INTEGER,
                findings_count INTEGER,
                report_type TEXT,
                organization_id INTEGER
            )
        """)
        try:
            c.execute("ALTER TABLE history ADD COLUMN organization_id INTEGER;")
        except Exception:
            pass

        c.execute("""
            CREATE TABLE IF NOT EXISTS employees (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id INTEGER,
                email TEXT,
                department TEXT,
                topic TEXT DEFAULT 'Módulo 1 — Phishing',
                status TEXT DEFAULT 'Pendiente',
                score INTEGER DEFAULT 0,
                last_completed TEXT,
                UNIQUE(email, topic)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS remediation_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id INTEGER,
                scan_id INTEGER,
                hostname TEXT,
                finding_vector TEXT,
                severity TEXT DEFAULT 'MEDIO',
                status TEXT DEFAULT 'Pendiente',
                notes TEXT
            )
        """)
        try:
            c.execute("ALTER TABLE remediation_tasks ADD COLUMN organization_id INTEGER;")
            c.execute("ALTER TABLE remediation_tasks ADD COLUMN scan_id INTEGER;")
            c.execute("ALTER TABLE remediation_tasks ADD COLUMN severity TEXT;")
            c.execute("ALTER TABLE remediation_tasks ADD COLUMN notes TEXT;")
        except Exception:
            pass

        c.execute("""
            CREATE TABLE IF NOT EXISTS remediation_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER,
                timestamp TEXT,
                status TEXT,
                notes TEXT
            )
        """)
        conn.commit()
    c.close()
    conn.close()

init_db()

# ========== FUNCIONES DEL ESCÁNER ==========
def send_webhook_alert(webhook_url, hostname, risk_score, findings_count):
    if not webhook_url:
        return
    try:
        payload = {
            "text": f"🚨 *CyberAudits Security Alert*\n• Objetivo: `{hostname}`\n• Risk Score: *{risk_score}/100*\n• Vulnerabilidades detectadas: *{findings_count}*"
        }
        requests.post(webhook_url, json=payload, timeout=5)
    except Exception:
        pass

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
                query = f"INSERT INTO history (timestamp, hostname, ip, risk_score, findings_count, report_type, organization_id) VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}) RETURNING id"
                c.execute(query, (timestamp, hostname, ip, risk_score, findings_count, report_type_val, organization_id))
            else:
                query = f"INSERT INTO history (timestamp, hostname, ip, risk_score, findings_count, report_type) VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}) RETURNING id"
                c.execute(query, (timestamp, hostname, ip, risk_score, findings_count, report_type_val))
            scan_id = c.fetchone()[0]
        else:
            if organization_id is not None:
                query = f"INSERT INTO history (timestamp, hostname, ip, risk_score, findings_count, report_type, organization_id) VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})"
                c.execute(query, (timestamp, hostname, ip, risk_score, findings_count, report_type_val, organization_id))
            else:
                query = f"INSERT INTO history (timestamp, hostname, ip, risk_score, findings_count, report_type) VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph})"
                c.execute(query, (timestamp, hostname, ip, risk_score, findings_count, report_type_val))
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
        st.error(f"Error detallado al guardar el escaneo en la base de datos: {e}")

def get_scan_history(org_id=None):
    conn = get_db_connection()
    is_pg = "postgres" in st.secrets
    ph = "%s" if is_pg else "?"
    
    if org_id is not None:
        query = f'SELECT timestamp AS "Fecha y Hora", hostname AS "Dominio / Host", ip AS "IP", risk_score AS "Risk Score (/100)", findings_count AS "Vulnerabilidades", report_type AS "Plantilla" FROM history WHERE organization_id = {ph} ORDER BY id DESC'
        df = pd.read_sql_query(query, conn, params=(org_id,))
    else:
        query = f'SELECT timestamp AS "Fecha y Hora", hostname AS "Dominio / Host", ip AS "IP", risk_score AS "Risk Score (/100)", findings_count AS "Vulnerabilidades", report_type AS "Plantilla" FROM history WHERE organization_id IS NULL ORDER BY id DESC'
        df = pd.read_sql_query(query, conn)
        
    conn.close()
    return df

def get_employees_df():
    conn = get_db_connection()
    df = pd.read_sql_query('SELECT email AS "Correo Electrónico", department AS "Departamento", topic AS "Campaña / Tema", status AS "Estado", score AS "Calificación (%)", last_completed AS "Última Evaluación" FROM employees', conn)
    conn.close()
    return df

# ========== CONTENIDO DE ENTRENAMIENTO ==========
TRAINING_TOPICS = {
    "Módulo 1 — Phishing": {
        "title": "Módulo 1 — Phishing y Detección de Fraudes",
        "theory": """
### 🎣 ¿Qué es el Phishing?
El **phishing** es una técnica utilizada para engañar a las personas y obtener información confidencial. No es un programa para proteger el ordenador ni un sistema para mejorar la velocidad de Internet.

#### 1. Señales de Alerta y Urgencia
* **Situaciones sospechosas:** Un mensaje que nos pide actuar inmediatamente y amenaza con bloquear nuestra cuenta es una señal clara de phishing.
* **Uso de la urgencia:** Los ciberdelincuentes suelen utilizar mensajes que generan urgencia para conseguir que la persona actúe rápidamente sin comprobar la información, impidiendo que analice el mensaje con calma.

#### 2. Cómo Actuar ante Correos y Enlaces Sospechosos
* **Correos bancarios:** Si recibes un correo que aparentemente procede de tu banco y contiene un enlace para "verificar tu cuenta", **nunca** hagas clic inmediatamente. Debes comprobar la información utilizando la aplicación o página oficial del banco.
* **Información crítica:** **Nunca** debemos proporcionar información sensible como nuestra contraseña o códigos de seguridad mediante un enlace sospechoso.
* **Archivos adjuntos:** Si recibes un archivo adjunto que no esperabas, no lo abras inmediatamente ni lo envíes a otros compañeros; debes comprobar primero si el mensaje y el remitente son legítimos.
* **Errores y falsas páginas:** Si accidentalmente introducimos nuestra contraseña en una página que creemos que era falsa, no te quedes sin hacer nada: debes cambiar la contraseña inmediatamente desde la página oficial e informar del incidente si corresponde.
* **Ámbito laboral:** Si recibes un correo sospechoso en tu trabajo, no lo reenvíes a todos ni hagas clic en los enlaces; debes informarlo siguiendo el procedimiento establecido por la organización.
        """,
        "questions": [
            {"q": "1. ¿Qué es el phishing?", "options": ["Un programa utilizado para proteger el ordenador.", "Una técnica utilizada para engañar a las personas y obtener información.", "Un sistema para mejorar la velocidad de Internet."], "correct": 1},
            {"q": "2. ¿Cuál de estas situaciones puede ser una señal de phishing?", "options": ["Un mensaje que nos pide actuar inmediatamente y amenaza con bloquear nuestra cuenta.", "Un mensaje que recibimos de un compañero y que estábamos esperando.", "Una notificación habitual de una aplicación que utilizamos."], "correct": 0},
            {"q": "3. Recibes un correo que aparentemente procede de tu banco y contiene un enlace para 'verificar tu cuenta'. ¿Qué deberías hacer?", "options": ["Hacer clic inmediatamente para evitar que bloqueen la cuenta.", "Comprobar la información utilizando la aplicación o página oficial del banco.", "Responder al correo solicitando más información."], "correct": 1},
            {"q": "4. ¿Qué información nunca debemos proporcionar mediante un enlace sospechoso?", "options": ["Nuestra contraseña o códigos de seguridad.", "El nombre de nuestra ciudad.", "El idioma que utilizamos."], "correct": 0},
            {"q": "5. ¿Por qué los ciberdelincuentes suelen utilizar mensajes que generan urgencia?", "options": ["Para que la persona tenga más tiempo para analizar el mensaje.", "Para conseguir que la persona actúe rápidamente sin comprobar la información.", "Para mejorar la seguridad del usuario."], "correct": 1},
            {"q": "6. Recibes un archivo adjunto que no esperabas. ¿Qué deberías hacer?", "options": ["Abrirlo inmediatamente para saber qué contiene.", "Descargarlo y enviarlo a otros compañeros.", "Comprobar primero si el mensaje y el remitente son legítimos."], "correct": 2},
            {"q": "7. ¿Qué debemos hacer si accidentalmente introducimos nuestra contraseña en una página que creemos que era falsa?", "options": ["No hacer nada y esperar a ver qué ocurre.", "Cambiar la contraseña desde la página oficial e informar del incidente si corresponde.", "Compartir la contraseña con un compañero para pedirle ayuda."], "correct": 1},
            {"q": "8. ¿Qué debemos hacer si recibimos un correo sospechoso en nuestro trabajo?", "options": ["Reenviarlo a todos los compañeros para preguntar si es real.", "Hacer clic en el enlace para comprobarlo.", "Informarlo siguiendo el procedimiento establecido por la organización."], "correct": 2}
        ]
    },
    "Módulo 2 — Contraseñas seguras": {
        "title": "Módulo 2 — Contraseñas Seguras y MFA",
        "theory": """
### 🔑 Gestión de Contraseñas y Autenticación
Una contraseña segura se caracteriza por ser larga y difícil de adivinar, evitando opciones débiles como '123456' o utilizar nuestro nombre seguido de un número sencillo.

#### 1. Buenas Prácticas y Errores a Evitar
* **Información personal:** Al crear una contraseña debemos evitar utilizar información personal fácil de conocer (como nombres o fechas obvias).
* **Reutilización:** No debemos utilizar la misma contraseña para todas nuestras cuentas. Si una contraseña queda expuesta, otras cuentas podrían quedar en riesgo ante los atacantes.
* **Dónde guardarlas:** Nunca debemos guardar nuestras contraseñas en un papel pegado al monitor del ordenador; lo adecuado es utilizar un gestor de contraseñas confiable o sistemas autorizados por la organización.

#### 2. Autenticación Multifactor (MFA)
* **¿Qué es?:** Es una medida de seguridad que solicita una comprobación adicional además de la contraseña (no elimina la necesidad de claves ni acelera la lentitud). Siempre debemos activarla en servicios importantes para añadir una capa adicional de protección.
* **Códigos inesperados:** Si recibes un código de verificación en tu teléfono que no has solicitado, no debes compartirlo con nadie ni publicarlo; debes no compartirlo con nadie y revisar si existe alguna actividad sospechosa.
        """,
        "questions": [
            {"q": "1. ¿Cuál es una característica de una contraseña segura?", "options": ["Es larga y difícil de adivinar.", "Es nuestro nombre seguido de 123.", "Es la misma que utilizamos en todas nuestras cuentas."], "correct": 0},
            {"q": "2. ¿Cuál de las siguientes contraseñas es menos segura?", "options": ["Una frase larga y difícil de adivinar.", "Una combinación de palabras y caracteres.", "123456."], "correct": 2},
            {"q": "3. ¿Por qué no debemos utilizar la misma contraseña para todas nuestras cuentas?", "options": ["Porque si una contraseña queda expuesta, otras cuentas podrían quedar en riesgo.", "Porque las contraseñas solamente funcionan una vez.", "Porque utilizar varias contraseñas hace que Internet sea más lento."], "correct": 0},
            {"q": "4. ¿Cuál de estas opciones debemos evitar al crear una contraseña?", "options": ["Utilizar información personal fácil de conocer.", "Utilizar una contraseña larga.", "Utilizar una contraseña diferente para cada cuenta."], "correct": 0},
            {"q": "5. ¿Qué es la autenticación multifactor o MFA?", "options": ["Un sistema que elimina la necesidad de utilizar contraseñas.", "Una medida de seguridad que solicita una comprobación adicional además de la contraseña.", "Un programa para aumentar la velocidad del ordenador."], "correct": 1},
            {"q": "6. Recibes un código de verificación en tu teléfono que no has solicitado. ¿Qué deberías hacer?", "options": ["Compartirlo con la persona que te lo solicite por teléfono.", "Publicarlo para preguntar qué significa.", "No compartirlo con nadie y revisar si existe alguna actividad sospechosa."], "correct": 2},
            {"q": "7. ¿Dónde debemos evitar guardar nuestras contraseñas?", "options": ["En un gestor de contraseñas confiable.", "En un papel pegado al monitor del ordenador.", "En un sistema autorizado por la organización."], "correct": 1},
            {"q": "8. ¿Qué debemos hacer cuando un servicio importante permite activar MFA?", "options": ["Activarlo para añadir una capa adicional de seguridad.", "Desactivarlo porque hace más lenta la conexión.", "Compartir el código MFA con nuestros compañeros."], "correct": 0}
        ]
    },
    "Módulo 3 — Seguridad en el puesto de trabajo": {
        "title": "Módulo 3 — Seguridad Física y en el Puesto de Trabajo",
        "theory": """
### 🏢 Seguridad en el Entorno Laboral
La protección de los equipos y la información no solo depende del software, sino de los hábitos diarios en el puesto de trabajo.

#### 1. Bloqueo y Dispositivos Físicos
* **Bloqueo de pantalla:** Cuando nos alejamos de nuestro ordenador, debemos bloquear siempre la pantalla (nunca dejarla abierta ni escribir la contraseña en el escritorio). Una combinación rápida para lograrlo en Windows es presionando `Windows + L`.
* **Dispositivos USB desconocidos:** Si encuentras una memoria USB desconocida en las instalaciones de la empresa, debes entregarla al responsable correspondiente sin conectarla, ya que estos dispositivos pueden contener archivos o programas maliciosos que ponen en riesgo la red.

#### 2. Manejo de Información y Movilidad
* **Documentos confidenciales:** Debemos proteger los documentos que contienen información confidencial y evitar que personas no autorizadas puedan acceder a ellos (nunca dejarlos sobre el escritorio a la vista).
* **Archivos inesperados de compañeros:** Si recibes un archivo de un compañero que no esperabas, debes comprobar primero que realmente lo haya enviado y que el archivo sea esperado antes de abrirlo.
* **Buenas prácticas generales:** Mantener los equipos actualizados y seguir rigurosamente las políticas de seguridad de la organización es una excelente práctica.
* **Trabajo fuera de la oficina:** Debemos cuidar nuestros dispositivos cuando trabajamos fuera de la empresa porque pueden contener información de la organización y corren el riesgo de perderse o ser robados.
        """,
        "questions": [
            {"q": "1. ¿Qué debemos hacer cuando nos alejamos de nuestro ordenador?", "options": ["Dejar la pantalla abierta.", "Bloquear la pantalla.", "Escribir nuestra contraseña en el escritorio."], "correct": 1},
            {"q": "2. ¿Qué combinación de teclas permite bloquear rápidamente un ordenador con Windows?", "options": ["Windows + L.", "Ctrl + C.", "Alt + F4."], "correct": 0},
            {"q": "3. Encuentras una memoria USB desconocida en las instalaciones de la empresa. ¿Qué deberías hacer?", "options": ["Conectarla al ordenador para descubrir quién es su propietario.", "Llevarla a casa para comprobar su contenido.", "Entregarla al responsable correspondiente sin conectarla."], "correct": 2},
            {"q": "4. ¿Por qué debemos tener cuidado con los dispositivos USB desconocidos?", "options": ["Porque pueden contener archivos o programas maliciosos.", "Porque siempre están vacíos.", "Porque pueden aumentar la velocidad del ordenador."], "correct": 0},
            {"q": "5. ¿Qué debemos hacer con documentos que contienen información confidencial?", "options": ["Dejarlos sobre el escritorio para tenerlos disponibles.", "Protegerlos y evitar que personas no autorizadas puedan acceder a ellos.", "Fotografiar los documentos y enviarlos a nuestro teléfono personal."], "correct": 1},
            {"q": "6. Recibes un archivo de un compañero que no esperabas. ¿Qué deberías hacer?", "options": ["Abrirlo inmediatamente porque procede de un compañero.", "Comprobar primero que realmente lo haya enviado y que el archivo sea esperado.", "Reenviarlo a otras personas."], "correct": 1},
            {"q": "7. ¿Cuál de estas acciones representa una buena práctica de seguridad?", "options": ["Instalar cualquier programa que encontremos en Internet.", "Compartir nuestra sesión con otros compañeros.", "Mantener los equipos actualizados y seguir las políticas de seguridad."], "correct": 2},
            {"q": "8. ¿Por qué también debemos cuidar nuestros dispositivos cuando trabajamos fuera de la oficina?", "options": ["Porque pueden contener información de la organización y podrían perderse o ser robados.", "Porque fuera de la oficina los ordenadores funcionan más lentamente.", "Porque todos los dispositivos dejan de funcionar fuera."], "correct": 0}
        ]
    },
    "Módulo 4 — Vishing y Smishing": {
        "title": "Módulo 4 — Llamadas y Mensajes Falsos (Vishing y Smishing)",
        "theory": """
### ☎️ Fraudes a través de Llamadas y Mensajes
Los atacantes no solo utilizan correos electrónicos, sino también canales directos de comunicación móvil.

#### 1. Conceptos Clave
* **Vishing:** Es una estafa realizada mediante llamadas telefónicas para engañar a las personas y obtener información sensible.
* **Smishing:** Es una estafa que utiliza principalmente SMS o mensajes de texto para engañar a las víctimas.

#### 2. Cómo Detectar y Protegerse
* **Llamadas sospechosas y códigos:** Si una persona te llama diciendo que trabaja para tu banco y te solicita un código que acabas de recibir por SMS, **no debes compartir el código** bajo ningún concepto; debes verificar la situación mediante un canal oficial. Una señal frecuente de llamada fraudulenta es que el interlocutor intenta presionarnos para que actuemos inmediatamente.
* **SMS con enlaces de paquetes:** Si recibes un SMS indicando que tienes un paquete pendiente y contiene un enlace, nunca hagas clic inmediatamente ni introduzcas datos bancarios; debes comprobar el envío directamente desde la página o aplicación oficial de la empresa.
* **Familiares pidiendo dinero:** Si un supuesto familiar te escribe desde un número desconocido pidiendo dinero urgentemente, evita enviar dinero o dar datos; debes comprobar por otro medio alternativo que realmente sea esa persona.
* **Información a evitar:** Durante una llamada sospechosa jamás debemos proporcionar contraseñas, códigos de seguridad o datos bancarios.
* **Acción recomendada:** Si una llamada o mensaje te parece sospechoso, finaliza la llamada inmediatamente y contacta con la empresa o entidad mediante un número oficial verificado.
        """,
        "questions": [
            {"q": "1. ¿Qué es el vishing?", "options": ["Una estafa realizada mediante llamadas telefónicas para engañar a las personas.", "Un programa antivirus.", "Un sistema para proteger las contraseñas."], "correct": 0},
            {"q": "2. ¿Qué es el smishing?", "options": ["Un tipo de copia de seguridad.", "Una estafa que utiliza principalmente SMS o mensajes para engañar a las personas.", "Un método para mejorar la conexión Wi-Fi."], "correct": 1},
            {"q": "3. Una persona te llama diciendo que trabaja para tu banco y te solicita un código que acabas de recibir por SMS. ¿Qué debes hacer?", "options": ["Proporcionarle el código para solucionar el problema.", "Proporcionarle solamente los primeros números.", "No compartir el código y verificar la situación mediante un canal oficial."], "correct": 2},
            {"q": "4. ¿Cuál es una señal frecuente de una llamada fraudulenta?", "options": ["La persona intenta presionarnos para que actuemos inmediatamente.", "La persona nos permite comprobar tranquilamente toda la información.", "La llamada no solicita ningún tipo de información."], "correct": 0},
            {"q": "5. Recibes un SMS indicando que tienes un paquete pendiente y contiene un enlace. ¿Qué deberías hacer?", "options": ["Hacer clic inmediatamente.", "Comprobar el envío directamente desde la página o aplicación oficial de la empresa.", "Introducir los datos de tu tarjeta para solucionar el problema."], "correct": 1},
            {"q": "6. Una persona que dice ser un familiar te escribe desde un número desconocido y te pide dinero urgentemente. ¿Qué deberías hacer?", "options": ["Enviar el dinero inmediatamente.", "Pedirle su contraseña.", "Comprobar por otro medio que realmente sea esa persona."], "correct": 2},
            {"q": "7. ¿Qué información debemos evitar proporcionar durante una llamada sospechosa?", "options": ["Nuestra contraseña, códigos de seguridad o datos bancarios.", "El nombre de la empresa donde trabajamos, si es información pública.", "La hora actual."], "correct": 0},
            {"q": "8. ¿Qué debemos hacer si una llamada nos parece sospechosa?", "options": ["Continuar hablando para descubrir qué quiere el atacante.", "Finalizar la llamada y contactar con la empresa mediante un número oficial.", "Dar información falsa para intentar engañar al atacante."], "correct": 1}
        ]
    }
}

# ========== ESTILOS CSS MEJORADOS ==========
st.markdown("""
    <style>
        .stApp { background-color: #f8fafc; color: #1e293b; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        [data-testid="stSidebar"] { background-color: #f0f2f6 !important; border-right: 1px solid #e2e8f0; }
        [data-testid="stSidebar"] label, [data-testid="stSidebar"] .stMarkdown, [data-testid="stSidebar"] span, [data-testid="stSidebar"] p, [data-testid="stSidebar"] h2 { color: #1e293b !important; }
        [data-testid="stSidebar"] input, [data-testid="stSidebar"] div[data-baseweb="select"] > div { background-color: #ffffff !important; color: #1e293b !important; border-color: #cbd5e1 !important; }
        .enterprise-banner { background: linear-gradient(90deg, #1e3a8a, #3b82f6); padding: 12px 20px; border-radius: 8px; color: white; text-align: center; margin-bottom: 20px; font-weight: 500; }
        .training-card { background: #ffffff; border: 1px solid #cbd5e1; border-left: 4px solid #3b82f6; padding: 20px; border-radius: 6px; margin-bottom: 20px; line-height: 1.6; }
        .employee-portal-banner { background: linear-gradient(90deg, #0f172a, #1e3a8a); padding: 20px; border-radius: 8px; color: white; text-align: center; margin-bottom: 25px; }
        .ticket-card { background: white; border: 1px solid #cbd5e1; border-radius: 8px; padding: 16px; margin-bottom: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
        
        /* Mejoras para la ticketera */
        .ticket-card {
            background: white;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 16px 18px;
            margin-bottom: 14px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.04);
            transition: all 0.2s ease;
        }
        .ticket-card:hover {
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
            transform: translateY(-1px);
        }
        .ticket-card h3 {
            margin-top: 0;
            font-size: 15px;
        }
        .ticket-card code {
            background: #f1f5f9;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 12px;
        }
        .sev-critical { border-left: 5px solid #dc2626 !important; }
        .sev-medium { border-left: 5px solid #f59e0b !important; }
        .sev-low { border-left: 5px solid #3b82f6 !important; }
        
        /* Mejoras para métricas */
        [data-testid="stMetricValue"] {
            font-size: 24px !important;
            font-weight: 700 !important;
        }
        [data-testid="stMetricDelta"] {
            font-weight: 600 !important;
        }
        
        /* Estilo para botones de actualización */
        .stButton button {
            border-radius: 8px !important;
            font-weight: 500 !important;
            transition: all 0.2s ease;
        }
        .stButton button:hover {
            transform: scale(1.02);
        }
    </style>
""", unsafe_allow_html=True)

# ========== FUNCIONES DEL ESCÁNER (GEOLOCALIZACIÓN, SSL, ETC.) ==========
def get_geolocation(hostname):
    geo_data = {"ip": "N/A", "
