import base64
import csv
import datetime
import hashlib
import io
import json
import os
import re
import socket
import ssl
from urllib.parse import urlparse
from docx import Document
from docx.shared import Inches, Pt, RGBColor
import matplotlib.pyplot as plt
import pandas as pd
import psycopg2
import requests
from weasyprint import HTML
import streamlit as st

st.set_page_config(
    page_title="CyberAudits - Escáner Perimetral Enterprise",
    page_icon="🛡️",
    layout="wide",
)


def get_db_connection():
  if "postgres" in st.secrets and "url" in st.secrets["postgres"]:
    return psycopg2.connect(st.secrets["postgres"]["url"])
  else:
    import sqlite3

    return sqlite3.connect("cyber_audits.db")


def init_db():
  try:
    conn = get_db_connection()
    conn.autocommit = True
    c = conn.cursor()
    is_pg = "postgres" in st.secrets

    if is_pg:
      try:
        c.execute("""
                CREATE TABLE IF NOT EXISTS organizations (
                    id SERIAL PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
      except Exception:
        pass

      try:
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
      except Exception:
        pass

      try:
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
      except Exception:
        pass

      try:
        c.execute("""
                CREATE TABLE IF NOT EXISTS remediation_tasks (
                    id SERIAL PRIMARY KEY,
                    organization_id INTEGER,
                    scan_id INTEGER,
                    hostname TEXT,
                    finding_vector TEXT,
                    status TEXT DEFAULT 'Pendiente',
                    notes TEXT
                )
            """)
      except Exception:
        pass

      try:
        c.execute("""
                CREATE TABLE IF NOT EXISTS remediation_logs (
                    id SERIAL PRIMARY KEY,
                    task_id INTEGER,
                    timestamp TEXT,
                    status TEXT,
                    notes TEXT
                )
            """)
      except Exception:
        pass
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
                status TEXT DEFAULT 'Pendiente',
                notes TEXT
            )
        """)
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
  except Exception:
    pass


init_db()


def send_webhook_alert(webhook_url, hostname, risk_score, findings_count):
  if not webhook_url:
    return
  try:
    payload = {
        "text": (
            f"🚨 *CyberAudits Security Alert*\n• Objetivo: `{hostname}`\n• Risk"
            f" Score: *{risk_score}/100*\n• Vulnerabilidades detectadas:"
            f" *{findings_count}*"
        )
    }
    requests.post(webhook_url, json=payload, timeout=5)
  except Exception:
    pass


def save_scan_to_db(
    hostname,
    ip,
    risk_score,
    findings_count,
    report_type_val,
    organization_id=None,
    findings=None,
):
  try:
    conn = get_db_connection()
    c = conn.cursor()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    is_pg = "postgres" in st.secrets
    ph = "%s" if is_pg else "?"

    if is_pg:
      if organization_id is not None:
        query = f"INSERT INTO history (timestamp, hostname, ip, risk_score, findings_count, report_type, organization_id) VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}) RETURNING id"
        c.execute(
            query,
            (
                timestamp,
                hostname,
                ip,
                risk_score,
                findings_count,
                report_type_val,
                organization_id,
            ),
        )
      else:
        query = f"INSERT INTO history (timestamp, hostname, ip, risk_score, findings_count, report_type) VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}) RETURNING id"
        c.execute(
            query,
            (
                timestamp,
                hostname,
                ip,
                risk_score,
                findings_count,
                report_type_val,
            ),
        )
      scan_id = c.fetchone()[0]
    else:
      if organization_id is not None:
        query = f"INSERT INTO history (timestamp, hostname, ip, risk_score, findings_count, report_type, organization_id) VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})"
        c.execute(
            query,
            (
                timestamp,
                hostname,
                ip,
                risk_score,
                findings_count,
                report_type_val,
                organization_id,
            ),
        )
      else:
        query = f"INSERT INTO history (timestamp, hostname, ip, risk_score, findings_count, report_type) VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph})"
        c.execute(
            query,
            (
                timestamp,
                hostname,
                ip,
                risk_score,
                findings_count,
                report_type_val,
            ),
        )
      scan_id = c.lastrowid

    if findings:
      for f in findings:
        vec = f["vector"]
        if organization_id is not None:
          c.execute(
              f"INSERT INTO remediation_tasks (organization_id, scan_id,"
              f" hostname, finding_vector, status) VALUES ({ph}, {ph}, {ph},"
              f" {ph}, 'Pendiente')",
              (organization_id, scan_id, hostname, vec),
          )
        else:
          c.execute(
              f"INSERT INTO remediation_tasks (organization_id, scan_id,"
              f" hostname, finding_vector, status) VALUES (NULL, {ph}, {ph},"
              f" {ph}, 'Pendiente')",
              (scan_id, hostname, vec),
          )

    conn.commit()
    c.close()
    conn.close()
  except Exception:
    pass


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
  df = pd.read_sql_query(
      'SELECT email AS "Correo Electrónico", department AS "Departamento",'
      ' topic AS "Campaña / Tema", status AS "Estado", score AS'
      ' "Calificación (%)", last_completed AS "Última Evaluación" FROM'
      " employees",
      conn,
  )
  conn.close()
  return df


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
            {
                "q": "1. ¿Qué es el phishing?",
                "options": [
                    "Un programa utilizado para proteger el ordenador.",
                    (
                        "Una técnica utilizada para engañar a las personas y"
                        " obtener información."
                    ),
                    "Un sistema para mejorar la velocidad de Internet.",
                ],
                "correct": 1,
            },
            {
                "q": (
                    "2. ¿Cuál de estas situaciones puede ser una señal de"
                    " phishing?"
                ),
                "options": [
                    (
                        "Un mensaje que nos pide actuar inmediatamente y"
                        " amenaza con bloquear nuestra cuenta."
                    ),
                    (
                        "Un mensaje que recibimos de un compañero y que"
                        " estábamos esperando."
                    ),
                    (
                        "Una notificación habitual de una aplicación que"
                        " utilizamos."
                    ),
                ],
                "correct": 0,
            },
            {
                "q": (
                    "3. Recibes un correo que aparentemente procede de tu"
                    " banco y contiene un enlace para 'verificar tu cuenta'."
                    " ¿Qué deberías hacer?"
                ),
                "options": [
                    (
                        "Hacer clic inmediatamente para evitar que bloqueen la"
                        " cuenta."
                    ),
                    (
                        "Comprobar la información utilizando la aplicación o"
                        " página oficial del banco."
                    ),
                    "Responder al correo solicitando más información.",
                ],
                "correct": 1,
            },
            {
                "q": (
                    "4. ¿Qué información nunca debemos proporcionar mediante"
                    " un enlace sospechoso?"
                ),
                "options": [
                    "Nuestra contraseña o códigos de seguridad.",
                    "El nombre de nuestra ciudad.",
                    "El idioma que utilizamos.",
                ],
                "correct": 0,
            },
            {
                "q": (
                    "5. ¿Por qué los ciberdelincuentes suelen utilizar mensajes"
                    " que generan urgencia?"
                ),
                "options": [
                    (
                        "Para que la persona tenga más tiempo para analizar el"
                        " mensaje."
                    ),
                    (
                        "Para conseguir que la persona actúe rápidamente sin"
                        " comprobar la información."
                    ),
                    "Para mejorar la seguridad del usuario.",
                ],
                "correct": 1,
            },
            {
                "q": (
                    "6. Recibes un archivo adjunto que no esperabas. ¿Qué"
                    " deberías hacer?"
                ),
                "options": [
                    "Abrirlo inmediatamente para saber qué contiene.",
                    "Descargarlo y enviarlo a otros compañeros.",
                    (
                        "Comprobar primero si el mensaje y el remitente son"
                        " legítimos."
                    ),
                ],
                "correct": 2,
            },
            {
                "q": (
                    "7. ¿Qué debemos hacer si accidentalmente introducimos"
                    " nuestra contraseña en una página que creemos que era"
                    " falsa?"
                ),
                "options": [
                    "No hacer nada y esperar a ver qué ocurre.",
                    (
                        "Cambiar la contraseña desde la página oficial e"
                        " informar del incidente si corresponde."
                    ),
                    (
                        "Compartir la contraseña con un compañero para pedirle"
                        " ayuda."
                    ),
                ],
                "correct": 1,
            },
            {
                "q": (
                    "8. ¿Qué debemos hacer si recibimos un correo sospechoso"
                    " en nuestro trabajo?"
                ),
                "options": [
                    (
                        "Reenviarlo a todos los compañeros para preguntar si es"
                        " real."
                    ),
                    "Hacer clic en el enlace para comprobarlo.",
                    (
                        "Informarlo siguiendo el procedimiento establecido por"
                        " la organización."
                    ),
                ],
                "correct": 2,
            },
        ],
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
            {
                "q": (
                    "1. ¿Cuál es una característica de una contraseña segura?"
                ),
                "options": [
                    "Es larga y difícil de adivinar.",
                    "Es nuestro nombre seguido de 123.",
                    "Es la misma que utilizamos en todas nuestras cuentas.",
                ],
                "correct": 0,
            },
            {
                "q": (
                    "2. ¿Cuál de las siguientes contraseñas es menos segura?"
                ),
                "options": [
                    "Una frase larga y difícil de adivinar.",
                    "Una combinación de palabras y caracteres.",
                    "123456.",
                ],
                "correct": 2,
            },
            {
                "q": (
                    "3. ¿Por qué no debemos utilizar la misma contraseña para"
                    " todas nuestras cuentas?"
                ),
                "options": [
                    (
                        "Porque si una contraseña queda expuesta, otras cuentas"
                        " podrían quedar en riesgo."
                    ),
                    "Porque las contraseñas solamente funcionan una vez.",
                    (
                        "Porque utilizar varias contraseñas hace que Internet"
                        " sea más lento."
                    ),
                ],
                "correct": 0,
            },
            {
                "q": (
                    "4. ¿Cuál de estas opciones debemos evitar al crear una"
                    " contraseña?"
                ),
                "options": [
                    "Utilizar información personal fácil de conocer.",
                    "Utilizar una contraseña larga.",
                    "Utilizar una contraseña diferente para cada cuenta.",
                ],
                "correct": 0,
            },
            {
                "q": (
                    "5. ¿Qué es la autenticación multifactor o MFA?"
                ),
                "options": [
                    "Un sistema que elimina la necesidad de utilizar contraseñas.",
                    (
                        "Una medida de seguridad que solicita una comprobación"
                        " adicional además de la contraseña."
                    ),
                    "Un programa para aumentar la velocidad del ordenador.",
                ],
                "correct": 1,
            },
            {
                "q": (
                    "6. Recibes un código de verificación en tu teléfono que"
                    " no has solicitado. ¿Qué deberías hacer?"
                ),
                "options": [
                    "Compartirlo con la persona que te lo solicite por teléfono.",
                    "Publicarlo para preguntar qué significa.",
                    (
                        "No compartirlo con nadie y revisar si existe alguna"
                        " actividad sospechosa."
                    ),
                ],
                "correct": 2,
            },
            {
                "q": (
                    "7. ¿Dónde debemos evitar guardar nuestras contraseñas?"
                ),
                "options": [
                    "En un gestor de contraseñas confiable.",
                    "En un papel pegado al monitor del ordenador.",
                    "En un sistema autorizado por la organización.",
                ],
                "correct": 1,
            },
            {
                "q": (
                    "8. ¿Qué debemos hacer cuando un servicio importante"
                    " permite activar MFA?"
                ),
                "options": [
                    "Activarlo para añadir una capa adicional de seguridad.",
                    "Desactivarlo porque hace más lenta la conexión.",
                    "Compartir el código MFA con nuestros compañeros.",
                ],
                "correct": 0,
            },
        ],
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
            {
                "q": (
                    "1. ¿Qué debemos hacer cuando nos alejamos de nuestro"
                    " ordenador?"
                ),
                "options": [
                    "Dejar la pantalla abierta.",
                    "Bloquear la pantalla.",
                    "Escribir nuestra contraseña en el escritorio.",
                ],
                "correct": 1,
            },
            {
                "q": (
                    "2. ¿Qué combinación de teclas permite bloquear"
                    " rápidamente un ordenador con Windows?"
                ),
                "options": [
                    "Windows + L.",
                    "Ctrl + C.",
                    "Alt + F4.",
                ],
                "correct": 0,
            },
            {
                "q": (
                    "3. Encuentras una memoria USB desconocida en las"
                    " instalaciones de la empresa. ¿Qué deberías hacer?"
                ),
                "options": [
                    (
                        "Conectarla al ordenador para descubrir quién es su"
                        " propietario."
                    ),
                    "Llevarla a casa para comprobar su contenido.",
                    "Entregarla al responsable correspondiente sin conectarla.",
                ],
                "correct": 2,
            },
            {
                "q": (
                    "4. ¿Por qué debemos tener cuidado con los dispositivos"
                    " USB desconocidos?"
                ),
                "options": [
                    "Porque pueden contener archivos o programas maliciosos.",
                    "Porque siempre están vacíos.",
                    "Porque pueden aumentar la velocidad del ordenador.",
                ],
                "correct": 0,
            },
            {
                "q": (
                    "5. ¿Qué debemos hacer con documentos que contienen"
                    " información confidencial?"
                ),
                "options": [
                    "Dejarlos sobre el escritorio para tenerlos disponibles.",
                    (
                        "Protegerlos y evitar que personas no autorizadas"
                        " puedan acceder a ellos."
                    ),
                    (
                        "Fotografiar los documentos y enviarlos a nuestro"
                        " teléfono personal."
                    ),
                ],
                "correct": 1,
            },
            {
                "q": (
                    "6. Recibes un archivo de un compañero que no esperabas."
                    " ¿Qué deberías hacer?"
                ),
                "options": [
                    (
                        "Abrirlo inmediatamente porque procede de un compañero."
                    ),
                    (
                        "Comprobar primero que realmente lo haya enviado y que"
                        " el archivo sea esperado."
                    ),
                    "Reenviarlo a otras personas.",
                ],
                "correct": 1,
            },
            {
                "q": (
                    "7. ¿Cuál de estas acciones representa una buena práctica"
                    " de seguridad?"
                ),
                "options": [
                    "Instalar cualquier programa que encontremos en Internet.",
                    "Compartir nuestra sesión con otros compañeros.",
                    (
                        "Mantener los equipos actualizados y seguir las"
                        " políticas de seguridad."
                    ),
                ],
                "correct": 2,
            },
            {
                "q": (
                    "8. ¿Por qué también debemos cuidar nuestros dispositivos"
                    " cuando trabajamos fuera de la oficina?"
                ),
                "options": [
                    (
                        "Porque pueden contener información de la"
                        " organización y podrían perderse o ser robados."
                    ),
                    (
                        "Porque fuera de la oficina los ordenadores funcionan"
                        " más lentamente."
                    ),
                    "Porque todos los dispositivos dejan de funcionar fuera.",
                ],
                "correct": 0,
            },
        ],
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
            {
                "q": "1. ¿Qué es el vishing?",
                "options": [
                    (
                        "Una estafa realizada mediante llamadas telefónicas para"
                        " engañar a las personas."
                    ),
                    "Un programa antivirus.",
                    "Un sistema para proteger las contraseñas.",
                ],
                "correct": 0,
            },
            {
                "q": "2. ¿Qué es el smishing?",
                "options": [
                    "Un tipo de copia de seguridad.",
                    (
                        "Una estafa que utiliza principalmente SMS o mensajes"
                        " para engañar a las personas."
                    ),
                    "Un método para mejorar la conexión Wi-Fi.",
                ],
                "correct": 1,
            },
            {
                "q": (
                    "3. Una persona te llama diciendo que trabaja para tu banco"
                    " y te solicita un código que acabas de recibir por SMS."
                    " ¿Qué debes hacer?"
                ),
                "options": [
                    "Proporcionarle el código para solucionar el problema.",
                    "Proporcionarle solamente los primeros números.",
                    (
                        "No compartir el código y verificar la situación"
                        " mediante un canal oficial."
                    ),
                ],
                "correct": 2,
            },
            {
                "q": (
                    "4. ¿Cuál es una señal frecuente de una llamada"
                    " fraudulenta?"
                ),
                "options": [
                    (
                        "La persona intenta presionarnos para que actuemos"
                        " inmediatamente."
                    ),
                    (
                        "La persona nos permite comprobar tranquilamente toda"
                        " la información."
                    ),
                    "La llamada no solicita ningún tipo de información.",
                ],
                "correct": 0,
            },
            {
                "q": (
                    "5. Recibes un SMS indicando que tienes un paquete"
                    " pendiente y contiene un enlace. ¿Qué deberías hacer?"
                ),
                "options": [
                    "Hacer clic inmediatamente.",
                    (
                        "Comprobar el envío directamente desde la página o"
                        " aplicación oficial de la empresa."
                    ),
                    (
                        "Introducir los datos de tu tarjeta para solucionar el"
                        " problema."
                    ),
                ],
                "correct": 1,
            },
            {
                "q": (
                    "6. Una persona que dice ser un familiar te escribe desde"
                    " un número desconocido y te pide dinero urgentemente. ¿Qué"
                    " deberías hacer?"
                ),
                "options": [
                    "Enviar el dinero inmediatamente.",
                    "Pedirle su contraseña.",
                    (
                        "Comprobar por otro medio que realmente sea esa"
                        " persona."
                    ),
                ],
                "correct": 2,
            },
            {
                "q": (
                    "7. ¿Qué información debemos evitar proporcionar durante"
                    " una llamada sospechosa?"
                ),
                "options": [
                    (
                        "Nuestra contraseña, códigos de seguridad o datos"
                        " bancarios."
                    ),
                    (
                        "El nombre de la empresa donde trabajamos, si es"
                        " información pública."
                    ),
                    "La hora actual.",
                ],
                "correct": 0,
            },
            {
                "q": (
                    "8. ¿Qué debemos hacer si una llamada nos parece"
                    " sospechosa?"
                ),
                "options": [
                    (
                        "Continuar hablando para descubrir qué quiere el"
                        " atacante."
                    ),
                    (
                        "Finalizar la llamada y contactar con la empresa"
                        " mediante un número oficial."
                    ),
                    "Dar información falsa para intentar engañar al atacante.",
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
        "compliance": "PCI-DSS 4.1 / ISO 27001 / SOC 2",
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
        "vector": "Ausencia de Registro SPF (Phishing / GDPR)",
        "severity": "MEDIO",
        "badge": "badge-medium",
        "exec_title": "Vulnerabilidad en Postura de Correo",
        "desc": "El dominio carece de un registro SPF válido.",
        "impact": "Facilita la suplantación de identidad (phishing).",
        "fix": "Publicar registro TXT con directivas SPF.",
        "compliance": "ISO 27001 A.13.2 / GDPR",
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
          "compliance": "PCI-DSS 1.3 / SOC 2 CC6.1",
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
          "compliance": "PCI-DSS 4.1 / HIPAA",
          "snippet": (
              'add_header Strict-Transport-Security "max-age=31536000;" always;'
          ),
      })
    if "Content-Security-Policy" in headers:
      stats["Seguras"] += 1
    else:
      stats["Medias"] += 1
      findings.append({
          "vector": "Content Security Policy (CSP) Ausente",
          "severity": "MEDIO",
          "badge": "badge-medium",
          "exec_title": "Ausencia de CSP",
          "desc": "No se detectó la cabecera Content-Security-Policy.",
          "impact": "Riesgo de ataques XSS (Cross-Site Scripting).",
          "fix": "Implementar directivas CSP robustas.",
          "compliance": "OWASP / SOC 2",
          "snippet": (
              "add_header Content-Security-Policy \"default-src 'self';\";"
          ),
      })
    if "X-Content-Type-Options" in headers:
      stats["Seguras"] += 1
    else:
      stats["Bajas"] += 1
      findings.append({
          "vector": "Cabecera X-Content-Type-Options Ausente",
          "severity": "BAJO",
          "badge": "badge-low",
          "exec_title": "MIME-Sniffing Risk",
          "desc": "Falta la protección contra sniffing de tipos MIME.",
          "impact": "Interpretación incorrecta de archivos por el navegador.",
          "fix": "Añadir X-Content-Type-Options nosniff.",
          "compliance": "OWASP Top 10",
          "snippet": 'add_header X-Content-Type-Options "nosniff";',
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


query_params = st.query_params
employee_token = query_params.get("empleado")
topic_token = query_params.get("tema", "Módulo 1 — Phishing")

if employee_token:
  st.markdown(
      """
        <div class="employee-portal-banner">
            <h2>🎓 Portal Corporativo de Concienciación en Ciberseguridad</h2>
            <p>Capacitación esencial para colaboradores</p>
        </div>
        """,
      unsafe_allow_html=True,
  )

  selected_topic_data = TRAINING_TOPICS.get(
      topic_token, TRAINING_TOPICS["Módulo 1 — Phishing"]
  )

  st.info(
      f"👤 Colaborador: **{employee_token}** | Módulo Asignado:"
      f" **{topic_token}**"
  )

  conn = get_db_connection()
  c = conn.cursor()
  placeholder = "%s" if "postgres" in st.secrets else "?"
  c.execute(
      f"SELECT status, score FROM employees WHERE email = {placeholder} AND"
      f" topic = {placeholder}",
      (employee_token, topic_token),
  )
  row = c.fetchone()
  if not row:
    try:
      c.execute(
          f"INSERT INTO employees (email, department, topic, status) VALUES"
          f" ({placeholder}, {placeholder}, {placeholder}, {placeholder})",
          (employee_token, "General", topic_token, "Pendiente"),
      )
      conn.commit()
    except Exception:
      pass
    current_status = "Pendiente"
    current_score = 0
  else:
    current_status, current_score = row
  c.close()
  conn.close()

  if current_status == "Completado":
    st.success(
        f"✅ ¡Ya hay un registro de examen completado para **{topic_token}**"
        f" con una calificación de **{current_score}%**!"
    )
  else:
    st.markdown(f"### 📚 Material de Estudio: {topic_token}")
    st.markdown(selected_topic_data["theory"])

    st.markdown("---")
    st.markdown("### 📝 Cuestionario de Evaluación")

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
        conn = get_db_connection()
        c = conn.cursor()
        placeholder = "%s" if "postgres" in st.secrets else "?"
        c.execute(
            f"UPDATE employees SET status = 'Completado', score ="
            f" {placeholder}, last_completed = {placeholder} WHERE email ="
            f" {placeholder} AND topic = {placeholder}",
            (final_score, timestamp, employee_token, topic_token),
        )
        conn.commit()
        c.close()
        conn.close()

        st.success(
            f"🎉 ¡Examen enviado con éxito! Has obtenido una calificación de"
            f" **{final_score}%** ({score_points}/{total_qs} aciertos)."
            " Resultados sincronizados con el panel corporativo."
        )
        st.rerun()

else:
  if "scanned" not in st.session_state:
    st.session_state.scanned = False
  if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
  if "org_success_msg" not in st.session_state:
    st.session_state.org_success_msg = ""

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

  selected_org_id = None
  selected_org_name = "General / Sin Asignar"

  if selected_module == "Auditoría Perimetral":
    st.sidebar.header("🏢 Organización / Cliente")
    try:
      conn_org = get_db_connection()
      org_df = pd.read_sql_query("SELECT id, name FROM organizations", conn_org)
      conn_org.close()
    except Exception:
      org_df = pd.DataFrame(columns=["id", "name"])

    org_options = {"General / Sin Asignar": None}
    if not org_df.empty:
      for _, row in org_df.iterrows():
        org_options[row["name"]] = row["id"]

    selected_org_name = st.sidebar.selectbox(
        "Cliente Objetivo", list(org_options.keys())
    )
    selected_org_id = org_options[selected_org_name]

    with st.sidebar.expander("➕ Añadir Nueva Organización"):
      with st.form("add_org_form", clear_on_submit=True):
        new_org_input = st.text_input("Nombre del Cliente")
        submit_org = st.form_submit_button("Guardar Cliente")
        if submit_org and new_org_input:
          try:
            conn_add = get_db_connection()
            c_add = conn_add.cursor()
            placeholder = "%s" if "postgres" in st.secrets else "?"
            c_add.execute(
                f"INSERT INTO organizations (name) VALUES ({placeholder})",
                (new_org_input,),
            )
            conn_add.commit()
            c_add.close()
            conn_add.close()
            st.session_state.org_success_msg = f"Cliente registrado: {new_org_input}"
            st.rerun()
          except Exception:
            st.warning("La organización ya existe o hubo un error.")

    if st.session_state.org_success_msg:
      st.sidebar.success(st.session_state.org_success_msg)
      st.session_state.org_success_msg = ""

    if selected_org_id is not None:
      if st.sidebar.button("🗑️ Eliminar Cliente Seleccionado"):
        try:
          conn_del = get_db_connection()
          c_del = conn_del.cursor()
          placeholder = "%s" if "postgres" in st.secrets else "?"
          c_del.execute(
              f"DELETE FROM organizations WHERE id = {placeholder}",
              (selected_org_id,),
          )
          conn_del.commit()
          c_del.close()
          conn_del.close()
          st.sidebar.success(
              f"Cliente '{selected_org_name}' eliminado correctamente."
          )
          st.rerun()
        except Exception as e:
          st.sidebar.error(f"Error al eliminar: {e}")

    st.sidebar.markdown("---")
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

    st.sidebar.markdown("---")
    st.sidebar.header("🚨 Webhook de Alertas (Slack / Teams)")
    webhook_url_input = st.sidebar.text_input(
        "Webhook URL", type="password", placeholder="https://hooks.slack.com/..."
    )
  else:
    agency_name = "SecOps Global Partners"
    agency_tagline = "División de Consultoría y Ciberseguridad"
    logo_file = None
    report_type = "Informe Técnico Exhaustivo (Completo)"
    recipient_name = "Dirección General"
    report_subject = "Evaluación de Riesgos"
    selected_org_id = None
    webhook_url_input = ""

  st.sidebar.markdown("---")
  st.sidebar.caption(
      "CyberAudits Enterprise v6.5 • Multi-tenant Cloud Platform."
  )

  if is_admin and selected_module == "🎓 Concienciación (Privado - En Desarrollo)":
    st.markdown("---")
    st.markdown(
        "## 🎓 Gestión de Campañas de Concienciación y Directorio Corporativo"
    )
    st.info(
        "Plataforma conectada a Supabase PostgreSQL. Los datos de tus"
        " colaboradores están seguros y centralizados en la nube."
    )

    sub_tab1, sub_tab2, sub_tab3 = st.tabs([
        "👥 Registro, Importación CSV y AD",
        "📊 Dashboard de Resultados",
        "🔗 Generador y Exportador de Enlaces",
    ])

    with sub_tab1:
      col_add1, col_add2 = st.columns(2)
      with col_add1:
        st.markdown("### ➕ Asignar Módulo a Colaborador")
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
              "Seleccionar Módulo de Capacitación",
              list(TRAINING_TOPICS.keys()),
          )
          submit_single = st.form_submit_button("Registrar y Asignar Módulo")
          if submit_single and emp_mail_input:
            try:
              conn = get_db_connection()
              c = conn.cursor()
              placeholder = "%s" if "postgres" in st.secrets else "?"
              c.execute(
                  f"INSERT INTO employees (email, department, topic) VALUES"
                  f" ({placeholder}, {placeholder}, {placeholder})",
                  (emp_mail_input, emp_dept_input, chosen_campaign),
              )
              conn.commit()
              c.close()
              conn.close()
              st.success(
                  f"Módulo '{chosen_campaign}' asignado con éxito a"
                  f" {emp_mail_input}."
              )
              st.rerun()
            except Exception:
              st.warning(
                  "Este colaborador ya se encuentra registrado específicamente"
                  " en este módulo."
              )

        st.markdown("---")
        st.markdown("### 📁 Importación Masiva por Archivo CSV")
        st.write(
            "Sube tu CSV con cabeceras (ej. `email`, `department`, `topic` o"
            " `correo`, `departamento`, `curso`). Soporta separación por `,` o"
            " `;`."
        )
        uploaded_csv = st.file_uploader(
            "Seleccionar CSV de Empleados", type=["csv"]
        )
        if uploaded_csv is not None:
          file_bytes = uploaded_csv.getvalue()
          file_hash = hashlib.md5(file_bytes).hexdigest()

          if st.session_state.get("last_csv_hash") != file_hash:
            try:
              parsed_rows = []

              try:
                uploaded_csv.seek(0)
                df_upload = pd.read_csv(
                    uploaded_csv,
                    encoding="utf-8-sig",
                    sep=None,
                    engine="python",
                )
                df_upload.columns = [
                    str(c).strip().lower().lstrip("\ufeff")
                    for c in df_upload.columns
                ]

                for _, row in df_upload.iterrows():
                  mail_val = None
                  for col in ["email", "correo", "mail", "colaborador"]:
                    if col in df_upload.columns and pd.notna(row[col]):
                      mail_val = str(row[col]).strip()
                      break
                  if not mail_val:
                    for val in row.values:
                      if pd.notna(val) and "@" in str(val):
                        mail_val = str(val).strip()
                        break

                  if mail_val and "@" in mail_val:
                    dept_val = "General"
                    for col in ["department", "departamento", "area", "depto"]:
                      if col in df_upload.columns and pd.notna(row[col]):
                        dept_val = str(row[col]).strip()
                        break

                    top_val = "Módulo 1 — Phishing"
                    for col in ["topic", "curso", "modulo", "módulo", "tema"]:
                      if col in df_upload.columns and pd.notna(row[col]):
                        val_str = str(row[col]).strip()
                        if "phishing" in val_str.lower():
                          top_val = "Módulo 1 — Phishing"
                        elif "contrase" in val_str.lower():
                          top_val = "Módulo 2 — Contraseñas seguras"
                        elif (
                            "puesto" in val_str.lower()
                            or "trabajo" in val_str.lower()
                        ):
                          top_val = (
                              "Módulo 3 — Seguridad en el puesto de trabajo"
                          )
                        elif (
                            "vishing" in val_str.lower()
                            or "smishing" in val_str.lower()
                        ):
                          top_val = "Módulo 4 — Vishing y Smishing"
                        else:
                          top_val = val_str
                        break
                    parsed_rows.append((mail_val, dept_val, top_val))
              except Exception:
                pass

              if not parsed_rows:
                uploaded_csv.seek(0)
                raw_bytes = uploaded_csv.read()
                for enc in ["utf-8-sig", "utf-8", "latin-1", "cp1252"]:
                  try:
                    text_content = raw_bytes.decode(enc)
                    break
                  except Exception:
                    text_content = raw_bytes.decode("latin-1", errors="ignore")

                lines = [
                    l.strip() for l in text_content.splitlines() if l.strip()
                ]
                for line in lines:
                  if any(
                      h == line.lower() or line.lower().startswith(h)
                      for h in ["email", "correo", "mail", "colaborador"]
                  ):
                    continue

                  row = None
                  for delim in [",", ";", "\t", "|"]:
                    try:
                      r = next(csv.reader(io.StringIO(line), delimiter=delim))
                      parts = [
                          p.strip().strip('"\'') for p in r if p.strip()
                      ]
                      if len(parts) > 1 and any("@" in p for p in parts):
                        row = parts
                        break
                    except Exception:
                      pass

                  if not row:
                    parts = [
                        p.strip().strip('"\'')
                        for p in re.split(r"[,;\t|]", line)
                        if p.strip()
                    ]
                    if any("@" in p for p in parts):
                      row = parts

                  if row:
                    mail_val = next((p for p in row if "@" in p), None)
                    if mail_val:
                      non_mail = [p for p in row if p != mail_val]
                      dept_val = (
                          non_mail[0] if len(non_mail) >= 1 else "General"
                      )
                      top_raw = (
                          non_mail[1]
                          if len(non_mail) >= 2
                          else "Módulo 1 — Phishing"
                      )
                      if "phishing" in top_raw.lower():
                        top_val = "Módulo 1 — Phishing"
                      elif "contrase" in top_raw.lower():
                        top_val = "Módulo 2 — Contraseñas seguras"
                      elif (
                          "puesto" in top_raw.lower()
                          or "trabajo" in top_raw.lower()
                      ):
                        top_val = (
                            "Módulo 3 — Seguridad en el puesto de trabajo"
                        )
                      elif (
                          "vishing" in top_raw.lower()
                          or "smishing" in top_raw.lower()
                      ):
                        top_val = "Módulo 4 — Vishing y Smishing"
                      else:
                        top_val = top_raw
                      parsed_rows.append((mail_val, dept_val, top_val))

              conn = get_db_connection()
              c = conn.cursor()
              imported = 0
              existing = 0
              placeholder = "%s" if "postgres" in st.secrets else "?"
              for mail, dept, top in parsed_rows:
                try:
                  c.execute(
                      f"INSERT INTO employees (email, department, topic) VALUES"
                      f" ({placeholder}, {placeholder}, {placeholder})",
                      (mail, dept, top),
                  )
                  imported += 1
                except Exception:
                  existing += 1
              conn.commit()
              c.close()
              conn.close()

              st.session_state["last_csv_hash"] = file_hash

              if parsed_rows:
                st.success(
                    f"✅ ¡Importación completada con éxito en la nube! Se"
                    f" cargaron {len(parsed_rows)} registros ({imported}"
                    f" nuevos, {existing} ya existentes)."
                )
              else:
                st.warning(
                    "No se pudieron extraer registros válidos. Asegúrate de"
                    " que el archivo incluya direcciones de correo con '@'."
                )
            except Exception as e:
              st.error(f"Error procesando el archivo CSV: {e}")
          else:
            st.success(
                "✅ Archivo CSV procesado y sincronizado con Supabase."
            )

      with col_add2:
        st.markdown("### 🔄 Sincronización Masiva (Simulador Active Directory)")
        st.write(
            "Importa automáticamente el listado de colaboradores desde tu"
            " directorio corporativo en lote:"
        )
        if st.button(
            "🌐 Sincronizar Directorio Activo (Mock AD Sync)", type="primary"
        ):
          mock_directory = [
              (
                  "carlos.gomez@empresa.com",
                  "Tecnología / TI",
                  "Módulo 1 — Phishing",
              ),
              (
                  "torrealba8100@gmail.com",
                  "Administración",
                  "Módulo 1 — Phishing",
              ),
              (
                  "torrealba8100@gmail.com",
                  "Administración",
                  "Módulo 2 — Contraseñas seguras",
              ),
              (
                  "ana.martinez@empresa.com",
                  "Finanzas",
                  "Módulo 2 — Contraseñas seguras",
              ),
              (
                  "lucas.pereira@empresa.com",
                  "Ventas",
                  "Módulo 3 — Seguridad en el puesto de trabajo",
              ),
              (
                  "sofia.benitez@empresa.com",
                  "Operaciones",
                  "Módulo 4 — Vishing y Smishing",
              ),
          ]
          conn = get_db_connection()
          c = conn.cursor()
          added_count = 0
          skipped_count = 0
          placeholder = "%s" if "postgres" in st.secrets else "?"
          for mail, dept, top in mock_directory:
            try:
              c.execute(
                  f"INSERT INTO employees (email, department, topic) VALUES"
                  f" ({placeholder}, {placeholder}, {placeholder})",
                  (mail, dept, top),
              )
              added_count += 1
            except Exception:
              skipped_count += 1
          conn.commit()
          c.close()
          conn.close()
          st.success(
              f"¡Sincronización AD ejecutada con éxito! Se añadieron {added_count}"
              f" asignaciones nuevas ({skipped_count} ya existían)."
          )
          st.rerun()

    with sub_tab2:
      st.markdown("### 📊 Panel de Control y Métricas Globales (Supabase)")
      emp_df = get_employees_df()
      if not emp_df.empty:
        st.dataframe(emp_df, use_container_width=True)
        if st.button("🗑️ Vaciar Base de Datos de Empleados", type="secondary"):
          conn = get_db_connection()
          c = conn.cursor()
          c.execute("DELETE FROM employees")
          conn.commit()
          c.close()
          conn.close()
          if "last_csv_hash" in st.session_state:
            del st.session_state["last_csv_hash"]
          st.success("Base de datos de empleados vaciada correctamente.")
          st.rerun()
      else:
        st.info("No hay registros en el dashboard de empleados.")

    with sub_tab3:
      st.markdown("### 🔗 Enlaces Únicos y Exportación Masiva")
      st.write(
          "Copia los enlaces individuales o descarga la lista completa en CSV"
          " para realizar campañas de correo masivo:"
      )

      conn = get_db_connection()
      c = conn.cursor()
      c.execute("SELECT email, topic FROM employees")
      records = c.fetchall()
      c.close()
      conn.close()

      if records:
        link_data = []
        for mail, top in records:
          link = f"https://cyber-auditorias-2gc3l28n5gmeajtui9d9a6.streamlit.app/?empleado={mail}&tema={top}"
          link_data.append({"Correo": mail, "Módulo": top, "Enlace": link})
          st.text_input(
              f"{mail} -> [{top}]", value=link, key=f"url_{mail}_{top}"
          )

        st.markdown("---")
        df_links = pd.DataFrame(link_data)
        st.download_button(
            "📥 Descargar Todos los Enlaces (CSV para Envíos Masivos)",
            df_links.to_csv(index=False, sep=";").encode("utf-8-sig"),
            file_name="enlaces_campana_colaboradores.csv",
            mime="text/csv",
            type="primary",
        )
      else:
        st.info(
            "Registra colaboradores en la primera sub-pestaña para ver y"
            " exportar sus enlaces."
        )

  else:
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🔍 Perimeter Scan",
        "📊 Security Analytics",
        "📜 Historial de Escaneos",
        "🛠️ Gestión de Remediación (Ticketera)",
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
                organization_id=selected_org_id,
                findings=findings,
            )

            if webhook_url_input:
              send_webhook_alert(
                  webhook_url_input, hostname, risk_score, len(findings)
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
            (
                "Protegido"
                if st.session_state.email_sec["spf"]
                else "Ausente"
            ),
        )
        g5.metric(
            "DMARC",
            (
                "Protegido"
                if st.session_state.email_sec["dmarc"]
                else "Ausente"
            ),
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
      st.subheader(
          f"📜 Historial de Escaneos Corporativos — {selected_org_name} (Supabase)"
      )
      history_df = get_scan_history(org_id=selected_org_id)
      if not history_df.empty:
        st.dataframe(history_df, use_container_width=True)
        if st.button(f"🗑️ Limpiar Historial de {selected_org_name}"):
          conn = get_db_connection()
          c = conn.cursor()
          is_pg = "postgres" in st.secrets
          ph = "%s" if "postgres" in st.secrets else "?"
          if selected_org_id is not None:
            c.execute(
                f"DELETE FROM history WHERE organization_id = {ph}",
                (selected_org_id,),
            )
          else:
            c.execute("DELETE FROM history WHERE organization_id IS NULL")
          conn.commit()
          c.close()
          conn.close()
          st.rerun()
      else:
        st.info(f"Aún no hay escaneos guardados para {selected_org_name}.")

    with tab4:
      st.subheader(
          f"🛠️ Ticketera y Seguimiento Diario de Remediación —"
          f" {selected_org_name}"
      )
      st.write(
          "Selecciona un escaneo específico realizado para este cliente para"
          " gestionar sus incidentes y ver su historial."
      )

      try:
        conn = get_db_connection()
        is_pg = "postgres" in st.secrets
        ph = "%s" if "postgres" in st.secrets else "?"
        if selected_org_id is not None:
          scans_query = f"SELECT id, timestamp, hostname, risk_score FROM history WHERE organization_id = {ph} ORDER BY id DESC"
          scans_df = pd.read_sql_query(scans_query, conn, params=(selected_org_id,))
        else:
          scans_query = "SELECT id, timestamp, hostname, risk_score FROM history WHERE organization_id IS NULL ORDER BY id DESC"
          scans_df = pd.read_sql_query(scans_query, conn)
        conn.close()
      except Exception:
        scans_df = pd.DataFrame()

      if not scans_df.empty:
        scan_options = {}
        for _, s_row in scans_df.iterrows():
          label = f"Escaneo #{s_row['id']} - {s_row['hostname']} ({s_row['timestamp']}) [Score: {s_row['risk_score']}/100]"
          scan_options[label] = s_row["id"]

        selected_scan_label = st.selectbox(
            "Seleccionar Escaneo a Trabajar", list(scan_options.keys())
        )
        selected_scan_id = scan_options[selected_scan_label]

        # Sub-pestañas para Activos vs Solucionados
        sub_t_active, sub_t_resolved = st.tabs([
            "⚠️ Incidentes Activos (Pendiente / En Proceso)",
            "✅ Incidentes Solucionados / Cerrados",
        ])

        with sub_t_active:
          try:
            conn = get_db_connection()
            query = f"SELECT id, hostname, finding_vector, status FROM remediation_tasks WHERE scan_id = {ph} AND status != 'Solucionado' ORDER BY id ASC"
            tasks_df = pd.read_sql_query(query, conn, params=(selected_scan_id,))
            conn.close()
          except Exception:
            tasks_df = pd.DataFrame()

          if not tasks_df.empty:
            for index, row in tasks_df.iterrows():
              t_id = row["id"]
              t_host = row["hostname"]
              t_vec = row["finding_vector"]
              t_status = row["status"]

              with st.container():
                st.markdown(f"### 📌 {t_vec}")
                st.caption(
                    f"Host: `{t_host}` | Estado actual: **{t_status}**"
                )

                col_t1, col_t2 = st.columns([2, 3])
                with col_t1:
                  new_status = st.selectbox(
                      "Actualizar Estado",
                      ["Pendiente", "En Proceso", "Solucionado"],
                      index=(
                          0
                          if t_status == "Pendiente"
                          else 1 if t_status == "En Proceso" else 2
                      ),
                      key=f"status_select_active_{t_id}",
                  )
                with col_t2:
                  new_note = st.text_input(
                      "Nueva Nota de Seguimiento (Día a Día)",
                      key=f"notes_input_active_{t_id}",
                      placeholder="Ej. Se aplicó parche...",
                  )

                if st.button(
                    "➕ Registrar Avance en Bitácora",
                    key=f"save_task_active_{t_id}",
                ):
                  if new_note.strip():
                    try:
                      conn_u = get_db_connection()
                      c_u = conn_u.cursor()
                      now_ts = datetime.datetime.now().strftime(
                          "%Y-%m-%d %H:%M:%S"
                      )
                      c_u.execute(
                          f"UPDATE remediation_tasks SET status = {ph} WHERE id"
                          f" = {ph}",
                          (new_status, t_id),
                      )
                      c_u.execute(
                          f"INSERT INTO remediation_logs (task_id, timestamp,"
                          f" status, notes) VALUES ({ph}, {ph}, {ph}, {ph})",
                          (t_id, now_ts, new_status, new_note),
                      )
                      conn_u.commit()
                      c_u.close()
                      conn_u.close()
                      st.success(
                          "¡Avance registrado! Si marcaste como Solucionado,"
                        " el incidente se movió a la pestaña de resueltos."
                      )
                      st.rerun()
                    except Exception as e:
                      st.error(f"Error al registrar: {e}")
                  else:
                    st.warning(
                        "Por favor, escribe una nota técnica antes de"
                        " registrar el avance."
                    )

                with st.expander(
                    f"🕒 Ver Historial de Seguimiento (Bitácora) para este"
                    f" hallazgo"
                ):
                  try:
                    conn_l = get_db_connection()
                    logs_query = f"SELECT timestamp, status, notes FROM remediation_logs WHERE task_id = {ph} ORDER BY id DESC"
                    logs_df = pd.read_sql_query(
                        logs_query, conn_l, params=(t_id,)
                    )
                    conn_l.close()
                  except Exception:
                    logs_df = pd.DataFrame()

                  if not logs_df.empty:
                    for _, log_row in logs_df.iterrows():
                      st.markdown(
                          f"🕒 **{log_row['timestamp']}** — Estado:"
                          f" `{log_row['status']}`\n> _{log_row['notes']}_"
                      )
                      st.markdown("---")
                  else:
                    st.info("Aún no hay notas registradas en la bitácora.")

                st.markdown("---")
          else:
            st.info(
                "No hay incidentes activos (pendientes o en proceso) para este"
                " escaneo."
            )

        with sub_t_resolved:
          try:
            conn = get_db_connection()
            query = f"SELECT id, hostname, finding_vector, status FROM remediation_tasks WHERE scan_id = {ph} AND status = 'Solucionado' ORDER BY id ASC"
            resolved_df = pd.read_sql_query(
                query, conn, params=(selected_scan_id,)
            )
            conn.close()
          except Exception:
            resolved_df = pd.DataFrame()

          if not resolved_df.empty:
            for index, row in resolved_df.iterrows():
              t_id = row["id"]
              t_host = row["hostname"]
              t_vec = row["finding_vector"]
              t_status = row["status"]

              with st.container():
                st.markdown(f"### ✅ {t_vec}")
                st.caption(
                    f"Host: `{t_host}` | Estado: **{t_status} (Cerrado)**"
                )

                # Permitir reabrir o revisar notas en resueltos también
                with st.expander(
                    f"🕒 Ver Historial Completo y Bitácora de este Incidente"
                    f" Solucionado"
                ):
                  try:
                    conn_l = get_db_connection()
                    logs_query = f"SELECT timestamp, status, notes FROM remediation_logs WHERE task_id = {ph} ORDER BY id DESC"
                    logs_df = pd.read_sql_query(
                        logs_query, conn_l, params=(t_id,)
                    )
                    conn_l.close()
                  except Exception:
                    logs_df = pd.DataFrame()

                  if not logs_df.empty:
                    for _, log_row in logs_df.iterrows():
                      st.markdown(
                          f"🕒 **{log_row['timestamp']}** — Estado:"
                          f" `{log_row['status']}`\n> _{log_row['notes']}_"
                      )
                      st.markdown("---")
                  else:
                    st.info("No hay registros en la bitácora.")

                st.markdown("---")
          else:
            st.info("Aún no hay incidentes solucionados para este escaneo.")
      else:
        st.info(
            "No hay escaneos guardados para este cliente. Realiza un escaneo"
            " en la primera pestaña."
        )

    with tab5:
      st.subheader("About CyberAudits Enterprise Suite")
      st.markdown("""
            **CyberAudits Enterprise Suite** es una plataforma integral orientada a consultorías de ciberseguridad corporativa.
            * **Módulos:** Auditoría perimetral, gestión del factor humano y seguimiento de remediación tipo ticketera con separación de incidentes resueltos.
            * **Arquitectura:** Desarrollado bajo estándares modulares con persistencia en PostgreSQL (Supabase).
            """)
