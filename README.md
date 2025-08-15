
🎓 CyberHub Academy - Bot Curso de Hacking Etico para Telegram
Una plataforma completa de e-learning sobre ciberseguridad, implementada como un bot de Telegram interactivo y gamificado. Este proyecto está diseñado para ser una herramienta educativa robusta, con un currículum extenso que guía a los usuarios desde los conceptos más básicos hasta técnicas avanzadas de hacking ético.

✨ Características Principales
Currículum Masivo (+90 Lecciones): El curso está estructurado en tres niveles de dificultad creciente para asegurar un aprendizaje progresivo que puede durar meses.

🔰 Nivel Básico (30 Lecciones): Fundamentos de redes, OSINT, criptografía y seguridad elemental.

🐍 Nivel Medio (30 Lecciones): Análisis de vulnerabilidades, explotación web (OWASP Top 10), uso de herramientas como Nmap y Metasploit.

💥 Nivel Pro (30 Lecciones): Técnicas de Red Team, evasión de defensas, seguridad en la nube y conceptos de exploit development.

🏆 Sistema de Gamificación:

Ranking y Puntos: Los usuarios ganan puntos por cada práctica resuelta.

Leaderboard Global: Un comando /leaderboard para fomentar la competencia sana.

CTF Diario: Un reto diario para mantener a la comunidad activa y poner a prueba sus habilidades.

🛠️ Arsenal de Herramientas Integrado:

Herramientas Gratuitas: Utilidades básicas como /hash y /base64.

Herramientas VIP: Un conjunto de herramientas de pentesting más potentes, incluyendo /whois, /dns, /subdomains, /portscan, /cve y /httpheaders.

⚙️ Panel de Administración Avanzado:

Gestión de Contenido Dinámico: El administrador puede añadir nuevas lecciones (/add_lesson) y configurar el CTF diario (/set_ctf) directamente desde el chat, sin necesidad de modificar el código.

Sistema de Monetización: Generación de claves de suscripción VIP (/key) por planes (semanal, mensual, etc.) y canje por parte de los usuarios (/redeem).

Control Total: Gestión de usuarios (dar VIP, banear), modo de mantenimiento y estadísticas de uso del bot.

🚀 Stack Tecnológico
Lenguaje: Python 3

Librería Principal: python-telegram-bot

Librerías Adicionales: requests, dnspython, python-dotenv

Base de Datos: Almacenamiento persistente en un archivo JSON plano para simplicidad y portabilidad.

🔧 Instalación y Configuración
Clonar el repositorio:

Bash

git clone https://github.com/tu-usuario/nombre-del-repositorio.git
cd nombre-del-repositorio
Instalar dependencias:

Bash

pip install -r requirements.txt
Configurar las variables de entorno:
Crea un archivo config.env en la raíz del proyecto y añade tus claves secretas:

TELEGRAM_TOKEN="TU_TOKEN_DE_TELEGRAM"
ADMIN_ID="TU_ID_DE_ADMINISTRADOR"
ADMIN_USERNAME="@tu_usuario_de_admin"
Ejecutar el bot:

Bash

python3 bot.py# Telegram-Ethic-Hacking-Bot
