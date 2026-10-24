# OpenRecon 🛡️
> **Plataforma Open Source de Gestión de Superficie de Ataque Externa (EASM), Protección Digital de Marca (DRP) e Inteligencia de Amenazas (CTI)**
> *Inspirada en las capacidades de Fortinet FortiRecon, Recorded Future, Palo Alto Cortex Xpanse y CrowdStrike Falcon Exposure Management.*

---

## 🌟 Características Principales

OpenRecon proporciona a cualquier organización una suite completa de ciberseguridad perimetral sin costos de licenciamiento privativo:

* **EASM (External Attack Surface Management):**
  * Descubrimiento continuo de activos y subdominios (`subfinder`, `crt.sh`, logs de transparencia de certificados).
  * Resolución DNS activa y pasiva (`dnspython`, `dnsx`).
  * Mapeo de puertos perimetrales y servicios expuestos (`naabu`, sockets asíncronos no destructivos).
  * Fingerprinting web, extracción de títulos, tecnologías y estado de certificados SSL/TLS.
  * Detección automatizada de puertos críticos expuestos sin cortafuegos (Bases de datos: MySQL, Redis, Postgres, MongoDB; Escritorio remoto RDP, FTP).
  * Conector para validación de vulnerabilidades conocidas y desconfiguraciones mediante plantillas de `Nuclei`.

* **DRP (Digital Risk Protection):**
  * Generación de permutaciones de dominios sospechosos / typosquatting (homóglifos, omisión, suplantación de marca con prefijos `login-`, `secure-`, etc.).
  * Verificación en tiempo real de registros DNS y MX de dominios imitadores para alertar sobre vectores de phishing activo.

* **Exposure & Risk Scoring:**
  * Cálculo de postura de seguridad y puntuación de exposición (Exposure Score de 0 a 100) en base a severidad de hallazgos y servicios expuestos.
  * Desglose de activos vivos, puertos abiertos y amenazas activas.

---

## 🏗️ Arquitectura del Sistema

```
OpenRecon/
├── backend/
│   ├── app/
│   │   ├── api/v1/endpoints/       # Endpoints REST (Organizaciones, Seeds, Scans, Assets, Exposures)
│   │   ├── core/                  # Configuración (Pydantic Settings) y Conexión DB (SQLAlchemy)
│   │   ├── models/                # Modelos de datos (Orgs, Assets, Ports, Vulns, DRP, Scans)
│   │   ├── schemas/               # Validadores y esquemas Pydantic v2
│   │   ├── services/
│   │   │   ├── engines/           # Motores (DNS, HTTP, Port, DRP Typosquatting, Nuclei)
│   │   │   └── scanner_orchestrator.py # Orquestador central de análisis asíncrono
│   │   └── main.py                # Aplicación FastAPI y middleware CORS
│   ├── requirements.txt           # Dependencias Python
│   └── Dockerfile                 # Imagen Docker con herramientas ProjectDiscovery
├── docker-compose.yml             # Despliegue con PostgreSQL 16 y Redis 7
├── run_dev.py                     # Script para iniciar en desarrollo local
└── PLAN_DE_TRABAJO_OPENRECON.md   # Roadmap maestro de fases de ingeniería
```

---

## 🚀 Despliegue Rápido

### Opción 1: Desarrollo Local (Python nativo)

1. Crear y activar entorno virtual:
   ```bash
   python -m venv venv
   # En Windows:
   venv\Scripts\activate
   # En Linux/Mac:
   source venv/bin/activate
   ```

2. Instalar dependencias:
   ```bash
   pip install -r backend/requirements.txt
   ```

3. Iniciar el servidor API y el orquestador:
   ```bash
   python run_dev.py
   ```

4. Abrir la documentación interactiva Swagger:
   * **URL:** [http://localhost:8000/docs](http://localhost:8000/docs)

---

### Opción 2: Producción con Docker Compose

```bash
docker compose up -d --build
```
Esto levantará automáticamente:
* Base de datos **PostgreSQL 16**.
* Cola de mensajes **Redis 7**.
* Contenedor de la API con los binarios de escaneo (`subfinder`, `httpx`, `naabu`, `nuclei`) preinstalados.

---

## 📡 Guía de Uso de la API (Paso a Paso)

### 1. Registrar tu Empresa / Organización
`POST /api/v1/organizations/`
```json
{
  "name": "MiEmpresa Corp",
  "description": "Monitoreo perimetral corporativo"
}
```

### 2. Agregar Semillas de Reconocimiento (Dominios o Rangos)
`POST /api/v1/organizations/{org_id}/seeds`
```json
{
  "seed_type": "DOMAIN",
  "value": "ejemplo.com"
}
```

### 3. Lanzar un Escaneo Automatizado (EASM + DRP)
`POST /api/v1/scans/`
```json
{
  "organization_id": 1,
  "scan_type": "EASM_FULL"
}
```
*El escaneo se ejecutará asíncronamente en segundo plano sin bloquear tu petición.*

### 4. Consultar Resultados e Inventario de Activos
* **Inventario de activos:** `GET /api/v1/assets/?organization_id=1`
* **Detalle de un activo (puertos y tecnologías):** `GET /api/v1/assets/{asset_id}/details`
* **Vulnerabilidades y servicios expuestos:** `GET /api/v1/exposures/vulnerabilities?organization_id=1`
* **Amenazas de suplantación de marca y phishing:** `GET /api/v1/exposures/drp?organization_id=1`
* **Puntuación ejecutiva de exposición (0-100):** `GET /api/v1/exposures/stats?organization_id=1`

---

## ⚖️ Seguridad y Ética

OpenRecon está diseñado bajo la premisa de **escaneo no intrusivo y defensivo**:
* Respeta límites de tasa de peticiones por segundo (`rate-limiting`).
* Realiza inspección perimetral pasiva y sondas activas seguras (sin explotación ofensiva destructiva).
* Toda la telemetría e información de inventario pertenece a la empresa y nunca se comparte con terceros.
