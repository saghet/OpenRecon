[README.md](https://github.com/user-attachments/files/33909528/README.md)
# php2shell Scanner v1.2 — CVE-2026-109618 / CVE-2026-109619

> **EN** · Scanner to test exposure to **php2shell** — the PHP RCE vulnerability
> tracked as **CVE-2026-109618** and **CVE-2026-109619**. It passively checks the
> PHP version of a host and reports whether it falls in the affected (unpatched)
> range.
> **ES** · Scanner para comprobar la exposición a **php2shell** — la vulnerabilidad
> de RCE en PHP identificada como **CVE-2026-109618** y **CVE-2026-109619**.
> Verifica de forma pasiva la versión de PHP de un host e informa si está en el
> rango afectado (sin parchear).

<p>
<img src="https://img.shields.io/badge/version-1.2-blueviolet" alt="v1.2">
<img src="https://img.shields.io/badge/CVE-2026--109618-red" alt="CVE-2026-109618">
<img src="https://img.shields.io/badge/CVE-2026--109619-red" alt="CVE-2026-109619">
<img src="https://img.shields.io/badge/python-3.9%2B-blue" alt="Python 3.9+">
<img src="https://img.shields.io/badge/deps-stdlib%20only-green" alt="No dependencies">
<img src="https://img.shields.io/badge/mode-passive%20(banner%20check)-orange" alt="Passive">
</p>

**Author / Autor:** Manuel Moreno — CEO, **GLOBALSECURE**
**Web:** [www.globalsecure.cl](https://www.globalsecure.cl)

---

## ⚠️ Legal / Ethical — Legal / Ético

**EN** — This tool is for **authorized security assessments only**: systems you own
or for which you have **explicit written permission**. It performs a passive
banner check (a single HTTP `HEAD`/`GET`), but you are still responsible for
scanning only what you are allowed to. **Do not** use it for indiscriminate or
mass scanning of networks you don't control. The authors assume no liability for
misuse.

**ES** — Esta herramienta es solo para **evaluaciones de seguridad autorizadas**:
sistemas propios o para los que tengas **permiso explícito por escrito**. Hace una
comprobación pasiva de banner (una única petición HTTP `HEAD`/`GET`), pero sigues
siendo responsable de escanear únicamente lo que tienes permitido. **No** la uses
para escaneo indiscriminado o masivo de redes que no controlas. Los autores no se
hacen responsables del mal uso.

---

## 🔍 What it does — Qué hace

**EN**
- Reads the PHP version advertised in the `Server` / `X-Powered-By` headers (and
  `PHPSESSID` cookie / body as secondary signals).
- Compares it against the patched versions and reports **VULNERABLE / PATCHED /
  UNKNOWN / NO-PHP / NO-RESPONSE**.
- **Does not** exploit anything: no payloads, no file uploads, no session
  tampering, none of the php2shell exploit chains.
- Detects when a host sits behind a **CDN/WAF** (Cloudflare, Akamai, Fastly,
  Sucuri, AWS…) and, for Cloudflare, can **auto-discover the origin IP** to read
  the real backend version.

**ES**
- Lee la versión de PHP anunciada en las cabeceras `Server` / `X-Powered-By` (y la
  cookie `PHPSESSID` / el cuerpo como señales secundarias).
- La compara con las versiones parcheadas y reporta **VULNERABLE / PARCHEADO /
  DESCONOCIDO / SIN-PHP / SIN-RESPUESTA**.
- **No** explota nada: sin payloads, sin subida de ficheros, sin manipular
  sesiones, ninguna de las cadenas de explotación de php2shell.
- Detecta si un host está tras un **CDN/WAF** (Cloudflare, Akamai, Fastly,
  Sucuri, AWS…) y, para Cloudflare, puede **auto-descubrir la IP de origen** para
  leer la versión real del backend.

---

## 📦 Requirements — Requisitos

**EN** · Python 3.9+ · standard library only (no `pip install`).
**ES** · Python 3.9+ · solo librería estándar (sin `pip install`).

```bash
git clone https://github.com/<usuario>/php2shell-version-scanner.git
cd php2shell-version-scanner
python3 php2shell_version_scanner.py --help
```

---

## 🚀 Usage — Uso

```bash
# Single host — Un objetivo
python3 php2shell_version_scanner.py --target www.example.com

# Whole domain — Dominio completo (descubrimiento multi-fuente de subdominios)
# EN: aggregates subdomains from several free sources and scans them all.
# ES: agrega subdominios de varias fuentes gratuitas y los escanea todos.
python3 php2shell_version_scanner.py -d example.com
python3 php2shell_version_scanner.py --domain example.com --ports 80,443 --only-vuln

# Pick specific discovery sources — Elegir fuentes concretas
python3 php2shell_version_scanner.py -d example.com --sources crtsh,certspotter

# Direct IP — IP directa
python3 php2shell_version_scanner.py --target 203.0.113.10 --ports 80,443

# Full network segment — Segmento de red completo (CIDR)
python3 php2shell_version_scanner.py --cidr 10.0.0.0/24 --ports 80,443,8080

# From a file of IPs/hosts — Desde un fichero de IPs/hosts (una por línea)
python3 php2shell_version_scanner.py --file targets.txt

# Multiple sources + export, only vulnerable — Varias fuentes + export, solo vulnerables
python3 php2shell_version_scanner.py \
    --cidr 192.168.10.0/24 --target extranet.example.com \
    --only-vuln --csv report.csv --json report.json

# Behind a CDN: reach the ORIGIN directly — Tras CDN: ir directo al ORIGEN
python3 php2shell_version_scanner.py \
    --target campus.example.com --origin-ip 203.0.113.10 --ports 443

# Force the vhost when pointing at an IP — Forzar el vhost al apuntar a una IP
python3 php2shell_version_scanner.py \
    --target 203.0.113.10 --host-header campus.example.com --ports 443
```

### Input file format — Formato del fichero de entrada

```text
# one host/IP per line — una IP/host por línea
# supports host:port and # comments — admite host:puerto y comentarios con #
www.example.com
10.0.0.10
10.0.0.11:8080
intranet.example.local:443
```

---

## 🧰 Options — Opciones

| Flag | EN | ES |
|------|----|----|
| `--target` | IP or domain. Repeatable. | IP o dominio. Repetible. |
| `-d`, `--domain` | Domain: discover **all** subdomains from multiple free sources and scan them. Repeatable. | Dominio: descubre **todos** los subdominios desde varias fuentes gratuitas y los escanea. Repetible. |
| `--sources` | Discovery sources, comma-separated: `crtsh,hackertarget,otx,certspotter,rapiddns` (default all). | Fuentes de descubrimiento, separadas por coma: `crtsh,hackertarget,otx,certspotter,rapiddns` (def. todas). |
| `--crtsh-timeout` | Timeout (s) per discovery query (default `30`). | Timeout (s) por consulta de descubrimiento (def. `30`). |
| `--cidr` | Network segment, e.g. `10.0.0.0/24`. Repeatable. | Segmento de red, p. ej. `10.0.0.0/24`. Repetible. |
| `--file` | File with one IP/host per line (`host:port` and `#` allowed). | Fichero con una IP/host por línea (admite `host:puerto` y `#`). |
| `--ports` | Ports to probe, comma-separated (default `80,443`). | Puertos a sondear, separados por coma (def. `80,443`). |
| `--host-header` | `Host`/vhost value to send. Useful when hitting an origin IP. | Valor de la cabecera `Host`/vhost. Útil al apuntar a una IP de origen. |
| `--origin-ip` | Connect to this origin IP instead of resolving the domain (CDN bypass). | Conecta a esta IP de origen en vez de resolver el dominio (bypass de CDN). |
| `--no-auto-origin` | Disable automatic origin discovery (on by default). | Desactiva el descubrimiento automático de origen (activo por defecto). |
| `--origin-subdomains` | Custom subdomain prefixes for auto-origin, comma-separated (`''` = apex). | Prefijos de subdominio propios para auto-origin, separados por coma (`''` = apex). |
| `--timeout` | Per-connection timeout in seconds (default `6`). | Timeout por conexión en segundos (def. `6`). |
| `--threads` | Concurrent threads (default `50`). | Hilos concurrentes (def. `50`). |
| `--csv` | Export results to CSV. | Exporta resultados a CSV. |
| `--json` | Export results to JSON. | Exporta resultados a JSON. |
| `--only-vuln` | Show only VULNERABLE targets in the console. | Muestra en consola solo los objetivos VULNERABLES. |
| `--confirm` | **Level 1** — active precondition validation on VULNERABLE hosts (requires authorization, see below). | **Nivel 1** — validación activa de precondiciones sobre hosts VULNERABLE (requiere autorización, ver abajo). |
| `--no-color` | Disable ANSI color. | Desactiva el color ANSI. |

---

## 🏷️ Verdicts — Veredictos

| Verdict / Veredicto | EN | ES |
|---------------------|----|----|
| `VULNERABLE` | PHP version below its branch's patched release, or EOL branch in the affected range. | Versión por debajo de la parcheada de su rama, o rama EOL en el rango afectado. |
| `PATCHED` / `PARCHEADO` | Version ≥ the fixed one, or out of the affected range. | Versión ≥ a la corregida, o fuera del rango afectado. |
| `UNKNOWN` / `DESCONOCIDO` | Responds as PHP but hides the version (`expose_php=Off`). | Responde como PHP pero oculta la versión (`expose_php=Off`). |
| `NO-PHP` / `SIN-PHP` | Port responds but no PHP detected. | El puerto responde pero no se detecta PHP. |
| `FILTRADO` | Connection timed out — port filtered / dropped by a firewall. | La conexión agotó el timeout — puerto filtrado / DROP de firewall. |
| `CERRADO` | Connection refused (RST) — port closed. | Conexión rechazada (RST) — puerto cerrado. |
| `NO-DNS` | Hostname does not resolve (internal/obsolete name). | El nombre no resuelve en DNS (nombre interno/obsoleto). |
| `IP-PRIVADA` | Resolves to an RFC1918 address — internal, not reachable here (only skipped for `-d` discovery). | Resuelve a RFC1918 — interno, no alcanzable desde aquí (solo se descarta en descubrimiento `-d`). |
| `NO-RESPONSE` / `SIN-RESPUESTA` | Other / no HTTP response. | Otra causa / sin respuesta HTTP. |

> **EN** · Splitting the old catch-all "no response" into `NO-DNS`, `IP-PRIVADA`,
> `FILTRADO` and `CERRADO` tells you *why* a host didn't answer, and `NO-DNS` /
> `IP-PRIVADA` are resolved instantly without wasting a timeout.
> **ES** · Separar el antiguo "sin respuesta" en `NO-DNS`, `IP-PRIVADA`,
> `FILTRADO` y `CERRADO` te dice *por qué* un host no contestó, y `NO-DNS` /
> `IP-PRIVADA` se resuelven al instante sin gastar timeout.

### Patched versions — Versiones corregidas

`8.2.35` · `8.3.36` · `8.4.27` · `8.5.12`

**EN** · Branches **5.4 – 8.1** are EOL and won't get the fix → flagged vulnerable.
**ES** · Las ramas **5.4 – 8.1** están EOL y no reciben el parche → se marcan vulnerables.

---

## 🌐 Subdomain discovery — Descubrimiento de subdominios (`-d`)

**EN** · With `-d/--domain` the scanner builds the target list by aggregating
subdomains from several **free, no-API-key** sources, then scans them all:

| Source | What it uses |
|--------|--------------|
| **crt.sh** | Certificate Transparency logs |
| **HackerTarget** | DNS dataset (same data behind DNSDumpster) |
| **AlienVault OTX** | Passive DNS |
| **CertSpotter** | Certificate Transparency |
| **RapidDNS** | Public DNS database |

Results are merged and de-duplicated, so if one source is down (crt.sh often
returns 502) the others still deliver — each source retries with backoff. Pick
sources with `--sources`, set the per-query timeout with `--crtsh-timeout`.
Discovered names feed the whole pipeline: DNS pre-filtering (`NO-DNS` /
`IP-PRIVADA`), the scan itself, and the **shared origin pool** used by auto-origin.

**ES** · Con `-d/--domain` el scanner construye la lista de objetivos agregando
subdominios de varias fuentes **gratuitas y sin API key**, y luego los escanea
todos:

| Fuente | Qué usa |
|--------|---------|
| **crt.sh** | Logs de Certificate Transparency |
| **HackerTarget** | Dataset DNS (los mismos datos tras DNSDumpster) |
| **AlienVault OTX** | Passive DNS |
| **CertSpotter** | Certificate Transparency |
| **RapidDNS** | Base de datos DNS pública |

Los resultados se combinan y deduplican, así que si una fuente está caída
(crt.sh suele dar 502) las demás siguen aportando — cada fuente reintenta con
backoff. Elige fuentes con `--sources` y ajusta el timeout por consulta con
`--crtsh-timeout`. Los nombres descubiertos alimentan todo el proceso: el
pre-filtro DNS (`NO-DNS` / `IP-PRIVADA`), el escaneo, y el **pool de origen
compartido** que usa el auto-origin.

> **Nota DNSDumpster / DNSDumpster note:** DNSDumpster no ofrece API libre; sus
> datos provienen de HackerTarget, que **sí** se integra aquí sin key. / DNSDumpster
> has no free API; its data comes from HackerTarget, which **is** integrated here
> without a key.

---

## 🛰️ Auto-origin discovery — Descubrimiento automático de origen

**EN** · **On by default, for single targets only.** When an individual `--target`
is behind **any CDN/WAF** (Cloudflare, Akamai, AWS CloudFront/ELB, Fastly…) and the
version isn't visible, the scanner resolves common leaky subdomains of that host
(`mail`, `direct`, `cpanel`, `origin`, apex…), discards CDN ranges, and retries
against the origin announcing the domain as `Host`. A candidate is adopted only if
it reveals a PHP version or is not itself behind a CDN.

**It does NOT run on `-d` domain scans.** Attributing one shared origin's version
to many CDN-fronted hosts caused false positives (many hosts flagged vulnerable on
the same origin IP), so on a `-d` scan the origins are simply scanned **directly**
as their own discovered hostnames. CDN-fronted hosts stay `SIN-PHP` with an honest
note: the backend version is **not observable passively** and needs the origin IP
(inventory) or an authenticated check. DNS-only recon. Disable with `--no-auto-origin`.

**ES** · **Activado por defecto, solo para objetivos sueltos.** Cuando un `--target`
individual está tras **cualquier CDN/WAF** (Cloudflare, Akamai, AWS CloudFront/ELB,
Fastly…) y no se ve la versión, el scanner resuelve subdominios comunes de ese host
(`mail`, `direct`, `cpanel`, `origin`, apex…), descarta rangos de CDN y reintenta
contra el origen anunciando el dominio como `Host`. Un candidato solo se adopta si
revela una versión de PHP o si él mismo no está tras un CDN.

**NO se ejecuta en escaneos `-d`.** Atribuir la versión de un único origen
compartido a muchos hosts tras CDN producía falsos positivos (muchos hosts marcados
vulnerables sobre la misma IP de origen), así que en un escaneo `-d` los orígenes se
escanean **directamente** como sus propios nombres descubiertos. Los hosts tras CDN
quedan `SIN-PHP` con una nota honesta: la versión del backend **no es observable
pasivamente** y requiere la IP de origen (inventario) o verificación autenticada.
Solo usa DNS. Desactívalo con `--no-auto-origin`.

---

## 🎯 Confidence levels — Niveles de confianza (`--confirm`)

**EN** · Two levels, passive by default:

- **Level 0 — Passive (default).** Verdict based on the advertised PHP version only
  → confidence `solo-versión`. Nothing is sent beyond a banner check.
- **Level 1 — Active confirmation (`--confirm`).** Runs **only on hosts already
  flagged `VULNERABLE`**, with three benign, non-exploitative checks:
  1. **Re-confirm the version** by connecting directly to the host (anti-stale).
  2. **PHP session present** — a benign `upload_progress` multipart POST (PoC
     technique: starts the session at SAPI level even if the app never calls
     `session_start()`), probed across **several common app paths** (`/`,
     `/index.php`, `/login`, `/wp-login.php`, `/admin`, …) until a `PHPSESSID`
     cookie appears.
  3. **Session fixation — differential test** (derived from the PoC, no payloads):
     a fresh SID is first presented cold; if the server accepts it,
     `use_strict_mode=0` fixation is confirmed. If it is rejected (strict mode on),
     the SID is created with a benign `upload_progress` POST and re-presented — if
     it is **now** accepted, the `use_strict_mode` **bypass via upload_progress** is
     confirmed (the real php2shell precondition). Adoption is detected by the
     **absence of a regenerated cookie**, which is how PHP signals acceptance.

  It sets a `confidence` field and **never creates or changes a verdict** — so it
  cannot introduce false positives; it only raises/lowers confidence on an existing
  version-based finding. It does **not** exploit: no code injection, no serialized
  objects, no OOM/UAF, no RCE. **Important:** a "no session signal" result is
  **inconclusive, not safe** — the real injection happens at SAPI level and may not
  be observable remotely; the version-based verdict remains authoritative.

  > ⚠️ **Authorization required.** `--confirm` sends active session/fixation test
  > requests and **creates session state** on the target. Use it only with the
  > client's explicit written permission.

When a passive scan finds VULNERABLE hosts and `--confirm` was not used, an
**interactive terminal** asks whether to run Level 1 and requires you to confirm
authorization before it runs — on the already-found hosts, with no re-scan. In a
non-interactive context (pipeline) it does not block: it prints a reminder instead.

**ES** · Dos niveles, pasivo por defecto:

- **Nivel 0 — Pasivo (default).** Veredicto según la versión de PHP anunciada
  → confianza `solo-versión`. No se envía nada más allá de la comprobación de banner.
- **Nivel 1 — Validación activa (`--confirm`).** Se ejecuta **solo sobre los hosts
  ya marcados `VULNERABLE`**, con tres comprobaciones benignas, sin explotación:
  1. **Re-confirmar la versión** conectando directamente al host (anti-stale).
  2. **Sesión PHP presente** — un POST multipart `upload_progress` benigno (técnica
     de la PoC: inicia la sesión a nivel de SAPI aunque la app no llame a
     `session_start()`), probado en **varias rutas comunes** (`/`, `/index.php`,
     `/login`, `/wp-login.php`, `/admin`, …) hasta que aparece una cookie `PHPSESSID`.
  3. **Fijación — prueba diferencial** (derivada del PoC, sin payloads): se presenta
     un SID nuevo en frío; si el servidor lo acepta, se confirma la fijación por
     `use_strict_mode=0`. Si lo rechaza (strict mode activo), se crea ese SID con un
     POST `upload_progress` benigno y se vuelve a presentar — si **ahora** lo acepta,
     queda confirmado el **bypass de `use_strict_mode` vía upload_progress** (la
     precondición real de php2shell). La adopción se detecta por la **ausencia de
     cookie regenerada**, que es como PHP señala que aceptó el id.

  Fija un campo `confidence` y **nunca crea ni cambia un veredicto** — así no puede
  introducir falsos positivos; solo sube/baja la confianza de un hallazgo ya basado
  en versión. **No** explota: sin inyección de código, sin objetos serializados, sin
  OOM/UAF, sin RCE. **Importante:** un resultado "sin señal de sesión" es
  **inconcluso, no sano** — la inyección real ocurre a nivel de SAPI y puede no ser
  observable en remoto; el veredicto por versión sigue mandando.

  > ⚠️ **Requiere autorización.** `--confirm` envía peticiones activas de prueba de
  > sesión/fijación y **crea estado de sesión** en el objetivo. Úsalo solo con
  > permiso explícito por escrito del cliente.

Niveles de confianza posibles: `solo-versión` · `activa: upload_progress + fijación
confirmadas` · `activa: sesión PHP presente, fijación no adoptada` · `activa: sin
señal de sesión PHP` (inconcluso, no descarta) · `activa: inconcluso (sin respuesta)`.

Cuando un escaneo pasivo encuentra hosts VULNERABLE y no se usó `--confirm`, una
**consola interactiva** pregunta si ejecutar el Nivel 1 y exige confirmar la
autorización antes de correrlo — sobre los hosts ya detectados, sin re-escanear. En
un contexto no interactivo (pipeline) no se bloquea: imprime un aviso en su lugar.

---

## 📤 Output — Salida

**EN** · Colored console table + summary. Optional `--csv` / `--json` export with
rich fields: `verdict`, `php_version`, `fixed_version`, `branch_eol`,
`behind_cdn_waf`, `cdn_waf`, `php_signal`, `connect_ip`, `host_header`,
`origin_auto`, `origin_source`, `server_header`, `confidence`, `active_note`,
`latency_ms`, `checked_at`, …

**ES** · Tabla en consola con color + resumen. Export opcional `--csv` / `--json`
con campos completos: `verdict`, `php_version`, `fixed_version`, `branch_eol`,
`behind_cdn_waf`, `cdn_waf`, `php_signal`, `connect_ip`, `host_header`,
`origin_auto`, `origin_source`, `server_header`, `confidence`, `active_note`,
`latency_ms`, `checked_at`, …

### Exit codes — Códigos de salida

| Code | EN | ES |
|------|----|----|
| `0` | No vulnerable targets. | Ningún objetivo vulnerable. |
| `1` | At least one `VULNERABLE` target (handy for CI). | Al menos un objetivo `VULNERABLE` (útil para CI). |
| `2` | Argument/target error. | Error de argumentos u objetivos. |

---

## ⚠️ Limitations — Limitaciones

**EN**
1. **Banner-based detection.** If the version is hidden (`expose_php=Off`, WAF/CDN
   rewriting headers), the result is `UNKNOWN` — confirm with `php -v`, an SBOM, or
   credentials.
2. **Version alone ≠ exploitable.** php2shell also needs configuration/app
   conditions (`session.upload_progress` on, an LFI, PHP-FPM, classes with
   `__destruct`, …). "VULNERABLE" here means *version in range, unpatched* — the
   right criterion for prioritizing patching.
3. **Distro backports.** Debian/RHEL sometimes patch without bumping the version
   number; a version flagged vulnerable may already be fixed by the distro. Check
   the package changelog.
4. **Auto-origin false positives.** A subdomain like `mail` may point to a
   *different* server than the website. The scanner always shows `origin_source`
   so you can validate it.

**ES**
1. **Detección por banner.** Si la versión está oculta (`expose_php=Off`, WAF/CDN
   reescribiendo cabeceras), el resultado es `DESCONOCIDO` — confirmar con
   `php -v`, SBOM o credenciales.
2. **La versión por sí sola ≠ explotable.** php2shell requiere además condiciones
   de configuración/app (`session.upload_progress` on, un LFI, PHP-FPM, clases con
   `__destruct`…). Aquí "VULNERABLE" significa *versión dentro del rango sin
   parchear* — el criterio correcto para priorizar el parcheo.
3. **Backports de distro.** Debian/RHEL a veces parchean sin cambiar el número de
   versión; una versión marcada como vulnerable puede estar ya corregida por la
   distribución. Revisar el changelog del paquete.
4. **Falsos positivos de auto-origin.** Un subdominio como `mail` puede apuntar a
   un servidor *distinto* del de la web. El scanner siempre muestra `origin_source`
   para que puedas validarlo.

---

## 🗒️ Changelog

### v1.2
- **Active confirmation — Level 1 (`--confirm`)** — opt-in, authorization-gated
  validation on VULNERABLE hosts: version re-confirm + PHP session presence +
  session fixation/SID-adoption. Benign (no exploitation, no RCE) and it **never
  creates or changes a verdict**, only sets a `confidence` field (zero false
  positives by construction).
- **Interactive prompt** — when a scan finds VULNERABLE hosts, the tool asks at the
  end whether to run Level 1 and requires confirming authorization, then validates
  only the already-found hosts without re-scanning (non-interactive runs print a
  reminder instead; `--confirm` skips the prompt).
- **Multi-path session discovery** — Level 1 probes several common application paths
  (`/`, `/index.php`, `/login`, `/wp-login.php`, `/admin`, …) to find a PHP session
  endpoint, instead of only `/`.
- **Differential fixation test** — derived from the PoC (benign, no payloads): a
  fresh SID rejected cold but accepted after a benign `upload_progress` POST confirms
  the `use_strict_mode` bypass; adoption is detected by the absence of a regenerated
  cookie. A "no session signal" result is explicitly flagged inconclusive, not safe.
- New export fields `confidence` and `active_note`.

### v1.1
- **Subdomain enumeration (`-d/--domain`)** — discovers **all** subdomains of a
  domain from multiple **free, no-API-key** sources (crt.sh, HackerTarget /
  DNSDumpster data, AlienVault OTX, CertSpotter, RapidDNS), merged and
  de-duplicated, with per-source retries; choose sources with `--sources`.
- **DNS-aware scanning** — new verdicts `NO-DNS` and `IP-PRIVADA` short-circuit
  non-resolving / RFC1918 hosts instantly, and connection failures are split into
  `FILTRADO` (drop) vs `CERRADO` (RST). No more wasted timeouts, clearer reports.
- **Multi-CDN auto-origin (single targets)** — for an individual `--target`, origin
  discovery triggers behind **any** CDN/WAF (Cloudflare, Akamai, AWS CloudFront/ELB,
  Fastly, Google), with CDN IP-range filtering and a candidate re-check. It does
  **not** run on `-d` scans (see below).
- **No cross-host origin attribution on `-d`** — a shared origin pool was trialled
  but removed: attributing one origin's version to many CDN-fronted hosts caused
  false positives. On `-d`, origins are scanned directly as their own hostnames.
- Faster probing (no double-timeout on dead ports), `--version` flag.

### v1.0
- Initial release — passive PHP version check against patched releases, targets
  via `--target` / `--cidr` / `--file`, CDN detection, CSV/JSON export.

---

## 📚 References — Referencias

- **CVE-2026-109618** — GHSA-w8hw-w9fx-j79w
- **CVE-2026-109619** — GHSA-6wmf-4rv5-p3rp
- Patched / Parcheado: `8.2.35` / `8.3.36` / `8.4.27` / `8.5.12`

> **EN** · Verify the exact affected range against the official PHP advisory.
> **ES** · Verifica el rango exacto afectado contra el advisory oficial de PHP.

---

## 👤 Author & Credits — Autor y Créditos

**Manuel Moreno** — CEO, **GLOBALSECURE**
🌐 [www.globalsecure.cl](https://www.globalsecure.cl)

**EN** · Developed by GLOBALSECURE for authorized vulnerability assessments
(CVE-2026-109618 / CVE-2026-109619 — php2shell).
**ES** · Desarrollado por GLOBALSECURE para evaluaciones de vulnerabilidades
autorizadas (CVE-2026-109618 / CVE-2026-109619 — php2shell).

---

© Manuel Moreno · GLOBALSECURE — [www.globalsecure.cl](https://www.globalsecure.cl)
Todos los derechos reservados. / All rights reserved.
