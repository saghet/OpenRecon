# REVISIÓN DE CTI Y CORRELACIÓN — OPENRECON 3.0 (FASE 4)

> **Fecha:** 2026-11-14  
> **Módulos:** `opencti_client.py`, `misp_client.py`, `stix_taxii_service.py`, `vuln_intel_enrichment.py`, `graph_engine.py`

---

## 1. OPENCTI, MISP, STIX 2.1 Y TAXII 2.1

- **TLS Estricto:** Tanto `OpenCTIClient` como `MISPClient` y `STIX21TaxiiService` utilizan verificación TLS obligatoria (`get_httpx_verify()`) y leen configuración desde variables de entorno (`OPENCTI_URL`, `OPENCTI_TOKEN`, `MISP_URL`, `MISP_KEY`).
- **Importación y Exportación STIX 2.1 (`STIX21TaxiiService`):**
  - Generación de bundles STIX 2.1 con `Identity`, `Indicator`, marcas **TLP** (`TLP:WHITE`, `TLP:GREEN`, `TLP:AMBER`, `TLP:RED`), `confidence`, `valid_from`, `valid_until` y deduplicación determinista por patrón.
  - Importación y deduplicación de bundles STIX 2.1 preservando la mayor confianza y extrayendo TLP/vigencia.
  - Soporte cliente **TAXII 2.1** (`fetch_taxii21_objects`) con TLS estricto.

---

## 2. CISA KEV, EPSS Y NVD (`VulnIntelEnrichmentService`)

- Distingue explícitamente 5 dimensiones en `evaluate_cve_posture()`:
  1. `identified_vulnerability`
  2. `known_exploited` (catálogo CISA KEV)
  3. `exploitation_probability` (FIRST EPSS score + percentile)
  4. `confirmed_exposure` (solo `True` cuando hay validación en objetivo)
  5. `mitigation_available` (guía de mitigación/NVD)

---

## 3. GRAFO DE CORRELACIÓN (`CorrelationGraphEngine`)

- Cada arista en `graph_engine.py` registra `source`, `evidence`, `confidence` (0–100) y el indicador explícito `is_inferred` (`True` si `confidence < 80` o si se marca como inferida), evitando presentar relaciones inferidas como confirmadas.
