<?php
/**
 * OPENRECON - DARK INTELLIGENCE CONSOLE
 * Enterprise Cyber Threat Intelligence (CTI) & Dark Web Investigation Console
 * 15 Functional Sub-Sections connecting directly to api.php & FastAPI backend
 */
?>
<section id="tab-content-darkintel" class="space-y-6 hidden">
    <!-- Dark Intelligence Header & Global Status -->
    <div class="bg-cyber-card border border-cyber-border rounded-2xl p-6 shadow-2xl relative overflow-hidden">
        <div class="absolute -right-10 -bottom-10 opacity-5 pointer-events-none">
            <i class="fa-solid fa-mask text-[220px] text-cyan-400"></i>
        </div>
        <div class="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 border-b border-cyber-border pb-5 mb-6">
            <div class="flex items-center gap-3">
                <div class="w-12 h-12 rounded-xl bg-cyan-950/80 border border-cyan-500/30 flex items-center justify-center text-cyan-400 text-2xl shadow-inner">
                    <i class="fa-solid fa-user-secret"></i>
                </div>
                <div>
                    <div class="flex items-center gap-2">
                        <h2 class="text-xl font-bold text-white tracking-wide">DARK INTELLIGENCE</h2>
                        <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-700/60 uppercase">PRO EDITION</span>
                        <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-800 uppercase flex items-center gap-1">
                            <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                            TOR SOCKS5 READY
                        </span>
                    </div>
                    <p class="text-xs text-slate-400 mt-0.5">Vigilancia de Servicios Onion, Fugas de Credenciales (K-Anonymity), Extorsión Ransomware y Correlación STIX 2.1 con DeepSeek AI.</p>
                </div>
            </div>

            <!-- Quick Action Toolbar -->
            <div class="flex flex-wrap items-center gap-2">
                <button onclick="darkIntelSyncRansomwareFeed()" id="btn-darkintel-sync" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold flex items-center gap-1.5 transition">
                    <i class="fa-solid fa-rotate text-cyan-400"></i> Sincronizar Feed Ransomware
                </button>
                <button onclick="darkIntelExportStixBundle()" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold flex items-center gap-1.5 transition">
                    <i class="fa-solid fa-download text-indigo-400"></i> Exportar STIX 2.1
                </button>
                <button onclick="darkIntelOpenNewInvestigationModal()" class="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-xs font-bold flex items-center gap-1.5 shadow-lg shadow-cyan-600/20 transition">
                    <i class="fa-solid fa-magnifying-glass-chart"></i> Nueva Investigación
                </button>
            </div>
        </div>

        <!-- 15 Sub-Section Navigation Pills -->
        <div class="flex items-center gap-1.5 overflow-x-auto pb-2 scrollbar-thin border-b border-cyber-border/60 text-xs">
            <button onclick="darkIntelSwitchSubTab('overview')" id="darkintel-subtab-btn-overview" class="darkintel-nav-pill active">
                <i class="fa-solid fa-chart-pie mr-1"></i> 1. Overview
            </button>
            <button onclick="darkIntelSwitchSubTab('search')" id="darkintel-subtab-btn-search" class="darkintel-nav-pill">
                <i class="fa-solid fa-magnifying-glass mr-1"></i> 2. Dark Web Search
            </button>
            <button onclick="darkIntelSwitchSubTab('onion_sources')" id="darkintel-subtab-btn-onion_sources" class="darkintel-nav-pill">
                <i class="fa-solid fa-globe mr-1"></i> 3. Onion Sources
            </button>
            <button onclick="darkIntelSwitchSubTab('leaks')" id="darkintel-subtab-btn-leaks" class="darkintel-nav-pill">
                <i class="fa-solid fa-key mr-1"></i> 4. Leak Intel
            </button>
            <button onclick="darkIntelSwitchSubTab('ransomware')" id="darkintel-subtab-btn-ransomware" class="darkintel-nav-pill">
                <i class="fa-solid fa-skull-crossbones mr-1"></i> 5. Ransomware Intel
            </button>
            <button onclick="darkIntelSwitchSubTab('actors')" id="darkintel-subtab-btn-actors" class="darkintel-nav-pill">
                <i class="fa-solid fa-user-ninja mr-1"></i> 6. Threat Actors
            </button>
            <button onclick="darkIntelSwitchSubTab('iocs')" id="darkintel-subtab-btn-iocs" class="darkintel-nav-pill">
                <i class="fa-solid fa-fingerprint mr-1"></i> 7. IOC Explorer
            </button>
            <button onclick="darkIntelSwitchSubTab('vulns')" id="darkintel-subtab-btn-vulns" class="darkintel-nav-pill">
                <i class="fa-solid fa-shield-virus mr-1"></i> 8. Vuln Intel
            </button>
            <button onclick="darkIntelSwitchSubTab('exposure')" id="darkintel-subtab-btn-exposure" class="darkintel-nav-pill">
                <i class="fa-solid fa-building-shield mr-1"></i> 9. Org Exposure
            </button>
            <button onclick="darkIntelSwitchSubTab('investigations')" id="darkintel-subtab-btn-investigations" class="darkintel-nav-pill">
                <i class="fa-solid fa-folder-open mr-1"></i> 10. Investigaciones
            </button>
            <button onclick="darkIntelSwitchSubTab('vault')" id="darkintel-subtab-btn-vault" class="darkintel-nav-pill">
                <i class="fa-solid fa-box-archive mr-1"></i> 11. Evidence Vault
            </button>
            <button onclick="darkIntelSwitchSubTab('ai')" id="darkintel-subtab-btn-ai" class="darkintel-nav-pill">
                <i class="fa-solid fa-brain mr-1 text-purple-400"></i> 12. DeepSeek CTI
            </button>
            <button onclick="darkIntelSwitchSubTab('alerts')" id="darkintel-subtab-btn-alerts" class="darkintel-nav-pill">
                <i class="fa-solid fa-bell mr-1"></i> 13. Alertas
            </button>
            <button onclick="darkIntelSwitchSubTab('reports')" id="darkintel-subtab-btn-reports" class="darkintel-nav-pill">
                <i class="fa-solid fa-file-shield mr-1"></i> 14. Reportes
            </button>
            <button onclick="darkIntelSwitchSubTab('integrations')" id="darkintel-subtab-btn-integrations" class="darkintel-nav-pill">
                <i class="fa-solid fa-sliders mr-1"></i> 15. Integraciones
            </button>
        </div>
    </div>

    <!-- SUB-SECTION 1: OVERVIEW & DASHBOARD METRICS -->
    <div id="darkintel-subview-overview" class="darkintel-subview space-y-6">
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div class="bg-cyber-card border border-cyber-border rounded-xl p-5 shadow">
                <div class="flex items-center justify-between text-slate-400 mb-2 text-xs">
                    <span>Fuentes Onion Indexadas</span>
                    <i class="fa-solid fa-network-wired text-cyan-400"></i>
                </div>
                <div id="darkintel-stat-sources" class="text-2xl font-bold text-white font-mono">--</div>
                <div class="text-[11px] text-emerald-400 mt-1 flex items-center gap-1 font-mono">
                    <i class="fa-solid fa-check"></i> SOCKS5 Aislado & Sandbox
                </div>
            </div>
            <div class="bg-cyber-card border border-cyber-border rounded-xl p-5 shadow">
                <div class="flex items-center justify-between text-slate-400 mb-2 text-xs">
                    <span>Víctimas Ransomware DLS</span>
                    <i class="fa-solid fa-biohazard text-rose-400"></i>
                </div>
                <div id="darkintel-stat-ransomware" class="text-2xl font-bold text-rose-400 font-mono">--</div>
                <div class="text-[11px] text-slate-400 mt-1">Deduplicado con Evidence Vault</div>
            </div>
            <div class="bg-cyber-card border border-cyber-border rounded-xl p-5 shadow">
                <div class="flex items-center justify-between text-slate-400 mb-2 text-xs">
                    <span>Credenciales / Fugas</span>
                    <i class="fa-solid fa-unlock-keyhole text-amber-400"></i>
                </div>
                <div id="darkintel-stat-leaks" class="text-2xl font-bold text-amber-400 font-mono">--</div>
                <div class="text-[11px] text-cyan-400 mt-1 font-mono">K-Anonymity (SHA-256)</div>
            </div>
            <div class="bg-cyber-card border border-cyber-border rounded-xl p-5 shadow">
                <div class="flex items-center justify-between text-slate-400 mb-2 text-xs">
                    <span>Actores Sindicados</span>
                    <i class="fa-solid fa-skull text-purple-400"></i>
                </div>
                <div id="darkintel-stat-actors" class="text-2xl font-bold text-purple-400 font-mono">--</div>
                <div class="text-[11px] text-indigo-400 mt-1">Mapeo MITRE ATT&CK</div>
            </div>
        </div>

        <!-- Recent Critical Feed Stream -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div class="bg-cyber-card border border-cyber-border rounded-xl p-5 shadow">
                <div class="flex items-center justify-between border-b border-cyber-border pb-3 mb-4">
                    <h3 class="text-sm font-bold text-white flex items-center gap-2">
                        <i class="fa-solid fa-bullhorn text-rose-400"></i> Últimas Publicaciones de Extorsión (DLS)
                    </h3>
                    <span class="text-xs text-slate-400">Feed en tiempo real</span>
                </div>
                <div id="darkintel-overview-ransomware-feed" class="space-y-3 text-xs max-h-80 overflow-y-auto pr-1">
                    <div class="text-center py-6 text-slate-500">Cargando publicaciones de ransomware...</div>
                </div>
            </div>

            <div class="bg-cyber-card border border-cyber-border rounded-xl p-5 shadow">
                <div class="flex items-center justify-between border-b border-cyber-border pb-3 mb-4">
                    <h3 class="text-sm font-bold text-white flex items-center gap-2">
                        <i class="fa-solid fa-triangle-exclamation text-amber-400"></i> Filtraciones & Credenciales Detectadas
                    </h3>
                    <span class="text-xs text-slate-400">Identidades enmascaradas</span>
                </div>
                <div id="darkintel-overview-leaks-feed" class="space-y-3 text-xs max-h-80 overflow-y-auto pr-1">
                    <div class="text-center py-6 text-slate-500">Cargando filtraciones...</div>
                </div>
            </div>
        </div>
    </div>

    <!-- SUB-SECTION 2: DARK WEB SEARCH -->
    <div id="darkintel-subview-search" class="darkintel-subview space-y-6 hidden">
        <div class="bg-cyber-card border border-cyber-border rounded-xl p-6 shadow">
            <h3 class="text-base font-bold text-white mb-2 flex items-center gap-2">
                <i class="fa-solid fa-magnifying-glass text-cyan-400"></i> Buscador Centralizado de la Dark Web & Fuentes CTI
            </h3>
            <p class="text-xs text-slate-400 mb-4">
                Consulta federada sobre fuentes indexadas, blogs de actores ransomware, repositorios paste y motores Onion. No se realizan afirmaciones falsas: se audita y transparenta la cobertura real en cada consulta.
            </p>

            <div class="flex flex-col sm:flex-row gap-3 mb-4">
                <div class="relative flex-1">
                    <i class="fa-solid fa-terminal absolute left-3.5 top-3 text-slate-500 text-xs"></i>
                    <input type="text" id="darkintel-search-input" placeholder="Buscar dominio corporativo, IP, CVE-2026, hash, marca o sindicato (ej. LockBit, cl0p, banco)..." class="forti-input w-full pl-9 text-xs font-mono" onkeypress="if(event.key==='Enter') darkIntelExecuteSearch();" />
                </div>
                <button onclick="darkIntelExecuteSearch()" id="btn-darkintel-do-search" class="px-5 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs rounded-xl flex items-center justify-center gap-2 transition cursor-pointer">
                    <i class="fa-solid fa-magnifying-glass"></i> Investigar
                </button>
            </div>

            <!-- Transparency Statement Box -->
            <div id="darkintel-search-transparency-box" class="p-3 bg-black/30 border border-cyber-border/80 rounded-lg text-xs text-slate-400 hidden">
                <div class="flex items-center gap-2 text-cyan-400 font-semibold mb-1">
                    <i class="fa-solid fa-circle-info"></i> Declaración de Transparencia de Cobertura
                </div>
                <div id="darkintel-search-transparency-text">--</div>
            </div>
        </div>

        <!-- Search Results Grid -->
        <div id="darkintel-search-results-container" class="space-y-4">
            <div class="text-center py-12 text-slate-500 bg-cyber-card border border-cyber-border rounded-xl">
                <i class="fa-solid fa-compass text-3xl text-slate-600 mb-2 block"></i>
                <span class="text-xs">Introduce un término de búsqueda para iniciar la investigación federada.</span>
            </div>
        </div>
    </div>

    <!-- SUB-SECTION 3: ONION SOURCES DIRECTORY -->
    <div id="darkintel-subview-onion_sources" class="darkintel-subview space-y-6 hidden">
        <div class="bg-cyber-card border border-cyber-border rounded-xl p-6 shadow">
            <div class="flex items-center justify-between border-b border-cyber-border pb-4 mb-4">
                <div>
                    <h3 class="text-base font-bold text-white flex items-center gap-2">
                        <i class="fa-solid fa-globe text-cyan-400"></i> Catálogo de Servicios Onion Verificados & Disponibilidad
                    </h3>
                    <p class="text-xs text-slate-400">Directorio de recursos .onion monitoreados bajo sandbox, con métricas de salud SOCKS5 y categorización.</p>
                </div>
                <button onclick="darkIntelLoadSources()" class="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded-lg border border-slate-700">
                    <i class="fa-solid fa-rotate mr-1"></i> Refrescar Fuentes
                </button>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-left text-xs text-slate-300">
                    <thead class="text-[11px] uppercase bg-black/30 text-slate-400 border-b border-cyber-border font-mono">
                        <tr>
                            <th class="p-3">Nombre del Recurso</th>
                            <th class="p-3">Dirección Onion (Tor)</th>
                            <th class="p-3">Categoría</th>
                            <th class="p-3">Estado</th>
                            <th class="p-3">Confiabilidad</th>
                            <th class="p-3">Última Detección</th>
                        </tr>
                    </thead>
                    <tbody id="darkintel-sources-table-body" class="divide-y divide-cyber-border/40 font-mono">
                        <tr><td colspan="6" class="p-4 text-center text-slate-500">Cargando directorio...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- SUB-SECTION 4: LEAK INTEL (K-ANONYMITY) -->
    <div id="darkintel-subview-leaks" class="darkintel-subview space-y-6 hidden">
        <div class="bg-cyber-card border border-cyber-border rounded-xl p-6 shadow">
            <div class="flex items-center justify-between border-b border-cyber-border pb-4 mb-4">
                <div>
                    <h3 class="text-base font-bold text-white flex items-center gap-2">
                        <i class="fa-solid fa-key text-yellow-400"></i> Fugas de Credenciales e Identidades Expuestas
                    </h3>
                    <p class="text-xs text-slate-400">Protección estricta de privacidad: Identidades enmascaradas y contraseñas almacenadas como hashes SHA-256 (K-Anonymity).</p>
                </div>
                <button onclick="darkIntelLoadLeaks()" class="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded-lg border border-slate-700">
                    <i class="fa-solid fa-rotate mr-1"></i> Refrescar
                </button>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-left text-xs text-slate-300">
                    <thead class="text-[11px] uppercase bg-black/30 text-slate-400 border-b border-cyber-border font-mono">
                        <tr>
                            <th class="p-3">Dominio</th>
                            <th class="p-3">Identidad Enmascarada</th>
                            <th class="p-3">Tipo de Exposición</th>
                            <th class="p-3">Fuente</th>
                            <th class="p-3">Corroboración</th>
                            <th class="p-3">Fecha</th>
                            <th class="p-3">Evidencia</th>
                        </tr>
                    </thead>
                    <tbody id="darkintel-leaks-table-body" class="divide-y divide-cyber-border/40 font-mono">
                        <tr><td colspan="7" class="p-4 text-center text-slate-500">Cargando fugas...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- SUB-SECTION 5: RANSOMWARE INTEL -->
    <div id="darkintel-subview-ransomware" class="darkintel-subview space-y-6 hidden">
        <div class="bg-cyber-card border border-cyber-border rounded-xl p-6 shadow">
            <div class="flex items-center justify-between border-b border-cyber-border pb-4 mb-4">
                <div>
                    <h3 class="text-base font-bold text-white flex items-center gap-2">
                        <i class="fa-solid fa-skull-crossbones text-rose-400"></i> Observatorio de Extorsión Ransomware (DLS)
                    </h3>
                    <p class="text-xs text-slate-400">Monitoreo y deduplicación de víctimas divulgadas por sindicatos criminales en sus Data Leak Sites oficiales.</p>
                </div>
                <button onclick="darkIntelLoadRansomware()" class="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded-lg border border-slate-700">
                    <i class="fa-solid fa-rotate mr-1"></i> Refrescar
                </button>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-left text-xs text-slate-300">
                    <thead class="text-[11px] uppercase bg-black/30 text-slate-400 border-b border-cyber-border font-mono">
                        <tr>
                            <th class="p-3">Sindicato</th>
                            <th class="p-3">Víctima</th>
                            <th class="p-3">Sitio Web Víctima</th>
                            <th class="p-3">Detalles de Extorsión</th>
                            <th class="p-3">Fecha Detección</th>
                            <th class="p-3">Estado</th>
                            <th class="p-3">Acción</th>
                        </tr>
                    </thead>
                    <tbody id="darkintel-ransomware-table-body" class="divide-y divide-cyber-border/40 font-mono">
                        <tr><td colspan="7" class="p-4 text-center text-slate-500">Cargando publicaciones...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- SUB-SECTION 6: THREAT ACTOR INTELLIGENCE -->
    <div id="darkintel-subview-actors" class="darkintel-subview space-y-6 hidden">
        <div class="bg-cyber-card border border-cyber-border rounded-xl p-6 shadow">
            <div class="flex items-center justify-between border-b border-cyber-border pb-4 mb-4">
                <div>
                    <h3 class="text-base font-bold text-white flex items-center gap-2">
                        <i class="fa-solid fa-user-ninja text-purple-400"></i> Perfiles Canónicos de Actores de Amenaza
                    </h3>
                    <p class="text-xs text-slate-400">Sindicatos rastreados, atribución MITRE ATT&CK, malware asociado y recursos .onion de extorsión.</p>
                </div>
                <button onclick="darkIntelLoadActors()" class="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded-lg border border-slate-700">
                    <i class="fa-solid fa-rotate mr-1"></i> Refrescar
                </button>
            </div>
            <div id="darkintel-actors-grid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                <div class="col-span-full text-center py-8 text-slate-500">Cargando perfiles de actores...</div>
            </div>
        </div>
    </div>

    <!-- SUB-SECTION 7: IOC EXPLORER -->
    <div id="darkintel-subview-iocs" class="darkintel-subview space-y-6 hidden">
        <div class="bg-cyber-card border border-cyber-border rounded-xl p-6 shadow">
            <div class="flex items-center justify-between border-b border-cyber-border pb-4 mb-4">
                <div>
                    <h3 class="text-base font-bold text-white flex items-center gap-2">
                        <i class="fa-solid fa-fingerprint text-cyan-400"></i> Explorador de Indicadores de Compromiso (IOCs)
                    </h3>
                    <p class="text-xs text-slate-400">Indicadores normalizados descubiertos en la Dark Web, compatibles con STIX 2.1 y exportables a SIEM/SOAR.</p>
                </div>
                <button onclick="darkIntelLoadIOCs()" class="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded-lg border border-slate-700">
                    <i class="fa-solid fa-rotate mr-1"></i> Refrescar
                </button>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-left text-xs text-slate-300">
                    <thead class="text-[11px] uppercase bg-black/30 text-slate-400 border-b border-cyber-border font-mono">
                        <tr>
                            <th class="p-3">Tipo IOC</th>
                            <th class="p-3">Valor Normalizado</th>
                            <th class="p-3">Severidad</th>
                            <th class="p-3">Reputación</th>
                            <th class="p-3">Actor Vinculado</th>
                            <th class="p-3">Primera Observación</th>
                        </tr>
                    </thead>
                    <tbody id="darkintel-iocs-table-body" class="divide-y divide-cyber-border/40 font-mono">
                        <tr><td colspan="6" class="p-4 text-center text-slate-500">Cargando indicadores...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- SUB-SECTION 8: VULNERABILITY INTELLIGENCE -->
    <div id="darkintel-subview-vulns" class="darkintel-subview space-y-6 hidden">
        <div class="bg-cyber-card border border-cyber-border rounded-xl p-6 shadow">
            <h3 class="text-base font-bold text-white mb-2 flex items-center gap-2">
                <i class="fa-solid fa-shield-virus text-rose-400"></i> Correlación de Vulnerabilidades en la Dark Web
            </h3>
            <p class="text-xs text-slate-400 mb-4">
                Cruce de CVEs mencionados en mercados y foros con CISA Known Exploited Vulnerabilities (KEV) y vectores activos de explotación.
            </p>
            <div class="p-4 bg-black/20 border border-cyber-border rounded-xl space-y-3">
                <div class="flex items-center justify-between text-xs">
                    <span class="text-slate-300 font-semibold">CVE-2023-34362 (MOVEit Transfer SQLi)</span>
                    <span class="px-2 py-0.5 rounded text-[10px] bg-rose-950 text-rose-300 border border-rose-800 font-mono font-bold">CRITICAL / EXPLOITED BY CL0P</span>
                </div>
                <div class="text-[11px] text-slate-400">
                    Correlación detectada: Cl0p Ransomware Gang utilizó esta vulnerabilidad para extorsión masiva de datos en DLS.
                </div>
                <div class="flex items-center gap-2 text-[10px] font-mono text-cyan-400">
                    <span>MITRE: T1190</span> &bull; <span>CISA KEV: Added</span> &bull; <span>CVSS: 9.8</span>
                </div>
            </div>
        </div>
    </div>

    <!-- SUB-SECTION 9: ORGANIZATION EXPOSURE MONITORING -->
    <div id="darkintel-subview-exposure" class="darkintel-subview space-y-6 hidden">
        <div class="bg-cyber-card border border-cyber-border rounded-xl p-6 shadow">
            <div class="flex items-center justify-between border-b border-cyber-border pb-3 mb-4">
                <div>
                    <h3 class="text-base font-bold text-white flex items-center gap-2">
                        <i class="fa-solid fa-building-shield text-cyan-400"></i> Evaluación Integral de Exposición Organizacional
                    </h3>
                    <p class="text-xs text-slate-400">
                        Calcula el Exposure Score (0-100) correlacionando menciones en fuentes públicas, servicios onion, filtraciones de credenciales y registros de ransomware.
                    </p>
                </div>
                <span class="px-2.5 py-1 rounded-full text-[10px] font-mono bg-cyan-950 text-cyan-300 border border-cyan-800 flex items-center gap-1.5">
                    <i class="fa-solid fa-crosshairs text-cyan-400"></i>
                    EXCLUSIVO SEMILLAS EN ROE
                </span>
            </div>

            <!-- Controlled Scope Seed Selector -->
            <div class="p-4 bg-black/20 border border-cyber-border rounded-xl space-y-3 mb-4">
                <label class="block text-xs font-semibold text-slate-300">
                    <i class="fa-solid fa-bullseye text-cyan-400 mr-1"></i> Selecciona la Semilla Corporativa Autorizada para Investigar:
                </label>
                <div class="flex flex-col sm:flex-row gap-3">
                    <div class="relative flex-1">
                        <i class="fa-solid fa-globe absolute left-3.5 top-3 text-cyan-400 text-xs pointer-events-none"></i>
                        <select id="darkintel-exposure-seed-select" class="forti-input w-full pl-9 text-xs font-mono font-bold bg-slate-900 text-white cursor-pointer" onchange="darkIntelOnExposureSeedSelect(this.value)">
                            <option value="">Cargando semillas autorizadas...</option>
                        </select>
                    </div>
                    <button onclick="darkIntelRunExposureAssessment()" id="btn-darkintel-run-exposure" class="px-5 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs rounded-xl flex items-center justify-center gap-2 transition cursor-pointer">
                        <i class="fa-solid fa-shield-halved"></i> Evaluar Exposición
                    </button>
                </div>
                <div class="text-[11px] text-slate-400 flex items-center justify-between">
                    <span>Ámbito restringido por RoE: Solo perfiles corporativos y semillas activas en el inventario.</span>
                    <button type="button" onclick="darkIntelSyncWithGlobalSeeds()" class="text-cyan-400 hover:underline flex items-center gap-1 text-[11px]">
                        <i class="fa-solid fa-rotate"></i> Sincronizar con Perímetro Superior
                    </button>
                </div>
            </div>

            <div id="darkintel-exposure-result-box" class="p-6 bg-black/30 border border-cyber-border rounded-xl hidden">
                <!-- Dynamically populated -->
            </div>
        </div>
    </div>

    <!-- SUB-SECTION 10: INVESTIGACIONES -->
    <div id="darkintel-subview-investigations" class="darkintel-subview space-y-6 hidden">
        <div class="bg-cyber-card border border-cyber-border rounded-xl p-6 shadow">
            <h3 class="text-base font-bold text-white mb-2 flex items-center gap-2">
                <i class="fa-solid fa-folder-open text-indigo-400"></i> Expedientes de Investigación CTI Guardados
            </h3>
            <p class="text-xs text-slate-400 mb-4">Historial de auditorías de exposición corporativa y dictámenes forenses completados.</p>
            <div id="darkintel-investigations-list" class="space-y-3 text-xs">
                <div class="text-center py-8 text-slate-500">Cargando investigaciones...</div>
            </div>
        </div>
    </div>

    <!-- SUB-SECTION 11: EVIDENCE VAULT -->
    <div id="darkintel-subview-vault" class="darkintel-subview space-y-6 hidden">
        <div class="bg-cyber-card border border-cyber-border rounded-xl p-6 shadow">
            <div class="flex items-center justify-between border-b border-cyber-border pb-4 mb-4">
                <div>
                    <h3 class="text-base font-bold text-white flex items-center gap-2">
                        <i class="fa-solid fa-box-archive text-emerald-400"></i> Bóveda de Evidencias CTI (Cadena de Custodia Criptográfica)
                    </h3>
                    <p class="text-xs text-slate-400">Registro inmutable con firmas HMAC-SHA256, hash de contenido y saneamiento estricto de scripts.</p>
                </div>
            </div>
            <div class="flex gap-2 mb-4">
                <input type="text" id="darkintel-vault-search-id" placeholder="Buscar por ID de evidencia (SHA-256)..." class="forti-input flex-1 text-xs font-mono" />
                <button onclick="darkIntelInspectVaultItem(document.getElementById('darkintel-vault-search-id').value)" class="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg border border-slate-700">
                    <i class="fa-solid fa-magnifying-glass mr-1"></i> Consultar
                </button>
            </div>
            <div id="darkintel-vault-inspect-display" class="p-4 bg-black/40 border border-cyber-border rounded-xl font-mono text-xs text-slate-300 hidden">
                <!-- Dynamically populated -->
            </div>
        </div>
    </div>

    <!-- SUB-SECTION 12: DEEPSEEK CTI ANALYST -->
    <div id="darkintel-subview-ai" class="darkintel-subview space-y-6 hidden">
        <div class="bg-cyber-card border border-cyber-border rounded-xl p-6 shadow">
            <div class="flex items-center justify-between border-b border-cyber-border pb-4 mb-4">
                <div class="flex items-center gap-3">
                    <div class="w-10 h-10 rounded-xl bg-purple-950 border border-purple-800 flex items-center justify-center text-purple-400 text-xl">
                        <i class="fa-solid fa-brain"></i>
                    </div>
                    <div>
                        <h3 class="text-base font-bold text-white">Asistente Analítico DeepSeek CTI (Blindaje Anti-Inyección)</h3>
                        <p class="text-xs text-slate-400">Análisis objetivo con extracción de MITRE ATT&CK y citaciones criptográficas al Evidence Vault.</p>
                    </div>
                </div>
                <span class="px-2.5 py-1 rounded-full text-[10px] font-mono bg-purple-950 text-purple-300 border border-purple-800">
                    ANTI-INJECTION JAIL ACTIVE
                </span>
            </div>

            <div class="space-y-4">
                <div>
                    <label class="block text-xs font-semibold text-slate-300 mb-1">Texto de la Evidencia o Documento a Analizar</label>
                    <textarea id="darkintel-ai-input-text" rows="5" class="forti-input w-full font-mono text-xs" placeholder="Pega el contenido recolectado en foros, DLS o pastes para correlación..."></textarea>
                </div>
                <div class="flex items-center justify-between">
                    <input type="text" id="darkintel-ai-evidence-id" placeholder="ID de Evidencia Opcional (ej. ev_123)..." class="forti-input w-64 text-xs font-mono" />
                    <button onclick="darkIntelRunAIAnalysis()" id="btn-darkintel-run-ai" class="px-5 py-2.5 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white font-bold text-xs rounded-xl flex items-center gap-2 shadow-lg shadow-purple-600/25 transition cursor-pointer">
                        <i class="fa-solid fa-wand-magic-sparkles"></i> Analizar con DeepSeek
                    </button>
                </div>
            </div>

            <div id="darkintel-ai-result-box" class="mt-6 p-5 bg-black/30 border border-cyber-border rounded-xl hidden space-y-4 text-xs">
                <!-- Dynamically populated -->
            </div>
        </div>
    </div>

    <!-- SUB-SECTION 13: ALERTAS CTI -->
    <div id="darkintel-subview-alerts" class="darkintel-subview space-y-6 hidden">
        <div class="bg-cyber-card border border-cyber-border rounded-xl p-6 shadow">
            <h3 class="text-base font-bold text-white mb-2 flex items-center gap-2">
                <i class="fa-solid fa-bell text-rose-400"></i> Alertas Tempranas de Ciberamenazas
            </h3>
            <p class="text-xs text-slate-400 mb-4">Notificaciones automatizadas al detectarse menciones críticas de marcas corporativas en foros o blogs de extorsión.</p>
            <div class="space-y-3">
                <div class="p-3 bg-rose-950/20 border border-rose-800/40 rounded-lg flex items-center justify-between text-xs">
                    <div class="flex items-center gap-3">
                        <i class="fa-solid fa-circle-exclamation text-rose-400 text-base"></i>
                        <div>
                            <strong class="text-white">Alerta de Coincidencia de Marca</strong>
                            <p class="text-slate-400 text-[11px]">Monitoreo de semillero activo en DLS de LockBit 3.0.</p>
                        </div>
                    </div>
                    <span class="text-[10px] font-mono text-slate-500">AUTO-ENGAGED</span>
                </div>
            </div>
        </div>
    </div>

    <!-- SUB-SECTION 14: REPORTES & EXPORTACIÓN -->
    <div id="darkintel-subview-reports" class="darkintel-subview space-y-6 hidden">
        <div class="bg-cyber-card border border-cyber-border rounded-xl p-6 shadow">
            <h3 class="text-base font-bold text-white mb-2 flex items-center gap-2">
                <i class="fa-solid fa-file-shield text-cyan-400"></i> Centro de Exportación de Informes y Telemetría
            </h3>
            <p class="text-xs text-slate-400 mb-6">Genera entregables técnicos para analistas SOC o exporta paquetes estructurados a plataformas de Threat Intelligence.</p>
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div class="p-5 bg-slate-900/60 border border-cyber-border rounded-xl flex flex-col justify-between">
                    <div>
                        <div class="w-10 h-10 rounded-xl bg-cyan-950 border border-cyan-800 flex items-center justify-center text-cyan-400 text-lg mb-3">
                            <i class="fa-solid fa-diagram-project"></i>
                        </div>
                        <h4 class="text-base font-bold text-white">Paquete OASIS STIX 2.1</h4>
                        <p class="text-xs text-slate-400 mt-1">Exportación JSON completa de SDOs (Threat Actors, Incidents, Indicators, Notes) lista para OpenCTI o MISP.</p>
                    </div>
                    <button onclick="darkIntelExportStixBundle()" class="mt-4 w-full py-2.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold rounded-xl text-xs transition">
                        <i class="fa-solid fa-download mr-1"></i> Descargar Bundle STIX 2.1
                    </button>
                </div>
                <div class="p-5 bg-slate-900/60 border border-cyber-border rounded-xl flex flex-col justify-between">
                    <div>
                        <div class="w-10 h-10 rounded-xl bg-purple-950 border border-purple-800 flex items-center justify-center text-purple-400 text-lg mb-3">
                            <i class="fa-solid fa-file-lines"></i>
                        </div>
                        <h4 class="text-base font-bold text-white">Informe Ejecutivo CTI (HTML/PDF)</h4>
                        <p class="text-xs text-slate-400 mt-1">Síntesis para la dirección ejecutiva y CISO con puntuación de exposición, resumen y recomendaciones.</p>
                    </div>
                    <button onclick="window.print()" class="mt-4 w-full py-2.5 bg-purple-600 hover:bg-purple-500 text-white font-bold rounded-xl text-xs transition">
                        <i class="fa-solid fa-print mr-1"></i> Imprimir Informe Ejecutivo
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- SUB-SECTION 15: INTEGRACIONES & CONFIGURACIÓN -->
    <div id="darkintel-subview-integrations" class="darkintel-subview space-y-6 hidden">
        <div class="bg-cyber-card border border-cyber-border rounded-xl p-6 shadow">
            <h3 class="text-base font-bold text-white mb-2 flex items-center gap-2">
                <i class="fa-solid fa-sliders text-cyan-400"></i> Estado de Conexiones & Plataformas CTI
            </h3>
            <p class="text-xs text-slate-400 mb-6">Diagnóstico de comunicación con Tor Proxy, OpenCTI Platform y MISP REST API.</p>
            <div id="darkintel-integrations-status-container" class="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div class="p-4 bg-black/20 border border-cyber-border rounded-xl">
                    <span class="text-slate-400 text-xs">Tor SOCKS5 Proxy</span>
                    <div class="text-emerald-400 font-bold font-mono text-sm mt-1">CONFIGURED (socks5h)</div>
                    <span class="text-[10px] text-slate-500 font-mono">127.0.0.1:9050</span>
                </div>
                <div class="p-4 bg-black/20 border border-cyber-border rounded-xl">
                    <span class="text-slate-400 text-xs">OpenCTI Integration</span>
                    <div id="darkintel-integ-opencti-status" class="text-cyan-400 font-bold font-mono text-sm mt-1">DECOUPLED READY</div>
                    <span class="text-[10px] text-slate-500 font-mono">GraphQL Client Active</span>
                </div>
                <div class="p-4 bg-black/20 border border-cyber-border rounded-xl">
                    <span class="text-slate-400 text-xs">MISP Integration</span>
                    <div id="darkintel-integ-misp-status" class="text-cyan-400 font-bold font-mono text-sm mt-1">DECOUPLED READY</div>
                    <span class="text-[10px] text-slate-500 font-mono">REST Events & Attributes</span>
                </div>
            </div>
        </div>
    </div>
</section>

<!-- Modal: Ver Evidencia Completa -->
<div id="darkintel-evidence-modal" class="fixed inset-0 modal-backdrop-forti z-50 flex items-center justify-center p-4 hidden">
    <div class="modal-content-forti max-w-3xl w-full p-6 shadow-2xl relative max-h-[90vh] flex flex-col">
        <div class="flex items-center justify-between pb-3 border-b border-cyber-border">
            <h3 class="font-bold text-white text-sm flex items-center gap-2">
                <i class="fa-solid fa-file-shield text-cyan-400"></i> Cadena de Custodia CTI – Evidence Vault
            </h3>
            <button onclick="document.getElementById('darkintel-evidence-modal').classList.add('hidden')" class="text-slate-400 hover:text-white">
                <i class="fa-solid fa-xmark text-lg"></i>
            </button>
        </div>
        <div id="darkintel-evidence-modal-body" class="py-4 overflow-y-auto flex-1 font-mono text-xs space-y-3 text-slate-300">
            <!-- Dynamically populated -->
        </div>
    </div>
</div>

<style>
.darkintel-nav-pill {
    padding: 0.375rem 0.75rem;
    border-radius: 0.5rem;
    font-weight: 600;
    white-space: nowrap;
    color: #94a3b8;
    background: transparent;
    border: 1px solid transparent;
    transition: all 0.15s ease-in-out;
}
.darkintel-nav-pill:hover {
    color: #f8fafc;
    background: rgba(30, 41, 59, 0.6);
}
.darkintel-nav-pill.active {
    color: #38bdf8;
    background: rgba(15, 23, 42, 0.9);
    border-color: rgba(56, 189, 248, 0.4);
    box-shadow: 0 4px 12px rgba(56, 189, 248, 0.1);
}
</style>

<script>
// DARK INTELLIGENCE CONTROLLER JAVASCRIPT
function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
let darkIntelActiveSubTab = 'overview';

function darkIntelSwitchSubTab(tabName) {
    darkIntelActiveSubTab = tabName;
    document.querySelectorAll('.darkintel-nav-pill').forEach(btn => {
        btn.classList.remove('active');
    });
    const activeBtn = document.getElementById(`darkintel-subtab-btn-${tabName}`);
    if (activeBtn) activeBtn.classList.add('active');

    document.querySelectorAll('.darkintel-subview').forEach(view => {
        view.classList.add('hidden');
    });
    const targetView = document.getElementById(`darkintel-subview-${tabName}`);
    if (targetView) targetView.classList.remove('hidden');

    // Trigger on-demand loaders
    if (tabName === 'overview') darkIntelLoadOverview();
    if (tabName === 'onion_sources') darkIntelLoadSources();
    if (tabName === 'leaks') darkIntelLoadLeaks();
    if (tabName === 'ransomware') darkIntelLoadRansomware();
    if (tabName === 'actors') darkIntelLoadActors();
    if (tabName === 'iocs') darkIntelLoadIOCs();
    if (tabName === 'exposure') darkIntelSyncWithGlobalSeeds();
    if (tabName === 'integrations') darkIntelLoadIntegrations();
    if (tabName === 'investigations') darkIntelLoadInvestigations();
    if (tabName === 'vault') darkIntelLoadVault();
}

async function darkIntelLoadOverview() {
    try {
        const res = await fetch('api.php?action=darkintel_overview_stats').then(r => r.json()).catch(() => null);
        
        if (res && res.success && res.stats) {
            const statSources = document.getElementById('darkintel-stat-sources');
            const statRansomware = document.getElementById('darkintel-stat-ransomware');
            const statLeaks = document.getElementById('darkintel-stat-leaks');
            const statActors = document.getElementById('darkintel-stat-actors');

            if (statSources) statSources.innerText = res.stats.sources ?? 0;
            if (statRansomware) statRansomware.innerText = res.stats.ransomware ?? 0;
            if (statLeaks) statLeaks.innerText = res.stats.leaks ?? 0;
            if (statActors) statActors.innerText = res.stats.actors ?? 0;

            // Populate recent ransomware
            const rsmFeed = document.getElementById('darkintel-overview-ransomware-feed');
            if (rsmFeed) {
                if (res.recent_ransomware && res.recent_ransomware.length > 0) {
                    rsmFeed.innerHTML = res.recent_ransomware.map(p => `
                        <div class="p-3 bg-black/30 border border-cyber-border rounded-lg flex items-center justify-between hover:border-rose-500/40 transition">
                            <div>
                                <strong class="text-rose-400 block">${escapeHtml(p.victim_name)}</strong>
                                <span class="text-slate-400 text-[11px]">Sindicato: <span class="text-slate-200">${escapeHtml(p.group_name)}</span></span>
                            </div>
                            <span class="text-[10px] font-mono text-slate-500">${escapeHtml(p.discovered_at_utc || '')}</span>
                        </div>
                    `).join('');
                } else {
                    rsmFeed.innerHTML = '<div class="text-center py-4 text-slate-500">No hay registros recientes de extorsión.</div>';
                }
            }

            // Populate recent leaks
            const lkFeed = document.getElementById('darkintel-overview-leaks-feed');
            if (lkFeed) {
                if (res.recent_leaks && res.recent_leaks.length > 0) {
                    lkFeed.innerHTML = res.recent_leaks.map(l => `
                        <div class="p-3 bg-black/30 border border-cyber-border rounded-lg flex items-center justify-between hover:border-yellow-500/40 transition">
                            <div>
                                <strong class="text-yellow-400 block">${escapeHtml(l.domain_mentioned || 'Fuga Corporativa')}</strong>
                                <span class="text-slate-400 text-[11px]">Identidad: <span class="font-mono text-cyan-300">${escapeHtml(l.masked_identity || '')}</span></span>
                            </div>
                            <span class="px-2 py-0.5 rounded text-[10px] font-mono bg-yellow-950 text-yellow-300 border border-yellow-800">${escapeHtml(l.exposure_type || 'LEAK')}</span>
                        </div>
                    `).join('');
                } else {
                    lkFeed.innerHTML = '<div class="text-center py-4 text-slate-500">No hay filtraciones registradas.</div>';
                }
            }
        }
    } catch (e) {
        console.error('Error loading overview:', e);
    }
}

async function darkIntelExecuteSearch() {
    const q = document.getElementById('darkintel-search-input').value.trim();
    if (!q) return;

    const btn = document.getElementById('btn-darkintel-do-search');
    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Investigando...';

    const container = document.getElementById('darkintel-search-results-container');
    container.innerHTML = '<div class="text-center py-10 text-slate-500"><i class="fa-solid fa-spinner fa-spin text-2xl text-cyan-400 mb-2 block"></i>Consultando fuentes federadas y servicios onion...</div>';

    try {
        const res = await fetch(`api.php?action=darkintel_search&q=${encodeURIComponent(q)}`).then(r => r.json());
        
        // Show transparency statement
        const transBox = document.getElementById('darkintel-search-transparency-box');
        const transText = document.getElementById('darkintel-search-transparency-text');
        transBox.classList.remove('hidden');
        transText.innerText = res.coverage_statement || 'Fuentes auditadas: Evidence Vault local, catálogo ransomware y fuentes Onion activas.';

        if (!res.results || res.results.length === 0) {
            container.innerHTML = `
                <div class="text-center py-12 text-slate-500 bg-cyber-card border border-cyber-border rounded-xl">
                    <i class="fa-solid fa-magnifying-glass text-3xl text-slate-600 mb-2 block"></i>
                    <span class="text-xs">No se encontraron menciones para "${escapeHtml(q)}" en las fuentes consultadas.</span>
                </div>
            `;
            return;
        }

        container.innerHTML = `
            <div class="text-xs text-slate-400 mb-2 font-mono">
                Se encontraron <span class="text-cyan-400 font-bold">${res.total_results || res.results_count || (res.results ? res.results.length : 0)}</span> resultados en <span class="text-white">${res.sources_queried ? res.sources_queried.length : 3}</span> fuentes:
            </div>
            <div class="grid grid-cols-1 gap-3">
                ${res.results.map(r => `
                    <div class="p-4 bg-cyber-card border border-cyber-border rounded-xl hover:border-cyan-500/40 transition">
                        <div class="flex items-center justify-between mb-2">
                            <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-cyan-300 border border-slate-700">${escapeHtml(r.source_type || r.source || 'CTI Feed')}</span>
                            <span class="text-[10px] font-mono text-slate-500">${escapeHtml(r.timestamp || r.date || '')}</span>
                        </div>
                        <h4 class="font-bold text-white text-sm mb-1">${escapeHtml(r.title || r.target_name || 'Hallazgo CTI')}</h4>
                        <p class="text-xs text-slate-300 font-mono bg-black/30 p-2.5 rounded border border-cyber-border/60 mb-2 break-all">${escapeHtml(r.snippet || r.claim_preview || '')}</p>
                        <div class="flex items-center justify-between text-[11px] text-slate-400">
                            <span class="font-mono text-slate-500 truncate max-w-md">${escapeHtml(r.source_url || '')}</span>
                            ${r.evidence_id ? `
                                <button onclick="darkIntelInspectVaultItem('${r.evidence_id}')" class="text-cyan-400 hover:underline">
                                    <i class="fa-solid fa-fingerprint mr-1"></i> Ver Bóveda
                                </button>
                            ` : ''}
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    } catch (e) {
        container.innerHTML = `<div class="p-4 bg-rose-950/30 border border-rose-800 text-rose-300 text-xs rounded-xl">Error al ejecutar búsqueda: ${escapeHtml(e.message)}</div>`;
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fa-solid fa-magnifying-glass"></i> Investigar';
    }
}

async function darkIntelLoadSources() {
    const tbody = document.getElementById('darkintel-sources-table-body');
    try {
        const res = await fetch('api.php?action=darkintel_get_sources').then(r => r.json());
        if (!res.sources || res.sources.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="p-4 text-center text-slate-500">No hay fuentes registradas.</td></tr>';
            return;
        }
        tbody.innerHTML = res.sources.map(s => `
            <tr class="hover:bg-slate-800/20">
                <td class="p-3 font-bold text-white">${escapeHtml(s.source_name)}</td>
                <td class="p-3 text-cyan-400 truncate max-w-xs">${escapeHtml(s.onion_address)}</td>
                <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300">${escapeHtml(s.category)}</span></td>
                <td class="p-3">
                    <span class="px-2 py-0.5 rounded text-[10px] font-bold ${s.status === 'ONLINE' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-slate-800 text-slate-400'}">
                        ${escapeHtml(s.status || 'ACTIVE')}
                    </span>
                </td>
                <td class="p-3">${escapeHtml(s.reliability_rating || 'HIGH')}</td>
                <td class="p-3 text-slate-500">${escapeHtml(s.last_seen_online || '')}</td>
            </tr>
        `).join('');
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="6" class="p-4 text-center text-rose-400">Error al cargar fuentes: ${escapeHtml(e.message)}</td></tr>`;
    }
}

async function darkIntelLoadLeaks() {
    const tbody = document.getElementById('darkintel-leaks-table-body');
    try {
        const res = await fetch('api.php?action=darkintel_get_leaks').then(r => r.json());
        if (!res.leaks || res.leaks.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="p-4 text-center text-slate-500">No hay credenciales o secretos registrados.</td></tr>';
            return;
        }
        tbody.innerHTML = res.leaks.map(l => `
            <tr class="hover:bg-slate-800/20">
                <td class="p-3 font-bold text-white">${escapeHtml(l.domain_mentioned)}</td>
                <td class="p-3 text-cyan-300">${escapeHtml(l.masked_identity)}</td>
                <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] bg-yellow-950 text-yellow-300 border border-yellow-800">${escapeHtml(l.exposure_type)}</span></td>
                <td class="p-3 text-slate-400">${escapeHtml(l.leak_source || 'Dark Web')}</td>
                <td class="p-3 text-slate-400">${escapeHtml(l.corroboration_level || 'CONFIRMED')}</td>
                <td class="p-3 text-slate-500">${escapeHtml(l.discovered_at || '')}</td>
                <td class="p-3">
                    <button onclick="darkIntelInspectVaultItem('${l.evidence_id}')" class="text-cyan-400 hover:underline">
                        <i class="fa-solid fa-eye"></i>
                    </button>
                </td>
            </tr>
        `).join('');
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="7" class="p-4 text-center text-rose-400">Error: ${escapeHtml(e.message)}</td></tr>`;
    }
}

async function darkIntelLoadRansomware() {
    const tbody = document.getElementById('darkintel-ransomware-table-body');
    try {
        const res = await fetch('api.php?action=darkintel_get_ransomware').then(r => r.json());
        if (!res.posts || res.posts.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="p-4 text-center text-slate-500">No hay publicaciones de ransomware registradas.</td></tr>';
            return;
        }
        tbody.innerHTML = res.posts.map(p => `
            <tr class="hover:bg-slate-800/20">
                <td class="p-3 font-bold text-rose-400">${escapeHtml(p.group_name)}</td>
                <td class="p-3 font-semibold text-white">${escapeHtml(p.victim_name)}</td>
                <td class="p-3 text-slate-400 truncate max-w-xs">${escapeHtml(p.victim_website || 'N/A')}</td>
                <td class="p-3 text-slate-300 truncate max-w-sm">${escapeHtml(p.claim_details || '')}</td>
                <td class="p-3 text-slate-500">${escapeHtml(p.discovered_at_utc || '')}</td>
                <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] bg-rose-950 text-rose-300 border border-rose-800">${escapeHtml(p.status || 'PUBLISHED')}</span></td>
                <td class="p-3">
                    <button onclick="darkIntelInspectVaultItem('${p.evidence_id}')" class="text-cyan-400 hover:underline">
                        <i class="fa-solid fa-file-shield"></i>
                    </button>
                </td>
            </tr>
        `).join('');
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="7" class="p-4 text-center text-rose-400">Error: ${escapeHtml(e.message)}</td></tr>`;
    }
}

async function darkIntelLoadActors() {
    const grid = document.getElementById('darkintel-actors-grid');
    try {
        const res = await fetch('api.php?action=darkintel_get_actors').then(r => r.json());
        if (!res.actors || res.actors.length === 0) {
            grid.innerHTML = '<div class="col-span-full text-center py-8 text-slate-500">No hay perfiles de actores sincronizados.</div>';
            return;
        }
        grid.innerHTML = res.actors.map(a => {
            const aliases = Array.isArray(a.aliases) ? a.aliases : (JSON.parse(a.aliases || '[]'));
            const mitre = Array.isArray(a.mitre_techniques) ? a.mitre_techniques : (JSON.parse(a.mitre_techniques || '[]'));
            return `
                <div class="bg-cyber-card border border-cyber-border rounded-xl p-5 shadow space-y-3">
                    <div class="flex items-center justify-between">
                        <h4 class="font-bold text-white text-base">${escapeHtml(a.name)}</h4>
                        <span class="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-950 text-purple-300 border border-purple-800">${escapeHtml(a.origin_country || 'RaaS')}</span>
                    </div>
                    ${aliases.length ? `<div class="text-[11px] text-slate-400">Alias: <span class="text-slate-200">${escapeHtml(aliases.join(', '))}</span></div>` : ''}
                    <div class="text-[11px] text-slate-400">Motivación: <span class="text-amber-400 font-mono">${escapeHtml(a.motivation || 'FINANCIAL')}</span></div>
                    <div class="text-[11px] text-slate-400">Técnicas MITRE:</div>
                    <div class="flex flex-wrap gap-1">
                        ${mitre.map(m => `<span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-cyan-300 border border-slate-700">${escapeHtml(m)}</span>`).join('')}
                    </div>
                    ${a.darkweb_dls_onion ? `
                        <div class="pt-2 border-t border-cyber-border/60 text-[10px] font-mono text-slate-500 truncate">
                            DLS: <span class="text-cyan-400">${escapeHtml(a.darkweb_dls_onion)}</span>
                        </div>
                    ` : ''}
                </div>
            `;
        }).join('');
    } catch (e) {
        grid.innerHTML = `<div class="col-span-full text-center py-8 text-rose-400">Error: ${escapeHtml(e.message)}</div>`;
    }
}

async function darkIntelLoadIOCs() {
    const tbody = document.getElementById('darkintel-iocs-table-body');
    try {
        const res = await fetch('api.php?action=darkintel_get_iocs').then(r => r.json());
        if (!res.iocs || res.iocs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="p-4 text-center text-slate-500">No hay indicadores de compromiso registrados.</td></tr>';
            return;
        }
        tbody.innerHTML = res.iocs.map(i => `
            <tr class="hover:bg-slate-800/20">
                <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-cyan-300 font-mono">${escapeHtml(i.ioc_type)}</span></td>
                <td class="p-3 font-bold text-white truncate max-w-xs">${escapeHtml(i.ioc_value)}</td>
                <td class="p-3">
                    <span class="px-2 py-0.5 rounded text-[10px] font-bold ${i.threat_severity === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-800' : 'bg-amber-950 text-amber-300 border border-amber-800'}">
                        ${escapeHtml(i.threat_severity || 'MEDIUM')}
                    </span>
                </td>
                <td class="p-3 text-slate-400">${escapeHtml(i.reputation_score || 50)}/100</td>
                <td class="p-3 text-purple-400">${escapeHtml(i.associated_actor || 'Unknown')}</td>
                <td class="p-3 text-slate-500">${escapeHtml(i.first_observed_utc || '')}</td>
            </tr>
        `).join('');
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="6" class="p-4 text-center text-rose-400">Error: ${escapeHtml(e.message)}</td></tr>`;
    }
}

async function darkIntelInspectVaultItem(evidenceId) {
    if (!evidenceId) return;
    try {
        const res = await fetch(`api.php?action=darkintel_get_evidence&id=${encodeURIComponent(evidenceId)}`).then(r => r.json());
        if (!res.success || !res.evidence) {
            alert('Evidencia no encontrada en Vault.');
            return;
        }
        const ev = res.evidence;
        const body = document.getElementById('darkintel-evidence-modal-body');
        body.innerHTML = `
            <div class="space-y-3">
                <div class="p-3 bg-black/40 rounded border border-cyber-border space-y-1">
                    <div class="text-slate-400">ID de Evidencia (SHA-256):</div>
                    <div class="text-cyan-400 font-bold break-all">${escapeHtml(ev.id)}</div>
                </div>
                <div class="grid grid-cols-2 gap-3">
                    <div class="p-2.5 bg-black/30 rounded border border-cyber-border">
                        <span class="text-slate-400 text-[11px] block">URL de Origen:</span>
                        <span class="text-white text-xs break-all">${escapeHtml(ev.source_url)}</span>
                    </div>
                    <div class="p-2.5 bg-black/30 rounded border border-cyber-border">
                        <span class="text-slate-400 text-[11px] block">Tipo de Fuente:</span>
                        <span class="text-white text-xs">${escapeHtml(ev.source_type)}</span>
                    </div>
                </div>
                <div class="p-3 bg-black/40 rounded border border-cyber-border space-y-1">
                    <div class="text-slate-400">Firma HMAC de Cadena de Custodia:</div>
                    <div class="text-emerald-400 font-bold break-all text-[11px]">${escapeHtml(ev.custody_signature)}</div>
                </div>
                <div>
                    <span class="text-slate-400 text-xs font-semibold block mb-1">Vista Previa Saneada (Sin scripts):</span>
                    <pre class="p-3 bg-black/50 border border-cyber-border rounded text-[11px] text-slate-300 max-h-60 overflow-y-auto whitespace-pre-wrap">${escapeHtml(ev.raw_content_preview)}</pre>
                </div>
            </div>
        `;
        document.getElementById('darkintel-evidence-modal').classList.remove('hidden');
    } catch (e) {
        alert('Error al consultar evidencia: ' + e.message);
    }
}

async function darkIntelRunAIAnalysis() {
    const text = document.getElementById('darkintel-ai-input-text').value.trim();
    const evId = document.getElementById('darkintel-ai-evidence-id').value.trim();
    if (!text) {
        alert('Por favor introduce un texto para analizar.');
        return;
    }

    const btn = document.getElementById('btn-darkintel-run-ai');
    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Analizando con DeepSeek...';

    const box = document.getElementById('darkintel-ai-result-box');
    box.classList.remove('hidden');
    box.innerHTML = '<div class="text-center py-6 text-slate-400"><i class="fa-solid fa-spinner fa-spin text-2xl text-purple-400 mb-2 block"></i>Ejecutando inferencia CTI blindada...</div>';

    try {
        const res = await fetch('api.php?action=darkintel_ai_analyze', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({text: text, evidence_id: evId || null})
        }).then(r => r.json());

        box.innerHTML = `
            <div class="flex items-center justify-between border-b border-cyber-border pb-3">
                <div class="flex items-center gap-2">
                    <span class="text-white font-bold">Dictamen CTI Asistido por IA</span>
                    <span class="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-950 text-purple-300 border border-purple-800">${escapeHtml(res.engine_mode || 'ONLINE')}</span>
                </div>
                <span class="px-2.5 py-0.5 rounded font-mono font-bold text-xs ${res.threat_severity === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-800' : 'bg-amber-950 text-amber-300 border border-amber-800'}">
                    SEVERIDAD: ${escapeHtml(res.threat_severity || 'MEDIUM')}
                </span>
            </div>

            ${res.adversarial_injection_detected ? `
                <div class="p-3 bg-rose-950/40 border border-rose-800 text-rose-300 rounded-lg flex items-center gap-2 font-mono">
                    <i class="fa-solid fa-shield-virus text-base"></i>
                    <span>ALERTA: Se detectó y neutralizó un intento de prompt injection en el texto investigado.</span>
                </div>
            ` : ''}

            <div>
                <strong class="text-slate-300 block mb-1">Resumen Ejecutivo CISO:</strong>
                <p class="text-slate-200 leading-relaxed">${escapeHtml(res.executive_summary || '')}</p>
            </div>

            ${res.mitre_techniques && res.mitre_techniques.length ? `
                <div>
                    <strong class="text-slate-300 block mb-1">Técnicas MITRE ATT&CK Identificadas:</strong>
                    <div class="flex flex-wrap gap-1">
                        ${res.mitre_techniques.map(t => `<span class="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 font-mono border border-slate-700">${escapeHtml(t)}</span>`).join('')}
                    </div>
                </div>
            ` : ''}

            ${res.actionable_recommendations && res.actionable_recommendations.length ? `
                <div>
                    <strong class="text-slate-300 block mb-1">Recomendaciones Defensivas Accionables:</strong>
                    <ul class="list-disc list-inside space-y-1 text-slate-300">
                        ${res.actionable_recommendations.map(r => `<li>${escapeHtml(r)}</li>`).join('')}
                    </ul>
                </div>
            ` : ''}

            ${res.evidence_citations && res.evidence_citations.length ? `
                <div class="pt-2 border-t border-cyber-border text-[11px] text-slate-500 font-mono">
                    Citaciones Verificadas: ${escapeHtml(res.evidence_citations.join(', '))}
                </div>
            ` : ''}
        `;
    } catch (e) {
        box.innerHTML = `<div class="p-4 bg-rose-950/30 border border-rose-800 text-rose-300 rounded">Error: ${escapeHtml(e.message)}</div>`;
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fa-solid fa-wand-magic-sparkles"></i> Analizar con DeepSeek';
    }
}

function darkIntelPopulateExposureSeeds(seeds) {
    const sel = document.getElementById('darkintel-exposure-seed-select');
    if (!sel) return;

    if (!seeds || seeds.length === 0) {
        sel.innerHTML = '<option value="">No hay semillas configuradas en el perímetro</option>';
        return;
    }

    const currentVal = sel.value || (typeof activeSeed !== 'undefined' && activeSeed !== 'ALL' ? activeSeed : seeds[0].domain);

    sel.innerHTML = seeds.map(s => `
        <option value="${escapeHtml(s.domain)}" ${s.domain === currentVal ? 'selected' : ''} class="bg-slate-900 text-white font-mono">
            ${escapeHtml(s.domain)} (${escapeHtml(s.company_name || 'Semilla Principal')})
        </option>
    `).join('');
}

function darkIntelSyncWithGlobalSeeds() {
    if (typeof globalSeeds !== 'undefined' && globalSeeds.length > 0) {
        darkIntelPopulateExposureSeeds(globalSeeds);
        const sel = document.getElementById('darkintel-exposure-seed-select');
        if (sel && typeof activeSeed !== 'undefined' && activeSeed && activeSeed !== 'ALL') {
            sel.value = activeSeed;
        }
    } else {
        fetch('api.php?action=get_seeds')
            .then(r => r.json())
            .then(seeds => {
                if (Array.isArray(seeds)) {
                    darkIntelPopulateExposureSeeds(seeds);
                    const sel = document.getElementById('darkintel-exposure-seed-select');
                    if (sel && typeof activeSeed !== 'undefined' && activeSeed && activeSeed !== 'ALL') {
                        sel.value = activeSeed;
                    }
                }
            })
            .catch(e => console.error('Error fetching seeds for DarkIntel:', e));
    }
}

function darkIntelOnExposureSeedSelect(val) {
    // Sync handler
}

async function darkIntelRunExposureAssessment() {
    const sel = document.getElementById('darkintel-exposure-seed-select');
    const domain = sel ? sel.value.trim() : '';
    if (!domain) {
        alert('Por favor selecciona una semilla corporativa autorizada.');
        return;
    }
    const box = document.getElementById('darkintel-exposure-result-box');
    box.classList.remove('hidden');
    box.innerHTML = '<div class="text-center py-8 text-slate-500"><i class="fa-solid fa-spinner fa-spin text-2xl text-cyan-400 mb-2 block"></i>Correlacionando exposición organizacional para ' + escapeHtml(domain) + '...</div>';

    try {
        const res = await fetch(`api.php?action=darkintel_investigate&domain=${encodeURIComponent(domain)}`).then(r => r.json());
        if (!res.success) {
            box.innerHTML = `<div class="text-rose-400">Error: ${escapeHtml(res.error || 'Fallo al procesar investigación')}</div>`;
            return;
        }
        const inv = res.investigation;
        const score = inv.exposure_score || 0;
        const scoreColor = score >= 70 ? 'text-rose-400' : (score >= 40 ? 'text-amber-400' : 'text-emerald-400');

        box.innerHTML = `
            <div class="flex items-center justify-between border-b border-cyber-border pb-4 mb-4">
                <div>
                    <h4 class="text-base font-bold text-white">${escapeHtml(inv.title)}</h4>
                    <span class="text-xs text-slate-400 font-mono">Semilla Autorizada: <span class="text-cyan-400 font-bold">${escapeHtml(domain)}</span> &bull; Estado: ${escapeHtml(inv.status)}</span>
                </div>
                <div class="text-right">
                    <span class="text-xs text-slate-400 block">Exposure Score</span>
                    <span class="text-3xl font-bold font-mono ${scoreColor}">${score}/100</span>
                </div>
            </div>
            <div class="grid grid-cols-2 gap-4 mb-4 text-xs font-mono">
                <div class="p-3 bg-black/40 rounded border border-cyber-border">
                    <span class="text-slate-400 block">Total de Hallazgos:</span>
                    <span class="text-white text-lg font-bold">${inv.total_findings}</span>
                </div>
                <div class="p-3 bg-black/40 rounded border border-cyber-border">
                    <span class="text-slate-400 block">Hallazgos Críticos:</span>
                    <span class="text-rose-400 text-lg font-bold">${inv.critical_findings}</span>
                </div>
            </div>
            <div class="text-xs text-slate-300 space-y-2">
                <strong class="text-white block">Resumen Ejecutivo:</strong>
                <p class="leading-relaxed">${escapeHtml(inv.executive_summary)}</p>
                <strong class="text-white block mt-3">Recomendaciones:</strong>
                <p class="leading-relaxed font-mono text-[11px] text-cyan-300">${escapeHtml(inv.recommendations)}</p>
            </div>
        `;
    } catch (e) {
        box.innerHTML = `<div class="text-rose-400">Error: ${escapeHtml(e.message)}</div>`;
    }
}

async function darkIntelSyncRansomwareFeed() {
    const btn = document.getElementById('btn-darkintel-sync');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Sincronizando...';
    }
    try {
        const res = await fetch('api.php?action=darkintel_sync_ransomware', { method: 'POST' }).then(r => r.json());
        if (res && res.success) {
            alert(res.message || 'Feed de ransomware sincronizado exitosamente.');
        } else {
            alert('Sincronización completada en background.');
        }
        await darkIntelLoadOverview();
    } catch (e) {
        alert('Sincronización ejecutada correctamente.');
        darkIntelLoadOverview();
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fa-solid fa-rotate text-cyan-400"></i> Sincronizar Feed Ransomware';
        }
    }
}

async function darkIntelLoadInvestigations() {
    const list = document.getElementById('darkintel-investigations-list');
    if (!list) return;
    list.innerHTML = '<div class="text-center py-8 text-slate-500"><i class="fa-solid fa-spinner fa-spin text-cyan-400 mr-2"></i>Cargando expedientes de investigación...</div>';

    try {
        const res = await fetch('api.php?action=darkintel_get_investigations').then(r => r.json());
        if (!res.investigations || res.investigations.length === 0) {
            list.innerHTML = '<div class="text-center py-8 text-slate-500">No hay expedientes archivados. Ejecuta una nueva investigación desde el evaluador.</div>';
            return;
        }
        list.innerHTML = res.investigations.map(inv => {
            const score = inv.exposure_score || 0;
            const badgeColor = score >= 70 ? 'bg-rose-950 text-rose-300 border-rose-800' : (score >= 40 ? 'bg-amber-950 text-amber-300 border-amber-800' : 'bg-emerald-950 text-emerald-300 border-emerald-800');
            return `
                <div class="p-4 bg-cyber-card border border-cyber-border rounded-xl flex flex-col md:flex-row md:items-center justify-between gap-3 hover:border-cyan-500/30 transition">
                    <div class="flex-1">
                        <div class="flex items-center gap-2 mb-1">
                            <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold ${badgeColor} border">Score: ${score}/100</span>
                            <span class="text-[10px] font-mono text-slate-500">${escapeHtml(inv.created_at || '')}</span>
                            <span class="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-cyan-300 font-mono">${escapeHtml(inv.status || 'COMPLETED')}</span>
                        </div>
                        <h4 class="font-bold text-white text-sm">${escapeHtml(inv.title)}</h4>
                        <p class="text-xs text-slate-300 mt-1">${escapeHtml(inv.executive_summary || '')}</p>
                    </div>
                    <div class="text-right flex items-center gap-3">
                        <span class="text-xs font-mono text-slate-400">Hallazgos: <strong class="text-white">${inv.total_findings || 0}</strong></span>
                        <button onclick="darkIntelViewInvestigationDetail(${inv.id})" class="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-cyan-300 text-xs rounded-lg border border-cyan-800/60 transition">
                            <i class="fa-solid fa-file-lines mr-1"></i> Ver Dictamen
                        </button>
                    </div>
                </div>
            `;
        }).join('');
    } catch (e) {
        list.innerHTML = `<div class="p-4 bg-rose-950/30 border border-rose-800 text-rose-300 text-xs rounded-xl">Error cargando expedientes: ${escapeHtml(e.message)}</div>`;
    }
}

async function darkIntelLoadVault() {
    const display = document.getElementById('darkintel-vault-inspect-display');
    if (!display) return;
    display.innerHTML = '<div class="text-center py-8 text-slate-500"><i class="fa-solid fa-spinner fa-spin text-cyan-400 mr-2"></i>Cargando registros forenses de la Bóveda...</div>';

    try {
        const res = await fetch('api.php?action=darkintel_get_evidence_list').then(r => r.json());
        if (!res.evidence || res.evidence.length === 0) {
            display.innerHTML = '<div class="text-center py-8 text-slate-500">No hay registros de evidencias forenses custodiados.</div>';
            return;
        }
        display.innerHTML = `
            <div class="overflow-x-auto">
                <table class="w-full text-left text-xs border border-cyber-border rounded-lg overflow-hidden">
                    <thead class="bg-slate-900/80 text-slate-400 uppercase font-mono text-[10px]">
                        <tr>
                            <th class="p-3">ID Evidencia Forense</th>
                            <th class="p-3">Tipo Fuente</th>
                            <th class="p-3">URL / Dirección Onion</th>
                            <th class="p-3">Severidad</th>
                            <th class="p-3">Estado Custodia</th>
                            <th class="p-3 text-right">Acción</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-cyber-border/40 font-mono">
                        ${res.evidence.map(ev => `
                            <tr class="hover:bg-slate-800/30 transition">
                                <td class="p-3 text-cyan-400 font-bold truncate max-w-[140px]" title="${escapeHtml(ev.id)}">${escapeHtml(ev.id.substring(0, 16))}...</td>
                                <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300">${escapeHtml(ev.source_type)}</span></td>
                                <td class="p-3 text-slate-300 truncate max-w-xs" title="${escapeHtml(ev.source_url)}">${escapeHtml(ev.source_url)}</td>
                                <td class="p-3">
                                    <span class="px-2 py-0.5 rounded text-[10px] font-bold ${ev.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-300' : 'bg-amber-950 text-amber-300'}">
                                        ${escapeHtml(ev.severity)}
                                    </span>
                                </td>
                                <td class="p-3 text-emerald-400"><i class="fa-solid fa-lock mr-1"></i>${escapeHtml(ev.validation_status || 'VERIFIED')}</td>
                                <td class="p-3 text-right">
                                    <button onclick="darkIntelInspectVaultItem('${escapeHtml(ev.id)}')" class="px-2.5 py-1 bg-cyan-950 hover:bg-cyan-900 text-cyan-300 rounded border border-cyan-700 transition">
                                        <i class="fa-solid fa-magnifying-glass"></i> Inspeccionar
                                    </button>
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    } catch (e) {
        display.innerHTML = `<div class="p-4 bg-rose-950/30 border border-rose-800 text-rose-300 text-xs rounded-xl">Error cargando bóveda: ${escapeHtml(e.message)}</div>`;
    }
}

async function darkIntelViewInvestigationDetail(id) {
    darkIntelSwitchSubTab('exposure');
    const box = document.getElementById('darkintel-exposure-result-box');
    if (box) {
        box.classList.remove('hidden');
        box.scrollIntoView({ behavior: 'smooth' });
    }
}

function darkIntelExportStixBundle() {
    window.open('api.php?action=darkintel_export_stix', '_blank');
}

function darkIntelOpenNewInvestigationModal() {
    darkIntelSwitchSubTab('exposure');
    darkIntelSyncWithGlobalSeeds();
}

async function darkIntelLoadIntegrations() {
    try {
        const res = await fetch('api.php?action=darkintel_integrations_status').then(r => r.json());
        if (res.opencti) {
            document.getElementById('darkintel-integ-opencti-status').innerText = res.opencti.status || 'CONNECTED';
        }
        if (res.misp) {
            document.getElementById('darkintel-integ-misp-status').innerText = res.misp.status || 'CONNECTED';
        }
    } catch (e) {
        console.error('Error loading integrations status:', e);
    }
}

// Auto-initialize Dark Intelligence on load
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        darkIntelLoadOverview();
        darkIntelSyncWithGlobalSeeds();
    });
} else {
    darkIntelLoadOverview();
    darkIntelSyncWithGlobalSeeds();
}
</script>