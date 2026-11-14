<?php
/**
 * OPENRECON - EMAIL INTELLIGENCE CONSOLE
 * Enterprise OSINT & Breach Intelligence Module (Zehef Engine Integration)
 * Full SOC Interface: Leaks, Digital Presence, Domain DNS Posture, Graph & Evidence Vault
 */
?>
<section id="tab-content-emailintel" class="space-y-6 hidden">
    <!-- Email Intelligence Header & Global Status -->
    <div class="bg-cyber-card border border-cyber-border rounded-2xl p-6 shadow-2xl relative overflow-hidden">
        <div class="absolute -right-10 -bottom-10 opacity-5 pointer-events-none">
            <i class="fa-solid fa-envelope-open-text text-[220px] text-sky-400"></i>
        </div>
        <div class="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 border-b border-cyber-border pb-5 mb-6">
            <div class="flex items-center gap-3">
                <div class="w-12 h-12 rounded-xl bg-sky-950/80 border border-sky-500/30 flex items-center justify-center text-sky-400 text-2xl shadow-inner">
                    <i class="fa-solid fa-at"></i>
                </div>
                <div>
                    <div class="flex items-center gap-2">
                        <h2 class="text-xl font-bold text-white tracking-wide">EMAIL INTELLIGENCE</h2>
                        <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-sky-950 text-sky-300 border border-sky-700/60 uppercase">ZEHEF OSINT v2.2</span>
                        <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-800 uppercase flex items-center gap-1">
                            <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                            ACTIVE CORRELATION
                        </span>
                    </div>
                    <p class="text-xs text-slate-400 mt-0.5">Investigaciones OSINT de Correos: Filtraciones (Info-Stealers), Presencia Digital Multi-Plataforma, Postura DNS (MX/SPF/DMARC) y Bóveda Forense.</p>
                </div>
            </div>

            <!-- Quick Action Toolbar -->
            <div class="flex flex-wrap items-center gap-2">
                <button onclick="emailIntelRefreshList()" id="btn-emailintel-refresh" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold flex items-center gap-1.5 transition">
                    <i class="fa-solid fa-rotate text-sky-400"></i> Actualizar
                </button>
                <button onclick="emailIntelOpenNewModal()" class="px-3 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-slate-950 text-xs font-bold flex items-center gap-1.5 shadow-lg shadow-sky-600/20 transition">
                    <i class="fa-solid fa-magnifying-glass-plus"></i> Nueva Investigación
                </button>
            </div>
        </div>

        <!-- Sub-Section Navigation Pills -->
        <div class="flex items-center gap-1.5 overflow-x-auto pb-2 scrollbar-thin border-b border-cyber-border/60 text-xs">
            <button onclick="emailIntelSwitchSubTab('overview')" id="emailintel-subtab-btn-overview" class="emailintel-nav-pill active">
                <i class="fa-solid fa-table-columns mr-1"></i> 1. Dashboard
            </button>
            <button onclick="emailIntelSwitchSubTab('detail')" id="emailintel-subtab-btn-detail" class="emailintel-nav-pill">
                <i class="fa-solid fa-magnifying-glass-chart mr-1"></i> 2. Detalle Caso
            </button>
            <button onclick="emailIntelSwitchSubTab('leaks')" id="emailintel-subtab-btn-leaks" class="emailintel-nav-pill">
                <i class="fa-solid fa-skull mr-1"></i> 3. Leak Search
            </button>
            <button onclick="emailIntelSwitchSubTab('accounts')" id="emailintel-subtab-btn-accounts" class="emailintel-nav-pill">
                <i class="fa-solid fa-users-viewfinder mr-1"></i> 4. Account Search
            </button>
            <button onclick="emailIntelSwitchSubTab('domain')" id="emailintel-subtab-btn-domain" class="emailintel-nav-pill">
                <i class="fa-solid fa-shield-halved mr-1"></i> 5. Domain & DNS Intel
            </button>
            <button onclick="emailIntelSwitchSubTab('pastes')" id="emailintel-subtab-btn-pastes" class="emailintel-nav-pill">
                <i class="fa-solid fa-paste mr-1"></i> 6. Paste Search
            </button>
            <button onclick="emailIntelSwitchSubTab('variants')" id="emailintel-subtab-btn-variants" class="emailintel-nav-pill">
                <i class="fa-solid fa-wand-magic-sparkles mr-1"></i> 7. Email Generation
            </button>
            <button onclick="emailIntelSwitchSubTab('graph')" id="emailintel-subtab-btn-graph" class="emailintel-nav-pill">
                <i class="fa-solid fa-circle-nodes mr-1"></i> 8. Grafo Relacional
            </button>
            <button onclick="emailIntelSwitchSubTab('evidence')" id="emailintel-subtab-btn-evidence" class="emailintel-nav-pill">
                <i class="fa-solid fa-fingerprint mr-1"></i> 9. Bóveda Forense
            </button>
        </div>

        <!-- ========================================================= -->
        <!-- SUBTAB 1: OVERVIEW & INVESTIGATION SELECTOR -->
        <!-- ========================================================= -->
        <div id="emailintel-pane-overview" class="emailintel-pane mt-6 space-y-6">
            <!-- Global Exposure Metrics Banner -->
            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
                <div class="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
                    <div>
                        <div class="text-[11px] text-slate-400 uppercase tracking-wider font-semibold">Total Investigaciones</div>
                        <div id="ei-stat-total-invs" class="text-2xl font-bold text-white font-mono mt-1">0</div>
                    </div>
                    <div class="w-10 h-10 rounded-lg bg-sky-950/60 border border-sky-800/40 flex items-center justify-center text-sky-400">
                        <i class="fa-solid fa-folder-tree"></i>
                    </div>
                </div>
                <div class="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
                    <div>
                        <div class="text-[11px] text-slate-400 uppercase tracking-wider font-semibold">Filtraciones (Stealers)</div>
                        <div id="ei-stat-total-leaks" class="text-2xl font-bold text-rose-400 font-mono mt-1">0</div>
                    </div>
                    <div class="w-10 h-10 rounded-lg bg-rose-950/60 border border-rose-800/40 flex items-center justify-center text-rose-400">
                        <i class="fa-solid fa-biohazard"></i>
                    </div>
                </div>
                <div class="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
                    <div>
                        <div class="text-[11px] text-slate-400 uppercase tracking-wider font-semibold">Cuentas Confirmadas</div>
                        <div id="ei-stat-total-accounts" class="text-2xl font-bold text-emerald-400 font-mono mt-1">0</div>
                    </div>
                    <div class="w-10 h-10 rounded-lg bg-emerald-950/60 border border-emerald-800/40 flex items-center justify-center text-emerald-400">
                        <i class="fa-solid fa-user-check"></i>
                    </div>
                </div>
                <div class="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
                    <div>
                        <div class="text-[11px] text-slate-400 uppercase tracking-wider font-semibold">Menciones en Pastes</div>
                        <div id="ei-stat-total-pastes" class="text-2xl font-bold text-amber-400 font-mono mt-1">0</div>
                    </div>
                    <div class="w-10 h-10 rounded-lg bg-amber-950/60 border border-amber-800/40 flex items-center justify-center text-amber-400">
                        <i class="fa-solid fa-file-lines"></i>
                    </div>
                </div>
                <div class="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
                    <div>
                        <div class="text-[11px] text-slate-400 uppercase tracking-wider font-semibold">Evidencias SHA-256</div>
                        <div id="ei-stat-total-evidences" class="text-2xl font-bold text-indigo-400 font-mono mt-1">0</div>
                    </div>
                    <div class="w-10 h-10 rounded-lg bg-indigo-950/60 border border-indigo-800/40 flex items-center justify-center text-indigo-400">
                        <i class="fa-solid fa-fingerprint"></i>
                    </div>
                </div>
            </div>

            <!-- Investigations Table & Selector -->
            <div class="bg-slate-900/60 border border-slate-800 rounded-xl p-5 shadow-lg">
                <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 mb-4">
                    <h3 class="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                        <i class="fa-solid fa-list-check text-sky-400"></i> Registro de Investigaciones de Correo
                    </h3>
                    <div class="flex items-center gap-2">
                        <input type="text" id="ei-filter-search" oninput="emailIntelFilterTable()" placeholder="Filtrar por correo, caso o título..." class="px-3 py-1 rounded bg-slate-950 border border-slate-700 text-xs text-slate-200 focus:border-sky-500 focus:outline-none w-64">
                    </div>
                </div>

                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs border-collapse">
                        <thead>
                            <tr class="border-b border-slate-800 text-slate-400 text-[11px] uppercase tracking-wider bg-slate-950/40">
                                <th class="p-3">ID Caso</th>
                                <th class="p-3">Correo Investigado</th>
                                <th class="p-3">Título / Justificación</th>
                                <th class="p-3">Score Exposición</th>
                                <th class="p-3">Nivel Riesgo</th>
                                <th class="p-3">Hallazgos</th>
                                <th class="p-3">Estado</th>
                                <th class="p-3">Fecha</th>
                                <th class="p-3 text-right">Acciones</th>
                            </tr>
                        </thead>
                        <tbody id="ei-investigations-tbody" class="divide-y divide-slate-800/50">
                            <tr>
                                <td colspan="9" class="p-6 text-center text-slate-500">
                                    <i class="fa-solid fa-spinner fa-spin mr-2"></i> Cargando investigaciones...
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- ========================================================= -->
        <!-- SUBTAB 2: INVESTIGATION DETAIL & CONTROLS -->
        <!-- ========================================================= -->
        <div id="emailintel-pane-detail" class="emailintel-pane mt-6 space-y-6 hidden">
            <!-- Active Investigation Banner -->
            <div class="bg-slate-900/90 border border-slate-800 rounded-xl p-5 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
                <div class="space-y-1">
                    <div class="flex items-center gap-3">
                        <span id="ei-det-id" class="px-2 py-0.5 rounded text-xs font-mono font-bold bg-sky-950 text-sky-300 border border-sky-800">EI-NONE</span>
                        <h3 id="ei-det-email" class="text-lg font-bold text-white font-mono">seleccione@investigacion.com</h3>
                        <span id="ei-det-status-badge" class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-800 text-slate-400">DESCONOCIDO</span>
                    </div>
                    <p id="ei-det-title-desc" class="text-xs text-slate-400">Sin investigación activa seleccionada.</p>
                    <div class="text-[11px] text-slate-500 flex items-center gap-4 pt-1">
                        <span><i class="fa-solid fa-briefcase mr-1 text-slate-400"></i> Caso: <b id="ei-det-case-id" class="text-slate-300">-</b></span>
                        <span><i class="fa-solid fa-gavel mr-1 text-slate-400"></i> Justificación: <span id="ei-det-justification" class="text-slate-300 italic">-</span></span>
                    </div>
                </div>

                <!-- Action Controls for Active Investigation -->
                <div class="flex flex-wrap items-center gap-2">
                    <button onclick="emailIntelCorrelateIocAction()" class="px-3 py-1.5 rounded-lg bg-indigo-950 hover:bg-indigo-900 text-indigo-300 border border-indigo-700 text-xs font-semibold flex items-center gap-1.5 transition" title="Registrar como IoC central en OpenRecon">
                        <i class="fa-solid fa-crosshairs text-indigo-400"></i> Correlacionar como IoC
                    </button>
                    <button onclick="emailIntelPauseAction()" id="btn-ei-pause" class="px-3 py-1.5 rounded-lg bg-amber-950 hover:bg-amber-900 text-amber-300 border border-amber-800 text-xs font-semibold flex items-center gap-1.5 transition">
                        <i class="fa-solid fa-pause"></i> Pausar
                    </button>
                    <button onclick="emailIntelCancelAction()" id="btn-ei-cancel" class="px-3 py-1.5 rounded-lg bg-rose-950 hover:bg-rose-900 text-rose-300 border border-rose-800 text-xs font-semibold flex items-center gap-1.5 transition">
                        <i class="fa-solid fa-stop"></i> Cancelar
                    </button>
                    <button onclick="emailIntelExportCurrent('json')" class="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-semibold" title="Exportar JSON">
                        <i class="fa-solid fa-file-code"></i> JSON
                    </button>
                    <button onclick="emailIntelExportCurrent('csv')" class="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-semibold" title="Exportar CSV">
                        <i class="fa-solid fa-file-csv"></i> CSV
                    </button>
                </div>
            </div>

            <!-- Risk Engine Card -->
            <div class="bg-gradient-to-r from-slate-900 via-slate-900 to-slate-950 border border-slate-800 rounded-xl p-5 shadow-xl">
                <div class="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-slate-800 pb-4 mb-4">
                    <div class="flex items-center gap-4">
                        <div id="ei-det-score-dial" class="w-16 h-16 rounded-full flex items-center justify-center text-xl font-bold font-mono border-4 border-rose-500 bg-rose-950/40 text-rose-400">
                            0.0
                        </div>
                        <div>
                            <div class="text-[11px] uppercase tracking-wider text-slate-400 font-semibold">Puntuación de Exposición Explicable</div>
                            <div class="flex items-center gap-2 mt-0.5">
                                <span id="ei-det-risk-badge" class="px-2.5 py-0.5 rounded text-xs font-bold uppercase bg-rose-950 text-rose-300 border border-rose-800 font-mono">INFORMATIVO</span>
                                <span class="text-xs text-slate-400">Escala de Impacto Forense (0 - 100)</span>
                            </div>
                        </div>
                    </div>
                    <div class="text-right text-xs text-slate-400">
                        <div>Progreso Motor: <b id="ei-det-progress-text" class="text-sky-400 font-mono">100%</b></div>
                        <div class="w-36 bg-slate-800 rounded-full h-1.5 mt-1 overflow-hidden">
                            <div id="ei-det-progress-bar" class="bg-sky-500 h-1.5 rounded-full" style="width: 100%"></div>
                        </div>
                    </div>
                </div>
                <div class="bg-slate-950/60 rounded-lg p-3 border border-slate-800/80">
                    <div class="text-[11px] uppercase tracking-wider text-slate-400 font-semibold mb-1 flex items-center gap-1.5">
                        <i class="fa-solid fa-brain text-purple-400"></i> Justificación Matemática del Riesgo
                    </div>
                    <p id="ei-det-risk-explanation" class="text-xs text-slate-300 leading-relaxed font-sans">
                        Seleccione una investigación para visualizar los factores de ponderación.
                    </p>
                </div>
            </div>

            <!-- Quick Metrics Grid for the Current Case -->
            <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div class="bg-slate-900/60 border border-slate-800 rounded-xl p-4">
                    <div class="text-xs text-slate-400">Infecciones Info-Stealer</div>
                    <div id="ei-det-leaks-count" class="text-2xl font-bold font-mono text-rose-400 mt-1">0</div>
                    <div class="text-[10px] text-slate-500 mt-0.5">Servicios corp. / credenciales</div>
                </div>
                <div class="bg-slate-900/60 border border-slate-800 rounded-xl p-4">
                    <div class="text-xs text-slate-400">Presencia en Cuentas</div>
                    <div id="ei-det-acc-count" class="text-2xl font-bold font-mono text-emerald-400 mt-1">0</div>
                    <div class="text-[10px] text-slate-500 mt-0.5">Plataformas confirmadas</div>
                </div>
                <div class="bg-slate-900/60 border border-slate-800 rounded-xl p-4">
                    <div class="text-xs text-slate-400">Seguridad Dominio (DNS)</div>
                    <div id="ei-det-dns-score" class="text-2xl font-bold font-mono text-sky-400 mt-1">0 / 100</div>
                    <div class="text-[10px] text-slate-500 mt-0.5">Postura SPF / DMARC / MX</div>
                </div>
                <div class="bg-slate-900/60 border border-slate-800 rounded-xl p-4">
                    <div class="text-xs text-slate-400">Bóveda de Evidencias</div>
                    <div id="ei-det-ev-count" class="text-2xl font-bold font-mono text-indigo-400 mt-1">0</div>
                    <div class="text-[10px] text-slate-500 mt-0.5">Hashes SHA-256 inmutables</div>
                </div>
            </div>
        </div>

        <!-- ========================================================= -->
        <!-- SUBTAB 3: LEAK SEARCH (INFO-STEALERS & BREACHES) -->
        <!-- ========================================================= -->
        <div id="emailintel-pane-leaks" class="emailintel-pane mt-6 space-y-6 hidden">
            <!-- Privacy & K-Anonymity Assurance Banner -->
            <div class="bg-rose-950/20 border border-rose-900/40 rounded-xl p-4 flex items-center gap-3">
                <div class="w-10 h-10 rounded-lg bg-rose-950/80 border border-rose-800/60 flex items-center justify-center text-rose-400 text-lg shrink-0">
                    <i class="fa-solid fa-user-shield"></i>
                </div>
                <div class="text-xs">
                    <b class="text-rose-300 font-semibold uppercase tracking-wider">Cumplimiento K-Anonymity & Cero Almacenamiento de Contraseñas</b>
                    <p class="text-slate-400 mt-0.5">De acuerdo con los estándares de DFIR y protección de datos, este módulo nunca descarga, muestra ni almacena contraseñas en texto claro. La telemetría refleja metadatos de infección, recuentos de servicios comprometidos y firmas forenses verificables.</p>
                </div>
            </div>

            <div class="bg-slate-900/60 border border-slate-800 rounded-xl p-5 shadow-lg">
                <h3 class="text-sm font-bold text-white uppercase tracking-wider mb-4 flex items-center gap-2">
                    <i class="fa-solid fa-skull-crossbones text-rose-400"></i> Exposiciones en Filtraciones y Telemetría de Stealers
                </h3>

                <div id="ei-leaks-container" class="space-y-3">
                    <div class="p-6 text-center text-slate-500 text-xs">
                        No hay filtraciones cargadas o seleccione una investigación.
                    </div>
                </div>
            </div>
        </div>

        <!-- ========================================================= -->
        <!-- SUBTAB 4: ACCOUNT SEARCH (DIGITAL PRESENCE) -->
        <!-- ========================================================= -->
        <div id="emailintel-pane-accounts" class="emailintel-pane mt-6 space-y-6 hidden">
            <!-- Filters by Status -->
            <div class="flex items-center gap-2 text-xs">
                <span class="text-slate-400 mr-1 font-semibold">Filtrar por Estado:</span>
                <button onclick="emailIntelFilterAccounts('ALL')" class="px-2.5 py-1 rounded bg-slate-800 text-slate-200 border border-slate-700 font-semibold">Todos</button>
                <button onclick="emailIntelFilterAccounts('CONFIRMED')" class="px-2.5 py-1 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 font-semibold">Confirmados</button>
                <button onclick="emailIntelFilterAccounts('PROBABLE')" class="px-2.5 py-1 rounded bg-blue-950 text-blue-300 border border-blue-800 font-semibold">Probables</button>
                <button onclick="emailIntelFilterAccounts('NOT_FOUND')" class="px-2.5 py-1 rounded bg-slate-900 text-slate-400 border border-slate-800 font-semibold">No Encontrados</button>
                <button onclick="emailIntelFilterAccounts('INCONCLUSIVE')" class="px-2.5 py-1 rounded bg-amber-950 text-amber-300 border border-amber-800 font-semibold">Inconclusos / WAF</button>
            </div>

            <div class="bg-slate-900/60 border border-slate-800 rounded-xl p-5 shadow-lg">
                <h3 class="text-sm font-bold text-white uppercase tracking-wider mb-4 flex items-center gap-2">
                    <i class="fa-solid fa-users-viewfinder text-emerald-400"></i> Presencia en Plataformas y Servicios Digitales
                </h3>

                <div id="ei-accounts-grid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    <div class="col-span-full p-6 text-center text-slate-500 text-xs">
                        Seleccione una investigación para visualizar cuentas comprobadas.
                    </div>
                </div>
            </div>
        </div>

        <!-- ========================================================= -->
        <!-- SUBTAB 5: DOMAIN & DNS INTELLIGENCE -->
        <!-- ========================================================= -->
        <div id="emailintel-pane-domain" class="emailintel-pane mt-6 space-y-6 hidden">
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-5">
                <!-- DNS Posture Overview -->
                <div class="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4">
                    <h3 class="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                        <i class="fa-solid fa-server text-sky-400"></i> Infraestructura de Correo
                    </h3>
                    <div class="space-y-3 text-xs">
                        <div>
                            <div class="text-slate-400">Dominio Receptor:</div>
                            <div id="ei-domain-name" class="text-white font-mono font-bold text-sm">-</div>
                        </div>
                        <div>
                            <div class="text-slate-400">Proveedor de Correo Detectado:</div>
                            <div id="ei-domain-provider" class="text-sky-400 font-semibold">-</div>
                        </div>
                        <div>
                            <div class="text-slate-400">Puntuación de Seguridad DNS:</div>
                            <div class="flex items-center gap-2 mt-1">
                                <span id="ei-domain-score-badge" class="px-2.5 py-0.5 rounded text-xs font-bold font-mono bg-sky-950 text-sky-300 border border-sky-800">0 / 100</span>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- SPF & DMARC Posture -->
                <div class="lg:col-span-2 bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4">
                    <h3 class="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                        <i class="fa-solid fa-shield-virus text-indigo-400"></i> Políticas de Anti-Spoofing & DMARC
                    </h3>
                    <div class="space-y-3 text-xs">
                        <div class="bg-slate-950 p-3 rounded-lg border border-slate-800">
                            <div class="flex items-center justify-between mb-1">
                                <span class="font-bold text-slate-300">Registro SPF (RFC 7208):</span>
                                <span id="ei-spf-status" class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-800 text-slate-400 font-mono">DESCONOCIDO</span>
                            </div>
                            <code id="ei-spf-record" class="text-[11px] text-slate-400 font-mono block break-all">Sin registro SPF verificado.</code>
                        </div>

                        <div class="bg-slate-950 p-3 rounded-lg border border-slate-800">
                            <div class="flex items-center justify-between mb-1">
                                <span class="font-bold text-slate-300">Política DMARC (RFC 7489):</span>
                                <span id="ei-dmarc-status" class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-800 text-slate-400 font-mono">DESCONOCIDO</span>
                            </div>
                            <code id="ei-dmarc-record" class="text-[11px] text-slate-400 font-mono block break-all">Sin registro DMARC verificado.</code>
                        </div>

                        <div class="bg-slate-950 p-3 rounded-lg border border-slate-800">
                            <div class="flex items-center justify-between mb-1">
                                <span class="font-bold text-slate-300">Firma DKIM (Selectores Comunes):</span>
                                <span id="ei-dkim-status" class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-800 text-slate-400 font-mono">DESCONOCIDO</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Weaknesses & Actionable Recommendations -->
            <div class="grid grid-cols-1 md:grid-cols-2 gap-5">
                <div class="bg-slate-900/60 border border-slate-800 rounded-xl p-5">
                    <h4 class="text-xs font-bold text-rose-400 uppercase tracking-wider mb-3 flex items-center gap-1.5">
                        <i class="fa-solid fa-triangle-exclamation"></i> Debilidades Perimetrales Detectadas
                    </h4>
                    <ul id="ei-domain-weaknesses-list" class="space-y-2 text-xs text-slate-300">
                        <li class="text-slate-500 italic">No hay debilidades registradas.</li>
                    </ul>
                </div>
                <div class="bg-slate-900/60 border border-slate-800 rounded-xl p-5">
                    <h4 class="text-xs font-bold text-emerald-400 uppercase tracking-wider mb-3 flex items-center gap-1.5">
                        <i class="fa-solid fa-circle-check"></i> Recomendaciones de Remediación
                    </h4>
                    <ul id="ei-domain-recommendations-list" class="space-y-2 text-xs text-slate-300">
                        <li class="text-slate-500 italic">No hay recomendaciones registradas.</li>
                    </ul>
                </div>
            </div>
        </div>

        <!-- ========================================================= -->
        <!-- SUBTAB 6: PASTES SEARCH -->
        <!-- ========================================================= -->
        <div id="emailintel-pane-pastes" class="emailintel-pane mt-6 space-y-6 hidden">
            <div class="bg-slate-900/60 border border-slate-800 rounded-xl p-5 shadow-lg">
                <h3 class="text-sm font-bold text-white uppercase tracking-wider mb-4 flex items-center gap-2">
                    <i class="fa-solid fa-paste text-amber-400"></i> Menciones Públicas en Repositorios de Texto (Pastes)
                </h3>
                <div id="ei-pastes-container" class="space-y-3">
                    <div class="p-6 text-center text-slate-500 text-xs">
                        No hay menciones en pastes detectadas.
                    </div>
                </div>
            </div>
        </div>

        <!-- ========================================================= -->
        <!-- SUBTAB 7: EMAIL VARIANT GENERATOR (HYPOTHESIS ENGINE) -->
        <!-- ========================================================= -->
        <div id="emailintel-pane-variants" class="emailintel-pane mt-6 space-y-6 hidden">
            <!-- Hypothesis Disclaimer Banner -->
            <div class="bg-amber-950/20 border border-amber-900/40 rounded-xl p-4 flex items-center gap-3">
                <div class="w-10 h-10 rounded-lg bg-amber-950/80 border border-amber-800/60 flex items-center justify-center text-amber-400 text-lg shrink-0">
                    <i class="fa-solid fa-flask-vial"></i>
                </div>
                <div class="text-xs">
                    <b class="text-amber-300 font-semibold uppercase tracking-wider">Aviso Ético: Hipótesis de Investigación No Confirmadas</b>
                    <p class="text-slate-400 mt-0.5">Las direcciones de correo generadas en este panel son permutaciones matemáticas hipotéticas. Jamás deben considerarse cuentas reales confirmadas sin evidencia independiente. Queda estrictamente prohibido enviar mensajes o realizar sondeos activos de SMTP.</p>
                </div>
            </div>

            <div class="bg-slate-900/60 border border-slate-800 rounded-xl p-5 shadow-lg">
                <h3 class="text-sm font-bold text-white uppercase tracking-wider mb-4 flex items-center gap-2">
                    <i class="fa-solid fa-diagram-project text-sky-400"></i> Variantes y Permutaciones de Identidad (Hipótesis)
                </h3>

                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs border-collapse">
                        <thead>
                            <tr class="border-b border-slate-800 text-slate-400 text-[11px] uppercase tracking-wider bg-slate-950/40">
                                <th class="p-3">Variante Hipotética</th>
                                <th class="p-3">Tipo de Dominio</th>
                                <th class="p-3">Patrón Heurístico</th>
                                <th class="p-3">Clasificación</th>
                            </tr>
                        </thead>
                        <tbody id="ei-variants-tbody" class="divide-y divide-slate-800/50">
                            <tr>
                                <td colspan="4" class="p-6 text-center text-slate-500">
                                    No hay variantes generadas para mostrar.
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- ========================================================= -->
        <!-- SUBTAB 8: RELATIONAL GRAPH (VIS-NETWORK) -->
        <!-- ========================================================= -->
        <div id="emailintel-pane-graph" class="emailintel-pane mt-6 space-y-4 hidden">
            <div id="ei-graph-backdrop" onclick="emailIntelToggleExpandGraph(false)" class="fixed inset-0 bg-slate-950/85 backdrop-blur-sm z-40 hidden"></div>
            <div id="ei-graph-wrapper" class="bg-slate-900/95 border border-slate-800 rounded-xl p-4 shadow-2xl flex flex-col transition-all duration-200">
                <div class="flex flex-wrap items-center justify-between gap-3 mb-3">
                    <div class="flex items-center gap-3">
                        <h3 class="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                            <i class="fa-solid fa-circle-nodes text-indigo-400"></i> Grafo de Conocimiento & Relaciones OSINT
                        </h3>
                        <span id="ei-graph-stats" class="text-[11px] px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700 hidden"></span>
                    </div>
                    <div class="flex flex-wrap items-center gap-1.5 text-xs">
                        <!-- Modo Manito vs Puntero -->
                        <div class="inline-flex rounded-lg bg-slate-950 p-0.5 border border-slate-700 mr-1" role="group" aria-label="Modo de manipulación">
                            <button id="ei-btn-mode-hand" onclick="emailIntelSetGraphMode('hand')" title="Modo Manito: arrastra todo el grafo libremente sin mover nodos" class="px-2.5 py-1 rounded-md bg-indigo-600 text-white font-medium flex items-center gap-1.5 transition">
                                <i class="fa-solid fa-hand"></i> <span>Manito</span>
                            </button>
                            <button id="ei-btn-mode-select" onclick="emailIntelSetGraphMode('select')" title="Modo Puntero: selecciona e inspecciona o mueve nodos individuales" class="px-2.5 py-1 rounded-md text-slate-300 hover:text-white flex items-center gap-1.5 transition">
                                <i class="fa-solid fa-arrow-pointer"></i> <span>Nodos</span>
                            </button>
                        </div>

                        <!-- Controles de Zoom -->
                        <div class="inline-flex items-center rounded-lg bg-slate-950 border border-slate-700 mr-1">
                            <button onclick="emailIntelZoomGraph(0.8)" title="Alejar (-)" class="px-2.5 py-1 text-slate-300 hover:text-white hover:bg-slate-800 rounded-l-lg transition">
                                <i class="fa-solid fa-magnifying-glass-minus"></i>
                            </button>
                            <span id="ei-graph-zoom-label" class="px-2 text-[11px] font-mono text-slate-300 border-x border-slate-800 select-none">100%</span>
                            <button onclick="emailIntelZoomGraph(1.25)" title="Acercar (+)" class="px-2.5 py-1 text-slate-300 hover:text-white hover:bg-slate-800 rounded-r-lg transition">
                                <i class="fa-solid fa-magnifying-glass-plus"></i>
                            </button>
                        </div>

                        <button onclick="emailIntelFitGraph()" title="Centrar y ajustar todo el grafo" class="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition">
                            <i class="fa-solid fa-compress mr-1"></i> Centrar
                        </button>
                        <button id="ei-btn-physics" onclick="emailIntelTogglePhysics()" title="Congelar / Reanudar física de nodos" class="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition">
                            <i class="fa-solid fa-snowflake mr-1 text-sky-400"></i> <span>Fijar</span>
                        </button>
                        <button onclick="emailIntelExportGraphPng()" title="Descargar imagen PNG del grafo" class="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition">
                            <i class="fa-solid fa-camera mr-1"></i> PNG
                        </button>
                        <button id="ei-btn-expand" onclick="emailIntelToggleExpandGraph()" title="Ampliar grafo a pantalla completa (Esc para salir)" class="px-3 py-1 rounded-lg bg-indigo-600/90 hover:bg-indigo-500 text-white font-semibold border border-indigo-400/40 transition">
                            <i class="fa-solid fa-expand mr-1"></i> <span>Ampliar</span>
                        </button>
                    </div>
                </div>

                <!-- Filtros rápidos y leyenda -->
                <div class="flex flex-wrap items-center justify-between gap-2 mb-3 text-[11px]">
                    <div class="flex flex-wrap items-center gap-1.5">
                        <span class="text-slate-400 mr-1">Filtrar:</span>
                        <button onclick="emailIntelFilterGraph('ALL')" data-ei-filter="ALL" class="ei-graph-filter-btn px-2 py-0.5 rounded-full bg-indigo-600 text-white border border-indigo-500">Todos</button>
                        <button onclick="emailIntelFilterGraph('leak')" data-ei-filter="leak" class="ei-graph-filter-btn px-2 py-0.5 rounded-full bg-slate-800 text-rose-300 border border-slate-700 hover:border-rose-500/60">Filtraciones</button>
                        <button onclick="emailIntelFilterGraph('account')" data-ei-filter="account" class="ei-graph-filter-btn px-2 py-0.5 rounded-full bg-slate-800 text-emerald-300 border border-slate-700 hover:border-emerald-500/60">Cuentas</button>
                        <button onclick="emailIntelFilterGraph('domain')" data-ei-filter="domain" class="ei-graph-filter-btn px-2 py-0.5 rounded-full bg-slate-800 text-sky-300 border border-slate-700 hover:border-sky-500/60">Dominio / MX</button>
                        <button onclick="emailIntelFilterGraph('device')" data-ei-filter="device" class="ei-graph-filter-btn px-2 py-0.5 rounded-full bg-slate-800 text-amber-300 border border-slate-700 hover:border-amber-500/60">Hosts</button>
                    </div>
                    <div class="flex flex-wrap items-center gap-3 text-slate-400">
                        <span class="flex items-center gap-1"><span class="w-2.5 h-2.5 rounded-full bg-blue-500 inline-block"></span> Correo</span>
                        <span class="flex items-center gap-1"><span class="w-2.5 h-2.5 rotate-45 bg-rose-500 inline-block"></span> Fuga</span>
                        <span class="flex items-center gap-1"><span class="w-2.5 h-2.5 rounded-full bg-amber-500 inline-block"></span> Host</span>
                        <span class="flex items-center gap-1"><span class="w-2.5 h-2.5 bg-emerald-500 inline-block"></span> Cuenta</span>
                        <span class="flex items-center gap-1"><span class="w-2.5 h-2.5 rounded-sm bg-teal-500 inline-block"></span> MX / Dominio</span>
                    </div>
                </div>

                <div id="ei-network-stage" class="relative w-full h-[640px] flex-1 min-h-0">
                    <div id="ei-network-container" class="w-full h-full bg-slate-950 rounded-xl border border-slate-800 relative overflow-hidden">
                        <div id="ei-network-loading" class="absolute inset-0 flex items-center justify-center text-slate-500 text-xs">
                            <i class="fa-solid fa-spinner fa-spin mr-2"></i> Inicializando grafo relacional...
                        </div>
                    </div>

                    <!-- Inspector flotante de nodo seleccionado -->
                    <div id="ei-node-inspector" class="hidden absolute bottom-3 left-3 max-w-sm bg-slate-900/95 border border-slate-700 rounded-xl p-3 shadow-2xl backdrop-blur-md z-10 text-xs">
                        <div class="flex items-start justify-between gap-3">
                            <div>
                                <span id="ei-inspector-group" class="text-[10px] font-bold uppercase px-1.5 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">NODO</span>
                                <p id="ei-inspector-label" class="text-slate-100 font-semibold mt-1.5 break-all whitespace-pre-line"></p>
                                <p id="ei-inspector-meta" class="text-slate-400 text-[11px] mt-1"></p>
                            </div>
                            <div class="flex items-center gap-1">
                                <button onclick="emailIntelCopyInspectorNode()" title="Copiar valor" class="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300">
                                    <i class="fa-regular fa-copy"></i>
                                </button>
                                <button onclick="document.getElementById('ei-node-inspector').classList.add('hidden')" title="Cerrar" class="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-400">
                                    <i class="fa-solid fa-xmark"></i>
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- ========================================================= -->
        <!-- SUBTAB 9: FORENSIC EVIDENCE VAULT -->
        <!-- ========================================================= -->
        <div id="emailintel-pane-evidence" class="emailintel-pane mt-6 space-y-6 hidden">
            <div class="bg-slate-900/60 border border-slate-800 rounded-xl p-5 shadow-lg">
                <h3 class="text-sm font-bold text-white uppercase tracking-wider mb-4 flex items-center gap-2">
                    <i class="fa-solid fa-fingerprint text-indigo-400"></i> Registro Inmutable de Evidencias Forenses
                </h3>

                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs border-collapse">
                        <thead>
                            <tr class="border-b border-slate-800 text-slate-400 text-[11px] uppercase tracking-wider bg-slate-950/40">
                                <th class="p-3">ID Evidencia</th>
                                <th class="p-3">Fuente</th>
                                <th class="p-3">Tipo</th>
                                <th class="p-3">Hash SHA-256</th>
                                <th class="p-3">Fecha Captura (UTC)</th>
                                <th class="p-3">Confianza</th>
                            </tr>
                        </thead>
                        <tbody id="ei-evidence-tbody" class="divide-y divide-slate-800/50">
                            <tr>
                                <td colspan="6" class="p-6 text-center text-slate-500">
                                    No hay evidencias registradas en la bóveda.
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

    </div>
</section>

<!-- ========================================================= -->
<!-- MODAL: NUEVA INVESTIGACIÓN EMAIL INTELLIGENCE -->
<!-- ========================================================= -->
<div id="modal-new-email-investigation" class="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4 hidden">
    <div class="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-xl shadow-2xl overflow-hidden">
        <div class="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
            <div class="flex items-center gap-2.5">
                <div class="w-8 h-8 rounded-lg bg-sky-950 border border-sky-800/60 flex items-center justify-center text-sky-400 text-sm">
                    <i class="fa-solid fa-at"></i>
                </div>
                <h3 class="text-sm font-bold text-white uppercase tracking-wider">Nueva Investigación OSINT de Correo</h3>
            </div>
            <button onclick="emailIntelCloseNewModal()" class="text-slate-400 hover:text-white transition">
                <i class="fa-solid fa-xmark text-lg"></i>
            </button>
        </div>

        <form id="form-new-email-investigation" onsubmit="emailIntelSubmitInvestigation(event)" class="p-6 space-y-4">
            <div>
                <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">
                    Dirección de Correo Electrónico *
                </label>
                <input type="email" id="ei-input-email" required placeholder="ej. usuario@empresa.com" class="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-sm text-slate-200 focus:border-sky-500 focus:outline-none font-mono">
            </div>

            <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                    <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">
                        Identificador de Caso *
                    </label>
                    <input type="text" id="ei-input-case-id" required placeholder="ej. CASE-2026-089" class="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs text-slate-200 focus:border-sky-500 focus:outline-none font-mono">
                </div>
                <div>
                    <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">
                        Etiquetas (separadas por coma)
                    </label>
                    <input type="text" id="ei-input-tags" placeholder="VIP, PHISHING, STEALER" class="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs text-slate-200 focus:border-sky-500 focus:outline-none">
                </div>
            </div>

            <div>
                <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">
                    Nombre / Título de la Investigación *
                </label>
                <input type="text" id="ei-input-title" required placeholder="ej. Exposición Perimetral de Correo Corporativo" class="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs text-slate-200 focus:border-sky-500 focus:outline-none">
            </div>

            <div>
                <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">
                    Descripción Contextual
                </label>
                <textarea id="ei-input-desc" rows="2" placeholder="Notas contextuales sobre la procedencia del indicador o incidente..." class="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs text-slate-200 focus:border-sky-500 focus:outline-none"></textarea>
            </div>

            <div>
                <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">
                    Autorización / Justificación Legal (RoE) *
                </label>
                <input type="text" id="ei-input-justification" required placeholder="ej. Autorizado bajo contrato de auditoría SOC - Regla de Compromiso RoE #401" class="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs text-slate-200 focus:border-sky-500 focus:outline-none">
            </div>

            <div class="pt-2 flex items-center justify-end gap-2 border-t border-slate-800">
                <button type="button" onclick="emailIntelCloseNewModal()" class="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-300 transition">
                    Cancelar
                </button>
                <button type="submit" id="btn-submit-email-investigation" class="px-4 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 text-xs font-bold text-slate-950 transition flex items-center gap-1.5 shadow-lg shadow-sky-600/20">
                    <i class="fa-solid fa-play"></i> Iniciar Investigación
                </button>
            </div>
        </form>
    </div>
</div>

<style>
.emailintel-nav-pill {
    padding: 0.375rem 0.75rem;
    border-radius: 0.5rem;
    font-weight: 600;
    white-space: nowrap;
    color: #94a3b8;
    background: transparent;
    border: 1px solid transparent;
    transition: all 0.15s ease-in-out;
}
.emailintel-nav-pill:hover {
    color: #f8fafc;
    background: rgba(30, 41, 59, 0.6);
}
.emailintel-nav-pill.active {
    color: #38bdf8;
    background: rgba(15, 23, 42, 0.9);
    border-color: rgba(56, 189, 248, 0.4);
    box-shadow: 0 4px 12px rgba(56, 189, 248, 0.1);
}
</style>

<script>
// =============================================================================
// EMAIL INTELLIGENCE CLIENT LOGIC
// =============================================================================

let currentEmailInvestigationId = null;
let emailIntelAllInvs = [];
let emailIntelGraphNetwork = null;
let emailIntelPollTimer = null;

// Tab switcher inside Email Intelligence
function emailIntelSwitchSubTab(subTabId) {
    document.querySelectorAll('.emailintel-nav-pill').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.emailintel-pane').forEach(pane => pane.classList.add('hidden'));

    const btn = document.getElementById(`emailintel-subtab-btn-${subTabId}`);
    if (btn) btn.classList.add('active');

    const pane = document.getElementById(`emailintel-pane-${subTabId}`);
    if (pane) pane.classList.remove('hidden');

    if (subTabId === 'graph') {
        setTimeout(emailIntelRenderGraph, 100);
    }
}

// Initial overview load
async function emailIntelLoadOverview() {
    try {
        const res = await fetch(`${API_URL}?action=email_intel_list`);
        const data = await res.json();
        if (data.status === 'ok') {
            emailIntelAllInvs = data.investigations || [];
            emailIntelRenderOverviewTable(emailIntelAllInvs);
            emailIntelUpdateOverviewStats(emailIntelAllInvs);

            // Auto-select latest investigation if none selected
            if (!currentEmailInvestigationId && emailIntelAllInvs.length > 0) {
                emailIntelSelectInvestigation(emailIntelAllInvs[0].id, false);
            }
        }
    } catch (e) {
        console.error("Error loading email intel investigations:", e);
    }
}

function emailIntelUpdateOverviewStats(invs) {
    document.getElementById('ei-stat-total-invs').textContent = invs.length;
    let totalLeaks = 0;
    let totalAccounts = 0;
    let totalPastes = 0;
    invs.forEach(i => {
        totalLeaks += (i.leaks_count || 0);
        totalAccounts += (i.accounts_confirmed || 0);
        totalPastes += (i.pastes_count || 0);
    });
    document.getElementById('ei-stat-total-leaks').textContent = totalLeaks;
    document.getElementById('ei-stat-total-accounts').textContent = totalAccounts;
    document.getElementById('ei-stat-total-pastes').textContent = totalPastes;

    // Update sidebar badge
    const badge = document.getElementById('nav-badge-emailintel');
    if (badge) badge.textContent = invs.length;
}

function emailIntelRenderOverviewTable(invs) {
    const tbody = document.getElementById('ei-investigations-tbody');
    if (!tbody) return;

    if (invs.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="9" class="p-6 text-center text-slate-500">
                    No se han registrado investigaciones. Haga clic en <b>Nueva Investigación</b> para iniciar una.
                </td>
            </tr>`;
        return;
    }

    tbody.innerHTML = invs.map(i => {
        let riskColor = 'text-slate-400 bg-slate-800 border-slate-700';
        if (i.risk_level === 'CRITICAL') riskColor = 'text-rose-300 bg-rose-950 border-rose-800';
        else if (i.risk_level === 'HIGH') riskColor = 'text-orange-300 bg-orange-950 border-orange-800';
        else if (i.risk_level === 'MEDIUM') riskColor = 'text-amber-300 bg-amber-950 border-amber-800';
        else if (i.risk_level === 'LOW') riskColor = 'text-emerald-300 bg-emerald-950 border-emerald-800';

        let statusColor = 'text-slate-400 bg-slate-900';
        if (i.status === 'RUNNING') statusColor = 'text-sky-300 bg-sky-950 animate-pulse';
        else if (i.status === 'COMPLETED') statusColor = 'text-emerald-300 bg-emerald-950';
        else if (i.status === 'FAILED') statusColor = 'text-rose-300 bg-rose-950';

        const isSelected = i.id === currentEmailInvestigationId;
        const rowClass = isSelected ? 'bg-sky-950/20 border-l-2 border-sky-400' : 'hover:bg-slate-950/30';

        return `
            <tr class="${rowClass} transition cursor-pointer" onclick="emailIntelSelectInvestigation('${i.id}')">
                <td class="p-3 font-mono font-bold text-sky-400">${i.case_id || i.id}</td>
                <td class="p-3 font-mono text-white font-semibold">${i.target_email}</td>
                <td class="p-3 text-slate-300">
                    <div class="font-medium">${i.title}</div>
                    <div class="text-[10px] text-slate-500 truncate max-w-xs">${i.authorization_justification}</div>
                </td>
                <td class="p-3 font-mono font-bold ${i.exposure_score >= 70 ? 'text-rose-400' : (i.exposure_score >= 40 ? 'text-amber-400' : 'text-emerald-400')}">
                    ${parseFloat(i.exposure_score).toFixed(1)} / 100
                </td>
                <td class="p-3">
                    <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase border font-mono ${riskColor}">
                        ${i.risk_level}
                    </span>
                </td>
                <td class="p-3 font-mono text-slate-300 text-[11px]">
                    <span title="Filtraciones" class="text-rose-400 mr-2"><i class="fa-solid fa-skull mr-0.5"></i>${i.leaks_count || 0}</span>
                    <span title="Cuentas Confirmadas" class="text-emerald-400 mr-2"><i class="fa-solid fa-user-check mr-0.5"></i>${i.accounts_confirmed || 0}</span>
                    <span title="Pastes" class="text-amber-400"><i class="fa-solid fa-paste mr-0.5"></i>${i.pastes_count || 0}</span>
                </td>
                <td class="p-3">
                    <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase ${statusColor}">
                        ${i.status}
                    </span>
                </td>
                <td class="p-3 text-slate-500 text-[11px] font-mono">
                    ${(i.created_at || '').substring(0, 16)}
                </td>
                <td class="p-3 text-right">
                    <button onclick="event.stopPropagation(); emailIntelSelectInvestigation('${i.id}', true)" class="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-sky-400 text-xs font-semibold">
                        Ver <i class="fa-solid fa-arrow-right ml-1"></i>
                    </button>
                </td>
            </tr>
        `;
    }).join('');
}

function emailIntelFilterTable() {
    const q = (document.getElementById('ei-filter-search').value || '').toLowerCase();
    const filtered = emailIntelAllInvs.filter(i => 
        (i.target_email || '').toLowerCase().includes(q) ||
        (i.case_id || '').toLowerCase().includes(q) ||
        (i.title || '').toLowerCase().includes(q)
    );
    emailIntelRenderOverviewTable(filtered);
}

// Polling Management for Real-Time Execution
function emailIntelStopPolling() {
    if (emailIntelPollTimer) {
        clearInterval(emailIntelPollTimer);
        emailIntelPollTimer = null;
    }
}

function emailIntelStartPolling(invId) {
    emailIntelStopPolling();
    emailIntelPollTimer = setInterval(async () => {
        if (!currentEmailInvestigationId || currentEmailInvestigationId !== invId) {
            emailIntelStopPolling();
            return;
        }
        try {
            const res = await fetch(`${API_URL}?action=email_intel_get&id=${invId}`);
            const data = await res.json();
            if (data.status === 'ok') {
                const inv = data.investigation;
                emailIntelPopulateDetailView(inv);
                emailIntelPopulateLeaks(inv.leaks || []);
                emailIntelPopulateAccounts(inv.accounts || []);
                emailIntelPopulateDomain(inv.domain_analysis || {});
                emailIntelPopulatePastes(inv.pastes || []);
                emailIntelPopulateVariants(inv.generated_variants || []);
                emailIntelLoadEvidenceVault(inv.evidences || []);

                if (inv.status === 'COMPLETED' || inv.status === 'FAILED' || inv.status === 'CANCELLED' || inv.status === 'PAUSED') {
                    emailIntelStopPolling();
                    emailIntelLoadOverview();
                }
            }
        } catch (err) {
            console.error("Polling error for investigation " + invId, err);
        }
    }, 2000);
}

// Select investigation and load details across all tabs
async function emailIntelSelectInvestigation(invId, switchToDetail = false) {
    currentEmailInvestigationId = invId;
    emailIntelRenderOverviewTable(emailIntelAllInvs);

    try {
        const res = await fetch(`${API_URL}?action=email_intel_get&id=${invId}`);
        const data = await res.json();
        if (data.status === 'ok') {
            const inv = data.investigation;
            emailIntelPopulateDetailView(inv);
            emailIntelPopulateLeaks(inv.leaks || []);
            emailIntelPopulateAccounts(inv.accounts || []);
            emailIntelPopulateDomain(inv.domain_analysis || {});
            emailIntelPopulatePastes(inv.pastes || []);
            emailIntelPopulateVariants(inv.generated_variants || []);
            emailIntelLoadEvidenceVault(inv.evidences || []);

            // Check if active polling is required
            if (inv.status === 'RUNNING' || inv.status === 'PENDING') {
                emailIntelStartPolling(invId);
            } else {
                emailIntelStopPolling();
            }

            if (switchToDetail) {
                emailIntelSwitchSubTab('detail');
            }
        }
    } catch (e) {
        console.error("Error loading investigation detail:", e);
    }
}

function emailIntelPopulateDetailView(inv) {
    document.getElementById('ei-det-id').textContent = inv.id;
    document.getElementById('ei-det-email').textContent = inv.target_email;
    document.getElementById('ei-det-case-id').textContent = inv.case_id;
    document.getElementById('ei-det-justification').textContent = inv.authorization_justification;
    document.getElementById('ei-det-title-desc').textContent = `${inv.title} — ${inv.description || 'Sin descripción adicional.'}`;

    // Status Badge
    const sBadge = document.getElementById('ei-det-status-badge');
    if (sBadge) {
        const st = inv.status || 'PENDING';
        sBadge.textContent = st;
        if (st === 'COMPLETED') {
            sBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-emerald-950 text-emerald-300 border border-emerald-800';
        } else if (st === 'RUNNING') {
            sBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-sky-950 text-sky-300 border border-sky-800 animate-pulse';
        } else if (st === 'PENDING') {
            sBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-amber-950 text-amber-300 border border-amber-800 animate-pulse';
        } else if (st === 'FAILED') {
            sBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-rose-950 text-rose-300 border border-rose-800';
        } else if (st === 'PAUSED') {
            sBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-amber-950 text-amber-300 border border-amber-800';
        } else {
            sBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-800 text-slate-400 border border-slate-700';
        }
    }

    // Risk dial
    const dial = document.getElementById('ei-det-score-dial');
    const scoreVal = parseFloat(inv.exposure_score || 0);
    dial.textContent = scoreVal.toFixed(1);
    if (scoreVal >= 70) {
        dial.className = 'w-16 h-16 rounded-full flex items-center justify-center text-xl font-bold font-mono border-4 border-rose-500 bg-rose-950/40 text-rose-400';
    } else if (scoreVal >= 40) {
        dial.className = 'w-16 h-16 rounded-full flex items-center justify-center text-xl font-bold font-mono border-4 border-amber-500 bg-amber-950/40 text-amber-400';
    } else if (scoreVal > 0) {
        dial.className = 'w-16 h-16 rounded-full flex items-center justify-center text-xl font-bold font-mono border-4 border-emerald-500 bg-emerald-950/40 text-emerald-400';
    } else {
        dial.className = 'w-16 h-16 rounded-full flex items-center justify-center text-xl font-bold font-mono border-4 border-slate-700 bg-slate-900/40 text-slate-400';
    }
    
    // Risk badge
    const rBadge = document.getElementById('ei-det-risk-badge');
    rBadge.textContent = inv.risk_level || 'INFORMATIVO';
    rBadge.className = `px-2.5 py-0.5 rounded text-xs font-bold uppercase border font-mono ${
        inv.risk_level === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border-rose-800' :
        inv.risk_level === 'HIGH' ? 'bg-orange-950 text-orange-300 border-orange-800' :
        inv.risk_level === 'MEDIUM' ? 'bg-amber-950 text-amber-300 border-amber-800' :
        inv.risk_level === 'LOW' ? 'bg-emerald-950 text-emerald-300 border-emerald-800' :
        'bg-slate-900 text-slate-400 border-slate-700'
    }`;

    document.getElementById('ei-det-risk-explanation').textContent = inv.risk_explanation || 'Ponderación calculada sin riesgos críticos.';
    document.getElementById('ei-det-progress-text').textContent = `${inv.progress}%`;
    document.getElementById('ei-det-progress-bar').style.width = `${inv.progress}%`;

    // Counts
    document.getElementById('ei-det-leaks-count').textContent = (inv.leaks || []).length;
    document.getElementById('ei-det-acc-count').textContent = (inv.accounts || []).filter(a => a.status === 'CONFIRMED').length;
    document.getElementById('ei-det-dns-score').textContent = `${inv.domain_analysis ? inv.domain_analysis.dns_security_score : 0} / 100`;
    document.getElementById('ei-det-ev-count').textContent = inv.evidences_count || 0;
}

function emailIntelPopulateLeaks(leaks) {
    const container = document.getElementById('ei-leaks-container');
    if (!container) return;

    if (leaks.length === 0) {
        container.innerHTML = `
            <div class="p-8 text-center text-slate-500 text-xs bg-slate-950/40 rounded-xl border border-slate-800/60">
                <i class="fa-solid fa-shield-cat text-3xl text-emerald-500/40 mb-2 block"></i>
                No se detectaron infecciones por info-stealers ni credenciales filtradas asociadas a esta dirección.
            </div>`;
        return;
    }

    container.innerHTML = leaks.map(l => {
        const isXon = String(l.source || '').startsWith('XposedOrNot');
        const badge = isXon
            ? '<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-amber-950 text-amber-300 border border-amber-800">XPOSEDORNOT BREACH</span>'
            : '<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-rose-950 text-rose-400 border border-rose-800">INFO-STEALER</span>';
        const cats = Array.isArray(l.exposed_data_types) ? l.exposed_data_types : [];
        const catsHtml = cats.map(c => `<span class="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-700 text-[10px] font-mono text-cyan-300">${c}</span>`).join(' ');
        const detailsHtml = isXon ? `
            <div class="text-xs text-slate-300 flex flex-wrap items-center gap-x-4 gap-y-1 pt-1">
                <span><i class="fa-solid fa-globe text-slate-500 mr-1"></i>Dominio/Servicio: <b class="text-cyan-300 font-mono">${l.computer_name_preview || 'N/A'}</b></span>
                <span><i class="fa-solid fa-industry text-slate-500 mr-1"></i>Categoría: <b class="text-slate-300">${l.operating_system || 'Breach'}</b></span>
                <span><i class="fa-solid fa-database text-slate-500 mr-1"></i>Volumen: <b class="text-amber-400 font-mono">${l.ip_address_preview || 'N/D'}</b></span>
                ${l.verifiable_reference ? `<a href="${l.verifiable_reference}" target="_blank" rel="noopener noreferrer" class="text-cyan-400 hover:underline"><i class="fa-solid fa-arrow-up-right-from-square mr-1"></i>Referencia</a>` : ''}
            </div>
            <div class="flex flex-wrap gap-1 pt-1.5">${catsHtml}</div>` : `
            <div class="text-xs text-slate-300 flex flex-wrap items-center gap-x-4 gap-y-1 pt-1">
                <span><i class="fa-solid fa-building text-slate-500 mr-1"></i>Servicios Corporativos: <b class="text-rose-400 font-mono">${l.corporate_services_count || 0}</b></span>
                <span><i class="fa-solid fa-users text-slate-500 mr-1"></i>Cuentas de Usuario: <b class="text-amber-400 font-mono">${l.user_services_count || 0}</b></span>
                <span><i class="fa-solid fa-laptop text-slate-500 mr-1"></i>Host: <b class="text-slate-300 font-mono">${l.computer_name_preview || 'N/A'}</b> (${l.operating_system || 'SO no especificado'})</span>
                <span><i class="fa-solid fa-network-wired text-slate-500 mr-1"></i>IP Anónima: <b class="text-slate-400 font-mono">${l.ip_address_preview || '***'}</b></span>
            </div>`;
        return `
        <div class="bg-slate-950 border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-4 shadow">
            <div class="space-y-1">
                <div class="flex items-center gap-2 flex-wrap">
                    ${badge}
                    <h4 class="text-sm font-bold text-white">${l.source}</h4>
                    <span class="text-xs text-slate-500 font-mono">(${l.leak_date || 'Fecha desconocida'})</span>
                </div>
                ${detailsHtml}
            </div>
            <div class="text-right shrink-0">
                <span class="px-2 py-1 rounded text-[10px] font-mono bg-slate-900 text-slate-400 border border-slate-800 block">
                    ${l.confidence_level || 'HIGH'} · K-Anonymity
                </span>
                <span class="text-[9px] text-slate-600 block mt-1 font-mono">SHA: ${(l.raw_evidence_sha256 || '').substring(0, 12)}...</span>
            </div>
        </div>`;
    }).join('');
}

function emailIntelPopulateAccounts(accounts) {
    const grid = document.getElementById('ei-accounts-grid');
    if (!grid) return;

    if (accounts.length === 0) {
        grid.innerHTML = `
            <div class="col-span-full p-8 text-center text-slate-500 text-xs bg-slate-950/40 rounded-xl border border-slate-800/60">
                No hay cuentas digitales evaluadas para esta investigación.
            </div>`;
        return;
    }

    grid.innerHTML = accounts.map(a => {
        let badgeClass = 'bg-slate-900 text-slate-400 border-slate-800';
        let icon = 'fa-solid fa-circle-question text-slate-500';
        if (a.status === 'CONFIRMED') {
            badgeClass = 'bg-emerald-950 text-emerald-300 border-emerald-800';
            icon = 'fa-solid fa-circle-check text-emerald-400';
        } else if (a.status === 'PROBABLE') {
            badgeClass = 'bg-blue-950 text-blue-300 border-blue-800';
            icon = 'fa-solid fa-circle-info text-blue-400';
        } else if (a.status === 'NOT_FOUND') {
            badgeClass = 'bg-slate-900 text-slate-500 border-slate-800';
            icon = 'fa-solid fa-circle-xmark text-slate-600';
        } else if (a.status === 'INCONCLUSIVE') {
            badgeClass = 'bg-amber-950 text-amber-300 border-amber-800';
            icon = 'fa-solid fa-triangle-exclamation text-amber-400';
        }

        return `
            <div class="bg-slate-950 border border-slate-800 rounded-xl p-4 flex items-start gap-3 shadow hover:border-slate-700 transition">
                ${a.avatar_url ? 
                    `<img src="${a.avatar_url}" alt="${a.platform}" class="w-10 h-10 rounded-full border border-slate-700 object-cover shrink-0">` :
                    `<div class="w-10 h-10 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-center text-slate-400 text-lg shrink-0">
                        <i class="fa-solid fa-globe"></i>
                    </div>`
                }
                <div class="space-y-1 min-w-0 flex-1">
                    <div class="flex items-center justify-between">
                        <h4 class="text-sm font-bold text-white truncate">${a.platform}</h4>
                        <span class="px-2 py-0.5 rounded text-[9px] font-bold uppercase border font-mono ${badgeClass}">
                            ${a.status}
                        </span>
                    </div>
                    <div class="text-xs text-slate-400 truncate">
                        ${a.username ? `<b class="text-slate-200">@${a.username}</b>` : '<span class="italic text-slate-600">Sin alias público</span>'}
                    </div>
                    <div class="text-[10px] text-slate-500 truncate" title="${a.evidence_snippet || ''}">
                        ${a.evidence_snippet || a.check_method}
                    </div>
                    ${a.profile_url ? 
                        `<a href="${a.profile_url}" target="_blank" rel="noopener noreferrer" class="text-[10px] text-sky-400 hover:underline inline-flex items-center gap-1 pt-1">
                            Ver Perfil <i class="fa-solid fa-arrow-up-right-from-square text-[9px]"></i>
                        </a>` : ''
                    }
                </div>
            </div>
        `;
    }).join('');
}

function emailIntelFilterAccounts(status) {
    if (!currentEmailInvestigationId) return;
    const cards = document.querySelectorAll('#ei-accounts-grid > div');
    cards.forEach(card => {
        if (status === 'ALL') {
            card.classList.remove('hidden');
        } else {
            const hasStatus = card.textContent.includes(status);
            card.classList.toggle('hidden', !hasStatus);
        }
    });
}

function emailIntelPopulateDomain(domain) {
    document.getElementById('ei-domain-name').textContent = domain.domain || '-';
    document.getElementById('ei-domain-provider').textContent = domain.mail_provider || 'No detectado';
    
    const scoreBadge = document.getElementById('ei-domain-score-badge');
    scoreBadge.textContent = `${domain.dns_security_score || 0} / 100`;
    scoreBadge.className = `px-2.5 py-0.5 rounded text-xs font-bold font-mono border ${
        (domain.dns_security_score || 0) >= 80 ? 'bg-emerald-950 text-emerald-300 border-emerald-800' :
        (domain.dns_security_score || 0) >= 50 ? 'bg-amber-950 text-amber-300 border-amber-800' :
        'bg-rose-950 text-rose-300 border-rose-800'
    }`;

    // SPF
    document.getElementById('ei-spf-status').textContent = domain.spf_status || 'MISSING';
    document.getElementById('ei-spf-record').textContent = domain.spf_record || 'Sin registro SPF autoritativo v=spf1';

    // DMARC
    document.getElementById('ei-dmarc-status').textContent = domain.dmarc_status || 'MISSING';
    document.getElementById('ei-dmarc-record').textContent = domain.dmarc_record || 'Sin registro DMARC autoritativo _dmarc';

    // DKIM
    document.getElementById('ei-dkim-status').textContent = domain.dkim_status || 'NOT_TESTED';

    // Weaknesses & Recommendations
    const wList = document.getElementById('ei-domain-weaknesses-list');
    const weaknesses = domain.weaknesses || [];
    wList.innerHTML = weaknesses.length > 0 ? 
        weaknesses.map(w => `<li class="flex items-start gap-1.5"><i class="fa-solid fa-circle-xmark text-rose-400 mt-0.5 shrink-0"></i><span>${w}</span></li>`).join('') :
        '<li class="text-slate-500 italic">No se detectaron debilidades críticas en DNS.</li>';

    const rList = document.getElementById('ei-domain-recommendations-list');
    const recs = domain.recommendations || [];
    rList.innerHTML = recs.length > 0 ? 
        recs.map(r => `<li class="flex items-start gap-1.5"><i class="fa-solid fa-arrow-right text-emerald-400 mt-0.5 shrink-0"></i><span>${r}</span></li>`).join('') :
        '<li class="text-slate-500 italic">Configuración perimetral óptima.</li>';
}

function emailIntelPopulatePastes(pastes) {
    const container = document.getElementById('ei-pastes-container');
    if (!container) return;

    if (pastes.length === 0) {
        container.innerHTML = `
            <div class="p-8 text-center text-slate-500 text-xs bg-slate-950/40 rounded-xl border border-slate-800/60">
                No se encontraron referencias en pastes públicos accesibles.
            </div>`;
        return;
    }

    container.innerHTML = pastes.map(p => `
        <div class="bg-slate-950 border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div class="space-y-1">
                <div class="flex items-center gap-2">
                    <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-amber-950 text-amber-300 border border-amber-800">${p.classification || 'PASTE'}</span>
                    <h4 class="text-sm font-bold text-white">${p.source}</h4>
                </div>
                <code class="text-xs text-slate-300 block font-mono bg-slate-900/60 p-2 rounded border border-slate-800">
                    ${p.minimal_context || 'Mención textual descubierta'}
                </code>
            </div>
            <div class="text-right shrink-0">
                <a href="${p.paste_url}" target="_blank" rel="noopener noreferrer" class="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-sky-400 text-xs font-semibold inline-flex items-center gap-1">
                    Visitar Paste <i class="fa-solid fa-arrow-up-right-from-square text-[10px]"></i>
                </a>
            </div>
        </div>
    `).join('');
}

function emailIntelPopulateVariants(variants) {
    const tbody = document.getElementById('ei-variants-tbody');
    if (!tbody) return;

    if (variants.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="4" class="p-6 text-center text-slate-500 text-xs">
                    No se han generado variantes para esta investigación.
                </td>
            </tr>`;
        return;
    }

    tbody.innerHTML = variants.map(v => `
        <tr class="hover:bg-slate-950/40 transition">
            <td class="p-3 font-mono font-bold text-sky-300">${v.variant_email}</td>
            <td class="p-3 text-slate-400">${v.domain_type}</td>
            <td class="p-3 text-slate-300 font-mono text-[11px]">${v.pattern_type}</td>
            <td class="p-3">
                <span class="px-2 py-0.5 rounded text-[9px] font-bold uppercase bg-amber-950/80 text-amber-300 border border-amber-800/60 font-mono">
                    ${v.classification}
                </span>
            </td>
        </tr>
    `).join('');
}

function emailIntelLoadEvidenceVault(evidences) {
    const tbody = document.getElementById('ei-evidence-tbody');
    if (!tbody) return;

    if (!Array.isArray(evidences) || evidences.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="p-6 text-center text-slate-500">
                    <i class="fa-solid fa-lock text-2xl text-slate-600 mb-2 block"></i>
                    No hay evidencias registradas en la bóveda forense para este caso.
                </td>
            </tr>`;
        return;
    }

    tbody.innerHTML = evidences.map(e => `
        <tr class="hover:bg-slate-900/40 font-mono text-xs transition">
            <td class="p-3 text-sky-400 font-bold">${e.evidence_id || e.id}</td>
            <td class="p-3 text-slate-300">${e.source}</td>
            <td class="p-3">
                <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-800 text-slate-300 border border-slate-700">
                    ${e.evidence_type}
                </span>
            </td>
            <td class="p-3 text-slate-400 font-mono text-[11px] truncate max-w-xs" title="${e.raw_sha256}">
                <i class="fa-solid fa-fingerprint text-indigo-400 mr-1"></i>${(e.raw_sha256 || '').substring(0, 24)}...
            </td>
            <td class="p-3 text-slate-500 text-[11px]">${(e.collected_at || '').substring(0, 19)}</td>
            <td class="p-3">
                <span class="px-2 py-0.5 rounded text-[10px] font-bold ${
                    e.confidence === 'HIGH' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' :
                    e.confidence === 'MEDIUM' ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                    'bg-slate-800 text-slate-400'
                }">
                    ${e.confidence || 'HIGH'}
                </span>
            </td>
        </tr>
    `).join('');
}

// Render Graph using Vis-Network (UX Enhanced: Hand Pan Mode, Zoom Controls, Expand, Filter & Inspector)
let emailIntelGraphNodesDS = null;
let emailIntelGraphEdgesDS = null;
let emailIntelGraphRawNodes = [];
let emailIntelGraphMode = 'hand';
let emailIntelGraphPhysicsEnabled = true;
let emailIntelGraphExpanded = false;

async function emailIntelRenderGraph() {
    if (!currentEmailInvestigationId) return;
    const container = document.getElementById('ei-network-container');
    const loading = document.getElementById('ei-network-loading');
    const statsEl = document.getElementById('ei-graph-stats');
    const inspector = document.getElementById('ei-node-inspector');
    if (!container) return;
    if (inspector) inspector.classList.add('hidden');

    try {
        const res = await fetch(`${API_URL}?action=email_intel_graph&id=${currentEmailInvestigationId}`);
        const data = await res.json();

        if (data.status === 'ok') {
            if (loading) loading.style.display = 'none';

            // Normalize node sizes/fonts so MX database nodes do not overlap neighboring labels
            emailIntelGraphRawNodes = (data.nodes || []).map((n) => {
                const copy = { ...n };
                if (copy.shape === 'database' || copy.group === 'mx') {
                    copy.size = 18;
                    copy.widthConstraint = { maximum: 190 };
                    copy.font = { ...(copy.font || {}), size: 10, color: '#e2e8f0' };
                } else {
                    copy.font = { ...(copy.font || {}), size: 11 };
                }
                copy._origColor = copy.color;
                return copy;
            });

            emailIntelGraphNodesDS = new vis.DataSet(emailIntelGraphRawNodes);
            emailIntelGraphEdgesDS = new vis.DataSet(data.edges || []);

            if (statsEl) {
                statsEl.textContent = `${emailIntelGraphRawNodes.length} nodos · ${(data.edges || []).length} relaciones`;
                statsEl.classList.remove('hidden');
            }

            const options = {
                physics: {
                    enabled: true,
                    stabilization: { iterations: 250, updateInterval: 25 },
                    barnesHut: {
                        gravitationalConstant: -8500,
                        centralGravity: 0.25,
                        springLength: 175,
                        springConstant: 0.04,
                        damping: 0.14,
                        avoidOverlap: 0.85
                    }
                },
                nodes: {
                    borderWidth: 2,
                    shadow: true
                },
                edges: {
                    smooth: { type: 'dynamic' },
                    arrows: { to: { enabled: true, scaleFactor: 0.75 } },
                    font: {
                        size: 9,
                        color: '#cbd5e1',
                        strokeWidth: 0,
                        background: 'rgba(15, 23, 42, 0.85)'
                    }
                },
                interaction: {
                    hover: true,
                    dragView: true,
                    zoomView: true,
                    dragNodes: emailIntelGraphMode === 'select',
                    keyboard: { enabled: true }
                }
            };

            if (emailIntelGraphNetwork) {
                emailIntelGraphNetwork.destroy();
            }
            emailIntelGraphNetwork = new vis.Network(
                container,
                { nodes: emailIntelGraphNodesDS, edges: emailIntelGraphEdgesDS },
                options
            );

            emailIntelGraphPhysicsEnabled = true;
            emailIntelUpdatePhysicsButton();
            emailIntelSetGraphMode(emailIntelGraphMode);

            emailIntelGraphNetwork.once('stabilizationIterationsDone', () => {
                emailIntelGraphPhysicsEnabled = false;
                emailIntelGraphNetwork.setOptions({ physics: { enabled: false } });
                emailIntelUpdatePhysicsButton();
                emailIntelGraphNetwork.fit({ animation: { duration: 300, easingFunction: 'easeInOutQuad' } });
            });

            emailIntelGraphNetwork.on('zoom', () => {
                emailIntelUpdateZoomLabel();
            });
            emailIntelGraphNetwork.on('afterDrawing', () => {
                emailIntelUpdateZoomLabel();
            });
            emailIntelGraphNetwork.on('click', (params) => {
                if (!params.nodes || params.nodes.length === 0) {
                    if (inspector) inspector.classList.add('hidden');
                    return;
                }
                const nodeId = params.nodes[0];
                const node = emailIntelGraphNodesDS.get(nodeId);
                if (node && inspector) {
                    const edgesCount = (emailIntelGraphNetwork.getConnectedEdges(nodeId) || []).length;
                    document.getElementById('ei-inspector-group').textContent = (node.group || 'ENTIDAD').toUpperCase();
                    document.getElementById('ei-inspector-label').textContent = node.label || node.id;
                    document.getElementById('ei-inspector-meta').textContent = `ID: ${node.id} · Conexiones: ${edgesCount}`;
                    inspector.classList.remove('hidden');
                }
            });

            container.onmousedown = () => {
                if (emailIntelGraphMode === 'hand') container.style.cursor = 'grabbing';
            };
            container.onmouseup = () => {
                container.style.cursor = emailIntelGraphMode === 'hand' ? 'grab' : 'default';
            };
        }
    } catch (e) {
        console.error("Error rendering email intel graph:", e);
    }
}

function emailIntelUpdateZoomLabel() {
    const label = document.getElementById('ei-graph-zoom-label');
    if (label && emailIntelGraphNetwork) {
        const pct = Math.max(10, Math.round(emailIntelGraphNetwork.getScale() * 100));
        label.textContent = `${pct}%`;
    }
}

function emailIntelSetGraphMode(mode) {
    emailIntelGraphMode = mode === 'select' ? 'select' : 'hand';
    const handBtn = document.getElementById('ei-btn-mode-hand');
    const selBtn = document.getElementById('ei-btn-mode-select');
    const container = document.getElementById('ei-network-container');

    if (handBtn && selBtn) {
        if (emailIntelGraphMode === 'hand') {
            handBtn.className = 'px-2.5 py-1 rounded-md bg-indigo-600 text-white font-medium flex items-center gap-1.5 transition';
            selBtn.className = 'px-2.5 py-1 rounded-md text-slate-300 hover:text-white flex items-center gap-1.5 transition';
        } else {
            selBtn.className = 'px-2.5 py-1 rounded-md bg-indigo-600 text-white font-medium flex items-center gap-1.5 transition';
            handBtn.className = 'px-2.5 py-1 rounded-md text-slate-300 hover:text-white flex items-center gap-1.5 transition';
        }
    }
    if (container) {
        container.style.cursor = emailIntelGraphMode === 'hand' ? 'grab' : 'default';
    }
    if (emailIntelGraphNetwork) {
        emailIntelGraphNetwork.setOptions({
            interaction: {
                dragView: true,
                dragNodes: emailIntelGraphMode === 'select'
            }
        });
    }
}

function emailIntelZoomGraph(factor) {
    if (!emailIntelGraphNetwork) return;
    const current = emailIntelGraphNetwork.getScale();
    const target = Math.min(4.0, Math.max(0.2, current * factor));
    emailIntelGraphNetwork.moveTo({
        scale: target,
        animation: { duration: 220, easingFunction: 'easeInOutQuad' }
    });
    setTimeout(emailIntelUpdateZoomLabel, 240);
}

function emailIntelFitGraph() {
    if (emailIntelGraphNetwork) {
        emailIntelGraphNetwork.fit({ animation: { duration: 280, easingFunction: 'easeInOutQuad' } });
        setTimeout(emailIntelUpdateZoomLabel, 300);
    }
}

function emailIntelUpdatePhysicsButton() {
    const btn = document.getElementById('ei-btn-physics');
    if (!btn) return;
    const span = btn.querySelector('span');
    if (span) {
        span.textContent = emailIntelGraphPhysicsEnabled ? 'Fijar' : 'Reanudar';
    }
}

function emailIntelTogglePhysics() {
    if (!emailIntelGraphNetwork) return;
    emailIntelGraphPhysicsEnabled = !emailIntelGraphPhysicsEnabled;
    emailIntelGraphNetwork.setOptions({ physics: { enabled: emailIntelGraphPhysicsEnabled } });
    emailIntelUpdatePhysicsButton();
}

function emailIntelToggleExpandGraph(forceState) {
    const wrapper = document.getElementById('ei-graph-wrapper');
    const backdrop = document.getElementById('ei-graph-backdrop');
    const stage = document.getElementById('ei-network-stage');
    const btn = document.getElementById('ei-btn-expand');
    if (!wrapper || !stage) return;

    emailIntelGraphExpanded = typeof forceState === 'boolean' ? forceState : !emailIntelGraphExpanded;

    if (emailIntelGraphExpanded) {
        if (backdrop) backdrop.classList.remove('hidden');
        wrapper.classList.add('fixed', 'inset-4', 'z-50', 'h-[calc(100vh-2rem)]');
        stage.classList.remove('h-[640px]');
        stage.classList.add('h-full');
        if (btn) btn.innerHTML = '<i class="fa-solid fa-compress mr-1"></i> <span>Reducir</span>';
    } else {
        if (backdrop) backdrop.classList.add('hidden');
        wrapper.classList.remove('fixed', 'inset-4', 'z-50', 'h-[calc(100vh-2rem)]');
        stage.classList.remove('h-full');
        stage.classList.add('h-[640px]');
        if (btn) btn.innerHTML = '<i class="fa-solid fa-expand mr-1"></i> <span>Ampliar</span>';
    }

    if (emailIntelGraphNetwork) {
        setTimeout(() => {
            emailIntelGraphNetwork.redraw();
            emailIntelGraphNetwork.fit({ animation: { duration: 220, easingFunction: 'easeInOutQuad' } });
        }, 120);
    }
}

document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape' && emailIntelGraphExpanded) {
        emailIntelToggleExpandGraph(false);
    }
});

function emailIntelFilterGraph(group) {
    document.querySelectorAll('.ei-graph-filter-btn').forEach((b) => {
        const active = b.getAttribute('data-ei-filter') === group;
        b.classList.toggle('bg-indigo-600', active);
        b.classList.toggle('text-white', active);
        b.classList.toggle('bg-slate-800', !active);
    });
    if (!emailIntelGraphNodesDS) return;

    const updates = emailIntelGraphRawNodes.map((n) => {
        const g = (n.group || '').toLowerCase();
        const match = group === 'ALL'
            || (group === 'domain' && (g === 'domain' || g === 'mx' || g === 'email'))
            || g === group
            || g === 'email';
        return {
            id: n.id,
            opacity: match ? 1.0 : 0.15,
            color: match ? n._origColor : { background: '#1e293b', border: '#334155' }
        };
    });
    emailIntelGraphNodesDS.update(updates);
}

function emailIntelCopyInspectorNode() {
    const txt = document.getElementById('ei-inspector-label')?.textContent || '';
    if (txt && navigator.clipboard) {
        navigator.clipboard.writeText(txt);
    }
}

function emailIntelExportGraphPng() {
    const canvas = document.querySelector('#ei-network-container canvas');
    if (!canvas) return;
    const link = document.createElement('a');
    link.download = `openrecon-email-graph-${currentEmailInvestigationId || 'export'}.png`;
    link.href = canvas.toDataURL('image/png');
    link.click();
}

// Correlate to Central Threat IOCs
async function emailIntelCorrelateIocAction() {
    if (!currentEmailInvestigationId) return;
    try {
        const form = new FormData();
        form.append('id', currentEmailInvestigationId);
        const res = await fetch(`${API_URL}?action=email_intel_correlate_ioc`, { method: 'POST', body: form });
        const data = await res.json();
        if (data.status === 'ok') {
            alert(`Éxito: ${data.message}`);
        } else {
            alert(`Error: ${data.message}`);
        }
    } catch (e) {
        alert("Error en la correlación: " + e.message);
    }
}

// Lifecycle actions
async function emailIntelPauseAction() {
    if (!currentEmailInvestigationId) return;
    const form = new FormData();
    form.append('id', currentEmailInvestigationId);
    await fetch(`${API_URL}?action=email_intel_pause`, { method: 'POST', body: form });
    emailIntelSelectInvestigation(currentEmailInvestigationId);
}

async function emailIntelCancelAction() {
    if (!currentEmailInvestigationId) return;
    if (!confirm("¿Desea cancelar esta investigación?")) return;
    const form = new FormData();
    form.append('id', currentEmailInvestigationId);
    await fetch(`${API_URL}?action=email_intel_cancel`, { method: 'POST', body: form });
    emailIntelSelectInvestigation(currentEmailInvestigationId);
}

function emailIntelExportCurrent(format) {
    if (!currentEmailInvestigationId) return;
    window.open(`${API_URL}?action=email_intel_export&id=${currentEmailInvestigationId}&format=${format}`, '_blank');
}

// Modal management
function emailIntelOpenNewModal() {
    document.getElementById('modal-new-email-investigation').classList.remove('hidden');
    document.getElementById('ei-input-case-id').value = `CASE-${new Date().toISOString().slice(0,10).replace(/-/g,'')}-${Math.floor(100+Math.random()*900)}`;
}

function emailIntelCloseNewModal() {
    document.getElementById('modal-new-email-investigation').classList.add('hidden');
}

async function emailIntelSubmitInvestigation(e) {
    e.preventDefault();
    const btn = document.getElementById('btn-submit-email-investigation');
    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-1"></i> Iniciando...';

    const form = new FormData();
    form.append('target_email', document.getElementById('ei-input-email').value);
    form.append('case_id', document.getElementById('ei-input-case-id').value);
    form.append('title', document.getElementById('ei-input-title').value);
    form.append('description', document.getElementById('ei-input-desc').value);
    form.append('tags', document.getElementById('ei-input-tags').value);
    form.append('authorization_justification', document.getElementById('ei-input-justification').value);

    try {
        const res = await fetch(`${API_URL}?action=email_intel_start`, { method: 'POST', body: form });
        const data = await res.json();
        if (data.status === 'ok') {
            emailIntelCloseNewModal();
            emailIntelLoadOverview();
            emailIntelSelectInvestigation(data.investigation_id, true);
        } else {
            alert(`Error al iniciar investigación: ${data.message}`);
        }
    } catch (err) {
        alert("Error de red: " + err.message);
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fa-solid fa-play mr-1"></i> Iniciar Investigación';
    }
}

function emailIntelRefreshList() {
    emailIntelLoadOverview();
    if (currentEmailInvestigationId) {
        emailIntelSelectInvestigation(currentEmailInvestigationId, false);
    }
}
</script>
