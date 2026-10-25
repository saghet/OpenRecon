<!DOCTYPE html>
<html lang="es" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenRecon | EASM, DRP, CTI & Attack Surface Management</title>
    <!-- Tailwind CSS CDN -->
    <script src="https://cdn.tailwindcss.com"></script>
    <!-- FontAwesome Icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <!-- Vis.js Network for Attack Surface Topology Graph -->
    <script src="https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        cyber: {
                            dark: '#0a0d14',
                            card: '#111726',
                            border: '#1e293b',
                            accent: '#06b6d4',
                            neon: '#10b981',
                            danger: '#f43f5e',
                            warning: '#f59e0b',
                            purple: '#a855f7'
                        }
                    }
                }
            }
        }
    </script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');
        body { font-family: 'Inter', sans-serif; background-color: #07090e; }
        .font-mono { font-family: 'JetBrains Mono', monospace; }
        #network-canvas { width: 100%; height: 580px; background: radial-gradient(circle at center, #0f172a 0%, #07090e 100%); }
        @media print {
            body { background-color: #ffffff !important; color: #000000 !important; }
            header, .no-print { display: none !important; }
            .bg-cyber-card, .bg-slate-900 { background-color: #ffffff !important; border: 1px solid #cbd5e1 !important; color: #0f172a !important; }
            .text-white { color: #0f172a !important; }
            .text-slate-400, .text-slate-300 { color: #475569 !important; }
        }
    </style>
</head>
<body class="text-slate-200 min-h-screen flex flex-col antialiased selection:bg-cyan-500 selection:text-black">

    <!-- Top Navigation Bar -->
    <header class="border-b border-cyber-border bg-cyber-dark/90 backdrop-blur sticky top-0 z-50 no-print">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
            <div class="flex items-center gap-3">
                <div class="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 to-emerald-400 flex items-center justify-center text-black font-extrabold text-xl shadow-lg shadow-cyan-500/20">
                    <i class="fa-solid fa-shield-halved"></i>
                </div>
                <div>
                    <div class="flex items-center gap-2">
                        <span class="font-extrabold text-lg tracking-tight text-white">Open<span class="text-cyan-400">Recon</span></span>
                        <span class="px-2 py-0.5 text-[10px] font-bold tracking-wider uppercase bg-cyan-950 text-cyan-400 border border-cyan-800/60 rounded">EASM &bull; DRP &bull; CTI</span>
                    </div>
                    <p class="text-[11px] text-slate-400">Alternativa Abierta a FortiRecon, Cortex Xpanse & Recorded Future</p>
                </div>
            </div>

            <!-- Actions & Seed Selector -->
            <div class="flex items-center gap-3">
                
                <!-- Dynamic Seed Switcher -->
                <div class="flex items-center gap-1.5 bg-slate-900/90 border border-cyan-700/60 px-3 py-1.5 rounded-xl shadow-sm">
                    <i class="fa-solid fa-crosshairs text-cyan-400 text-xs"></i>
                    <span class="text-[11px] text-slate-400 font-semibold hidden sm:inline">Perímetro:</span>
                    <select id="active-seed-selector" onchange="onActiveSeedChange(this.value)" class="bg-transparent text-white font-mono text-xs font-bold focus:outline-none cursor-pointer">
                        <option value="ALL" class="bg-slate-900 text-white">Cargando semillas...</option>
                    </select>
                </div>

                <button onclick="openPlanModal()" class="px-3 py-1.5 rounded-xl bg-blue-950/70 hover:bg-blue-900/70 text-blue-300 font-semibold text-xs border border-blue-800/60 transition flex items-center gap-1.5" title="Ver plan de trabajo y hoja de ruta">
                    <i class="fa-solid fa-list-check text-blue-400"></i>
                    <span class="hidden md:inline">Plan de Trabajo</span>
                </button>

                <button onclick="syncCti()" class="px-3 py-1.5 rounded-xl bg-purple-950/60 hover:bg-purple-900/60 text-purple-300 font-medium text-xs border border-purple-800/50 transition flex items-center gap-1.5" title="Sincronizar feeds de Dark Web y C2 Botnets">
                    <i id="sync-icon" class="fa-solid fa-arrows-rotate text-purple-400"></i>
                    <span class="hidden md:inline">Sincronizar CTI</span>
                </button>

                <a id="btn-report-link" href="report.php" target="_blank" class="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium text-xs border border-cyber-border transition flex items-center gap-1.5" title="Abrir Reporte Ejecutivo Formal para Dirección/CISO">
                    <i class="fa-solid fa-file-pdf text-rose-400"></i>
                    <span class="hidden sm:inline">Reporte</span>
                </a>

                <button id="btn-scan" onclick="triggerScan()" class="relative group px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-semibold text-xs shadow-lg shadow-cyan-500/25 hover:from-cyan-400 hover:to-blue-500 transition-all flex items-center gap-2 cursor-pointer">
                    <i id="scan-icon" class="fa-solid fa-radar text-black group-hover:rotate-45 transition-transform"></i>
                    <span id="scan-text">Escanear</span>
                </button>
            </div>
        </div>
    </header>

    <!-- Main Container -->
    <main class="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">

        <!-- Top Banner: Executive Posture & KPIs -->
        <section class="grid grid-cols-1 lg:grid-cols-12 gap-6">
            
            <!-- Exposure Score Card -->
            <div class="lg:col-span-4 bg-cyber-card border border-cyber-border rounded-2xl p-6 relative overflow-hidden flex flex-col justify-between">
                <div class="absolute -right-8 -top-8 w-40 h-40 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none"></div>
                <div class="flex items-center justify-between mb-4">
                    <span class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Security Exposure Score</span>
                    <i class="fa-solid fa-gauge-high text-cyan-400"></i>
                </div>

                <div class="flex items-center gap-6 my-2">
                    <div class="relative w-28 h-28 flex items-center justify-center">
                        <svg class="w-full h-full transform -rotate-90">
                            <circle cx="56" cy="56" r="48" stroke="#1e293b" stroke-width="10" fill="transparent" />
                            <circle id="score-circle" cx="56" cy="56" r="48" stroke="#10b981" stroke-width="10" fill="transparent" stroke-dasharray="301" stroke-dashoffset="60" stroke-linecap="round" class="transition-all duration-1000" />
                        </svg>
                        <div class="absolute flex flex-col items-center">
                            <span id="score-val" class="text-3xl font-black text-white">--</span>
                            <span class="text-[10px] text-slate-400">/ 100</span>
                        </div>
                    </div>
                    <div>
                        <div id="posture-badge" class="inline-block px-2.5 py-1 text-xs font-bold rounded-lg bg-emerald-950 text-emerald-400 border border-emerald-800/50 mb-1">
                            Calculando...
                        </div>
                        <p class="text-xs text-slate-400 leading-relaxed">
                            Métrica perimetral aislada exclusivamente para la semilla seleccionada.
                        </p>
                    </div>
                </div>

                <div class="pt-4 border-t border-cyber-border text-[11px] text-slate-400 flex items-center justify-between">
                    <span>Evaluación perimetral continua</span>
                    <span id="current-scope-label" class="text-cyan-400 font-mono">Todas las semillas</span>
                </div>
            </div>

            <!-- Key Metric Counters -->
            <div class="lg:col-span-8 grid grid-cols-2 sm:grid-cols-4 gap-4">
                
                <div class="bg-cyber-card border border-cyber-border rounded-2xl p-5 flex flex-col justify-between hover:border-slate-700 transition">
                    <div class="w-10 h-10 rounded-xl bg-slate-800/80 flex items-center justify-center text-cyan-400 mb-3">
                        <i class="fa-solid fa-network-wired"></i>
                    </div>
                    <div>
                        <span class="text-xs text-slate-400 font-medium">Activos Descubiertos</span>
                        <h3 id="stat-assets" class="text-2xl font-bold text-white mt-1">0</h3>
                    </div>
                    <span id="stat-live" class="text-[11px] text-emerald-400 font-mono mt-2">0 activos vivos</span>
                </div>

                <div class="bg-cyber-card border border-cyber-border rounded-2xl p-5 flex flex-col justify-between hover:border-slate-700 transition">
                    <div class="w-10 h-10 rounded-xl bg-slate-800/80 flex items-center justify-center text-blue-400 mb-3">
                        <i class="fa-solid fa-door-open"></i>
                    </div>
                    <div>
                        <span class="text-xs text-slate-400 font-medium">Puertos Abiertos</span>
                        <h3 id="stat-ports" class="text-2xl font-bold text-white mt-1">0</h3>
                    </div>
                    <span class="text-[11px] text-slate-400 font-mono mt-2">Superficie externa</span>
                </div>

                <div class="bg-cyber-card border border-cyber-border rounded-2xl p-5 flex flex-col justify-between hover:border-slate-700 transition">
                    <div class="w-10 h-10 rounded-xl bg-rose-950/60 border border-rose-900/40 flex items-center justify-center text-rose-400 mb-3">
                        <i class="fa-solid fa-triangle-exclamation"></i>
                    </div>
                    <div>
                        <span class="text-xs text-slate-400 font-medium">Vulnerabilidades</span>
                        <h3 id="stat-vulns" class="text-2xl font-bold text-rose-400 mt-1">0</h3>
                    </div>
                    <span id="stat-crit-vulns" class="text-[11px] text-rose-400/90 font-mono mt-2">0 críticas / altas</span>
                </div>

                <div class="bg-cyber-card border border-cyber-border rounded-2xl p-5 flex flex-col justify-between hover:border-slate-700 transition">
                    <div class="w-10 h-10 rounded-xl bg-purple-950/60 border border-purple-900/40 flex items-center justify-center text-purple-400 mb-3">
                        <i class="fa-solid fa-skull-crossbones"></i>
                    </div>
                    <div>
                        <span class="text-xs text-slate-400 font-medium">CTI & Dark Web</span>
                        <h3 id="stat-cti" class="text-2xl font-bold text-purple-400 mt-1">0</h3>
                    </div>
                    <span id="stat-cti-info" class="text-[11px] text-purple-400/90 font-mono mt-2">Ransomware & C2s</span>
                </div>

            </div>
        </section>

        <!-- Navigation Tabs -->
        <div class="flex items-center gap-2 border-b border-cyber-border overflow-x-auto pb-1 text-sm font-medium no-print">
            <button onclick="switchTab('easm')" id="tab-btn-easm" class="tab-btn px-4 py-2.5 rounded-xl bg-slate-800 text-cyan-400 border border-cyan-800/50 flex items-center gap-2 transition">
                <i class="fa-solid fa-globe"></i>
                Superficie de Ataque (EASM)
            </button>
            <button onclick="switchTab('graph')" id="tab-btn-graph" class="tab-btn px-4 py-2.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800/50 flex items-center gap-2 transition">
                <i class="fa-solid fa-diagram-project"></i>
                Topología de Ataque (Grafo)
            </button>
            <button onclick="switchTab('vulns')" id="tab-btn-vulns" class="tab-btn px-4 py-2.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800/50 flex items-center gap-2 transition">
                <i class="fa-solid fa-shield-virus"></i>
                Exposición y Remediación
            </button>
            <button onclick="switchTab('drp')" id="tab-btn-drp" class="tab-btn px-4 py-2.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800/50 flex items-center gap-2 transition">
                <i class="fa-solid fa-masks-theater"></i>
                Protección Digital (DRP)
            </button>
            <button onclick="switchTab('leaks')" id="tab-btn-leaks" class="tab-btn px-4 py-2.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800/50 flex items-center gap-2 transition">
                <i class="fa-solid fa-key text-amber-400"></i>
                Fugas y Secretos
            </button>
            <button onclick="switchTab('cti')" id="tab-btn-cti" class="tab-btn px-4 py-2.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800/50 flex items-center gap-2 transition">
                <i class="fa-solid fa-user-ninja text-purple-400"></i>
                Inteligencia de Amenazas (CTI)
            </button>
            <button onclick="switchTab('seeds')" id="tab-btn-seeds" class="tab-btn px-4 py-2.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800/50 flex items-center gap-2 transition">
                <i class="fa-solid fa-crosshairs"></i>
                Semillas / Dominios
            </button>
            <button onclick="switchTab('strix')" id="tab-btn-strix" class="tab-btn px-4 py-2.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800/50 flex items-center gap-2 transition" title="Suite de pentesting interactivo, PoCs reproducibles y herramientas ofensivas">
                <i class="fa-solid fa-wand-magic-sparkles text-emerald-400"></i>
                Navaja Suiza Strix (Pentesting)
            </button>
        </div>

        <!-- TAB CONTENT: EASM (Assets) -->
        <section id="tab-content-easm" class="space-y-4">
            <div class="flex flex-col sm:flex-row items-center justify-between gap-4">
                <div>
                    <h3 class="text-lg font-bold text-white flex items-center gap-2">
                        <i class="fa-solid fa-server text-cyan-400"></i>
                        Inventario Perimetral Descubierto
                    </h3>
                    <p class="text-xs text-slate-400">Mostrando exclusivamente los activos descubiertos para el dominio seleccionado.</p>
                </div>
                
                <div class="flex items-center gap-3 w-full sm:w-auto no-print">
                    <button onclick="openPlanModal()" class="px-3 py-2 rounded-xl bg-blue-900/60 hover:bg-blue-800 text-blue-200 border border-blue-700/60 text-xs font-semibold flex items-center gap-1.5 transition">
                        <i class="fa-solid fa-clipboard-check text-blue-400"></i>
                        <span>Generar Plan de Trabajo</span>
                    </button>

                    <div class="relative w-full sm:w-72">
                        <i class="fa-solid fa-magnifying-glass absolute left-3 top-3 text-slate-500 text-xs"></i>
                        <input type="text" id="asset-search" oninput="renderAssetsTable()" placeholder="Buscar subdominio, IP..." class="w-full pl-9 pr-4 py-2 rounded-xl bg-cyber-card border border-cyber-border text-xs text-white focus:outline-none focus:border-cyan-500 transition">
                    </div>
                </div>
            </div>

            <div class="bg-cyber-card border border-cyber-border rounded-2xl overflow-hidden shadow-xl">
                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs">
                        <thead class="bg-slate-900/60 text-slate-400 uppercase text-[10px] tracking-wider border-b border-cyber-border">
                            <tr>
                                <th class="p-4">Activo / Subdominio</th>
                                <th class="p-4">Dirección IP</th>
                                <th class="p-4">Proveedor / Infraestructura</th>
                                <th class="p-4">Fuente de Descubrimiento</th>
                                <th class="p-4">Puertos Detectados</th>
                                <th class="p-4 text-center">Estado</th>
                                <th class="p-4 text-center">Gestión Semillas</th>
                            </tr>
                        </thead>
                        <tbody id="assets-table-body" class="divide-y divide-cyber-border/60 text-slate-300">
                            <tr>
                                <td colspan="6" class="p-8 text-center text-slate-500">
                                    <i class="fa-solid fa-spinner fa-spin text-xl text-cyan-400 mb-2 block"></i>
                                    Cargando activos descubiertos...
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </section>

        <!-- TAB CONTENT: ATTACK SURFACE TOPOLOGY GRAPH -->
        <section id="tab-content-graph" class="space-y-4 hidden">
            <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                <div>
                    <h3 class="text-lg font-bold text-white flex items-center gap-2">
                        <i class="fa-solid fa-diagram-project text-cyan-400"></i>
                        Grafo de Topología y Relaciones Perimetrales
                    </h3>
                    <p class="text-xs text-slate-400">Mapeo visual de relaciones para la semilla activa: [Semilla] ➔ [Subdominios] ➔ [IPs] ➔ [Puertos] ➔ [Vulnerabilidades].</p>
                </div>

                <div class="flex items-center gap-2 text-xs">
                    <button onclick="loadGraph()" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-cyber-border flex items-center gap-1.5 transition">
                        <i class="fa-solid fa-rotate"></i>
                        <span>Centrar Grafo</span>
                    </button>
                </div>
            </div>

            <div class="flex flex-wrap items-center gap-4 p-3 bg-cyber-card border border-cyber-border rounded-xl text-xs font-mono">
                <span class="text-slate-400 font-sans font-semibold">Leyenda de Nodos:</span>
                <div class="flex items-center gap-1.5"><span class="w-3 h-3 rounded-sm bg-cyan-500 inline-block"></span><span class="text-slate-300">Semilla</span></div>
                <div class="flex items-center gap-1.5"><span class="w-3 h-3 rounded-full bg-sky-400 inline-block"></span><span class="text-slate-300">Subdominio</span></div>
                <div class="flex items-center gap-1.5"><span class="w-3 h-3 rounded-sm bg-slate-600 inline-block"></span><span class="text-slate-300">IP / Cloud</span></div>
                <div class="flex items-center gap-1.5"><span class="w-3 h-3 rounded-full bg-emerald-500 inline-block"></span><span class="text-slate-300">Puerto Seguro</span></div>
                <div class="flex items-center gap-1.5"><span class="w-3 h-3 rounded-full bg-rose-500 inline-block"></span><span class="text-slate-300">Puerto Crítico</span></div>
                <div class="flex items-center gap-1.5"><span class="w-3 h-3 border-b-2 border-rose-500 inline-block"></span><span class="text-rose-400 font-bold">Vulnerabilidad</span></div>
            </div>

            <div class="relative bg-cyber-card border border-cyber-border rounded-2xl overflow-hidden shadow-2xl">
                <div id="network-canvas"></div>
                <div id="graph-loading" class="absolute inset-0 bg-cyber-dark/80 backdrop-blur-sm flex flex-col items-center justify-center text-cyan-400 gap-3">
                    <i class="fa-solid fa-circle-nodes fa-spin text-4xl"></i>
                    <span class="text-sm font-mono font-medium text-white">Calculando física y topología del grafo...</span>
                </div>
            </div>
        </section>

        <!-- TAB CONTENT: Vulnerabilities & Exposures -->
        <section id="tab-content-vulns" class="space-y-4 hidden">
            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                    <h3 class="text-lg font-bold text-white flex items-center gap-2">
                        <i class="fa-solid fa-bug text-rose-400"></i>
                        Hallazgos de Exposición y Ciclo de Remediación
                    </h3>
                    <p class="text-xs text-slate-400">Gestiona y mitiga los hallazgos perimetrales. Al marcar un hallazgo como "Mitigado", se recupera la puntuación de exposición.</p>
                </div>
                <div class="flex items-center gap-2">
                    <button onclick="exportVulnsCsv()" class="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 border border-cyber-border text-xs font-semibold flex items-center gap-1.5 transition">
                        <i class="fa-solid fa-file-csv text-emerald-400"></i>
                        <span>Exportar CSV</span>
                    </button>
                    <button onclick="runVulnerabilityScan()" class="px-4 py-1.5 rounded-xl bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold shadow-lg shadow-rose-900/40 flex items-center gap-1.5 transition">
                        <i class="fa-solid fa-shield-virus"></i>
                        <span>Re-escanear Perímetro</span>
                    </button>
                </div>
            </div>

            <!-- Filter and Search Toolbar -->
            <div class="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 bg-cyber-card border border-cyber-border rounded-xl p-3">
                <div class="flex items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0" id="vuln-severity-filters">
                    <button onclick="filterVulnsBySeverity('ALL')" id="vuln-filter-ALL" class="px-3 py-1 rounded-lg text-xs font-bold bg-cyan-950 text-cyan-300 border border-cyan-800 transition">Todas (<span id="count-vuln-all">0</span>)</button>
                    <button onclick="filterVulnsBySeverity('HIGH')" id="vuln-filter-HIGH" class="px-3 py-1 rounded-lg text-xs font-semibold text-slate-400 hover:text-white border border-transparent hover:border-cyber-border transition">Altas (<span id="count-vuln-high">0</span>)</button>
                    <button onclick="filterVulnsBySeverity('MEDIUM')" id="vuln-filter-MEDIUM" class="px-3 py-1 rounded-lg text-xs font-semibold text-slate-400 hover:text-white border border-transparent hover:border-cyber-border transition">Medias (<span id="count-vuln-med">0</span>)</button>
                    <button onclick="filterVulnsBySeverity('LOW')" id="vuln-filter-LOW" class="px-3 py-1 rounded-lg text-xs font-semibold text-slate-400 hover:text-white border border-transparent hover:border-cyber-border transition">Bajas (<span id="count-vuln-low">0</span>)</button>
                    <button onclick="filterVulnsBySeverity('RESOLVED')" id="vuln-filter-RESOLVED" class="px-3 py-1 rounded-lg text-xs font-semibold text-slate-400 hover:text-white border border-transparent hover:border-cyber-border transition">Mitigadas (<span id="count-vuln-res">0</span>)</button>
                </div>

                <div class="relative w-full sm:w-64">
                    <i class="fa-solid fa-magnifying-glass absolute left-3 top-2.5 text-slate-500 text-xs"></i>
                    <input type="text" id="vuln-search-input" oninput="applyVulnFilters()" placeholder="Buscar hallazgo o activo..." class="w-full pl-8 pr-3 py-1.5 rounded-lg bg-slate-900 border border-cyber-border text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500">
                </div>
            </div>

            <div id="vulns-container" class="space-y-4"></div>
        </section>

        <!-- TAB CONTENT: DRP (Typosquatting & Phishing) -->
        <section id="tab-content-drp" class="space-y-4 hidden">
            <div>
                <h3 class="text-lg font-bold text-white flex items-center gap-2">
                    <i class="fa-solid fa-shield-cat text-amber-400"></i>
                    Detección de Suplantación y Phishing (Digital Risk Protection)
                </h3>
                <p class="text-xs text-slate-400">Variaciones de marca y dominios homóglifos registrados activamente por terceros.</p>
            </div>

            <div class="bg-cyber-card border border-cyber-border rounded-2xl overflow-hidden shadow-xl">
                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs">
                        <thead class="bg-slate-900/60 text-slate-400 uppercase text-[10px] tracking-wider border-b border-cyber-border">
                            <tr>
                                <th class="p-4">Dominio Clon Detectado</th>
                                <th class="p-4">IP Asociada</th>
                                <th class="p-4">Servidor MX (Email)</th>
                                <th class="p-4">Nivel de Riesgo</th>
                                <th class="p-4">Detalles y Vector</th>
                                <th class="p-4 text-center">Acción de Respuesta</th>
                            </tr>
                        </thead>
                        <tbody id="drp-table-body" class="divide-y divide-cyber-border/60 text-slate-300"></tbody>
                    </table>
                </div>
            </div>
        </section>

        <!-- TAB CONTENT: Credential Leaks & Exposed Secrets -->
        <section id="tab-content-leaks" class="space-y-6 hidden">
            <div class="bg-cyber-card border border-cyber-border rounded-2xl p-6">
                <h3 class="text-lg font-bold text-white flex items-center gap-2 mb-1">
                    <i class="fa-solid fa-file-code text-rose-400"></i>
                    Secretos y Archivos Sensibles Expuestos (.env, .git, backups)
                </h3>
                <p class="text-xs text-slate-400 mb-4">Inspección de endpoints desprotegidos que exponen variables de entorno o credenciales de backend.</p>
                <div id="secrets-container" class="space-y-3"></div>
            </div>

            <!-- Breach Intelligence Section -->
            <div class="bg-cyber-card border border-cyber-border rounded-2xl p-6">
                <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-4">
                    <div>
                        <h3 class="text-lg font-bold text-white flex items-center gap-2 mb-1">
                            <i class="fa-solid fa-address-book text-amber-400"></i>
                            Fugas de Credenciales Corporativas (Breach Intelligence)
                        </h3>
                        <p class="text-xs text-slate-400">Identidades corporativas detectadas en volcados masivos y logs de malware Infostealer (RedLine, Vidar, Racoon).</p>
                    </div>
                    <div class="flex items-center gap-2">
                        <span class="px-3 py-1 rounded-xl bg-rose-950/80 text-rose-300 border border-rose-800 text-xs font-bold font-mono">
                            <i class="fa-solid fa-triangle-exclamation mr-1"></i> RIESGO DE IDENTIDAD: ALTO
                        </span>
                    </div>
                </div>

                <!-- Executive Metric Highlights -->
                <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
                    <div class="p-4 rounded-xl bg-slate-900/80 border border-cyber-border">
                        <span class="text-[10px] text-slate-400 uppercase tracking-wider font-semibold">Identidad Expuesta</span>
                        <div id="leak-stat-email" class="text-lg font-mono font-bold text-cyan-400 mt-1 truncate">admin@...</div>
                        <span class="text-[10px] text-slate-500">Cuenta administrativa</span>
                    </div>
                    <div class="p-4 rounded-xl bg-slate-900/80 border border-cyber-border">
                        <span class="text-[10px] text-slate-400 uppercase tracking-wider font-semibold">Registros Comprometidos</span>
                        <div id="leak-stat-pwn" class="text-2xl font-black text-rose-400 mt-1">773 Registros</div>
                        <span class="text-[10px] text-rose-400/80 font-mono">Collection #1 (Public Stealer)</span>
                    </div>
                    <div class="p-4 rounded-xl bg-slate-900/80 border border-cyber-border">
                        <span class="text-[10px] text-slate-400 uppercase tracking-wider font-semibold">Severidad Técnica</span>
                        <div class="text-xl font-black text-amber-400 mt-1 flex items-center gap-1.5">
                            <span>HIGH</span>
                            <span class="text-[10px] px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800 font-mono">MITRE T1078</span>
                        </div>
                        <span class="text-[10px] text-slate-500">Credential Stuffing inminente</span>
                    </div>
                    <div class="p-4 rounded-xl bg-slate-900/80 border border-cyber-border">
                        <span class="text-[10px] text-slate-400 uppercase tracking-wider font-semibold">Naturaleza de Datos</span>
                        <div class="text-xs font-semibold text-slate-200 mt-1 line-clamp-2">Contraseñas en texto plano, hashes descifrados y credenciales de acceso</div>
                        <span class="text-[10px] text-cyan-400 mt-1 block">Requiere reseteo y MFA</span>
                    </div>
                </div>

                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs">
                        <thead class="bg-slate-900/60 text-slate-400 uppercase text-[10px] tracking-wider border-b border-cyber-border">
                            <tr>
                                <th class="p-4">Identidad / Email</th>
                                <th class="p-4">Origen de la Brecha</th>
                                <th class="p-4">Fecha de Publicación</th>
                                <th class="p-4">Impacto / Registros</th>
                                <th class="p-4">Datos Comprometidos</th>
                                <th class="p-4 text-center">Severidad</th>
                                <th class="p-4 text-center">Acciones</th>
                            </tr>
                        </thead>
                        <tbody id="leaks-table-body" class="divide-y divide-cyber-border/60 text-slate-300"></tbody>
                    </table>
                </div>
            </div>
        </section>

        <!-- TAB CONTENT: CTI & Dark Web Intelligence -->
        <section id="tab-content-cti" class="space-y-6 hidden">
            <div class="bg-cyber-card border border-cyber-border rounded-2xl p-6">
                <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-4">
                    <div>
                        <div class="flex items-center gap-2">
                            <span class="w-2.5 h-2.5 rounded-full bg-purple-500 animate-ping"></span>
                            <h3 class="text-lg font-bold text-white flex items-center gap-2">
                                <i class="fa-solid fa-radiation text-purple-400"></i>
                                Dark Web Ransomware Leak Watchdog (Blogs de Extorsión)
                            </h3>
                        </div>
                        <p class="text-xs text-slate-400 mt-1">Rastreo de sitios de fuga en la red Tor operados por sindicatos de ransomware.</p>
                    </div>

                    <div id="ransom-alert-badge" class="px-3 py-1.5 rounded-xl bg-emerald-950 text-emerald-400 border border-emerald-800/60 text-xs font-bold flex items-center gap-2">
                        <i class="fa-solid fa-shield-check"></i>
                        <span>Tu empresa no figura como víctima</span>
                    </div>
                </div>

                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs">
                        <thead class="bg-slate-900/60 text-slate-400 uppercase text-[10px] tracking-wider border-b border-cyber-border">
                            <tr>
                                <th class="p-4">Víctima Reclamada</th>
                                <th class="p-4">Grupo de Ransomware</th>
                                <th class="p-4">Fecha de Detección</th>
                                <th class="p-4 text-center">Estado de Alerta</th>
                            </tr>
                        </thead>
                        <tbody id="ransomware-table-body" class="divide-y divide-cyber-border/60 text-slate-300"></tbody>
                    </table>
                </div>
            </div>

            <!-- Threat Actors -->
            <div class="bg-cyber-card border border-cyber-border rounded-2xl p-6">
                <h3 class="text-lg font-bold text-white flex items-center gap-2 mb-1">
                    <i class="fa-solid fa-user-secret text-rose-400"></i>
                    Perfiles de Actores de Amenaza y TTPs (MITRE ATT&CK)
                </h3>
                <p class="text-xs text-slate-400 mb-6">Tácticas, técnicas y vectores de acceso inicial utilizados por los grupos que atacan tu sector.</p>
                <div id="actors-container" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4"></div>
            </div>

            <!-- Botnet IOCs -->
            <div class="bg-cyber-card border border-cyber-border rounded-2xl p-6">
                <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-4">
                    <div>
                        <h3 class="text-lg font-bold text-white flex items-center gap-2 mb-1">
                            <i class="fa-solid fa-spider text-cyan-400"></i>
                            Indicadores de Compromiso (IOCs) - Servidores C2 & Botnets Activos
                        </h3>
                        <p class="text-xs text-slate-400">Correlación multi-fuente en tiempo real de 160+ nodos hostiles activos (Feodo Tracker, Emerging Threats, IPsum Blacklist con Score &ge; 4).</p>
                    </div>
                    <div class="flex items-center gap-2">
                        <button onclick="openFirewallRulesModal()" class="px-3 py-1.5 rounded-xl bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 text-xs font-semibold flex items-center gap-1.5 transition">
                            <i class="fa-solid fa-file-export"></i>
                            <span>Exportar Reglas Firewall (FortiGate / iptables)</span>
                        </button>
                    </div>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs">
                        <thead class="bg-slate-900/60 text-slate-400 uppercase text-[10px] tracking-wider border-b border-cyber-border">
                            <tr>
                                <th class="p-4">IP C2 Hostil</th>
                                <th class="p-4">Puerto</th>
                                <th class="p-4">Familia de Malware / Botnet</th>
                                <th class="p-4">Feed de Inteligencia / Reputación</th>
                                <th class="p-4 text-center">Estado</th>
                            </tr>
                        </thead>
                        <tbody id="iocs-table-body" class="divide-y divide-cyber-border/60 text-slate-300"></tbody>
                    </table>
                </div>
            </div>
        </section>

        <!-- TAB CONTENT: Seeds Configuration -->
        <section id="tab-content-seeds" class="space-y-6 hidden">
            <div class="bg-cyber-card border border-cyber-border rounded-2xl p-6">
                <h3 class="text-lg font-bold text-white mb-2 flex items-center gap-2">
                    <i class="fa-solid fa-plus-circle text-cyan-400"></i>
                    Agregar Dominio Semilla a la Vigilancia
                </h3>
                <p class="text-xs text-slate-400 mb-4">Ingresa el dominio principal de tu organización para iniciar el reconocimiento continuo.</p>

                <form onsubmit="handleAddSeed(event)" class="flex flex-col sm:flex-row gap-3">
                    <input type="text" id="new-seed-domain" placeholder="ejemplo: tuempresa.com" class="flex-1 px-4 py-2.5 rounded-xl bg-slate-900 border border-cyber-border text-sm text-white focus:outline-none focus:border-cyan-500">
                    <button type="submit" class="px-5 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-sm transition flex items-center justify-center gap-2">
                        <i class="fa-solid fa-plus-circle"></i>
                        Registrar Semilla
                    </button>
                    <button type="button" onclick="handleAutoDiscoverAndAddSeeds()" id="btn-auto-discover-seeds" class="px-5 py-2.5 rounded-xl bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white font-bold text-xs transition flex items-center justify-center gap-2 shadow-lg" title="Descubre automáticamente todos los subdominios pasivos de la entidad y los agrega en lote a las semillas">
                        <i class="fa-solid fa-wand-magic-sparkles text-amber-300"></i>
                        <span>Auto-descubrir y Añadir Subdominios a Semillas</span>
                    </button>
                </form>
            </div>

            <div class="bg-cyber-card border border-cyber-border rounded-2xl overflow-hidden">
                <div class="p-4 border-b border-cyber-border font-bold text-sm text-white flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                    <div class="flex items-center gap-3">
                        <span>Dominios Actualmente Monitoreados</span>
                        <span id="seeds-count" class="text-xs font-mono text-cyan-400 bg-cyan-950/70 border border-cyan-800/60 px-2.5 py-0.5 rounded-full">0 semillas</span>
                    </div>
                    <button onclick="handleDeleteAllSeeds()" class="px-3.5 py-1.5 rounded-xl bg-rose-950/80 hover:bg-rose-900 text-rose-300 border border-rose-800 text-xs font-semibold flex items-center gap-1.5 transition shadow" title="Eliminar todas las semillas y limpiar el inventario perimetral">
                        <i class="fa-solid fa-trash-can text-rose-400"></i>
                        <span>Eliminar Todas las Semillas</span>
                    </button>
                </div>
                <div id="seeds-list" class="divide-y divide-cyber-border/60"></div>
            </div>
        </section>

        <!-- TAB CONTENT: STRIX PENTESTING TOOLKIT (NAVAJA SUIZA) -->
        <section id="tab-content-strix" class="space-y-6 hidden">
            <!-- Header Card -->
            <div class="bg-cyber-card border border-cyber-border rounded-2xl p-6 relative overflow-hidden">
                <div class="absolute -right-10 -bottom-10 opacity-5 pointer-events-none text-9xl text-emerald-400">
                    <i class="fa-solid fa-wand-magic-sparkles"></i>
                </div>
                <div class="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                    <div>
                        <div class="flex items-center gap-2 mb-1">
                            <span class="px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-emerald-950 text-emerald-400 border border-emerald-800">
                                <i class="fa-solid fa-bolt mr-1"></i> Pentesting Suite & PoC Engine
                            </span>
                            <span class="text-xs text-slate-500 font-mono">Inspirado en Strix (OpenSource)</span>
                        </div>
                        <h3 class="text-xl font-bold text-white flex items-center gap-2">
                            <i class="fa-solid fa-screwdriver-wrench text-emerald-400"></i>
                            Navaja Suiza Strix (Auditoría Ofensiva & Validación)
                        </h3>
                        <p class="text-xs text-slate-400 mt-1 max-w-3xl">
                            Herramientas multi-plataforma de pentesting interactivo: inspección cruda de paquetes HTTP (estilo Caido/Burp Suite), validación determinista de PoCs con comandos cURL y scripts Python listos para replicar, fuzzing de rutas de exposición, inspección de certificados X.509 y auditorías RFC DNS.
                        </p>
                    </div>

                    <!-- Asset quick-loader -->
                    <div class="flex items-center gap-2 bg-slate-900/80 p-2.5 rounded-xl border border-cyber-border">
                        <i class="fa-solid fa-crosshairs text-cyan-400 text-xs"></i>
                        <select id="strix-asset-quick-select" class="bg-slate-950 text-xs text-slate-200 border border-slate-700 rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500 max-w-[200px]">
                            <option value="">Seleccionar activo...</option>
                        </select>
                        <button onclick="applyStrixSelectedAsset()" class="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition">
                            Cargar
                        </button>
                    </div>
                </div>

                <!-- Sub-tools Navigation Pills -->
                <div class="flex items-center gap-2 mt-5 border-t border-cyber-border/70 pt-4 overflow-x-auto text-xs font-semibold">
                    <button onclick="switchStrixSubTool('poc')" id="strix-subtab-poc" class="px-4 py-2 rounded-xl bg-emerald-950/80 text-emerald-300 border border-emerald-700/80 flex items-center gap-2 transition">
                        <i class="fa-solid fa-bolt text-emerald-400"></i>
                        <span>PoC & Raw HTTP Inspector</span>
                    </button>
                    <button onclick="switchStrixSubTool('fuzz')" id="strix-subtab-fuzz" class="px-4 py-2 rounded-xl bg-slate-900 text-slate-400 hover:text-white border border-cyber-border flex items-center gap-2 transition">
                        <i class="fa-solid fa-folder-tree text-amber-400"></i>
                        <span>Fuzzing de Rutas Críticas</span>
                    </button>
                    <button onclick="switchStrixSubTool('tls')" id="strix-subtab-tls" class="px-4 py-2 rounded-xl bg-slate-900 text-slate-400 hover:text-white border border-cyber-border flex items-center gap-2 transition">
                        <i class="fa-solid fa-lock text-cyan-400"></i>
                        <span>Inspección Certificado X.509 / TLS</span>
                    </button>
                    <button onclick="switchStrixSubTool('cors')" id="strix-subtab-cors" class="px-4 py-2 rounded-xl bg-slate-900 text-slate-400 hover:text-white border border-cyber-border flex items-center gap-2 transition">
                        <i class="fa-solid fa-shield-halved text-purple-400"></i>
                        <span>Laboratorio CORS & Headers</span>
                    </button>
                    <button onclick="switchStrixSubTool('dns')" id="strix-subtab-dns" class="px-4 py-2 rounded-xl bg-slate-900 text-slate-400 hover:text-white border border-cyber-border flex items-center gap-2 transition">
                        <i class="fa-solid fa-network-wired text-blue-400"></i>
                        <span>Auditoría RFC DNS & Resiliencia</span>
                    </button>
                </div>
            </div>

            <!-- SUB-PANEL 1: PoC & Raw HTTP Inspector -->
            <div id="strix-panel-poc" class="space-y-4">
                <div class="bg-cyber-card border border-cyber-border rounded-2xl p-5 space-y-4">
                    <div class="flex flex-col md:flex-row items-stretch md:items-center gap-3">
                        <div class="w-full md:w-32">
                            <label class="block text-[10px] uppercase font-bold text-slate-400 mb-1">Método</label>
                            <select id="strix-poc-method" class="w-full bg-slate-900 border border-cyber-border rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono">
                                <option value="GET">GET</option>
                                <option value="POST">POST</option>
                                <option value="HEAD">HEAD</option>
                                <option value="OPTIONS">OPTIONS</option>
                            </select>
                        </div>
                        <div class="flex-1">
                            <label class="block text-[10px] uppercase font-bold text-slate-400 mb-1">URL Objetivo / Endpoint a Validar</label>
                            <div class="relative">
                                <i class="fa-solid fa-globe absolute left-3 top-2.5 text-slate-500 text-xs"></i>
                                <input type="text" id="strix-poc-url" placeholder="https://ejemplo.com/endpoint-o-archivo" class="w-full pl-9 pr-3 py-2 rounded-xl bg-slate-900 border border-cyber-border text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono">
                            </div>
                        </div>
                        <div class="flex items-end">
                            <button onclick="runStrixPocTest()" id="btn-strix-run-poc" class="w-full md:w-auto px-5 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold transition flex items-center justify-center gap-2 shadow-lg shadow-emerald-950/50">
                                <i class="fa-solid fa-play"></i>
                                <span>Ejecutar PoC</span>
                            </button>
                        </div>
                    </div>

                    <!-- Result Container -->
                    <div id="strix-poc-results" class="hidden space-y-4 pt-2">
                        <!-- Summary Status Bar -->
                        <div class="grid grid-cols-2 sm:grid-cols-4 gap-3">
                            <div class="bg-slate-900/90 border border-cyber-border rounded-xl p-3">
                                <span class="text-[10px] text-slate-400 uppercase font-medium">Veredicto PoC</span>
                                <div id="strix-poc-badge" class="mt-1 font-bold text-xs"></div>
                            </div>
                            <div class="bg-slate-900/90 border border-cyber-border rounded-xl p-3">
                                <span class="text-[10px] text-slate-400 uppercase font-medium">Código HTTP</span>
                                <div id="strix-poc-http-code" class="mt-1 font-bold font-mono text-xs text-white"></div>
                            </div>
                            <div class="bg-slate-900/90 border border-cyber-border rounded-xl p-3">
                                <span class="text-[10px] text-slate-400 uppercase font-medium">Latencia RTT</span>
                                <div id="strix-poc-latency" class="mt-1 font-bold font-mono text-xs text-cyan-400"></div>
                            </div>
                            <div class="bg-slate-900/90 border border-cyber-border rounded-xl p-3">
                                <span class="text-[10px] text-slate-400 uppercase font-medium">Tipo / Tamaño</span>
                                <div id="strix-poc-content-type" class="mt-1 font-mono text-xs text-slate-300 truncate"></div>
                            </div>
                        </div>

                        <!-- Technical Diagnostic -->
                        <div id="strix-poc-diag-box" class="p-4 rounded-xl border text-xs">
                            <div class="font-bold flex items-center gap-2 mb-1" id="strix-poc-diag-title"></div>
                            <p id="strix-poc-diag-msg" class="text-slate-300 leading-relaxed"></p>
                        </div>

                        <!-- Two-pane Caido / Burp Raw HTTP Inspector -->
                        <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
                            <!-- Request Pane -->
                            <div class="bg-slate-950 border border-cyber-border rounded-xl overflow-hidden flex flex-col">
                                <div class="bg-slate-900/90 px-4 py-2 border-b border-cyber-border flex items-center justify-between text-xs">
                                    <span class="font-bold text-slate-300 flex items-center gap-2">
                                        <i class="fa-solid fa-arrow-up-right-from-square text-cyan-400"></i>
                                        Petición HTTP Enviada (Raw Request)
                                    </span>
                                    <button onclick="copyToClipboard('strix-poc-raw-req', 'Petición copiada')" class="text-slate-400 hover:text-white text-[11px] flex items-center gap-1">
                                        <i class="fa-regular fa-copy"></i> Copiar
                                    </button>
                                </div>
                                <pre id="strix-poc-raw-req" class="p-4 text-xs font-mono text-emerald-400/90 overflow-x-auto max-h-72 overflow-y-auto whitespace-pre leading-snug"></pre>
                            </div>

                            <!-- Response Pane -->
                            <div class="bg-slate-950 border border-cyber-border rounded-xl overflow-hidden flex flex-col">
                                <div class="bg-slate-900/90 px-4 py-2 border-b border-cyber-border flex items-center justify-between text-xs">
                                    <span class="font-bold text-slate-300 flex items-center gap-2">
                                        <i class="fa-solid fa-arrow-down-left-and-up-right-to-center text-amber-400"></i>
                                        Respuesta HTTP Recibida (Raw Response)
                                    </span>
                                    <button onclick="copyToClipboard('strix-poc-raw-res', 'Respuesta copiada')" class="text-slate-400 hover:text-white text-[11px] flex items-center gap-1">
                                        <i class="fa-regular fa-copy"></i> Copiar
                                    </button>
                                </div>
                                <pre id="strix-poc-raw-res" class="p-4 text-xs font-mono text-slate-300 overflow-x-auto max-h-72 overflow-y-auto whitespace-pre leading-snug"></pre>
                            </div>
                        </div>

                        <!-- Reproducible Commands -->
                        <div class="space-y-3">
                            <h4 class="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                                <i class="fa-solid fa-terminal text-cyan-400"></i> Comandos de Reproducción Determinista (PoC)
                            </h4>
                            <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                                <div class="bg-slate-950 border border-cyber-border rounded-xl p-3">
                                    <div class="flex items-center justify-between mb-1.5">
                                        <span class="text-[11px] font-bold text-cyan-400 font-mono">cURL Command</span>
                                        <button onclick="copyToClipboard('strix-poc-curl', 'cURL copiado')" class="text-slate-400 hover:text-white text-[11px] flex items-center gap-1">
                                            <i class="fa-regular fa-copy"></i> Copiar
                                        </button>
                                    </div>
                                    <pre id="strix-poc-curl" class="text-[11px] font-mono text-slate-300 overflow-x-auto p-2 bg-slate-900/60 rounded border border-slate-800"></pre>
                                </div>
                                <div class="bg-slate-950 border border-cyber-border rounded-xl p-3">
                                    <div class="flex items-center justify-between mb-1.5">
                                        <span class="text-[11px] font-bold text-amber-400 font-mono">Python 3 Script</span>
                                        <button onclick="copyToClipboard('strix-poc-python', 'Script Python copiado')" class="text-slate-400 hover:text-white text-[11px] flex items-center gap-1">
                                            <i class="fa-regular fa-copy"></i> Copiar
                                        </button>
                                    </div>
                                    <pre id="strix-poc-python" class="text-[11px] font-mono text-slate-300 overflow-x-auto p-2 bg-slate-900/60 rounded border border-slate-800 max-h-32 overflow-y-auto"></pre>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- SUB-PANEL 2: Fuzzing de Rutas Críticas -->
            <div id="strix-panel-fuzz" class="space-y-4 hidden">
                <div class="bg-cyber-card border border-cyber-border rounded-2xl p-5 space-y-4">
                    <div class="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
                        <div class="flex-1">
                            <label class="block text-[10px] uppercase font-bold text-slate-400 mb-1">URL Base del Objetivo</label>
                            <div class="relative">
                                <i class="fa-solid fa-network-wired absolute left-3 top-2.5 text-slate-500 text-xs"></i>
                                <input type="text" id="strix-fuzz-url" placeholder="https://ejemplo.com" class="w-full pl-9 pr-3 py-2 rounded-xl bg-slate-900 border border-cyber-border text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono">
                            </div>
                        </div>
                        <div class="flex items-end">
                            <button onclick="runStrixRouteFuzz()" id="btn-strix-run-fuzz" class="w-full sm:w-auto px-5 py-2 rounded-xl bg-amber-600 hover:bg-amber-500 text-white text-xs font-bold transition flex items-center justify-center gap-2 shadow-lg shadow-amber-950/50">
                                <i class="fa-solid fa-magnifying-glass-chart"></i>
                                <span>Iniciar Fuzzing (16 Rutas)</span>
                            </button>
                        </div>
                    </div>

                    <div id="strix-fuzz-results" class="hidden space-y-4 pt-2">
                        <!-- Canary Soft-404 Banner -->
                        <div class="p-3 bg-slate-900/80 rounded-xl border border-cyber-border flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
                            <div class="flex items-center gap-2">
                                <i class="fa-solid fa-shield-virus text-amber-400"></i>
                                <span class="text-slate-300 font-medium">Filtrado Soft-404 Activo:</span>
                                <span id="strix-fuzz-canary-status" class="text-slate-400 font-mono text-[11px]"></span>
                            </div>
                            <span class="text-[11px] text-cyan-400 font-mono">Descarta falsos positivos de Single Page Apps (SPA)</span>
                        </div>

                        <!-- Fuzzing Table -->
                        <div class="bg-slate-950 border border-cyber-border rounded-xl overflow-hidden">
                            <div class="overflow-x-auto">
                                <table class="w-full text-left text-xs">
                                    <thead class="bg-slate-900/80 text-slate-400 uppercase text-[10px] tracking-wider border-b border-cyber-border">
                                        <tr>
                                            <th class="p-3.5">Ruta Probada</th>
                                            <th class="p-3.5 text-center">Código HTTP</th>
                                            <th class="p-3.5 text-right">Tamaño</th>
                                            <th class="p-3.5">Clasificación / Veredicto</th>
                                            <th class="p-3.5 text-center">Acción</th>
                                        </tr>
                                    </thead>
                                    <tbody id="strix-fuzz-tbody" class="divide-y divide-cyber-border/60 text-slate-300"></tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- SUB-PANEL 3: Inspección Certificado X.509 / TLS -->
            <div id="strix-panel-tls" class="space-y-4 hidden">
                <div class="bg-cyber-card border border-cyber-border rounded-2xl p-5 space-y-4">
                    <div class="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
                        <div class="flex-1">
                            <label class="block text-[10px] uppercase font-bold text-slate-400 mb-1">Hostname / FQDN Objetivo</label>
                            <input type="text" id="strix-tls-host" placeholder="ejemplo: demo.testfire.net o fdn.com.co" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-cyber-border text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono">
                        </div>
                        <div class="w-full sm:w-28">
                            <label class="block text-[10px] uppercase font-bold text-slate-400 mb-1">Puerto</label>
                            <input type="number" id="strix-tls-port" value="443" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-cyber-border text-xs text-white font-mono focus:outline-none focus:border-cyan-500">
                        </div>
                        <div class="flex items-end">
                            <button onclick="runStrixTlsInspect()" id="btn-strix-run-tls" class="w-full sm:w-auto px-5 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold transition flex items-center justify-center gap-2 shadow-lg shadow-cyan-950/50">
                                <i class="fa-solid fa-lock"></i>
                                <span>Inspeccionar X.509</span>
                            </button>
                        </div>
                    </div>

                    <div id="strix-tls-results" class="hidden space-y-4 pt-2">
                        <!-- Status Banner -->
                        <div id="strix-tls-banner" class="p-4 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                            <div class="flex items-center gap-3">
                                <div id="strix-tls-icon" class="w-10 h-10 rounded-xl flex items-center justify-center text-lg"></div>
                                <div>
                                    <h4 id="strix-tls-status-title" class="font-bold text-sm text-white"></h4>
                                    <p id="strix-tls-status-desc" class="text-xs text-slate-300 mt-0.5"></p>
                                </div>
                            </div>
                            <div id="strix-tls-days-badge" class="px-3 py-1.5 rounded-xl font-mono text-xs font-bold border"></div>
                        </div>

                        <!-- Certificate Fields Grid -->
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div class="bg-slate-950 border border-cyber-border rounded-xl p-4 space-y-3">
                                <h5 class="text-xs font-bold text-slate-400 uppercase tracking-wider border-b border-cyber-border/70 pb-2">Identidad y Emisor</h5>
                                <div class="text-xs space-y-2">
                                    <div>
                                        <span class="text-slate-500 block text-[10px] uppercase">Common Name (CN)</span>
                                        <span id="strix-tls-cn" class="font-mono text-white font-bold"></span>
                                    </div>
                                    <div>
                                        <span class="text-slate-500 block text-[10px] uppercase">Autoridad Emisora (Issuer)</span>
                                        <span id="strix-tls-issuer" class="font-mono text-cyan-300"></span>
                                    </div>
                                    <div>
                                        <span class="text-slate-500 block text-[10px] uppercase">Algoritmo de Firma</span>
                                        <span id="strix-tls-algo" class="font-mono text-amber-300"></span>
                                    </div>
                                </div>
                            </div>

                            <div class="bg-slate-950 border border-cyber-border rounded-xl p-4 space-y-3">
                                <h5 class="text-xs font-bold text-slate-400 uppercase tracking-wider border-b border-cyber-border/70 pb-2">Vigencia y Validez</h5>
                                <div class="text-xs space-y-2">
                                    <div>
                                        <span class="text-slate-500 block text-[10px] uppercase">Válido Desde</span>
                                        <span id="strix-tls-from" class="font-mono text-slate-300"></span>
                                    </div>
                                    <div>
                                        <span class="text-slate-500 block text-[10px] uppercase">Válido Hasta</span>
                                        <span id="strix-tls-to" class="font-mono text-slate-300"></span>
                                    </div>
                                    <div>
                                        <span class="text-slate-500 block text-[10px] uppercase">Nombres Alternativos (SANs)</span>
                                        <div id="strix-tls-sans" class="flex flex-wrap gap-1 mt-1"></div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- SUB-PANEL 4: Laboratorio CORS & Headers -->
            <div id="strix-panel-cors" class="space-y-4 hidden">
                <div class="bg-cyber-card border border-cyber-border rounded-2xl p-5 space-y-4">
                    <div class="flex flex-col md:flex-row items-stretch md:items-center gap-3">
                        <div class="flex-1">
                            <label class="block text-[10px] uppercase font-bold text-slate-400 mb-1">URL Objetivo</label>
                            <input type="text" id="strix-cors-url" placeholder="https://ejemplo.com/api" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-cyber-border text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono">
                        </div>
                        <div class="w-full md:w-72">
                            <label class="block text-[10px] uppercase font-bold text-slate-400 mb-1">Origin a Inyectar (Test Origin)</label>
                            <input type="text" id="strix-cors-origin" value="https://evil-attacker.com" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-cyber-border text-xs text-amber-300 font-mono focus:outline-none focus:border-cyan-500">
                        </div>
                        <div class="flex items-end">
                            <button onclick="runStrixCorsTest()" id="btn-strix-run-cors" class="w-full md:w-auto px-5 py-2 rounded-xl bg-purple-600 hover:bg-purple-500 text-white text-xs font-bold transition flex items-center justify-center gap-2 shadow-lg shadow-purple-950/50">
                                <i class="fa-solid fa-shield-halved"></i>
                                <span>Auditar CORS</span>
                            </button>
                        </div>
                    </div>

                    <div id="strix-cors-results" class="hidden space-y-4 pt-2">
                        <!-- Origin Reflection Banner -->
                        <div id="strix-cors-banner" class="p-4 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                            <div class="flex items-center gap-3">
                                <div id="strix-cors-icon" class="w-10 h-10 rounded-xl flex items-center justify-center text-lg"></div>
                                <div>
                                    <h4 id="strix-cors-verdict" class="font-bold text-sm text-white"></h4>
                                    <p id="strix-cors-explanation" class="text-xs text-slate-300 mt-0.5"></p>
                                </div>
                            </div>
                            <div class="text-right font-mono text-xs">
                                <div class="text-slate-400 text-[10px]">Allow-Credentials</div>
                                <div id="strix-cors-credentials" class="font-bold"></div>
                            </div>
                        </div>

                        <!-- Defensive Headers Checklist -->
                        <div class="bg-slate-950 border border-cyber-border rounded-xl p-4">
                            <h5 class="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3">Auditoría de Cabeceras Defensivas Perimetrales</h5>
                            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3" id="strix-cors-headers-grid"></div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- SUB-PANEL 5: Auditoría RFC DNS & Resiliencia -->
            <div id="strix-panel-dns" class="space-y-4 hidden">
                <div class="bg-cyber-card border border-cyber-border rounded-2xl p-5 space-y-4">
                    <div class="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
                        <div class="flex-1">
                            <label class="block text-[10px] uppercase font-bold text-slate-400 mb-1">Dominio / FQDN</label>
                            <input type="text" id="strix-dns-domain" placeholder="ejemplo: fdn.com.co" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-cyber-border text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono">
                        </div>
                        <div class="flex items-end">
                            <button onclick="runStrixDnsInspect()" id="btn-strix-run-dns" class="w-full sm:w-auto px-5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold transition flex items-center justify-center gap-2 shadow-lg shadow-blue-950/50">
                                <i class="fa-solid fa-network-wired"></i>
                                <span>Consultar DNS RFC</span>
                            </button>
                        </div>
                    </div>

                    <div id="strix-dns-results" class="hidden space-y-4 pt-2">
                        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                            <!-- A / AAAA Card -->
                            <div class="bg-slate-950 border border-cyber-border rounded-xl p-4 space-y-2">
                                <div class="flex items-center justify-between text-xs font-bold text-slate-300 border-b border-cyber-border/70 pb-2">
                                    <span class="flex items-center gap-1.5"><i class="fa-solid fa-server text-cyan-400"></i> Registros A / AAAA</span>
                                    <span id="strix-dns-count-a" class="text-[10px] font-mono text-cyan-400"></span>
                                </div>
                                <div id="strix-dns-records-a" class="space-y-1 font-mono text-xs max-h-40 overflow-y-auto"></div>
                            </div>

                            <!-- MX Card -->
                            <div class="bg-slate-950 border border-cyber-border rounded-xl p-4 space-y-2">
                                <div class="flex items-center justify-between text-xs font-bold text-slate-300 border-b border-cyber-border/70 pb-2">
                                    <span class="flex items-center gap-1.5"><i class="fa-solid fa-envelope text-amber-400"></i> Servidores MX (Correo)</span>
                                    <span id="strix-dns-count-mx" class="text-[10px] font-mono text-amber-400"></span>
                                </div>
                                <div id="strix-dns-records-mx" class="space-y-1 font-mono text-xs max-h-40 overflow-y-auto"></div>
                            </div>

                            <!-- NS Card -->
                            <div class="bg-slate-950 border border-cyber-border rounded-xl p-4 space-y-2">
                                <div class="flex items-center justify-between text-xs font-bold text-slate-300 border-b border-cyber-border/70 pb-2">
                                    <span class="flex items-center gap-1.5"><i class="fa-solid fa-sitemap text-purple-400"></i> Nameservers (NS)</span>
                                    <span id="strix-dns-count-ns" class="text-[10px] font-mono text-purple-400"></span>
                                </div>
                                <div id="strix-dns-records-ns" class="space-y-1 font-mono text-xs max-h-40 overflow-y-auto"></div>
                            </div>

                            <!-- TXT Card -->
                            <div class="bg-slate-950 border border-cyber-border rounded-xl p-4 space-y-2 md:col-span-2">
                                <div class="flex items-center justify-between text-xs font-bold text-slate-300 border-b border-cyber-border/70 pb-2">
                                    <span class="flex items-center gap-1.5"><i class="fa-solid fa-file-lines text-emerald-400"></i> Registros TXT (SPF, Verificación)</span>
                                    <span id="strix-dns-count-txt" class="text-[10px] font-mono text-emerald-400"></span>
                                </div>
                                <div id="strix-dns-records-txt" class="space-y-1.5 font-mono text-xs max-h-48 overflow-y-auto"></div>
                            </div>

                            <!-- DMARC & CAA Card -->
                            <div class="bg-slate-950 border border-cyber-border rounded-xl p-4 space-y-3">
                                <div class="border-b border-cyber-border/70 pb-2">
                                    <span class="text-xs font-bold text-slate-300 flex items-center gap-1.5"><i class="fa-solid fa-shield-halved text-rose-400"></i> DMARC & CAA</span>
                                </div>
                                <div class="space-y-2 text-xs">
                                    <div>
                                        <span class="text-[10px] text-slate-500 uppercase font-mono block">DMARC Record (_dmarc)</span>
                                        <div id="strix-dns-record-dmarc" class="font-mono text-slate-300 text-[11px] bg-slate-900 p-1.5 rounded border border-slate-800 break-all mt-0.5"></div>
                                    </div>
                                    <div>
                                        <span class="text-[10px] text-slate-500 uppercase font-mono block">CAA Policy</span>
                                        <div id="strix-dns-record-caa" class="font-mono text-slate-300 text-[11px] bg-slate-900 p-1.5 rounded border border-slate-800 break-all mt-0.5"></div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>

    </main>

    <!-- Work Plan & Roadmap Modal -->
    <div id="plan-modal" class="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4 hidden">
        <div class="bg-cyber-card border border-cyan-500/50 rounded-2xl max-w-3xl w-full p-6 shadow-2xl relative max-h-[90vh] flex flex-col">
            <div class="flex items-center justify-between pb-4 border-b border-cyber-border">
                <div class="flex items-center gap-2.5">
                    <div class="w-8 h-8 rounded-lg bg-blue-950 border border-blue-700 flex items-center justify-center text-blue-400 font-bold">
                        <i class="fa-solid fa-list-check"></i>
                    </div>
                    <div>
                        <h3 class="font-bold text-white text-base">Plan de Trabajo y Hoja de Ruta de Remediación</h3>
                        <p id="plan-seed-subtitle" class="text-xs text-cyan-400 font-mono">Semilla Activa: www.fdn.com.co</p>
                    </div>
                </div>
                <button onclick="closePlanModal()" class="text-slate-400 hover:text-white p-1 rounded-lg">
                    <i class="fa-solid fa-xmark text-lg"></i>
                </button>
            </div>

            <div class="mt-4 space-y-4 overflow-y-auto pr-2 text-xs text-slate-300 flex-1">
                <div class="p-4 bg-slate-900/80 rounded-xl border border-cyber-border">
                    <h4 class="font-bold text-cyan-400 text-sm flex items-center gap-2 mb-1">
                        <i class="fa-solid fa-bolt"></i> Prioridad Inmediata (0 - 48 Horas)
                    </h4>
                    <ul class="list-disc list-inside space-y-1.5 text-slate-300 mt-2">
                        <li><strong>Remediación de Fuga de Credenciales (773 Registros):</strong> Forzar reseteo inmediato de contraseña de la cuenta <code>admin</code> expuesta en Collection #1 y habilitar MFA obligatorio (FIDO2/TOTP).</li>
                        <li><strong>Bloqueo Perimetral de Servidores C2:</strong> Cargar la lista de 160+ IOCs activos en el firewall corporativo (FortiGate / iptables) para prevenir exfiltración de infostealers.</li>
                        <li><strong>Cierre de Puertos No Web:</strong> Inspeccionar puertos no estándar (ej. 8080) y aplicar lista blanca de administración perimetral.</li>
                        <li><strong>Verificación de Endpoints Sensibles:</strong> Validar que rutas administrativas (.env, .git) no estén accesibles públicamente.</li>
                    </ul>
                </div>

                <div class="p-4 bg-slate-900/80 rounded-xl border border-cyber-border">
                    <h4 class="font-bold text-amber-400 text-sm flex items-center gap-2 mb-1">
                        <i class="fa-solid fa-shield-halved"></i> Corto Plazo (1 - 2 Semanas)
                    </h4>
                    <ul class="list-disc list-inside space-y-1.5 text-slate-300 mt-2">
                        <li><strong>Protección de Cabeceras HTTP:</strong> Habilitar <code>Strict-Transport-Security (HSTS)</code>, <code>X-Content-Type-Options: nosniff</code> y política CSP estricta.</li>
                        <li><strong>Ocultamiento de Banners:</strong> Configurar el servidor para suprimir información sobre el software de base (Apache / Nginx / PHP).</li>
                        <li><strong>DMARC & Anti-Spoofing:</strong> Configurar registro DMARC en modo rechazo (<code>p=reject</code>) junto con SPF y DKIM para blindar el dominio corporativo contra phishing.</li>
                    </ul>
                </div>

                <div class="p-4 bg-slate-900/80 rounded-xl border border-cyber-border">
                    <h4 class="font-bold text-emerald-400 text-sm flex items-center gap-2 mb-1">
                        <i class="fa-solid fa-chart-line"></i> Mediano Plazo y Vigilancia Continua (Permanente)
                    </h4>
                    <ul class="list-disc list-inside space-y-1.5 text-slate-300 mt-2">
                        <li><strong>Automatización EASM:</strong> Programar re-escaneos automáticos semanales para detectar nuevos subdominios o cambios en puertos.</li>
                        <li><strong>Alerta Temprana DRP:</strong> Tramitar solicitudes de Takedown de inmediato si se detecta un dominio clon con servidores MX activos.</li>
                        <li><strong>Monitoreo de la Dark Web:</strong> Cruzar mensualmente el inventario con los blogs de ransomware y feeds C2.</li>
                    </ul>
                </div>
            </div>

            <div class="mt-4 pt-4 border-t border-cyber-border flex justify-between items-center">
                <span class="text-[11px] text-slate-500 font-mono">Basado en metodologías CIS & NIST CSF</span>
                <button onclick="closePlanModal()" class="px-5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold">
                    Cerrar
                </button>
            </div>
        </div>
    </div>

    <!-- Takedown Modal -->
    <div id="takedown-modal" class="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4 hidden">
        <div class="bg-cyber-card border border-cyan-500/50 rounded-2xl max-w-2xl w-full p-6 shadow-2xl relative">
            <div class="flex items-center justify-between pb-4 border-b border-cyber-border">
                <div class="flex items-center gap-2">
                    <i class="fa-solid fa-gavel text-rose-400 text-lg"></i>
                    <h3 class="font-bold text-white text-base">Ficha Legal de Takedown / Solicitud de Abuso</h3>
                </div>
                <button onclick="closeTakedownModal()" class="text-slate-400 hover:text-white p-1 rounded-lg">
                    <i class="fa-solid fa-xmark text-lg"></i>
                </button>
            </div>

            <div class="mt-4 space-y-4">
                <p class="text-xs text-slate-300">
                    Plantilla estandarizada (RFC 2142 y directivas UDRP/ICANN) lista para enviar a la dirección de abuso del registrador o proveedor de hosting del dominio infractor.
                </p>
                <div class="relative">
                    <textarea id="takedown-text" readonly rows="12" class="w-full p-4 rounded-xl bg-slate-950 border border-cyber-border font-mono text-[11px] text-slate-300 focus:outline-none"></textarea>
                    <button onclick="copyTakedownText()" class="absolute top-3 right-3 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs flex items-center gap-1.5 shadow">
                        <i class="fa-solid fa-copy"></i>
                        <span>Copiar Notificación</span>
                    </button>
                </div>
            </div>

            <div class="mt-6 flex justify-end">
                <button onclick="closeTakedownModal()" class="px-5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold">
                    Cerrar
                </button>
            </div>
        </div>
    </div>

    <!-- Forensic Breach Detail & Remediation Playbook Modal -->
    <div id="breach-modal" class="fixed inset-0 bg-black/85 backdrop-blur-md z-50 flex items-center justify-center p-4 hidden">
        <div class="bg-cyber-card border border-amber-500/50 rounded-2xl max-w-3xl w-full p-6 shadow-2xl relative max-h-[92vh] flex flex-col">
            <div class="flex items-center justify-between pb-4 border-b border-cyber-border">
                <div class="flex items-center gap-3">
                    <div class="w-10 h-10 rounded-xl bg-amber-950/80 border border-amber-600 flex items-center justify-center text-amber-400 text-lg shadow-lg">
                        <i class="fa-solid fa-microscope"></i>
                    </div>
                    <div>
                        <h3 class="font-bold text-white text-base flex items-center gap-2">
                            <span>Análisis Forense de Fuga de Credenciales (Collection #1)</span>
                            <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-300 border border-rose-800">SEVERIDAD ALTA</span>
                        </h3>
                        <p id="breach-modal-email" class="text-xs text-amber-400 font-mono">admin@www.fdn.com.co &bull; 773 Registros Pwned</p>
                    </div>
                </div>
                <button onclick="closeBreachModal()" class="text-slate-400 hover:text-white p-1 rounded-lg">
                    <i class="fa-solid fa-xmark text-lg"></i>
                </button>
            </div>

            <div class="mt-4 space-y-4 overflow-y-auto pr-2 text-xs text-slate-300 flex-1">
                <!-- Seccion 1: Que se encontro -->
                <div class="p-4 bg-slate-900/90 rounded-xl border border-cyber-border">
                    <h4 class="font-bold text-cyan-400 text-sm flex items-center gap-2 mb-2">
                        <i class="fa-solid fa-magnifying-glass-chart"></i> 1. ¿Qué se encontró exactamente en los 773 registros?
                    </h4>
                    <p class="text-slate-300 leading-relaxed mb-3">
                        El hallazgo corresponde a la mega-filtración <strong>Collection #1</strong>, una de las compilaciones más grandes de la historia cibernética (<strong>87 Gigabytes</strong> y <strong>773,907,047 registros únicos de credenciales</strong>) expuesta en foros clandestinos como RaidForums y canales de Telegram.
                    </p>
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-2">
                        <div class="p-3 bg-slate-950/80 rounded-lg border border-slate-800">
                            <span class="text-[11px] font-bold text-amber-400 block mb-1">
                                <i class="fa-solid fa-bug mr-1"></i> Origen: Malware Infostealer
                            </span>
                            <p class="text-[11px] text-slate-400">
                                Combinaciones robadas por troyanos ladrones de información (<strong>RedLine, Vidar, Racoon, Raccoon Stealer</strong>) que infectan estaciones de trabajo y extraen credenciales cacheadas en navegadores (Chrome, Edge, Firefox).
                            </p>
                        </div>
                        <div class="p-3 bg-slate-950/80 rounded-lg border border-slate-800">
                            <span class="text-[11px] font-bold text-rose-400 block mb-1">
                                <i class="fa-solid fa-unlock-keyhole mr-1"></i> Estado: Texto Claro & Hashes Débiles
                            </span>
                            <p class="text-[11px] text-slate-400">
                                Los 773 registros asociados al dominio corporativo contienen contraseñas en <strong>texto plano legible</strong> o hashes vulnerables (MD5 / SHA-1) descifrados mediante tablas arcoíris (Rainbow Tables).
                            </p>
                        </div>
                    </div>
                    <div class="p-2.5 bg-slate-950 rounded border border-cyber-border/70 text-[11px] font-mono text-cyan-300">
                        <strong>Clases de Datos Comprometidas:</strong> <span id="breach-modal-dataclasses">Contraseñas en texto plano, Hashes MD5/SHA1 descifrados, Nombres de usuario corporativos, URLs de portales de autenticación.</span>
                    </div>
                </div>

                <!-- Seccion 2: Por que la severidad es High -->
                <div class="p-4 bg-slate-900/90 rounded-xl border border-rose-900/40">
                    <h4 class="font-bold text-rose-400 text-sm flex items-center gap-2 mb-2">
                        <i class="fa-solid fa-shield-virus"></i> 2. ¿Por qué la Severidad se clasifica como ALTA (HIGH)?
                    </h4>
                    <ul class="space-y-2.5 text-slate-300">
                        <li class="flex items-start gap-2">
                            <i class="fa-solid fa-check text-rose-400 mt-1"></i>
                            <div>
                                <strong class="text-white">Vector MITRE ATT&CK T1078 (Cuentas Válidas / Valid Accounts):</strong>
                                Al contar con contraseñas funcionales, los actores maliciosos no requieren explotar vulnerabilidades de software (cero exploits). Pueden ingresar directamente por los flujos legítimos de autenticación de la empresa sin activar firmas de IDS ni WAF perimetral.
                            </div>
                        </li>
                        <li class="flex items-start gap-2">
                            <i class="fa-solid fa-check text-rose-400 mt-1"></i>
                            <div>
                                <strong class="text-white">Ataques Masivos de Credential Stuffing & Password Spraying (MITRE T1110):</strong>
                                Los atacantes emplean herramientas automatizadas (OpenBullet, Sentry MBA) para inyectar estas 773 combinaciones en los puntos de acceso expuestos (Webmail, VPN SSL en puerto 443, portales administrativos en puerto 8080). Más del 65% de los empleados reutiliza contraseñas en plataformas corporativas.
                            </div>
                        </li>
                        <li class="flex items-start gap-2">
                            <i class="fa-solid fa-check text-rose-400 mt-1"></i>
                            <div>
                                <strong class="text-white">Impacto Crítico por Identidad Administrativa:</strong>
                                La cuenta identificada (<code>admin@...</code>) ostenta privilegios elevados. Si el acceso se consuma, permite persistencia silenciosa (T1114), compromiso de directorios Active Directory / Azure AD y posible despliegue lateral de ransomware.
                            </div>
                        </li>
                    </ul>
                </div>

                <!-- Seccion 3: Playbook de Remediacion -->
                <div class="p-4 bg-slate-900/90 rounded-xl border border-cyan-800/50">
                    <h4 class="font-bold text-cyan-400 text-sm flex items-center gap-2 mb-2">
                        <i class="fa-solid fa-list-check"></i> 3. Playbook Operativo de Remediación (Acciones Mandatorias)
                    </h4>
                    <div id="breach-modal-playbook" class="space-y-2 font-mono text-[11px] text-slate-300 bg-slate-950 p-3.5 rounded-lg border border-slate-800 whitespace-pre-line">
1. FORZAR RESTABLECIMIENTO INMEDIATO de contraseña corporativa en Active Directory / Azure AD con política de complejidad robusta (&ge; 14 caracteres).
2. HABILITAR OBLIGATORIAMENTE MFA (Autenticación Multifactor) resistente a phishing mediante FIDO2 o Microsoft Authenticator (descartar SMS).
3. AUDITAR ACCESOS PERIMETRALES en puertos 80 y 443 en las últimas 72 horas buscando inicios de sesión anómalos o desde geolocalizaciones no habituales.
4. BLOQUEAR IOCs ACTIVOS: Integrar la lista de 160+ servidores C2 maliciosos sincronizados en los firewalls perimetrales (FortiGate / iptables).
                    </div>
                </div>
            </div>

            <div class="mt-4 pt-4 border-t border-cyber-border flex justify-between items-center">
                <span class="text-[11px] text-slate-500 font-mono">Auditoría NIST SP 800-63B &bull; Identidad Digital</span>
                <button onclick="closeBreachModal()" class="px-5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold">
                    Cerrar Detalle
                </button>
            </div>
        </div>
    </div>

    <!-- Firewall Rules Export Modal (C2 Blocking) -->
    <div id="firewall-modal" class="fixed inset-0 bg-black/85 backdrop-blur-md z-50 flex items-center justify-center p-4 hidden">
        <div class="bg-cyber-card border border-cyan-500/50 rounded-2xl max-w-3xl w-full p-6 shadow-2xl relative max-h-[90vh] flex flex-col">
            <div class="flex items-center justify-between pb-4 border-b border-cyber-border">
                <div class="flex items-center gap-2.5">
                    <div class="w-9 h-9 rounded-xl bg-cyan-950 border border-cyan-700 flex items-center justify-center text-cyan-400 text-base">
                        <i class="fa-solid fa-shield-halved"></i>
                    </div>
                    <div>
                        <h3 class="font-bold text-white text-base">Reglas de Bloqueo Perimetral para Firewall (Servidores C2)</h3>
                        <p class="text-xs text-cyan-400 font-mono">160+ Nodos Maliciosos Activos (Feodo Tracker, Emerging Threats, IPsum)</p>
                    </div>
                </div>
                <button onclick="closeFirewallRulesModal()" class="text-slate-400 hover:text-white p-1 rounded-lg">
                    <i class="fa-solid fa-xmark text-lg"></i>
                </button>
            </div>

            <div class="mt-4 space-y-3 overflow-y-auto pr-1 flex-1 text-xs">
                <p class="text-slate-300">
                    Aplica estas directivas en tus firewalls perimetrales para cortar de raíz cualquier intento de conexión hacia servidores de Comando y Control (C2) de botnets o exfiltración de Infostealers:
                </p>

                <div class="flex gap-2 mb-2">
                    <button onclick="setFirewallTab('fortigate')" id="fw-tab-fortigate" class="px-3 py-1.5 rounded-lg bg-cyan-900/60 text-white text-xs font-semibold border border-cyan-600">
                        FortiGate CLI
                    </button>
                    <button onclick="setFirewallTab('iptables')" id="fw-tab-iptables" class="px-3 py-1.5 rounded-lg bg-slate-900 text-slate-400 hover:text-white text-xs font-semibold border border-cyber-border">
                        Linux iptables
                    </button>
                    <button onclick="setFirewallTab('plain')" id="fw-tab-plain" class="px-3 py-1.5 rounded-lg bg-slate-900 text-slate-400 hover:text-white text-xs font-semibold border border-cyber-border">
                        Lista IP / CIDR
                    </button>
                </div>

                <div class="relative">
                    <textarea id="firewall-rules-text" readonly rows="12" class="w-full p-4 rounded-xl bg-slate-950 border border-cyber-border font-mono text-[11px] text-cyan-300 focus:outline-none"></textarea>
                    <button onclick="copyFirewallRules()" class="absolute top-3 right-3 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs flex items-center gap-1.5 shadow">
                        <i class="fa-solid fa-copy"></i>
                        <span>Copiar Reglas</span>
                    </button>
                </div>
            </div>

            <div class="mt-4 pt-4 border-t border-cyber-border flex justify-between items-center">
                <span class="text-[11px] text-slate-500 font-mono">OpenRecon Threat Intel Ingestion Engine</span>
                <button onclick="closeFirewallRulesModal()" class="px-5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold">
                    Cerrar
                </button>
            </div>
        </div>
    </div>

    <!-- Vulnerability Hardening & Playbook Modal -->
    <div id="vuln-playbook-modal" class="fixed inset-0 bg-black/85 backdrop-blur-md z-50 flex items-center justify-center p-4 hidden">
        <div class="bg-cyber-card border border-indigo-500/50 rounded-2xl max-w-4xl w-full p-6 shadow-2xl relative max-h-[92vh] flex flex-col">
            <div class="flex items-center justify-between pb-4 border-b border-cyber-border">
                <div class="flex items-center gap-3">
                    <div class="w-10 h-10 rounded-xl bg-indigo-950 border border-indigo-700 flex items-center justify-center text-indigo-400">
                        <i class="fa-solid fa-shield-halved text-lg"></i>
                    </div>
                    <div>
                        <div class="flex items-center gap-2">
                            <span id="vp-severity" class="px-2 py-0.5 rounded text-[10px] font-bold border uppercase tracking-wider bg-rose-950 text-rose-400 border-rose-800">HIGH</span>
                            <span id="vp-cwe" class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-cyan-400 border border-slate-700">CWE-298</span>
                            <span id="vp-asset" class="px-2 py-0.5 rounded text-[10px] font-mono text-slate-300 bg-slate-900 border border-slate-700">demo.testfire.net</span>
                        </div>
                        <h3 id="vp-title" class="text-base font-bold text-white mt-1">Título de la Vulnerabilidad</h3>
                    </div>
                </div>
                <button onclick="closeVulnPlaybookModal()" class="text-slate-400 hover:text-white p-2">
                    <i class="fa-solid fa-times text-xl"></i>
                </button>
            </div>

            <div class="overflow-y-auto my-4 space-y-4 pr-1 text-xs">
                <!-- Description & Diagnostic -->
                <div class="bg-slate-950 p-4 rounded-xl border border-cyber-border space-y-2">
                    <h5 class="text-xs font-bold text-slate-300 flex items-center gap-1.5">
                        <i class="fa-solid fa-circle-info text-cyan-400"></i> Descripción y Diagnóstico Forense
                    </h5>
                    <p id="vp-desc" class="text-slate-300 leading-relaxed font-sans"></p>
                    <div class="mt-2 pt-2 border-t border-slate-800 text-slate-400">
                        <strong class="text-emerald-400">Remediación Estándar:</strong>
                        <span id="vp-remediation"></span>
                    </div>
                </div>

                <!-- Executive Non-Technical Explanation -->
                <div class="bg-amber-950/20 p-4 rounded-xl border border-amber-800/40 space-y-2">
                    <h5 class="text-xs font-bold text-amber-400 flex items-center gap-1.5">
                        <i class="fa-solid fa-lightbulb text-amber-400"></i> Explicación Ejecutiva No Técnica (Impacto en Negocio)
                    </h5>
                    <div id="vp-exec-explanation" class="text-slate-300 leading-relaxed font-sans text-xs space-y-1.5">
                    </div>
                </div>

                <!-- Hardening Snippets Multi-Stack -->
                <div class="space-y-2">
                    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <h5 class="text-xs font-bold text-indigo-400 flex items-center gap-1.5">
                            <i class="fa-solid fa-code text-indigo-400"></i> Directivas de Configuración y Hardening (Copiar y Pegar)
                        </h5>
                        <div class="flex items-center gap-1.5 flex-wrap">
                            <button onclick="setVpStack('fortiweb')" id="vp-tab-fortiweb" class="px-2.5 py-1 rounded text-xs font-semibold bg-red-950/80 text-red-300 hover:text-white border border-red-700/60 flex items-center gap-1"><i class="fa-solid fa-shield-halved text-red-500"></i> Fortinet FortiWeb</button>
                            <button onclick="setVpStack('nginx')" id="vp-tab-nginx" class="px-2.5 py-1 rounded text-xs font-semibold bg-indigo-900 text-white border border-indigo-600">Nginx</button>
                            <button onclick="setVpStack('apache')" id="vp-tab-apache" class="px-2.5 py-1 rounded text-xs font-semibold bg-slate-900 text-slate-400 hover:text-white border border-cyber-border">Apache</button>
                            <button onclick="setVpStack('tomcat')" id="vp-tab-tomcat" class="px-2.5 py-1 rounded text-xs font-semibold bg-slate-900 text-slate-400 hover:text-white border border-cyber-border">Tomcat / Java</button>
                            <button onclick="setVpStack('iis')" id="vp-tab-iis" class="px-2.5 py-1 rounded text-xs font-semibold bg-slate-900 text-slate-400 hover:text-white border border-cyber-border">IIS / Windows</button>
                            <button onclick="setVpStack('cloudflare')" id="vp-tab-cloudflare" class="px-2.5 py-1 rounded text-xs font-semibold bg-slate-900 text-slate-400 hover:text-white border border-cyber-border">Cloudflare</button>
                        </div>
                    </div>

                    <div class="relative">
                        <pre id="vp-snippet-code" class="w-full p-4 rounded-xl bg-slate-950 border border-cyber-border font-mono text-[11px] text-cyan-300 overflow-x-auto whitespace-pre leading-relaxed"></pre>
                        <button onclick="copyVpSnippet()" class="absolute top-3 right-3 px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs flex items-center gap-1.5 shadow">
                            <i class="fa-solid fa-copy"></i>
                            <span>Copiar Snippet</span>
                        </button>
                    </div>
                </div>

                <!-- Verification Curl Command -->
                <div class="space-y-2">
                    <h5 class="text-xs font-bold text-emerald-400 flex items-center gap-1.5">
                        <i class="fa-solid fa-terminal text-emerald-400"></i> Comando de Verificación Post-Remediación
                    </h5>
                    <div class="relative">
                        <pre id="vp-curl-code" class="w-full p-3.5 rounded-xl bg-slate-950 border border-emerald-900/50 font-mono text-[11px] text-emerald-300 overflow-x-auto whitespace-pre leading-relaxed"></pre>
                        <button onclick="copyVpCurl()" class="absolute top-2.5 right-2.5 px-3 py-1 rounded-lg bg-emerald-700 hover:bg-emerald-600 text-white font-semibold text-xs flex items-center gap-1.5 shadow">
                            <i class="fa-solid fa-copy"></i>
                            <span>Copiar Comando</span>
                        </button>
                    </div>
                </div>
            </div>

            <div class="mt-2 pt-3 border-t border-cyber-border flex flex-col sm:flex-row justify-between items-center gap-2">
                <div class="flex items-center gap-2">
                    <span class="text-xs text-slate-400 font-medium">Actualizar Estado:</span>
                    <select id="vp-status-select" onchange="onVpStatusChange(this.value)" class="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-900 text-cyan-300 border border-cyan-800 focus:outline-none">
                        <option value="OPEN">🔴 Abierto</option>
                        <option value="IN_PROGRESS">🟡 En Remediación</option>
                        <option value="RESOLVED">🟢 Mitigado / Resuelto</option>
                        <option value="FALSE_POSITIVE">⚪ Falso Positivo</option>
                    </select>
                </div>
                <button onclick="closeVulnPlaybookModal()" class="px-5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold">
                    Cerrar Playbook
                </button>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <footer class="border-t border-cyber-border py-6 text-center text-xs text-slate-500 no-print">
        <p>OpenRecon &copy; 2026 - Plataforma Libre de Ciberseguridad Defensiva y Exposición Perimetral.</p>
        <p class="mt-1">Publicado con Apache / XAMPP &bull; Diseñado para soberanía de datos y escaneo no intrusivo.</p>
    </footer>

    <!-- Toast Notification -->
    <div id="toast" class="fixed bottom-6 right-6 px-5 py-3 rounded-xl bg-slate-900 border border-cyan-500 text-white text-xs shadow-2xl transition-all duration-300 opacity-0 pointer-events-none transform translate-y-4 z-50 flex items-center gap-3 no-print">
        <i id="toast-icon" class="fa-solid fa-circle-check text-cyan-400"></i>
        <span id="toast-msg">Mensaje de notificación</span>
    </div>

    <!-- Application Script -->
    <script>
        const API_URL = 'api.php';
        let globalAssets = [];
        let globalLeaks = [];
        let globalIocs = [];
        let currentFwTab = 'fortigate';
        let networkInstance = null;
        let activeSeed = ''; // Empty or 'ALL' or specific domain

        async function init() {
            await loadSeeds();
            await refreshAllData();
        }

        async function refreshAllData() {
            await Promise.all([
                loadStats(),
                loadAssets(),
                loadVulns(),
                loadDrp(),
                loadLeaks(),
                loadCti(),
                loadGraph()
            ]);
            populateStrixAssetDropdown();
        }

        function onActiveSeedChange(newSeed) {
            activeSeed = newSeed;
            document.getElementById('current-scope-label').innerText = (activeSeed && activeSeed !== 'ALL') ? activeSeed : 'Todas las semillas';
            document.getElementById('plan-seed-subtitle').innerText = 'Semilla Activa: ' + ((activeSeed && activeSeed !== 'ALL') ? activeSeed : 'Consolidado');
            
            // Update report link
            const reportBtn = document.getElementById('btn-report-link');
            if (activeSeed && activeSeed !== 'ALL') {
                reportBtn.href = `report.php?seed=${encodeURIComponent(activeSeed)}`;
            } else {
                reportBtn.href = `report.php`;
            }

            showToast(`Cambiando perímetro a: ${(activeSeed && activeSeed !== 'ALL') ? activeSeed : 'Todas las semillas'}`);
            refreshAllData();
        }

        function getSeedQueryParam() {
            return (activeSeed && activeSeed !== 'ALL') ? `&seed=${encodeURIComponent(activeSeed)}` : '';
        }

        // Show toast
        function showToast(msg, isError = false) {
            const toast = document.getElementById('toast');
            const toastMsg = document.getElementById('toast-msg');
            const toastIcon = document.getElementById('toast-icon');

            toastMsg.innerText = msg;
            if (isError) {
                toast.className = toast.className.replace('border-cyan-500', 'border-rose-500');
                toastIcon.className = 'fa-solid fa-triangle-exclamation text-rose-400';
            } else {
                toast.className = toast.className.replace('border-rose-500', 'border-cyan-500');
                toastIcon.className = 'fa-solid fa-circle-check text-cyan-400';
            }

            toast.classList.remove('opacity-0', 'pointer-events-none', 'translate-y-4');
            setTimeout(() => {
                toast.classList.add('opacity-0', 'pointer-events-none', 'translate-y-4');
            }, 4000);
        }

        // Tab Switching
        function switchTab(tabId) {
            document.querySelectorAll('.tab-btn').forEach(btn => {
                btn.className = 'tab-btn px-4 py-2.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800/50 flex items-center gap-2 transition';
            });
            const activeBtn = document.getElementById(`tab-btn-${tabId}`);
            if (activeBtn) {
                activeBtn.className = 'tab-btn px-4 py-2.5 rounded-xl bg-slate-800 text-cyan-400 border border-cyan-800/50 flex items-center gap-2 transition';
            }

            ['easm', 'graph', 'vulns', 'drp', 'leaks', 'cti', 'seeds', 'strix'].forEach(t => {
                const el = document.getElementById(`tab-content-${t}`);
                if (el) el.classList.toggle('hidden', t !== tabId);
            });

            if (tabId === 'graph' && networkInstance) {
                setTimeout(() => { networkInstance.fit(); }, 100);
            }

            if (tabId === 'strix') {
                populateStrixAssetDropdown();
            }
        }

        // Plan Modal
        function openPlanModal() {
            document.getElementById('plan-modal').classList.remove('hidden');
        }
        function closePlanModal() {
            document.getElementById('plan-modal').classList.add('hidden');
        }

        // Load Stats
        async function loadStats() {
            try {
                const res = await fetch(`${API_URL}?action=get_stats${getSeedQueryParam()}`);
                const data = await res.json();

                const postureBadge = document.getElementById('posture-badge');
                const circle = document.getElementById('score-circle');

                if (data.is_unscanned || data.exposure_score === null) {
                    document.getElementById('score-val').innerText = '--';
                    circle.style.stroke = '#6366f1';
                    circle.style.strokeDashoffset = 150;
                    postureBadge.className = 'inline-block px-2.5 py-1 text-xs font-bold rounded-lg bg-indigo-950 text-indigo-400 border border-indigo-800/50 mb-1';
                    postureBadge.innerText = 'Pendiente de Escaneo';
                } else {
                    const score = data.exposure_score;
                    document.getElementById('score-val').innerText = score;
                    const offset = 301 - (301 * score / 100);
                    circle.style.strokeDashoffset = offset;

                    if (score >= 80) {
                        circle.style.stroke = '#10b981';
                        postureBadge.className = 'inline-block px-2.5 py-1 text-xs font-bold rounded-lg bg-emerald-950 text-emerald-400 border border-emerald-800/50 mb-1';
                        postureBadge.innerText = 'Excelente (Baja Exposición)';
                    } else if (score >= 50) {
                        circle.style.stroke = '#f59e0b';
                        postureBadge.className = 'inline-block px-2.5 py-1 text-xs font-bold rounded-lg bg-amber-950 text-amber-400 border border-amber-800/50 mb-1';
                        postureBadge.innerText = 'Riesgo Moderado';
                    } else {
                        circle.style.stroke = '#f43f5e';
                        postureBadge.className = 'inline-block px-2.5 py-1 text-xs font-bold rounded-lg bg-rose-950 text-rose-400 border border-rose-800/50 mb-1';
                        postureBadge.innerText = 'Alerta Crítica';
                    }
                }

                document.getElementById('stat-assets').innerText = data.total_assets || 0;
                document.getElementById('stat-live').innerText = `${data.live_assets || 0} activos vivos`;
                document.getElementById('stat-ports').innerText = data.open_ports || 0;
                document.getElementById('stat-vulns').innerText = data.vulnerabilities.total || 0;
                document.getElementById('stat-crit-vulns').innerText = `${data.vulnerabilities.critical + data.vulnerabilities.high} críticas / altas`;
                
                document.getElementById('stat-cti').innerText = (data.ransomware_total || 0) + (data.threat_iocs || 0);
                document.getElementById('stat-cti-info').innerText = `${data.ransomware_total || 0} fugas / ${data.threat_iocs || 0} C2s`;

                const ransomBadge = document.getElementById('ransom-alert-badge');
                if (data.ransomware_matched > 0) {
                    ransomBadge.className = 'px-3 py-1.5 rounded-xl bg-rose-950 text-rose-400 border border-rose-800/80 text-xs font-bold flex items-center gap-2 animate-bounce';
                    ransomBadge.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> ALERTA: ${data.ransomware_matched} Menciones en Ransomware!`;
                } else {
                    ransomBadge.className = 'px-3 py-1.5 rounded-xl bg-emerald-950 text-emerald-400 border border-emerald-800/60 text-xs font-bold flex items-center gap-2';
                    ransomBadge.innerHTML = `<i class="fa-solid fa-shield-check"></i> Tu empresa no figura como víctima`;
                }

            } catch (err) {
                console.error(err);
            }
        }

        // Load Vis.js Topology Graph
        async function loadGraph() {
            const loading = document.getElementById('graph-loading');
            loading.classList.remove('hidden');

            try {
                const res = await fetch(`${API_URL}?action=get_graph_data${getSeedQueryParam()}`);
                const graphData = await res.json();

                const container = document.getElementById('network-canvas');
                const data = {
                    nodes: new vis.DataSet(graphData.nodes),
                    edges: new vis.DataSet(graphData.edges)
                };

                const options = {
                    physics: {
                        stabilization: { iterations: 100 },
                        barnesHut: {
                            gravitationalConstant: -3500,
                            centralGravity: 0.35,
                            springLength: 95,
                            springConstant: 0.04
                        }
                    },
                    interaction: {
                        hover: true,
                        tooltipDelay: 100,
                        zoomView: true
                    }
                };

                if (networkInstance) {
                    networkInstance.destroy();
                }
                networkInstance = new vis.Network(container, data, options);

                networkInstance.on("stabilizationIterationsDone", function () {
                    loading.classList.add('hidden');
                });

            } catch (err) {
                console.error("Error al cargar grafo de ataque:", err);
                loading.classList.add('hidden');
            }
        }

        // Load Assets
        async function loadAssets() {
            try {
                const res = await fetch(`${API_URL}?action=get_assets${getSeedQueryParam()}`);
                globalAssets = await res.json();
                renderAssetsTable();
            } catch (err) {
                console.error(err);
            }
        }

        function renderAssetsTable() {
            const query = (document.getElementById('asset-search').value || '').toLowerCase();
            const tbody = document.getElementById('assets-table-body');
            
            const filtered = globalAssets.filter(a => 
                a.subdomain.toLowerCase().includes(query) || 
                (a.ip_address && a.ip_address.includes(query)) ||
                (a.cloud_provider && a.cloud_provider.toLowerCase().includes(query))
            );

            if (filtered.length === 0) {
                tbody.innerHTML = `<tr><td colspan="7" class="p-8 text-center text-slate-500">No se encontraron activos perimetrales para la semilla seleccionada. Ejecuta un escaneo para descubrirlos.</td></tr>`;
                return;
            }

            tbody.innerHTML = filtered.map(a => {
                const portsArray = a.ports ? a.ports.split(',') : [];
                const portsBadges = portsArray.length > 0 ? 
                    portsArray.map(p => {
                        const isDangerous = [3306, 5432, 6379, 27017, 3389, 21].includes(parseInt(p));
                        const cls = isDangerous ? 'bg-rose-950 text-rose-300 border-rose-800' : 'bg-slate-800 text-cyan-300 border-slate-700';
                        return `<span class="px-1.5 py-0.5 rounded text-[10px] font-mono border ${cls}">${p}</span>`;
                    }).join(' ') : '<span class="text-slate-500 text-[11px]">-</span>';

                const cloudBadge = a.cloud_provider ? 
                    `<span class="px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700 text-[10px]"><i class="fa-solid fa-cloud text-cyan-400 mr-1"></i>${a.cloud_provider}</span>` : 
                    `<span class="text-slate-500 text-[11px]">Directo</span>`;

                const sourceBadge = a.discovery_source ?
                    `<span class="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-cyan-950 text-cyan-300 border border-cyan-800"><i class="fa-solid fa-radar mr-1"></i>${a.discovery_source}</span>` :
                    `<span class="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-900 text-slate-400 border border-slate-800">DNS Pasivo</span>`;

                return `
                    <tr class="hover:bg-slate-800/40 transition">
                        <td class="p-4 font-mono font-medium text-white flex items-center gap-2">
                            <i class="fa-solid fa-globe text-cyan-500/70"></i>
                            <a href="https://${a.subdomain}" target="_blank" class="hover:text-cyan-400 underline decoration-cyan-500/30">${a.subdomain}</a>
                        </td>
                        <td class="p-4 font-mono text-slate-400">${a.ip_address || '<span class="text-slate-600">No resuelve</span>'}</td>
                        <td class="p-4">${cloudBadge}</td>
                        <td class="p-4">${sourceBadge}</td>
                        <td class="p-4 flex flex-wrap gap-1 max-w-xs">${portsBadges}</td>
                        <td class="p-4 text-center">
                            ${a.is_live ? 
                                '<span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-800/60"><span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>ONLINE</span>' : 
                                '<span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-bold bg-slate-900 text-slate-500 border border-slate-800">OFFLINE</span>'}
                        </td>
                        <td class="p-4 text-center">
                            <button onclick="promoteToSeed('${a.subdomain}')" class="px-2.5 py-1 rounded-lg bg-blue-950 hover:bg-blue-900 text-blue-300 border border-blue-800 text-[11px] font-semibold transition flex items-center gap-1 mx-auto" title="Añadir a semillas para vigilancia perimetral independiente">
                                <i class="fa-solid fa-plus-circle text-blue-400"></i>
                                <span>Añadir a Semillas</span>
                            </button>
                        </td>
                    </tr>
                `;
            }).join('');
        }

        async function promoteToSeed(subdomain) {
            try {
                showToast(`Promoviendo ${subdomain} a semilla de vigilancia...`);
                const formData = new FormData();
                formData.append('subdomain', subdomain);
                const res = await fetch(`${API_URL}?action=promote_to_seed`, { method: 'POST', body: formData });
                const data = await res.json();
                if (data.success) {
                    showToast(`¡Activo ${subdomain} añadido exitosamente a las semillas!`);
                    await loadSeeds();
                } else {
                    showToast('Error: ' + (data.error || 'No se pudo promover'), true);
                }
            } catch (err) {
                showToast('Fallo al conectar con la API', true);
            }
        }

        // Global Vulnerabilities State
        let rawVulnsList = [];
        let currentVulnFilter = 'ALL';

        function updateVulnCounts() {
            const allCount = rawVulnsList.length;
            const highCount = rawVulnsList.filter(v => v.severity === 'HIGH' && v.status !== 'RESOLVED').length;
            const medCount = rawVulnsList.filter(v => v.severity === 'MEDIUM' && v.status !== 'RESOLVED').length;
            const lowCount = rawVulnsList.filter(v => v.severity === 'LOW' && v.status !== 'RESOLVED').length;
            const resCount = rawVulnsList.filter(v => v.status === 'RESOLVED').length;

            const setElem = (id, val) => { const el = document.getElementById(id); if (el) el.innerText = val; };
            setElem('count-vuln-all', allCount);
            setElem('count-vuln-high', highCount);
            setElem('count-vuln-med', medCount);
            setElem('count-vuln-low', lowCount);
            setElem('count-vuln-res', resCount);
        }

        function filterVulnsBySeverity(sev) {
            currentVulnFilter = sev;
            const buttons = ['ALL', 'HIGH', 'MEDIUM', 'LOW', 'RESOLVED'];
            buttons.forEach(b => {
                const el = document.getElementById(`vuln-filter-${b}`);
                if (el) {
                    if (b === sev) {
                        el.className = 'px-3 py-1 rounded-lg text-xs font-bold bg-cyan-950 text-cyan-300 border border-cyan-800 transition';
                    } else {
                        el.className = 'px-3 py-1 rounded-lg text-xs font-semibold text-slate-400 hover:text-white border border-transparent hover:border-cyber-border transition';
                    }
                }
            });
            applyVulnFilters();
        }

        function applyVulnFilters() {
            const searchInput = document.getElementById('vuln-search-input');
            const q = searchInput ? searchInput.value.toLowerCase().trim() : '';

            let filtered = rawVulnsList.filter(v => {
                // Severity / Status filter
                if (currentVulnFilter === 'RESOLVED') {
                    if (v.status !== 'RESOLVED') return false;
                } else if (currentVulnFilter !== 'ALL') {
                    if (v.severity !== currentVulnFilter || v.status === 'RESOLVED') return false;
                }

                // Search query
                if (q) {
                    const matchText = (v.title + ' ' + v.description + ' ' + v.asset_subdomain + ' ' + (v.remediation || '')).toLowerCase();
                    if (!matchText.includes(q)) return false;
                }
                return true;
            });

            renderVulnsList(filtered);
        }

        function getVulnStandardTags(v) {
            const title = (v.title || '').toLowerCase();
            const tags = [];
            if (title.includes('certificado') || title.includes('expirado')) {
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-rose-400 border border-slate-700">CWE-298</span>');
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-amber-400 border border-slate-700">OWASP A02:2021 Criptografía</span>');
            } else if (title.includes('cookie') || title.includes('samesite') || title.includes('httponly')) {
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-cyan-400 border border-slate-700">CWE-614 / CWE-1275</span>');
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-amber-400 border border-slate-700">OWASP A05:2021 Gestión de Sesión</span>');
            } else if (title.includes('formulario de autenticación')) {
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-rose-400 border border-slate-700">CWE-523 / CWE-319</span>');
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-amber-400 border border-slate-700">PCI-DSS 4.1 / Plaintext Auth</span>');
            } else if (title.includes('swagger') || title.includes('openapi')) {
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-rose-400 border border-slate-700">CWE-200 / CWE-651</span>');
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-cyan-400 border border-slate-700">OWASP API9:2023 Gestión de Inventario</span>');
            } else if (title.includes('diagnóstico') || title.includes('estado del servidor')) {
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-amber-400 border border-slate-700">CWE-200 / CWE-918</span>');
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-rose-400 border border-slate-700">OWASP A05:2021 Server Status</span>');
            } else if (title.includes('portal de gestión') || title.includes('portal admin')) {
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-amber-400 border border-slate-700">CWE-284</span>');
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-rose-400 border border-slate-700">OWASP A01:2021 Broken Access Control</span>');
            } else if (title.includes('cifrada') || title.includes('tls') || title.includes('http en claro')) {
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-cyan-400 border border-slate-700">CWE-319</span>');
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-amber-400 border border-slate-700">OWASP A02:2021 Criptografía</span>');
            } else if (title.includes('hsts') || title.includes('strict-transport')) {
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-cyan-400 border border-slate-700">RFC 6797</span>');
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-orange-400 border border-slate-700">MITRE T1557.001</span>');
            } else if (title.includes('clickjacking') || title.includes('x-frame-options')) {
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-cyan-400 border border-slate-700">CWE-1021</span>');
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-amber-400 border border-slate-700">OWASP A04:2021 UI Redressing</span>');
            } else if (title.includes('content-security-policy') || title.includes('csp')) {
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-cyan-400 border border-slate-700">CWE-79</span>');
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-rose-400 border border-slate-700">OWASP A03:2021 XSS/Inyección</span>');
            } else if (title.includes('anti-mime') || title.includes('content-type')) {
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-cyan-400 border border-slate-700">CWE-430</span>');
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-blue-400 border border-slate-700">OWASP A05:2021 Hardening</span>');
            } else if (title.includes('cabecera server') || title.includes('fuga de información')) {
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-cyan-400 border border-slate-700">CWE-200</span>');
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-amber-400 border border-slate-700">OWASP A05:2021 Banner Disclosure</span>');
            } else if (title.includes('obsoleto') || title.includes('descontinuado') || title.includes('x-powered-by')) {
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-rose-400 border border-slate-700">CWE-937 / EOL</span>');
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-rose-400 border border-slate-700">OWASP A06:2021 Componentes Vulnerables</span>');
            } else if (title.includes('archivo crítico') || title.includes('.env') || title.includes('.git')) {
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-rose-400 border border-slate-700">CWE-552</span>');
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-rose-400 border border-slate-700">OWASP A01:2021 Control de Acceso</span>');
            } else if (title.includes('spf')) {
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-rose-400 border border-slate-700">RFC 7208 / CWE-290</span>');
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-amber-400 border border-slate-700">Email Spoofing Defense</span>');
            } else if (title.includes('dmarc')) {
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-rose-400 border border-slate-700">RFC 7489 / CWE-290</span>');
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-rose-400 border border-slate-700">Anti-Phishing / Brand Protection</span>');
            } else if (title.includes('dnssec')) {
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-blue-400 border border-slate-700">RFC 4033 / CWE-345</span>');
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-cyan-400 border border-slate-700">DNS Integrity</span>');
            } else if (title.includes('huérfana') || title.includes('dangling') || title.includes('secuestro de dominio')) {
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-rose-400 border border-slate-700">CWE-284 / Zone Takeover</span>');
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-orange-400 border border-slate-700">OWASP A01:2021 Broken Access Control</span>');
            } else if (title.includes('cors')) {
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-rose-400 border border-slate-700">CWE-942</span>');
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-amber-400 border border-slate-700">OWASP A01:2021 Cross-Origin</span>');
            } else if (title.includes('indexación') || title.includes('directory listing')) {
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-cyan-400 border border-slate-700">CWE-548</span>');
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-amber-400 border border-slate-700">OWASP A05:2021 Information Exposure</span>');
            } else if (title.includes('backup') || title.includes('respaldo') || title.includes('dump') || title.includes('phpinfo')) {
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-rose-400 border border-slate-700">CWE-538 / CWE-200</span>');
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-rose-400 border border-slate-700">OWASP A05:2021 Sensitive Data</span>');
            } else if (title.includes('cross-domain') || title.includes('crossdomain')) {
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-cyan-400 border border-slate-700">CWE-942</span>');
            } else if (title.includes('caa') || title.includes('autorización de emisión')) {
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-amber-400 border border-slate-700">RFC 6844 / CWE-295</span>');
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-cyan-400 border border-slate-700">Cert Authority Authorization</span>');
            } else if (title.includes('mta-sts')) {
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-blue-400 border border-slate-700">RFC 8461 / CWE-319</span>');
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-amber-400 border border-slate-700">SMTP Strict TLS</span>');
            } else if (title.includes('security.txt')) {
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-emerald-400 border border-slate-700">RFC 9116 / CWE-1059</span>');
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-cyan-400 border border-slate-700">Responsible Disclosure</span>');
            } else if (title.includes('referrer-policy')) {
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-cyan-400 border border-slate-700">CWE-116</span>');
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-amber-400 border border-slate-700">OWASP A05:2021 Privacy</span>');
            } else if (title.includes('permissions-policy')) {
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-blue-400 border border-slate-700">CWE-693</span>');
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-cyan-400 border border-slate-700">Browser Permissions</span>');
            } else if (title.includes('caché inseguro') || title.includes('cache-control')) {
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-amber-400 border border-slate-700">CWE-524</span>');
                tags.push('<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-rose-400 border border-slate-700">OWASP A05:2021 Sensitive Cache</span>');
            }
            return tags.join(' ');
        }

        function renderVulnsList(vulns) {
            const container = document.getElementById('vulns-container');
            if (!container) return;

            if (vulns.length === 0) {
                container.innerHTML = `
                    <div class="bg-cyber-card border border-cyber-border rounded-2xl p-8 text-center text-slate-400">
                        <i class="fa-solid fa-shield-heart text-3xl text-emerald-400 mb-2 block"></i>
                        <p class="font-bold text-white text-base">Sin hallazgos para este filtro</p>
                        <p class="text-xs text-slate-500 mt-1">No se encontraron vulnerabilidades que coincidan con el criterio seleccionado.</p>
                    </div>
                `;
                return;
            }

            container.innerHTML = vulns.map(v => {
                let badgeColor = 'bg-rose-950 text-rose-400 border-rose-800';
                if (v.severity === 'HIGH') badgeColor = 'bg-orange-950 text-orange-400 border-orange-800';
                if (v.severity === 'MEDIUM') badgeColor = 'bg-amber-950 text-amber-400 border-amber-800';
                if (v.severity === 'LOW') badgeColor = 'bg-blue-950 text-blue-400 border-blue-800';
                if (v.severity === 'INFO') badgeColor = 'bg-slate-800 text-slate-300 border-slate-600';

                const currentStatus = v.status || 'OPEN';
                const isResolved = currentStatus === 'RESOLVED';
                const isInProgress = currentStatus === 'IN_PROGRESS';
                const standardTags = getVulnStandardTags(v);

                return `
                    <div class="bg-cyber-card border ${isResolved ? 'border-emerald-800/50 bg-emerald-950/10' : 'border-cyber-border'} rounded-2xl p-5 hover:border-slate-700 transition space-y-3">
                        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                            <div class="flex flex-wrap items-center gap-2">
                                <span class="px-2 py-0.5 rounded text-[10px] font-bold border uppercase tracking-wider ${badgeColor}">${v.severity}</span>
                                <h4 class="font-bold ${isResolved ? 'text-slate-400 line-through' : 'text-white'} text-sm">${v.title}</h4>
                            </div>

                            <div class="flex items-center gap-2">
                                <span class="text-[11px] text-slate-400 font-medium">Estado:</span>
                                <select onchange="handleStatusChange(${v.id}, this.value)" class="px-3 py-1.5 rounded-lg text-xs font-semibold border ${isResolved ? 'bg-emerald-950 text-emerald-300 border-emerald-800' : (isInProgress ? 'bg-amber-950 text-amber-300 border-amber-800' : 'bg-slate-900 text-rose-300 border-rose-800')} focus:outline-none">
                                    <option value="OPEN" ${currentStatus === 'OPEN' ? 'selected' : ''}>🔴 Abierto</option>
                                    <option value="IN_PROGRESS" ${currentStatus === 'IN_PROGRESS' ? 'selected' : ''}>🟡 En Remediación</option>
                                    <option value="RESOLVED" ${currentStatus === 'RESOLVED' ? 'selected' : ''}>🟢 Mitigado / Resuelto</option>
                                    <option value="FALSE_POSITIVE" ${currentStatus === 'FALSE_POSITIVE' ? 'selected' : ''}>⚪ Falso Positivo</option>
                                </select>
                            </div>
                        </div>

                        ${standardTags ? `<div class="flex flex-wrap items-center gap-1.5">${standardTags}</div>` : ''}

                        <p class="text-xs text-slate-300 leading-relaxed">${v.description}</p>
                        
                        <div class="p-3 bg-slate-900/80 rounded-xl border border-cyber-border text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                            <div>
                                <div class="flex items-center gap-1.5 text-emerald-400 font-bold mb-0.5">
                                    <i class="fa-solid fa-wrench"></i> Remediación Sugerida:
                                </div>
                                <p class="text-slate-400 text-[11px]">${v.remediation}</p>
                            </div>
                            <span class="font-mono text-xs text-cyan-400 bg-slate-950 px-2 py-1 rounded border border-cyber-border whitespace-nowrap">
                                <i class="fa-solid fa-globe mr-1 text-slate-500"></i>${v.asset_subdomain}
                            </span>
                        </div>

                        <div class="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-800/80">
                            <div class="flex items-center gap-2">
                                <button onclick="openVulnPlaybookModal(${v.id})" class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-indigo-950/80 hover:bg-indigo-900 text-indigo-300 border border-indigo-700/60 transition shadow-sm">
                                    <i class="fa-solid fa-code"></i> Playbook & Guía de Hardening
                                </button>
                                <button onclick="launchStrixForUrl('${v.asset_subdomain ? (v.asset_subdomain.startsWith('http') ? v.asset_subdomain : 'https://' + v.asset_subdomain) : ''}', '${(v.title || '').replace(/'/g, "\\'")}')" class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-950/80 hover:bg-emerald-900 text-emerald-300 border border-emerald-700/60 transition shadow-sm" title="Ejecutar validación de evidencia y Raw HTTP en la Navaja Suiza Strix">
                                    <i class="fa-solid fa-wand-magic-sparkles text-emerald-400"></i> Validar con Strix
                                </button>
                            </div>
                            <span class="text-[11px] text-slate-500 font-mono">
                                Detectado: ${(v.created_at || '').slice(0, 16)}
                            </span>
                        </div>
                    </div>
                `;
            }).join('');
        }

        // ==========================================
        // VULNERABILITY PLAYBOOK & HARDENING MODAL
        // ==========================================
        let currentVpVuln = null;
        let currentVpStack = 'nginx';

        function openVulnPlaybookModal(vulnId) {
            const v = (rawVulnsList || []).find(item => item.id == vulnId);
            if (!v) {
                showToast('No se encontró el hallazgo solicitado', true);
                return;
            }
            currentVpVuln = v;

            // Fill basic info
            const sevEl = document.getElementById('vp-severity');
            sevEl.innerText = v.severity || 'INFO';
            sevEl.className = 'px-2 py-0.5 rounded text-[10px] font-bold border uppercase tracking-wider ' + 
                (v.severity === 'HIGH' ? 'bg-orange-950 text-orange-400 border-orange-800' : 
                (v.severity === 'MEDIUM' ? 'bg-amber-950 text-amber-400 border-amber-800' : 'bg-blue-950 text-blue-400 border-blue-800'));

            document.getElementById('vp-title').innerText = v.title || 'Hallazgo de Seguridad';
            document.getElementById('vp-asset').innerText = v.asset_subdomain || 'host';
            document.getElementById('vp-desc').innerText = v.description || 'Sin descripción';
            document.getElementById('vp-remediation').innerText = v.remediation || 'Aplicar buenas prácticas OWASP.';
            document.getElementById('vp-status-select').value = v.status || 'OPEN';

            // Extract CWE tag
            const titleLower = (v.title || '').toLowerCase();
            let cweText = 'CWE-200';
            if (titleLower.includes('certificado') || titleLower.includes('expirado')) cweText = 'CWE-298 (Certificado Expirado)';
            else if (titleLower.includes('cookie') || titleLower.includes('samesite')) cweText = 'CWE-614 / CWE-1275 (Cookies)';
            else if (titleLower.includes('formulario de autenticación')) cweText = 'CWE-523 / CWE-319 (Cleartext Auth)';
            else if (titleLower.includes('swagger') || titleLower.includes('openapi')) cweText = 'CWE-200 / CWE-651 (API Docs)';
            else if (titleLower.includes('diagnóstico') || titleLower.includes('estado del servidor')) cweText = 'CWE-200 / CWE-918 (Diagnostic)';
            else if (titleLower.includes('portal de gestión')) cweText = 'CWE-284 (Admin Exposure)';
            else if (titleLower.includes('spf')) cweText = 'RFC 7208 / CWE-290 (SPF Spoofing)';
            else if (titleLower.includes('dmarc')) cweText = 'RFC 7489 / CWE-290 (DMARC Policy)';
            else if (titleLower.includes('dnssec')) cweText = 'RFC 4033 / CWE-345 (DNSSEC)';
            else if (titleLower.includes('huérfana') || titleLower.includes('dangling')) cweText = 'CWE-284 (Dangling NS / Zone Takeover)';
            else if (titleLower.includes('cors')) cweText = 'CWE-942 (CORS Misconfiguration)';
            else if (titleLower.includes('caa') || titleLower.includes('autorización de emisión')) cweText = 'RFC 6844 / CWE-295 (CAA)';
            else if (titleLower.includes('mta-sts')) cweText = 'RFC 8461 / CWE-319 (MTA-STS)';
            else if (titleLower.includes('security.txt')) cweText = 'RFC 9116 / CWE-1059 (security.txt)';
            else if (titleLower.includes('referrer-policy')) cweText = 'CWE-116 (Referrer-Policy)';
            else if (titleLower.includes('permissions-policy')) cweText = 'CWE-693 (Permissions-Policy)';
            else if (titleLower.includes('caché inseguro') || titleLower.includes('cache-control')) cweText = 'CWE-524 (Insecure Cache)';
            else if (titleLower.includes('indexación') || titleLower.includes('directory listing')) cweText = 'CWE-548 (Directory Listing)';
            else if (titleLower.includes('backup') || titleLower.includes('dump') || titleLower.includes('.env') || titleLower.includes('.git')) cweText = 'CWE-538 / CWE-552 (Data Exposure)';
            else if (titleLower.includes('cabecera') || titleLower.includes('hsts')) cweText = 'CWE-1021 / CWE-693 (OWASP Headers)';
            document.getElementById('vp-cwe').innerText = cweText;

            // Generate Executive Non-Technical Explanation
            let execExplanation = '';
            if (titleLower.includes('certificado') || titleLower.includes('expirado')) {
                execExplanation = '<strong>¿Qué es en la vida real?</strong> Es como un pasaporte de seguridad vencido. Los navegadores muestran una pantalla roja de advertencia que asusta a los clientes.<br><strong>Impacto de Negocio:</strong> Pérdida inmediata de clientes por desconfianza y riesgo de intercepción de datos confidenciales.';
            } else if (titleLower.includes('spf')) {
                execExplanation = '<strong>¿Qué es en la vida real?</strong> Es como enviar cartas oficiales sin un membrete verificado. Cualquiera puede enviar correos a nombre de la empresa sin ser rechazado.<br><strong>Impacto de Negocio:</strong> Campañas masivas de fraude y suplantación a clientes y proveedores a nombre del dominio corporativo.';
            } else if (titleLower.includes('dmarc')) {
                execExplanation = '<strong>¿Qué es en la vida real?</strong> Es la instrucción a los carteros del mundo: <em>"Si alguien envía un correo que no esté en mi lista oficial, destrúyalo de inmediato"</em>.<br><strong>Impacto de Negocio:</strong> Estafas de transferencia bancaria, fraude del CEO (BEC) y secuestro de la reputación corporativa.';
            } else if (titleLower.includes('caa') || titleLower.includes('autorización de emisión')) {
                execExplanation = '<strong>¿Qué es en la vida real?</strong> Es una lista exclusiva de cerrajeros autorizados. Sin este registro, cualquier empresa certificadora del mundo puede emitir un candado para tu dominio.<br><strong>Impacto de Negocio:</strong> Creación de sitios web clonados con candado de seguridad aparentemente "legítimo".';
            } else if (titleLower.includes('huérfana') || titleLower.includes('dangling')) {
                execExplanation = '<strong>¿Qué es en la vida real?</strong> Un local comercial registrado pero abandonado y con la puerta abierta en el proveedor de nube.<br><strong>Impacto de Negocio:</strong> Un atacante puede reclamar el dominio en AWS Route 53 y tomar control de todo el tráfico de la empresa.';
            } else if (titleLower.includes('swagger') || titleLower.includes('openapi')) {
                execExplanation = '<strong>¿Qué es en la vida real?</strong> Dejar el manual técnico con los planos de todas las cajas fuertes pegado en la puerta de entrada.<br><strong>Impacto de Negocio:</strong> Los atacantes conocen todas las APIs internas, endpoints administrativos y credenciales de prueba de los desarrolladores.';
            } else if (titleLower.includes('formulario de autenticación') || titleLower.includes('en claro')) {
                execExplanation = '<strong>¿Qué es en la vida real?</strong> Escribir el usuario y la clave en una hoja abierta en vez de guardarla en un sobre lacrado.<br><strong>Impacto de Negocio:</strong> Robo de claves en cafeterías o redes compartidas mediante programas espía de red (Sniffing).';
            } else if (titleLower.includes('cookie') || titleLower.includes('samesite')) {
                execExplanation = '<strong>¿Qué es en la vida real?</strong> Llaves de acceso temporales del usuario emitidas sin precinto de seguridad.<br><strong>Impacto de Negocio:</strong> Secuestro de cuentas de usuarios activos mientras navegan en otras páginas web.';
            } else if (titleLower.includes('referrer-policy')) {
                execExplanation = '<strong>¿Qué es en la vida real?</strong> El navegador le cuenta a páginas externas de qué dirección privada y confidencial venía navegando el cliente.<br><strong>Impacto de Negocio:</strong> Fuga involuntaria de identificadores de sesión o datos personales en enlaces salientes.';
            } else if (titleLower.includes('permissions-policy')) {
                execExplanation = '<strong>¿Qué es en la vida real?</strong> No prohibir expresamente el encendido de cámara, micrófono o GPS a scripts publicitarios o externos.<br><strong>Impacto de Negocio:</strong> Espionaje no autorizado de dispositivos de los usuarios que visitan el portal.';
            } else if (titleLower.includes('caché inseguro') || titleLower.includes('cache-control')) {
                execExplanation = '<strong>¿Qué es en la vida real?</strong> Computadores compartidos o proxys guardan copias de las páginas donde se escribieron usuarios y contraseñas.<br><strong>Impacto de Negocio:</strong> La siguiente persona que use el computador puede pulsar "Atrás" y ver datos confidenciales del usuario previo.';
            } else if (titleLower.includes('security.txt')) {
                execExplanation = '<strong>¿Qué es en la vida real?</strong> El buzón de sugerencias éticas de seguridad de la empresa.<br><strong>Impacto de Negocio:</strong> Si un investigador descubre una vulnerabilidad, no sabe a quién avisar y la falla puede filtrarse en redes sociales o ser vendida en foros oscuros.';
            } else if (titleLower.includes('cors')) {
                execExplanation = '<strong>¿Qué es en la vida real?</strong> Permitir que páginas web de terceros consulten libremente la información interna de tu aplicación.<br><strong>Impacto de Negocio:</strong> Sitios web maliciosos pueden extraer información de cuentas autenticadas de los clientes.';
            } else if (titleLower.includes('indexación') || titleLower.includes('directory listing')) {
                execExplanation = '<strong>¿Qué es en la vida real?</strong> Dejar carpetas de archivos del servidor abiertas para que cualquiera pueda navegar y descargar su contenido.<br><strong>Impacto de Negocio:</strong> Descarga de códigos fuente, copias de seguridad o documentos de configuración confidenciales.';
            } else {
                execExplanation = '<strong>¿Qué es en la vida real?</strong> Falta de directivas de blindaje perimetral estándar recomendadas por marcos internacionales (OWASP / CIS Benchmarks).<br><strong>Impacto de Negocio:</strong> Exposición a ataques automatizados de bots y herramientas de escaneo malicioso.';
            }
            const execEl = document.getElementById('vp-exec-explanation');
            if (execEl) execEl.innerHTML = execExplanation;

            setVpStack(currentVpStack || 'nginx');
            document.getElementById('vuln-playbook-modal').classList.remove('hidden');
        }

        function closeVulnPlaybookModal() {
            document.getElementById('vuln-playbook-modal').classList.add('hidden');
        }

        function setVpStack(stack) {
            currentVpStack = stack;
            const stacks = ['fortiweb', 'nginx', 'apache', 'tomcat', 'iis', 'cloudflare'];
            stacks.forEach(s => {
                const btn = document.getElementById(`vp-tab-${s}`);
                if (btn) {
                    if (s === stack) {
                        if (s === 'fortiweb') {
                            btn.className = 'px-2.5 py-1 rounded text-xs font-semibold bg-red-950 text-white border border-red-600 shadow-sm flex items-center gap-1';
                        } else {
                            btn.className = 'px-2.5 py-1 rounded text-xs font-semibold bg-indigo-900 text-white border border-indigo-600 shadow-sm';
                        }
                    } else {
                        if (s === 'fortiweb') {
                            btn.className = 'px-2.5 py-1 rounded text-xs font-semibold bg-slate-900 text-red-400 hover:text-white border border-cyber-border flex items-center gap-1';
                        } else {
                            btn.className = 'px-2.5 py-1 rounded text-xs font-semibold bg-slate-900 text-slate-400 hover:text-white border border-cyber-border';
                        }
                    }
                }
            });
            updateVpPlaybookContent();
        }

        function updateVpPlaybookContent() {
            if (!currentVpVuln) return;
            const title = (currentVpVuln.title || '').toLowerCase();
            const host = currentVpVuln.asset_subdomain || 'demo.testfire.net';
            let snippet = '';
            let curlCmd = '';

            if (title.includes('certificado') || title.includes('expirado')) {
                curlCmd = `curl -Iv --connect-timeout 5 https://${host}/`;
                if (currentVpStack === 'nginx') {
                    snippet = `# Renovar e instalar certificado SSL/TLS con Let's Encrypt / Certbot\nsudo certbot --nginx -d ${host}\n\n# O actualizar manualmente en /etc/nginx/conf.d/${host}.conf:\nserver {\n    listen 443 ssl http2;\n    server_name ${host};\n\n    ssl_certificate /etc/ssl/certs/${host}_fullchain.pem;\n    ssl_certificate_key /etc/ssl/private/${host}_privkey.pem;\n    ssl_protocols TLSv1.2 TLSv1.3;\n    ssl_ciphers HIGH:!aNULL:!MD5;\n}`;
                } else if (currentVpStack === 'apache') {
                    snippet = `# En /etc/apache2/sites-available/${host}-ssl.conf:\n<VirtualHost *:443>\n    ServerName ${host}\n    SSLEngine on\n    SSLCertificateFile /etc/ssl/certs/${host}.crt\n    SSLCertificateKeyFile /etc/ssl/private/${host}.key\n    SSLCertificateChainFile /etc/ssl/certs/${host}_ca.crt\n    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\n</VirtualHost>`;
                } else if (currentVpStack === 'tomcat') {
                    snippet = `<!-- En conf/server.xml de Apache Tomcat -->\n<Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol"\n           maxThreads="150" SSLEnabled="true">\n    <SSLHostConfig hostName="${host}">\n        <Certificate certificateKeystoreFile="conf/${host}.p12"\n                     certificateKeystorePassword="TU_CONTRASENA"\n                     type="RSA" />\n    </SSLHostConfig>\n</Connector>`;
                } else if (currentVpStack === 'iis') {
                    snippet = `# PowerShell (Administrador) para instalar y vincular certificado SSL en IIS:\n$cert = Import-PfxCertificate -FilePath "C:\\certs\\${host}.pfx" -CertStoreLocation Cert:\\LocalMachine\\My\nNew-WebBinding -Name "Default Web Site" -IP "*" -Port 443 -Protocol https -HostHeader "${host}" -SslFlags 1\nGet-ChildItem Cert:\\LocalMachine\\My\\$($cert.Thumbprint) | New-Item "IIS:\\SslBindings\\0.0.0.0!443!${host}"`;
                } else if (currentVpStack === 'cloudflare') {
                    snippet = `# En Cloudflare Dashboard > SSL/TLS > Overview:\n1. Configurar Modo de Encriptación: "Full (Strict)"\n2. Ir a SSL/TLS > Edge Certificates y activar "Always Use HTTPS"\n3. Activar "Automatic HTTPS Rewrites" y "Minimum TLS Version: TLS 1.2"`;
                }
            } else if (title.includes('swagger') || title.includes('openapi')) {
                curlCmd = `curl -I -s "http://${host}/swagger/index.html" | grep "HTTP/"\n# Debe retornar 403 Forbidden o 404 Not Found`;
                if (currentVpStack === 'nginx') {
                    snippet = `# Bloquear acceso publico a Swagger y documentación OpenAPI en Nginx\nlocation ~* ^/(swagger|api-docs|v2/api-docs|v3/api-docs|openapi\\.json|swagger-resources) {\n    # Permitir solo IP de gestión corporativa / VPN:\n    allow 10.0.0.0/8;\n    allow 192.168.1.0/24;\n    deny all;\n    return 403 "Acceso no autorizado al catálogo de APIs.";\n}`;
                } else if (currentVpStack === 'apache') {
                    snippet = `# En .htaccess o VirtualHost de Apache:\n<LocationMatch "^/(swagger|api-docs|v2/api-docs|v3/api-docs|openapi\\.json)">\n    Require ip 10.0.0.0/8\n    ErrorDocument 403 "Acceso restringido a documentación técnica."\n</LocationMatch>`;
                } else if (currentVpStack === 'tomcat') {
                    snippet = `# En application.properties (Spring Boot) o web.xml:\nspringdoc.swagger-ui.enabled=false\nspringdoc.api-docs.enabled=false\nmanagement.endpoints.web.exposure.exclude=swagger,openapi\n\n# O en web.xml restringir con security-constraint por rol ADMIN:`;
                } else if (currentVpStack === 'iis') {
                    snippet = `<!-- En web.config de IIS / ASP.NET -->\n<system.webServer>\n  <security>\n    <requestFiltering>\n      <denyUrlSequences>\n        <add sequence="/swagger" />\n        <add sequence="/openapi.json" />\n      </denyUrlSequences>\n    </requestFiltering>\n  </security>\n</system.webServer>`;
                } else if (currentVpStack === 'cloudflare') {
                    snippet = `# Regla WAF en Cloudflare (Security > WAF > Custom Rules):\nRegla: (http.request.uri.path contains "/swagger" or http.request.uri.path contains "properties.json") and not (ip.src in {10.0.0.0/8})\nAcción: Block`;
                }
            } else if (title.includes('formulario de autenticación') || title.includes('en claro')) {
                curlCmd = `curl -IL --connect-timeout 5 "http://${host}/login.jsp" | grep -E "HTTP/|Location:"`;
                if (currentVpStack === 'nginx') {
                    snippet = `# Forzar Redirección HTTP -> HTTPS permanente (301) en Nginx:\nserver {\n    listen 80;\n    server_name ${host};\n    return 301 https://$host$request_uri;\n}`;
                } else if (currentVpStack === 'apache') {
                    snippet = `# En .htaccess o VirtualHost *:80 de Apache:\nRewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]`;
                } else if (currentVpStack === 'tomcat') {
                    snippet = `<!-- En WEB-INF/web.xml para obligar transporte CONFIDENTIAL -->\n<security-constraint>\n    <web-resource-collection>\n        <web-resource-name>Protected Area</web-resource-name>\n        <url-pattern>/*</url-pattern>\n    </web-resource-collection>\n    <user-data-constraint>\n        <transport-guarantee>CONFIDENTIAL</transport-guarantee>\n    </user-data-constraint>\n</security-constraint>`;
                } else if (currentVpStack === 'iis') {
                    snippet = `<!-- En web.config de IIS (URL Rewrite) -->\n<system.webServer>\n  <rewrite>\n    <rules>\n      <rule name="Redirect to HTTPS" stopProcessing="true">\n        <match url="(.*)" />\n        <conditions><add input="{HTTPS}" pattern="off" ignoreCase="true" /></conditions>\n        <action type="Redirect" url="https://{HTTP_HOST}/{R:1}" redirectType="Permanent" />\n      </rule>\n    </rules>\n  </rewrite>\n</system.webServer>`;
                } else if (currentVpStack === 'cloudflare') {
                    snippet = `# En Cloudflare Dashboard > SSL/TLS > Edge Certificates:\nActivar interruptor: "Always Use HTTPS" (Habilitado)`;
                }
            } else if (title.includes('cookie') || title.includes('samesite') || title.includes('httponly')) {
                curlCmd = `curl -I -s "http://${host}/" | grep -i "set-cookie"\n# Debe contener: Secure; HttpOnly; SameSite=Lax (o Strict)`;
                if (currentVpStack === 'fortiweb') {
                    snippet = `# Fortinet FortiWeb CLI (Persistencia de Sesión y Cookie Security):\n# 1. Configuración de la cookie nativa de persistencia (cookiesession1):\nconfig server-policy policy\n    edit "NOMBRE_POLICY_VIRTUAL_SERVER"\n        config persistence\n            set persistence-type cookie\n            set cookie-name "cookiesession1"\n            set cookie-secure enable\n            set cookie-httponly enable\n            set cookie-samesite lax\n        end\n    next\nend\n\n# 2. Inyección de SameSite en cookies de la aplicación backend:\nconfig web-protection advanced-protection cookie-security\n    edit "Cookie_Security_Profile"\n        config cookie-rule\n            edit 1\n                set cookie-name "*"\n                set samesite-attribute lax\n                set secure-attribute enable\n                set httponly-attribute enable\n            next\n        end\n    next\nend\n# En GUI: Server Objects > Service > Server Policy > Persistence > SameSite: Lax\n#         Web Protection > Advanced Protection > Cookie Security`;
                } else if (currentVpStack === 'nginx') {
                    snippet = `# Inyectar atributos Secure, HttpOnly y SameSite en Nginx proxy_pass:\nlocation / {\n    proxy_pass http://backend_upstream;\n    proxy_cookie_path / "/; Secure; HttpOnly; SameSite=Lax";\n}`;
                } else if (currentVpStack === 'apache') {
                    snippet = `# En Apache (mod_headers habilitado):\nHeader edit Set-Cookie ^(.*)$ "$1; Secure; HttpOnly; SameSite=Lax"\n\n# O para PHP en php.ini:\nsession.cookie_secure = 1\nsession.cookie_httponly = 1\nsession.cookie_samesite = "Lax"`;
                } else if (currentVpStack === 'tomcat') {
                    snippet = `<!-- En conf/context.xml de Apache Tomcat -->\n<Context useHttpOnly="true">\n    <CookieProcessor sameSiteCookies="lax" secure="true" />\n</Context>`;
                } else if (currentVpStack === 'iis') {
                    snippet = `<!-- En web.config de IIS -->\n<system.web>\n  <httpCookies httpOnlyCookies="true" requireSSL="true" sameSite="Lax" />\n</system.web>`;
                } else if (currentVpStack === 'cloudflare') {
                    snippet = `# En Cloudflare > Rules > Transform Rules > Modify Response Header:\nModificar encabezado 'Set-Cookie' agregando directivas '; Secure; HttpOnly; SameSite=Lax'`;
                }
            } else if (title.includes('diagnóstico') || title.includes('estado del servidor') || title.includes('portal de gestión')) {
                curlCmd = `curl -I -s "http://${host}/status_check.jsp" | grep "HTTP/"\n# Debe retornar 403 Forbidden o 404 Not Found`;
                if (currentVpStack === 'nginx') {
                    snippet = `# Bloquear utilidades de diagnóstico y consolas administrativas en Nginx\nlocation ~* ^/(status_check\\.jsp|util/|admin/|manager/|server-status) {\n    deny all;\n    return 404;\n}`;
                } else if (currentVpStack === 'apache') {
                    snippet = `# En Apache:\n<LocationMatch "^/(status_check\\.jsp|util/|admin/|manager/|server-status)">\n    Require all denied\n</LocationMatch>`;
                } else if (currentVpStack === 'tomcat') {
                    snippet = `# Eliminar utilidades y servlets de prueba de Tomcat:\nsudo rm -rf /opt/tomcat/webapps/examples\nsudo rm -rf /opt/tomcat/webapps/manager\nsudo rm -rf /opt/tomcat/webapps/host-manager\n# En server.xml asegurar RemoteAddrValve en Context`;
                } else if (currentVpStack === 'iis') {
                    snippet = `<!-- En web.config de IIS -->\n<system.webServer>\n  <security>\n    <requestFiltering>\n      <denyUrlSequences>\n        <add sequence="/status_check.jsp" />\n        <add sequence="/admin" />\n      </denyUrlSequences>\n    </requestFiltering>\n  </security>\n</system.webServer>`;
                } else if (currentVpStack === 'cloudflare') {
                    snippet = `# Regla WAF en Cloudflare:\n(http.request.uri.path contains "/status_check.jsp" or http.request.uri.path contains "/admin/") -> Action: Block`;
                }
            } else if (title.includes('spf') || title.includes('dmarc')) {
                curlCmd = `nslookup -type=TXT ${host}\nnslookup -type=TXT _dmarc.${host}`;
                if (currentVpStack === 'nginx' || currentVpStack === 'apache' || currentVpStack === 'tomcat') {
                    snippet = `# Configurar registros de seguridad de correo en la zona DNS corporativa:\n\n# 1. Registro SPF en la raíz (@):\n${host}. IN TXT "v=spf1 -all"\n\n# 2. Registro DMARC en _dmarc.${host}:\n_dmarc.${host}. IN TXT "v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc-reports@${host}; aspf=s;"`;
                } else if (currentVpStack === 'iis') {
                    snippet = `# PowerShell (Administrador) para crear registros SPF y DMARC en Windows DNS Server:\nAdd-DnsServerResourceRecordTxt -ZoneName "${host}" -Name "@" -DescriptiveText "v=spf1 -all"\nAdd-DnsServerResourceRecordTxt -ZoneName "${host}" -Name "_dmarc" -DescriptiveText "v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc-reports@${host};"`;
                } else if (currentVpStack === 'cloudflare') {
                    snippet = `# En Cloudflare Dashboard > DNS > Records:\n1. Añadir Registro Tipo: TXT | Name: @ | Content: "v=spf1 -all" | TTL: Auto\n2. Añadir Registro Tipo: TXT | Name: _dmarc | Content: "v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc@${host}" | TTL: Auto`;
                }
            } else if (title.includes('huérfana') || title.includes('dangling') || title.includes('dnssec')) {
                curlCmd = `nslookup -type=NS ${host}\nnslookup -type=DNSKEY ${host}`;
                snippet = `# Diagnóstico y Hardening de Infraestructura DNS Perimetral:\n# 1. Si el dominio está en desuso: Retirar la delegación NS en el registrador (Verisign/GoDaddy/AWS) para prevenir Zone Takeover.\n# 2. Si el dominio está activo: Crear la zona alojada en el proveedor y publicar registros A de protección.\n# 3. Para DNSSEC: Activar DNSSEC en el panel del registrador y publicar registros DS firmados.`;
            } else if (title.includes('cors')) {
                curlCmd = `curl -I -H "Origin: https://evil-attacker.com" "http://${host}/" | grep -i "access-control-"`;
                if (currentVpStack === 'nginx') {
                    snippet = `# En Nginx (bloquear CORS comodín y restringir a orígenes autorizados):\nif ($http_origin ~* "^https?://(www\\.)?${host.replace('.', '\\.')}$") {\n    add_header Access-Control-Allow-Origin "$http_origin" always;\n    add_header Access-Control-Allow-Credentials "true" always;\n}`;
                } else if (currentVpStack === 'apache') {
                    snippet = `# En Apache .htaccess / VirtualHost:\nHeader always set Access-Control-Allow-Origin "https://${host}"\nHeader always set Access-Control-Allow-Credentials "true"`;
                } else if (currentVpStack === 'tomcat') {
                    snippet = `// En Spring Boot / Controller Java:\n@CrossOrigin(origins = "https://${host}", allowCredentials = "true")\n// O en web.xml configurar CorsFilter con allowedOrigins estricto`;
                } else if (currentVpStack === 'iis') {
                    snippet = `<!-- En web.config de IIS -->\n<system.webServer>\n  <httpProtocol>\n    <customHeaders>\n      <add name="Access-Control-Allow-Origin" value="https://${host}" />\n    </customHeaders>\n  </httpProtocol>\n</system.webServer>`;
                } else if (currentVpStack === 'cloudflare') {
                    snippet = `# En Cloudflare > Rules > Transform Rules > Modify Response Header:\nEliminar cabecera 'Access-Control-Allow-Origin' con valor comodín '*' y fijar el dominio corporativo.`;
                }
            } else if (title.includes('indexación') || title.includes('directory listing')) {
                curlCmd = `curl -I -s "http://${host}/" | grep "HTTP/"`;
                if (currentVpStack === 'nginx') {
                    snippet = `# Deshabilitar exploración de directorios en Nginx:\nautoindex off;`;
                } else if (currentVpStack === 'apache') {
                    snippet = `# Deshabilitar exploración de directorios en Apache (.htaccess / httpd.conf):\nOptions -Indexes`;
                } else if (currentVpStack === 'tomcat') {
                    snippet = `<!-- En conf/web.xml de Tomcat dentro del default servlet -->\n<init-param>\n    <param-name>listings</param-name>\n    <param-value>false</param-value>\n</init-param>`;
                } else if (currentVpStack === 'iis') {
                    snippet = `<!-- En web.config de IIS -->\n<system.webServer>\n  <directoryBrowse enabled="false" />\n</system.webServer>`;
                } else if (currentVpStack === 'cloudflare') {
                    snippet = `# Regla WAF en Cloudflare: Activar protección contra exploración y listado de directorios.`;
                }
            } else if (title.includes('archivo crítico') || title.includes('backup') || title.includes('respaldo') || title.includes('dump') || title.includes('.git') || title.includes('.env')) {
                curlCmd = `curl -I -s "http://${host}/.env" | grep "HTTP/"\n# Debe retornar 403 Forbidden o 404 Not Found`;
                if (currentVpStack === 'nginx') {
                    snippet = `# Bloquear acceso a archivos sensibles y respaldos en Nginx:\nlocation ~* (\\.git|\\.env|\\.sql|\\.zip|\\.bak|\\.sqlite|composer\\.json|web\\.config) {\n    deny all;\n    return 404;\n}`;
                } else if (currentVpStack === 'apache') {
                    snippet = `# En .htaccess de Apache:\n<FilesMatch "(^#.*#|\\.(bak|config|dist|fla|inc|ini|log|psd|sh|sql|sw[op]|env|git)|~)$">\n    Require all denied\n</FilesMatch>`;
                } else if (currentVpStack === 'tomcat') {
                    snippet = `<!-- En web.xml restringir acceso a patrones de archivos -->\n<security-constraint>\n    <web-resource-collection>\n        <web-resource-name>Sensitive Files</web-resource-name>\n        <url-pattern>*.sql</url-pattern>\n        <url-pattern>*.zip</url-pattern>\n        <url-pattern>*.env</url-pattern>\n    </web-resource-collection>\n    <auth-constraint />\n</security-constraint>`;
                } else if (currentVpStack === 'iis') {
                    snippet = `<!-- En web.config de IIS -->\n<system.webServer>\n  <security>\n    <requestFiltering>\n      <fileExtensions>\n        <add fileExtension=".env" allowed="false" />\n        <add fileExtension=".sql" allowed="false" />\n        <add fileExtension=".zip" allowed="false" />\n      </fileExtensions>\n    </requestFiltering>\n  </security>\n</system.webServer>`;
                } else if (currentVpStack === 'cloudflare') {
                    snippet = `# Regla WAF en Cloudflare:\n(http.request.uri.path contains ".env" or http.request.uri.path contains ".git" or http.request.uri.path contains ".sql") -> Action: Block`;
                }
            } else if (title.includes('caa') || title.includes('autorización de emisión')) {
                curlCmd = `nslookup -type=ANY ${host} | grep -i "caa"`;
                if (currentVpStack === 'cloudflare') {
                    snippet = `# En Cloudflare Dashboard > DNS > Records:\n1. Añadir Registro Tipo: CAA | Name: @ | Tag: Only allow specific CAs to issue certs (issue) | Value: "letsencrypt.org"\n2. Añadir Registro Tipo: CAA | Name: @ | Tag: Send violation reports to (iodef) | Value: "mailto:security@${host}"`;
                } else if (currentVpStack === 'iis') {
                    snippet = `# PowerShell para servidor DNS Windows:\nAdd-DnsServerResourceRecord -ZoneName "${host}" -Name "@" -Type 257 -RecordData "0 issue letsencrypt.org"`;
                } else {
                    snippet = `# Configuración de registro CAA en zona DNS (BIND / Route 53 / DNS Server):\n${host}. IN CAA 0 issue "letsencrypt.org"\n${host}. IN CAA 0 issuewild "letsencrypt.org"\n${host}. IN CAA 0 iodef "mailto:security@${host}"`;
                }
            } else if (title.includes('referrer-policy')) {
                curlCmd = `curl -I -s "https://${host}/" | grep -i "referrer-policy"`;
                if (currentVpStack === 'nginx') {
                    snippet = `# En Nginx (http o server block):\nadd_header Referrer-Policy "strict-origin-when-cross-origin" always;`;
                } else if (currentVpStack === 'apache') {
                    snippet = `# En Apache (.htaccess o VirtualHost):\nHeader always set Referrer-Policy "strict-origin-when-cross-origin"`;
                } else if (currentVpStack === 'tomcat') {
                    snippet = `<!-- En conf/web.xml de Tomcat dentro de HttpHeaderSecurityFilter -->\n<filter>\n    <filter-name>httpHeaderSecurity</filter-name>\n    <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>\n    <init-param><param-name>referrerPolicy</param-name><param-value>strict-origin-when-cross-origin</param-value></init-param>\n</filter>`;
                } else if (currentVpStack === 'iis') {
                    snippet = `<!-- En web.config de IIS -->\n<system.webServer>\n  <httpProtocol>\n    <customHeaders>\n      <add name="Referrer-Policy" value="strict-origin-when-cross-origin" />\n    </customHeaders>\n  </httpProtocol>\n</system.webServer>`;
                } else if (currentVpStack === 'cloudflare') {
                    snippet = `# En Cloudflare > Rules > Transform Rules > Add Response Header:\nReferrer-Policy = strict-origin-when-cross-origin`;
                }
            } else if (title.includes('permissions-policy')) {
                curlCmd = `curl -I -s "https://${host}/" | grep -i "permissions-policy"`;
                if (currentVpStack === 'nginx') {
                    snippet = `# En Nginx:\nadd_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;`;
                } else if (currentVpStack === 'apache') {
                    snippet = `# En Apache:\nHeader always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"`;
                } else if (currentVpStack === 'tomcat') {
                    snippet = `<!-- En conf/web.xml o filtro de cabeceras -->\nHeader set Permissions-Policy "camera=(), microphone=(), geolocation=()"`;
                } else if (currentVpStack === 'iis') {
                    snippet = `<!-- En web.config de IIS -->\n<system.webServer>\n  <httpProtocol>\n    <customHeaders>\n      <add name="Permissions-Policy" value="camera=(), microphone=(), geolocation=()" />\n    </customHeaders>\n  </httpProtocol>\n</system.webServer>`;
                } else if (currentVpStack === 'cloudflare') {
                    snippet = `# En Cloudflare > Transform Rules > Add Response Header:\nPermissions-Policy = camera=(), microphone=(), geolocation=()`;
                }
            } else if (title.includes('caché inseguro') || title.includes('cache-control')) {
                curlCmd = `curl -I -s "http://${host}/login.jsp" | grep -i "cache-control"`;
                if (currentVpStack === 'nginx') {
                    snippet = `# En Nginx para rutas de login y datos sensibles:\nlocation ~* (login|auth|session|account) {\n    add_header Cache-Control "no-store, no-cache, must-revalidate, max-age=0" always;\n    add_header Pragma "no-cache" always;\n}`;
                } else if (currentVpStack === 'apache') {
                    snippet = `# En Apache:\n<FilesMatch "(login|auth|session|account)">\n    Header set Cache-Control "no-store, no-cache, must-revalidate, max-age=0"\n    Header set Pragma "no-cache"\n</FilesMatch>`;
                } else if (currentVpStack === 'tomcat') {
                    snippet = `// En Controller Java o Servlet:\nresponse.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");\nresponse.setHeader("Pragma", "no-cache");`;
                } else if (currentVpStack === 'iis') {
                    snippet = `<!-- En web.config de IIS para la página de login -->\n<location path="login.jsp">\n  <system.webServer>\n    <httpProtocol>\n      <customHeaders>\n        <add name="Cache-Control" value="no-store, no-cache, must-revalidate" />\n      </customHeaders>\n    </httpProtocol>\n  </system.webServer>\n</location>`;
                } else if (currentVpStack === 'cloudflare') {
                    snippet = `# En Cloudflare > Caching > Cache Rules:\nURI Path contains "/login" -> Cache Eligibility: Bypass cache`;
                }
            } else if (title.includes('security.txt')) {
                curlCmd = `curl -IL -s "http://${host}/.well-known/security.txt"`;
                snippet = `# Crear el archivo /.well-known/security.txt con el estándar RFC 9116:\nContact: mailto:security@${host}\nExpires: 2027-12-31T23:59:59.000Z\nPreferred-Languages: es, en\nPolicy: https://${host}/security-policy\nCanonical: https://${host}/.well-known/security.txt`;
            } else {
                // Generic security headers (HSTS, CSP, etc.)
                curlCmd = `curl -I -s "https://${host}/" | grep -E -i "(strict-transport|x-frame|x-content|content-security)"`;
                if (currentVpStack === 'fortiweb') {
                    snippet = `# Fortinet FortiWeb CLI (Hardening de Cabeceras Perimetrales y Ocultación):\n# 1. Inyección de Cabeceras de Seguridad:\nconfig web-protection advanced-protection http-header-security\n    edit "FortiWeb_Headers_Profile"\n        set hsts enable\n        set max-age 31536000\n        set include-sub-domains enable\n        set preload enable\n        set x-frame-options enable\n        set frame-options sameorigin\n        set x-content-type-options enable\n        set referrer-policy enable\n        set referrer-policy-option strict-origin-when-cross-origin\n        set content-security-policy enable\n        set csp-directive "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none';"\n    next\nend\n\n# 2. Ocultar firmas de servidor e IIS / ASP.NET (Information Disclosure):\nconfig web-protection info-disclosure hide-info\n    edit "Hide_Server_Banner"\n        set hide-server-header enable\n        set hide-powered-by enable\n    next\nend\n# En GUI: Web Protection > Advanced Protection > HTTP Header Security\n#         Web Protection > Information Disclosure > Hide Information`;
                } else if (currentVpStack === 'nginx') {
                    snippet = `# Hardening de cabeceras de seguridad perimetral en Nginx\nadd_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;\nadd_header X-Frame-Options "SAMEORIGIN" always;\nadd_header X-Content-Type-Options "nosniff" always;\nadd_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none';" always;\nadd_header Referrer-Policy "strict-origin-when-cross-origin" always;`;
                } else if (currentVpStack === 'apache') {
                    snippet = `# Hardening de cabeceras en Apache (mod_headers):\nHeader always set Strict-Transport-Security "max-age=31536000; includeSubDomains"\nHeader always set X-Frame-Options "SAMEORIGIN"\nHeader always set X-Content-Type-Options "nosniff"\nHeader always set Content-Security-Policy "default-src 'self';"\nHeader always set Referrer-Policy "strict-origin-when-cross-origin"`;
                } else if (currentVpStack === 'tomcat') {
                    snippet = `<!-- En conf/web.xml de Apache Tomcat -->\n<filter>\n    <filter-name>httpHeaderSecurity</filter-name>\n    <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>\n    <init-param><param-name>hstsEnabled</param-name><param-value>true</param-value></init-param>\n    <init-param><param-name>antiClickJackingOption</param-name><param-value>SAMEORIGIN</param-value></init-param>\n</filter>\n<filter-mapping>\n    <filter-name>httpHeaderSecurity</filter-name>\n    <url-pattern>/*</url-pattern>\n</filter-mapping>`;
                } else if (currentVpStack === 'iis') {
                    snippet = `<!-- En web.config de IIS -->\n<system.webServer>\n  <httpProtocol>\n    <customHeaders>\n      <add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains" />\n      <add name="X-Frame-Options" value="SAMEORIGIN" />\n      <add name="X-Content-Type-Options" value="nosniff" />\n    </customHeaders>\n  </httpProtocol>\n</system.webServer>`;
                } else if (currentVpStack === 'cloudflare') {
                    snippet = `# En Cloudflare > Rules > Transform Rules > Add Response Headers:\n1. Strict-Transport-Security = max-age=31536000; includeSubDomains\n2. X-Frame-Options = SAMEORIGIN\n3. X-Content-Type-Options = nosniff`;
                }
            }

            document.getElementById('vp-snippet-code').innerText = snippet;
            document.getElementById('vp-curl-code').innerText = curlCmd;
        }

        function copyVpSnippet() {
            const code = document.getElementById('vp-snippet-code').innerText;
            navigator.clipboard.writeText(code).then(() => {
                showToast('Snippet de configuración copiado al portapapeles');
            });
        }

        function copyVpCurl() {
            const code = document.getElementById('vp-curl-code').innerText;
            navigator.clipboard.writeText(code).then(() => {
                showToast('Comando de verificación curl copiado');
            });
        }

        async function onVpStatusChange(newStatus) {
            if (!currentVpVuln) return;
            await handleStatusChange(currentVpVuln.id, newStatus);
            currentVpVuln.status = newStatus;
        }

        async function loadVulns() {
            try {
                const res = await fetch(`${API_URL}?action=get_vulnerabilities${getSeedQueryParam()}`);
                rawVulnsList = await res.json();
                updateVulnCounts();
                applyVulnFilters();
            } catch (err) {
                console.error(err);
            }
        }

        function exportVulnsCsv() {
            if (!rawVulnsList || rawVulnsList.length === 0) {
                showToast('No hay hallazgos disponibles para exportar', true);
                return;
            }
            const headers = ['ID', 'Activo Subdominio', 'Severidad', 'Titulo', 'Estado', 'Descripcion', 'Remediacion', 'Fecha'];
            const rows = rawVulnsList.map(v => [
                v.id,
                `"${(v.asset_subdomain || '').replace(/"/g, '""')}"`,
                `"${v.severity || ''}"`,
                `"${(v.title || '').replace(/"/g, '""')}"`,
                `"${v.status || 'OPEN'}"`,
                `"${(v.description || '').replace(/"/g, '""')}"`,
                `"${(v.remediation || '').replace(/"/g, '""')}"`,
                `"${v.created_at || ''}"`
            ]);
            const csvContent = 'data:text/csv;charset=utf-8,\uFEFF' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
            const encodedUri = encodeURI(csvContent);
            const link = document.createElement('a');
            link.setAttribute('href', encodedUri);
            link.setAttribute('download', `openrecon_vulnerabilidades_${activeSeed || 'consolidado'}_${new Date().toISOString().slice(0,10)}.csv`);
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            showToast('Reporte CSV descargado con éxito');
        }

        async function runVulnerabilityScan() {
            showToast('Iniciando sondeo de vulnerabilidades DAST en vivo...');
            const scanBtn = document.getElementById('btn-scan');
            if (scanBtn) scanBtn.disabled = true;

            try {
                const res = await fetch(`${API_URL}?action=run_scan${getSeedQueryParam()}`);
                const data = await res.json();
                if (data.success) {
                    showToast(`Escaneo finalizado: ${data.summary.vulns_detected} vulnerabilidades catalogadas`);
                    await refreshAllData();
                } else {
                    showToast('Error en el escaneo: ' + (data.error || 'Fallo desconocido'), true);
                }
            } catch (err) {
                showToast('Fallo al ejecutar el escaneo perimetral', true);
            } finally {
                if (scanBtn) scanBtn.disabled = false;
            }
        }

        async function handleStatusChange(vulnId, newStatus) {
            const form = new FormData();
            form.append('id', vulnId);
            form.append('status', newStatus);

            try {
                const res = await fetch(`${API_URL}?action=update_vuln_status`, { method: 'POST', body: form });
                const data = await res.json();
                if (data.success) {
                    showToast(`Estado del hallazgo actualizado a ${newStatus}`);
                    await Promise.all([loadStats(), loadVulns(), loadGraph()]);
                } else {
                    showToast('Error actualizando estado', true);
                }
            } catch (err) {
                showToast('Fallo de conexión al actualizar hallazgo', true);
            }
        }

        // Load DRP Threats
        async function loadDrp() {
            try {
                const res = await fetch(`${API_URL}?action=get_drp${getSeedQueryParam()}`);
                const threats = await res.json();
                const tbody = document.getElementById('drp-table-body');

                if (threats.length === 0) {
                    tbody.innerHTML = `<tr><td colspan="6" class="p-8 text-center text-slate-500">No se han detectado dominios imitadores o suplantaciones activas.</td></tr>`;
                    return;
                }

                tbody.innerHTML = threats.map(t => {
                    const mxBadge = t.has_mx ? 
                        '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-400 border border-rose-800"><i class="fa-solid fa-envelope mr-1"></i>ACTIVO (Riesgo Phishing)</span>' : 
                        '<span class="text-slate-500 text-[11px]">Inactivo</span>';

                    return `
                        <tr class="hover:bg-slate-800/40 transition">
                            <td class="p-4 font-mono font-bold text-white flex items-center gap-2">
                                <i class="fa-solid fa-triangle-exclamation text-amber-400"></i>
                                ${t.lookalike_domain}
                            </td>
                            <td class="p-4 font-mono text-slate-400">${t.ip_address || '-'}</td>
                            <td class="p-4">${mxBadge}</td>
                            <td class="p-4">
                                <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-400 border border-amber-800">${t.severity}</span>
                            </td>
                            <td class="p-4 text-xs text-slate-400">${t.details}</td>
                            <td class="p-4 text-center">
                                <button onclick="openTakedownModal('${t.lookalike_domain}')" class="px-3 py-1.5 rounded-lg bg-rose-950 hover:bg-rose-900 text-rose-300 border border-rose-800 font-semibold text-xs transition flex items-center gap-1.5 mx-auto">
                                    <i class="fa-solid fa-gavel"></i>
                                    <span>Takedown</span>
                                </button>
                            </td>
                        </tr>
                    `;
                }).join('');

            } catch (err) {
                console.error(err);
            }
        }

        // Load Leaks & Secrets
        async function loadLeaks() {
            try {
                const resSec = await fetch(`${API_URL}?action=get_exposed_secrets${getSeedQueryParam()}`);
                const secrets = await resSec.json();
                const secContainer = document.getElementById('secrets-container');

                if (secrets.length === 0) {
                    secContainer.innerHTML = `
                        <div class="p-4 rounded-xl bg-slate-900/60 border border-cyber-border text-center text-xs text-slate-500">
                            No se han detectado archivos .env o repositorios .git expuestos para esta semilla.
                        </div>
                    `;
                } else {
                    secContainer.innerHTML = secrets.map(s => `
                        <div class="p-4 rounded-xl bg-rose-950/30 border border-rose-900/50 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                            <div>
                                <div class="flex items-center gap-2">
                                    <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-900 text-rose-200 uppercase">CRÍTICO</span>
                                    <span class="font-bold text-white text-sm">${s.secret_type}</span>
                                </div>
                                <p class="text-xs text-slate-300 font-mono mt-1">${s.endpoint_url}</p>
                                <p class="text-[11px] text-slate-500 font-mono truncate max-w-xl mt-1">Snippet: ${s.matched_snippet}</p>
                            </div>
                            <span class="text-[10px] text-slate-400 font-mono">${s.detected_at}</span>
                        </div>
                    `).join('');
                }

                const resLeaks = await fetch(`${API_URL}?action=get_credential_leaks${getSeedQueryParam()}`);
                const leaks = await resLeaks.json();
                globalLeaks = leaks;
                const tbody = document.getElementById('leaks-table-body');

                if (leaks.length === 0) {
                    tbody.innerHTML = `<tr><td colspan="7" class="p-8 text-center text-slate-500">No se han registrado credenciales corporativas en brechas públicas recientes para esta semilla.</td></tr>`;
                    document.getElementById('leak-stat-email').innerText = 'Ninguno';
                    document.getElementById('leak-stat-pwn').innerText = '0 Registros';
                    return;
                }

                const firstLeak = leaks[0];
                document.getElementById('leak-stat-email').innerText = firstLeak.email;
                document.getElementById('leak-stat-pwn').innerText = `${firstLeak.pwn_count} Registros`;

                tbody.innerHTML = leaks.map(l => `
                    <tr class="hover:bg-slate-800/40 transition">
                        <td class="p-4 font-mono font-bold text-white flex items-center gap-2">
                            <i class="fa-solid fa-user-shield text-cyan-400"></i>
                            <span>${l.email}</span>
                        </td>
                        <td class="p-4 text-slate-300">
                            <div class="font-semibold text-white">${l.source_breach}</div>
                            <span class="text-[10px] text-slate-500 font-mono">Semilla: ${l.seed_domain}</span>
                        </td>
                        <td class="p-4 text-slate-400 font-mono text-[11px]">${l.breach_date || '-'}</td>
                        <td class="p-4 text-amber-400 font-mono font-bold">${l.pwn_count} registros</td>
                        <td class="p-4 text-[11px] text-slate-300 max-w-xs">
                            <span class="line-clamp-2 text-slate-400">${l.data_classes || 'Contraseñas en texto plano, Hashes deshashados, Nombres de usuario'}</span>
                        </td>
                        <td class="p-4 text-center">
                            <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-300 border border-rose-800">${l.severity}</span>
                        </td>
                        <td class="p-4 text-center">
                            <button onclick="openBreachModal(${l.id})" class="px-3 py-1.5 rounded-lg bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 font-semibold text-xs transition flex items-center gap-1.5 mx-auto shadow">
                                <i class="fa-solid fa-microscope text-cyan-400"></i>
                                <span>Detalle Forense</span>
                            </button>
                        </td>
                    </tr>
                `).join('');

            } catch (err) {
                console.error(err);
            }
        }

        // Load CTI & Dark Web
        async function loadCti() {
            try {
                const resR = await fetch(`${API_URL}?action=get_ransomware_leaks${getSeedQueryParam()}`);
                const leaks = await resR.json();
                const tbodyR = document.getElementById('ransomware-table-body');

                if (leaks.length === 0) {
                    tbodyR.innerHTML = `<tr><td colspan="4" class="p-8 text-center text-slate-500">Presiona "Sincronizar CTI" para descargar los últimos registros de la Dark Web.</td></tr>`;
                } else {
                    tbodyR.innerHTML = leaks.map(r => {
                        const alertBadge = r.is_matched ? 
                            '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-300 border border-rose-800 animate-pulse">OBJETIVO: TU EMPRESA</span>' : 
                            '<span class="text-slate-500 text-[10px]">Tercero / Global</span>';

                        return `
                            <tr class="hover:bg-slate-800/40 transition ${r.is_matched ? 'bg-rose-950/20' : ''}">
                                <td class="p-4 font-bold text-white flex items-center gap-2">
                                    <i class="fa-solid fa-building text-slate-400"></i>
                                    ${r.victim_name}
                                </td>
                                <td class="p-4 font-mono text-purple-400 font-semibold">${r.group_name}</td>
                                <td class="p-4 font-mono text-[11px] text-slate-400">${r.discovered_date || '-'}</td>
                                <td class="p-4 text-center">${alertBadge}</td>
                            </tr>
                        `;
                    }).join('');
                }

                const resAct = await fetch(`${API_URL}?action=get_threat_actors`);
                const actors = await resAct.json();
                const containerAct = document.getElementById('actors-container');

                containerAct.innerHTML = actors.map(a => `
                    <div class="p-5 rounded-2xl bg-slate-900/80 border border-cyber-border hover:border-purple-600/50 transition flex flex-col justify-between">
                        <div>
                            <div class="flex items-center justify-between mb-2">
                                <h4 class="font-bold text-white text-sm">${a.name}</h4>
                                <span class="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-950 text-purple-300 border border-purple-800/60">${a.origin}</span>
                            </div>
                            <p class="text-[11px] text-slate-400 italic mb-2">Alias: ${a.aliases}</p>
                            <p class="text-xs text-slate-300 leading-relaxed mb-3">${a.description}</p>
                        </div>
                        <div class="pt-3 border-t border-cyber-border space-y-1.5 text-[11px]">
                            <div>
                                <span class="text-slate-500">Vector Inicial:</span>
                                <span class="text-rose-400 font-mono block">${a.initial_access}</span>
                            </div>
                            <div>
                                <span class="text-slate-500">TTPs MITRE:</span>
                                <span class="text-cyan-400 font-mono block">${a.mitre_tactics}</span>
                            </div>
                        </div>
                    </div>
                `).join('');

                const resIoc = await fetch(`${API_URL}?action=get_threat_iocs`);
                const iocs = await resIoc.json();
                globalIocs = iocs;
                const tbodyIoc = document.getElementById('iocs-table-body');

                if (iocs.length === 0) {
                    tbodyIoc.innerHTML = `<tr><td colspan="5" class="p-8 text-center text-slate-500">Presiona "Sincronizar CTI" para obtener los IOCs activos.</td></tr>`;
                } else {
                    tbodyIoc.innerHTML = iocs.map(i => `
                        <tr class="hover:bg-slate-800/40 transition">
                            <td class="p-4 font-mono font-bold text-rose-400">${i.ip_address}</td>
                            <td class="p-4 font-mono text-slate-300">${i.port || '-'}</td>
                            <td class="p-4 font-semibold text-white">${i.malware_family}</td>
                            <td class="p-4 text-slate-400 text-xs">${i.as_name}</td>
                            <td class="p-4 text-center">
                                <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-400 border border-rose-800">${i.status.toUpperCase()}</span>
                            </td>
                        </tr>
                    `).join('');
                }

            } catch (err) {
                console.error(err);
            }
        }

        // Sync CTI Feeds
        async function syncCti() {
            const icon = document.getElementById('sync-icon');
            icon.classList.add('fa-spin');
            showToast('Sincronizando feeds de Dark Web y Botnets C2...');

            try {
                const res = await fetch(`${API_URL}?action=sync_cti`);
                const data = await res.json();
                if (data.success) {
                    showToast(`Sincronización CTI completada: ${data.ransomware_ingested} fugas y ${data.iocs_ingested} IOCs.`);
                    await Promise.all([loadStats(), loadCti()]);
                } else {
                    showToast('Error sincronizando feeds', true);
                }
            } catch (err) {
                showToast('Fallo al conectar con feeds CTI', true);
            } finally {
                icon.classList.remove('fa-spin');
            }
        }

        // Takedown Modal Functions
        async function openTakedownModal(domain) {
            try {
                const res = await fetch(`${API_URL}?action=generate_takedown&domain=${encodeURIComponent(domain)}`);
                const data = await res.json();
                document.getElementById('takedown-text').value = data.generated_notice;
                document.getElementById('takedown-modal').classList.remove('hidden');
            } catch (err) {
                showToast('Error generando ficha de Takedown', true);
            }
        }

        function closeTakedownModal() {
            document.getElementById('takedown-modal').classList.add('hidden');
        }

        function copyTakedownText() {
            const textarea = document.getElementById('takedown-text');
            textarea.select();
            navigator.clipboard.writeText(textarea.value);
            showToast('¡Notificación de abuso copiada al portapapeles!');
        }

        // Breach Intelligence Forensic Modal
        function openBreachModal(leakId) {
            const leak = globalLeaks.find(item => item.id == leakId) || globalLeaks[0];
            if (leak) {
                document.getElementById('breach-modal-email').innerText = `${leak.email} • ${leak.pwn_count} Registros Pwned en ${leak.source_breach}`;
                if (leak.data_classes) {
                    document.getElementById('breach-modal-dataclasses').innerText = leak.data_classes;
                }
                if (leak.playbook_actions) {
                    document.getElementById('breach-modal-playbook').innerText = leak.playbook_actions;
                }
            }
            document.getElementById('breach-modal').classList.remove('hidden');
        }

        function closeBreachModal() {
            document.getElementById('breach-modal').classList.add('hidden');
        }

        // Firewall Rules Modal (C2 Blocking)
        function openFirewallRulesModal() {
            setFirewallTab('fortigate');
            document.getElementById('firewall-modal').classList.remove('hidden');
        }

        function closeFirewallRulesModal() {
            document.getElementById('firewall-modal').classList.add('hidden');
        }

        function setFirewallTab(tab) {
            currentFwTab = tab;
            ['fortigate', 'iptables', 'plain'].forEach(t => {
                const btn = document.getElementById(`fw-tab-${t}`);
                if (btn) {
                    if (t === tab) {
                        btn.className = 'px-3 py-1.5 rounded-lg bg-cyan-900/60 text-white text-xs font-semibold border border-cyan-600';
                    } else {
                        btn.className = 'px-3 py-1.5 rounded-lg bg-slate-900 text-slate-400 hover:text-white text-xs font-semibold border border-cyber-border';
                    }
                }
            });

            const textarea = document.getElementById('firewall-rules-text');
            if (!globalIocs || globalIocs.length === 0) {
                textarea.value = '# No hay IOCs sincronizados aún. Presiona "Sincronizar CTI" en el dashboard.';
                return;
            }

            if (tab === 'fortigate') {
                let out = "# ==========================================================\n";
                out += "# OpenRecon CTI - FortiGate Firewall C2 IP Blocklist\n";
                out += `# Nodos C2 Activos: ${globalIocs.length} IPs hostiles sincronizadas\n`;
                out += "# ==========================================================\nconfig firewall address\n";
                globalIocs.forEach((ioc) => {
                    const cleanName = `C2_${ioc.ip_address.replace(/[\.:]/g, '_')}`;
                    out += `edit "${cleanName}"\n    set subnet ${ioc.ip_address} 255.255.255.255\n    set comment "OpenRecon CTI: ${ioc.malware_family.substring(0, 30)}"\nnext\n`;
                });
                out += "end\n\nconfig firewall addrgrp\nedit \"MALICIOUS_C2_FEED\"\n    set member " + globalIocs.map(i => `"C2_${i.ip_address.replace(/[\.:]/g, '_')}"`).join(" ") + "\n    set comment \"Regla de bloqueo perimetral automatizada OpenRecon\"\nnext\nend\n";
                textarea.value = out;
            } else if (tab === 'iptables') {
                let out = "#!/bin/bash\n# ==========================================================\n";
                out += "# OpenRecon CTI - Linux iptables Droplist para Servidores C2\n";
                out += `# Total IOCs: ${globalIocs.length} direcciones hostiles detectadas\n`;
                out += "# ==========================================================\niptables -N OPENRECON_C2_BLOCK 2>/dev/null || true\n";
                globalIocs.forEach(ioc => {
                    out += `iptables -A OPENRECON_C2_BLOCK -s ${ioc.ip_address} -j DROP -m comment --comment "${ioc.malware_family.substring(0, 25)}"\n`;
                });
                out += "iptables -I INPUT 1 -j OPENRECON_C2_BLOCK\niptables -I FORWARD 1 -j OPENRECON_C2_BLOCK\necho '[+] " + globalIocs.length + " Servidores C2 bloqueados exitosamente en iptables'\n";
                textarea.value = out;
            } else {
                textarea.value = globalIocs.map(i => `${i.ip_address}/32  # ${i.malware_family}`).join("\n");
            }
        }

        function copyFirewallRules() {
            const textarea = document.getElementById('firewall-rules-text');
            textarea.select();
            navigator.clipboard.writeText(textarea.value);
            showToast('¡Reglas de firewall copiadas al portapapeles!');
        }

        // Load Seeds & Populate Switcher
        async function loadSeeds() {
            try {
                const res = await fetch(`${API_URL}?action=get_seeds`);
                const seeds = await res.json();
                document.getElementById('seeds-count').innerText = `${seeds.length} semillas`;

                // Populate Topbar Switcher
                const selector = document.getElementById('active-seed-selector');
                if (seeds.length === 0) {
                    selector.innerHTML = `<option value="ALL">Sin semillas</option>`;
                    activeSeed = 'ALL';
                } else {
                    // Set default active seed to first seed if not set
                    if (!activeSeed || activeSeed === 'ALL') {
                        activeSeed = seeds[0].domain;
                    }

                    selector.innerHTML = seeds.map(s => `
                        <option value="${s.domain}" ${s.domain === activeSeed ? 'selected' : ''} class="bg-slate-900 text-white">${s.domain}</option>
                    `).join('') + `<option value="ALL" ${activeSeed === 'ALL' ? 'selected' : ''} class="bg-slate-900 text-white">Todas las semillas (Consolidado)</option>`;

                    document.getElementById('current-scope-label').innerText = activeSeed;
                    document.getElementById('plan-seed-subtitle').innerText = 'Semilla Activa: ' + activeSeed;
                    document.getElementById('btn-report-link').href = `report.php?seed=${encodeURIComponent(activeSeed)}`;
                }

                const list = document.getElementById('seeds-list');
                if (seeds.length === 0) {
                    list.innerHTML = `<p class="p-6 text-center text-xs text-slate-500">No hay semillas configuradas.</p>`;
                    return;
                }

                list.innerHTML = seeds.map(s => `
                    <div class="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-slate-800/30 transition">
                        <div class="flex items-center gap-3">
                            <div class="w-8 h-8 rounded-lg bg-cyan-950/60 border border-cyan-800/50 flex items-center justify-center text-cyan-400">
                                <i class="fa-solid fa-globe"></i>
                            </div>
                            <div>
                                <h4 class="font-bold text-white text-sm font-mono">${s.domain}</h4>
                                <span class="text-[10px] text-slate-500">Registrado el ${s.created_at}</span>
                            </div>
                        </div>
                        <div class="flex items-center gap-2">
                            <button onclick="handleDiscoverForSeed('${s.domain}')" class="px-3 py-1.5 rounded-lg bg-indigo-950 hover:bg-indigo-900 text-indigo-300 border border-indigo-800 text-xs font-semibold flex items-center gap-1.5 transition" title="Auto-descubrir subdominios e incorporarlos directamente como semillas">
                                <i class="fa-solid fa-wand-magic-sparkles text-amber-400"></i>
                                <span>Auto-descubrir Subdominios</span>
                            </button>
                            <button onclick="handleDeleteSeed(${s.id})" class="p-2 text-slate-500 hover:text-rose-400 hover:bg-rose-950/30 rounded-lg transition" title="Eliminar semilla">
                                <i class="fa-solid fa-trash-can"></i>
                            </button>
                        </div>
                    </div>
                `).join('');

            } catch (err) {
                console.error(err);
            }
        }

        // Auto-discover and add subdomains directly as seeds
        async function handleAutoDiscoverAndAddSeeds() {
            const domainInput = document.getElementById('new-seed-domain');
            const domain = domainInput.value.trim() || activeSeed;
            if (!domain || domain === 'ALL') {
                showToast('Ingresa un dominio en la caja de texto para auto-descubrir sus subdominios', true);
                domainInput.focus();
                return;
            }
            await runDiscoverAndAddSeeds(domain);
        }

        async function handleDiscoverForSeed(domain) {
            await runDiscoverAndAddSeeds(domain);
        }

        async function runDiscoverAndAddSeeds(domain) {
            const btn = document.getElementById('btn-auto-discover-seeds');
            const originalHtml = btn ? btn.innerHTML : '';
            if (btn) {
                btn.disabled = true;
                btn.classList.add('opacity-75');
                btn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin text-amber-300"></i><span>Buscando e ingiriendo subdominios...</span>`;
            }

            showToast(`Descubriendo subdominios para ${domain} mediante inteligencia pasiva...`);

            try {
                const formData = new FormData();
                formData.append('domain', domain);
                const res = await fetch(`${API_URL}?action=discover_and_add_seeds`, { method: 'POST', body: formData });
                const data = await res.json();

                if (data.success) {
                    showToast(`¡Completado! Se descubrieron e incorporaron ${data.seeds_added} subdominios. Iniciando escaneo perimetral...`);
                    activeSeed = data.root_domain;
                    await loadSeeds();
                    await refreshAllData();
                    await triggerScan();
                } else {
                    showToast(data.error || 'Fallo durante el auto-descubrimiento', true);
                }
            } catch (err) {
                showToast('Error al conectar con el motor de descubrimiento', true);
            } finally {
                if (btn) {
                    btn.disabled = false;
                    btn.classList.remove('opacity-75');
                    btn.innerHTML = originalHtml;
                }
            }
        }

        // Delete all seeds (mass purge)
        async function handleDeleteAllSeeds() {
            if (!confirm('¿ATENCIÓN: Deseas eliminar TODAS las semillas y purgar por completo todos los activos, puertos y vulnerabilidades del inventario?')) {
                return;
            }

            showToast('Eliminando masivamente todas las semillas y reseteando inventario...');

            try {
                const res = await fetch(`${API_URL}?action=delete_all_seeds`, { method: 'POST' });
                const data = await res.json();
                if (data.success) {
                    showToast('Todas las semillas y activos perimetrales han sido eliminados.');
                    activeSeed = 'ALL';
                    await loadSeeds();
                    await refreshAllData();
                } else {
                    showToast(data.error || 'Error al eliminar semillas', true);
                }
            } catch (err) {
                showToast('Error de conexión al purgar semillas', true);
            }
        }

        // Add Seed
        async function handleAddSeed(e) {
            e.preventDefault();
            const domainInput = document.getElementById('new-seed-domain');
            const domain = domainInput.value.trim();
            if (!domain) return;

            const form = new FormData();
            form.append('domain', domain);

            try {
                const res = await fetch(`${API_URL}?action=add_seed`, { method: 'POST', body: form });
                const data = await res.json();
                if (data.success) {
                    domainInput.value = '';
                    activeSeed = domain;
                    showToast(`Semilla ${domain} agregada exitosamente. Iniciando escaneo...`);
                    await loadSeeds();
                    await refreshAllData();
                    await triggerScan();
                } else {
                    showToast(data.error || 'Error al agregar', true);
                }
            } catch (err) {
                showToast('Error de conexión', true);
            }
        }

        // Delete Seed (Cascade Purge)
        async function handleDeleteSeed(id) {
            if (!confirm('¿Deseas eliminar este dominio y purgar todos sus activos de la superficie?')) return;
            const form = new FormData();
            form.append('id', id);
            try {
                const res = await fetch(`${API_URL}?action=delete_seed`, { method: 'POST', body: form });
                const data = await res.json();
                if (data.success) {
                    showToast('Semilla y activos purgados');
                    activeSeed = '';
                    await loadSeeds();
                    await refreshAllData();
                }
            } catch (err) {
                showToast('Error de conexión', true);
            }
        }

        // Trigger Scan
        async function triggerScan() {
            const btn = document.getElementById('btn-scan');
            const icon = document.getElementById('scan-icon');
            const text = document.getElementById('scan-text');

            btn.disabled = true;
            btn.classList.add('opacity-75');
            icon.className = 'fa-solid fa-circle-notch fa-spin text-black';
            text.innerText = 'Escaneando...';
            showToast(`Iniciando reconocimiento perimetral para: ${activeSeed || 'Semillas activas'}...`);

            try {
                const res = await fetch(`${API_URL}?action=run_scan${getSeedQueryParam()}`);
                const data = await res.json();

                if (data.success) {
                    showToast(`¡Escaneo finalizado! ${data.summary.assets_cataloged} activos analizados.`);
                    await refreshAllData();
                } else {
                    showToast(data.error || 'Fallo durante el escaneo', true);
                }
            } catch (err) {
                showToast('Error ejecutando el escaneo perimetral', true);
            } finally {
                btn.disabled = false;
                btn.classList.remove('opacity-75');
                icon.className = 'fa-solid fa-radar text-black group-hover:rotate-45 transition-transform';
                text.innerText = 'Escanear';
            }
        }

        // ==========================================
        // STRIX PENTESTING TOOLKIT (NAVAJA SUIZA)
        // ==========================================
        let currentStrixSubTool = 'poc';

        function switchStrixSubTool(tool) {
            currentStrixSubTool = tool;
            ['poc', 'fuzz', 'tls', 'cors', 'dns'].forEach(t => {
                const btn = document.getElementById(`strix-subtab-${t}`);
                const panel = document.getElementById(`strix-panel-${t}`);
                if (btn) {
                    if (t === tool) {
                        btn.className = 'px-4 py-2 rounded-xl bg-emerald-950/80 text-emerald-300 border border-emerald-700/80 flex items-center gap-2 transition';
                    } else {
                        btn.className = 'px-4 py-2 rounded-xl bg-slate-900 text-slate-400 hover:text-white border border-cyber-border flex items-center gap-2 transition';
                    }
                }
                if (panel) {
                    panel.classList.toggle('hidden', t !== tool);
                }
            });
        }

        function populateStrixAssetDropdown() {
            const select = document.getElementById('strix-asset-quick-select');
            if (!select) return;

            let optionsHtml = '<option value="">Seleccionar activo...</option>';
            if (activeSeed && activeSeed !== 'ALL') {
                optionsHtml += `<option value="https://${activeSeed}">${activeSeed} (Semilla activa)</option>`;
            }

            if (globalAssets && globalAssets.length > 0) {
                globalAssets.forEach(a => {
                    const host = a.subdomain || a.ip_address;
                    if (host && host !== activeSeed) {
                        optionsHtml += `<option value="https://${host}">${host}</option>`;
                    }
                });
            }
            select.innerHTML = optionsHtml;
        }

        function applyStrixSelectedAsset() {
            const select = document.getElementById('strix-asset-quick-select');
            if (!select || !select.value) return;
            const targetUrl = select.value;
            const domain = targetUrl.replace(/^https?:\/\//i, '').split('/')[0];

            document.getElementById('strix-poc-url').value = targetUrl;
            document.getElementById('strix-fuzz-url').value = targetUrl;
            document.getElementById('strix-tls-host').value = domain;
            document.getElementById('strix-cors-url').value = targetUrl;
            document.getElementById('strix-dns-domain').value = domain;

            showToast(`Activo ${domain} cargado en la Navaja Suiza`);
        }

        function launchStrixForUrl(url, vulnTitle) {
            if (!url) return;
            switchTab('strix');
            switchStrixSubTool('poc');

            const domain = url.replace(/^https?:\/\//i, '').split('/')[0];
            document.getElementById('strix-poc-url').value = url;
            document.getElementById('strix-fuzz-url').value = 'https://' + domain;
            document.getElementById('strix-tls-host').value = domain;
            document.getElementById('strix-cors-url').value = url;
            document.getElementById('strix-dns-domain').value = domain;

            showToast(`Cargado en Strix PoC: ${vulnTitle ? vulnTitle.substring(0, 30) + '...' : url}`);
            runStrixPocTest();
        }

        function copyToClipboard(elementId, successMsg) {
            const el = document.getElementById(elementId);
            if (!el) return;
            const text = el.innerText || el.value;
            navigator.clipboard.writeText(text).then(() => {
                showToast(successMsg || 'Copiado al portapapeles');
            }).catch(() => {
                showToast('No se pudo copiar automáticamente', true);
            });
        }

        async function runStrixPocTest() {
            const urlInput = document.getElementById('strix-poc-url');
            const methodSelect = document.getElementById('strix-poc-method');
            const btn = document.getElementById('btn-strix-run-poc');
            let targetUrl = urlInput.value.trim();

            if (!targetUrl) {
                showToast('Ingresa una URL objetivo para validar', true);
                return;
            }
            if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
                targetUrl = 'https://' + targetUrl;
                urlInput.value = targetUrl;
            }

            const method = methodSelect.value || 'GET';
            btn.disabled = true;
            btn.classList.add('opacity-75');
            btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i><span>Ejecutando PoC...</span>';

            try {
                const res = await fetch(`${API_URL}?action=strix_poc_test&url=${encodeURIComponent(targetUrl)}&method=${encodeURIComponent(method)}`);
                const data = await res.json();

                if (!data.success) {
                    showToast(data.error || 'Error al ejecutar PoC', true);
                    return;
                }

                document.getElementById('strix-poc-results').classList.remove('hidden');

                // Badge
                const badgeEl = document.getElementById('strix-poc-badge');
                let badgeClass = 'text-rose-400';
                if (data.verdict === 'PROTEGIDO') badgeClass = 'text-emerald-400';
                else if (data.verdict === 'INFO_LEAK') badgeClass = 'text-amber-400';
                badgeEl.className = `mt-1 font-bold text-xs ${badgeClass}`;
                badgeEl.innerText = `${data.verdict}`;

                // HTTP Code
                document.getElementById('strix-poc-http-code').innerText = data.http_code ? `${data.http_code}` : 'N/A';
                document.getElementById('strix-poc-latency').innerText = `${data.latency_ms} ms`;
                document.getElementById('strix-poc-content-type').innerText = data.content_type || 'N/A';

                // Diagnostic Box
                const diagBox = document.getElementById('strix-poc-diag-box');
                const diagTitle = document.getElementById('strix-poc-diag-title');
                const diagMsg = document.getElementById('strix-poc-diag-msg');

                if (data.verdict === 'VULNERABLE') {
                    diagBox.className = 'p-4 rounded-xl border border-rose-800 bg-rose-950/20 text-xs';
                    diagTitle.innerHTML = '<i class="fa-solid fa-triangle-exclamation text-rose-400"></i><span class="text-rose-300 font-bold">Hallazgo Confirmado: Vulnerable / Expuesto</span>';
                } else if (data.verdict === 'PROTEGIDO') {
                    diagBox.className = 'p-4 rounded-xl border border-emerald-800 bg-emerald-950/20 text-xs';
                    diagTitle.innerHTML = '<i class="fa-solid fa-shield-check text-emerald-400"></i><span class="text-emerald-300 font-bold">Endpoint Protegido / Sin Exposición Crítica</span>';
                } else {
                    diagBox.className = 'p-4 rounded-xl border border-amber-800 bg-amber-950/20 text-xs';
                    diagTitle.innerHTML = '<i class="fa-solid fa-circle-info text-amber-400"></i><span class="text-amber-300 font-bold">Fuga Informativa / Exposición Parcial</span>';
                }
                diagMsg.innerText = data.diagnostic || 'Respuesta inspeccionada con éxito.';

                // Raw Request & Response
                document.getElementById('strix-poc-raw-req').innerText = data.raw_request || '(Sin cabeceras crudas)';
                document.getElementById('strix-poc-raw-res').innerText = (data.raw_response_headers || '') + "\n\n" + (data.response_body_snippet || '');

                // Reproduction
                document.getElementById('strix-poc-curl').innerText = data.poc_curl || '';
                document.getElementById('strix-poc-python').innerText = data.poc_python || '';

                showToast(`PoC completado en ${data.latency_ms}ms: ${data.verdict}`);
            } catch (err) {
                showToast('Fallo al conectar con el motor PoC de Strix', true);
            } finally {
                btn.disabled = false;
                btn.classList.remove('opacity-75');
                btn.innerHTML = '<i class="fa-solid fa-play"></i><span>Ejecutar PoC</span>';
            }
        }

        async function runStrixRouteFuzz() {
            const urlInput = document.getElementById('strix-fuzz-url');
            const btn = document.getElementById('btn-strix-run-fuzz');
            let targetUrl = urlInput.value.trim();

            if (!targetUrl) {
                showToast('Ingresa la URL base del objetivo', true);
                return;
            }
            if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
                targetUrl = 'https://' + targetUrl;
                urlInput.value = targetUrl;
            }

            btn.disabled = true;
            btn.classList.add('opacity-75');
            btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i><span>Fuzzeando rutas...</span>';

            try {
                const res = await fetch(`${API_URL}?action=strix_route_fuzz&url=${encodeURIComponent(targetUrl)}`);
                const data = await res.json();

                if (!data.success) {
                    showToast(data.error || 'Error en fuzzing de rutas', true);
                    return;
                }

                document.getElementById('strix-fuzz-results').classList.remove('hidden');

                // Canary info
                const canaryInfo = data.canary_info || {};
                document.getElementById('strix-fuzz-canary-status').innerText = `Canario: ${canaryInfo.status_code || 404} | Tamaño baseline: ${canaryInfo.length || 0} bytes`;

                // Render table
                const tbody = document.getElementById('strix-fuzz-tbody');
                const results = data.results || [];

                tbody.innerHTML = results.map(r => {
                    let codeBadge = 'bg-slate-800 text-slate-300';
                    if (r.http_code >= 200 && r.http_code < 300) codeBadge = 'bg-emerald-950 text-emerald-300 border border-emerald-800';
                    else if (r.http_code >= 300 && r.http_code < 400) codeBadge = 'bg-cyan-950 text-cyan-300 border border-cyan-800';
                    else if (r.http_code === 403 || r.http_code === 401) codeBadge = 'bg-amber-950 text-amber-300 border border-amber-800';
                    else if (r.http_code === 404) codeBadge = 'bg-slate-900 text-slate-500';

                    let verdBadge = '<span class="text-slate-500 font-mono text-[11px]">No expuesto</span>';
                    if (r.verdict === 'EXPOSED') {
                        verdBadge = '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-300 border border-rose-800">EXPUESTO (200 OK)</span>';
                    } else if (r.verdict === 'POTENTIAL') {
                        verdBadge = '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-300 border border-amber-800">POTENCIAL (403/302)</span>';
                    } else if (r.verdict === 'SOFT_404') {
                        verdBadge = '<span class="px-2 py-0.5 rounded text-[10px] font-mono text-slate-400 bg-slate-900 border border-slate-700">Soft-404 Ignorado</span>';
                    }

                    return `
                        <tr class="hover:bg-slate-900/40 transition">
                            <td class="p-3.5 font-mono text-xs font-semibold text-white">${r.path}</td>
                            <td class="p-3.5 text-center font-mono"><span class="px-2 py-0.5 rounded text-[10px] font-bold ${codeBadge}">${r.http_code}</span></td>
                            <td class="p-3.5 text-right font-mono text-xs text-slate-400">${r.size_bytes} B</td>
                            <td class="p-3.5">${verdBadge}</td>
                            <td class="p-3.5 text-center">
                                <button onclick="loadFuzzedRouteInPoc('${targetUrl}${r.path}')" class="px-2.5 py-1 rounded bg-indigo-950/80 hover:bg-indigo-900 text-indigo-300 border border-indigo-700/60 text-[11px] font-semibold transition" title="Cargar ruta en el PoC Inspector">
                                    <i class="fa-solid fa-bolt mr-1"></i> Probar PoC
                                </button>
                            </td>
                        </tr>
                    `;
                }).join('');

                showToast(`Fuzzing finalizado: ${results.filter(r => r.verdict === 'EXPOSED').length} rutas expuestas confirmadas`);
            } catch (err) {
                showToast('Error de conexión durante el fuzzing de rutas', true);
            } finally {
                btn.disabled = false;
                btn.classList.remove('opacity-75');
                btn.innerHTML = '<i class="fa-solid fa-magnifying-glass-chart"></i><span>Iniciar Fuzzing (16 Rutas)</span>';
            }
        }

        function loadFuzzedRouteInPoc(url) {
            switchStrixSubTool('poc');
            document.getElementById('strix-poc-url').value = url;
            runStrixPocTest();
        }

        async function runStrixTlsInspect() {
            const hostInput = document.getElementById('strix-tls-host');
            const portInput = document.getElementById('strix-tls-port');
            const btn = document.getElementById('btn-strix-run-tls');
            let host = hostInput.value.trim().replace(/^https?:\/\//i, '').split('/')[0];
            const port = parseInt(portInput.value) || 443;

            if (!host) {
                showToast('Ingresa el hostname para inspección X.509', true);
                return;
            }
            hostInput.value = host;

            btn.disabled = true;
            btn.classList.add('opacity-75');
            btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i><span>Inspeccionando...</span>';

            try {
                const res = await fetch(`${API_URL}?action=strix_tls_inspect&host=${encodeURIComponent(host)}&port=${port}`);
                const data = await res.json();

                if (!data.success) {
                    showToast(data.error || 'Error al inspeccionar TLS', true);
                    return;
                }

                document.getElementById('strix-tls-results').classList.remove('hidden');

                const banner = document.getElementById('strix-tls-banner');
                const icon = document.getElementById('strix-tls-icon');
                const daysBadge = document.getElementById('strix-tls-days-badge');

                if (data.is_expired) {
                    banner.className = 'p-4 rounded-xl border border-rose-800 bg-rose-950/20 flex flex-col sm:flex-row sm:items-center justify-between gap-3';
                    icon.className = 'w-10 h-10 rounded-xl bg-rose-900/60 text-rose-400 border border-rose-700 flex items-center justify-center text-lg';
                    icon.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i>';
                    daysBadge.className = 'px-3 py-1.5 rounded-xl font-mono text-xs font-bold border bg-rose-950 text-rose-300 border-rose-800';
                    daysBadge.innerText = `EXPIRADO HACE ${Math.abs(data.days_remaining)} DÍAS`;
                } else if (data.days_remaining <= 30) {
                    banner.className = 'p-4 rounded-xl border border-amber-800 bg-amber-950/20 flex flex-col sm:flex-row sm:items-center justify-between gap-3';
                    icon.className = 'w-10 h-10 rounded-xl bg-amber-900/60 text-amber-400 border border-amber-700 flex items-center justify-center text-lg';
                    icon.innerHTML = '<i class="fa-solid fa-clock"></i>';
                    daysBadge.className = 'px-3 py-1.5 rounded-xl font-mono text-xs font-bold border bg-amber-950 text-amber-300 border-amber-800';
                    daysBadge.innerText = `${data.days_remaining} DÍAS RESTANTES (URGENTE)`;
                } else {
                    banner.className = 'p-4 rounded-xl border border-emerald-800 bg-emerald-950/20 flex flex-col sm:flex-row sm:items-center justify-between gap-3';
                    icon.className = 'w-10 h-10 rounded-xl bg-emerald-900/60 text-emerald-400 border border-emerald-700 flex items-center justify-center text-lg';
                    icon.innerHTML = '<i class="fa-solid fa-lock"></i>';
                    daysBadge.className = 'px-3 py-1.5 rounded-xl font-mono text-xs font-bold border bg-emerald-950 text-emerald-300 border-emerald-800';
                    daysBadge.innerText = `${data.days_remaining} DÍAS VIGENTE`;
                }

                document.getElementById('strix-tls-status-title').innerText = data.status || 'Certificado TLS';
                document.getElementById('strix-tls-status-desc').innerText = data.recommendation || '';
                document.getElementById('strix-tls-cn').innerText = data.common_name || host;
                document.getElementById('strix-tls-issuer').innerText = data.issuer || 'N/A';
                document.getElementById('strix-tls-algo').innerText = data.signature_algorithm || 'N/A';
                document.getElementById('strix-tls-from').innerText = data.valid_from || 'N/A';
                document.getElementById('strix-tls-to').innerText = data.valid_to || 'N/A';

                const sansContainer = document.getElementById('strix-tls-sans');
                const sans = data.subject_alt_names || [];
                if (sans.length === 0) {
                    sansContainer.innerHTML = '<span class="text-slate-500 font-mono text-xs">Sin SANs adicionales</span>';
                } else {
                    sansContainer.innerHTML = sans.map(s => `<span class="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-900 text-slate-300 border border-slate-700">${s}</span>`).join('');
                }

                showToast(`TLS inspeccionado: ${data.is_expired ? 'Certificado Expirado' : 'Certificado Válido'}`);
            } catch (err) {
                showToast('Error al conectar con el socket TLS', true);
            } finally {
                btn.disabled = false;
                btn.classList.remove('opacity-75');
                btn.innerHTML = '<i class="fa-solid fa-lock"></i><span>Inspeccionar X.509</span>';
            }
        }

        async function runStrixCorsTest() {
            const urlInput = document.getElementById('strix-cors-url');
            const originInput = document.getElementById('strix-cors-origin');
            const btn = document.getElementById('btn-strix-run-cors');
            let targetUrl = urlInput.value.trim();
            const origin = originInput.value.trim() || 'https://evil-attacker.com';

            if (!targetUrl) {
                showToast('Ingresa la URL objetivo para prueba CORS', true);
                return;
            }
            if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
                targetUrl = 'https://' + targetUrl;
                urlInput.value = targetUrl;
            }

            btn.disabled = true;
            btn.classList.add('opacity-75');
            btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i><span>Auditando CORS...</span>';

            try {
                const res = await fetch(`${API_URL}?action=strix_cors_test&url=${encodeURIComponent(targetUrl)}&origin=${encodeURIComponent(origin)}`);
                const data = await res.json();

                if (!data.success) {
                    showToast(data.error || 'Error en auditoría CORS', true);
                    return;
                }

                document.getElementById('strix-cors-results').classList.remove('hidden');

                const banner = document.getElementById('strix-cors-banner');
                const icon = document.getElementById('strix-cors-icon');

                if (data.verdict === 'VULNERABLE') {
                    banner.className = 'p-4 rounded-xl border border-rose-800 bg-rose-950/20 flex flex-col sm:flex-row sm:items-center justify-between gap-3';
                    icon.className = 'w-10 h-10 rounded-xl bg-rose-900/60 text-rose-400 border border-rose-700 flex items-center justify-center text-lg';
                    icon.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i>';
                } else {
                    banner.className = 'p-4 rounded-xl border border-emerald-800 bg-emerald-950/20 flex flex-col sm:flex-row sm:items-center justify-between gap-3';
                    icon.className = 'w-10 h-10 rounded-xl bg-emerald-900/60 text-emerald-400 border border-emerald-700 flex items-center justify-center text-lg';
                    icon.innerHTML = '<i class="fa-solid fa-shield-check"></i>';
                }

                document.getElementById('strix-cors-verdict').innerText = `Veredicto: ${data.verdict}`;
                document.getElementById('strix-cors-explanation').innerText = data.explanation || '';
                document.getElementById('strix-cors-credentials').innerHTML = data.allow_credentials 
                    ? '<span class="text-rose-400 font-bold">TRUE (Peligroso con Origin no confiable)</span>' 
                    : '<span class="text-emerald-400 font-bold">FALSE (Seguro)</span>';

                // Defensive Headers
                const headersGrid = document.getElementById('strix-cors-headers-grid');
                const defHeaders = data.defensive_headers || {};
                const list = [
                    { key: 'strict-transport-security', label: 'HSTS (Cifrado Estricto)', val: defHeaders['strict-transport-security'] },
                    { key: 'x-frame-options', label: 'Anti-Clickjacking (XFO)', val: defHeaders['x-frame-options'] },
                    { key: 'content-security-policy', label: 'Content Security Policy', val: defHeaders['content-security-policy'] },
                    { key: 'x-content-type-options', label: 'Anti-MIME Sniffing', val: defHeaders['x-content-type-options'] }
                ];

                headersGrid.innerHTML = list.map(h => {
                    const present = !!h.val;
                    return `
                        <div class="p-3 rounded-xl border ${present ? 'border-emerald-800/60 bg-emerald-950/10' : 'border-rose-800/60 bg-rose-950/10'} text-xs">
                            <div class="flex items-center justify-between mb-1">
                                <span class="font-bold text-white">${h.label}</span>
                                <i class="fa-solid ${present ? 'fa-check text-emerald-400' : 'fa-xmark text-rose-400'}"></i>
                            </div>
                            <div class="font-mono text-[11px] truncate ${present ? 'text-slate-300' : 'text-slate-500'}">
                                ${present ? h.val : 'Ausente (Riesgo)'}
                            </div>
                        </div>
                    `;
                }).join('');

                showToast(`CORS analizado: ${data.verdict}`);
            } catch (err) {
                showToast('Error de conexión en prueba CORS', true);
            } finally {
                btn.disabled = false;
                btn.classList.remove('opacity-75');
                btn.innerHTML = '<i class="fa-solid fa-shield-halved"></i><span>Auditar CORS</span>';
            }
        }

        async function runStrixDnsInspect() {
            const domainInput = document.getElementById('strix-dns-domain');
            const btn = document.getElementById('btn-strix-run-dns');
            let domain = domainInput.value.trim().replace(/^https?:\/\//i, '').split('/')[0];

            if (!domain) {
                showToast('Ingresa el dominio para auditoría DNS', true);
                return;
            }
            domainInput.value = domain;

            btn.disabled = true;
            btn.classList.add('opacity-75');
            btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i><span>Consultando DNS...</span>';

            try {
                const res = await fetch(`${API_URL}?action=strix_dns_inspect&domain=${encodeURIComponent(domain)}`);
                const data = await res.json();

                if (!data.success) {
                    showToast(data.error || 'Error al consultar DNS', true);
                    return;
                }

                document.getElementById('strix-dns-results').classList.remove('hidden');

                const recs = data.records || {};

                // A / AAAA
                const aRecs = (recs.A || []).concat(recs.AAAA || []);
                document.getElementById('strix-dns-count-a').innerText = `${aRecs.length} registros`;
                const aCont = document.getElementById('strix-dns-records-a');
                aCont.innerHTML = aRecs.length ? aRecs.map(r => `<div class="p-1.5 rounded bg-slate-900 border border-slate-800 text-cyan-300">${r.type || 'A'}: ${r.ip || r.ipv6}</div>`).join('') : '<div class="text-slate-500">Sin registros A/AAAA</div>';

                // MX
                const mxRecs = recs.MX || [];
                document.getElementById('strix-dns-count-mx').innerText = `${mxRecs.length} servidores`;
                const mxCont = document.getElementById('strix-dns-records-mx');
                mxCont.innerHTML = mxRecs.length ? mxRecs.map(r => `<div class="p-1.5 rounded bg-slate-900 border border-slate-800 text-amber-300">[Pri ${r.pri}] ${r.target}</div>`).join('') : '<div class="text-slate-500">Sin registros MX</div>';

                // NS
                const nsRecs = recs.NS || [];
                document.getElementById('strix-dns-count-ns').innerText = `${nsRecs.length} NS`;
                const nsCont = document.getElementById('strix-dns-records-ns');
                nsCont.innerHTML = nsRecs.length ? nsRecs.map(r => `<div class="p-1.5 rounded bg-slate-900 border border-slate-800 text-purple-300">${r.target}</div>`).join('') : '<div class="text-slate-500">Sin registros NS</div>';

                // TXT
                const txtRecs = recs.TXT || [];
                document.getElementById('strix-dns-count-txt').innerText = `${txtRecs.length} TXT`;
                const txtCont = document.getElementById('strix-dns-records-txt');
                txtCont.innerHTML = txtRecs.length ? txtRecs.map(r => {
                    const isSpf = (r.txt || '').toLowerCase().startsWith('v=spf1');
                    return `<div class="p-1.5 rounded bg-slate-900 border ${isSpf ? 'border-emerald-800/80 text-emerald-300' : 'border-slate-800 text-slate-300'} break-all">${isSpf ? '<span class="text-[10px] font-bold bg-emerald-950 px-1 py-0.5 rounded mr-1">SPF</span>' : ''}${r.txt}</div>`;
                }).join('') : '<div class="text-slate-500">Sin registros TXT</div>';

                // DMARC & CAA
                const dmarc = data.dmarc_policy;
                const dmarcEl = document.getElementById('strix-dns-record-dmarc');
                dmarcEl.innerText = dmarc ? dmarc.record : 'No configurado (Vulnerable a Spoofing de Correo)';
                dmarcEl.className = dmarc ? 'font-mono text-emerald-300 text-[11px] bg-slate-900 p-1.5 rounded border border-emerald-900/60 break-all mt-0.5' : 'font-mono text-rose-400 text-[11px] bg-rose-950/20 p-1.5 rounded border border-rose-900/60 break-all mt-0.5';

                const caaRecs = recs.CAA || [];
                const caaEl = document.getElementById('strix-dns-record-caa');
                caaEl.innerText = caaRecs.length ? caaRecs.map(c => `${c.tag} "${c.value}"`).join(', ') : 'Sin registro CAA (Cualquier CA puede emitir certificados)';
                caaEl.className = caaRecs.length ? 'font-mono text-cyan-300 text-[11px] bg-slate-900 p-1.5 rounded border border-cyan-900/60 break-all mt-0.5' : 'font-mono text-amber-400 text-[11px] bg-amber-950/20 p-1.5 rounded border border-amber-900/60 break-all mt-0.5';

                showToast(`Auditoría DNS RFC para ${domain} completada`);
            } catch (err) {
                showToast('Error al consultar registros DNS', true);
            } finally {
                btn.disabled = false;
                btn.classList.remove('opacity-75');
                btn.innerHTML = '<i class="fa-solid fa-network-wired"></i><span>Consultar DNS RFC</span>';
            }
        }

        window.onload = init;
    </script>
</body>
</html>
