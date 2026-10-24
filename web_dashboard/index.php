<!DOCTYPE html>
<html lang="es" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenRecon | EASM, DRP & Threat Exposure Platform</title>
    <!-- Tailwind CSS CDN -->
    <script src="https://cdn.tailwindcss.com"></script>
    <!-- FontAwesome Icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
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
                            warning: '#f59e0b'
                        }
                    }
                }
            }
        }
    </script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');
        body {
            font-family: 'Inter', sans-serif;
            background-color: #07090e;
        }
        .font-mono {
            font-family: 'JetBrains Mono', monospace;
        }
        @media print {
            body {
                background-color: #ffffff !important;
                color: #000000 !important;
            }
            header, .no-print {
                display: none !important;
            }
            .bg-cyber-card, .bg-slate-900 {
                background-color: #ffffff !important;
                border: 1px solid #cbd5e1 !important;
                color: #0f172a !important;
            }
            .text-white {
                color: #0f172a !important;
            }
            .text-slate-400, .text-slate-300 {
                color: #475569 !important;
            }
        }
    </style>
</head>
<body class="text-slate-200 min-h-screen flex flex-col antialiased selection:bg-cyan-500 selection:text-black">

    <!-- Top Navigation Bar -->
    <header class="border-b border-cyber-border bg-cyber-dark/80 backdrop-blur sticky top-0 z-50 no-print">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
            <div class="flex items-center gap-3">
                <div class="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 to-emerald-400 flex items-center justify-center text-black font-extrabold text-xl shadow-lg shadow-cyan-500/20">
                    <i class="fa-solid fa-shield-halved"></i>
                </div>
                <div>
                    <div class="flex items-center gap-2">
                        <span class="font-extrabold text-lg tracking-tight text-white">Open<span class="text-cyan-400">Recon</span></span>
                        <span class="px-2 py-0.5 text-[10px] font-bold tracking-wider uppercase bg-cyan-950 text-cyan-400 border border-cyan-800/60 rounded">Fase 2: EASM + DRP + Leaks</span>
                    </div>
                    <p class="text-[11px] text-slate-400">Alternativa Abierta y Soberana a FortiRecon & Recorded Future</p>
                </div>
            </div>

            <!-- Actions & Status -->
            <div class="flex items-center gap-3">
                <button onclick="window.print()" class="px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium text-xs border border-cyber-border transition flex items-center gap-2" title="Imprimir o exportar PDF del reporte">
                    <i class="fa-solid fa-file-pdf text-rose-400"></i>
                    <span>Exportar Reporte</span>
                </button>

                <button id="btn-scan" onclick="triggerScan()" class="relative group px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-semibold text-xs shadow-lg shadow-cyan-500/25 hover:from-cyan-400 hover:to-blue-500 transition-all flex items-center gap-2 cursor-pointer">
                    <i id="scan-icon" class="fa-solid fa-radar text-black group-hover:rotate-45 transition-transform"></i>
                    <span id="scan-text">Escanear Superficie</span>
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
                            Métrica basada en puertos de riesgo, desconfiguraciones, fugas de secretos y dominios suplantadores.
                        </p>
                    </div>
                </div>

                <div class="pt-4 border-t border-cyber-border text-[11px] text-slate-400 flex items-center justify-between">
                    <span>Evaluación perimetral continua</span>
                    <span class="text-cyan-400 font-mono">MITRE ATT&CK</span>
                </div>
            </div>

            <!-- Key Metric Counters (Fase 2 Expanded) -->
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
                    <div class="w-10 h-10 rounded-xl bg-amber-950/60 border border-amber-900/40 flex items-center justify-center text-amber-400 mb-3">
                        <i class="fa-solid fa-user-secret"></i>
                    </div>
                    <div>
                        <span class="text-xs text-slate-400 font-medium">Riesgo DRP & Fugas</span>
                        <h3 id="stat-drp" class="text-2xl font-bold text-amber-400 mt-1">0</h3>
                    </div>
                    <span id="stat-leaks-info" class="text-[11px] text-amber-400/90 font-mono mt-2">Phishing / Brechas</span>
                </div>

            </div>
        </section>

        <!-- Navigation Tabs -->
        <div class="flex items-center gap-2 border-b border-cyber-border overflow-x-auto pb-1 text-sm font-medium no-print">
            <button onclick="switchTab('easm')" id="tab-btn-easm" class="tab-btn px-4 py-2.5 rounded-xl bg-slate-800 text-cyan-400 border border-cyan-800/50 flex items-center gap-2 transition">
                <i class="fa-solid fa-globe"></i>
                Superficie de Ataque (EASM)
            </button>
            <button onclick="switchTab('vulns')" id="tab-btn-vulns" class="tab-btn px-4 py-2.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800/50 flex items-center gap-2 transition">
                <i class="fa-solid fa-shield-virus"></i>
                Exposición y Brechas
            </button>
            <button onclick="switchTab('drp')" id="tab-btn-drp" class="tab-btn px-4 py-2.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800/50 flex items-center gap-2 transition">
                <i class="fa-solid fa-masks-theater"></i>
                Protección Digital (DRP)
            </button>
            <button onclick="switchTab('leaks')" id="tab-btn-leaks" class="tab-btn px-4 py-2.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800/50 flex items-center gap-2 transition">
                <i class="fa-solid fa-key text-amber-400"></i>
                Fugas de Credenciales y Secretos
            </button>
            <button onclick="switchTab('seeds')" id="tab-btn-seeds" class="tab-btn px-4 py-2.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800/50 flex items-center gap-2 transition">
                <i class="fa-solid fa-crosshairs"></i>
                Semillas / Dominios
            </button>
        </div>

        <!-- TAB CONTENT: EASM (Assets) -->
        <section id="tab-content-easm" class="space-y-4">
            <div class="flex flex-col sm:flex-row items-center justify-between gap-4">
                <h3 class="text-lg font-bold text-white flex items-center gap-2">
                    <i class="fa-solid fa-server text-cyan-400"></i>
                    Inventario Perimetral Descubierto
                </h3>
                <div class="relative w-full sm:w-72 no-print">
                    <i class="fa-solid fa-magnifying-glass absolute left-3 top-3 text-slate-500 text-xs"></i>
                    <input type="text" id="asset-search" oninput="renderAssetsTable()" placeholder="Buscar subdominio, IP..." class="w-full pl-9 pr-4 py-2 rounded-xl bg-cyber-card border border-cyber-border text-xs text-white focus:outline-none focus:border-cyan-500 transition">
                </div>
            </div>

            <div class="bg-cyber-card border border-cyber-border rounded-2xl overflow-hidden shadow-xl">
                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs">
                        <thead class="bg-slate-900/60 text-slate-400 uppercase text-[10px] tracking-wider border-b border-cyber-border">
                            <tr>
                                <th class="p-4">Activo / Subdominio</th>
                                <th class="p-4">Dirección IP</th>
                                <th class="p-4">Proveedor / CDN</th>
                                <th class="p-4">Puertos Detectados</th>
                                <th class="p-4">Servicio Web / Tecnologías</th>
                                <th class="p-4 text-center">Estado</th>
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

        <!-- TAB CONTENT: Vulnerabilities & Exposures -->
        <section id="tab-content-vulns" class="space-y-4 hidden">
            <div>
                <h3 class="text-lg font-bold text-white flex items-center gap-2">
                    <i class="fa-solid fa-bug text-rose-400"></i>
                    Hallazgos de Exposición y Servicios Críticos
                </h3>
                <p class="text-xs text-slate-400">Puertos de administración o bases de datos expuestos directamente al tráfico de Internet.</p>
            </div>

            <div id="vulns-container" class="space-y-4">
                <!-- Dynamically loaded -->
            </div>
        </section>

        <!-- TAB CONTENT: DRP (Typosquatting & Phishing) -->
        <section id="tab-content-drp" class="space-y-4 hidden">
            <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                <div>
                    <h3 class="text-lg font-bold text-white flex items-center gap-2">
                        <i class="fa-solid fa-shield-cat text-amber-400"></i>
                        Detección de Suplantación y Phishing (Digital Risk Protection)
                    </h3>
                    <p class="text-xs text-slate-400">Variaciones de marca y dominios homóglifos registrados activamente por terceros.</p>
                </div>
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
                        <tbody id="drp-table-body" class="divide-y divide-cyber-border/60 text-slate-300">
                            <!-- Dynamically loaded -->
                        </tbody>
                    </table>
                </div>
            </div>
        </section>

        <!-- TAB CONTENT: Credential Leaks & Exposed Secrets (Fase 2) -->
        <section id="tab-content-leaks" class="space-y-6 hidden">
            
            <!-- Exposed Secrets Card -->
            <div class="bg-cyber-card border border-cyber-border rounded-2xl p-6">
                <div class="flex items-center justify-between mb-4">
                    <div>
                        <h3 class="text-lg font-bold text-white flex items-center gap-2">
                            <i class="fa-solid fa-file-code text-rose-400"></i>
                            Secretos y Archivos Sensibles Expuestos (.env, .git, backups)
                        </h3>
                        <p class="text-xs text-slate-400">Inspección de endpoints desprotegidos que exponen variables de entorno o credenciales de backend.</p>
                    </div>
                </div>

                <div id="secrets-container" class="space-y-3">
                    <!-- Dynamically loaded -->
                </div>
            </div>

            <!-- Credential Breaches Card -->
            <div class="bg-cyber-card border border-cyber-border rounded-2xl p-6">
                <div class="flex items-center justify-between mb-4">
                    <div>
                        <h3 class="text-lg font-bold text-white flex items-center gap-2">
                            <i class="fa-solid fa-address-book text-amber-400"></i>
                            Fugas de Credenciales Corporativas (Breach Intelligence)
                        </h3>
                        <p class="text-xs text-slate-400">Cuentas de correo del dominio corporativo detectadas en filtraciones y bases de datos clandestinas.</p>
                    </div>
                </div>

                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs">
                        <thead class="bg-slate-900/60 text-slate-400 uppercase text-[10px] tracking-wider border-b border-cyber-border">
                            <tr>
                                <th class="p-4">Identidad / Email</th>
                                <th class="p-4">Origen de la Brecha</th>
                                <th class="p-4">Fecha de Publicación</th>
                                <th class="p-4">Impacto / Cuentas</th>
                                <th class="p-4 text-center">Severidad</th>
                            </tr>
                        </thead>
                        <tbody id="leaks-table-body" class="divide-y divide-cyber-border/60 text-slate-300">
                            <!-- Dynamically loaded -->
                        </tbody>
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
                    <input type="text" id="new-seed-domain" required placeholder="ejemplo: tuempresa.com" class="flex-1 px-4 py-2.5 rounded-xl bg-slate-900 border border-cyber-border text-sm text-white focus:outline-none focus:border-cyan-500">
                    <button type="submit" class="px-5 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-sm transition flex items-center justify-center gap-2">
                        <i class="fa-solid fa-satellite-dish"></i>
                        Registrar Semilla
                    </button>
                </form>
            </div>

            <div class="bg-cyber-card border border-cyber-border rounded-2xl overflow-hidden">
                <div class="p-4 border-b border-cyber-border font-bold text-sm text-white flex items-center justify-between">
                    <span>Dominios Actualmente Monitoreados</span>
                    <span id="seeds-count" class="text-xs font-mono text-cyan-400">0 semillas</span>
                </div>
                <div id="seeds-list" class="divide-y divide-cyber-border/60">
                    <!-- Dynamically loaded -->
                </div>
            </div>
        </section>

    </main>

    <!-- Takedown Modal (RFC Abuse Notification) -->
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

        async function init() {
            await Promise.all([
                loadStats(),
                loadAssets(),
                loadVulns(),
                loadDrp(),
                loadLeaks(),
                loadSeeds()
            ]);
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

            ['easm', 'vulns', 'drp', 'leaks', 'seeds'].forEach(t => {
                const el = document.getElementById(`tab-content-${t}`);
                if (el) el.classList.toggle('hidden', t !== tabId);
            });
        }

        // Load Stats
        async function loadStats() {
            try {
                const res = await fetch(`${API_URL}?action=get_stats`);
                const data = await res.json();

                const score = data.exposure_score ?? 100;
                document.getElementById('score-val').innerText = score;
                
                // Color circle
                const circle = document.getElementById('score-circle');
                const offset = 301 - (301 * score / 100);
                circle.style.strokeDashoffset = offset;

                const postureBadge = document.getElementById('posture-badge');
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

                document.getElementById('stat-assets').innerText = data.total_assets || 0;
                document.getElementById('stat-live').innerText = `${data.live_assets || 0} activos vivos`;
                document.getElementById('stat-ports').innerText = data.open_ports || 0;
                document.getElementById('stat-vulns').innerText = data.vulnerabilities.total || 0;
                document.getElementById('stat-crit-vulns').innerText = `${data.vulnerabilities.critical + data.vulnerabilities.high} críticas / altas`;
                
                const totalThreats = (data.drp_threats || 0) + (data.credential_leaks || 0) + (data.exposed_secrets || 0);
                document.getElementById('stat-drp').innerText = totalThreats;
                document.getElementById('stat-leaks-info').innerText = `${data.credential_leaks || 0} fugas / ${data.drp_threats || 0} clones`;

            } catch (err) {
                console.error(err);
            }
        }

        // Load Assets
        async function loadAssets() {
            try {
                const res = await fetch(`${API_URL}?action=get_assets`);
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
                tbody.innerHTML = `<tr><td colspan="6" class="p-8 text-center text-slate-500">No se encontraron activos perimetrales coincidentes. Ejecuta un escaneo para descubrirlos.</td></tr>`;
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

                return `
                    <tr class="hover:bg-slate-800/40 transition">
                        <td class="p-4 font-mono font-medium text-white flex items-center gap-2">
                            <i class="fa-solid fa-globe text-cyan-500/70"></i>
                            <a href="https://${a.subdomain}" target="_blank" class="hover:text-cyan-400 underline decoration-cyan-500/30">${a.subdomain}</a>
                        </td>
                        <td class="p-4 font-mono text-slate-400">${a.ip_address || '<span class="text-slate-600">No resuelve</span>'}</td>
                        <td class="p-4">${cloudBadge}</td>
                        <td class="p-4 flex flex-wrap gap-1 max-w-xs">${portsBadges}</td>
                        <td class="p-4 max-w-xs truncate">
                            <span class="text-white block font-medium truncate" title="${a.web_title || ''}">${a.web_title || '<span class="text-slate-600 italic">Sin título HTTP</span>'}</span>
                            <span class="text-[10px] text-slate-400">${a.tech_stack || ''}</span>
                        </td>
                        <td class="p-4 text-center">
                            ${a.is_live ? 
                                '<span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-800/60"><span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>ONLINE</span>' : 
                                '<span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-bold bg-slate-900 text-slate-500 border border-slate-800">OFFLINE</span>'}
                        </td>
                    </tr>
                `;
            }).join('');
        }

        // Load Vulnerabilities
        async function loadVulns() {
            try {
                const res = await fetch(`${API_URL}?action=get_vulnerabilities`);
                const vulns = await res.json();
                const container = document.getElementById('vulns-container');

                if (vulns.length === 0) {
                    container.innerHTML = `
                        <div class="bg-cyber-card border border-cyber-border rounded-2xl p-8 text-center text-slate-400">
                            <i class="fa-solid fa-shield-heart text-3xl text-emerald-400 mb-2 block"></i>
                            <p class="font-bold text-white text-base">Sin vulnerabilidades críticas expuestas</p>
                            <p class="text-xs text-slate-500 mt-1">Los puertos de bases de datos y administración remota están protegidos correctamente.</p>
                        </div>
                    `;
                    return;
                }

                container.innerHTML = vulns.map(v => {
                    let badgeColor = 'bg-rose-950 text-rose-400 border-rose-800';
                    if (v.severity === 'HIGH') badgeColor = 'bg-orange-950 text-orange-400 border-orange-800';
                    if (v.severity === 'MEDIUM') badgeColor = 'bg-amber-950 text-amber-400 border-amber-800';

                    return `
                        <div class="bg-cyber-card border border-cyber-border rounded-2xl p-5 hover:border-slate-700 transition">
                            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-3">
                                <div class="flex items-center gap-2">
                                    <span class="px-2 py-0.5 rounded text-[10px] font-bold border uppercase tracking-wider ${badgeColor}">${v.severity}</span>
                                    <h4 class="font-bold text-white text-sm">${v.title}</h4>
                                </div>
                                <span class="font-mono text-xs text-cyan-400 bg-slate-900 px-2 py-1 rounded border border-cyber-border">
                                    Activo: ${v.asset_subdomain}
                                </span>
                            </div>
                            <p class="text-xs text-slate-300 leading-relaxed mb-3">${v.description}</p>
                            <div class="p-3 bg-slate-900/80 rounded-xl border border-cyber-border text-xs">
                                <div class="flex items-center gap-1.5 text-emerald-400 font-bold mb-1">
                                    <i class="fa-solid fa-wrench"></i> Remediación Sugerida:
                                </div>
                                <p class="text-slate-400 text-[11px] leading-relaxed">${v.remediation}</p>
                            </div>
                        </div>
                    `;
                }).join('');

            } catch (err) {
                console.error(err);
            }
        }

        // Load DRP Threats
        async function loadDrp() {
            try {
                const res = await fetch(`${API_URL}?action=get_drp`);
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

        // Load Leaks & Secrets (Fase 2)
        async function loadLeaks() {
            try {
                // Exposed Secrets
                const resSec = await fetch(`${API_URL}?action=get_exposed_secrets`);
                const secrets = await resSec.json();
                const secContainer = document.getElementById('secrets-container');

                if (secrets.length === 0) {
                    secContainer.innerHTML = `
                        <div class="p-4 rounded-xl bg-slate-900/60 border border-cyber-border text-center text-xs text-slate-500">
                            No se han detectado archivos .env o repositorios .git expuestos al público.
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

                // Credential Leaks
                const resLeaks = await fetch(`${API_URL}?action=get_credential_leaks`);
                const leaks = await resLeaks.json();
                const tbody = document.getElementById('leaks-table-body');

                if (leaks.length === 0) {
                    tbody.innerHTML = `<tr><td colspan="5" class="p-8 text-center text-slate-500">No se han registrado credenciales corporativas en brechas públicas recientes.</td></tr>`;
                    return;
                }

                tbody.innerHTML = leaks.map(l => `
                    <tr class="hover:bg-slate-800/40 transition">
                        <td class="p-4 font-mono font-bold text-white flex items-center gap-2">
                            <i class="fa-solid fa-user-shield text-cyan-400"></i>
                            ${l.email}
                        </td>
                        <td class="p-4 text-slate-300">${l.source_breach}</td>
                        <td class="p-4 text-slate-400 font-mono text-[11px]">${l.breach_date || '-'}</td>
                        <td class="p-4 text-slate-400">${l.pwn_count} registros</td>
                        <td class="p-4 text-center">
                            <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-400 border border-amber-800">${l.severity}</span>
                        </td>
                    </tr>
                `).join('');

            } catch (err) {
                console.error(err);
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

        // Load Seeds
        async function loadSeeds() {
            try {
                const res = await fetch(`${API_URL}?action=get_seeds`);
                const seeds = await res.json();
                document.getElementById('seeds-count').innerText = `${seeds.length} semillas`;

                const list = document.getElementById('seeds-list');
                if (seeds.length === 0) {
                    list.innerHTML = `<p class="p-6 text-center text-xs text-slate-500">No hay semillas configuradas.</p>`;
                    return;
                }

                list.innerHTML = seeds.map(s => `
                    <div class="p-4 flex items-center justify-between hover:bg-slate-800/30 transition">
                        <div class="flex items-center gap-3">
                            <div class="w-8 h-8 rounded-lg bg-cyan-950/60 border border-cyan-800/50 flex items-center justify-center text-cyan-400">
                                <i class="fa-solid fa-globe"></i>
                            </div>
                            <div>
                                <h4 class="font-bold text-white text-sm font-mono">${s.domain}</h4>
                                <span class="text-[10px] text-slate-500">Registrado el ${s.created_at}</span>
                            </div>
                        </div>
                        <button onclick="handleDeleteSeed(${s.id})" class="p-2 text-slate-500 hover:text-rose-400 hover:bg-rose-950/30 rounded-lg transition" title="Eliminar semilla">
                            <i class="fa-solid fa-trash-can"></i>
                        </button>
                    </div>
                `).join('');

            } catch (err) {
                console.error(err);
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
                    showToast(`Semilla ${domain} agregada exitosamente`);
                    await loadSeeds();
                } else {
                    showToast(data.error || 'Error al agregar', true);
                }
            } catch (err) {
                showToast('Error de conexión', true);
            }
        }

        // Delete Seed
        async function handleDeleteSeed(id) {
            if (!confirm('¿Deseas eliminar este dominio de la vigilancia?')) return;
            const form = new FormData();
            form.append('id', id);
            try {
                const res = await fetch(`${API_URL}?action=delete_seed`, { method: 'POST', body: form });
                const data = await res.json();
                if (data.success) {
                    showToast('Semilla eliminada');
                    await loadSeeds();
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
            text.innerText = 'Escaneando superficie...';
            showToast('Iniciando reconocimiento exhaustivo (EASM + DRP + Secretos)...');

            try {
                const res = await fetch(`${API_URL}?action=run_scan`);
                const data = await res.json();

                if (data.success) {
                    showToast(`¡Escaneo finalizado! ${data.summary.assets_cataloged} activos analizados.`);
                    await init();
                } else {
                    showToast(data.error || 'Fallo durante el escaneo', true);
                }
            } catch (err) {
                showToast('Error ejecutando el escaneo perimetral', true);
            } finally {
                btn.disabled = false;
                btn.classList.remove('opacity-75');
                icon.className = 'fa-solid fa-radar text-black group-hover:rotate-45 transition-transform';
                text.innerText = 'Escanear Superficie';
            }
        }

        window.onload = init;
    </script>
</body>
</html>
