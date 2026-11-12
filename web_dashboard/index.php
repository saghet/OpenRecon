<!DOCTYPE html>
<html lang="es" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenRecon | EASM, DRP, CTI & Attack Surface Management</title>
    <!-- Core Local CSS & Anti-FOUC Foundation (Render-Blocking) -->
    <link rel="stylesheet" href="assets/css/openrecon-styles.css">
    <!-- Local FontAwesome 6.5.1 -->
    <link rel="stylesheet" href="assets/vendor/fontawesome/css/all.min.css">
    <!-- Local Tailwind Engine -->
    <!-- Local Tailwind Engine -->
    <script src="assets/js/tailwindcss.min.js"></script>
    <script>
        // =============================================================
        // STAGE 3 CLIENT-SIDE CONTROLLERS (Connectors, Scope, Cloud, AI)
        // =============================================================

        // Connectors State
        let globalConnectors = [];
        let currentConnectorFilter = 'ALL';

        async function loadConnectors() {
            try {
                const res = await fetch(`${API_URL}?action=get_connectors`);
                const data = await res.json();
                if (data.success) {
                    globalConnectors = data.connectors || [];
                    document.getElementById('conn-stat-total').innerText = data.counts.total || 16;
                    document.getElementById('conn-stat-free').innerText = data.counts.free || 6;
                    document.getElementById('conn-stat-api').innerText = data.counts.api_key || 6;
                    document.getElementById('conn-stat-comm').innerText = data.counts.commercial || 4;
                    renderConnectorsGrid();
                }
            } catch (e) {
                console.error("Error loading connectors:", e);
            }
        }

        function filterConnectorsList(cat) {
            currentConnectorFilter = cat;
            ['ALL', 'FREE', 'API_KEY', 'COMMERCIAL'].forEach(c => {
                const btn = document.getElementById(`conn-filter-${c}`);
                if (btn) {
                    if (c === cat) {
                        btn.className = 'px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 text-teal-300 border border-teal-800/60 transition';
                    } else {
                        btn.className = 'px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-400 hover:text-white hover:bg-slate-800 transition';
                    }
                }
            });
            renderConnectorsGrid();
        }

        function renderConnectorsGrid() {
            const grid = document.getElementById('connectors-grid');
            if (!grid) return;

            let filtered = globalConnectors;
            if (currentConnectorFilter !== 'ALL') {
                filtered = globalConnectors.filter(c => c.category === currentConnectorFilter);
            }

            grid.innerHTML = filtered.map(c => {
                let catBadge = '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">GRATUITO</span>';
                if (c.category === 'API_KEY') {
                    catBadge = '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-300 border border-amber-800">API KEY</span>';
                } else if (c.category === 'COMMERCIAL') {
                    catBadge = '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-indigo-950 text-indigo-300 border border-indigo-800">COMERCIAL</span>';
                }

                const isEnabled = parseInt(c.is_enabled) === 1;
                const toggleBadge = isEnabled ?
                    '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-800 flex items-center gap-1"><i class="fa-solid fa-circle text-[6px]"></i>ACTIVO</span>' :
                    '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-900 text-slate-500 border border-slate-800 flex items-center gap-1"><i class="fa-solid fa-circle text-[6px]"></i>INACTIVO</span>';

                return `
                    <div class="bg-cyber-card border border-cyber-border rounded-xl p-5 flex flex-col justify-between space-y-4 hover:border-slate-700 transition">
                        <div>
                            <div class="flex items-center justify-between mb-2">
                                <h4 class="font-bold text-white text-sm flex items-center gap-2">
                                    <i class="fa-solid fa-satellite-dish text-teal-400"></i>
                                    ${c.name}
                                </h4>
                                ${catBadge}
                            </div>
                            <p class="text-xs text-slate-400 line-clamp-2">${c.description || ''}</p>
                            <div class="mt-3 pt-3 border-t border-cyber-border text-[11px] font-mono space-y-1">
                                <div class="flex justify-between text-slate-400">
                                    <span>Auth:</span> <strong class="text-slate-300">${c.auth_type}</strong>
                                </div>
                                <div class="flex justify-between text-slate-400">
                                    <span>Clave:</span> <strong class="text-slate-300">${c.api_key_masked || 'Sin requerimiento'}</strong>
                                </div>
                                <div class="flex justify-between text-slate-400">
                                    <span>Sincronizados:</span> <strong class="text-teal-400">${c.items_synced || 0} items</strong>
                                </div>
                            </div>
                        </div>

                        <div class="flex items-center justify-between pt-2 border-t border-cyber-border">
                            ${toggleBadge}
                            <button onclick="openConnectorConfigModal('${c.connector_id}', '${c.name}', ${isEnabled})" class="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold flex items-center gap-1.5 transition">
                                <i class="fa-solid fa-gear"></i>
                                <span>Configurar</span>
                            </button>
                        </div>
                    </div>
                `;
            }).join('');
        }

        function openConnectorConfigModal(id, name, isEnabled) {
            document.getElementById('conn-modal-id').value = id;
            document.getElementById('conn-modal-title').innerHTML = `<i class="fa-solid fa-key text-teal-400"></i> Configurar: ${name}`;
            document.getElementById('conn-modal-enabled').checked = isEnabled;
            document.getElementById('conn-modal-key').value = '';
            document.getElementById('connector-config-modal').classList.remove('hidden');
        }

        function closeConnectorConfigModal() {
            document.getElementById('connector-config-modal').classList.add('hidden');
        }

        async function handleSaveConnectorKey(e) {
            e.preventDefault();
            const id = document.getElementById('conn-modal-id').value;
            const key = document.getElementById('conn-modal-key').value;
            const enabled = document.getElementById('conn-modal-enabled').checked ? '1' : '0';

            const form = new FormData();
            form.append('connector_id', id);
            form.append('is_enabled', enabled);
            if (key) form.append('api_key', key);

            try {
                const res = await fetch(`${API_URL}?action=update_connector`, { method: 'POST', body: form });
                const data = await res.json();
                if (data.success) {
                    showToast(data.message);
                    closeConnectorConfigModal();
                    await loadConnectors();
                } else {
                    showToast(data.error || 'Error al guardar', true);
                }
            } catch (err) {
                showToast('Fallo al conectar con el servidor', true);
            }
        }

        async function syncCtiFeedsLive() {
            showToast('Sincronizando feeds de CTI en vivo (CISA KEV, IPsum, Ransomwatch)...');
            try {
                const res = await fetch(`${API_URL}?action=sync_cti`);
                const data = await res.json();
                if (data.success) {
                    showToast(`CTI Sincronizado: ${data.iocs_ingested} IoCs y ${data.ransomware_ingested} posts de ransomware actualizados.`);
                    await Promise.all([loadStats(), loadConnectors(), loadCti()]);
                } else {
                    showToast('Fallo en sincronización CTI', true);
                }
            } catch (err) {
                showToast('Error al ejecutar sincronización', true);
            }
        }

        // Scope Management
        let globalScope = [];
        async function loadScope() {
            try {
                const res = await fetch(`${API_URL}?action=get_scope`);
                const data = await res.json();
                if (data.success) {
                    globalScope = data.scope || [];
                    document.getElementById('scope-count').innerText = globalScope.length;
                    renderScopeTable(globalScope);
                }
            } catch (err) {
                console.error("Error loading scope:", err);
            }
        }

        function renderScopeTable(list) {
            const tbody = document.getElementById('scope-table-body');
            if (!tbody) return;

            if (list.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="p-8 text-center text-slate-500 font-sans">No hay objetivos de alcance registrados.</td></tr>';
                return;
            }

            tbody.innerHTML = list.map(s => `
                <tr class="hover:bg-slate-800/40 transition">
                    <td class="p-3 font-bold text-white flex items-center gap-1.5">
                        <i class="fa-solid fa-bullseye text-cyan-400"></i>
                        ${s.target_pattern}
                    </td>
                    <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-cyan-300 border border-slate-700">${s.scope_type}</span></td>
                    <td class="p-3 text-slate-300">${s.authorized_by}</td>
                    <td class="p-3 text-slate-400">${s.created_at}</td>
                    <td class="p-3 text-slate-400 font-sans text-xs">${s.notes || '-'}</td>
                    <td class="p-3 text-center">
                        <button onclick="deleteScopeEntry(${s.id})" class="text-rose-400 hover:text-rose-300 px-2 py-1 rounded hover:bg-rose-950/40 transition" title="Revocar alcance"><i class="fa-solid fa-trash"></i></button>
                    </td>
                </tr>
            `).join('');
        }

        function filterScopeTable() {
            const q = (document.getElementById('scope-filter-search')?.value || '').toLowerCase().trim();
            const filtered = globalScope.filter(s => s.target_pattern.toLowerCase().includes(q) || (s.notes || '').toLowerCase().includes(q));
            renderScopeTable(filtered);
        }

        async function handleAddScopeSubmit(e) {
            e.preventDefault();
            const pattern = document.getElementById('scope-input-pattern').value.trim();
            const type = document.getElementById('scope-input-type').value;
            const notes = document.getElementById('scope-input-notes').value.trim();

            const form = new FormData();
            form.append('target_pattern', pattern);
            form.append('scope_type', type);
            form.append('notes', notes);

            try {
                const res = await fetch(`${API_URL}?action=add_scope`, { method: 'POST', body: form });
                const data = await res.json();
                if (data.success) {
                    showToast(data.message);
                    document.getElementById('scope-input-pattern').value = '';
                    document.getElementById('scope-input-notes').value = '';
                    await loadScope();
                } else {
                    showToast(data.error || 'Error al autorizar objetivo', true);
                }
            } catch (err) {
                showToast('Fallo de conexión al guardar alcance', true);
            }
        }

        async function deleteScopeEntry(id) {
            if (!confirm('¿Confirmas revocar y eliminar esta regla de alcance autorizado?')) return;
            const form = new FormData();
            form.append('id', id);
            try {
                const res = await fetch(`${API_URL}?action=delete_scope`, { method: 'POST', body: form });
                const data = await res.json();
                if (data.success) {
                    showToast(data.message);
                    await loadScope();
                } else {
                    showToast(data.error || 'Error al eliminar', true);
                }
            } catch (err) {
                showToast('Fallo al conectar', true);
            }
        }

        // Cloud Security Exposure
        async function loadCloudExposure() {
            try {
                const res = await fetch(`${API_URL}?action=get_cloud_exposure${getSeedQueryParam()}`);
                const data = await res.json();
                if (data.success) {
                    renderCloudTable(data.exposures || []);
                }
            } catch (err) {
                console.error("Error loading cloud:", err);
            }
        }

        function renderCloudTable(list) {
            const tbody = document.getElementById('cloud-table-body');
            if (!tbody) return;

            if (list.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="p-8 text-center text-slate-500 font-sans">No se han registrado recursos cloud expuestos para esta semilla.</td></tr>';
                return;
            }

            tbody.innerHTML = list.map(c => {
                let badge = '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-400 border border-slate-700">ACCESO RESTRINGIDO (403)</span>';
                if (c.status === 'PUBLIC_LISTABLE') {
                    badge = '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-300 border border-rose-800 animate-pulse"><i class="fa-solid fa-triangle-exclamation mr-1"></i>PÚBLICO LISTABLE (CRÍTICO)</span>';
                }

                return `
                    <tr class="hover:bg-slate-800/40 transition">
                        <td class="p-3 font-bold text-white font-sans">${c.provider}</td>
                        <td class="p-3 text-cyan-400 font-bold">${c.resource_name}</td>
                        <td class="p-3"><a href="${c.url}" target="_blank" class="hover:underline text-slate-300">${c.url}</a></td>
                        <td class="p-3">${badge}</td>
                        <td class="p-3 text-slate-400 font-sans text-xs">${c.details || '-'}</td>
                        <td class="p-3 text-slate-500">${c.detected_at}</td>
                    </tr>
                `;
            }).join('');
        }

        async function triggerCloudScan() {
            showToast('Sondeando almacenamiento público (AWS S3, Azure Blob, GCP Storage)...');
            const form = new FormData();
            form.append('seed', activeSeed || 'vulnweb.com');
            try {
                const res = await fetch(`${API_URL}?action=scan_cloud_exposure`, { method: 'POST', body: form });
                const data = await res.json();
                if (data.success) {
                    showToast(`Sondeo finalizado: ${data.permutations_scanned} permutaciones cloud evaluadas.`);
                    await loadCloudExposure();
                } else {
                    showToast(data.error || 'Fallo en sondeo cloud', true);
                }
            } catch (err) {
                showToast('Error ejecutando auditoría cloud', true);
            }
        }

        // Risk Breakdown Modal
        async function openRiskBreakdownModal() {
            const modal = document.getElementById('risk-breakdown-modal');
            const content = document.getElementById('risk-breakdown-content');
            modal.classList.remove('hidden');
            content.innerHTML = '<div class="text-center py-12 text-slate-400"><i class="fa-solid fa-spinner fa-spin text-2xl mb-2 block"></i>Calculando desglose explicable de riesgo...</div>';

            try {
                const res = await fetch(`${API_URL}?action=get_risk_score_breakdown${getSeedQueryParam()}`);
                const data = await res.json();
                if (data.success) {
                    renderRiskBreakdown(data.assessment);
                } else {
                    content.innerHTML = '<div class="text-rose-400 p-4">Error obteniendo desglose.</div>';
                }
            } catch (err) {
                content.innerHTML = '<div class="text-rose-400 p-4">Fallo de comunicación con la API.</div>';
            }
        }

        function closeRiskBreakdownModal() {
            document.getElementById('risk-breakdown-modal').classList.add('hidden');
        }

        function renderRiskBreakdown(a) {
            const content = document.getElementById('risk-breakdown-content');
            if (!content || !a) return;

            let levelColor = 'text-emerald-400 border-emerald-800 bg-emerald-950/60';
            if (a.risk_level === 'CRÍTICO') levelColor = 'text-rose-400 border-rose-800 bg-rose-950/60';
            if (a.risk_level === 'ALTO') levelColor = 'text-orange-400 border-orange-800 bg-orange-950/60';
            if (a.risk_level === 'MEDIO') levelColor = 'text-amber-400 border-amber-800 bg-amber-950/60';

            const factorsHtml = (a.factors || []).map(f => {
                let evidenceList = '';
                if (f.evidence && f.evidence.length > 0) {
                    evidenceList = `
                        <div class="mt-2 pt-2 border-t border-cyber-border font-mono text-[11px] text-slate-400 space-y-0.5">
                            <strong class="text-slate-300 block text-[10px] uppercase">Evidencias Verificadas:</strong>
                            ${f.evidence.map(e => `<div>• ${e}</div>`).join('')}
                        </div>
                    `;
                }
                return `
                    <div class="bg-slate-900 border border-cyber-border rounded-xl p-4 space-y-2">
                        <div class="flex items-center justify-between">
                            <span class="font-bold text-white text-sm">${f.category}</span>
                            <span class="px-2.5 py-1 rounded text-xs font-mono font-bold bg-rose-950 text-rose-300 border border-rose-800">+${f.points} pts</span>
                        </div>
                        <p class="text-slate-400 text-xs">${f.description}</p>
                        <div class="text-[11px] text-slate-500 font-mono">Ponderación: ${f.weight}</div>
                        ${evidenceList}
                    </div>
                `;
            }).join('');

            content.innerHTML = `
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div class="bg-slate-900 border border-cyber-border rounded-xl p-5 flex items-center gap-4">
                        <div class="text-4xl font-black text-rose-400 font-mono">${a.risk_score} <span class="text-xs text-slate-500">/ 100</span></div>
                        <div>
                            <span class="text-xs text-slate-400 block font-medium">Nivel de Riesgo EASM</span>
                            <span class="px-2 py-0.5 rounded text-xs font-bold border ${levelColor}">${a.risk_level}</span>
                        </div>
                    </div>
                    <div class="bg-slate-900 border border-cyber-border rounded-xl p-5 flex items-center gap-4">
                        <div class="text-4xl font-black text-emerald-400 font-mono">${a.posture_score} <span class="text-xs text-slate-500">/ 100</span></div>
                        <div>
                            <span class="text-xs text-slate-400 block font-medium">Postura de Resiliencia</span>
                            <strong class="text-white text-sm block">${a.posture_level}</strong>
                        </div>
                    </div>
                </div>

                <div class="space-y-3">
                    <h4 class="text-xs font-bold text-slate-400 uppercase tracking-wider">Factores de Riesgo Identificados (${(a.factors || []).length})</h4>
                    ${factorsHtml || '<div class="p-4 bg-slate-900 rounded-xl text-slate-500 text-center">No hay factores que aumenten el riesgo. Postura óptima.</div>'}
                </div>

                <div class="p-3 bg-slate-950 rounded-xl border border-cyber-border text-[11px] text-slate-400">
                    <i class="fa-solid fa-info-circle text-cyan-400 mr-1"></i>
                    ${a.methodology || 'Metodología EASM explicable.'}
                </div>
            `;
        }

        // AI Correlation
        async function triggerAiCorrelation() {
            const container = document.getElementById('ai-report-container');
            const btn = document.getElementById('btn-run-ai');
            if (btn) btn.disabled = true;

            container.innerHTML = `
                <div class="text-center py-16 text-slate-400">
                    <i class="fa-solid fa-spinner fa-spin text-3xl text-purple-400 mb-3 block"></i>
                    <strong class="text-white text-sm block font-bold">Correlacionando Telemetría con Inteligencia Artificial...</strong>
                    <p class="text-xs text-slate-500 mt-1">Auditando activos, puertos, CISA KEV y vectores MITRE ATT&CK.</p>
                </div>
            `;

            try {
                const res = await fetch(`${API_URL}?action=ai_correlate_evidence&seed=${encodeURIComponent(activeSeed || 'vulnweb.com')}`);
                const data = await res.json();
                if (data.success) {
                    renderAiMarkdownReport(data.report_markdown);
                } else {
                    container.innerHTML = '<div class="text-rose-400 p-4">Error generando análisis de IA.</div>';
                }
            } catch (err) {
                container.innerHTML = '<div class="text-rose-400 p-4">Fallo de comunicación con el motor de IA.</div>';
            } finally {
                if (btn) btn.disabled = false;
            }
        }

        function renderAiMarkdownReport(md) {
            const container = document.getElementById('ai-report-container');
            if (!container) return;

            // Simple fast client-side markdown formatter
            let html = md
                .replace(/^# (.*$)/gim, '<h1 class="text-lg font-black text-white mb-2 pb-2 border-b border-cyber-border">$1</h1>')
                .replace(/^## (.*$)/gim, '<h2 class="text-sm font-bold text-teal-300 mt-4 mb-2 flex items-center gap-1.5">$1</h2>')
                .replace(/^### (.*$)/gim, '<h3 class="text-xs font-bold text-white mt-3 mb-1">$1</h3>')
                .replace(/^> (.*$)/gim, '<blockquote class="p-3 rounded-xl bg-slate-900 border-l-4 border-purple-500 text-slate-300 text-xs my-2">$1</blockquote>')
                .replace(/\*\*(.*?)\*\*/gim, '<strong class="text-white font-bold">$1</strong>')
                .replace(/`([^`]+)`/gim, '<code class="px-1.5 py-0.5 rounded bg-slate-900 text-cyan-300 font-mono text-[11px]">$1</code>')
                .replace(/^- (.*$)/gim, '<li class="ml-4 list-disc text-slate-300 my-1">$1</li>')
                .replace(/\n/g, '<br>');

            container.innerHTML = `<div class="space-y-3">${html}</div>`;
        }

        // Enhance switchTab to cover all Stage 3 tabs
        const originalSwitchTab = switchTab;
        switchTab = function(tabId) {
            document.querySelectorAll('.tab-btn').forEach(btn => {
                btn.className = 'tab-btn px-4 py-2.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800/50 flex items-center gap-2 transition';
            });
            const activeBtn = document.getElementById(`tab-btn-${tabId}`);
            if (activeBtn) {
                activeBtn.className = 'tab-btn px-4 py-2.5 rounded-xl bg-slate-800 text-cyan-400 border border-cyan-800/50 flex items-center gap-2 transition';
            }

            const allTabs = ['easm', 'graph', 'vulns', 'drp', 'leaks', 'cti', 'seeds', 'strix', 'loginrecon', 'php2shell', 'connectors', 'scope', 'cloud', 'ai', 'darkintel', 'emailintel'];
            allTabs.forEach(t => {
                const el = document.getElementById(`tab-content-${t}`);
                if (el) el.classList.toggle('hidden', t !== tabId);
            });

            if (tabId === 'connectors') loadConnectors();
            if (tabId === 'scope') loadScope();
            if (tabId === 'cloud') loadCloudExposure();
            if (tabId === 'graph' && networkInstance) setTimeout(() => { networkInstance.fit(); }, 100);
            if (tabId === 'strix') populateStrixAssetDropdown();
            if (tabId === 'loginrecon') populateLoginReconPresets();
            if (tabId === 'darkintel') {
                if (typeof darkIntelLoadOverview === 'function') darkIntelLoadOverview();
                if (typeof darkIntelSyncWithGlobalSeeds === 'function') darkIntelSyncWithGlobalSeeds();
            }
            if (tabId === 'emailintel') {
                if (typeof emailIntelLoadOverview === 'function') emailIntelLoadOverview();
            }
        };

        // Handler for updating vulnerability validation state
        async function handleValidationStateChange(vulnId, newState) {
            const form = new FormData();
            form.append('id', vulnId);
            form.append('validation_state', newState);

            try {
                const res = await fetch(`${API_URL}?action=update_vuln_validation`, { method: 'POST', body: form });
                const data = await res.json();
                if (data.success) {
                    showToast(`Estado de validación actualizado a: ${newState}`);
                    await Promise.all([loadStats(), loadVulns()]);
                } else {
                    showToast(data.error || 'Error actualizando validación', true);
                }
            } catch (err) {
                showToast('Fallo de conexión al actualizar validación', true);
            }
        }

</script>
    <!-- Local Chart.js & Vis-Network -->
    <script src="assets/vendor/chart.min.js"></script>
    <script src="assets/vendor/vis-network.min.js"></script>
    <script>
        if (typeof tailwind !== 'undefined') {
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
            };
        }
    </script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');
        body { font-family: 'Inter', system-ui, -apple-system, sans-serif; background-color: #07090e; }
        .font-mono { font-family: 'JetBrains Mono', monospace; }
        #network-canvas { width: 100%; height: 580px; background: radial-gradient(circle at center, #0f172a 0%, #07090e 100%); }
    </style>
</head>
<body class="text-slate-200 min-h-screen flex flex-col antialiased selection:bg-emerald-500 selection:text-black">

    <!-- Main FortiOS Shell Container -->
    <div id="forti-app-shell">

    <!-- Fortinet FortiOS 7.4.13 Top Navigation Bar -->
    <header id="forti-topbar" class="no-print">
        <!-- Left: Hamburger toggle + Branding -->
        <div class="flex items-center gap-3">
            <!-- Emergency Kill Switch Quick Button -->
            <button id="btn-top-kill-switch" onclick="handleToggleKillSwitchUI()" class="px-2.5 py-1 rounded text-xs font-semibold flex items-center gap-1.5 border border-slate-700 bg-slate-900/80 text-slate-300 hover:border-rose-700 hover:text-rose-300 transition" title="Parada de Emergencia de Escaneos (Kill-Switch)">
                <i class="fa-solid fa-power-off text-emerald-400" id="kill-switch-icon"></i>
                <span id="kill-switch-label">RO-GUARD: NORMAL</span>
            </button>
            <button onclick="toggleFortiSidebar()" class="w-8 h-8 rounded flex items-center justify-center text-slate-300 hover:text-white hover:bg-white/10 transition" title="Contraer/Expandir Menú de Navegación [Ctrl+B]">
                <i class="fa-solid fa-bars text-sm"></i>
            </button>
            <div class="flex items-center gap-2 cursor-pointer" onclick="switchTab('easm')">
                <div class="w-7 h-7 rounded bg-gradient-to-tr from-emerald-600 to-teal-400 flex items-center justify-center text-black font-extrabold text-sm shadow">
                    <i class="fa-solid fa-shield-halved"></i>
                </div>
                <div class="flex flex-col">
                    <div class="flex items-center gap-1.5 leading-none">
                        <span class="font-extrabold text-sm tracking-tight text-white">Open<span style="color:var(--fg-accent)">Recon</span></span>
                        <span class="px-1.5 py-0.2 rounded text-[9px] font-mono font-bold bg-black/40 border border-white/10 text-emerald-400 flex items-center gap-1">
                            <span class="forti-pulse-dot"></span> v7.4.13
                        </span>
                    </div>
                    <span class="text-[9px] text-slate-400 font-mono tracking-wider">ENTERPRISE EASM & DRP CONSOLE</span>
                </div>
            </div>
        </div>

        <!-- Center: Search + Perimeter VDOM Selector -->
        <div class="hidden md:flex items-center gap-3">
            <!-- Global Search -->
            <div class="relative w-64 lg:w-80">
                <i class="fa-solid fa-magnifying-glass absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400 text-xs pointer-events-none"></i>
                <input id="forti-global-search" type="search" placeholder="Buscar activos, CVEs, IPs, IoCs... [Ctrl+K]" oninput="handleGlobalSearch(this.value)" class="forti-input w-full pl-8 pr-12 text-xs h-7 rounded" autocomplete="off" />
                <span class="absolute right-2 top-1/2 -translate-y-1/2 text-[10px] font-mono text-slate-500 border border-slate-700 rounded px-1">Ctrl+K</span>
            </div>

            <!-- Dynamic Seed Selector (VDOM Style) -->
            <div class="flex items-center gap-1.5 px-2.5 py-1 rounded bg-black/30 border border-white/10 shadow-inner">
                <i class="fa-solid fa-crosshairs text-xs" style="color:var(--fg-accent)"></i>
                <span class="text-[11px] text-slate-400 font-semibold">Perímetro:</span>
                <select id="active-seed-selector" onchange="onActiveSeedChange(this.value)" class="bg-transparent text-white font-mono text-xs font-bold focus:outline-none cursor-pointer">
                    <option value="ALL" class="bg-slate-900 text-white">Cargando semillas...</option>
                </select>
            </div>
        </div>

        <!-- Right: Actions, Density, Theme Selector & Analyst Profile -->
        <div class="flex items-center gap-2">
            <!-- Quick Action: Scan -->
            <button id="btn-scan" onclick="triggerScan()" class="forti-btn-primary h-7 text-xs px-2.5 rounded font-semibold" title="Iniciar análisis perimetral asíncrono">
                <i id="scan-icon" class="fa-solid fa-radar text-xs"></i>
                <span id="scan-text" class="hidden sm:inline">Escanear</span>
            </button>

            <!-- Quick Action: CTI Sync -->
            <button onclick="syncCti()" class="forti-btn-secondary h-7 text-xs px-2 rounded" title="Sincronizar feeds de inteligencia de amenazas (CTI, CISA KEV, Ransomwatch)">
                <i id="sync-icon" class="fa-solid fa-arrows-rotate text-xs"></i>
                <span class="hidden xl:inline">Sync CTI</span>
            </button>

            <!-- Quick Action: Report PDF -->
            <a id="btn-report-link" href="report.php" target="_blank" class="forti-btn-secondary h-7 text-xs px-2 rounded" title="Generar Informe Ejecutivo Formal PDF">
                <i class="fa-solid fa-file-pdf text-rose-400 text-xs"></i>
                <span class="hidden xl:inline">Reporte</span>
            </a>

            <!-- Quick Action: Roadmap -->
            <button onclick="openPlanModal()" class="forti-btn-secondary h-7 text-xs px-2 rounded" title="Ver plan de trabajo y hoja de ruta">
                <i class="fa-solid fa-list-check text-xs"></i>
                <span class="hidden 2xl:inline">Roadmap</span>
            </button>

            <div class="h-4 w-px bg-white/10 mx-1 hidden sm:block"></div>

            <!-- Density Toggle -->
            <button onclick="toggleDensity()" id="density-btn" class="w-7 h-7 rounded flex items-center justify-center text-slate-300 hover:text-white hover:bg-white/10 transition" title="Alternar Densidad de Información (Compacto/Normal)">
                <i class="fa-solid fa-table-cells-large text-xs"></i>
            </button>

            <!-- Theme Selector Dropdown -->
            <div class="relative inline-block text-left" id="theme-dropdown-container">
                <button onclick="toggleThemeDropdown()" class="forti-btn-secondary h-7 text-xs px-2 rounded flex items-center gap-1.5" title="Seleccionar Tema Visual Fortinet">
                    <i class="fa-solid fa-palette text-xs" style="color:var(--fg-accent)"></i>
                    <span id="current-theme-label" class="hidden lg:inline font-mono text-[11px]">Jade</span>
                    <i class="fa-solid fa-caret-down text-[10px]"></i>
                </button>
                <div id="theme-dropdown-menu" class="hidden absolute right-0 mt-1 w-56 rounded-md shadow-2xl border border-slate-700 bg-slate-900 z-50 text-xs py-1.5">
                    <div class="px-3 py-1 text-[10px] font-bold text-slate-400 uppercase tracking-wider border-b border-slate-800">
                        Temas Oficiales FortiOS
                    </div>
                    <button onclick="applyTheme('jade')" class="theme-option-btn w-full px-3 py-1.5 text-left flex items-center justify-between hover:bg-slate-800 text-slate-200">
                        <span class="flex items-center gap-2"><span class="w-3 h-3 rounded-full bg-emerald-500 inline-block"></span> Jade (Fortinet Green)</span>
                        <i id="theme-check-jade" class="fa-solid fa-check text-emerald-400 text-xs"></i>
                    </button>
                    <button onclick="applyTheme('neutrino')" class="theme-option-btn w-full px-3 py-1.5 text-left flex items-center justify-between hover:bg-slate-800 text-slate-200">
                        <span class="flex items-center gap-2"><span class="w-3 h-3 rounded-full bg-cyan-500 inline-block"></span> Neutrino (Electric Cyan)</span>
                        <i id="theme-check-neutrino" class="fa-solid fa-check text-cyan-400 text-xs hidden"></i>
                    </button>
                    <button onclick="applyTheme('mariner')" class="theme-option-btn w-full px-3 py-1.5 text-left flex items-center justify-between hover:bg-slate-800 text-slate-200">
                        <span class="flex items-center gap-2"><span class="w-3 h-3 rounded-full bg-blue-600 inline-block"></span> Mariner (Navy Blue)</span>
                        <i id="theme-check-mariner" class="fa-solid fa-check text-blue-400 text-xs hidden"></i>
                    </button>
                    <button onclick="applyTheme('graphite')" class="theme-option-btn w-full px-3 py-1.5 text-left flex items-center justify-between hover:bg-slate-800 text-slate-200">
                        <span class="flex items-center gap-2"><span class="w-3 h-3 rounded-full bg-slate-400 inline-block"></span> Graphite (Charcoal Steel)</span>
                        <i id="theme-check-graphite" class="fa-solid fa-check text-slate-300 text-xs hidden"></i>
                    </button>
                    <button onclick="applyTheme('melongene')" class="theme-option-btn w-full px-3 py-1.5 text-left flex items-center justify-between hover:bg-slate-800 text-slate-200">
                        <span class="flex items-center gap-2"><span class="w-3 h-3 rounded-full bg-purple-500 inline-block"></span> Melongene (Aubergine)</span>
                        <i id="theme-check-melongene" class="fa-solid fa-check text-purple-400 text-xs hidden"></i>
                    </button>
                    <button onclick="applyTheme('retro')" class="theme-option-btn w-full px-3 py-1.5 text-left flex items-center justify-between hover:bg-slate-800 text-slate-200">
                        <span class="flex items-center gap-2"><span class="w-3 h-3 rounded-full bg-amber-500 inline-block"></span> Retro (Terminal Amber)</span>
                        <i id="theme-check-retro" class="fa-solid fa-check text-amber-400 text-xs hidden"></i>
                    </button>
                    <button onclick="applyTheme('darkmatter')" class="theme-option-btn w-full px-3 py-1.5 text-left flex items-center justify-between hover:bg-slate-800 text-slate-200">
                        <span class="flex items-center gap-2"><span class="w-3 h-3 rounded-full bg-teal-400 inline-block"></span> Dark Matter (Void Teal)</span>
                        <i id="theme-check-darkmatter" class="fa-solid fa-check text-teal-400 text-xs hidden"></i>
                    </button>
                    <button onclick="applyTheme('onyx')" class="theme-option-btn w-full px-3 py-1.5 text-left flex items-center justify-between hover:bg-slate-800 text-slate-200">
                        <span class="flex items-center gap-2"><span class="w-3 h-3 rounded-full bg-zinc-200 inline-block"></span> Onyx (Obsidian Platinum)</span>
                        <i id="theme-check-onyx" class="fa-solid fa-check text-zinc-200 text-xs hidden"></i>
                    </button>
                    <button onclick="applyTheme('eclipse')" class="theme-option-btn w-full px-3 py-1.5 text-left flex items-center justify-between hover:bg-slate-800 text-slate-200">
                        <span class="flex items-center gap-2"><span class="w-3 h-3 rounded-full bg-yellow-400 inline-block"></span> Eclipse (Midnight Gold)</span>
                        <i id="theme-check-eclipse" class="fa-solid fa-check text-yellow-400 text-xs hidden"></i>
                    </button>
                    <div class="border-t border-slate-800 my-1"></div>
                    <button onclick="openThemeCustomizer()" class="w-full px-3 py-1.5 text-left flex items-center gap-2 hover:bg-slate-800 text-teal-300 font-semibold">
                        <i class="fa-solid fa-sliders text-xs"></i>
                        <span>Personalizar Colores...</span>
                    </button>
                </div>
            </div>

            <!-- Analyst Profile Pill -->
            <div class="flex items-center gap-2 pl-2 border-l border-white/10">
                <div class="w-7 h-7 rounded-full bg-gradient-to-tr from-slate-700 to-slate-900 border border-slate-600 flex items-center justify-center text-slate-200 font-bold text-xs" title="Analista SOC en Sesión">
                    <i class="fa-solid fa-user-shield text-[11px]"></i>
                </div>
                <div class="hidden xl:flex flex-col text-left leading-tight">
                    <span id="analyst-name" class="font-bold text-xs text-white">admin</span>
                    <span class="text-[9px] text-emerald-400 font-mono">SecOps_Lead</span>
                </div>
            </div>
        </div>
    </header>


    <!-- Fortinet FortiOS 7.4.13 Left Navigation Tree -->
    <aside id="forti-sidebar" class="no-print">
        <div class="py-2 flex-1 overflow-y-auto">

            <!-- Category: DASHBOARD -->
            <div class="forti-nav-group-title">Dashboard & Topología</div>
            <button onclick="switchTab('easm')" id="tab-btn-easm" class="forti-nav-item active" data-forti-tooltip="Estado Ejecutivo y Activos EASM">
                <i class="fa-solid fa-server" style="color:var(--fg-accent)"></i>
                <span class="nav-label">Inventario Activos</span>
                <span id="nav-badge-assets" class="nav-badge bg-emerald-950 text-emerald-400 border border-emerald-800 font-mono">147</span>
            </button>
            <button onclick="switchTab('graph')" id="tab-btn-graph" class="forti-nav-item" data-forti-tooltip="Attack Surface Knowledge Graph">
                <i class="fa-solid fa-circle-nodes text-indigo-400"></i>
                <span class="nav-label">Grafo de Amenazas</span>
                <span class="nav-badge bg-indigo-950 text-indigo-300 border border-indigo-800 font-mono">Vis</span>
            </button>

            <!-- Category: ATTACK SURFACE (EASM) -->
            <div class="forti-nav-group-title">Superficie Externa (EASM)</div>
            <button onclick="switchTab('cloud')" id="tab-btn-cloud" class="forti-nav-item" data-forti-tooltip="Auditoría Cloud & Buckets Públicos">
                <i class="fa-solid fa-cloud text-blue-400"></i>
                <span class="nav-label">Exposición Cloud</span>
                <span id="nav-badge-cloud" class="nav-badge bg-blue-950 text-blue-300 border border-blue-800 font-mono">S3/GCS</span>
            </button>
            <button onclick="switchTab('seeds')" id="tab-btn-seeds" class="forti-nav-item" data-forti-tooltip="Semillas y Perímetro Corporativo">
                <i class="fa-solid fa-crosshairs text-cyan-400"></i>
                <span class="nav-label">Semillas / Perímetro</span>
                <span id="nav-badge-seeds" class="nav-badge bg-cyan-950 text-cyan-300 border border-cyan-800 font-mono">100</span>
            </button>

            <!-- Category: VULNERABILITIES -->
            <div class="forti-nav-group-title">Vulnerabilidades & CTEM</div>
            <button onclick="switchTab('vulns')" id="tab-btn-vulns" class="forti-nav-item" data-forti-tooltip="Centro de Vulnerabilidades & CISA KEV">
                <i class="fa-solid fa-triangle-exclamation text-rose-400"></i>
                <span class="nav-label">Vulnerabilidades</span>
                <span id="nav-badge-vulns" class="nav-badge bg-rose-950 text-rose-400 border border-rose-800 font-mono">74</span>
            </button>
            <button onclick="switchTab('php2shell')" id="tab-btn-php2shell" class="forti-nav-item" data-forti-tooltip="Escáner PHP2Shell (CVE-2026-109618/19)">
                <i class="fa-brands fa-php text-purple-400"></i>
                <span class="nav-label">PHP2Shell Scanner</span>
                <span class="nav-badge bg-rose-950 text-rose-300 border border-rose-800 font-mono text-[9px]">CVE-2026</span>
            </button>

            <!-- Category: THREAT INTEL & DRP -->
            <div class="forti-nav-group-title">Threat Intelligence & DRP</div>
            <button onclick="switchTab('darkintel')" id="tab-btn-darkintel" class="forti-nav-item" data-forti-tooltip="Dark Intelligence, Red Tor & Fugas">
                <i class="fa-solid fa-user-secret text-cyan-400"></i>
                <span class="nav-label">Dark Intelligence</span>
                <span id="nav-badge-darkintel" class="nav-badge bg-cyan-950 text-cyan-300 border border-cyan-800 font-mono">PRO</span>
            </button>
            <button onclick="switchTab('drp')" id="tab-btn-drp" class="forti-nav-item" data-forti-tooltip="Protección de Marca & Phishing (DRP)">
                <i class="fa-solid fa-masks-theater text-amber-400"></i>
                <span class="nav-label">Protección DRP</span>
                <span id="nav-badge-drp" class="nav-badge bg-amber-950 text-amber-300 border border-amber-800 font-mono">2</span>
            </button>
            <button onclick="switchTab('leaks')" id="tab-btn-leaks" class="forti-nav-item" data-forti-tooltip="Fugas de Credenciales y Secretos">
                <i class="fa-solid fa-key text-yellow-400"></i>
                <span class="nav-label">Fugas & Secretos</span>
                <span class="nav-badge bg-slate-900 text-slate-400 border border-slate-700 font-mono">0</span>
            </button>
            <button onclick="switchTab('cti')" id="tab-btn-cti" class="forti-nav-item" data-forti-tooltip="Feeds CTI, Ransomware y Actores">
                <i class="fa-solid fa-user-ninja text-purple-400"></i>
                <span class="nav-label">Inteligencia CTI</span>
                <span id="nav-badge-cti" class="nav-badge bg-purple-950 text-purple-300 border border-purple-800 font-mono">163</span>
            </button>

            <!-- Category: OFFENSIVE OPERATIONS & OSINT -->
            <div class="forti-nav-group-title">OSINT & Operaciones Ofensivas</div>
            <button onclick="switchTab('emailintel')" id="tab-btn-emailintel" class="forti-nav-item" data-forti-tooltip="Email Intelligence & Fugas (Zehef OSINT)">
                <i class="fa-solid fa-at text-sky-400"></i>
                <span class="nav-label">Email Intelligence</span>
                <span id="nav-badge-emailintel" class="nav-badge bg-sky-950 text-sky-300 border border-sky-800 font-mono">ZEHEF</span>
            </button>
            <button onclick="switchTab('loginrecon')" id="tab-btn-loginrecon" class="forti-nav-item" data-forti-tooltip="LoginRecon & OSINT de Identidades">
                <i class="fa-solid fa-id-badge text-sky-400"></i>
                <span class="nav-label">LoginRecon OSINT</span>
                <span class="nav-badge bg-sky-950 text-sky-300 border border-sky-800 font-mono">ID</span>
            </button>
            <button onclick="switchTab('strix')" id="tab-btn-strix" class="forti-nav-item" data-forti-tooltip="Sackmesser Suite (Strix & AutoPentestX)">
                <i class="fa-solid fa-wand-magic-sparkles text-emerald-400"></i>
                <span class="nav-label">Sackmesser Pentest</span>
                <span class="nav-badge bg-emerald-950 text-emerald-300 border border-emerald-800 font-mono">PoC</span>
            </button>

            <!-- Category: FABRIC & AI -->
            <div class="forti-nav-group-title">Security Fabric & IA</div>
            <button onclick="switchTab('ai')" id="tab-btn-ai" class="forti-nav-item" data-forti-tooltip="Correlación Asistida por Inteligencia Artificial">
                <i class="fa-solid fa-brain text-purple-400"></i>
                <span class="nav-label">Correlación IA</span>
                <span class="nav-badge bg-purple-950 text-purple-300 border border-purple-800 font-mono">MITRE</span>
            </button>
            <button onclick="switchTab('connectors')" id="tab-btn-connectors" class="forti-nav-item" data-forti-tooltip="Conectores OSINT y Proveedores de Inteligencia">
                <i class="fa-solid fa-plug text-teal-400"></i>
                <span class="nav-label">Conectores OSINT</span>
                <span id="nav-badge-connectors" class="nav-badge bg-teal-950 text-teal-300 border border-teal-800 font-mono">16</span>
            </button>

            <!-- Category: POLICY & OBJECTS -->
            <div class="forti-nav-group-title">Políticas & Control</div>
            <button onclick="switchTab('scope')" id="tab-btn-scope" class="forti-nav-item" data-forti-tooltip="Alcance Autorizado & Protección Anti-SSRF">
                <i class="fa-solid fa-shield-halved text-cyan-400"></i>
                <span class="nav-label">Alcance & RoE</span>
                <span id="nav-badge-scope" class="nav-badge bg-cyan-950 text-cyan-300 border border-cyan-800 font-mono">198</span>
            </button>

        </div>

        <!-- Sidebar Footer Toggle -->
        <div class="p-2 border-t border-white/10 flex items-center justify-between text-xs text-slate-400">
            <!-- Emergency Kill Switch Quick Button -->
            <button id="btn-top-kill-switch" onclick="handleToggleKillSwitchUI()" class="px-2.5 py-1 rounded text-xs font-semibold flex items-center gap-1.5 border border-slate-700 bg-slate-900/80 text-slate-300 hover:border-rose-700 hover:text-rose-300 transition" title="Parada de Emergencia de Escaneos (Kill-Switch)">
                <i class="fa-solid fa-power-off text-emerald-400" id="kill-switch-icon"></i>
                <span id="kill-switch-label">RO-GUARD: NORMAL</span>
            </button>
            <button onclick="toggleFortiSidebar()" class="w-full py-1.5 rounded flex items-center justify-center gap-2 hover:bg-white/10 hover:text-white transition" title="Alternar Barra Lateral [Ctrl+B]">
                <i id="sidebar-toggle-icon" class="fa-solid fa-angles-left"></i>
                <span class="nav-label font-mono text-[11px]">Contraer Menú</span>
            </button>
        </div>
    </aside>

        <!-- Main Workspace Viewport -->
        <div id="forti-main-viewport">

        <!-- Contextual Breadcrumb & Status Bar -->
        <div id="forti-context-header" class="no-print">
            <div class="flex items-center gap-2 text-xs">
                <span class="text-slate-400 flex items-center gap-1.5">
                    <i class="fa-solid fa-cubes text-slate-500"></i>
                    <span>OpenRecon</span>
                </span>
                <i class="fa-solid fa-chevron-right text-[10px] text-slate-500"></i>
                <span id="bc-category" class="text-slate-400 font-medium">Dashboard & Topología</span>
                <i class="fa-solid fa-chevron-right text-[10px] text-slate-500"></i>
                <span id="bc-module" class="font-bold" style="color:var(--fg-accent)">Inventario Activos</span>
            </div>

            <div class="flex items-center gap-3 text-xs">
                <div class="flex items-center gap-1 text-[11px] text-slate-400">
                    <i class="fa-solid fa-circle-check text-emerald-400 text-[10px]"></i>
                    <span>Estado: <strong>Operacional</strong></span>
                </div>
                <div class="h-3 w-px bg-slate-700"></div>
                <button onclick="refreshAllData()" class="text-slate-400 hover:text-white flex items-center gap-1 text-[11px] transition">
                    <i class="fa-solid fa-arrow-rotate-right text-[10px]"></i>
                    <span>Actualizar</span>
                </button>
            </div>
        </div>

            <main class="flex-1 w-full px-4 sm:px-6 lg:px-8 py-6 space-y-6">
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
                        <p class="text-xs text-slate-400 leading-relaxed mb-2">
                            Métrica perimetral explicable basada en CISA KEV, EPSS y telemetría de activos.
                        </p>
                        <button onclick="openRiskBreakdownModal()" class="text-[11px] px-2.5 py-1 rounded-lg bg-indigo-950/80 border border-indigo-700/60 text-indigo-300 hover:text-white hover:bg-indigo-900 transition flex items-center gap-1.5 cursor-pointer">
                            <i class="fa-solid fa-calculator text-indigo-400"></i>
                            <span>Explicabilidad del Riesgo (0-100)</span>
                        </button>
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
                                <div class="mb-4 p-3 rounded-xl bg-slate-900/80 border border-cyber-border/70 flex flex-col md:flex-row items-start md:items-center justify-between gap-3 text-xs">
                    <div class="flex items-center gap-2 text-slate-300">
                        <i class="fa-solid fa-flask-vial text-cyan-400 text-sm"></i>
                        <span><strong class="text-white">Laboratorio de Pruebas y Validación:</strong> Puedes auditar y validar este módulo con los sitios de prueba oficiales: <code class="text-cyan-300 bg-slate-800 px-1.5 py-0.5 rounded font-mono">vulnweb.com</code>, <code class="text-cyan-300 bg-slate-800 px-1.5 py-0.5 rounded font-mono">hackthissite.org</code>, <code class="text-cyan-300 bg-slate-800 px-1.5 py-0.5 rounded font-mono">juice-shop.herokuapp.com</code>, <code class="text-cyan-300 bg-slate-800 px-1.5 py-0.5 rounded font-mono">dvwa.co.uk</code>, <code class="text-cyan-300 bg-slate-800 px-1.5 py-0.5 rounded font-mono">zero.webappsecurity.com</code>, <code class="text-cyan-300 bg-slate-800 px-1.5 py-0.5 rounded font-mono">demo.testfire.net</code>.</span>
                    </div>
                    <span class="text-[10px] px-2 py-0.5 rounded bg-cyan-950/60 text-cyan-400 border border-cyan-800/60 whitespace-nowrap font-mono"><i class="fa-solid fa-shield-virus mr-1"></i>Modo Auditoría CSIRT</span>
                </div>

                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs">
                        <thead class="bg-slate-900/60 text-slate-400 uppercase text-[10px] tracking-wider border-b border-cyber-border">
                            <tr>
                                <th class="p-4">Víctima Reclamada / Empresa</th>
                                <th class="p-4">Grupo Cibercriminal</th>
                                <th class="p-4">Ultimátum / Datos Exfiltrados</th>
                                <th class="p-4 text-center">Estado de Amenaza</th>
                                <th class="p-4 text-center">Acción / Alerta Temprana</th>
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
                <div class="flex items-center gap-2 flex-wrap">
                    <button onclick="exportVulnsCsv()" class="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 border border-cyber-border text-xs font-semibold flex items-center gap-1.5 transition">
                        <i class="fa-solid fa-file-csv text-emerald-400"></i>
                        <span>Exportar CSV</span>
                    </button>
                    <button onclick="runBatchPerimeterValidation()" id="btn-batch-validate" class="px-3.5 py-1.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold shadow-lg shadow-emerald-900/40 flex items-center gap-1.5 transition">
                        <i class="fa-solid fa-wand-magic-sparkles"></i>
                        <span>Validar Perímetro (Batch)</span>
                    </button>
                    <button onclick="runVulnerabilityScan()" class="px-3.5 py-1.5 rounded-xl bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold shadow-lg shadow-rose-900/40 flex items-center gap-1.5 transition">
                        <i class="fa-solid fa-shield-virus"></i>
                        <span>Re-escanear Perímetro</span>
                    </button>
                </div>
            </div>

            <!-- VulnValidator Real-Time Metrics Bar -->
            <div id="vuln-validator-metrics-bar" class="grid grid-cols-2 sm:grid-cols-5 gap-3 p-3 bg-cyber-card border border-cyber-border rounded-xl">
                <div class="p-2.5 bg-slate-900/60 rounded-lg border border-slate-800/80">
                    <span class="text-[10px] text-slate-400 font-medium block">Total Hallazgos</span>
                    <span id="vmb-total" class="text-base font-bold text-white font-mono">0</span>
                </div>
                <div class="p-2.5 bg-rose-950/30 rounded-lg border border-rose-800/40">
                    <span class="text-[10px] text-rose-300 font-medium block">Confirmadas</span>
                    <span id="vmb-confirmed" class="text-base font-bold text-rose-400 font-mono">0</span>
                </div>
                <div class="p-2.5 bg-slate-900/80 rounded-lg border border-slate-700/60">
                    <span class="text-[10px] text-slate-300 font-medium block">Falsos Positivos</span>
                    <div class="flex items-baseline gap-1.5">
                        <span id="vmb-fp" class="text-base font-bold text-slate-200 font-mono">0</span>
                        <span id="vmb-fp-pct" class="text-[10px] text-cyan-400 font-mono font-bold">(0%)</span>
                    </div>
                </div>
                <div class="p-2.5 bg-cyan-950/30 rounded-lg border border-cyan-800/40">
                    <span class="text-[10px] text-cyan-300 font-medium block">Mitigadas</span>
                    <span id="vmb-mitigated" class="text-base font-bold text-cyan-400 font-mono">0</span>
                </div>
                <div class="p-2.5 bg-emerald-950/30 rounded-lg border border-emerald-800/40">
                    <span class="text-[10px] text-emerald-300 font-medium block">Certeza Promedio</span>
                    <span id="vmb-avg-conf" class="text-base font-bold text-emerald-400 font-mono">--%</span>
                </div>
            </div>

            <!-- Filter and Search Toolbar -->
            <div class="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 bg-cyber-card border border-cyber-border rounded-xl p-3">
                <div class="flex items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0" id="vuln-severity-filters">
                    <button onclick="filterVulnsBySeverity('ALL')" id="vuln-filter-ALL" class="px-2.5 py-1 rounded-lg text-xs font-bold bg-cyan-950 text-cyan-300 border border-cyan-800 transition">Todas (<span id="count-vuln-all">0</span>)</button>
                    <button onclick="filterVulnsBySeverity('HIGH')" id="vuln-filter-HIGH" class="px-2.5 py-1 rounded-lg text-xs font-semibold text-slate-400 hover:text-white border border-transparent hover:border-cyber-border transition">Altas (<span id="count-vuln-high">0</span>)</button>
                    <button onclick="filterVulnsBySeverity('MEDIUM')" id="vuln-filter-MEDIUM" class="px-2.5 py-1 rounded-lg text-xs font-semibold text-slate-400 hover:text-white border border-transparent hover:border-cyber-border transition">Medias (<span id="count-vuln-med">0</span>)</button>
                    <button onclick="filterVulnsBySeverity('LOW')" id="vuln-filter-LOW" class="px-2.5 py-1 rounded-lg text-xs font-semibold text-slate-400 hover:text-white border border-transparent hover:border-cyber-border transition">Bajas (<span id="count-vuln-low">0</span>)</button>
                    <button onclick="filterVulnsBySeverity('CONFIRMADA')" id="vuln-filter-CONFIRMADA" class="px-2.5 py-1 rounded-lg text-xs font-semibold text-emerald-400 hover:text-emerald-300 border border-transparent hover:border-emerald-800/60 transition">Confirmadas (<span id="count-vuln-confirmed">0</span>)</button>
                    <button onclick="filterVulnsBySeverity('FALSO_POSITIVO')" id="vuln-filter-FALSO_POSITIVO" class="px-2.5 py-1 rounded-lg text-xs font-semibold text-slate-400 hover:text-slate-200 border border-transparent hover:border-slate-700 transition">Falsos Positivos (<span id="count-vuln-fp">0</span>)</button>
                    <button onclick="filterVulnsBySeverity('RESOLVED')" id="vuln-filter-RESOLVED" class="px-2.5 py-1 rounded-lg text-xs font-semibold text-slate-400 hover:text-white border border-transparent hover:border-cyber-border transition">Mitigadas (<span id="count-vuln-res">0</span>)</button>
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

        <!-- TAB CONTENT: STRIX & AUTOPENTESTX TOOLKIT (SACKMESSER) -->
        <section id="tab-content-strix" class="space-y-6 hidden">
            <!-- Suite Switcher: Strix vs AutoPentestX -->
            <div class="bg-cyber-card border border-cyber-border rounded-2xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div class="flex items-center gap-3">
                    <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-emerald-600 via-teal-700 to-purple-800 flex items-center justify-center text-white shadow-lg shadow-purple-950/40">
                        <i class="fa-solid fa-toolbox text-lg"></i>
                    </div>
                    <div>
                        <div class="flex items-center gap-2">
                            <h2 class="text-base font-bold text-white">Sackmesser de Pentesting & Auditoría Ofensiva</h2>
                            <span class="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-purple-950 text-purple-300 border border-purple-800">Multi-Framework</span>
                        </div>
                        <p class="text-xs text-slate-400">Selecciona el paquete de herramientas según la necesidad del analista y auditor.</p>
                    </div>
                </div>

                <div class="flex items-center gap-2 bg-slate-950 p-1.5 rounded-xl border border-cyber-border">
                    <button onclick="switchPentestSuite('strix')" id="btn-suite-strix" class="px-4 py-2 rounded-lg bg-emerald-950 text-emerald-300 border border-emerald-700 text-xs font-bold flex items-center gap-2 transition shadow">
                        <i class="fa-solid fa-wand-magic-sparkles text-emerald-400"></i>
                        <span>Suite Strix (PoC & Raw HTTP)</span>
                    </button>
                    <button onclick="switchPentestSuite('autopentestx')" id="btn-suite-autopentestx" class="px-4 py-2 rounded-lg bg-slate-900 text-slate-400 hover:text-white border border-transparent text-xs font-bold flex items-center gap-2 transition">
                        <i class="fa-solid fa-robot text-purple-400"></i>
                        <span>Suite AutoPentestX (Pipeline & Informes)</span>
                    </button>
                </div>
            </div>

            <!-- CRI METRIC HARMONIZATION CARD (AUDIT & MULTI-DIMENSIONAL SCORING) -->
            <div class="bg-cyber-card border border-cyber-border rounded-2xl p-5 space-y-4">
                <div class="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-cyber-border/70 pb-3">
                    <div class="flex items-center gap-3">
                        <div class="w-9 h-9 rounded-xl bg-indigo-950 border border-indigo-700 flex items-center justify-center text-indigo-400">
                            <i class="fa-solid fa-scale-balanced text-sm"></i>
                        </div>
                        <div>
                            <div class="flex items-center gap-2">
                                <h3 class="text-sm font-bold text-white">Índice Global de Resiliencia Cibernética (CRI)</h3>
                                <span class="px-2 py-0.5 rounded text-[10px] font-mono bg-indigo-950 text-indigo-300 border border-indigo-800">Marco de Armonización</span>
                            </div>
                            <p class="text-[11px] text-slate-400">Ponderación matemática de las 3 dimensiones evaluadas para justificación ante comités y auditores.</p>
                        </div>
                    </div>
                    <div class="flex items-center gap-2">
                        <select id="cri-target-select" onchange="loadCriMetrics()" class="bg-slate-900 border border-cyber-border text-xs text-white rounded-xl px-3 py-1.5 focus:outline-none focus:border-indigo-500 font-mono">
                            <option value="">Seleccionar activo para evaluar CRI...</option>
                        </select>
                        <button onclick="loadCriMetrics()" class="px-3 py-1.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold transition flex items-center gap-1.5 shadow">
                            <i class="fa-solid fa-arrows-rotate text-[11px]"></i>
                            <span>Calcular CRI</span>
                        </button>
                    </div>
                </div>

                <!-- 3 Dimensions + Composite CRI -->
                <div class="grid grid-cols-1 md:grid-cols-4 gap-3">
                    <!-- Dimensión 1: EASM Core -->
                    <div class="p-3.5 rounded-xl bg-slate-950/80 border border-cyber-border space-y-2">
                        <div class="flex items-center justify-between">
                            <span class="text-[11px] font-bold text-slate-300">1. OpenRecon EASM</span>
                            <span class="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">Peso 30%</span>
                        </div>
                        <div class="flex items-baseline gap-1">
                            <span id="cri-score-easm" class="text-2xl font-black text-cyan-400 font-mono">--</span>
                            <span class="text-[10px] text-slate-500 font-mono">/100</span>
                        </div>
                        <div class="text-[10px] text-slate-400 leading-tight">
                            <strong>Amplitud & Higiene:</strong> Evalúa puertos, certificados SSL, subdominios y cabeceras pasivas.
                        </div>
                    </div>

                    <!-- Dimensión 2: AutoPentestX -->
                    <div class="p-3.5 rounded-xl bg-slate-950/80 border border-cyber-border space-y-2">
                        <div class="flex items-center justify-between">
                            <span class="text-[11px] font-bold text-slate-300">2. AutoPentestX CVE</span>
                            <span class="text-[10px] font-mono px-1.5 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800">Peso 30%</span>
                        </div>
                        <div class="flex items-baseline gap-1">
                            <span id="cri-score-apx" class="text-2xl font-black text-purple-400 font-mono">--</span>
                            <span class="text-[10px] text-slate-500 font-mono">/100</span>
                        </div>
                        <div class="text-[10px] text-slate-400 leading-tight">
                            <strong>Deuda Teórica:</strong> Pondera severidad agregada según catálogo CVSS y orquestación de red.
                        </div>
                    </div>

                    <!-- Dimensión 3: Strix PoC Engine -->
                    <div class="p-3.5 rounded-xl bg-slate-950/80 border border-cyber-border space-y-2">
                        <div class="flex items-center justify-between">
                            <span class="text-[11px] font-bold text-slate-300">3. Strix PoC Engine</span>
                            <span class="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800">Peso 40%</span>
                        </div>
                        <div class="flex items-baseline gap-1">
                            <span id="cri-score-strix" class="text-2xl font-black text-emerald-400 font-mono">--</span>
                            <span class="text-[10px] text-slate-500 font-mono">/100</span>
                        </div>
                        <div class="text-[10px] text-slate-400 leading-tight">
                            <strong>Explotabilidad Real:</strong> Tolerancia cero a falsos positivos; valida PoCs funcionales o bloqueo por WAF.
                        </div>
                    </div>

                    <!-- Composite CRI Global -->
                    <div class="p-3.5 rounded-xl bg-gradient-to-br from-indigo-950/60 to-slate-950 border border-indigo-700/60 space-y-2">
                        <div class="flex items-center justify-between">
                            <span class="text-[11px] font-bold text-white">Índice Global CRI</span>
                            <span id="cri-posture-badge" class="text-[10px] font-mono px-1.5 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800">Sin Evaluar</span>
                        </div>
                        <div class="flex items-baseline gap-1">
                            <span id="cri-score-global" class="text-2xl font-black text-indigo-400 font-mono">--</span>
                            <span class="text-[10px] text-slate-500 font-mono">/100</span>
                        </div>
                        <div id="cri-briefing" class="text-[10px] text-slate-300 leading-tight line-clamp-2">
                            Selecciona un objetivo para calcular la armonización de métricas.
                        </div>
                    </div>
                </div>
            </div>

            <!-- CONTAINER SUITE STRIX -->
            <div id="container-suite-strix" class="space-y-6">
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
                            Sackmesser Strix (Auditoría Ofensiva & Validación)
                        </h3>
                        <p class="text-xs text-slate-400 mt-1 max-w-3xl">
                            Herramientas multi-plataforma de pentesting interactivo: inspección cruda de paquetes HTTP (estilo Caido/Burp Suite), validación determinista de PoCs con comandos cURL y scripts Python listos para replicar, fuzzing de rutas de exposición, inspección de certificados X.509 y auditorías RFC DNS.
                        </p>
                    </div>

                    <!-- Asset quick-loader -->
                    <div class="flex items-center gap-2 bg-slate-900/80 p-2.5 rounded-xl border border-cyber-border">
                        <i class="fa-solid fa-crosshairs text-cyan-400 text-xs"></i>
                        <select id="strix-asset-quick-select" onchange="applyStrixSelectedAsset()" class="bg-slate-950 text-xs text-slate-200 border border-slate-700 rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500 max-w-[200px]">
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
            </div> <!-- CLOSE #container-suite-strix -->

            <!-- CONTAINER SUITE AUTOPENTESTX -->
            <div id="container-suite-autopentestx" class="space-y-6 hidden">
                <!-- Header Card AutoPentestX -->
                <div class="bg-cyber-card border border-cyber-border rounded-2xl p-6 relative overflow-hidden">
                    <div class="absolute -right-10 -bottom-10 opacity-5 pointer-events-none text-9xl text-purple-400">
                        <i class="fa-solid fa-robot"></i>
                    </div>
                    <div class="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                        <div>
                            <div class="flex items-center gap-2 mb-1">
                                <span class="px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-purple-950 text-purple-300 border border-purple-800">
                                    <i class="fa-solid fa-microchip mr-1"></i> AutoPentestX Framework
                                </span>
                                <span class="text-xs text-slate-500 font-mono">Inspirado en AutoPentestX (Gowtham-Darkseid)</span>
                            </div>
                            <h3 class="text-xl font-bold text-white flex items-center gap-2">
                                <i class="fa-solid fa-shield-virus text-purple-400"></i>
                                AutoPentestX (Pipeline Autónomo, Auditoría de Verbos & Reportes PDF)
                            </h3>
                            <p class="text-xs text-slate-400 mt-1 max-w-3xl">
                                Orquestación de pruebas de penetración automatizadas en 5 fases secuenciales (Perímetro, Puertos, Cabeceras Defensivas, Verbos HTTP y Fuzzing Sensible), auditoría profunda de métodos inseguros (TRACE/XST, PUT) y generación de informes ejecutivos/técnicos listos para imprimir o exportar a PDF para gerencia y auditoría.
                            </p>
                        </div>

                        <!-- Asset quick-loader for APX -->
                        <div class="flex items-center gap-2 bg-slate-900/80 p-2.5 rounded-xl border border-cyber-border">
                            <i class="fa-solid fa-crosshairs text-purple-400 text-xs"></i>
                            <select id="apx-asset-quick-select" class="bg-slate-950 text-xs text-slate-200 border border-slate-700 rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-purple-500 max-w-[200px]">
                                <option value="">Seleccionar activo...</option>
                            </select>
                            <button onclick="applyApxSelectedAsset()" class="px-3 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold transition">
                                Cargar
                            </button>
                        </div>
                    </div>

                    <!-- AutoPentestX Sub-tools Navigation Pills -->
                    <div class="flex items-center gap-2 mt-5 border-t border-cyber-border/70 pt-4 overflow-x-auto text-xs font-semibold">
                        <button onclick="switchAutoPentestXSubTool('pipeline')" id="apx-subtab-pipeline" class="px-4 py-2 rounded-xl bg-purple-950/80 text-purple-300 border border-purple-700/80 flex items-center gap-2 transition">
                            <i class="fa-solid fa-network-wired text-purple-400"></i>
                            <span>Pipeline 1-Click (5 Fases)</span>
                        </button>
                        <button onclick="switchAutoPentestXSubTool('methods')" id="apx-subtab-methods" class="px-4 py-2 rounded-xl bg-slate-900 text-slate-400 hover:text-white border border-cyber-border flex items-center gap-2 transition">
                            <i class="fa-solid fa-arrows-split-up-and-left text-amber-400"></i>
                            <span>Auditor de Verbos HTTP & Fuga de Servidor</span>
                        </button>
                        <button onclick="switchAutoPentestXSubTool('report')" id="apx-subtab-report" class="px-4 py-2 rounded-xl bg-slate-900 text-slate-400 hover:text-white border border-cyber-border flex items-center gap-2 transition">
                            <i class="fa-solid fa-file-pdf text-rose-400"></i>
                            <span>Generador de Informes (PDF / Ejecutivo)</span>
                        </button>
                    </div>
                </div>

                <!-- APX SUB-PANEL 1: Pipeline 1-Click (5 Fases) -->
                <div id="apx-panel-pipeline" class="space-y-4">
                    <div class="bg-cyber-card border border-cyber-border rounded-2xl p-5 space-y-4">
                        <div class="grid grid-cols-1 md:grid-cols-12 gap-3 items-end">
                            <div class="md:col-span-6">
                                <label class="block text-[10px] uppercase font-bold text-slate-400 mb-1">Objetivo / FQDN / URL</label>
                                <input type="text" id="apx-pipeline-target" placeholder="ejemplo: https://demo.testfire.net o altoromutual.com" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-cyber-border text-xs text-white placeholder-slate-500 focus:outline-none focus:border-purple-500 font-mono">
                            </div>
                            <div class="md:col-span-3">
                                <label class="block text-[10px] uppercase font-bold text-slate-400 mb-1">Perfil de Análisis</label>
                                <select id="apx-pipeline-profile" class="w-full bg-slate-900 border border-cyber-border rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-purple-500">
                                    <option value="full">Completo (5 Fases Secuenciales)</option>
                                    <option value="fast">Rápido (Perímetro + Cabeceras)</option>
                                    <option value="intrusive">Intrusivo (Fuzzing y Verbos)</option>
                                </select>
                            </div>
                            <div class="md:col-span-3">
                                <button onclick="runAutoPentestXPipeline()" id="btn-apx-run-pipeline" class="w-full px-5 py-2 rounded-xl bg-purple-600 hover:bg-purple-500 text-white text-xs font-bold transition flex items-center justify-center gap-2 shadow-lg shadow-purple-950/50">
                                    <i class="fa-solid fa-play"></i>
                                    <span>Ejecutar Pipeline AutoPentestX</span>
                                </button>
                            </div>
                        </div>

                        <!-- 5-Phase Progression Tracker -->
                        <div class="border border-cyber-border rounded-xl p-4 bg-slate-950/60">
                            <div class="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-3 flex items-center justify-between">
                                <span><i class="fa-solid fa-timeline text-purple-400 mr-1.5"></i> Progreso de Pipeline Autónomo</span>
                                <span id="apx-pipeline-timer" class="text-slate-500 font-mono text-[10px]">Listo para iniciar</span>
                            </div>
                            <div class="grid grid-cols-1 sm:grid-cols-5 gap-3">
                                <div id="apx-phase-1" class="p-3 rounded-lg border border-slate-800 bg-slate-900/50 transition">
                                    <div class="flex items-center justify-between text-xs font-bold text-slate-400 mb-1">
                                        <span>Fase 1</span>
                                        <span class="phase-status text-[10px] text-slate-500 font-mono">En espera</span>
                                    </div>
                                    <div class="text-xs font-medium text-slate-300">Recon Perimetral & DNS</div>
                                </div>
                                <div id="apx-phase-2" class="p-3 rounded-lg border border-slate-800 bg-slate-900/50 transition">
                                    <div class="flex items-center justify-between text-xs font-bold text-slate-400 mb-1">
                                        <span>Fase 2</span>
                                        <span class="phase-status text-[10px] text-slate-500 font-mono">En espera</span>
                                    </div>
                                    <div class="text-xs font-medium text-slate-300">Puertos & Servicios</div>
                                </div>
                                <div id="apx-phase-3" class="p-3 rounded-lg border border-slate-800 bg-slate-900/50 transition">
                                    <div class="flex items-center justify-between text-xs font-bold text-slate-400 mb-1">
                                        <span>Fase 3</span>
                                        <span class="phase-status text-[10px] text-slate-500 font-mono">En espera</span>
                                    </div>
                                    <div class="text-xs font-medium text-slate-300">Cabeceras Defensivas</div>
                                </div>
                                <div id="apx-phase-4" class="p-3 rounded-lg border border-slate-800 bg-slate-900/50 transition">
                                    <div class="flex items-center justify-between text-xs font-bold text-slate-400 mb-1">
                                        <span>Fase 4</span>
                                        <span class="phase-status text-[10px] text-slate-500 font-mono">En espera</span>
                                    </div>
                                    <div class="text-xs font-medium text-slate-300">Verbos HTTP Inseguros</div>
                                </div>
                                <div id="apx-phase-5" class="p-3 rounded-lg border border-slate-800 bg-slate-900/50 transition">
                                    <div class="flex items-center justify-between text-xs font-bold text-slate-400 mb-1">
                                        <span>Fase 5</span>
                                        <span class="phase-status text-[10px] text-slate-500 font-mono">En espera</span>
                                    </div>
                                    <div class="text-xs font-medium text-slate-300">Fuzzing & Fuga Rutas</div>
                                </div>
                            </div>
                        </div>

                        <!-- Pipeline Results Container -->
                        <div id="apx-pipeline-results" class="hidden space-y-4 pt-2">
                            <!-- Score & Executive Summary Banner -->
                            <div class="grid grid-cols-1 lg:grid-cols-12 gap-4">
                                <!-- Gauge Card -->
                                <div id="apx-pipeline-score-card" class="lg:col-span-4 p-5 rounded-xl border border-cyber-border bg-slate-950 flex flex-col items-center justify-center text-center space-y-2">
                                    <span class="text-[10px] uppercase font-bold text-slate-400 tracking-wider">AutoPentestX Risk Score</span>
                                    <div class="flex items-baseline gap-1">
                                        <span id="apx-pipeline-score" class="text-5xl font-black text-white font-mono">--</span>
                                        <span class="text-slate-500 text-sm font-mono">/100</span>
                                    </div>
                                    <div id="apx-pipeline-posture-badge" class="px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider">
                                        Sin evaluar
                                    </div>
                                    <p id="apx-pipeline-posture-desc" class="text-[11px] text-slate-400 mt-1 max-w-xs"></p>
                                </div>

                                <!-- Executive Briefing & Stats -->
                                <div class="lg:col-span-8 p-5 rounded-xl border border-cyber-border bg-slate-950 flex flex-col justify-between space-y-4">
                                    <div>
                                        <div class="flex items-center justify-between border-b border-cyber-border/70 pb-2 mb-2">
                                            <h4 class="text-xs font-bold uppercase text-slate-300 tracking-wider flex items-center gap-1.5">
                                                <i class="fa-solid fa-briefcase text-purple-400"></i> Dictamen Ejecutivo del Auditor
                                            </h4>
                                            <span id="apx-pipeline-timestamp" class="text-[10px] font-mono text-slate-500"></span>
                                        </div>
                                        <p id="apx-pipeline-summary" class="text-xs text-slate-300 leading-relaxed"></p>
                                    </div>

                                    <!-- Severity Breakdown Badges -->
                                    <div class="grid grid-cols-5 gap-2 pt-2 border-t border-cyber-border/50 text-center font-mono">
                                        <div class="p-2 rounded-lg bg-rose-950/40 border border-rose-900/60">
                                            <span class="text-[10px] block text-rose-400 font-bold uppercase">Crítica</span>
                                            <span id="apx-count-critical" class="text-lg font-bold text-rose-300">0</span>
                                        </div>
                                        <div class="p-2 rounded-lg bg-orange-950/40 border border-orange-900/60">
                                            <span class="text-[10px] block text-orange-400 font-bold uppercase">Alta</span>
                                            <span id="apx-count-high" class="text-lg font-bold text-orange-300">0</span>
                                        </div>
                                        <div class="p-2 rounded-lg bg-amber-950/40 border border-amber-900/60">
                                            <span class="text-[10px] block text-amber-400 font-bold uppercase">Media</span>
                                            <span id="apx-count-medium" class="text-lg font-bold text-amber-300">0</span>
                                        </div>
                                        <div class="p-2 rounded-lg bg-blue-950/40 border border-blue-900/60">
                                            <span class="text-[10px] block text-blue-400 font-bold uppercase">Baja</span>
                                            <span id="apx-count-low" class="text-lg font-bold text-blue-300">0</span>
                                        </div>
                                        <div class="p-2 rounded-lg bg-slate-900 border border-slate-800">
                                            <span class="text-[10px] block text-slate-400 font-bold uppercase">Info</span>
                                            <span id="apx-count-info" class="text-lg font-bold text-slate-300">0</span>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <!-- Findings Ledger Table -->
                            <div class="bg-slate-950 border border-cyber-border rounded-xl p-4 space-y-3">
                                <div class="flex items-center justify-between">
                                    <h4 class="text-xs font-bold uppercase text-slate-300 tracking-wider flex items-center gap-1.5">
                                        <i class="fa-solid fa-bug text-purple-400"></i> Hallazgos Detectados en el Pipeline
                                    </h4>
                                    <span id="apx-pipeline-vuln-count" class="text-[10px] font-mono text-purple-400"></span>
                                </div>
                                <div class="overflow-x-auto">
                                    <table class="w-full text-left text-xs">
                                        <thead>
                                            <tr class="border-b border-cyber-border text-[10px] font-bold uppercase text-slate-400">
                                                <th class="py-2.5 px-3">Fase</th>
                                                <th class="py-2.5 px-3">Severidad</th>
                                                <th class="py-2.5 px-3">Vulnerabilidad</th>
                                                <th class="py-2.5 px-3">Evidencia / Detalle Técnico</th>
                                                <th class="py-2.5 px-3 text-right">Acción</th>
                                            </tr>
                                        </thead>
                                        <tbody id="apx-pipeline-vulns-tbody" class="divide-y divide-cyber-border/50 text-slate-300"></tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- APX SUB-PANEL 2: Auditor de Verbos HTTP & Fuga de Servidor -->
                <div id="apx-panel-methods" class="space-y-4 hidden">
                    <div class="bg-cyber-card border border-cyber-border rounded-2xl p-5 space-y-4">
                        <div class="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
                            <div class="flex-1">
                                <label class="block text-[10px] uppercase font-bold text-slate-400 mb-1">URL Objetivo para Auditoría de Verbos</label>
                                <input type="text" id="apx-methods-target" placeholder="ejemplo: https://demo.testfire.net" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-cyber-border text-xs text-white placeholder-slate-500 focus:outline-none focus:border-amber-500 font-mono">
                            </div>
                            <div class="flex items-end">
                                <button onclick="runAutoPentestXHttpMethods()" id="btn-apx-run-methods" class="w-full sm:w-auto px-5 py-2 rounded-xl bg-amber-600 hover:bg-amber-500 text-white text-xs font-bold transition flex items-center justify-center gap-2 shadow-lg shadow-amber-950/50">
                                    <i class="fa-solid fa-arrows-split-up-and-left"></i>
                                    <span>Auditar Verbos HTTP</span>
                                </button>
                            </div>
                        </div>

                        <!-- Methods Results Container -->
                        <div id="apx-methods-results" class="hidden space-y-4 pt-2">
                            <!-- Server Banner & Fingerprint Card -->
                            <div class="p-4 rounded-xl border border-cyber-border bg-slate-950 space-y-2">
                                <div class="flex items-center justify-between border-b border-cyber-border/70 pb-2">
                                    <span class="text-xs font-bold text-slate-300 flex items-center gap-1.5">
                                        <i class="fa-solid fa-fingerprint text-amber-400"></i> Fuga de Información en Cabeceras (Fingerprinting)
                                    </span>
                                    <span id="apx-banner-verdict" class="text-[10px] font-mono px-2 py-0.5 rounded"></span>
                                </div>
                                <div class="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs pt-1">
                                    <div class="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                                        <span class="text-[10px] uppercase text-slate-500 font-bold block">Cabecera Server</span>
                                        <span id="apx-banner-server" class="font-mono text-slate-200 block truncate mt-0.5"></span>
                                    </div>
                                    <div class="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                                        <span class="text-[10px] uppercase text-slate-500 font-bold block">Cabecera X-Powered-By</span>
                                        <span id="apx-banner-powered" class="font-mono text-slate-200 block truncate mt-0.5"></span>
                                    </div>
                                    <div class="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                                        <span class="text-[10px] uppercase text-slate-500 font-bold block">Riesgo Tecnológico</span>
                                        <span id="apx-banner-risk" class="text-slate-300 block truncate mt-0.5"></span>
                                    </div>
                                </div>
                            </div>

                            <!-- 8-Method Matrix -->
                            <div class="space-y-2">
                                <h4 class="text-xs font-bold uppercase text-slate-400 tracking-wider flex items-center gap-1.5">
                                    <i class="fa-solid fa-table-cells text-amber-400"></i> Matriz de Respuesta por Método HTTP (RFC 9110)
                                </h4>
                                <div id="apx-methods-grid" class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3"></div>
                            </div>

                            <!-- Hardening Configuration Snippets -->
                            <div class="bg-slate-950 border border-cyber-border rounded-xl p-4 space-y-3">
                                <div class="flex items-center justify-between">
                                    <h4 class="text-xs font-bold uppercase text-slate-300 tracking-wider flex items-center gap-1.5">
                                        <i class="fa-solid fa-shield-halved text-cyan-400"></i> Guía de Hardening: Bloqueo de Verbos Inseguros
                                    </h4>
                                    <span class="text-[10px] text-slate-500 font-mono">Nginx / Apache / IIS</span>
                                </div>
                                <div class="grid grid-cols-1 lg:grid-cols-3 gap-3">
                                    <div class="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1.5">
                                        <div class="flex items-center justify-between">
                                            <span class="text-xs font-bold text-slate-200">Nginx Hardening</span>
                                            <button onclick="copyToClipboard('apx-snippet-nginx', 'Regla Nginx copiada')" class="text-[10px] text-cyan-400 hover:text-cyan-300"><i class="fa-solid fa-copy"></i> Copiar</button>
                                        </div>
                                        <pre id="apx-snippet-nginx" class="text-[10px] font-mono text-slate-300 bg-slate-950 p-2 rounded border border-slate-800 overflow-x-auto whitespace-pre">if ($request_method !~ ^(GET|HEAD|POST)$ ) {
    return 405;
}</pre>
                                    </div>
                                    <div class="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1.5">
                                        <div class="flex items-center justify-between">
                                            <span class="text-xs font-bold text-slate-200">Apache HTTPD (.htaccess)</span>
                                            <button onclick="copyToClipboard('apx-snippet-apache', 'Regla Apache copiada')" class="text-[10px] text-cyan-400 hover:text-cyan-300"><i class="fa-solid fa-copy"></i> Copiar</button>
                                        </div>
                                        <pre id="apx-snippet-apache" class="text-[10px] font-mono text-slate-300 bg-slate-950 p-2 rounded border border-slate-800 overflow-x-auto whitespace-pre">TraceEnable Off
&lt;LimitExcept GET POST HEAD&gt;
    Require all denied
&lt;/LimitExcept&gt;</pre>
                                    </div>
                                    <div class="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1.5">
                                        <div class="flex items-center justify-between">
                                            <span class="text-xs font-bold text-slate-200">Microsoft IIS (web.config)</span>
                                            <button onclick="copyToClipboard('apx-snippet-iis', 'Regla IIS copiada')" class="text-[10px] text-cyan-400 hover:text-cyan-300"><i class="fa-solid fa-copy"></i> Copiar</button>
                                        </div>
                                        <pre id="apx-snippet-iis" class="text-[10px] font-mono text-slate-300 bg-slate-950 p-2 rounded border border-slate-800 overflow-x-auto whitespace-pre">&lt;security&gt;
  &lt;requestFiltering&gt;
    &lt;verbs allowUnlisted="false"&gt;
      &lt;add verb="GET" allowed="true"/&gt;
      &lt;add verb="POST" allowed="true"/&gt;
    &lt;/verbs&gt;
  &lt;/requestFiltering&gt;
&lt;/security&gt;</pre>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- APX SUB-PANEL 3: Generador de Informes (PDF / Ejecutivo) -->
                <div id="apx-panel-report" class="space-y-4 hidden">
                    <div class="bg-cyber-card border border-cyber-border rounded-2xl p-5 space-y-4 no-print">
                        <div class="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4">
                            <div class="flex items-center gap-3">
                                <div class="w-10 h-10 rounded-xl bg-rose-950 border border-rose-800 flex items-center justify-center text-rose-400 text-lg">
                                    <i class="fa-solid fa-file-invoice"></i>
                                </div>
                                <div>
                                    <h3 class="text-sm font-bold text-white">Generador de Informes de Seguridad & Pentesting</h3>
                                    <p class="text-xs text-slate-400">Compila hallazgos registrados, métricas de cumplimiento normativo y dictámenes ejecutivos.</p>
                                </div>
                            </div>
                            <div class="flex items-center gap-2">
                                <select id="apx-report-target-select" class="bg-slate-900 border border-cyber-border text-xs text-white rounded-xl px-3 py-2 focus:outline-none focus:border-rose-500">
                                    <option value="">Seleccionar activo...</option>
                                </select>
                                <button onclick="generateAutoPentestXReport()" id="btn-apx-generate-report" class="px-4 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold transition flex items-center gap-2 shadow-lg shadow-rose-950/50">
                                    <i class="fa-solid fa-arrows-rotate"></i>
                                    <span>Compilar Informe</span>
                                </button>
                                <button onclick="printAutoPentestXReport()" id="btn-apx-print-report" class="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-white text-xs font-bold border border-slate-700 transition flex items-center gap-2">
                                    <i class="fa-solid fa-print"></i>
                                    <span>Imprimir / PDF</span>
                                </button>
                            </div>
                        </div>
                    </div>

                    <!-- Printable Formal Report Container -->
                    <div id="apx-printable-report" class="bg-cyber-card border border-cyber-border rounded-2xl p-6 md:p-8 space-y-6 text-slate-200">
                        <div class="text-center py-12 text-slate-500 space-y-2">
                            <i class="fa-solid fa-file-circle-check text-4xl text-slate-600"></i>
                            <p class="text-xs">Selecciona un activo y pulsa "Compilar Informe" para generar el documento formal de auditoría.</p>
                        </div>
                    </div>
                </div>
            </div> <!-- CLOSE #container-suite-autopentestx -->
        </section>

        <!-- TAB CONTENT: LOGINRECON (OSINT DIGITAL FOOTPRINT & IDENTITY RECON) -->
        <section id="tab-content-loginrecon" class="space-y-6 hidden">
            <!-- Header Card -->
            <div class="bg-cyber-card border border-cyber-border rounded-2xl p-6 relative overflow-hidden">
                <div class="absolute -right-10 -bottom-10 opacity-5 pointer-events-none text-9xl text-sky-400">
                    <i class="fa-solid fa-id-badge"></i>
                </div>
                <div class="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                    <div>
                        <div class="flex items-center gap-2 mb-1">
                            <span class="px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-sky-950 text-sky-300 border border-sky-800">
                                <i class="fa-solid fa-fingerprint mr-1"></i> OSINT Identity Intelligence
                            </span>
                            <span class="text-xs text-slate-500 font-mono">Inspirado en UserRecon (wishihab/userrecon)</span>
                        </div>
                        <h3 class="text-xl font-bold text-white flex items-center gap-2">
                            <i class="fa-solid fa-id-badge text-sky-400"></i>
                            LoginRecon (Rastreo de Huella Digital & Cuentas Expuestas)
                        </h3>
                        <p class="text-xs text-slate-400 mt-1 max-w-3xl">
                            Sondeo asíncrono y en tiempo real de 100 redes sociales, plataformas de citas, comunidades de creadores, repositorios de código, comunidades y plataformas web para identificar cuentas asociadas a logins corporativos, desarrolladores o credenciales comprometidas.
                        </p>
                    </div>

                    <!-- Preset Loader -->
                    <div class="flex items-center gap-2 bg-slate-900/80 p-2.5 rounded-xl border border-cyber-border">
                        <i class="fa-solid fa-key text-sky-400 text-xs"></i>
                        <select id="loginrecon-preset-select" class="bg-slate-950 text-xs text-slate-200 border border-slate-700 rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-sky-500 max-w-[200px]">
                            <option value="">Logins / Fugas Detectadas...</option>
                        </select>
                        <button onclick="applyLoginReconPreset()" class="px-3 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold transition">
                            Cargar
                        </button>
                    </div>
                </div>
            </div>

            <!-- Search Bar Card -->
            <div class="bg-cyber-card border border-cyber-border rounded-2xl p-5 space-y-4">
                <div class="grid grid-cols-1 md:grid-cols-12 gap-3 items-end">
                    <div class="md:col-span-6">
                        <label class="block text-[10px] uppercase font-bold text-slate-400 mb-1">Usuario o Correo Electrónico Objetivo (OSINT & CTI)</label>
                        <div class="relative">
                            <span class="absolute inset-y-0 left-0 flex items-center pl-3 pointer-events-none text-slate-500 font-mono text-xs">@</span>
                            <input type="text" id="loginrecon-input-username" placeholder="ejemplo: usuario, dev@empresa.com, karen.tuu@gmail.com" class="w-full pl-8 pr-3 py-2 rounded-xl bg-slate-900 border border-cyber-border text-xs text-white placeholder-slate-500 focus:outline-none focus:border-sky-500 font-mono">
                        </div>
                    </div>
                    <div class="md:col-span-3">
                        <label class="block text-[10px] uppercase font-bold text-slate-400 mb-1">Categoría de Plataformas</label>
                        <select id="loginrecon-select-category" class="w-full bg-slate-900 border border-cyber-border rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-sky-500">
                            <option value="all">Todas las Plataformas (100)</option>
                            <option value="gov_co">🏛️ Gobierno Colombia (.gov.co)</option>
                            <option value="social">Redes Sociales (Twitter, Instagram, FB, Telegram...)</option>
                            <option value="dating">Citas & Relaciones (Tinder, Bumble, FetLife...)</option>
                            <option value="adult">Suscripción Creadores & Adulto (OnlyFans, Fansly, Pornhub...)</option>
                            <option value="creators">Comunidades de Creadores (Patreon, Ko-fi...)</option>
                            <option value="dev">Código & DevOps (GitHub, GitLab, BitBucket...)</option>
                            <option value="media">Multimedia & Streaming (YouTube, Spotify, Twitch...)</option>
                            <option value="blogs">Blogs & Foros (Medium, Substack, Reddit...)</option>
                            <option value="prof">Profesionales & Otros (Slack, Behance, Linktree...)</option>
                        </select>
                    </div>
                    <div class="md:col-span-3">
                        <button onclick="runLoginReconSearch()" id="btn-loginrecon-search" class="w-full px-5 py-2 rounded-xl bg-sky-600 hover:bg-sky-500 text-white text-xs font-bold transition flex items-center justify-center gap-2 shadow-lg shadow-sky-950/50">
                            <i class="fa-solid fa-magnifying-glass"></i>
                            <span>Rastrear Huella Digital</span>
                        </button>
                    </div>
                </div>

                <!-- Forensic Identity Attribution Dossier Card -->
                <div id="loginrecon-identity-dossier" class="hidden bg-gradient-to-r from-slate-900 via-sky-950/30 to-slate-900 border-2 border-sky-500/60 rounded-2xl p-5 shadow-2xl relative overflow-hidden space-y-4">
                    <div class="absolute -right-8 -bottom-8 opacity-10 pointer-events-none text-8xl text-sky-400">
                        <i class="fa-solid fa-user-secret"></i>
                    </div>
                    <div class="flex flex-col md:flex-row items-start md:items-center gap-5">
                        <!-- Avatar Box -->
                        <div class="relative flex-shrink-0">
                            <img id="dossier-avatar-img" src="" alt="Avatar" class="w-16 h-16 rounded-2xl border-2 border-sky-400 object-cover shadow-lg shadow-sky-950/80 bg-slate-900 hidden" />
                            <div id="dossier-avatar-placeholder" class="w-16 h-16 rounded-2xl border-2 border-sky-500/50 bg-slate-900 flex items-center justify-center text-sky-400 text-2xl shadow-lg">
                                <i class="fa-solid fa-user-shield"></i>
                            </div>
                            <div class="absolute -bottom-1 -right-1 w-5 h-5 rounded-full bg-emerald-500 border-2 border-slate-900 flex items-center justify-center text-[10px] text-black font-bold" title="Identidad Verificada">
                                <i class="fa-solid fa-check"></i>
                            </div>
                        </div>

                        <!-- Main Identity Header -->
                        <div class="flex-1 space-y-1">
                            <div class="flex flex-wrap items-center gap-2">
                                <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-sky-950 text-sky-300 border border-sky-800">
                                    <i class="fa-solid fa-magnifying-glass-chart mr-1"></i> Atribución de Identidad Forense
                                </span>
                                <span id="dossier-confidence-badge" class="px-2 py-0.5 rounded text-[10px] font-bold uppercase border bg-amber-950 text-amber-300 border-amber-700">
                                    Calculando...
                                </span>
                                <span id="dossier-username-badge" class="font-mono text-xs text-sky-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                                    @usuario
                                </span>
                            </div>
                            <h3 id="dossier-primary-name" class="text-xl font-black text-white flex items-center gap-2">
                                Identificando...
                            </h3>
                            <p id="dossier-method" class="text-xs text-slate-400 font-mono">
                                Método de atribución: Correlación OSINT
                            </p>
                        </div>

                        <!-- Metric Badges -->
                        <div class="flex md:flex-col items-center md:items-end gap-3 flex-shrink-0 border-t md:border-t-0 md:border-l border-slate-800 pt-3 md:pt-0 md:pl-5">
                            <div class="text-left md:text-right">
                                <span class="text-[10px] uppercase text-slate-500 font-bold block">Huella Detectada</span>
                                <span id="dossier-footprint" class="text-base font-black text-sky-400 font-mono">0%</span>
                            </div>
                            <div class="text-left md:text-right">
                                <span class="text-[10px] uppercase text-slate-500 font-bold block">Cuentas Confirmadas</span>
                                <span id="dossier-accounts-count" class="text-base font-black text-emerald-400 font-mono">0</span>
                            </div>
                        </div>
                    </div>

                    <!-- Forensic Details Drawer -->
                    <div id="dossier-details-grid" class="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs mt-4 pt-4 border-t border-cyber-border/70">
                        <div class="bg-slate-950/60 p-2.5 rounded-xl border border-slate-800/80">
                            <span class="text-[10px] font-bold uppercase text-slate-500 block mb-1">
                                <i class="fa-solid fa-envelope mr-1 text-emerald-400"></i> Emails Detectados en Commits
                            </span>
                            <div id="dossier-emails-container" class="font-mono text-emerald-400 text-xs">
                                No detectados
                            </div>
                        </div>
                        <div class="bg-slate-950/60 p-2.5 rounded-xl border border-slate-800/80">
                            <span class="text-[10px] font-bold uppercase text-slate-500 block mb-1">
                                <i class="fa-solid fa-building mr-1 text-sky-400"></i> Organización / Ubicación
                            </span>
                            <div id="dossier-org-loc" class="text-slate-300 text-xs">
                                No especificada
                            </div>
                        </div>
                        <div class="bg-slate-950/60 p-2.5 rounded-xl border border-slate-800/80">
                            <span class="text-[10px] font-bold uppercase text-slate-500 block mb-1">
                                <i class="fa-solid fa-network-wired mr-1 text-purple-400"></i> Fuentes Correlacionadas
                            </span>
                            <div id="dossier-sources-container" class="text-slate-300 text-xs">
                                0 fuentes
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Facebook AI Vision Correlation Panel -->
                <div id="loginrecon-facebook-ai-card" class="hidden bg-gradient-to-r from-slate-900 via-blue-950/20 to-slate-900 border-2 border-blue-500/40 rounded-2xl p-5 shadow-2xl relative overflow-hidden space-y-4">
                    <div class="absolute -right-6 -bottom-6 opacity-10 pointer-events-none text-8xl text-blue-400">
                        <i class="fa-brands fa-facebook"></i>
                    </div>
                    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                        <div class="space-y-1">
                            <div class="flex flex-wrap items-center gap-2">
                                <span class="px-2.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-blue-950 text-blue-300 border border-blue-800 flex items-center gap-1.5">
                                    <i class="fa-brands fa-facebook text-blue-400"></i> Correlación Facial Facebook (IA Vision)
                                </span>
                                <span id="fb-ai-badge" class="px-2.5 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-900 text-slate-400 border border-slate-800">
                                    Listo para Análisis
                                </span>
                            </div>
                            <h3 class="text-base sm:text-lg font-black text-white flex items-center gap-2">
                                Cruce Fotográfico y de Identidad Asistido por Visión Artificial
                            </h3>
                            <p class="text-xs text-slate-400">
                                Compara avatares extraídos (Instagram, GitHub, Pinterest) con perfiles en Facebook usando Computer Vision (pHash, SIFT/ORB y correlación cromática).
                            </p>
                        </div>
                        <div class="flex items-center gap-2 flex-shrink-0">
                            <button onclick="triggerFacebookAICorrelation()" id="btn-run-fb-ai" class="px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold transition flex items-center gap-2 shadow-lg shadow-blue-900/50">
                                <i class="fa-solid fa-wand-magic-sparkles"></i> Escanear Facebook con IA
                            </button>
                        </div>
                    </div>

                    <!-- Loading State -->
                    <div id="fb-ai-loading" class="hidden py-8 text-center space-y-2">
                        <div class="inline-block animate-spin text-blue-400 text-3xl">
                            <i class="fa-solid fa-circle-notch"></i>
                        </div>
                        <p class="text-xs text-slate-400 font-mono">Descargando candidatos públicos de Facebook y evaluando similitud biométrica con IA...</p>
                    </div>

                    <!-- Initial Placeholder -->
                    <div id="fb-ai-empty-message" class="text-xs text-slate-400/90 italic py-2 bg-slate-950/40 p-3 rounded-xl border border-slate-800/60 flex items-center gap-2">
                        <i class="fa-solid fa-circle-info text-blue-400"></i>
                        <span>Presiona <strong>"Escanear Facebook con IA"</strong> para cruzar automáticamente las fotos y nombres detectados con candidatos de Facebook.</span>
                    </div>

                    <!-- Candidates Grid -->
                    <div id="fb-ai-candidates-grid" class="hidden grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 pt-2">
                        <!-- Dynamically populated -->
                    </div>
                </div>

                <!-- Metrics & Export Card (Hidden until search) -->
                <div id="loginrecon-metrics-card" class="hidden border border-cyber-border rounded-xl p-4 bg-slate-950/70 space-y-4">
                    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-cyber-border/70 pb-3">
                        <div class="flex items-center gap-4">
                            <div>
                                <span class="text-[10px] uppercase text-slate-500 font-bold block">Plataformas Evaluadas</span>
                                <span id="loginrecon-stat-total" class="text-xl font-black text-white font-mono">0</span>
                            </div>
                            <div class="border-l border-slate-800 pl-4">
                                <span class="text-[10px] uppercase text-slate-500 font-bold block">Perfiles Confirmados</span>
                                <span id="loginrecon-stat-found" class="text-xl font-black text-emerald-400 font-mono">0</span>
                            </div>
                            <div class="border-l border-slate-800 pl-4">
                                <span class="text-[10px] uppercase text-slate-500 font-bold block">Tasa de Huella Digital</span>
                                <span id="loginrecon-stat-rate" class="text-xl font-black text-sky-400 font-mono">0%</span>
                            </div>
                            <div class="border-l border-slate-800 pl-4">
                                <span class="text-[10px] uppercase text-slate-500 font-bold block">Tiempo de Sondeo</span>
                                <span id="loginrecon-stat-time" class="text-xl font-black text-amber-400 font-mono">0 ms</span>
                            </div>
                        </div>

                        <!-- Export buttons -->
                        <div class="flex items-center gap-2">
                            <button onclick="exportLoginReconTxt()" class="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 text-xs font-semibold transition flex items-center gap-1.5" title="Descargar reporte .txt estilo UserRecon">
                                <i class="fa-solid fa-download text-emerald-400"></i>
                                <span>Descargar .TXT</span>
                            </button>
                            <button onclick="copyLoginReconLinks()" class="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 text-xs font-semibold transition flex items-center gap-1.5" title="Copiar URLs encontradas al portapapeles">
                                <i class="fa-solid fa-copy text-sky-400"></i>
                                <span>Copiar Enlaces</span>
                            </button>
                        </div>
                    </div>

                    <!-- Category Filter Pills inside Results -->
                    <div class="flex items-center gap-2 overflow-x-auto text-xs font-medium pt-1">
                        <button onclick="filterLoginReconCards('all')" id="loginrecon-filter-all" class="px-3 py-1 rounded-lg bg-sky-950 text-sky-300 border border-sky-800 transition font-bold shadow">Todas (<span id="count-pill-all">0</span>)</button>
                        <button onclick="filterLoginReconCards('found')" id="loginrecon-filter-found" class="px-3 py-1 rounded-lg bg-slate-900 text-slate-400 hover:text-white border border-cyber-border transition">Confirmadas (<span id="count-pill-found">0</span>)</button>
                        <button onclick="filterLoginReconCards('gov_co')" id="loginrecon-filter-gov_co" class="px-3 py-1 rounded-lg bg-slate-900 text-slate-400 hover:text-white border border-cyber-border transition">Gov (.gov.co) (<span id="count-pill-gov_co">0</span>)</button>
                        <button onclick="filterLoginReconCards('social')" id="loginrecon-filter-social" class="px-3 py-1 rounded-lg bg-slate-900 text-slate-400 hover:text-white border border-cyber-border transition">Social (<span id="count-pill-social">0</span>)</button>
                        <button onclick="filterLoginReconCards('dev')" id="loginrecon-filter-dev" class="px-3 py-1 rounded-lg bg-slate-900 text-slate-400 hover:text-white border border-cyber-border transition">DevOps (<span id="count-pill-dev">0</span>)</button>
                        <button onclick="filterLoginReconCards('media')" id="loginrecon-filter-media" class="px-3 py-1 rounded-lg bg-slate-900 text-slate-400 hover:text-white border border-cyber-border transition">Media (<span id="count-pill-media">0</span>)</button>
                        <button onclick="filterLoginReconCards('blogs')" id="loginrecon-filter-blogs" class="px-3 py-1 rounded-lg bg-slate-900 text-slate-400 hover:text-white border border-cyber-border transition">Blogs & Foros (<span id="count-pill-blogs">0</span>)</button>
                        <button onclick="filterLoginReconCards('dating')" id="loginrecon-filter-dating" class="px-3 py-1 rounded-lg bg-slate-900 text-slate-400 hover:text-white border border-cyber-border transition">Citas (<span id="count-pill-dating">0</span>)</button>
                        <button onclick="filterLoginReconCards('adult')" id="loginrecon-filter-adult" class="px-3 py-1 rounded-lg bg-slate-900 text-slate-400 hover:text-white border border-cyber-border transition">Adulto/Fans (<span id="count-pill-adult">0</span>)</button>
                        <button onclick="filterLoginReconCards('creators')" id="loginrecon-filter-creators" class="px-3 py-1 rounded-lg bg-slate-900 text-slate-400 hover:text-white border border-cyber-border transition">Creadores (<span id="count-pill-creators">0</span>)</button>
                        <button onclick="filterLoginReconCards('prof')" id="loginrecon-filter-prof" class="px-3 py-1 rounded-lg bg-slate-900 text-slate-400 hover:text-white border border-cyber-border transition">Profesional (<span id="count-pill-prof">0</span>)</button>
                    </div>
                </div>

                <!-- Results Grid -->
                <div id="loginrecon-results-container" class="space-y-3">
                    <div id="loginrecon-initial-message" class="text-center py-16 text-slate-500 space-y-3 border border-dashed border-slate-800 rounded-xl bg-slate-950/40">
                        <i class="fa-solid fa-id-badge text-5xl text-slate-600"></i>
                        <p class="text-xs max-w-md mx-auto">Ingresa un nombre de usuario o selecciona una credencial filtrada para iniciar el reconocimiento OSINT en 100 plataformas simultáneas.</p>
                    </div>
                    <div id="loginrecon-results-grid" class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3 hidden"></div>
                </div>
            </div>
        </section>

    
        <!-- TAB CONTENT: PHP2SHELL SCANNER (CVE-2026-109618 / CVE-2026-109619) -->
        <section id="tab-content-php2shell" class="space-y-6 hidden">
            <!-- Header Card -->
            <div class="bg-cyber-card border border-cyber-border rounded-2xl p-6 relative overflow-hidden">
                <div class="absolute -right-8 -bottom-8 opacity-5 pointer-events-none text-9xl text-indigo-400">
                    <i class="fa-brands fa-php"></i>
                </div>
                <div class="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                    <div class="space-y-2">
                        <div class="flex flex-wrap items-center gap-3">
                            <div class="w-10 h-10 rounded-xl bg-indigo-950/80 border border-indigo-700/80 flex items-center justify-center text-indigo-400 text-xl shadow-lg shadow-indigo-950/50">
                                <i class="fa-brands fa-php"></i>
                            </div>
                            <div>
                                <div class="flex items-center gap-2 flex-wrap">
                                    <h2 class="text-xl font-bold text-white tracking-tight">PHP2Shell Scanner — CVE-2026-109618 / CVE-2026-109619</h2>
                                    <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-300 border border-rose-700 font-mono">CVSS 9.2 CRITICAL</span>
                                    <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-indigo-950 text-indigo-300 border border-indigo-700 font-mono">100% PASIVO</span>
                                </div>
                                <p class="text-xs text-slate-400 mt-0.5">
                                    Detección diagnóstica y no intrusiva de versiones de PHP vulnerables a Ejecución Remota de Código (RCE) pre-autenticación.
                                </p>
                            </div>
                        </div>
                    </div>
                    <div class="flex items-center gap-2 text-xs">
                        <div class="px-3 py-1.5 rounded-xl bg-slate-900 border border-cyber-border flex items-center gap-2">
                            <i class="fa-brands fa-github text-slate-300"></i>
                            <span class="text-slate-400">Comunidad:</span>
                            <a href="https://github.com/GlobalsecureAcademy/php2shell-scanner-CVE-2026-109618-CVE-2026-109619" target="_blank" class="text-indigo-400 hover:text-indigo-300 font-mono font-semibold">GlobalsecureAcademy</a>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Scanner Control Card -->
            <div class="bg-cyber-card border border-cyber-border rounded-2xl p-6">
                <h3 class="text-base font-bold text-white flex items-center gap-2 mb-4">
                    <i class="fa-solid fa-radar text-indigo-400"></i>
                    Configuración de Auditoría de Exposición PHP2Shell
                </h3>

                <form onsubmit="runPhp2shellScan(event); return false;" class="space-y-4">
                    <div class="grid grid-cols-1 md:grid-cols-12 gap-4">
                        <!-- Target Selection (Only Preloaded Seeds) -->
                        <div class="md:col-span-6 space-y-1.5">
                            <label class="text-xs font-semibold text-slate-300 flex items-center justify-between">
                                <span class="flex items-center gap-1.5">
                                    <i class="fa-solid fa-crosshairs text-indigo-400"></i>
                                    <span>Objetivo a Auditar (Semilla Precargada):</span>
                                </span>
                                <span class="text-[10px] text-emerald-400 font-mono flex items-center gap-1">
                                    <i class="fa-solid fa-shield-halved text-[9px]"></i>
                                    <span>Alcance Autorizado Exclusivo</span>
                                </span>
                            </label>
                            <div class="relative">
                                <i class="fa-solid fa-server absolute left-3.5 top-3.5 text-indigo-400 text-xs"></i>
                                <select id="php2shell-target-select" onchange="onPhp2shellSeedSelect(this.value)"
                                    class="w-full pl-9 pr-4 py-2.5 rounded-xl bg-slate-900 border border-cyber-border text-xs text-white focus:outline-none focus:border-indigo-500 transition font-mono cursor-pointer font-bold">
                                    <option value="" class="bg-slate-900 text-slate-400">Cargando semillas precargadas del perímetro...</option>
                                </select>
                                <input type="hidden" id="php2shell-target-input" value="">
                            </div>
                            <div class="flex flex-wrap items-center gap-1.5 pt-1 text-[10px]">
                                <span class="text-slate-400 font-semibold">Semillas precargadas autorizadas:</span>
                                <div id="php2shell-quick-seeds" class="flex flex-wrap items-center gap-1.5">
                                    <span class="text-slate-500 italic text-[10px]">Cargando semillas...</span>
                                </div>
                            </div>
                        </div>

                        <!-- Mode Selector -->
                        <div class="md:col-span-3 space-y-1.5">
                            <label class="text-xs font-semibold text-slate-300">Modo de Escaneo:</label>
                            <select id="php2shell-mode-select" class="w-full px-3 py-2.5 rounded-xl bg-slate-900 border border-cyber-border text-xs text-white focus:outline-none focus:border-indigo-500 transition">
                                <option value="target" selected>Host / IP Individual (--target)</option>
                                <option value="domain">Dominio Completo + Subdominios (-d)</option>
                                <option value="cidr">Segmento de Red CIDR (--cidr)</option>
                            </select>
                        </div>

                        <!-- Ports Input -->
                        <div class="md:col-span-3 space-y-1.5">
                            <label class="text-xs font-semibold text-slate-300 flex items-center justify-between">
                                <span>Puertos a Sondear:</span>
                                <span class="text-[10px] text-slate-400">Separados por coma</span>
                            </label>
                            <input type="text" id="php2shell-ports-input" value="80,443" placeholder="80,443"
                                class="w-full px-3 py-2.5 rounded-xl bg-slate-900 border border-cyber-border text-xs text-white focus:outline-none focus:border-indigo-500 transition font-mono">
                        </div>
                    </div>

                    <!-- Additional Options & Action Button -->
                    <div class="pt-2 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-t border-cyber-border/60">
                        <div class="flex flex-wrap items-center gap-4 text-xs">
                            <label class="flex items-center gap-2 cursor-pointer text-slate-300 hover:text-white">
                                <input type="checkbox" id="php2shell-auto-origin" checked class="rounded bg-slate-900 border-slate-700 text-indigo-600 focus:ring-0">
                                <span>Bypass CDN (Auto-descubrir origen Cloudflare)</span>
                            </label>
                            <label class="flex items-center gap-2 cursor-pointer text-slate-300 hover:text-white">
                                <input type="checkbox" id="php2shell-only-vuln" class="rounded bg-slate-900 border-slate-700 text-rose-600 focus:ring-0">
                                <span>Mostrar solo vulnerables</span>
                            </label>
                            <div class="flex items-center gap-1.5 text-slate-400 text-[11px]">
                                <span>Timeout:</span>
                                <select id="php2shell-timeout-select" class="px-2 py-1 rounded-lg bg-slate-900 border border-cyber-border text-xs text-slate-300">
                                    <option value="4">4s</option>
                                    <option value="6" selected>6s (Recomendado)</option>
                                    <option value="10">10s</option>
                                    <option value="15">15s</option>
                                </select>
                            </div>
                        </div>

                        <button type="button" onclick="runPhp2shellScan(event)" id="php2shell-btn-submit" class="w-full sm:w-auto px-6 py-2.5 rounded-xl bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 text-white font-bold text-xs flex items-center justify-center gap-2 shadow-lg shadow-indigo-900/40 transition">
                            <i class="fa-solid fa-bolt-lightning"></i>
                            <span>Ejecutar Escáner PHP2Shell</span>
                        </button>
                    </div>
                </form>
            </div>

            <!-- KPI Summary Counters -->
            <div class="grid grid-cols-2 sm:grid-cols-5 gap-3">
                <div class="p-4 rounded-xl bg-slate-900/80 border border-cyber-border">
                    <div class="text-slate-400 text-xs mb-1">Total Sondeados</div>
                    <div id="php2shell-stat-total" class="text-xl font-bold font-mono text-white">0</div>
                </div>
                <div class="p-4 rounded-xl bg-rose-950/30 border border-rose-800/40">
                    <div class="text-rose-400 text-xs mb-1 flex items-center gap-1">
                        <i class="fa-solid fa-triangle-exclamation"></i>
                        Vulnerables
                    </div>
                    <div id="php2shell-stat-vuln" class="text-xl font-bold font-mono text-rose-400">0</div>
                </div>
                <div class="p-4 rounded-xl bg-emerald-950/30 border border-emerald-800/40">
                    <div class="text-emerald-400 text-xs mb-1 flex items-center gap-1">
                        <i class="fa-solid fa-shield-check"></i>
                        Parcheados
                    </div>
                    <div id="php2shell-stat-patched" class="text-xl font-bold font-mono text-emerald-400">0</div>
                </div>
                <div class="p-4 rounded-xl bg-amber-950/30 border border-amber-800/40">
                    <div class="text-amber-400 text-xs mb-1">expose_php Off</div>
                    <div id="php2shell-stat-unknown" class="text-xl font-bold font-mono text-amber-400">0</div>
                </div>
                <div class="p-4 rounded-xl bg-slate-900/80 border border-cyber-border">
                    <div class="text-slate-400 text-xs mb-1">Sin PHP / Filtro</div>
                    <div id="php2shell-stat-other" class="text-xl font-bold font-mono text-slate-400">0</div>
                </div>
            </div>

            <!-- Findings Table Card -->
            <div class="bg-cyber-card border border-cyber-border rounded-2xl p-6">
                <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-4">
                    <div>
                        <h3 class="text-base font-bold text-white flex items-center gap-2">
                            <i class="fa-solid fa-table-list text-indigo-400"></i>
                            Matriz de Resultados y Diagnóstico de Exposición
                        </h3>
                        <p class="text-xs text-slate-400 mt-0.5">Veredicto por host y puerto analizado con las versiones oficiales corregidas.</p>
                    </div>
                    <div class="flex items-center gap-2">
                        <button onclick="exportPhp2shellJson()" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs flex items-center gap-1.5 transition">
                            <i class="fa-solid fa-file-code text-cyan-400"></i>
                            <span>Exportar JSON</span>
                        </button>
                        <button onclick="exportPhp2shellCsv()" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs flex items-center gap-1.5 transition">
                            <i class="fa-solid fa-file-csv text-emerald-400"></i>
                            <span>Exportar CSV</span>
                        </button>
                    </div>
                </div>

                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs">
                        <thead class="bg-slate-900/60 text-slate-400 uppercase text-[10px] tracking-wider border-b border-cyber-border">
                            <tr>
                                <th class="p-4">Objetivo / Host</th>
                                <th class="p-4">IP & Puerto</th>
                                <th class="p-4">Versión Detectada</th>
                                <th class="p-4">Parche Oficial</th>
                                <th class="p-4">WAF / CDN</th>
                                <th class="p-4 text-center">Veredicto</th>
                                <th class="p-4">Detalle / Latencia</th>
                            </tr>
                        </thead>
                        <tbody id="php2shell-results-body" class="divide-y divide-cyber-border/60 text-slate-300">
                            <tr>
                                <td colspan="7" class="p-8 text-center text-slate-500">
                                    <i class="fa-brands fa-php text-3xl mb-2 text-indigo-400/40 block"></i>
                                    Configura el objetivo arriba y presiona "Ejecutar Escáner PHP2Shell" para iniciar la auditoría diagnóstica.
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Official Mitigation Playbook -->
            <div class="bg-cyber-card border border-cyber-border rounded-2xl p-6">
                <h3 class="text-base font-bold text-white flex items-center gap-2 mb-2">
                    <i class="fa-solid fa-shield-virus text-emerald-400"></i>
                    Guía de Mitigación y Versiones Parcheadas Oficiales
                </h3>
                <p class="text-xs text-slate-400 mb-4">
                    Para resolver la vulnerabilidad PHP2Shell (CVE-2026-109618 / CVE-2026-109619), la única remediación definitiva es actualizar el intérprete de PHP a las versiones seguras publicadas por el PHP Group:
                </p>

                <div class="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs mb-4">
                    <div class="p-3 rounded-xl bg-slate-900 border border-cyber-border font-mono">
                        <div class="text-slate-400 text-[10px]">Rama PHP 8.2:</div>
                        <strong class="text-emerald-400 text-sm">>= 8.2.35</strong>
                    </div>
                    <div class="p-3 rounded-xl bg-slate-900 border border-cyber-border font-mono">
                        <div class="text-slate-400 text-[10px]">Rama PHP 8.3:</div>
                        <strong class="text-emerald-400 text-sm">>= 8.3.36</strong>
                    </div>
                    <div class="p-3 rounded-xl bg-slate-900 border border-cyber-border font-mono">
                        <div class="text-slate-400 text-[10px]">Rama PHP 8.4:</div>
                        <strong class="text-emerald-400 text-sm">>= 8.4.27</strong>
                    </div>
                    <div class="p-3 rounded-xl bg-slate-900 border border-cyber-border font-mono">
                        <div class="text-slate-400 text-[10px]">Rama PHP 8.5:</div>
                        <strong class="text-emerald-400 text-sm">>= 8.5.12</strong>
                    </div>
                </div>

                <div class="p-4 rounded-xl bg-slate-950 border border-cyber-border font-mono text-[11px] text-slate-300 space-y-2">
                    <div class="text-slate-400 text-[10px] uppercase font-bold">Comandos de Actualización Rápida en Servidores:</div>
                    <div class="text-emerald-300"># Debian / Ubuntu (ppa:ondrej/php):</div>
                    <div class="text-slate-200">sudo apt update && sudo apt install --only-upgrade php8.2 php8.3 php8.4 libapache2-mod-php* php*-fpm</div>
                    <div class="text-emerald-300 mt-2"># RHEL / Rocky Linux / AlmaLinux (Remi Repo):</div>
                    <div class="text-slate-200">sudo dnf upgrade "php*"</div>
                    <div class="text-emerald-300 mt-2"># Mitigación Temporal mientras se programa mantenimiento (php.ini):</div>
                    <div class="text-amber-300">expose_php = Off</div>
                    <div class="text-amber-300">session.upload_progress.enabled = 0</div>
                </div>
            </div>
        </section>

        <!-- TAB CONTENT: CONNECTORS (OSINT & CTI HUB) -->
        <section id="tab-content-connectors" class="space-y-6 hidden">
            <div class="flex flex-col sm:flex-row items-center justify-between gap-4">
                <div>
                    <h3 class="text-lg font-bold text-white flex items-center gap-2">
                        <i class="fa-solid fa-plug text-teal-400"></i>
                        Centro de Conectores OSINT & Inteligencia de Amenazas
                    </h3>
                    <p class="text-xs text-slate-400">Gestión de conectores clasificados con separación estricta: fuentes gratuitas, con API key y comerciales.</p>
                </div>
                <div class="flex items-center gap-2">
                    <button onclick="syncCtiFeedsLive()" class="px-3 py-1.5 rounded-xl bg-gradient-to-r from-teal-500 to-emerald-600 text-white font-semibold text-xs shadow-lg shadow-teal-500/20 hover:from-teal-400 hover:to-emerald-500 transition flex items-center gap-1.5 cursor-pointer">
                        <i class="fa-solid fa-arrows-rotate"></i>
                        <span>Sincronizar Feeds Vivos</span>
                    </button>
                </div>
            </div>

            <!-- Connectors KPI Cards -->
            <div class="grid grid-cols-2 sm:grid-cols-4 gap-4">
                <div class="bg-cyber-card border border-cyber-border rounded-xl p-4">
                    <span class="text-[11px] text-slate-400 block font-medium">Total Conectores</span>
                    <strong id="conn-stat-total" class="text-xl font-bold text-white">16</strong>
                </div>
                <div class="bg-cyber-card border border-emerald-900/40 rounded-xl p-4">
                    <span class="text-[11px] text-emerald-400 block font-medium">Fuentes Gratuitas (Activas)</span>
                    <strong id="conn-stat-free" class="text-xl font-bold text-emerald-400">6</strong>
                </div>
                <div class="bg-cyber-card border border-amber-900/40 rounded-xl p-4">
                    <span class="text-[11px] text-amber-400 block font-medium">Requieren API Key</span>
                    <strong id="conn-stat-api" class="text-xl font-bold text-amber-400">6</strong>
                </div>
                <div class="bg-cyber-card border border-indigo-900/40 rounded-xl p-4">
                    <span class="text-[11px] text-indigo-400 block font-medium">Comerciales / Enterprise</span>
                    <strong id="conn-stat-comm" class="text-xl font-bold text-indigo-400">4</strong>
                </div>
            </div>

            <!-- Filter Buttons -->
            <div class="flex items-center gap-2 border-b border-cyber-border pb-3">
                <button onclick="filterConnectorsList('ALL')" id="conn-filter-ALL" class="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 text-teal-300 border border-teal-800/60 transition">Todos (16)</button>
                <button onclick="filterConnectorsList('FREE')" id="conn-filter-FREE" class="px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-400 hover:text-white hover:bg-slate-800 transition">Gratuitos (6)</button>
                <button onclick="filterConnectorsList('API_KEY')" id="conn-filter-API_KEY" class="px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-400 hover:text-white hover:bg-slate-800 transition">Con API Key (6)</button>
                <button onclick="filterConnectorsList('COMMERCIAL')" id="conn-filter-COMMERCIAL" class="px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-400 hover:text-white hover:bg-slate-800 transition">Comerciales (4)</button>
            </div>

            <!-- Connectors Grid -->
            <div id="connectors-grid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                <!-- Dynamically loaded -->
            </div>
        </section>

        <!-- TAB CONTENT: SCOPE & GOVERNANCE -->
        <section id="tab-content-scope" class="space-y-6 hidden">
            <div>
                <h3 class="text-lg font-bold text-white flex items-center gap-2">
                    <i class="fa-solid fa-shield-halved text-cyan-400"></i>
                    Gobernanza de Alcance Autorizado (Rules of Engagement)
                </h3>
                <p class="text-xs text-slate-400">Control estricto de objetivos legales. Los sondeos activos bloquean cualquier host fuera de esta lista y previenen SSRF contra IPs privadas.</p>
            </div>

            <!-- Anti-SSRF Defense Banner -->
            <div class="p-4 rounded-xl bg-cyan-950/30 border border-cyan-800/50 flex items-start gap-3">
                <i class="fa-solid fa-lock text-cyan-400 text-lg mt-0.5"></i>
                <div class="text-xs text-slate-300 space-y-1">
                    <strong class="text-white block font-semibold">Protección Perimetral Anti-SSRF Activa (RFC 1918 / Loopback / Link-Local)</strong>
                    <p class="text-slate-400">Todo intento de sondeo hacia rangos internos (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8) o metadatos cloud (169.254.169.254) es rechazado y registrado en la bitácora de auditoría.</p>
                </div>
            </div>

            <!-- Add Scope Form -->
            <div class="bg-cyber-card border border-cyber-border rounded-2xl p-6">
                <h4 class="text-sm font-bold text-white mb-4 flex items-center gap-2">
                    <i class="fa-solid fa-plus-circle text-cyan-400"></i>
                    Registrar Nuevo Objetivo en el Alcance Autorizado
                </h4>
                <form id="form-add-scope" onsubmit="handleAddScopeSubmit(event)" class="grid grid-cols-1 sm:grid-cols-12 gap-4">
                    <div class="sm:col-span-5">
                        <label class="block text-xs font-semibold text-slate-400 mb-1">Patrón de Objetivo (Dominio, Comodín o IP):</label>
                        <input type="text" id="scope-input-pattern" placeholder="ej: organizacion.com, *.organizacion.com, 200.1.2.3" required class="w-full bg-slate-900 border border-cyber-border rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-400 font-mono">
                    </div>
                    <div class="sm:col-span-2">
                        <label class="block text-xs font-semibold text-slate-400 mb-1">Tipo:</label>
                        <select id="scope-input-type" class="w-full bg-slate-900 border border-cyber-border rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-400">
                            <option value="DOMAIN">DOMAIN</option>
                            <option value="IP">IP</option>
                            <option value="CIDR">CIDR</option>
                        </select>
                    </div>
                    <div class="sm:col-span-3">
                        <label class="block text-xs font-semibold text-slate-400 mb-1">Justificación / RoE:</label>
                        <input type="text" id="scope-input-notes" placeholder="ej: Autorizado por CISO contrato #2026-B" class="w-full bg-slate-900 border border-cyber-border rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-400">
                    </div>
                    <div class="sm:col-span-2 flex items-end">
                        <button type="submit" class="w-full px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs transition cursor-pointer flex items-center justify-center gap-1.5">
                            <i class="fa-solid fa-check"></i>
                            <span>Autorizar</span>
                        </button>
                    </div>
                </form>
            </div>

            <!-- Scope Table -->
            <div class="bg-cyber-card border border-cyber-border rounded-2xl overflow-hidden">
                <div class="p-4 border-b border-cyber-border flex items-center justify-between">
                    <h4 class="text-sm font-bold text-white">Objetivos Legalmente Habilitados (<span id="scope-count">0</span>)</h4>
                    <input type="text" id="scope-filter-search" oninput="filterScopeTable()" placeholder="Filtrar alcance..." class="bg-slate-900 border border-cyber-border rounded-lg px-2.5 py-1 text-xs text-white focus:outline-none focus:border-cyan-400">
                </div>
                <div class="overflow-x-auto max-h-[500px]">
                    <table class="w-full text-left border-collapse text-xs">
                        <thead class="bg-slate-900/80 text-slate-400 font-semibold border-b border-cyber-border sticky top-0">
                            <tr>
                                <th class="p-3">Patrón de Alcance</th>
                                <th class="p-3">Tipo</th>
                                <th class="p-3">Autorizado Por</th>
                                <th class="p-3">Fecha de Alta</th>
                                <th class="p-3">Notas RoE</th>
                                <th class="p-3 text-center">Acciones</th>
                            </tr>
                        </thead>
                        <tbody id="scope-table-body" class="divide-y divide-cyber-border font-mono">
                            <!-- Dynamically loaded -->
                        </tbody>
                    </table>
                </div>
            </div>
        </section>

        <!-- TAB CONTENT: CLOUD EXPOSURE -->
        <section id="tab-content-cloud" class="space-y-6 hidden">
            <div class="flex flex-col sm:flex-row items-center justify-between gap-4">
                <div>
                    <h3 class="text-lg font-bold text-white flex items-center gap-2">
                        <i class="fa-solid fa-cloud text-blue-400"></i>
                        Exposición y Almacenamiento Cloud (AWS S3, Azure Blob, GCP)
                    </h3>
                    <p class="text-xs text-slate-400">Identificación de buckets públicos, permisos de listado no autorizados y recursos cloud expuestos externamente.</p>
                </div>
                <button onclick="triggerCloudScan()" class="px-4 py-2 rounded-xl bg-gradient-to-r from-blue-500 to-indigo-600 text-white font-semibold text-xs shadow-lg shadow-blue-500/20 hover:from-blue-400 hover:to-indigo-500 transition flex items-center gap-1.5 cursor-pointer">
                    <i class="fa-solid fa-radar"></i>
                    <span>Sondear Almacenamiento Cloud</span>
                </button>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div class="bg-cyber-card border border-cyber-border rounded-xl p-4 flex items-center gap-3">
                    <i class="fa-brands fa-aws text-amber-400 text-2xl"></i>
                    <div>
                        <span class="text-xs text-slate-400">AWS S3 Permutations</span>
                        <strong class="text-white block font-mono text-sm">&lt;domain&gt;.s3.amazonaws.com</strong>
                    </div>
                </div>
                <div class="bg-cyber-card border border-cyber-border rounded-xl p-4 flex items-center gap-3">
                    <i class="fa-brands fa-microsoft text-sky-400 text-2xl"></i>
                    <div>
                        <span class="text-xs text-slate-400">Azure Blob Storage</span>
                        <strong class="text-white block font-mono text-sm">&lt;domain&gt;.blob.core.windows.net</strong>
                    </div>
                </div>
                <div class="bg-cyber-card border border-cyber-border rounded-xl p-4 flex items-center gap-3">
                    <i class="fa-brands fa-google text-red-400 text-2xl"></i>
                    <div>
                        <span class="text-xs text-slate-400">Google Cloud Storage</span>
                        <strong class="text-white block font-mono text-sm">storage.googleapis.com/&lt;domain&gt;</strong>
                    </div>
                </div>
            </div>

            <!-- Cloud Exposures Table -->
            <div class="bg-cyber-card border border-cyber-border rounded-2xl overflow-hidden">
                <div class="p-4 border-b border-cyber-border">
                    <h4 class="text-sm font-bold text-white">Recursos Cloud Identificados</h4>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full text-left border-collapse text-xs">
                        <thead class="bg-slate-900/80 text-slate-400 font-semibold border-b border-cyber-border">
                            <tr>
                                <th class="p-3">Proveedor</th>
                                <th class="p-3">Recurso / Bucket</th>
                                <th class="p-3">URL Pública</th>
                                <th class="p-3">Estado de Exposición</th>
                                <th class="p-3">Diagnóstico</th>
                                <th class="p-3">Fecha</th>
                            </tr>
                        </thead>
                        <tbody id="cloud-table-body" class="divide-y divide-cyber-border font-mono">
                            <tr>
                                <td colspan="6" class="p-8 text-center text-slate-500 font-sans">
                                    Presiona "Sondear Almacenamiento Cloud" para verificar recursos públicos en AWS, Azure y Google Cloud.
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </section>

        <!-- TAB CONTENT: AI CORRELATION -->
        <section id="tab-content-ai" class="space-y-6 hidden">
            <div class="flex flex-col sm:flex-row items-center justify-between gap-4">
                <div>
                    <h3 class="text-lg font-bold text-white flex items-center gap-2">
                        <i class="fa-solid fa-brain text-purple-400"></i>
                        Correlación de Amenazas Asistida por Inteligencia Artificial
                    </h3>
                    <p class="text-xs text-slate-400">Síntesis determinista basada estrictamente en evidencias empíricas comprobables con mapeo MITRE ATT&CK.</p>
                </div>
                <button onclick="triggerAiCorrelation()" id="btn-run-ai" class="px-4 py-2 rounded-xl bg-gradient-to-r from-purple-600 to-indigo-600 text-white font-semibold text-xs shadow-lg shadow-purple-600/25 hover:from-purple-500 hover:to-indigo-500 transition flex items-center gap-1.5 cursor-pointer">
                    <i class="fa-solid fa-wand-magic-sparkles"></i>
                    <span>Generar Informe Ejecutivo IA</span>
                </button>
            </div>

            <div id="ai-report-container" class="bg-cyber-card border border-cyber-border rounded-2xl p-8 space-y-4 text-slate-300 text-xs leading-relaxed font-sans">
                <div class="text-center py-12 text-slate-500">
                    <i class="fa-solid fa-microchip text-4xl text-purple-400 mb-3 block"></i>
                    <strong class="text-white text-base block font-bold">Motor de Inteligencia de Amenazas Listo</strong>
                    <p class="text-xs text-slate-400 mt-1 max-w-md mx-auto">Haz clic en "Generar Informe Ejecutivo IA" para correlacionar activos vivos, vulnerabilidades confirmadas, vectores MITRE ATT&CK y prioridades NIST.</p>
                </div>
            </div>
        </section>
    
        <!-- MÓDULO 8: MITRE ATT&CK ENTERPRISE MATRIX -->
        <section id="tab-content-mitre" class="space-y-6 hidden">
            <div class="bg-cyber-card border border-slate-800 rounded-2xl p-6 shadow-xl">
                <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-4 mb-6">
                    <div>
                        <h3 class="text-lg font-bold text-white flex items-center gap-2">
                            <i class="fa-solid fa-chess-knight text-red-400"></i>
                            Matriz MITRE ATT&CK Enterprise (Mapeo a Superficie de Ataque)
                        </h3>
                        <p class="text-xs text-slate-400">Tácticas y técnicas empleadas por actores de amenazas correlacionadas con la exposición detectada en el perímetro.</p>
                    </div>
                    <button onclick="loadMitreMatrixUI()" class="px-3.5 py-1.5 bg-red-600/20 text-red-300 border border-red-700/50 rounded-xl text-xs hover:bg-red-600/30 flex items-center gap-2 transition">
                        <i class="fa-solid fa-arrows-rotate"></i> Recargar Matriz
                    </button>
                </div>
                <div id="mitre-matrix-container" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    <!-- Populated dynamically via JS -->
                </div>
            </div>
        </section>

        <!-- MÓDULO 9: IOC MANAGEMENT & STIX 2.1 -->
        <section id="tab-content-iocs" class="space-y-6 hidden">
            <div class="bg-cyber-card border border-slate-800 rounded-2xl p-6 shadow-xl">
                <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-4 mb-6">
                    <div>
                        <h3 class="text-lg font-bold text-white flex items-center gap-2">
                            <i class="fa-solid fa-crosshairs text-amber-400"></i>
                            Centro de Gestión de Indicadores de Compromiso (IoCs)
                        </h3>
                        <p class="text-xs text-slate-400">Base unificada de IPs maliciosas, dominios C2 y hashes bajo formato STIX 2.1.</p>
                    </div>
                    <div class="flex items-center gap-2">
                        <input type="text" id="ioc-search-filter" onkeyup="filterIoCsTable()" placeholder="Buscar IP, dominio, malware..." class="px-3 py-1.5 bg-slate-900 border border-slate-700 text-xs text-white rounded-xl focus:border-amber-500 outline-none w-52">
                        <button onclick="exportStixBundleUI()" class="px-3.5 py-1.5 bg-amber-600/20 text-amber-300 border border-amber-700/50 rounded-xl text-xs hover:bg-amber-600/30 flex items-center gap-2 transition">
                            <i class="fa-solid fa-file-export"></i> Exportar STIX 2.1
                        </button>
                    </div>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs text-slate-300">
                        <thead class="bg-slate-900/80 uppercase text-[10px] text-slate-400 border-b border-slate-800">
                            <tr>
                                <th class="py-3 px-4">Indicador (IoC)</th>
                                <th class="py-3 px-4">Tipo</th>
                                <th class="py-3 px-4">Familia Malware / Amenaza</th>
                                <th class="py-3 px-4">Fuente / Confiabilidad</th>
                                <th class="py-3 px-4">Estado</th>
                            </tr>
                        </thead>
                        <tbody id="iocs-table-body" class="divide-y divide-slate-800/50 font-mono">
                            <!-- Populated dynamically -->
                        </tbody>
                    </table>
                </div>
            </div>
        </section>

        <!-- MÓDULO 10: RANSOMWARE INTELLIGENCE -->
        <section id="tab-content-ransomware" class="space-y-6 hidden">
            <div class="bg-cyber-card border border-slate-800 rounded-2xl p-6 shadow-xl">
                <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-4 mb-6">
                    <div>
                        <h3 class="text-lg font-bold text-white flex items-center gap-2">
                            <i class="fa-solid fa-skull-crossbones text-rose-400"></i>
                            Telemetría Global de Ransomware & Grupos de Extorsión
                        </h3>
                        <p class="text-xs text-slate-400">Monitoreo continuo de sitios de divulgación (DLS) en la Dark Web con verificación de coincidencias sobre el perímetro corporativo.</p>
                    </div>
                    <button onclick="runDarkWebCorrelationUI()" class="px-3.5 py-1.5 bg-rose-600/20 text-rose-300 border border-rose-700/50 rounded-xl text-xs hover:bg-rose-600/30 flex items-center gap-2 transition">
                        <i class="fa-solid fa-magnifying-glass-arrow-right"></i> Correlacionar Semillas Ahora
                    </button>
                </div>
                <div id="ransomware-intel-stats" class="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6">
                    <div class="p-4 bg-slate-900/60 border border-slate-800 rounded-xl">
                        <span class="text-xs text-slate-400">Víctimas Globales Monitoreadas</span>
                        <div class="text-2xl font-black text-white mt-1" id="rw-stat-total">100</div>
                    </div>
                    <div class="p-4 bg-slate-900/60 border border-slate-800 rounded-xl">
                        <span class="text-xs text-slate-400">Coincidencias en Semillas</span>
                        <div class="text-2xl font-black text-rose-400 mt-1" id="rw-stat-matched">0</div>
                    </div>
                    <div class="p-4 bg-slate-900/60 border border-slate-800 rounded-xl">
                        <span class="text-xs text-slate-400">Sindicatos Criminales Activos</span>
                        <div class="text-2xl font-black text-amber-400 mt-1">42</div>
                    </div>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs text-slate-300">
                        <thead class="bg-slate-900/80 uppercase text-[10px] text-slate-400 border-b border-slate-800">
                            <tr>
                                <th class="py-3 px-4">Grupo de Ransomware</th>
                                <th class="py-3 px-4">Víctima Anunciada</th>
                                <th class="py-3 px-4">Fecha Descubrimiento</th>
                                <th class="py-3 px-4">Estado / Coincidencia</th>
                                <th class="py-3 px-4">Severidad</th>
                            </tr>
                        </thead>
                        <tbody id="ransomware-table-body" class="divide-y divide-slate-800/50">
                            <!-- Populated dynamically -->
                        </tbody>
                    </table>
                </div>
            </div>
        </section>

        <!-- MÓDULO 11: RISK SCORING EXPLICABLE -->
        <section id="tab-content-riskscoring" class="space-y-6 hidden">
            <div class="bg-cyber-card border border-slate-800 rounded-2xl p-6 shadow-xl">
                <div class="border-b border-slate-800/80 pb-4 mb-6">
                    <h3 class="text-lg font-bold text-white flex items-center gap-2">
                        <i class="fa-solid fa-chart-line text-cyan-400"></i>
                        Motor de Ponderación y Explicabilidad de Riesgo (Exposure Score)
                    </h3>
                    <p class="text-xs text-slate-400">Cálculo transparente basado en CVSS v3.1, percentil EPSS, presencia en CISA KEV, exposición perimetral y mitigaciones verificadas.</p>
                </div>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div class="p-5 bg-slate-900/60 border border-slate-800 rounded-xl space-y-4">
                        <h4 class="text-sm font-semibold text-white">Ponderación Oficial de Criterios (Suma = 100%)</h4>
                        <div class="space-y-3 text-xs">
                            <div>
                                <div class="flex justify-between mb-1"><span class="text-slate-300">Severidad Técnica Base (CVSS v3.1)</span><span class="text-cyan-400 font-bold">25%</span></div>
                                <div class="w-full bg-slate-800 h-2 rounded"><div class="bg-cyan-500 h-2 rounded" style="width: 25%"></div></div>
                            </div>
                            <div>
                                <div class="flex justify-between mb-1"><span class="text-slate-300">Explotabilidad en el Mundo Real (FIRST.org EPSS)</span><span class="text-emerald-400 font-bold">20%</span></div>
                                <div class="w-full bg-slate-800 h-2 rounded"><div class="bg-emerald-500 h-2 rounded" style="width: 20%"></div></div>
                            </div>
                            <div>
                                <div class="flex justify-between mb-1"><span class="text-slate-300">Explotación Activa Confirmada (CISA KEV)</span><span class="text-red-400 font-bold">25%</span></div>
                                <div class="w-full bg-slate-800 h-2 rounded"><div class="bg-red-500 h-2 rounded" style="width: 25%"></div></div>
                            </div>
                            <div>
                                <div class="flex justify-between mb-1"><span class="text-slate-300">Nivel de Exposición Perimetral & Puertos Vivos</span><span class="text-amber-400 font-bold">15%</span></div>
                                <div class="w-full bg-slate-800 h-2 rounded"><div class="bg-amber-500 h-2 rounded" style="width: 15%"></div></div>
                            </div>
                            <div>
                                <div class="flex justify-between mb-1"><span class="text-slate-300">Amenaza de Ransomware & Fugas CTI</span><span class="text-purple-400 font-bold">15%</span></div>
                                <div class="w-full bg-slate-800 h-2 rounded"><div class="bg-purple-500 h-2 rounded" style="width: 15%"></div></div>
                            </div>
                        </div>
                    </div>
                    <div class="p-5 bg-slate-900/60 border border-slate-800 rounded-xl space-y-4">
                        <h4 class="text-sm font-semibold text-white">Impacto según Estado de Validación Forense</h4>
                        <div class="space-y-2 text-xs">
                            <div class="p-2.5 rounded bg-red-950/40 border border-red-800/60 flex items-center justify-between">
                                <span class="font-bold text-red-300">VALIDADA (Técnicamente Confirmada)</span>
                                <span class="text-red-400 font-mono">+15% Multiplicador</span>
                            </div>
                            <div class="p-2.5 rounded bg-amber-950/40 border border-amber-800/60 flex items-center justify-between">
                                <span class="font-bold text-amber-300">PROBABLE (Versión dentro de rango CVE)</span>
                                <span class="text-amber-400 font-mono">100% Impacto Base</span>
                            </div>
                            <div class="p-2.5 rounded bg-blue-950/40 border border-blue-800/60 flex items-center justify-between">
                                <span class="font-bold text-blue-300">POTENCIAL / INFO_INSUFICIENTE</span>
                                <span class="text-blue-400 font-mono">75% Impacto Reducido</span>
                            </div>
                            <div class="p-2.5 rounded bg-slate-950/40 border border-slate-700/60 flex items-center justify-between">
                                <span class="font-bold text-slate-300">RIESGO_ACEPTADO (403 Cloud Block)</span>
                                <span class="text-slate-400 font-mono">Penalización Mínima</span>
                            </div>
                            <div class="p-2.5 rounded bg-emerald-950/40 border border-emerald-800/60 flex items-center justify-between">
                                <span class="font-bold text-emerald-300">FALSO_POSITIVO / MITIGADA</span>
                                <span class="text-emerald-400 font-mono font-bold">0% (Riesgo Nulo)</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <!-- MÓDULO 13: REPORTES & EXPORTACIÓN -->
        <section id="tab-content-reports" class="space-y-6 hidden">
            <div class="bg-cyber-card border border-slate-800 rounded-2xl p-6 shadow-xl">
                <div class="border-b border-slate-800/80 pb-4 mb-6">
                    <h3 class="text-lg font-bold text-white flex items-center gap-2">
                        <i class="fa-solid fa-file-invoice text-emerald-400"></i>
                        Centro de Generación de Reportes y Exportación Ejecutiva
                    </h3>
                    <p class="text-xs text-slate-400">Exporta informes ejecutivos en HTML/PDF, bundles de inteligencia en formato STIX 2.1 y solicitudes formales de Takedown (RFC 2142).</p>
                </div>
                <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div class="p-5 bg-slate-900/60 border border-slate-800 rounded-xl flex flex-col justify-between">
                        <div>
                            <div class="w-10 h-10 rounded-xl bg-emerald-950 border border-emerald-800 flex items-center justify-center text-emerald-400 mb-3 text-lg">
                                <i class="fa-solid fa-file-pdf"></i>
                            </div>
                            <h4 class="text-base font-bold text-white">Informe Ejecutivo de Exposición</h4>
                            <p class="text-xs text-slate-400 mt-1">Reporte completo con métricas de postura, activos vivos, desglose CISA KEV y recomendaciones de mitigación.</p>
                        </div>
                        <a href="report.php" target="_blank" class="mt-4 w-full py-2 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold text-center rounded-xl text-xs transition block">
                            <i class="fa-solid fa-external-link mr-1"></i> Abrir Reporte Ejecutivo
                        </a>
                    </div>
                    <div class="p-5 bg-slate-900/60 border border-slate-800 rounded-xl flex flex-col justify-between">
                        <div>
                            <div class="w-10 h-10 rounded-xl bg-cyan-950 border border-cyan-800 flex items-center justify-center text-cyan-400 mb-3 text-lg">
                                <i class="fa-solid fa-file-code"></i>
                            </div>
                            <h4 class="text-base font-bold text-white">Exportación STIX 2.1 Bundle</h4>
                            <p class="text-xs text-slate-400 mt-1">Exporta todos los activos, vulnerabilidades e indicadores en formato estándar STIX 2.1 para OpenCTI y MISP.</p>
                        </div>
                        <button onclick="exportStixBundleUI()" class="mt-4 w-full py-2 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-center rounded-xl text-xs transition">
                            <i class="fa-solid fa-download mr-1"></i> Descargar STIX 2.1 JSON
                        </button>
                    </div>
                    <div class="p-5 bg-slate-900/60 border border-slate-800 rounded-xl flex flex-col justify-between">
                        <div>
                            <div class="w-10 h-10 rounded-xl bg-purple-950 border border-purple-800 flex items-center justify-center text-purple-400 mb-3 text-lg">
                                <i class="fa-solid fa-gavel"></i>
                            </div>
                            <h4 class="text-base font-bold text-white">Plantilla de Solicitud Takedown</h4>
                            <p class="text-xs text-slate-400 mt-1">Avisos formales de abuso dirigidos a registradores y proveedores de hosting para retiro de sitios phishing.</p>
                        </div>
                        <button onclick="switchTab('drp')" class="mt-4 w-full py-2 bg-purple-600 hover:bg-purple-500 text-white font-bold text-center rounded-xl text-xs transition">
                            <i class="fa-solid fa-arrow-right mr-1"></i> Ir a Módulo DRP
                        </button>
                    </div>
                </div>
            </div>
        </section>


        <!-- TAB CONTENT: DARK INTELLIGENCE PRO -->
        <?php include __DIR__ . '/darkintel.php'; ?>

        <!-- TAB CONTENT: EMAIL INTELLIGENCE (ZEHEF OSINT) -->
        <?php include __DIR__ . '/email_intel.php'; ?>

</main>

            </main>
        </div>
    </div>


    <!-- Custom Theme Editor Modal (Fortinet Theme Customizer) -->
    <div id="theme-customizer-modal" class="fixed inset-0 modal-backdrop-forti z-50 flex items-center justify-center p-4 hidden">
        <div class="modal-content-forti max-w-4xl w-full p-6 shadow-2xl relative max-h-[92vh] flex flex-col">
            <!-- Modal Header -->
            <div class="flex items-center justify-between pb-3 border-b border-cyber-border">
                <div class="flex items-center gap-2.5">
                    <div class="w-8 h-8 rounded bg-gradient-to-tr from-emerald-600 to-teal-400 flex items-center justify-center text-black font-bold">
                        <i class="fa-solid fa-palette text-sm"></i>
                    </div>
                    <div>
                        <h3 class="font-bold text-white text-base">Editor de Temas Personalizados FortiRecon</h3>
                        <p class="text-xs text-slate-400">Diseña, personaliza y guarda paletas corporativas exclusivas para tu cuenta de analista.</p>
                    </div>
                </div>
                <button onclick="closeThemeCustomizer()" class="text-slate-400 hover:text-white p-1 rounded">
                    <i class="fa-solid fa-xmark text-lg"></i>
                </button>
            </div>

            <!-- Modal Body -->
            <div class="py-4 overflow-y-auto flex-1 space-y-5 text-xs">
                <!-- Theme Name & Base Preset Selection -->
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 bg-black/20 p-4 rounded-lg border border-cyber-border">
                    <div>
                        <label class="block text-slate-300 font-semibold mb-1">Nombre del Tema Personalizado</label>
                        <input type="text" id="custom-theme-name" value="Mi Tema Corporativo" class="forti-input w-full" placeholder="Ej. CyberSec SOC Alpha" />
                    </div>
                    <div>
                        <label class="block text-slate-300 font-semibold mb-1">Cargar Plantilla Base</label>
                        <select id="custom-theme-base-preset" onchange="loadPresetIntoCustomizer(this.value)" class="forti-input w-full">
                            <option value="jade">Jade (Verde Fortinet Clásico)</option>
                            <option value="neutrino">Neutrino (Cian Tecnológico)</option>
                            <option value="mariner">Mariner (Azul Marino Corporativo)</option>
                            <option value="graphite">Graphite (Gris Carbón Neutro)</option>
                            <option value="melongene">Melongene (Púrpura Berenjena)</option>
                            <option value="retro">Retro (Ámbar Industrial)</option>
                            <option value="darkmatter">Dark Matter (Negro Profundo & Teal)</option>
                            <option value="onyx">Onyx (Negro Ónice & Platino)</option>
                            <option value="eclipse">Eclipse (Azul Noche & Oro)</option>
                        </select>
                    </div>
                </div>

                <!-- Color Pickers Grid (12 Tokens) -->
                <div>
                    <h4 class="font-bold text-slate-200 uppercase tracking-wider text-[11px] mb-3 flex items-center gap-1.5">
                        <i class="fa-solid fa-eye-dropper text-teal-400"></i>
                        <span>Paleta de 12 Tokens de Diseño FortiOS</span>
                    </h4>
                    <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
                        <div class="bg-black/30 p-2.5 rounded border border-cyber-border">
                            <label class="block text-[11px] text-slate-400 mb-1">Barra Superior (Header)</label>
                            <div class="flex items-center gap-2">
                                <input type="color" id="picker-header-bg" onchange="updateThemePreview()" class="w-8 h-8 rounded cursor-pointer border-0 bg-transparent" />
                                <input type="text" id="text-header-bg" oninput="syncColorInput('header-bg')" class="forti-input w-20 font-mono text-[11px]" />
                            </div>
                        </div>

                        <div class="bg-black/30 p-2.5 rounded border border-cyber-border">
                            <label class="block text-[11px] text-slate-400 mb-1">Menú Lateral (Sidebar)</label>
                            <div class="flex items-center gap-2">
                                <input type="color" id="picker-sidebar-bg" onchange="updateThemePreview()" class="w-8 h-8 rounded cursor-pointer border-0 bg-transparent" />
                                <input type="text" id="text-sidebar-bg" oninput="syncColorInput('sidebar-bg')" class="forti-input w-20 font-mono text-[11px]" />
                            </div>
                        </div>

                        <div class="bg-black/30 p-2.5 rounded border border-cyber-border">
                            <label class="block text-[11px] text-slate-400 mb-1">Hover en Menú</label>
                            <div class="flex items-center gap-2">
                                <input type="color" id="picker-sidebar-hover" onchange="updateThemePreview()" class="w-8 h-8 rounded cursor-pointer border-0 bg-transparent" />
                                <input type="text" id="text-sidebar-hover" oninput="syncColorInput('sidebar-hover')" class="forti-input w-20 font-mono text-[11px]" />
                            </div>
                        </div>

                        <div class="bg-black/30 p-2.5 rounded border border-cyber-border">
                            <label class="block text-[11px] text-slate-400 mb-1">Elemento Activo (Selección)</label>
                            <div class="flex items-center gap-2">
                                <input type="color" id="picker-selection" onchange="updateThemePreview()" class="w-8 h-8 rounded cursor-pointer border-0 bg-transparent" />
                                <input type="text" id="text-selection" oninput="syncColorInput('selection')" class="forti-input w-20 font-mono text-[11px]" />
                            </div>
                        </div>

                        <div class="bg-black/30 p-2.5 rounded border border-cyber-border">
                            <label class="block text-[11px] text-slate-400 mb-1">Botón Primario</label>
                            <div class="flex items-center gap-2">
                                <input type="color" id="picker-primary" onchange="updateThemePreview()" class="w-8 h-8 rounded cursor-pointer border-0 bg-transparent" />
                                <input type="text" id="text-primary" oninput="syncColorInput('primary')" class="forti-input w-20 font-mono text-[11px]" />
                            </div>
                        </div>

                        <div class="bg-black/30 p-2.5 rounded border border-cyber-border">
                            <label class="block text-[11px] text-slate-400 mb-1">Color de Acento</label>
                            <div class="flex items-center gap-2">
                                <input type="color" id="picker-accent" onchange="updateThemePreview()" class="w-8 h-8 rounded cursor-pointer border-0 bg-transparent" />
                                <input type="text" id="text-accent" oninput="syncColorInput('accent')" class="forti-input w-20 font-mono text-[11px]" />
                            </div>
                        </div>

                        <div class="bg-black/30 p-2.5 rounded border border-cyber-border">
                            <label class="block text-[11px] text-slate-400 mb-1">Fondo Principal</label>
                            <div class="flex items-center gap-2">
                                <input type="color" id="picker-bg-main" onchange="updateThemePreview()" class="w-8 h-8 rounded cursor-pointer border-0 bg-transparent" />
                                <input type="text" id="text-bg-main" oninput="syncColorInput('bg-main')" class="forti-input w-20 font-mono text-[11px]" />
                            </div>
                        </div>

                        <div class="bg-black/30 p-2.5 rounded border border-cyber-border">
                            <label class="block text-[11px] text-slate-400 mb-1">Tarjetas & Paneles</label>
                            <div class="flex items-center gap-2">
                                <input type="color" id="picker-card-bg" onchange="updateThemePreview()" class="w-8 h-8 rounded cursor-pointer border-0 bg-transparent" />
                                <input type="text" id="text-card-bg" oninput="syncColorInput('card-bg')" class="forti-input w-20 font-mono text-[11px]" />
                            </div>
                        </div>

                        <div class="bg-black/30 p-2.5 rounded border border-cyber-border">
                            <label class="block text-[11px] text-slate-400 mb-1">Cabecera de Tarjeta</label>
                            <div class="flex items-center gap-2">
                                <input type="color" id="picker-card-header" onchange="updateThemePreview()" class="w-8 h-8 rounded cursor-pointer border-0 bg-transparent" />
                                <input type="text" id="text-card-header" oninput="syncColorInput('card-header')" class="forti-input w-20 font-mono text-[11px]" />
                            </div>
                        </div>

                        <div class="bg-black/30 p-2.5 rounded border border-cyber-border">
                            <label class="block text-[11px] text-slate-400 mb-1">Bordes & Separadores</label>
                            <div class="flex items-center gap-2">
                                <input type="color" id="picker-border" onchange="updateThemePreview()" class="w-8 h-8 rounded cursor-pointer border-0 bg-transparent" />
                                <input type="text" id="text-border" oninput="syncColorInput('border')" class="forti-input w-20 font-mono text-[11px]" />
                            </div>
                        </div>

                        <div class="bg-black/30 p-2.5 rounded border border-cyber-border">
                            <label class="block text-[11px] text-slate-400 mb-1">Texto Principal</label>
                            <div class="flex items-center gap-2">
                                <input type="color" id="picker-text-main" onchange="updateThemePreview()" class="w-8 h-8 rounded cursor-pointer border-0 bg-transparent" />
                                <input type="text" id="text-text-main" oninput="syncColorInput('text-main')" class="forti-input w-20 font-mono text-[11px]" />
                            </div>
                        </div>

                        <div class="bg-black/30 p-2.5 rounded border border-cyber-border">
                            <label class="block text-[11px] text-slate-400 mb-1">Texto Secundario</label>
                            <div class="flex items-center gap-2">
                                <input type="color" id="picker-text-muted" onchange="updateThemePreview()" class="w-8 h-8 rounded cursor-pointer border-0 bg-transparent" />
                                <input type="text" id="text-text-muted" oninput="syncColorInput('text-muted')" class="forti-input w-20 font-mono text-[11px]" />
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Real-time Live Interactive Preview -->
                <div>
                    <h4 class="font-bold text-slate-200 uppercase tracking-wider text-[11px] mb-2 flex items-center gap-1.5">
                        <i class="fa-solid fa-desktop text-teal-400"></i>
                        <span>Previsualización Dinámica en Tiempo Real</span>
                    </h4>
                    <div id="theme-preview-box" class="p-4 rounded-lg border overflow-hidden transition-all duration-150 space-y-3">
                        <!-- Mock Topbar -->
                        <div id="prev-header" class="p-2.5 rounded flex items-center justify-between border">
                            <div class="flex items-center gap-2">
                                <i class="fa-solid fa-shield-halved text-sm" id="prev-accent-icon"></i>
                                <strong id="prev-header-title">OpenRecon Mockup</strong>
                            </div>
                            <div class="flex items-center gap-2">
                                <button id="prev-btn-primary" class="px-2.5 py-1 rounded text-xs font-bold">Botón Primario</button>
                                <span id="prev-badge-crit" class="px-2 py-0.5 rounded text-[10px] font-bold">Crítico</span>
                            </div>
                        </div>

                        <!-- Mock Layout: Sidebar + Table -->
                        <div class="grid grid-cols-12 gap-3">
                            <div id="prev-sidebar" class="col-span-4 p-2 rounded border space-y-1">
                                <div class="text-[9px] uppercase font-bold text-slate-400 px-1">Navegación</div>
                                <div id="prev-nav-active" class="p-1.5 rounded text-xs font-bold flex items-center gap-1.5 border-l-2">
                                    <i class="fa-solid fa-server text-[10px]"></i>
                                    <span>Activo Seleccionado</span>
                                </div>
                                <div id="prev-nav-normal" class="p-1.5 rounded text-xs text-slate-400 flex items-center gap-1.5">
                                    <i class="fa-solid fa-crosshairs text-[10px]"></i>
                                    <span>Elemento Inactivo</span>
                                </div>
                            </div>

                            <div id="prev-card" class="col-span-8 p-3 rounded border space-y-2">
                                <div id="prev-card-hdr" class="font-bold text-xs pb-1 border-b">Panel Administrativo</div>
                                <div class="text-[11px] leading-relaxed" id="prev-text-sample">
                                    Previsualización de contraste para analistas SOC. Legibilidad verificada según norma WCAG 2.1 AA.
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Modal Footer Actions -->
            <div class="pt-3 border-t border-cyber-border flex items-center justify-between flex-wrap gap-2">
                <div class="flex items-center gap-2">
                    <button onclick="resetToDefaultTheme()" class="forti-btn-secondary text-xs">
                        <i class="fa-solid fa-rotate-left"></i>
                        <span>Restablecer a Jade</span>
                    </button>
                    <button onclick="duplicateCustomTheme()" class="forti-btn-secondary text-xs">
                        <i class="fa-solid fa-clone"></i>
                        <span>Duplicar Tema</span>
                    </button>
                </div>
                <div class="flex items-center gap-2">
                    <button onclick="closeThemeCustomizer()" class="forti-btn-secondary text-xs">
                        <span>Cancelar</span>
                    </button>
                    <button onclick="saveAndApplyCustomTheme()" class="forti-btn-primary text-xs font-bold">
                        <i class="fa-solid fa-floppy-disk"></i>
                        <span>Guardar y Aplicar</span>
                    </button>
                </div>
            </div>
        </div>
    </div>

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
                    <div class="absolute top-3 right-3 flex items-center gap-2">
                        <button onclick="copyTakedownText()" class="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs flex items-center gap-1.5 shadow transition">
                            <i class="fa-solid fa-copy"></i>
                            <span>Copiar Notificación</span>
                        </button>
                        <button onclick="downloadTakedownNotice()" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-semibold text-xs flex items-center gap-1.5 shadow transition">
                            <i class="fa-solid fa-download"></i>
                            <span>Descargar (.txt)</span>
                        </button>
                    </div>
                </div>
            </div>

            <div class="mt-6 flex justify-end">
                <button onclick="closeTakedownModal()" class="px-5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold">
                    Cerrar
                </button>
            </div>
        </div>
    </div>

    <!-- CTI Incident Advisory Modal -->
    <div id="cti-advisory-modal" class="fixed inset-0 bg-black/85 backdrop-blur-md z-50 flex items-center justify-center p-4 hidden">
        <div class="bg-cyber-card border border-rose-500/60 rounded-2xl max-w-3xl w-full p-6 shadow-2xl relative max-h-[90vh] flex flex-col">
            <div class="flex items-center justify-between pb-4 border-b border-cyber-border">
                <div class="flex items-center gap-3">
                    <div class="w-10 h-10 rounded-xl bg-rose-950/80 border border-rose-700/80 flex items-center justify-center text-rose-400 text-lg shadow-lg shadow-rose-950/50">
                        <i class="fa-solid fa-shield-virus"></i>
                    </div>
                    <div>
                        <div class="flex items-center gap-2">
                            <h3 class="font-bold text-white text-base">Alerta Temprana de Extorsión & Ransomware</h3>
                            <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-300 border border-amber-700 font-mono">TLP:AMBER+STRICT</span>
                        </div>
                        <p class="text-xs text-slate-400">Comunicado confidencial CSIRT / CISO y Guía de Contención Inmediata (NIST SP 800-61r2).</p>
                    </div>
                </div>
                <button onclick="closeCtiAdvisoryModal()" class="text-slate-400 hover:text-white p-2 rounded-lg bg-slate-800/60 border border-slate-700/50 transition">
                    <i class="fa-solid fa-xmark text-lg"></i>
                </button>
            </div>

            <div class="mt-4 grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
                <div class="p-2.5 rounded-xl bg-slate-900/90 border border-cyber-border">
                    <span class="text-slate-400 text-[10px] block">Organización Objetivo:</span>
                    <strong id="advisory-victim" class="text-white font-mono truncate block">-</strong>
                </div>
                <div class="p-2.5 rounded-xl bg-slate-900/90 border border-cyber-border">
                    <span class="text-slate-400 text-[10px] block">Sindicato Atacante:</span>
                    <strong id="advisory-group" class="text-purple-400 font-mono truncate block">-</strong>
                </div>
                <div class="p-2.5 rounded-xl bg-slate-900/90 border border-cyber-border">
                    <span class="text-slate-400 text-[10px] block">Ultimátum / Timer:</span>
                    <strong id="advisory-deadline" class="text-amber-400 font-mono truncate block">-</strong>
                </div>
                <div class="p-2.5 rounded-xl bg-slate-900/90 border border-cyber-border">
                    <span class="text-slate-400 text-[10px] block">Volumen Exfiltrado:</span>
                    <strong id="advisory-size" class="text-cyan-400 font-mono truncate block">-</strong>
                </div>
            </div>

            <div class="mt-4 flex-1 flex flex-col min-h-0 relative">
                <textarea id="cti-advisory-text" readonly class="w-full flex-1 p-4 rounded-xl bg-slate-950 border border-cyber-border font-mono text-[11px] text-slate-300 focus:outline-none resize-none leading-relaxed overflow-y-auto" rows="12"></textarea>
            </div>

            <div class="mt-4 pt-3 border-t border-cyber-border flex flex-wrap items-center justify-between gap-3">
                <div class="flex items-center gap-2">
                    <button onclick="copyCtiAdvisoryText()" class="px-4 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs flex items-center gap-2 shadow-lg shadow-rose-900/40 transition">
                        <i class="fa-solid fa-copy"></i>
                        <span>Copiar Comunicado</span>
                    </button>
                    <button onclick="downloadCtiAdvisoryText('txt')" class="px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-semibold text-xs flex items-center gap-1.5 transition">
                        <i class="fa-solid fa-file-lines text-slate-400"></i>
                        <span>Descargar (.TXT)</span>
                    </button>
                    <button onclick="downloadCtiAdvisoryText('md')" class="px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-semibold text-xs flex items-center gap-1.5 transition">
                        <i class="fa-brands fa-markdown text-cyan-400"></i>
                        <span>Descargar (.MD)</span>
                    </button>
                </div>
                <button onclick="closeCtiAdvisoryModal()" class="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold transition">
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

    <!-- ========================================== -->
    <!-- MODAL: EVIDENCIA DE VALIDACIÓN & cURL POc -->
    <!-- ========================================== -->
    <div id="vuln-evidence-modal" class="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm hidden flex items-center justify-center p-4">
        <div class="bg-cyber-card border border-cyber-border rounded-2xl w-full max-w-3xl overflow-hidden shadow-2xl flex flex-col max-h-[90vh]">
            <div class="px-6 py-4 border-b border-cyber-border flex items-center justify-between bg-slate-900/60">
                <div class="flex items-center gap-2.5">
                    <div class="w-8 h-8 rounded-lg bg-emerald-950 border border-emerald-800 flex items-center justify-center text-emerald-400">
                        <i class="fa-solid fa-file-shield text-sm"></i>
                    </div>
                    <div>
                        <h3 class="font-bold text-white text-sm" id="ve-title">Evidencia Técnica de Validación</h3>
                        <p class="text-[11px] text-slate-400 font-mono" id="ve-asset">activo.fdn.com.co</p>
                    </div>
                </div>
                <button onclick="closeVulnEvidenceModal()" class="text-slate-400 hover:text-white transition text-sm">
                    <i class="fa-solid fa-xmark"></i>
                </button>
            </div>

            <div class="p-6 overflow-y-auto space-y-4 text-xs">
                <!-- Header Status & Confidence -->
                <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <div class="bg-slate-900/80 p-3 rounded-xl border border-cyber-border">
                        <span class="text-[10px] text-slate-500 uppercase font-bold block mb-1">Estado de Validación</span>
                        <span id="ve-badge-state" class="px-2 py-0.5 rounded text-xs font-bold font-mono">--</span>
                    </div>
                    <div class="bg-slate-900/80 p-3 rounded-xl border border-cyber-border">
                        <span class="text-[10px] text-slate-500 uppercase font-bold block mb-1">Índice de Certeza</span>
                        <span id="ve-confidence" class="text-sm font-bold text-cyan-400 font-mono">--%</span>
                    </div>
                    <div class="bg-slate-900/80 p-3 rounded-xl border border-cyber-border">
                        <span class="text-[10px] text-slate-500 uppercase font-bold block mb-1">Método de Comprobación</span>
                        <span id="ve-method" class="text-xs font-bold text-slate-300 font-mono">--</span>
                    </div>
                </div>

                <!-- Justification Verdict -->
                <div class="bg-slate-900/90 p-4 rounded-xl border border-cyber-border space-y-1.5">
                    <div class="flex items-center gap-1.5 text-xs font-bold text-slate-200">
                        <i class="fa-solid fa-quote-left text-cyan-400"></i>
                        <span>Diagnóstico Forense / Justificación:</span>
                    </div>
                    <p id="ve-justification" class="text-xs text-slate-300 leading-relaxed font-sans"></p>
                </div>

                <!-- Reproduction cURL -->
                <div class="space-y-1.5">
                    <div class="flex items-center justify-between">
                        <span class="text-xs font-bold text-slate-300 flex items-center gap-1.5">
                            <i class="fa-solid fa-terminal text-emerald-400"></i> Comando cURL Reproducible:
                        </span>
                        <button onclick="copyVeCurl()" class="text-[11px] text-emerald-400 hover:text-emerald-300 font-semibold flex items-center gap-1">
                            <i class="fa-solid fa-copy"></i> Copiar cURL
                        </button>
                    </div>
                    <pre id="ve-curl" class="bg-slate-950 p-3 rounded-xl border border-slate-800 text-emerald-300 font-mono text-[11px] overflow-x-auto whitespace-pre-wrap"></pre>
                </div>

                <!-- Technical Evidence JSON / Headers -->
                <div class="space-y-1.5">
                    <span class="text-xs font-bold text-slate-300 flex items-center gap-1.5">
                        <i class="fa-solid fa-receipt text-cyan-400"></i> Evidencias Técnicas & Cabeceras Inspeccionadas:
                    </span>
                    <pre id="ve-evidence-json" class="bg-slate-950 p-3 rounded-xl border border-slate-800 text-slate-300 font-mono text-[11px] max-h-48 overflow-y-auto whitespace-pre-wrap"></pre>
                </div>
            </div>

            <div class="px-6 py-3 border-t border-cyber-border bg-slate-900/60 flex items-center justify-between">
                <span class="text-[10px] text-slate-500 font-mono" id="ve-timestamp">Validado: --</span>
                <button onclick="closeVulnEvidenceModal()" class="px-4 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-white font-semibold text-xs transition">
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
        let globalSeeds = [];
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
            if (typeof updatePhp2shellSelectedSeed === 'function') {
                updatePhp2shellSelectedSeed(activeSeed);
            }
            if (typeof darkIntelSyncWithGlobalSeeds === 'function') {
                darkIntelSyncWithGlobalSeeds();
            }
            populateStrixAssetDropdown();
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

            ['easm', 'graph', 'vulns', 'drp', 'leaks', 'cti', 'seeds', 'strix', 'loginrecon', 'php2shell'].forEach(t => {
                const el = document.getElementById(`tab-content-${t}`);
                if (el) el.classList.toggle('hidden', t !== tabId);
            });

            if (tabId === 'graph' && networkInstance) {
                setTimeout(() => { networkInstance.fit(); }, 100);
            }

            if (tabId === 'strix') {
                populateStrixAssetDropdown();
            }
            if (tabId === 'loginrecon') {
                populateLoginReconPresets();
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

            const confirmedCount = rawVulnsList.filter(v => (v.validation_state === 'CONFIRMADA' || v.validation_state === 'VALIDADA')).length;
            const fpCount = rawVulnsList.filter(v => v.validation_state === 'FALSO_POSITIVO').length;

            const setElem = (id, val) => { const el = document.getElementById(id); if (el) el.innerText = val; };
            setElem('count-vuln-all', allCount);
            setElem('count-vuln-high', highCount);
            setElem('count-vuln-med', medCount);
            setElem('count-vuln-low', lowCount);
            setElem('count-vuln-res', resCount);
            setElem('count-vuln-confirmed', confirmedCount);
            setElem('count-vuln-fp', fpCount);

            // Sincronización Dinámica del Menú Lateral Izquierdo (FortiOS 7.4.13)
            const navBadge = document.getElementById('nav-badge-vulns');
            if (navBadge) navBadge.innerText = allCount;

            fetchValidationMetrics();
        }

        function filterVulnsBySeverity(sev) {
            currentVulnFilter = sev;
            const buttons = ['ALL', 'HIGH', 'MEDIUM', 'LOW', 'CONFIRMADA', 'FALSO_POSITIVO', 'RESOLVED'];
            buttons.forEach(b => {
                const el = document.getElementById(`vuln-filter-${b}`);
                if (el) {
                    if (b === sev) {
                        el.className = 'px-2.5 py-1 rounded-lg text-xs font-bold bg-cyan-950 text-cyan-300 border border-cyan-800 transition';
                    } else {
                        el.className = 'px-2.5 py-1 rounded-lg text-xs font-semibold text-slate-400 hover:text-white border border-transparent hover:border-cyber-border transition';
                    }
                }
            });
            applyVulnFilters();
        }

        function applyVulnFilters() {
            const searchInput = document.getElementById('vuln-search-input');
            const q = searchInput ? searchInput.value.toLowerCase().trim() : '';

            let filtered = rawVulnsList.filter(v => {
                const valState = (v.validation_state || 'POTENCIAL').toUpperCase();
                
                // Severity / Validation Status filter
                if (currentVulnFilter === 'RESOLVED') {
                    if (v.status !== 'RESOLVED') return false;
                } else if (currentVulnFilter === 'CONFIRMADA') {
                    if (valState !== 'CONFIRMADA' && valState !== 'VALIDADA') return false;
                } else if (currentVulnFilter === 'FALSO_POSITIVO') {
                    if (valState !== 'FALSO_POSITIVO') return false;
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

        // ====================================================
        // VULNVALIDATOR ENGINE - INTERFAZ Y CONTROLADORES
        // ====================================================

        async function fetchValidationMetrics() {
            try {
                const res = await fetch(`${API_URL}?action=get_validation_metrics${getSeedQueryParam()}`);
                const data = await res.json();
                if (data && data.success && data.metrics) {
                    const m = data.metrics;
                    const setM = (id, val) => { const el = document.getElementById(id); if (el) el.innerText = val; };
                    setM('vmb-total', m.total || 0);
                    setM('vmb-confirmed', m.confirmed || 0);
                    setM('vmb-fp', m.false_positives || 0);
                    setM('vmb-fp-pct', `(${m.fp_percentage || 0}%)`);
                    setM('vmb-mitigated', m.mitigated || 0);
                    setM('vmb-avg-conf', `${m.avg_confidence || 50}%`);
                }
            } catch (e) {
                console.error("Error al obtener métricas de validación:", e);
            }
        }

        async function triggerVulnValidation(vulnId) {
            const btn = document.getElementById(`btn-val-${vulnId}`);
            const btnText = document.getElementById(`btn-val-text-${vulnId}`);
            if (btn) btn.disabled = true;
            if (btnText) btnText.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-1"></i> Validando...';

            try {
                const formData = new FormData();
                formData.append('id', vulnId);
                const res = await fetch(`${API_URL}?action=validate_vulnerability`, {
                    method: 'POST',
                    body: formData
                });
                const data = await res.json();

                if (data && data.success) {
                    showToast(`Hallazgo Validado: ${data.validation_state} (Certeza: ${data.confidence_score}%)`);
                    
                    // Actualizar objeto en rawVulnsList
                    const idx = rawVulnsList.findIndex(x => x.id == vulnId);
                    if (idx !== -1) {
                        rawVulnsList[idx].validation_state = data.validation_state;
                        rawVulnsList[idx].confidence_score = data.confidence_score;
                        rawVulnsList[idx].validation_method = data.validation_method;
                        rawVulnsList[idx].validation_justification = data.justification;
                        rawVulnsList[idx].reproduction_curl = data.reproduction_curl;
                        rawVulnsList[idx].validation_evidence = JSON.stringify(data.evidence);
                        rawVulnsList[idx].last_validated_at = data.validated_at;
                    }
                    updateVulnCounts();
                    applyVulnFilters();
                } else {
                    showToast(data.error || 'No se pudo completar la validación', true);
                }
            } catch (err) {
                showToast('Error de red al conectar con el motor de validación', true);
            } finally {
                if (btn) btn.disabled = false;
                if (btnText) btnText.innerText = 'Validar Hallazgo';
            }
        }

        async function runBatchPerimeterValidation() {
            const btn = document.getElementById('btn-batch-validate');
            if (btn) {
                btn.disabled = true;
                btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-1"></i> Validando Perímetro...';
            }

            try {
                const formData = new FormData();
                formData.append('seed', activeSeed || '');
                formData.append('limit', 30);
                const res = await fetch(`${API_URL}?action=batch_validate_vulnerabilities`, {
                    method: 'POST',
                    body: formData
                });
                const data = await res.json();

                if (data && data.success && data.stats) {
                    const s = data.stats;
                    showToast(`Auditoría Finalizada: ${s.false_positives} Falsos Positivos, ${s.confirmed} Confirmadas, ${s.mitigated} Mitigadas.`);
                    await fetchVulnerabilities();
                } else {
                    showToast(data.error || 'Error al ejecutar validación masiva', true);
                }
            } catch (e) {
                showToast('Error de conexión durante la validación masiva', true);
            } finally {
                if (btn) {
                    btn.disabled = false;
                    btn.innerHTML = '<i class="fa-solid fa-wand-magic-sparkles"></i> <span>Validar Perímetro (Batch)</span>';
                }
            }
        }

        let currentEvidenceCurl = '';

        function openVulnEvidenceModal(vulnId) {
            const v = (rawVulnsList || []).find(x => x.id == vulnId);
            if (!v) {
                showToast('No se encontró el registro de evidencia', true);
                return;
            }

            document.getElementById('ve-title').innerText = v.title || 'Hallazgo Evaluado';
            document.getElementById('ve-asset').innerText = v.asset_subdomain || 'host';
            
            const badgeEl = document.getElementById('ve-badge-state');
            const state = (v.validation_state || 'POTENCIAL').toUpperCase();
            badgeEl.innerText = state;
            if (state === 'CONFIRMADA' || state === 'VALIDADA') {
                badgeEl.className = 'px-2 py-0.5 rounded text-xs font-bold font-mono bg-emerald-950 text-emerald-300 border border-emerald-800';
            } else if (state === 'FALSO_POSITIVO') {
                badgeEl.className = 'px-2 py-0.5 rounded text-xs font-bold font-mono bg-slate-900 text-slate-300 border border-slate-700';
            } else if (state === 'MITIGADA') {
                badgeEl.className = 'px-2 py-0.5 rounded text-xs font-bold font-mono bg-cyan-950 text-cyan-300 border border-cyan-800';
            } else {
                badgeEl.className = 'px-2 py-0.5 rounded text-xs font-bold font-mono bg-amber-950 text-amber-300 border border-amber-800';
            }

            document.getElementById('ve-confidence').innerText = `${v.confidence_score !== undefined ? v.confidence_score : 50}%`;
            document.getElementById('ve-method').innerText = v.validation_method || 'HEURISTIC_DAST_REVIEW';
            document.getElementById('ve-justification').innerText = v.validation_justification || v.description || 'Evaluación técnica completada sin anomalías de explotación.';
            
            currentEvidenceCurl = v.reproduction_curl || `curl -ILs "https://${v.asset_subdomain}/"`;
            document.getElementById('ve-curl').innerText = currentEvidenceCurl;

            let evJson = v.validation_evidence || '{}';
            try {
                const parsed = JSON.parse(evJson);
                document.getElementById('ve-evidence-json').innerText = JSON.stringify(parsed, null, 2);
            } catch (e) {
                document.getElementById('ve-evidence-json').innerText = evJson;
            }

            document.getElementById('ve-timestamp').innerText = `Última validación técnica: ${v.last_validated_at || 'Reciente'}`;

            const modal = document.getElementById('vuln-evidence-modal');
            if (modal) modal.classList.remove('hidden');
        }

        function closeVulnEvidenceModal() {
            const modal = document.getElementById('vuln-evidence-modal');
            if (modal) modal.classList.add('hidden');
        }

        function copyVeCurl() {
            if (!currentEvidenceCurl) return;
            navigator.clipboard.writeText(currentEvidenceCurl).then(() => {
                showToast('Comando cURL copiado al portapapeles');
            }).catch(() => {
                showToast('No se pudo copiar automáticamente', true);
            });
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
                                ${(() => {
                                    const vState = (v.validation_state || 'POTENCIAL').toUpperCase();
                                    let b = '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-yellow-950 text-yellow-300 border border-yellow-800 flex items-center gap-1"><i class="fa-solid fa-lightbulb"></i>POTENCIAL</span>';
                                    if (vState === 'VALIDADA' || vState === 'CONFIRMADA') {
                                        b = '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-800 flex items-center gap-1"><i class="fa-solid fa-circle-check"></i>CONFIRMADA</span>';
                                    } else if (vState === 'FALSO_POSITIVO') {
                                        b = '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-900 text-slate-300 border border-slate-700 flex items-center gap-1"><i class="fa-solid fa-ban text-rose-400"></i>FALSO POSITIVO</span>';
                                    } else if (vState === 'MITIGADA') {
                                        b = '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-950 text-cyan-300 border border-cyan-800 flex items-center gap-1"><i class="fa-solid fa-shield-check"></i>MITIGADA</span>';
                                    } else if (vState === 'RIESGO_ACEPTADO') {
                                        b = '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-indigo-950 text-indigo-300 border border-indigo-800 flex items-center gap-1"><i class="fa-solid fa-handshake"></i>RIESGO ACEPTADO</span>';
                                    } else if (vState === 'PROBABLE') {
                                        b = '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-900 text-amber-200 border border-amber-700 flex items-center gap-1"><i class="fa-solid fa-triangle-exclamation"></i>PROBABLE</span>';
                                    } else if (vState === 'INFO_INSUFICIENTE' || vState === 'INCONCLUSO') {
                                        b = '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-900 text-slate-400 border border-slate-800 flex items-center gap-1"><i class="fa-solid fa-circle-question"></i>INCONCLUSO</span>';
                                    }
                                    
                                    const conf = (v.confidence_score !== undefined && v.confidence_score !== null) ? v.confidence_score : 50;
                                    const confBadge = `<span class="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${conf >= 80 ? 'bg-cyan-950 text-cyan-300 border border-cyan-800' : 'bg-slate-900 text-slate-400 border border-slate-800'}" title="Índice de Certeza Técnica (${conf}%)"><i class="fa-solid fa-gauge text-[9px] mr-0.5"></i>${conf}%</span>`;
                                    return b + ' ' + confBadge;
                                })()}
                                ${parseInt(v.cisa_kev) === 1 ? '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-red-950 text-red-300 border border-red-700 animate-pulse flex items-center gap-1"><i class="fa-solid fa-radiation"></i>CISA KEV</span>' : ''}
                                ${parseFloat(v.epss_score) > 0 ? `<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-950 text-purple-300 border border-purple-800">EPSS: ${(parseFloat(v.epss_score) * 100).toFixed(1)}%</span>` : ''}
                                ${v.cve_id ? `<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-cyan-300 border border-cyan-800">${v.cve_id}</span>` : ''}
                                <h4 class="font-bold ${isResolved ? 'text-slate-400 line-through' : 'text-white'} text-sm">${v.title}</h4>
                            </div>

                            <div class="flex flex-wrap items-center gap-2">
                                <div class="flex items-center gap-1">
                                    <span class="text-[10px] text-slate-400 font-medium">Validación:</span>
                                    <select onchange="handleValidationStateChange(${v.id}, this.value)" class="px-2 py-1 rounded-lg text-[11px] font-semibold bg-slate-900 text-slate-300 border border-cyber-border focus:outline-none">
                                        <option value="POTENCIAL" ${(v.validation_state || '') === 'POTENCIAL' ? 'selected' : ''}>Potencial</option>
                                        <option value="PROBABLE" ${(v.validation_state || '') === 'PROBABLE' ? 'selected' : ''}>Probable</option>
                                        <option value="VALIDADA" ${(v.validation_state || '') === 'VALIDADA' ? 'selected' : ''}>Validada</option>
                                        <option value="FALSO_POSITIVO" ${(v.validation_state || '') === 'FALSO_POSITIVO' ? 'selected' : ''}>Falso Positivo</option>
                                        <option value="INFO_INSUFICIENTE" ${(v.validation_state || '') === 'INFO_INSUFICIENTE' ? 'selected' : ''}>Info Insuficiente</option>
                                    </select>
                                </div>
                                <div class="flex items-center gap-1">
                                    <span class="text-[10px] text-slate-400 font-medium">Ciclo:</span>
                                    <select onchange="handleStatusChange(${v.id}, this.value)" class="px-2.5 py-1 rounded-lg text-[11px] font-semibold border ${isResolved ? 'bg-emerald-950 text-emerald-300 border-emerald-800' : (isInProgress ? 'bg-amber-950 text-amber-300 border-amber-800' : 'bg-slate-900 text-rose-300 border-rose-800')} focus:outline-none">
                                        <option value="OPEN" ${currentStatus === 'OPEN' ? 'selected' : ''}>🔴 Abierto</option>
                                        <option value="IN_PROGRESS" ${currentStatus === 'IN_PROGRESS' ? 'selected' : ''}>🟡 En Remediación</option>
                                        <option value="RESOLVED" ${currentStatus === 'RESOLVED' ? 'selected' : ''}>🟢 Mitigado</option>
                                        <option value="FALSE_POSITIVE" ${currentStatus === 'FALSE_POSITIVE' ? 'selected' : ''}>⚪ Falso Positivo</option>
                                    </select>
                                </div>
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
                            <div class="flex items-center gap-2 flex-wrap">
                                <button onclick="openVulnPlaybookModal(${v.id})" class="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-indigo-950/80 hover:bg-indigo-900 text-indigo-300 border border-indigo-700/60 transition shadow-sm">
                                    <i class="fa-solid fa-code"></i> Playbook & Hardening
                                </button>
                                <button onclick="triggerVulnValidation(${v.id})" id="btn-val-${v.id}" class="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-emerald-950 hover:bg-emerald-900 text-emerald-300 border border-emerald-700/70 transition shadow-sm" title="Ejecutar comprobación técnica no destructiva y recolectar evidencia">
                                    <i class="fa-solid fa-wand-magic-sparkles text-emerald-400"></i> <span id="btn-val-text-${v.id}">Validar Hallazgo</span>
                                </button>
                                ${v.validation_evidence || v.reproduction_curl ? `
                                <button onclick="openVulnEvidenceModal(${v.id})" class="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-cyan-800/60 transition shadow-sm" title="Ver evidencia forense y comando cURL reproducible">
                                    <i class="fa-solid fa-terminal text-cyan-400"></i> <span>Ver Evidencia & cURL</span>
                                </button>` : ''}
                            </div>
                            <span class="text-[11px] text-slate-500 font-mono">
                                ${v.last_validated_at ? `<span class="text-cyan-400 font-semibold mr-1">Validado: ${v.last_validated_at.slice(0, 16)}</span> &bull; ` : ''}
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

                // Dynamic update of top alert badge
                const hasMatched = leaks.some(r => r.is_matched == 1 || r.is_matched === true);
                const ransomBadge = document.getElementById('ransom-alert-badge');
                if (ransomBadge) {
                    if (hasMatched) {
                        ransomBadge.className = 'px-3 py-1.5 rounded-xl bg-rose-950 text-rose-300 border border-rose-700 text-xs font-bold flex items-center gap-2 animate-bounce shadow-lg shadow-rose-950/50';
                        ransomBadge.innerHTML = `<i class="fa-solid fa-triangle-exclamation text-rose-400"></i><span>ALERTA CRÍTICA: ¡Empresa en Lista de Extorsión Dark Web!</span>`;
                    } else {
                        ransomBadge.className = 'px-3 py-1.5 rounded-xl bg-emerald-950 text-emerald-400 border border-emerald-800/60 text-xs font-bold flex items-center gap-2';
                        ransomBadge.innerHTML = `<i class="fa-solid fa-shield-check"></i><span>Tu empresa no figura como víctima (Telemetría limpia)</span>`;
                    }
                }

                if (leaks.length === 0) {
                    tbodyR.innerHTML = `<tr><td colspan="5" class="p-8 text-center text-slate-500">Presiona "Sincronizar CTI" para descargar los últimos registros de la Dark Web.</td></tr>`;
                } else {
                    tbodyR.innerHTML = leaks.map(r => {
                        const isMatch = (r.is_matched == 1 || r.is_matched === true);
                        const alertBadge = isMatch ? 
                            `<div class="flex flex-col items-center gap-1">
                                <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-300 border border-rose-800 animate-pulse">OBJETIVO: TU EMPRESA</span>
                                ${r.is_simulation ? '<span class="text-[9px] text-amber-400 font-mono">[SIMULACIÓN LAB]</span>' : ''}
                            </div>` : 
                            `<span class="text-slate-500 text-[10px]">Tercero / Global</span>`;

                        const ultimatumInfo = (r.extortion_deadline || r.data_size) ?
                            `<div class="text-[11px]">
                                <div class="text-amber-400 font-semibold flex items-center gap-1"><i class="fa-regular fa-clock text-[10px]"></i> ${r.extortion_deadline || 'No especificado'}</div>
                                <div class="text-slate-400 text-[10px] flex items-center gap-1 mt-0.5"><i class="fa-solid fa-database text-[9px] text-cyan-400"></i> ${r.data_size || 'N/D'} &bull; ${r.discovered_date || '-'}</div>
                            </div>` :
                            `<span class="font-mono text-[11px] text-slate-400">${r.discovered_date || '-'}</span>`;

                        const statusDisplay = r.status ?
                            `<span class="px-2 py-1 rounded text-[10px] font-semibold ${isMatch ? 'bg-rose-900/50 text-rose-200 border border-rose-700/70' : 'bg-slate-800 text-slate-400 border border-slate-700'}">${r.status}</span>` :
                            alertBadge;

                        return `
                            <tr class="hover:bg-slate-800/40 transition ${isMatch ? 'bg-rose-950/25' : ''}">
                                <td class="p-4 font-bold text-white">
                                    <div class="flex items-center gap-2">
                                        <i class="fa-solid fa-building ${isMatch ? 'text-rose-400' : 'text-slate-400'}"></i>
                                        <span>${r.victim_name}</span>
                                    </div>
                                    ${r.proof_summary ? `<div class="text-[10px] text-slate-400 font-normal mt-1 line-clamp-1 max-w-sm" title="${r.proof_summary}">${r.proof_summary}</div>` : ''}
                                </td>
                                <td class="p-4">
                                    <div class="font-mono text-purple-400 font-semibold flex items-center gap-1.5">
                                        <i class="fa-solid fa-skull text-xs text-purple-400/80"></i>
                                        ${r.group_name}
                                    </div>
                                    ${r.claim_url ? `<div class="text-[10px] text-slate-500 font-mono flex items-center gap-1 mt-0.5 truncate max-w-[200px]" title="${r.claim_url}"><i class="fa-solid fa-lock text-[8px] text-amber-500"></i> ${r.claim_url}</div>` : ''}
                                </td>
                                <td class="p-4">${ultimatumInfo}</td>
                                <td class="p-4 text-center">
                                    <div class="flex flex-col items-center gap-1.5">
                                        ${statusDisplay}
                                        ${isMatch ? alertBadge : ''}
                                    </div>
                                </td>
                                <td class="p-4 text-center">
                                    <button onclick="openCtiAdvisoryModal(${r.id})" class="px-3 py-1.5 rounded-lg text-[11px] font-bold ${isMatch ? 'bg-rose-600 hover:bg-rose-500 text-white shadow-lg shadow-rose-900/50 animate-pulse' : 'bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700'} transition flex items-center gap-1.5 justify-center mx-auto whitespace-nowrap">
                                        <i class="fa-solid fa-bullhorn ${isMatch ? 'text-amber-300' : 'text-slate-400'}"></i>
                                        <span>${isMatch ? '🚨 Notificar Empresa' : 'Emitir Alerta'}</span>
                                    </button>
                                </td>
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

        
        // CTI Advisory Modal Helper Functions
        let currentAdvisoryData = null;

        async function openCtiAdvisoryModal(leakId) {
            try {
                const res = await fetch(`${API_URL}?action=generate_cti_advisory&leak_id=${leakId}`);
                const data = await res.json();
                if (!data.success) {
                    showToast('Error al generar comunicado CSIRT', true);
                    return;
                }
                currentAdvisoryData = data;
                document.getElementById('advisory-victim').textContent = data.victim_name || '-';
                document.getElementById('advisory-group').textContent = data.group_name || '-';
                document.getElementById('advisory-deadline').textContent = data.extortion_deadline || '-';
                document.getElementById('advisory-size').textContent = data.data_size || '-';
                document.getElementById('cti-advisory-text').value = data.advisory_text || '';
                document.getElementById('cti-advisory-modal').classList.remove('hidden');
            } catch (e) {
                console.error('Error fetching advisory:', e);
                showToast('Error de conexión al generar alerta', true);
            }
        }

        function closeCtiAdvisoryModal() {
            document.getElementById('cti-advisory-modal').classList.add('hidden');
        }

        function copyCtiAdvisoryText() {
            const txtArea = document.getElementById('cti-advisory-text');
            if (txtArea && txtArea.value) {
                navigator.clipboard.writeText(txtArea.value).then(() => {
                    showToast('¡Comunicado CSIRT copiado al portapapeles!');
                }).catch(() => {
                    txtArea.select();
                    document.execCommand('copy');
                    showToast('¡Comunicado CSIRT copiado al portapapeles!');
                });
            }
        }

        function downloadCtiAdvisoryText(format) {
            if (!currentAdvisoryData) return;
            const content = (format === 'md') ? currentAdvisoryData.advisory_markdown : currentAdvisoryData.advisory_text;
            const ext = (format === 'md') ? 'md' : 'txt';
            const cleanName = (currentAdvisoryData.victim_name || 'empresa').replace(/[^a-zA-Z0-9_-]/g, '_');
            const filename = `ALERTA_TEMPRANA_CSIRT_${cleanName}_${currentAdvisoryData.incident_id}.${ext}`;
            
            const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
            const link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            link.download = filename;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            showToast(`Descargado comunicado oficial (.${ext.toUpperCase()})`);
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

        function downloadTakedownNotice() {
            const text = document.getElementById('takedown-text').value;
            if (!text) {
                showToast('No hay notificación de takedown para descargar', true);
                return;
            }
            const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = `takedown_abuse_notice_${Date.now()}.txt`;
            a.click();
            showToast('Notificación legal de Takedown descargada en .txt');
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
                globalSeeds = Array.isArray(seeds) ? seeds : [];
                document.getElementById('seeds-count').innerText = `${globalSeeds.length} semillas`;
                if (typeof populatePhp2shellPreloadedSeeds === 'function') {
                    populatePhp2shellPreloadedSeeds(globalSeeds);
                }
                if (typeof darkIntelPopulateExposureSeeds === 'function') {
                    darkIntelPopulateExposureSeeds(globalSeeds);
                }

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

                populateStrixAssetDropdown();
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
        // STRIX PENTESTING TOOLKIT (SACKMESSER)
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

            const seedsToDisplay = (globalSeeds || []).filter(s => s && s.domain);

            if (seedsToDisplay.length === 0) {
                optionsHtml = '<option value="">(No hay semillas registradas)</option>';
            } else {
                seedsToDisplay.forEach(s => {
                    const domain = (s.domain || '').trim();
                    if (!domain) return;
                    const optValue = `https://${domain}`;
                    const isSelected = (activeSeed && activeSeed !== 'ALL' && domain === activeSeed) ? 'selected' : '';
                    const badge = (domain === activeSeed) ? ' (Semilla Activa)' : ' (Semilla)';
                    optionsHtml += `<option value="${optValue}" ${isSelected} class="bg-slate-900 text-white font-medium">${domain}${badge}</option>`;
                });
            }

            select.innerHTML = optionsHtml;

            const apxSelect = document.getElementById('apx-asset-quick-select');
            if (apxSelect) apxSelect.innerHTML = optionsHtml;
            const apxReportSelect = document.getElementById('apx-report-target-select');
            if (apxReportSelect) apxReportSelect.innerHTML = optionsHtml;
            const criSelect = document.getElementById('cri-target-select');
            if (criSelect) criSelect.innerHTML = optionsHtml;
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

            showToast(`Activo ${domain} cargado en Sackmesser`);
        }

        function launchStrixForUrl(url, vulnTitle) {
            if (!url) return;
            switchTab('strix');
            switchPentestSuite('strix');
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

        function setStrixPocUrl(newUrl) {
            document.getElementById('strix-poc-url').value = newUrl;
            runStrixPocTest();
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

                if (!data.success && !data.is_error) {
                    showToast(data.error || 'Error al ejecutar PoC', true);
                    return;
                }

                document.getElementById('strix-poc-results').classList.remove('hidden');

                const badgeEl = document.getElementById('strix-poc-badge');
                const diagBox = document.getElementById('strix-poc-diag-box');
                const diagTitle = document.getElementById('strix-poc-diag-title');
                const diagMsg = document.getElementById('strix-poc-diag-msg');

                // Handle network error (Timeout, Connection Refused, DNS Fail)
                if (data.is_error) {
                    badgeEl.className = 'mt-1 font-bold text-xs text-rose-400';
                    badgeEl.innerText = data.verdict;

                    document.getElementById('strix-poc-http-code').innerText = '0 (Sin respuesta)';
                    document.getElementById('strix-poc-latency').innerText = `${data.latency_ms !== undefined ? data.latency_ms : (data.duration_ms || 0)} ms`;
                    document.getElementById('strix-poc-content-type').innerText = data.content_type || 'Error de Red';

                    diagBox.className = 'p-4 rounded-xl border border-rose-800 bg-rose-950/40 text-xs';
                    diagTitle.innerHTML = `<i class="fa-solid fa-triangle-exclamation text-rose-400"></i><span class="text-rose-300 font-bold">${data.diagnostic_title || 'Error de Conexión'}</span>`;

                    let diagContent = `<p class="text-slate-300 leading-relaxed mb-2">${data.diagnostic}</p>`;
                    if (data.alt_url) {
                        diagContent += `
                            <div class="mt-2 pt-2 border-t border-rose-900/40 flex flex-wrap items-center gap-2">
                                <span class="text-slate-400 text-[11px]">¿Deseas probar el protocolo alternativo?</span>
                                <button onclick="setStrixPocUrl('${data.alt_url}')" class="px-2.5 py-1 rounded bg-rose-900 hover:bg-rose-800 text-white text-[11px] font-bold transition flex items-center gap-1 shadow-sm">
                                    <i class="fa-solid fa-rotate mr-1"></i> Probar en ${data.alt_scheme.toUpperCase()} (${data.alt_url})
                                </button>
                            </div>
                        `;
                    }

                    // Check if there are live subdomains discovered for this host
                    const hostOnly = targetUrl.replace(/^https?:\/\//i, '').split('/')[0];
                    const subLive = (globalAssets || []).filter(a => {
                        const sub = a.subdomain || '';
                        return (sub.endsWith('.' + hostOnly) || a.seed_domain === hostOnly) && sub !== hostOnly && (a.ports || a.is_live);
                    });

                    if (subLive.length > 0) {
                        diagContent += `
                            <div class="mt-3 p-3 bg-slate-900/90 rounded-xl border border-slate-700/60 text-xs">
                                <div class="text-emerald-400 font-bold mb-1.5 flex items-center gap-1.5">
                                    <i class="fa-solid fa-server"></i> Subdominios con Servicios Activos Descubiertos (${subLive.length}):
                                </div>
                                <p class="text-[11px] text-slate-400 mb-2">Este dominio aloja sus aplicaciones de prueba en subdominios independientes. Selecciona uno para validar inmediatamente:</p>
                                <div class="flex flex-wrap gap-2">
                                    ${subLive.slice(0, 8).map(s => {
                                        const portsStr = s.ports || '';
                                        const proto = portsStr.includes('443') ? 'https' : 'http';
                                        return `<button onclick="setStrixPocUrl('${proto}://${s.subdomain}')" class="px-2.5 py-1 rounded-lg bg-emerald-950/80 hover:bg-emerald-900 text-emerald-300 border border-emerald-700/60 font-mono text-[11px] font-semibold transition flex items-center gap-1 shadow-sm">
                                            <i class="fa-solid fa-bolt text-emerald-400"></i> ${proto}://${s.subdomain}
                                        </button>`;
                                    }).join('')}
                                </div>
                            </div>
                        `;
                    }
                    diagMsg.innerHTML = diagContent;

                    document.getElementById('strix-poc-raw-req').innerText = data.raw_request || '';
                    document.getElementById('strix-poc-raw-res').innerText = (data.raw_response_headers || '') + "\n\n" + (data.response_body_snippet || data.response_preview || '');
                    document.getElementById('strix-poc-curl').innerText = data.poc_curl || data.reproduction_curl || '';
                    document.getElementById('strix-poc-python').innerText = data.poc_python || data.reproduction_python || '';

                    showToast(`Conexión fallida: ${data.verdict}`, true);
                    return;
                }

                // Normal response
                let badgeClass = 'text-rose-400';
                const vText = data.verdict || '';
                if (vText.includes('PROTEGIDO') || vText.includes('BLOQUEADO')) badgeClass = 'text-emerald-400';
                else if (vText.includes('REDIRECCIÓN') || vText.includes('INFO_LEAK')) badgeClass = 'text-amber-400';
                else if (vText.includes('NO ENCONTRADO') || vText.includes('NEUTRO')) badgeClass = 'text-slate-400';

                badgeEl.className = `mt-1 font-bold text-xs ${badgeClass}`;
                badgeEl.innerText = `${data.verdict}`;

                // HTTP Code & Latency
                const codeVal = data.http_code !== undefined ? data.http_code : data.status_code;
                document.getElementById('strix-poc-http-code').innerText = codeVal !== undefined ? `${codeVal}` : 'N/A';
                const latVal = data.latency_ms !== undefined ? data.latency_ms : data.duration_ms;
                document.getElementById('strix-poc-latency').innerText = `${latVal !== undefined ? latVal : 0} ms`;
                document.getElementById('strix-poc-content-type').innerText = data.content_type || 'N/A';

                // Diagnostic Box
                if (vText.includes('EXPUESTO') || vText.includes('VULNERABLE')) {
                    diagBox.className = 'p-4 rounded-xl border border-rose-800 bg-rose-950/20 text-xs';
                    diagTitle.innerHTML = `<i class="fa-solid fa-triangle-exclamation text-rose-400"></i><span class="text-rose-300 font-bold">${data.diagnostic_title || 'Hallazgo Confirmado: Vulnerable / Expuesto'}</span>`;
                } else if (vText.includes('PROTEGIDO') || vText.includes('BLOQUEADO')) {
                    diagBox.className = 'p-4 rounded-xl border border-emerald-800 bg-emerald-950/20 text-xs';
                    diagTitle.innerHTML = `<i class="fa-solid fa-shield-check text-emerald-400"></i><span class="text-emerald-300 font-bold">${data.diagnostic_title || 'Endpoint Protegido'}</span>`;
                } else {
                    diagBox.className = 'p-4 rounded-xl border border-amber-800 bg-amber-950/20 text-xs';
                    diagTitle.innerHTML = `<i class="fa-solid fa-circle-info text-amber-400"></i><span class="text-amber-300 font-bold">${data.diagnostic_title || 'Fuga Informativa / Redirección'}</span>`;
                }
                diagMsg.innerText = data.diagnostic || 'Respuesta inspeccionada con éxito.';

                // Raw Request & Response
                document.getElementById('strix-poc-raw-req').innerText = data.raw_request || '(Sin cabeceras crudas)';
                document.getElementById('strix-poc-raw-res').innerText = (data.raw_response_headers || '') + "\n\n" + (data.response_body_snippet || data.response_preview || '');

                // Reproduction
                document.getElementById('strix-poc-curl').innerText = data.poc_curl || data.reproduction_curl || '';
                document.getElementById('strix-poc-python').innerText = data.poc_python || data.reproduction_python || '';

                showToast(`PoC completado en ${latVal}ms: ${data.verdict}`);
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

                if (!data.success && !data.is_error) {
                    showToast(data.error || 'Error al inspeccionar TLS', true);
                    return;
                }

                document.getElementById('strix-tls-results').classList.remove('hidden');

                const banner = document.getElementById('strix-tls-banner');
                const icon = document.getElementById('strix-tls-icon');
                const daysBadge = document.getElementById('strix-tls-days-badge');

                if (data.is_error) {
                    banner.className = 'p-4 rounded-xl border border-rose-800 bg-rose-950/20 flex flex-col sm:flex-row sm:items-center justify-between gap-3';
                    icon.className = 'w-10 h-10 rounded-xl bg-rose-900/60 text-rose-400 border border-rose-700 flex items-center justify-center text-lg';
                    icon.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i>';
                    daysBadge.className = 'px-3 py-1.5 rounded-xl font-mono text-xs font-bold border bg-rose-950 text-rose-300 border-rose-800';
                    daysBadge.innerText = 'PUERTO CERRADO / INACCESIBLE';

                    document.getElementById('strix-tls-status-title').innerText = data.status || 'Conexión Fallida';
                    document.getElementById('strix-tls-status-desc').innerText = data.recommendation || data.error;
                    document.getElementById('strix-tls-cn').innerText = host;
                    document.getElementById('strix-tls-issuer').innerText = 'Sin negociación TLS';
                    document.getElementById('strix-tls-algo').innerText = 'N/A';
                    document.getElementById('strix-tls-from').innerText = 'N/A';
                    document.getElementById('strix-tls-to').innerText = 'N/A';
                    document.getElementById('strix-tls-sans').innerHTML = '<span class="text-slate-500 font-mono text-xs">Sin información de certificados</span>';
                    showToast(`TLS inalcanzable en puerto ${port}`, true);
                    return;
                }

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

                if (!data.success && !data.is_error) {
                    showToast(data.error || 'Error en auditoría CORS', true);
                    return;
                }

                document.getElementById('strix-cors-results').classList.remove('hidden');

                const banner = document.getElementById('strix-cors-banner');
                const icon = document.getElementById('strix-cors-icon');

                if (data.is_error) {
                    banner.className = 'p-4 rounded-xl border border-rose-800 bg-rose-950/20 flex flex-col sm:flex-row sm:items-center justify-between gap-3';
                    icon.className = 'w-10 h-10 rounded-xl bg-rose-900/60 text-rose-400 border border-rose-700 flex items-center justify-center text-lg';
                    icon.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i>';
                    document.getElementById('strix-cors-verdict').innerText = 'Veredicto: INACCESIBLE (Timeout / Error de Red)';
                    document.getElementById('strix-cors-explanation').innerText = data.explanation || 'El objetivo no respondió en el puerto especificado.';
                    document.getElementById('strix-cors-credentials').innerHTML = '<span class="text-slate-400 font-mono">No evaluable</span>';
                    document.getElementById('strix-cors-headers-grid').innerHTML = `
                        <div class="col-span-full p-4 rounded-xl border border-rose-900/60 bg-rose-950/30 text-rose-300 text-xs">
                            <i class="fa-solid fa-circle-exclamation mr-1.5"></i>
                            No se pudieron inspeccionar las cabeceras defensivas porque el servidor no respondió a la petición HTTP.
                        </div>
                    `;
                    showToast(`Error de conexión en prueba CORS: ${data.verdict}`, true);
                    return;
                }

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

        // ==========================================
        // CRI (CYBER RESILIENCE INDEX) HARMONIZATION
        // ==========================================
        async function loadCriMetrics() {
            const select = document.getElementById('cri-target-select');
            let target = (select ? select.value : '') || '';
            if (!target) {
                target = (activeSeed && activeSeed !== 'ALL') ? activeSeed : (globalAssets && globalAssets[0] ? globalAssets[0].subdomain : 'demo.testfire.net');
                if (select) select.value = target;
            }
            if (!target) return;

            try {
                const res = await fetch(`${API_URL}?action=get_unified_resilience_metrics&target=${encodeURIComponent(target)}`);
                const data = await res.json();
                if (!data.success) return;

                document.getElementById('cri-score-easm').innerText = data.dimensions.easm.score;
                document.getElementById('cri-score-apx').innerText = data.dimensions.autopentestx.score;
                document.getElementById('cri-score-strix').innerText = data.dimensions.strix.score;

                const globalEl = document.getElementById('cri-score-global');
                const badgeEl = document.getElementById('cri-posture-badge');
                const briefEl = document.getElementById('cri-briefing');

                globalEl.innerText = data.cri_score;
                globalEl.className = `text-2xl font-black font-mono ${data.cri_class}`;
                badgeEl.innerText = data.cri_posture;
                briefEl.innerText = data.auditor_briefing;
                briefEl.title = data.auditor_briefing;

                showToast(`CRI calculado para ${data.target}: ${data.cri_score}/100 (${data.cri_posture})`);
            } catch (err) {
                console.error("Error loading CRI metrics:", err);
            }
        }

        // ==========================================
        // SUITE SWITCHER & AUTOPENTESTX FRAMEWORK
        // ==========================================
        let currentPentestSuite = 'strix';
        function switchPentestSuite(suite) {
            currentPentestSuite = suite;
            const isStrix = (suite === 'strix');
            const containerStrix = document.getElementById('container-suite-strix');
            const containerApx = document.getElementById('container-suite-autopentestx');
            const btnStrix = document.getElementById('btn-suite-strix');
            const btnApx = document.getElementById('btn-suite-autopentestx');

            if (containerStrix) containerStrix.classList.toggle('hidden', !isStrix);
            if (containerApx) containerApx.classList.toggle('hidden', isStrix);

            if (btnStrix) {
                btnStrix.className = isStrix 
                    ? 'px-4 py-2 rounded-lg bg-emerald-950 text-emerald-300 border border-emerald-700 text-xs font-bold flex items-center gap-2 transition shadow'
                    : 'px-4 py-2 rounded-lg bg-slate-900 text-slate-400 hover:text-white border border-transparent text-xs font-bold flex items-center gap-2 transition';
            }
            if (btnApx) {
                btnApx.className = !isStrix
                    ? 'px-4 py-2 rounded-lg bg-purple-950 text-purple-300 border border-purple-700 text-xs font-bold flex items-center gap-2 transition shadow'
                    : 'px-4 py-2 rounded-lg bg-slate-900 text-slate-400 hover:text-white border border-transparent text-xs font-bold flex items-center gap-2 transition';
            }
        }

        let currentAutoPentestXSubTool = 'pipeline';
        function switchAutoPentestXSubTool(tool) {
            currentAutoPentestXSubTool = tool;
            ['pipeline', 'methods', 'report'].forEach(t => {
                const btn = document.getElementById(`apx-subtab-${t}`);
                const panel = document.getElementById(`apx-panel-${t}`);
                if (btn) {
                    if (t === tool) {
                        btn.className = 'px-4 py-2 rounded-xl bg-purple-950/80 text-purple-300 border border-purple-700/80 flex items-center gap-2 transition';
                    } else {
                        btn.className = 'px-4 py-2 rounded-xl bg-slate-900 text-slate-400 hover:text-white border border-cyber-border flex items-center gap-2 transition';
                    }
                }
                if (panel) {
                    panel.classList.toggle('hidden', t !== tool);
                }
            });
        }

        function applyApxSelectedAsset() {
            const select = document.getElementById('apx-asset-quick-select');
            if (!select || !select.value) return;
            const targetUrl = select.value;
            const domain = targetUrl.replace(/^https?:\/\//i, '').split('/')[0];

            document.getElementById('apx-pipeline-target').value = targetUrl;
            document.getElementById('apx-methods-target').value = targetUrl;
            const rSelect = document.getElementById('apx-report-target-select');
            if (rSelect) rSelect.value = targetUrl;

            showToast(`Activo ${domain} cargado en AutoPentestX`);
        }

        function launchAutoPentestXForUrl(url) {
            if (!url) return;
            switchTab('strix');
            switchPentestSuite('autopentestx');
            switchAutoPentestXSubTool('pipeline');

            document.getElementById('apx-pipeline-target').value = url;
            document.getElementById('apx-methods-target').value = url;
            const rSelect = document.getElementById('apx-report-target-select');
            if (rSelect) rSelect.value = url;

            showToast(`Objetivo ${url} preparado en AutoPentestX`);
        }

        async function runAutoPentestXPipeline() {
            const targetInput = document.getElementById('apx-pipeline-target');
            const profileSelect = document.getElementById('apx-pipeline-profile');
            const btn = document.getElementById('btn-apx-run-pipeline');
            const timerEl = document.getElementById('apx-pipeline-timer');

            let target = (targetInput.value || '').trim();
            const profile = profileSelect.value || 'full';

            if (!target) {
                showToast('Ingresa una URL o dominio para el Pipeline AutoPentestX', true);
                return;
            }

            btn.disabled = true;
            btn.classList.add('opacity-75');
            btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i><span>Ejecutando Pipeline...</span>';

            // Reset phase indicators
            for (let i = 1; i <= 5; i++) {
                const phaseEl = document.getElementById(`apx-phase-${i}`);
                if (phaseEl) {
                    phaseEl.className = 'p-3 rounded-lg border border-slate-800 bg-slate-900/50 transition';
                    const statusSpan = phaseEl.querySelector('.phase-status');
                    if (statusSpan) {
                        statusSpan.innerText = 'En espera';
                        statusSpan.className = 'phase-status text-[10px] text-slate-500 font-mono';
                    }
                }
            }

            document.getElementById('apx-pipeline-results').classList.add('hidden');
            let startTime = Date.now();
            timerEl.innerText = 'Iniciando fases...';

            // Simulate progressive visual feedback
            let phaseInterval = setInterval(() => {
                let elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
                timerEl.innerText = `Tiempo transcurrido: ${elapsed}s`;
            }, 500);

            try {
                // Phase 1 active
                const p1 = document.getElementById('apx-phase-1');
                if (p1) {
                    p1.className = 'p-3 rounded-lg border border-purple-500/80 bg-purple-950/30 transition shadow-lg shadow-purple-950/50';
                    p1.querySelector('.phase-status').innerHTML = '<i class="fa-solid fa-spinner fa-spin text-purple-400"></i>';
                }

                const res = await fetch(`${API_URL}?action=autopentestx_run_pipeline&target=${encodeURIComponent(target)}&profile=${encodeURIComponent(profile)}`);
                const data = await res.json();
                clearInterval(phaseInterval);

                if (!data.success) {
                    timerEl.innerText = 'Error en pipeline';
                    showToast(data.error || 'Fallo en la ejecución del pipeline', true);
                    return;
                }

                let totalTime = ((Date.now() - startTime) / 1000).toFixed(2);
                const executedPhases = data.phases || data.phases_executed || [];
                timerEl.innerText = `Completado en ${totalTime}s (${executedPhases.length} fases)`;

                // Mark executed phases as completed
                executedPhases.forEach((phaseObj, idx) => {
                    const phaseEl = document.getElementById(`apx-phase-${idx + 1}`);
                    if (phaseEl) {
                        phaseEl.className = 'p-3 rounded-lg border border-emerald-500/60 bg-emerald-950/20 transition';
                        const statusSpan = phaseEl.querySelector('.phase-status');
                        if (statusSpan) {
                            const statusLabel = (typeof phaseObj === 'object' && phaseObj.status) ? phaseObj.status : 'OK';
                            statusSpan.innerHTML = `<i class="fa-solid fa-check-circle text-emerald-400"></i> ${statusLabel}`;
                            statusSpan.className = 'phase-status text-[10px] text-emerald-400 font-mono font-bold';
                        }
                    }
                });

                // Display Results
                document.getElementById('apx-pipeline-results').classList.remove('hidden');

                // Score Card
                const scoreEl = document.getElementById('apx-pipeline-score');
                const postureBadge = document.getElementById('apx-pipeline-posture-badge');
                const postureDesc = document.getElementById('apx-pipeline-posture-desc');
                const scoreCard = document.getElementById('apx-pipeline-score-card');

                scoreEl.innerText = data.risk_score;
                postureBadge.innerText = `Postura: ${data.posture}`;

                if (data.posture === 'Crítica' || data.posture === 'Alta') {
                    scoreCard.className = 'lg:col-span-4 p-5 rounded-xl border border-rose-800/80 bg-rose-950/20 flex flex-col items-center justify-center text-center space-y-2';
                    postureBadge.className = 'px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-rose-950 text-rose-300 border border-rose-700';
                    scoreEl.className = 'text-5xl font-black text-rose-400 font-mono';
                } else if (data.posture === 'Media') {
                    scoreCard.className = 'lg:col-span-4 p-5 rounded-xl border border-amber-800/80 bg-amber-950/20 flex flex-col items-center justify-center text-center space-y-2';
                    postureBadge.className = 'px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-amber-950 text-amber-300 border border-amber-700';
                    scoreEl.className = 'text-5xl font-black text-amber-400 font-mono';
                } else {
                    scoreCard.className = 'lg:col-span-4 p-5 rounded-xl border border-emerald-800/80 bg-emerald-950/20 flex flex-col items-center justify-center text-center space-y-2';
                    postureBadge.className = 'px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-emerald-950 text-emerald-300 border border-emerald-700';
                    scoreEl.className = 'text-5xl font-black text-emerald-400 font-mono';
                }

                const totalVulns = (data.vulnerabilities || []).length;
                postureDesc.innerText = `Activo analizado: ${data.target} (${data.ip || 'Perímetro'}) con ${totalVulns} hallazgo(s).`;

                // Executive Briefing
                document.getElementById('apx-pipeline-summary').innerText = data.executive_summary;
                document.getElementById('apx-pipeline-timestamp').innerText = data.timestamp || new Date().toLocaleString();

                // Counters
                const sev = data.severity_counts || data.severity_breakdown || {};
                document.getElementById('apx-count-critical').innerText = sev.CRITICAL || 0;
                document.getElementById('apx-count-high').innerText = sev.HIGH || 0;
                document.getElementById('apx-count-medium').innerText = sev.MEDIUM || 0;
                document.getElementById('apx-count-low').innerText = sev.LOW || 0;
                document.getElementById('apx-count-info').innerText = sev.INFO || 0;

                // Vulnerabilities Table
                const tbody = document.getElementById('apx-pipeline-vulns-tbody');
                const vCount = document.getElementById('apx-pipeline-vuln-count');
                vCount.innerText = `${data.vulnerabilities.length} hallazgo(s) registrado(s)`;

                if (data.vulnerabilities.length === 0) {
                    tbody.innerHTML = `
                        <tr>
                            <td colspan="5" class="py-8 text-center text-slate-500 font-mono text-xs">
                                <i class="fa-solid fa-shield-check text-emerald-400 text-2xl mb-2 block"></i>
                                No se identificaron vulnerabilidades perimetrales evidentes bajo las fases ejecutadas.
                            </td>
                        </tr>
                    `;
                } else {
                    tbody.innerHTML = data.vulnerabilities.map(v => {
                        let sevBadgeClass = 'bg-slate-800 text-slate-300 border-slate-700';
                        if (v.severity === 'CRITICAL') sevBadgeClass = 'bg-rose-950 text-rose-300 border-rose-700';
                        else if (v.severity === 'HIGH') sevBadgeClass = 'bg-orange-950 text-orange-300 border-orange-700';
                        else if (v.severity === 'MEDIUM') sevBadgeClass = 'bg-amber-950 text-amber-300 border-amber-700';
                        else if (v.severity === 'LOW') sevBadgeClass = 'bg-blue-950 text-blue-300 border-blue-700';

                        let phaseBadge = v.phase ? `<span class="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-950 text-purple-300 border border-purple-800">${v.phase}</span>` : '';
                        let targetUrl = target.startsWith('http') ? target : `https://${target}`;

                        return `
                            <tr class="hover:bg-slate-900/60 transition">
                                <td class="py-3 px-3 align-top">${phaseBadge}</td>
                                <td class="py-3 px-3 align-top">
                                    <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${sevBadgeClass}">
                                        ${v.severity}
                                    </span>
                                </td>
                                <td class="py-3 px-3 align-top">
                                    <div class="font-bold text-white text-xs">${v.title}</div>
                                    <div class="text-[10px] text-slate-400 font-mono mt-0.5">Categoría: ${v.category || 'General'}</div>
                                </td>
                                <td class="py-3 px-3 align-top font-mono text-[11px] text-slate-300">
                                    ${v.evidence ? `<div class="bg-slate-900/80 p-1.5 rounded border border-slate-800 max-w-xl break-all">${v.evidence}</div>` : (v.details || '-')}
                                </td>
                                <td class="py-3 px-3 align-top text-right whitespace-nowrap">
                                    <button onclick="launchStrixForUrl('${targetUrl}', '${v.title.replace(/'/g, "\'")}')" class="px-2.5 py-1 rounded-lg bg-emerald-950 text-emerald-300 hover:bg-emerald-900 border border-emerald-700 text-[11px] font-bold transition flex items-center gap-1.5 ml-auto">
                                        <i class="fa-solid fa-wand-magic-sparkles text-emerald-400"></i>
                                        <span>Strix PoC</span>
                                    </button>
                                </td>
                            </tr>
                        `;
                    }).join('');
                }

                showToast(`Pipeline completado para ${data.target}: ${data.total_vulnerabilities} hallazgo(s)`);
            } catch (err) {
                clearInterval(phaseInterval);
                timerEl.innerText = 'Error de conexión';
                showToast('Error de comunicación con el pipeline de AutoPentestX', true);
            } finally {
                btn.disabled = false;
                btn.classList.remove('opacity-75');
                btn.innerHTML = '<i class="fa-solid fa-play"></i><span>Ejecutar Pipeline AutoPentestX</span>';
            }
        }

        async function runAutoPentestXHttpMethods() {
            const targetInput = document.getElementById('apx-methods-target');
            const btn = document.getElementById('btn-apx-run-methods');
            let url = (targetInput.value || '').trim();

            if (!url) {
                showToast('Ingresa una URL objetivo para la auditoría de verbos HTTP', true);
                return;
            }
            if (!url.startsWith('http://') && !url.startsWith('https://')) {
                url = 'https://' + url;
                targetInput.value = url;
            }

            btn.disabled = true;
            btn.classList.add('opacity-75');
            btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i><span>Auditando Verbos...</span>';

            try {
                const res = await fetch(`${API_URL}?action=autopentestx_http_methods&url=${encodeURIComponent(url)}`);
                const data = await res.json();

                if (!data.success) {
                    showToast(data.error || 'Error en auditoría de verbos', true);
                    return;
                }

                document.getElementById('apx-methods-results').classList.remove('hidden');

                // Server Banner Information
                const serverEl = document.getElementById('apx-banner-server');
                const poweredEl = document.getElementById('apx-banner-powered');
                const riskEl = document.getElementById('apx-banner-risk');
                const verdictEl = document.getElementById('apx-banner-verdict');

                const hasLeak = !!(data.server_banner || data.x_powered_by);
                serverEl.innerText = data.server_banner || 'Oculto (Seguro)';
                serverEl.className = data.server_banner ? 'font-mono text-amber-300 block truncate mt-0.5' : 'font-mono text-emerald-400 block truncate mt-0.5';

                poweredEl.innerText = data.x_powered_by || 'Oculto (Seguro)';
                poweredEl.className = data.x_powered_by ? 'font-mono text-rose-300 block truncate mt-0.5' : 'font-mono text-emerald-400 block truncate mt-0.5';

                if (hasLeak) {
                    verdictEl.innerText = 'Fuga de Versión Detectada';
                    verdictEl.className = 'text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800';
                    riskEl.innerText = 'El servidor revela tecnología de backend facilitando ataques dirigidos (CVEs conocidos).';
                } else {
                    verdictEl.innerText = 'Sin Fuga de Cabeceras';
                    verdictEl.className = 'text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800';
                    riskEl.innerText = 'Cabeceras de servidor ocultas o genéricas.';
                }

                // 8-Method Matrix
                const grid = document.getElementById('apx-methods-grid');
                const rawMethods = data.methods || data.methods_tested || {};
                const methodsList = Array.isArray(rawMethods) ? rawMethods : Object.values(rawMethods);

                grid.innerHTML = methodsList.map(m => {
                    let badgeClass = m.badge_class || 'bg-emerald-950 text-emerald-300 border-emerald-700';
                    let borderCard = 'border-slate-800 bg-slate-900/60';
                    let code = m.code || m.status_code || 0;
                    let vText = m.verdict || 'OK';

                    if (vText.includes('CRÍTICO') || m.security_flag === 'CRITICAL_RISK') {
                        badgeClass = 'bg-rose-950 text-rose-300 border border-rose-700';
                        borderCard = 'border-rose-900/80 bg-rose-950/20';
                    } else if (vText.includes('ALERTA') || vText.includes('DECLARATIVO') || m.security_flag === 'WARNING') {
                        badgeClass = 'bg-amber-950 text-amber-300 border border-amber-700';
                        borderCard = 'border-amber-900/80 bg-amber-950/20';
                    }

                    return `
                        <div class="p-3.5 rounded-xl border ${borderCard} space-y-2">
                            <div class="flex items-center justify-between">
                                <span class="font-mono font-bold text-white text-xs px-2 py-0.5 rounded bg-slate-950 border border-slate-800">${m.method}</span>
                                <span class="px-2 py-0.5 rounded text-[10px] font-bold font-mono ${badgeClass}">${vText}</span>
                            </div>
                            <div class="flex items-baseline justify-between text-xs font-mono">
                                <span class="text-slate-400">HTTP Status:</span>
                                <span class="font-bold ${code >= 200 && code < 400 ? 'text-amber-400' : 'text-slate-400'}">${code || 'Err'}</span>
                            </div>
                            <div class="text-[11px] text-slate-300 leading-tight">
                                ${m.analysis || m.status_text || (m.latency_ms ? `Latencia: ${m.latency_ms}ms` : 'Método evaluado')}
                            </div>
                        </div>
                    `;
                }).join('');

                // Update Hardening Snippets if provided
                if (data.recommendations) {
                    if (data.recommendations.nginx) document.getElementById('apx-snippet-nginx').innerText = data.recommendations.nginx;
                    if (data.recommendations.apache) document.getElementById('apx-snippet-apache').innerText = data.recommendations.apache;
                    if (data.recommendations.iis) document.getElementById('apx-snippet-iis').innerText = data.recommendations.iis;
                }

                showToast(`Auditoría de métodos HTTP para ${data.target_url} finalizada`);
            } catch (err) {
                showToast('Error al auditar verbos HTTP', true);
            } finally {
                btn.disabled = false;
                btn.classList.remove('opacity-75');
                btn.innerHTML = '<i class="fa-solid fa-arrows-split-up-and-left"></i><span>Auditar Verbos HTTP</span>';
            }
        }

        async function generateAutoPentestXReport() {
            const select = document.getElementById('apx-report-target-select');
            const btn = document.getElementById('btn-apx-generate-report');
            const container = document.getElementById('apx-printable-report');

            let target = (select.value || '').trim();
            if (!target) {
                // If not in select, fallback to pipeline target
                target = (document.getElementById('apx-pipeline-target').value || '').trim();
            }

            if (!target) {
                showToast('Selecciona o ingresa el activo a reportar', true);
                return;
            }

            btn.disabled = true;
            btn.classList.add('opacity-75');
            btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i><span>Compilando...</span>';

            try {
                const res = await fetch(`${API_URL}?action=autopentestx_generate_report&target=${encodeURIComponent(target)}`);
                const data = await res.json();

                if (!data.success) {
                    showToast(data.error || 'Error al generar informe', true);
                    return;
                }

                const r = data.report || data;
                r.target = r.target || r.target_host || target;
                const meta = r.metadata || {
                    report_id: r.report_id || `APX-${Date.now()}`,
                    generation_date: r.generated_at || new Date().toLocaleString(),
                    classification: 'CONFIDENCIAL / AUDITORÍA',
                    framework: 'OpenRecon & AutoPentestX Suite',
                    auditor: r.auditor || 'Equipo de Ciberseguridad & Analistas EASM'
                };
                const sev = r.severity_summary || r.severity_counts || {};
                const reportVulns = r.vulnerabilities || r.vulns || [];

                // Build Printable Report HTML
                let vulnsHtml = '';
                if (!reportVulns || reportVulns.length === 0) {
                    vulnsHtml = `
                        <tr>
                            <td colspan="5" class="py-6 text-center text-slate-500 font-mono text-xs">
                                No hay vulnerabilidades críticas abiertas en la base de datos para este activo.
                            </td>
                        </tr>
                    `;
                } else {
                    vulnsHtml = reportVulns.map(v => {
                        let sevBadgeClass = 'bg-slate-800 text-slate-300';
                        if (v.severity === 'CRITICAL') sevBadgeClass = 'bg-rose-900 text-rose-200';
                        else if (v.severity === 'HIGH') sevBadgeClass = 'bg-orange-900 text-orange-200';
                        else if (v.severity === 'MEDIUM') sevBadgeClass = 'bg-amber-900 text-amber-200';
                        else if (v.severity === 'LOW') sevBadgeClass = 'bg-blue-900 text-blue-200';

                        return `
                            <tr class="border-b border-slate-700/60">
                                <td class="py-2.5 px-3">
                                    <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase ${sevBadgeClass}">${v.severity}</span>
                                </td>
                                <td class="py-2.5 px-3">
                                    <div class="font-bold text-white text-xs">${v.title}</div>
                                    <div class="text-[10px] text-slate-400 font-mono mt-0.5">${v.category || 'Vulnerabilidad Web'}</div>
                                </td>
                                <td class="py-2.5 px-3 font-mono text-[11px] text-slate-300">
                                    ${v.cve_cwe || 'CWE-200'}
                                </td>
                                <td class="py-2.5 px-3 text-[11px] text-slate-300">
                                    ${v.remediation || 'Aplicar control defensivo y validar con WAF/Servidor.'}
                                </td>
                            </tr>
                        `;
                    }).join('');
                }

                // Frameworks Badges
                let frameworksHtml = (r.compliance_frameworks || []).map(f => `
                    <div class="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
                        <div class="flex items-center justify-between">
                            <span class="font-bold text-white text-xs">${f.name}</span>
                            <span class="text-[10px] font-mono px-2 py-0.5 rounded ${f.status === 'En Riesgo' ? 'bg-rose-950 text-rose-300 border border-rose-800' : 'bg-emerald-950 text-emerald-300 border border-emerald-800'}">${f.status}</span>
                        </div>
                        <p class="text-[11px] text-slate-400 leading-tight">${f.details}</p>
                    </div>
                `).join('');

                container.innerHTML = `
                    <!-- Formal Header -->
                    <div class="border-b-2 border-purple-500 pb-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
                        <div>
                            <div class="flex items-center gap-2">
                                <span class="px-2.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-purple-950 text-purple-300 border border-purple-800">
                                    ${meta.classification || 'CONFIDENCIAL'}
                                </span>
                                <span class="text-xs font-mono text-slate-400">ID: ${meta.report_id}</span>
                            </div>
                            <h2 class="text-2xl font-black text-white mt-1">Informe de Pruebas de Penetración & Evaluación EASM</h2>
                            <p class="text-xs text-slate-400 font-mono mt-0.5">Generado por: ${meta.framework} | Auditor: ${meta.auditor}</p>
                        </div>
                        <div class="text-right">
                            <div class="text-xs font-mono text-slate-400">Fecha de Auditoría: <span class="text-white font-bold">${meta.generation_date}</span></div>
                            <div class="text-xs font-mono text-purple-400 font-bold mt-1">Objetivo: ${r.target}</div>
                        </div>
                    </div>

                    <!-- Executive Score & Summary -->
                    <div class="grid grid-cols-1 md:grid-cols-12 gap-4">
                        <div class="md:col-span-4 p-5 rounded-xl border border-slate-800 bg-slate-900/60 flex flex-col items-center justify-center text-center space-y-2">
                            <span class="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Puntuación de Riesgo Global</span>
                            <div class="text-5xl font-black ${r.risk_score >= 70 ? 'text-rose-400' : (r.risk_score >= 40 ? 'text-amber-400' : 'text-emerald-400')} font-mono">
                                ${r.risk_score}<span class="text-slate-500 text-lg">/100</span>
                            </div>
                            <div class="px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider ${r.posture === 'Crítica' || r.posture === 'Alta' ? 'bg-rose-950 text-rose-300 border border-rose-800' : 'bg-emerald-950 text-emerald-300 border border-emerald-800'}">
                                Postura: ${r.posture}
                            </div>
                        </div>
                        <div class="md:col-span-8 p-5 rounded-xl border border-slate-800 bg-slate-900/60 space-y-3">
                            <h3 class="text-xs font-bold uppercase text-slate-300 tracking-wider flex items-center gap-1.5 border-b border-slate-800 pb-2">
                                <i class="fa-solid fa-file-lines text-purple-400"></i> Resumen Ejecutivo para la Alta Dirección
                            </h3>
                            <p class="text-xs text-slate-300 leading-relaxed">${r.executive_summary}</p>
                            <div class="grid grid-cols-4 gap-2 pt-2 border-t border-slate-800 text-center font-mono">
                                <div class="p-1.5 rounded bg-rose-950/40 text-rose-300 text-xs font-bold">Críticas: ${sev.CRITICAL || 0}</div>
                                <div class="p-1.5 rounded bg-orange-950/40 text-orange-300 text-xs font-bold">Altas: ${sev.HIGH || 0}</div>
                                <div class="p-1.5 rounded bg-amber-950/40 text-amber-300 text-xs font-bold">Medias: ${sev.MEDIUM || 0}</div>
                                <div class="p-1.5 rounded bg-blue-950/40 text-blue-300 text-xs font-bold">Bajas/Info: ${(sev.LOW || 0) + (sev.INFO || 0)}</div>
                            </div>
                        </div>
                    </div>

                    <!-- Compliance Alignment -->
                    <div class="space-y-3">
                        <h3 class="text-xs font-bold uppercase text-slate-300 tracking-wider flex items-center gap-1.5">
                            <i class="fa-solid fa-scale-balanced text-purple-400"></i> Alineación con Estándares y Marcos de Cumplimiento
                        </h3>
                        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">${frameworksHtml}</div>
                    </div>

                    <!-- Vulnerability Findings Ledger -->
                    <div class="space-y-3">
                        <div class="flex items-center justify-between">
                            <h3 class="text-xs font-bold uppercase text-slate-300 tracking-wider flex items-center gap-1.5">
                                <i class="fa-solid fa-bug text-purple-400"></i> Registro Consolidado de Vulnerabilidades y Mitigaciones
                            </h3>
                            <span class="text-[10px] font-mono text-purple-400">${reportVulns.length} ítems auditados</span>
                        </div>
                        <div class="overflow-x-auto border border-slate-800 rounded-xl bg-slate-900/40">
                            <table class="w-full text-left text-xs">
                                <thead>
                                    <tr class="border-b border-slate-800 text-[10px] font-bold uppercase text-slate-400 bg-slate-950">
                                        <th class="py-2.5 px-3">Severidad</th>
                                        <th class="py-2.5 px-3">Vulnerabilidad</th>
                                        <th class="py-2.5 px-3">Control / CVE</th>
                                        <th class="py-2.5 px-3">Plan de Remediación Recomendado</th>
                                    </tr>
                                </thead>
                                <tbody>${vulnsHtml}</tbody>
                            </table>
                        </div>
                    </div>

                    <!-- Sign-off Footer -->
                    <div class="border-t border-slate-800 pt-4 flex flex-col sm:flex-row items-center justify-between text-[11px] text-slate-500 font-mono">
                        <div>Documento emitido conforme al estándar PTES (Penetration Testing Execution Standard)</div>
                        <div class="mt-2 sm:mt-0 font-bold text-slate-400">OpenRecon & AutoPentestX Platform</div>
                    </div>
                `;

                showToast(`Informe AutoPentestX generado con éxito para ${r.target}`);
            } catch (err) {
                showToast('Error al compilar el informe ejecutivo', true);
            } finally {
                btn.disabled = false;
                btn.classList.remove('opacity-75');
                btn.innerHTML = '<i class="fa-solid fa-arrows-rotate"></i><span>Compilar Informe</span>';
            }
        }

        function printAutoPentestXReport() {
            const reportContent = document.getElementById('apx-printable-report');
            if (!reportContent || reportContent.innerText.includes('Selecciona un activo')) {
                showToast('Primero compila el informe antes de imprimir o exportar a PDF', true);
                return;
            }
            window.print();
        }

        // ==========================================
        // LOGINRECON (OSINT DIGITAL FOOTPRINT ENGINE)
        // ==========================================
        let currentLoginReconData = null;
        let currentLoginReconFilter = 'all';

        async function populateLoginReconPresets() {
            try {
                const res = await fetch(`${API_URL}?action=loginrecon_get_leaked_users`);
                const data = await res.json();
                if (!data.success) return;
                const select = document.getElementById('loginrecon-preset-select');
                if (!select) return;
                let html = '<option value="">Logins / Fugas Detectadas...</option>';
                (data.users || []).forEach(u => {
                    html += `<option value="${u}">@${u}</option>`;
                });
                select.innerHTML = html;
            } catch (e) {
                console.error("Error loading leaked presets:", e);
            }
        }

        function applyLoginReconPreset() {
            const select = document.getElementById('loginrecon-preset-select');
            if (!select || !select.value) return;
            document.getElementById('loginrecon-input-username').value = select.value;
            runLoginReconSearch();
        }

        async function runLoginReconSearch() {
            const input = document.getElementById('loginrecon-input-username');
            const selectCat = document.getElementById('loginrecon-select-category');
            const btn = document.getElementById('btn-loginrecon-search');
            
            const username = (input.value || '').trim();
            const category = selectCat ? selectCat.value : 'all';

            if (!username) {
                showToast('Por favor ingresa un nombre de usuario para buscar', true);
                input.focus();
                return;
            }

            btn.disabled = true;
            btn.classList.add('opacity-75');
            btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i><span>Rastreando Forense (75+)...</span>';

            try {
                const res = await fetch(`${API_URL}?action=loginrecon_search&username=${encodeURIComponent(username)}&category=${encodeURIComponent(category)}`);
                const data = await res.json();

                if (!data.success) {
                    showToast(data.error || 'Error en el rastreo de LoginRecon', true);
                    return;
                }

                currentLoginReconData = data;
                document.getElementById('loginrecon-initial-message').classList.add('hidden');
                document.getElementById('loginrecon-metrics-card').classList.remove('hidden');
                document.getElementById('loginrecon-results-grid').classList.remove('hidden');

                // Populate Forensic Identity Dossier
                const dossier = data.identity_dossier || {};
                const dossierCard = document.getElementById('loginrecon-identity-dossier');
                if (dossierCard) {
                    dossierCard.classList.remove('hidden');
                    document.getElementById('dossier-primary-name').innerText = dossier.primary_name || data.username;
                    const uBadge = document.getElementById('dossier-username-badge');
                    if (dossier.target_type === 'EMAIL' && dossier.email) {
                        uBadge.innerHTML = `<i class="fa-solid fa-envelope mr-1 text-amber-400"></i>${dossier.email}`;
                        uBadge.className = 'font-mono text-xs text-amber-300 bg-amber-950/80 px-2 py-0.5 rounded border border-amber-800';
                    } else {
                        uBadge.innerText = `@${data.username}`;
                        uBadge.className = 'font-mono text-xs text-sky-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800';
                    }
                    document.getElementById('dossier-method').innerText = `Método de atribución: ${dossier.attribution_method || 'OSINT'}`;
                    document.getElementById('dossier-footprint').innerText = `${data.footprint_rate}%`;
                    document.getElementById('dossier-accounts-count').innerText = data.found_count;

                    // Confidence badge styling
                    const confBadge = document.getElementById('dossier-confidence-badge');
                    confBadge.innerText = dossier.confidence || 'BAJA';
                    if ((dossier.confidence || '').includes('ALTA')) {
                        confBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold uppercase border bg-emerald-950 text-emerald-300 border-emerald-700';
                    } else if ((dossier.confidence || '').includes('MEDIA')) {
                        confBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold uppercase border bg-sky-950 text-sky-300 border-sky-700';
                    } else {
                        confBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold uppercase border bg-slate-800 text-slate-400 border-slate-700';
                    }

                    // Avatar
                    const avatarImg = document.getElementById('dossier-avatar-img');
                    const avatarPlaceholder = document.getElementById('dossier-avatar-placeholder');
                    if (dossier.avatar_url) {
                        avatarImg.src = dossier.avatar_url;
                        avatarImg.classList.remove('hidden');
                        avatarPlaceholder.classList.add('hidden');
                    } else {
                        avatarImg.classList.add('hidden');
                        avatarPlaceholder.classList.remove('hidden');
                    }

                    // Emails & CTI Leaks
                    const emailsContainer = document.getElementById('dossier-emails-container');
                    if (dossier.detected_breaches && dossier.detected_breaches.length > 0) {
                        emailsContainer.innerHTML = dossier.detected_breaches.map(b => 
                            `<div class="truncate text-[11px] text-rose-300"><i class="fa-solid fa-triangle-exclamation mr-1 text-rose-400"></i><strong class="text-white">${b.source_breach}</strong> (${b.breach_date || 'N/A'})</div>`
                        ).join('');
                    } else if (dossier.detected_emails && dossier.detected_emails.length > 0) {
                        emailsContainer.innerHTML = dossier.detected_emails.map(em => `<div class="truncate"><i class="fa-solid fa-at mr-1 text-[10px]"></i>${em}</div>`).join('');
                    } else if (dossier.target_type === 'EMAIL') {
                        emailsContainer.innerHTML = `<span class="text-emerald-400"><i class="fa-solid fa-shield-check mr-1"></i>Sin fugas detectadas en CTI</span>`;
                    } else {
                        emailsContainer.innerText = 'No detectados en commits públicos';
                    }

                    // Org / Loc
                    const orgLoc = document.getElementById('dossier-org-loc');
                    const parts = [];
                    if (dossier.company) parts.push(`<span class="font-bold text-white">${dossier.company}</span>`);
                    if (dossier.location) parts.push(`<span>${dossier.location}</span>`);
                    if (dossier.bio) parts.push(`<div class="text-[11px] text-slate-400 mt-1 italic line-clamp-2">"${dossier.bio}"</div>`);
                    orgLoc.innerHTML = parts.length > 0 ? parts.join(' • ') : 'No especificada en perfiles analizados';

                    // Sources
                    const sourcesContainer = document.getElementById('dossier-sources-container');
                    if (dossier.confirmed_identities && dossier.confirmed_identities.length > 0) {
                        sourcesContainer.innerHTML = dossier.confirmed_identities.map(ci => `<span class="inline-block px-1.5 py-0.5 mr-1 mb-1 rounded bg-slate-900 border border-slate-800 text-[10px] text-sky-300">${ci.source}: <strong class="text-white">${ci.name}</strong></span>`).join('');
                    } else {
                        sourcesContainer.innerText = `${data.found_count} plataformas asociadas a @${data.username}`;
                    }
                }

                // Activate Facebook AI correlation card
                const fbCard = document.getElementById('loginrecon-facebook-ai-card');
                if (fbCard) {
                    fbCard.classList.remove('hidden');
                    const seed = data.facebook_correlation_seed || {};
                    const avatarCount = (seed.source_avatars || []).length;
                    const namesCount = (seed.names || []).length;
                    const badge = document.getElementById('fb-ai-badge');
                    if (badge) {
                        badge.innerText = `${avatarCount} fotos | ${namesCount} nombres detectados`;
                        badge.className = 'px-2.5 py-0.5 rounded text-[10px] font-bold uppercase bg-blue-950/80 text-blue-300 border border-blue-700';
                    }
                    // Reset grid state for new search
                    document.getElementById('fb-ai-empty-message').classList.remove('hidden');
                    document.getElementById('fb-ai-candidates-grid').classList.add('hidden');
                    document.getElementById('fb-ai-candidates-grid').innerHTML = '';
                }

                document.getElementById('loginrecon-stat-total').innerText = data.total_platforms;
                document.getElementById('loginrecon-stat-found').innerText = data.found_count;
                document.getElementById('loginrecon-stat-rate').innerText = `${data.footprint_rate}%`;
                document.getElementById('loginrecon-stat-time').innerText = `${data.duration_ms} ms`;

                // Update category pill counts
                const allRes = data.results || [];
                document.getElementById('count-pill-all').innerText = allRes.length;
                document.getElementById('count-pill-found').innerText = data.found_count;
                const pillGov = document.getElementById('count-pill-gov_co');
                if (pillGov) pillGov.innerText = allRes.filter(r => r.category === 'gov_co').length;
                document.getElementById('count-pill-social').innerText = allRes.filter(r => r.category === 'social').length;
                document.getElementById('count-pill-dev').innerText = allRes.filter(r => r.category === 'dev').length;
                document.getElementById('count-pill-media').innerText = allRes.filter(r => r.category === 'media').length;
                document.getElementById('count-pill-blogs').innerText = allRes.filter(r => r.category === 'blogs').length;
                const pillDating = document.getElementById('count-pill-dating');
                if (pillDating) pillDating.innerText = allRes.filter(r => r.category === 'dating').length;
                const pillAdult = document.getElementById('count-pill-adult');
                if (pillAdult) pillAdult.innerText = allRes.filter(r => r.category === 'adult').length;
                const pillCreators = document.getElementById('count-pill-creators');
                if (pillCreators) pillCreators.innerText = allRes.filter(r => r.category === 'creators').length;
                document.getElementById('count-pill-prof').innerText = allRes.filter(r => r.category === 'prof').length;

                renderLoginReconCards(allRes);
                showToast(`LoginRecon finalizado: ${data.found_count} perfiles confirmados para @${username} [Atribuido: ${dossier.primary_name || username}]`);
            } catch (e) {
                console.error(e);
                showToast('Error de conexión en LoginRecon', true);
            } finally {
                btn.disabled = false;
                btn.classList.remove('opacity-75');
                btn.innerHTML = '<i class="fa-solid fa-magnifying-glass"></i><span>Rastrear Huella Digital</span>';
            }
        }

        function filterLoginReconCards(cat) {
            currentLoginReconFilter = cat;
            ['all', 'found', 'gov_co', 'social', 'dev', 'media', 'blogs', 'prof', 'dating', 'adult', 'creators'].forEach(c => {
                const btn = document.getElementById(`loginrecon-filter-${c}`);
                if (btn) {
                    if (c === cat) {
                        btn.className = 'px-3 py-1 rounded-lg bg-sky-950 text-sky-300 border border-sky-800 transition font-bold shadow';
                    } else {
                        btn.className = 'px-3 py-1 rounded-lg bg-slate-900 text-slate-400 hover:text-white border border-cyber-border transition';
                    }
                }
            });

            if (!currentLoginReconData || !currentLoginReconData.results) return;
            let filtered = currentLoginReconData.results;
            if (cat === 'found') {
                filtered = filtered.filter(r => r.is_found);
            } else if (cat !== 'all') {
                filtered = filtered.filter(r => r.category === cat);
            }
            renderLoginReconCards(filtered);
        }

        function renderLoginReconCards(items) {
            const grid = document.getElementById('loginrecon-results-grid');
            if (!grid) return;

            if (!items || items.length === 0) {
                grid.innerHTML = '<div class="col-span-full py-12 text-center text-slate-500 font-mono text-xs">No se encontraron plataformas que coincidan con el filtro seleccionado.</div>';
                return;
            }

            grid.innerHTML = items.map(item => {
                const isFound = item.is_found;
                const cardBorder = isFound ? 'border-emerald-700/80 bg-emerald-950/20 shadow-lg shadow-emerald-950/30' : 'border-slate-800/80 bg-slate-900/40 opacity-70';
                const badgeClass = isFound ? 'bg-emerald-950 text-emerald-300 border-emerald-700' : 'bg-slate-800 text-slate-400 border-slate-700';

                const avatarHtml = (isFound && item.avatar) ? 
                    `<img src="${item.avatar}" alt="${item.name}" class="w-8 h-8 rounded-lg object-cover border border-slate-700" onerror="this.style.display='none'; this.nextElementSibling.style.display='flex';" /><div class="w-8 h-8 rounded-lg bg-slate-900 border border-slate-800 hidden items-center justify-center text-white text-sm"><i class="${item.icon}"></i></div>` :
                    `<div class="w-8 h-8 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-center text-white text-sm"><i class="${item.icon}"></i></div>`;

                return `
                    <div class="p-3.5 rounded-xl border ${cardBorder} flex flex-col justify-between space-y-3 transition hover:border-sky-500/60">
                        <div class="flex items-start justify-between gap-2">
                            <div class="flex items-center gap-2.5">
                                ${avatarHtml}
                                <div class="truncate max-w-[130px]">
                                    <h4 class="text-xs font-bold text-white truncate">${item.name}</h4>
                                    ${item.category === "gov_co" ? '<span class="text-[10px] text-amber-400 font-mono font-bold"><i class="fa-solid fa-landmark mr-1"></i>Gov Colombia</span>' : `<span class="text-[10px] text-slate-400 font-mono capitalize">${item.category}</span>`}
                                </div>
                            </div>
                            <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${badgeClass}">
                                ${isFound ? 'Confirmado' : 'No Encontrado'}
                            </span>
                        </div>

                        ${isFound && (item.display_name || item.bio_snippet) ? `
                            <div class="bg-slate-950/70 p-2 rounded-lg border border-slate-800/60 space-y-1 text-left">
                                ${item.display_name ? `
                                    <div class="text-[11px] font-bold text-sky-300 flex items-center gap-1.5 truncate">
                                        <i class="fa-solid fa-id-card text-[10px] text-emerald-400 flex-shrink-0"></i>
                                        <span class="truncate" title="${item.display_name}">${item.display_name}</span>
                                    </div>
                                ` : ''}
                                ${item.bio_snippet ? `
                                    <p class="text-[10px] text-slate-400 italic line-clamp-2" title="${item.bio_snippet}">${item.bio_snippet}</p>
                                ` : ''}
                            </div>
                        ` : ''}

                        <div class="pt-2 border-t border-cyber-border/40 flex items-center justify-between text-xs">
                            ${isFound ? `
                                <a href="${item.url}" target="_blank" rel="noopener noreferrer" class="text-sky-400 hover:text-sky-300 flex items-center gap-1 font-mono text-[11px] truncate max-w-[140px]">
                                    <span>Abrir Perfil</span>
                                    <i class="fa-solid fa-arrow-up-right-from-square text-[10px]"></i>
                                </a>
                                <button onclick="launchStrixForUrl('${item.url}')" class="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-emerald-400 text-[10px] font-bold border border-emerald-900/60 transition flex items-center gap-1">
                                    <i class="fa-solid fa-wand-magic-sparkles text-[9px]"></i>
                                    <span>Strix</span>
                                </button>
                            ` : `
                                <span class="text-[10px] text-slate-500 font-mono">Disponible / HTTP ${item.status_code || 404}</span>
                            `}
                        </div>
                    </div>
                `;
            }).join('');
        }

        function exportLoginReconTxt() {
            if (!currentLoginReconData || !currentLoginReconData.txt_content) {
                showToast('Primero realiza una búsqueda para exportar resultados', true);
                return;
            }
            const blob = new Blob([currentLoginReconData.txt_content], { type: 'text/plain;charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${currentLoginReconData.username}_userrecon.txt`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            showToast(`Archivo ${currentLoginReconData.username}_userrecon.txt descargado`);
        }

        function copyLoginReconLinks() {
            if (!currentLoginReconData || !currentLoginReconData.results) {
                showToast('No hay resultados para copiar', true);
                return;
            }
            const found = currentLoginReconData.results.filter(r => r.is_found).map(r => r.url);
            if (found.length === 0) {
                showToast('No hay enlaces confirmados para copiar', true);
                return;
            }
            navigator.clipboard.writeText(found.join('\n')).then(() => {
                showToast(`${found.length} enlaces copiados al portapapeles`);
            }).catch(() => {
                showToast('Error al copiar al portapapeles', true);
            });
        }

        window.onload = init;

        // -------------------------------------------------------------
        // FACEBOOK AI VISION CORRELATOR CLIENT CONTROLLER
        // -------------------------------------------------------------
        async function triggerFacebookAICorrelation() {
            if (!currentLoginReconData || !currentLoginReconData.facebook_correlation_seed) {
                showToast('Primero realiza una búsqueda en LoginRecon', true);
                return;
            }

            const btn = document.getElementById('btn-run-fb-ai');
            const loading = document.getElementById('fb-ai-loading');
            const emptyMsg = document.getElementById('fb-ai-empty-message');
            const grid = document.getElementById('fb-ai-candidates-grid');

            btn.disabled = true;
            btn.classList.add('opacity-75');
            btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i><span>Analizando IA...</span>';
            loading.classList.remove('hidden');
            emptyMsg.classList.add('hidden');
            grid.classList.add('hidden');

            try {
                const seed = currentLoginReconData.facebook_correlation_seed;
                const res = await fetch(`${API_URL}?action=loginrecon_facebook_correlate`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(seed)
                });
                const data = await res.json();

                loading.classList.add('hidden');
                btn.disabled = false;
                btn.classList.remove('opacity-75');
                btn.innerHTML = '<i class="fa-solid fa-wand-magic-sparkles"></i><span>Re-Escanear Facebook (IA)</span>';

                if (data.status === 'success' && data.matches && data.matches.length > 0) {
                    renderFacebookAICandidates(data.matches);
                    grid.classList.remove('hidden');
                    const badge = document.getElementById('fb-ai-badge');
                    if (badge) {
                        badge.innerText = `${data.matches.length} Candidatos Evaluados`;
                        badge.className = 'px-2.5 py-0.5 rounded text-[10px] font-bold uppercase bg-emerald-950 text-emerald-300 border border-emerald-700';
                    }
                    showToast(`Facebook AI: ${data.matches.length} candidatos correlacionados exitosamente`);
                } else {
                    emptyMsg.classList.remove('hidden');
                    emptyMsg.innerHTML = '<i class="fa-solid fa-circle-exclamation text-amber-400"></i> No se encontraron perfiles públicos en Facebook con los datos suministrados.';
                    showToast('No se encontraron perfiles públicos en Facebook', false);
                }
            } catch (err) {
                console.error('Error in Facebook AI correlation:', err);
                loading.classList.add('hidden');
                emptyMsg.classList.remove('hidden');
                emptyMsg.innerHTML = '<i class="fa-solid fa-triangle-exclamation text-rose-400"></i> Error de conexión con el motor de IA de Facebook.';
                btn.disabled = false;
                btn.classList.remove('opacity-75');
                btn.innerHTML = '<i class="fa-solid fa-wand-magic-sparkles"></i><span>Reintentar Escaneo IA</span>';
                showToast('Error ejecutando la correlación en Facebook con IA', true);
            }
        }

        function renderFacebookAICandidates(matches) {
            const grid = document.getElementById('fb-ai-candidates-grid');
            if (!grid) return;

            grid.innerHTML = matches.map((m, idx) => {
                const sim = m.similarity_percent || 0.0;
                let badgeClass = 'bg-slate-800 text-slate-300 border-slate-700';
                let iconClass = 'fa-solid fa-user';
                let verdictText = m.confidence || 'Perfil Encontrado';

                if (m.verdict === 'MATCH_HIGH' || sim >= 75) {
                    badgeClass = 'bg-emerald-950 text-emerald-300 border-emerald-700 shadow-md shadow-emerald-950/60';
                    iconClass = 'fa-solid fa-circle-check text-emerald-400';
                } else if (m.verdict === 'MATCH_MODERATE' || sim >= 50) {
                    badgeClass = 'bg-amber-950 text-amber-300 border-amber-700';
                    iconClass = 'fa-solid fa-triangle-exclamation text-amber-400';
                }

                const sourceImgHtml = m.source_avatar_url ? `
                    <div class="text-center">
                        <span class="text-[9px] uppercase font-bold text-slate-400 block mb-1">Origen (${m.matched_platform || 'OSINT'})</span>
                        <img src="${m.source_avatar_url}" alt="Origen" class="w-12 h-12 rounded-xl object-cover border border-sky-500/60 shadow mx-auto" />
                    </div>
                ` : '';

                const fbImgHtml = m.facebook_avatar ? `
                    <div class="text-center">
                        <span class="text-[9px] uppercase font-bold text-slate-400 block mb-1">Facebook</span>
                        <img src="${m.facebook_avatar}" alt="Facebook" class="w-12 h-12 rounded-xl object-cover border border-blue-500/60 shadow mx-auto" onerror="this.src='https://static.xx.fbcdn.net/rsrc.php/v3/yO/r/zg6f851o1DJ.png';" />
                    </div>
                ` : `
                    <div class="text-center">
                        <span class="text-[9px] uppercase font-bold text-slate-400 block mb-1">Facebook</span>
                        <div class="w-12 h-12 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-center text-blue-400 text-lg mx-auto">
                            <i class="fa-brands fa-facebook"></i>
                        </div>
                    </div>
                `;

                const aiDetailsHtml = m.ai_details ? `
                    <div class="mt-2 pt-2 border-t border-slate-800/80 grid grid-cols-3 gap-1 text-[10px] text-center font-mono">
                        <div class="bg-slate-950 p-1 rounded border border-slate-800/50">
                            <span class="text-slate-500 block text-[8px] uppercase">pHash</span>
                            <span class="text-sky-300 font-bold">${m.ai_details.phash_similarity}%</span>
                        </div>
                        <div class="bg-slate-950 p-1 rounded border border-slate-800/50">
                            <span class="text-slate-500 block text-[8px] uppercase">SIFT/ORB</span>
                            <span class="text-purple-300 font-bold">${m.ai_details.feature_similarity}%</span>
                        </div>
                        <div class="bg-slate-950 p-1 rounded border border-slate-800/50">
                            <span class="text-slate-500 block text-[8px] uppercase">Color HSV</span>
                            <span class="text-emerald-300 font-bold">${m.ai_details.color_similarity}%</span>
                        </div>
                    </div>
                ` : '';

                return `
                    <div class="p-4 rounded-xl border border-blue-500/30 bg-slate-950/70 hover:border-blue-400/60 transition shadow-lg space-y-3 flex flex-col justify-between">
                        <div>
                            <div class="flex items-start justify-between gap-2 mb-2">
                                <div class="truncate max-w-[170px]">
                                    <h4 class="text-xs font-bold text-white flex items-center gap-1.5 truncate" title="${m.facebook_name}">
                                        <i class="fa-brands fa-facebook text-blue-400"></i> ${m.facebook_name}
                                    </h4>
                                    <span class="text-[10px] text-slate-400 font-mono">slug: /${m.slug || 'perfil'}</span>
                                </div>
                                <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${badgeClass} flex items-center gap-1">
                                    <i class="${iconClass}"></i> ${sim}%
                                </span>
                            </div>

                            <div class="flex items-center justify-center gap-3 bg-slate-900/60 p-2.5 rounded-xl border border-slate-800/70">
                                ${sourceImgHtml}
                                ${m.source_avatar_url ? '<div class="text-slate-600 text-xs"><i class="fa-solid fa-arrows-left-right"></i></div>' : ''}
                                ${fbImgHtml}
                            </div>

                            ${aiDetailsHtml}
                        </div>

                        <div class="pt-2 border-t border-slate-800/60 flex items-center justify-between gap-2">
                            <span class="text-[10px] text-slate-400 font-medium">${verdictText}</span>
                            <a href="${m.profile_url}" target="_blank" rel="noopener noreferrer" class="px-2.5 py-1 rounded-lg bg-blue-600/30 hover:bg-blue-600/60 text-blue-300 hover:text-white border border-blue-500/40 text-[10px] font-bold transition flex items-center gap-1">
                                <span>Ver Perfil</span> <i class="fa-solid fa-arrow-up-right-from-square text-[9px]"></i>
                            </a>
                        </div>
                    </div>
                `;
            }).join('');
        }

    

        // -------------------------------------------------------------
        // PHP2SHELL SCANNER JAVASCRIPT CONTROLLER (CVE-2026-109618 / 109619)
        // -------------------------------------------------------------
        let php2shellLastResults = [];

        function setPhp2shellTarget(val) {
            if (val === 'currentSeed') {
                const seed = (typeof activeSeed !== 'undefined' && activeSeed && activeSeed !== 'ALL') ? activeSeed : (globalSeeds[0]?.domain || '');
                onPhp2shellSeedSelect(seed);
            } else {
                onPhp2shellSeedSelect(val);
            }
        }

        // =============================================================
        // PHP2SHELL PRELOADED SEEDS CONTROLLER
        // =============================================================
        function populatePhp2shellPreloadedSeeds(seeds) {
            const select = document.getElementById('php2shell-target-select');
            const input = document.getElementById('php2shell-target-input');
            const quickContainer = document.getElementById('php2shell-quick-seeds');
            if (!select) return;

            const validSeeds = (seeds || []).filter(s => s && s.domain);
            if (validSeeds.length === 0) {
                select.innerHTML = '<option value="">(No hay semillas precargadas en el perímetro)</option>';
                if (input) input.value = '';
                if (quickContainer) quickContainer.innerHTML = '<span class="text-rose-400 font-mono text-[10px]">Sin semillas registradas</span>';
                return;
            }

            // Determine currently active seed
            let current = (typeof activeSeed !== 'undefined' && activeSeed && activeSeed !== 'ALL') ? activeSeed : validSeeds[0].domain;

            select.innerHTML = validSeeds.map(s => `
                <option value="${s.domain}" ${s.domain === current ? 'selected' : ''} class="bg-slate-900 text-white font-mono">
                    🎯 ${s.domain}
                </option>
            `).join('');

            if (input) input.value = current;

            // Render dynamic quick seed buttons exclusively for preloaded seeds
            if (quickContainer) {
                quickContainer.innerHTML = validSeeds.map(s => {
                    const isSelected = s.domain === current;
                    const activeClass = isSelected 
                        ? 'bg-indigo-900/90 text-indigo-200 border-indigo-500 font-bold shadow-sm' 
                        : 'bg-slate-800 hover:bg-slate-700 text-slate-300 border-slate-700';
                    return `<button type="button" onclick="onPhp2shellSeedSelect('${s.domain}')" class="px-2 py-0.5 rounded font-mono border text-[10px] transition ${activeClass}">
                        <i class="fa-solid fa-bullseye text-[9px] mr-1 text-indigo-400"></i>${s.domain}
                    </button>`;
                }).join('');
            }
        }

        function onPhp2shellSeedSelect(domain) {
            if (!domain) return;
            const select = document.getElementById('php2shell-target-select');
            const input = document.getElementById('php2shell-target-input');
            if (select) select.value = domain;
            if (input) input.value = domain;

            // Update active state on seed pills
            const quickContainer = document.getElementById('php2shell-quick-seeds');
            if (quickContainer) {
                quickContainer.querySelectorAll('button').forEach(btn => {
                    if (btn.innerText.includes(domain)) {
                        btn.className = 'px-2 py-0.5 rounded font-mono border text-[10px] transition bg-indigo-900/90 text-indigo-200 border-indigo-500 font-bold shadow-sm';
                    } else {
                        btn.className = 'px-2 py-0.5 rounded font-mono border text-[10px] transition bg-slate-800 hover:bg-slate-700 text-slate-300 border-slate-700';
                    }
                });
            }
        }

        function updatePhp2shellSelectedSeed(seed) {
            if (!seed || seed === 'ALL') {
                const select = document.getElementById('php2shell-target-select');
                if (select && select.value) {
                    onPhp2shellSeedSelect(select.value);
                }
                return;
            }
            onPhp2shellSeedSelect(seed);
        }


        async function runPhp2shellScan(e) {
            if (e) {
                if (typeof e.preventDefault === 'function') e.preventDefault();
                if (typeof e.stopPropagation === 'function') e.stopPropagation();
            }

            const targetInput = document.getElementById('php2shell-target-input');
            const modeSelect = document.getElementById('php2shell-mode-select');
            const portsInput = document.getElementById('php2shell-ports-input');
            const timeoutSelect = document.getElementById('php2shell-timeout-select');
            const autoOriginCheck = document.getElementById('php2shell-auto-origin');
            const onlyVulnCheck = document.getElementById('php2shell-only-vuln');
            const btnSubmit = document.getElementById('php2shell-btn-submit');
            const tbody = document.getElementById('php2shell-results-body');

            const target = (targetInput ? targetInput.value.trim() : '');
            if (!target) {
                if (typeof showToast === 'function') {
                    showToast('Por favor ingresa un objetivo a auditar (ej: vulnweb.com, 127.0.0.1)', true);
                } else {
                    alert('Por favor ingresa un objetivo a auditar');
                }
                return false;
            }

            const mode = modeSelect ? modeSelect.value : 'target';
            const ports = portsInput ? portsInput.value.trim() : '80,443';
            const timeout = timeoutSelect ? timeoutSelect.value : '6';
            const noAutoOrigin = (autoOriginCheck && !autoOriginCheck.checked) ? '1' : '0';
            const onlyVuln = (onlyVulnCheck && onlyVulnCheck.checked) ? '1' : '0';

            if (btnSubmit) {
                btnSubmit.disabled = true;
                btnSubmit.innerHTML = `<i class="fa-solid fa-spinner fa-spin text-white"></i><span>Escaneando ${target}...</span>`;
            }

            if (tbody) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="7" class="p-8 text-center text-slate-400">
                            <i class="fa-solid fa-circle-notch fa-spin text-3xl mb-3 text-indigo-400 block mx-auto"></i>
                            <div class="font-bold text-white text-sm">Ejecutando escáner pasivo PHP2Shell (CVE-2026-109618 / CVE-2026-109619)...</div>
                            <div class="text-xs text-slate-400 mt-1">Interrogando banners HTTP, cabeceras Server/X-Powered-By y cookies en <code class="text-indigo-300 font-mono">${target}</code>...</div>
                        </td>
                    </tr>
                `;
            }

            try {
                const params = new URLSearchParams({
                    action: 'php2shell_scan',
                    target: target,
                    mode: mode,
                    ports: ports,
                    timeout: timeout,
                    no_auto_origin: noAutoOrigin,
                    only_vuln: onlyVuln
                });

                const res = await fetch(`api.php?${params.toString()}`);
                const data = await res.json();

                if (!data.success) {
                    const errMsg = data.error || 'Error al ejecutar escáner PHP2Shell';
                    if (typeof showToast === 'function') showToast(errMsg, true);
                    if (tbody) {
                        tbody.innerHTML = `<tr><td colspan="7" class="p-6 text-center text-rose-400 font-bold">${errMsg}</td></tr>`;
                    }
                    return false;
                }

                php2shellLastResults = data.results || [];

                // Update KPI counters
                const s = data.stats || {};
                const statTotal = document.getElementById('php2shell-stat-total');
                const statVuln = document.getElementById('php2shell-stat-vuln');
                const statPatched = document.getElementById('php2shell-stat-patched');
                const statUnknown = document.getElementById('php2shell-stat-unknown');
                const statOther = document.getElementById('php2shell-stat-other');

                if (statTotal) statTotal.textContent = s.total || '0';
                if (statVuln) statVuln.textContent = s.vulnerable || '0';
                if (statPatched) statPatched.textContent = s.patched || '0';
                if (statUnknown) statUnknown.textContent = s.unknown || '0';
                if (statOther) statOther.textContent = (s.no_php || 0) + (s.filtered || 0) + (s.closed || 0) + (s.other || 0);

                renderPhp2shellResults(php2shellLastResults);

                if (s.vulnerable > 0) {
                    if (typeof showToast === 'function') showToast(`⚠️ ¡ALERTA! Se detectaron ${s.vulnerable} objetivo(s) vulnerables a PHP2Shell`, true);
                } else {
                    if (typeof showToast === 'function') showToast(`Auditoría completada: ${s.total} objetivo(s) analizados. Sin vulnerabilidades expuestas.`);
                }
            } catch (err) {
                console.error('Error in PHP2Shell scan:', err);
                if (typeof showToast === 'function') showToast('Error de conexión con el servidor al ejecutar el escáner', true);
                if (tbody) {
                    tbody.innerHTML = `<tr><td colspan="7" class="p-6 text-center text-rose-400">Error inesperado al conectar con api.php</td></tr>`;
                }
            } finally {
                if (btnSubmit) {
                    btnSubmit.disabled = false;
                    btnSubmit.innerHTML = `<i class="fa-solid fa-bolt-lightning"></i><span>Ejecutar Escáner PHP2Shell</span>`;
                }
            }
            return false;
        }

        function renderPhp2shellResults(results) {
            const tbody = document.getElementById('php2shell-results-body');
            if (!tbody) return;

            if (!results || results.length === 0) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="7" class="p-8 text-center text-slate-500">
                            No se encontraron resultados para los criterios seleccionados.
                        </td>
                    </tr>
                `;
                return;
            }

            tbody.innerHTML = results.map(r => {
                const v = (r.verdict || '').toUpperCase();
                let badge = `<span class="px-2 py-0.5 rounded text-[11px] text-slate-400 bg-slate-800">${v}</span>`;
                let rowBg = '';

                if (v === 'VULNERABLE') {
                    badge = `<span class="px-2.5 py-1 rounded-md text-xs font-bold bg-rose-950 text-rose-300 border border-rose-800 animate-pulse flex items-center gap-1 justify-center"><i class="fa-solid fa-triangle-exclamation"></i> VULNERABLE</span>`;
                    rowBg = 'bg-rose-950/25';
                } else if (v === 'PATCHED' || v === 'PARCHEADO') {
                    badge = `<span class="px-2.5 py-1 rounded-md text-xs font-bold bg-emerald-950 text-emerald-400 border border-emerald-800 flex items-center gap-1 justify-center"><i class="fa-solid fa-circle-check"></i> PARCHEADO</span>`;
                    rowBg = 'bg-emerald-950/10';
                } else if (v === 'UNKNOWN' || v === 'DESCONOCIDO') {
                    badge = `<span class="px-2.5 py-1 rounded-md text-xs font-semibold bg-amber-950 text-amber-300 border border-amber-800 flex items-center gap-1 justify-center"><i class="fa-solid fa-eye-slash"></i> OCULTO</span>`;
                } else if (v === 'NO-PHP' || v === 'SIN-PHP') {
                    badge = `<span class="px-2 py-0.5 rounded text-[11px] text-slate-400 bg-slate-800/80 border border-slate-700">SIN-PHP</span>`;
                } else if (v === 'FILTRADO') {
                    badge = `<span class="px-2 py-0.5 rounded text-[11px] text-slate-500 bg-slate-800/60">FILTRADO</span>`;
                } else if (v === 'CERRADO') {
                    badge = `<span class="px-2 py-0.5 rounded text-[11px] text-slate-500 bg-slate-800/60">CERRADO</span>`;
                }

                const wafInfo = r.behind_cdn_waf ?
                    `<span class="text-amber-400 font-mono text-[10px] flex items-center gap-1"><i class="fa-solid fa-shield"></i> ${r.cdn_waf || 'CDN/WAF'}</span>` :
                    `<span class="text-slate-500 text-[10px]">Directo</span>`;

                const phpVer = r.php_version ?
                    `<strong class="${v === 'VULNERABLE' ? 'text-rose-400' : 'text-emerald-400'} font-mono">${r.php_version}</strong>` :
                    `<span class="text-slate-500 font-mono">-</span>`;

                const fixVer = r.fixed_version ?
                    `<span class="text-indigo-400 font-mono font-semibold">${r.fixed_version}</span>` :
                    `<span class="text-slate-500 font-mono">-</span>`;

                const latency = r.latency_ms ? `${r.latency_ms} ms` : '-';

                return `
                    <tr class="hover:bg-slate-800/40 transition ${rowBg}">
                        <td class="p-4 font-bold text-white font-mono flex items-center gap-2">
                            <i class="fa-brands fa-php ${v === 'VULNERABLE' ? 'text-rose-400' : 'text-indigo-400'}"></i>
                            <span>${r.target || '-'}</span>
                        </td>
                        <td class="p-4 font-mono text-[11px] text-slate-300">
                            <div>${r.ip || '-'}</div>
                            <div class="text-slate-500 text-[10px] uppercase">${r.scheme || 'http'}:${r.port || 80}</div>
                        </td>
                        <td class="p-4">${phpVer}</td>
                        <td class="p-4">${fixVer}</td>
                        <td class="p-4">${wafInfo}</td>
                        <td class="p-4 text-center">${badge}</td>
                        <td class="p-4 text-[11px]">
                            <div class="text-slate-300">${r.detail || '-'}</div>
                            <div class="text-slate-500 text-[10px] mt-0.5">Latencia: ${latency} &bull; HTTP: ${r.http_status || '-'}</div>
                        </td>
                    </tr>
                `;
            }).join('');
        }

        function exportPhp2shellJson() {
            if (!php2shellLastResults || php2shellLastResults.length === 0) {
                if (typeof showToast === 'function') showToast('No hay resultados de PHP2Shell para exportar', true);
                return;
            }
            const blob = new Blob([JSON.stringify(php2shellLastResults, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `php2shell_audit_${Date.now()}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            if (typeof showToast === 'function') showToast('Resultados exportados en formato JSON');
        }

        function exportPhp2shellCsv() {
            if (!php2shellLastResults || php2shellLastResults.length === 0) {
                if (typeof showToast === 'function') showToast('No hay resultados de PHP2Shell para exportar', true);
                return;
            }
            const headers = ['target', 'ip', 'port', 'scheme', 'http_status', 'php_version', 'verdict', 'fixed_version', 'latency_ms', 'detail'];
            const rows = php2shellLastResults.map(r => headers.map(h => `"${(r[h] ?? '').toString().replace(/"/g, '""')}"`).join(','));
            const csvContent = headers.join(',') + '\n' + rows.join('\n');

            const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `php2shell_audit_${Date.now()}.csv`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            if (typeof showToast === 'function') showToast('Resultados exportados en formato CSV');
        }

</script>
    <!-- RISK SCORE BREAKDOWN MODAL -->
    <div id="risk-breakdown-modal" class="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4 hidden">
        <div class="bg-cyber-card border border-cyber-border rounded-2xl max-w-3xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
            <div class="p-6 border-b border-cyber-border flex items-center justify-between">
                <div>
                    <h3 class="text-base font-bold text-white flex items-center gap-2">
                        <i class="fa-solid fa-calculator text-indigo-400"></i>
                        Desglose Explicable de Riesgo EASM / CTEM (0 a 100)
                    </h3>
                    <p class="text-xs text-slate-400">Metodología transparente con evidencias consultables y ponderadas (CISA KEV, EPSS, NIST).</p>
                </div>
                <button onclick="closeRiskBreakdownModal()" class="text-slate-400 hover:text-white text-lg"><i class="fa-solid fa-xmark"></i></button>
            </div>

            <div class="p-6 overflow-y-auto space-y-6 text-xs" id="risk-breakdown-content">
                <div class="text-center py-8 text-slate-500">Cargando desglose de riesgo...</div>
            </div>

            <div class="p-4 border-t border-cyber-border bg-slate-900/60 flex justify-end">
                <button onclick="closeRiskBreakdownModal()" class="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-white font-semibold text-xs transition">Cerrar</button>
            </div>
        </div>
    </div>

    <!-- CONNECTOR CONFIG MODAL -->
    <div id="connector-config-modal" class="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4 hidden">
        <div class="bg-cyber-card border border-cyber-border rounded-2xl max-w-md w-full shadow-2xl overflow-hidden">
            <div class="p-5 border-b border-cyber-border flex items-center justify-between">
                <h4 class="text-sm font-bold text-white flex items-center gap-2" id="conn-modal-title">
                    <i class="fa-solid fa-key text-teal-400"></i>
                    Configurar Conector
                </h4>
                <button onclick="closeConnectorConfigModal()" class="text-slate-400 hover:text-white"><i class="fa-solid fa-xmark"></i></button>
            </div>
            <form onsubmit="handleSaveConnectorKey(event)" class="p-5 space-y-4">
                <input type="hidden" id="conn-modal-id">
                <div>
                    <label class="block text-xs font-semibold text-slate-400 mb-1">API Key / Token de Acceso:</label>
                    <input type="password" id="conn-modal-key" placeholder="Ingresa la API key del proveedor" class="w-full bg-slate-900 border border-cyber-border rounded-xl px-3 py-2 text-xs text-white font-mono focus:outline-none focus:border-teal-400">
                    <span class="text-[10px] text-slate-500 mt-1 block">La clave se almacena encriptada y se enmascara para preservar su confidencialidad.</span>
                </div>
                <div class="flex items-center gap-2">
                    <input type="checkbox" id="conn-modal-enabled" class="rounded bg-slate-900 border-cyber-border text-teal-500 focus:ring-0">
                    <label for="conn-modal-enabled" class="text-xs text-slate-300 font-medium">Habilitar sincronización para este conector</label>
                </div>
                <div class="flex justify-end gap-2 pt-2 border-t border-cyber-border">
                    <button type="button" onclick="closeConnectorConfigModal()" class="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 text-xs">Cancelar</button>
                    <button type="submit" class="px-4 py-1.5 rounded-lg bg-teal-600 hover:bg-teal-500 text-white font-semibold text-xs transition">Guardar</button>
                </div>
            </form>
        </div>
    </div>
</body>
</html>


    <!-- Fortinet FortiOS 7.4.13 Theme Engine & UI Controller -->
    <script>
    // =========================================================================
    // FORTINET THEMES DATA DICTIONARY & PERSISTENCE ENGINE
    // =========================================================================
    const FORTI_THEMES = {
        jade: {
            name: "Jade",
            header_bg: "#0f291e",
            sidebar_bg: "#0a1c14",
            sidebar_hover: "#123326",
            selection: "#164332",
            selection_text: "#34d399",
            selection_border: "#10b981",
            primary: "#10b981",
            primary_hover: "#059669",
            primary_text: "#042013",
            accent: "#34d399",
            bg_main: "#060f0b",
            card_bg: "#0c1913",
            card_header: "#10221a",
            border: "#1b3b2d",
            text_main: "#f0fdf4",
            text_muted: "#86efac"
        },
        neutrino: {
            name: "Neutrino",
            header_bg: "#0b253a",
            sidebar_bg: "#081a29",
            sidebar_hover: "#0f334f",
            selection: "#134469",
            selection_text: "#38bdf8",
            selection_border: "#06b6d4",
            primary: "#06b6d4",
            primary_hover: "#0891b2",
            primary_text: "#021a24",
            accent: "#38bdf8",
            bg_main: "#040d14",
            card_bg: "#0a1724",
            card_header: "#0e2032",
            border: "#163b5c",
            text_main: "#f0f9ff",
            text_muted: "#7dd3fc"
        },
        mariner: {
            name: "Mariner",
            header_bg: "#132238",
            sidebar_bg: "#0d1726",
            sidebar_hover: "#182c47",
            selection: "#1f395c",
            selection_text: "#60a5fa",
            selection_border: "#2563eb",
            primary: "#2563eb",
            primary_hover: "#1d4ed8",
            primary_text: "#ffffff",
            accent: "#60a5fa",
            bg_main: "#070c14",
            card_bg: "#0e1828",
            card_header: "#142239",
            border: "#1c3353",
            text_main: "#eff6ff",
            text_muted: "#93c5fd"
        },
        graphite: {
            name: "Graphite",
            header_bg: "#212529",
            sidebar_bg: "#181b1e",
            sidebar_hover: "#2b3035",
            selection: "#343a40",
            selection_text: "#f1f5f9",
            selection_border: "#94a3b8",
            primary: "#64748b",
            primary_hover: "#475569",
            primary_text: "#ffffff",
            accent: "#94a3b8",
            bg_main: "#0f1113",
            card_bg: "#1a1d21",
            card_header: "#24282d",
            border: "#343a40",
            text_main: "#f8fafc",
            text_muted: "#cbd5e1"
        },
        melongene: {
            name: "Melongene",
            header_bg: "#2a173b",
            sidebar_bg: "#1d1029",
            sidebar_hover: "#381f4f",
            selection: "#492866",
            selection_text: "#d8b4fe",
            selection_border: "#a855f7",
            primary: "#a855f7",
            primary_hover: "#9333ea",
            primary_text: "#ffffff",
            accent: "#c084fc",
            bg_main: "#0f0717",
            card_bg: "#1a0e26",
            card_header: "#241334",
            border: "#42235c",
            text_main: "#faf5ff",
            text_muted: "#d8b4fe"
        },
        retro: {
            name: "Retro",
            header_bg: "#2d2013",
            sidebar_bg: "#20160d",
            sidebar_hover: "#3d2b1a",
            selection: "#4f3822",
            selection_text: "#fde68a",
            selection_border: "#f59e0b",
            primary: "#f59e0b",
            primary_hover: "#d97706",
            primary_text: "#261604",
            accent: "#fbbf24",
            bg_main: "#120c07",
            card_bg: "#1c130b",
            card_header: "#261a0f",
            border: "#4a331c",
            text_main: "#fffbeb",
            text_muted: "#fcd34d"
        },
        darkmatter: {
            name: "Dark Matter",
            header_bg: "#121214",
            sidebar_bg: "#0a0a0c",
            sidebar_hover: "#1a1a1e",
            selection: "#24242a",
            selection_text: "#2dd4bf",
            selection_border: "#14b8a6",
            primary: "#14b8a6",
            primary_hover: "#0d9488",
            primary_text: "#042f2e",
            accent: "#2dd4bf",
            bg_main: "#020203",
            card_bg: "#0e0e11",
            card_header: "#141418",
            border: "#222228",
            text_main: "#f0fdfa",
            text_muted: "#99f6e4"
        },
        onyx: {
            name: "Onyx",
            header_bg: "#18181b",
            sidebar_bg: "#09090b",
            sidebar_hover: "#27272a",
            selection: "#3f3f46",
            selection_text: "#ffffff",
            selection_border: "#e4e4e7",
            primary: "#f4f4f5",
            primary_hover: "#e4e4e7",
            primary_text: "#09090b",
            accent: "#ffffff",
            bg_main: "#000000",
            card_bg: "#0c0c0e",
            card_header: "#141417",
            border: "#27272a",
            text_main: "#ffffff",
            text_muted: "#a1a1aa"
        },
        eclipse: {
            name: "Eclipse",
            header_bg: "#1a1e36",
            sidebar_bg: "#121526",
            sidebar_hover: "#232949",
            selection: "#313966",
            selection_text: "#fde047",
            selection_border: "#fbbf24",
            primary: "#fbbf24",
            primary_hover: "#f59e0b",
            primary_text: "#2d1802",
            accent: "#fde047",
            bg_main: "#0a0c17",
            card_bg: "#13172b",
            card_header: "#1c213d",
            border: "#293156",
            text_main: "#fefce8",
            text_muted: "#fef08a"
        }
    };

    function getCurrentAnalyst() {
        return 'admin';
    }

    function applyTheme(themeId, customObj = null, persist = true) {
        const root = document.documentElement;
        let themeData = null;

        if (customObj) {
            themeData = customObj;
            root.setAttribute('data-theme', 'custom');
            // Inject Custom CSS Variables
            root.style.setProperty('--fg-header-bg', themeData.header_bg);
            root.style.setProperty('--fg-header-border', themeData.border);
            root.style.setProperty('--fg-sidebar-bg', themeData.sidebar_bg);
            root.style.setProperty('--fg-sidebar-hover', themeData.sidebar_hover);
            root.style.setProperty('--fg-selection', themeData.selection);
            root.style.setProperty('--fg-selection-text', themeData.selection_text);
            root.style.setProperty('--fg-selection-border', themeData.selection_border || themeData.accent);
            root.style.setProperty('--fg-primary', themeData.primary);
            root.style.setProperty('--fg-primary-hover', themeData.primary_hover || themeData.primary);
            root.style.setProperty('--fg-accent', themeData.accent);
            root.style.setProperty('--fg-bg-main', themeData.bg_main);
            root.style.setProperty('--fg-card-bg', themeData.card_bg);
            root.style.setProperty('--fg-card-header', themeData.card_header);
            root.style.setProperty('--fg-border', themeData.border);
            root.style.setProperty('--fg-text-main', themeData.text_main);
            root.style.setProperty('--fg-text-muted', themeData.text_muted);
            root.style.setProperty('--fg-input-bg', themeData.bg_main);
            root.style.setProperty('--fg-input-border', themeData.border);
            root.style.setProperty('--fg-table-header-bg', themeData.card_header);
        } else {
            themeData = FORTI_THEMES[themeId] || FORTI_THEMES.jade;
            root.setAttribute('data-theme', themeId);
            // Clear custom inline styles so CSS takes precedence
            [
                '--fg-header-bg', '--fg-header-border', '--fg-sidebar-bg', '--fg-sidebar-hover',
                '--fg-selection', '--fg-selection-text', '--fg-selection-border', '--fg-primary',
                '--fg-primary-hover', '--fg-accent', '--fg-bg-main', '--fg-card-bg',
                '--fg-card-header', '--fg-border', '--fg-text-main', '--fg-text-muted',
                '--fg-input-bg', '--fg-input-border', '--fg-table-header-bg'
            ].forEach(prop => root.style.removeProperty(prop));
        }

        // Update Theme Dropdown Label & Checkmarks
        const label = document.getElementById('current-theme-label');
        if (label) label.innerText = themeData.name || themeId;

        Object.keys(FORTI_THEMES).forEach(k => {
            const chk = document.getElementById(`theme-check-${k}`);
            if (chk) {
                if (k === themeId && !customObj) {
                    chk.classList.remove('hidden');
                } else {
                    chk.classList.add('hidden');
                }
            }
        });

        // Close dropdown
        const menu = document.getElementById('theme-dropdown-menu');
        if (menu) menu.classList.add('hidden');

        // Update Chart.js if active
        if (typeof Chart !== 'undefined' && Chart.instances) {
            Object.values(Chart.instances).forEach(inst => {
                try { inst.update(); } catch(e) {}
            });
        }

        // Update Vis-Network background if active
        const canvas = document.getElementById('network-canvas');
        if (canvas) {
            canvas.style.backgroundColor = themeData.bg_main;
        }

        // Save preference per-analyst
        if (persist) {
            const user = getCurrentAnalyst();
            localStorage.setItem(`openrecon_theme_${user}`, customObj ? 'custom' : themeId);
            if (customObj) {
                localStorage.setItem(`openrecon_custom_data_${user}`, JSON.stringify(customObj));
            }
        }
    }

    function toggleThemeDropdown() {
        const menu = document.getElementById('theme-dropdown-menu');
        if (menu) menu.classList.toggle('hidden');
    }

    document.addEventListener('click', function(e) {
        const container = document.getElementById('theme-dropdown-container');
        const menu = document.getElementById('theme-dropdown-menu');
        if (container && menu && !container.contains(e.target)) {
            menu.classList.add('hidden');
        }
    });

    // Sidebar Collapse/Expand Logic
    function toggleFortiSidebar() {
        const sb = document.getElementById('forti-sidebar');
        const icon = document.getElementById('sidebar-toggle-icon');
        if (!sb) return;

        sb.classList.toggle('collapsed');
        const isCollapsed = sb.classList.contains('collapsed');
        document.body.classList.toggle('sidebar-collapsed', isCollapsed);

        if (icon) {
            icon.className = isCollapsed ? 'fa-solid fa-angles-right' : 'fa-solid fa-angles-left';
        }

        localStorage.setItem('openrecon_sidebar_collapsed', isCollapsed ? '1' : '0');
        if (typeof networkInstance !== 'undefined' && networkInstance) {
            setTimeout(() => networkInstance.fit(), 250);
        }
    }

    // High Density Toggle
    function toggleDensity() {
        const isCompact = document.documentElement.getAttribute('data-density') === 'compact';
        if (isCompact) {
            document.documentElement.removeAttribute('data-density');
            localStorage.setItem('openrecon_density', 'normal');
            showToast('Densidad de visualización: Estándar');
        } else {
            document.documentElement.setAttribute('data-density', 'compact');
            localStorage.setItem('openrecon_density', 'compact');
            showToast('Densidad de visualización: Alta Densidad (SOC Compacto)');
        }
    }

    // Global Search Filter Handler (Ctrl+K)
    function handleGlobalSearch(term) {
        term = (term || '').trim().toLowerCase();
        if (!term) return;

        // Search in active view
        const currentActive = document.querySelector('.forti-nav-item.active');
        const currentTab = currentActive ? currentActive.id.replace('tab-btn-', '') : 'easm';

        if (currentTab === 'easm') {
            const input = document.getElementById('asset-search');
            if (input) { input.value = term; renderAssetsTable(); }
        } else if (currentTab === 'vulns') {
            const input = document.getElementById('vuln-search');
            if (input) { input.value = term; applyVulnFilters(); }
        } else if (currentTab === 'seeds') {
            const input = document.getElementById('seed-search');
            if (input) { input.value = term; filterSeedsTable(); }
        } else if (currentTab === 'connectors') {
            renderConnectorsGrid();
        }
    }

    document.addEventListener('keydown', function(e) {
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
            e.preventDefault();
            const searchInput = document.getElementById('forti-global-search');
            if (searchInput) { searchInput.focus(); searchInput.select(); }
        }
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'b') {
            e.preventDefault();
            toggleFortiSidebar();
        }
    });

    // Theme Customizer Modal Functions
    function openThemeCustomizer() {
        const menu = document.getElementById('theme-dropdown-menu');
        if (menu) menu.classList.add('hidden');

        // Load current active theme into customizer inputs
        const currentThemeId = document.documentElement.getAttribute('data-theme') || 'jade';
        loadPresetIntoCustomizer(currentThemeId === 'custom' ? 'jade' : currentThemeId);

        document.getElementById('theme-customizer-modal').classList.remove('hidden');
        updateThemePreview();
    }

    function closeThemeCustomizer() {
        document.getElementById('theme-customizer-modal').classList.add('hidden');
    }

    function loadPresetIntoCustomizer(presetKey) {
        const t = FORTI_THEMES[presetKey] || FORTI_THEMES.jade;
        document.getElementById('custom-theme-name').value = `Personalizado (${t.name})`;
        document.getElementById('custom-theme-base-preset').value = presetKey;

        const mapping = {
            'header-bg': t.header_bg,
            'sidebar-bg': t.sidebar_bg,
            'sidebar-hover': t.sidebar_hover,
            'selection': t.selection,
            'primary': t.primary,
            'accent': t.accent,
            'bg-main': t.bg_main,
            'card-bg': t.card_bg,
            'card-header': t.card_header,
            'border': t.border,
            'text-main': t.text_main,
            'text-muted': t.text_muted
        };

        Object.entries(mapping).forEach(([key, val]) => {
            const picker = document.getElementById(`picker-${key}`);
            const txt = document.getElementById(`text-${key}`);
            if (picker) picker.value = val;
            if (txt) txt.value = val;
        });

        updateThemePreview();
    }

    function syncColorInput(key) {
        const txt = document.getElementById(`text-${key}`);
        const picker = document.getElementById(`picker-${key}`);
        if (txt && picker && /^#[0-9A-Fa-f]{6}$/.test(txt.value)) {
            picker.value = txt.value;
            updateThemePreview();
        }
    }

    function updateThemePreview() {
        const getVal = (k) => {
            const picker = document.getElementById(`picker-${k}`);
            return picker ? picker.value : '#000000';
        };

        const colHeader = getVal('header-bg');
        const colSidebar = getVal('sidebar-bg');
        const colHover = getVal('sidebar-hover');
        const colSelection = getVal('selection');
        const colPrimary = getVal('primary');
        const colAccent = getVal('accent');
        const colBgMain = getVal('bg-main');
        const colCard = getVal('card-bg');
        const colCardHdr = getVal('card-header');
        const colBorder = getVal('border');
        const colTextMain = getVal('text-main');
        const colTextMuted = getVal('text-muted');

        // Sync text inputs with picker
        [
            'header-bg', 'sidebar-bg', 'sidebar-hover', 'selection',
            'primary', 'accent', 'bg-main', 'card-bg', 'card-header',
            'border', 'text-main', 'text-muted'
        ].forEach(k => {
            const picker = document.getElementById(`picker-${k}`);
            const txt = document.getElementById(`text-${k}`);
            if (picker && txt && document.activeElement !== txt) {
                txt.value = picker.value;
            }
        });

        // Update preview elements
        const previewBox = document.getElementById('theme-preview-box');
        if (previewBox) {
            previewBox.style.backgroundColor = colBgMain;
            previewBox.style.borderColor = colBorder;
        }

        const prevHdr = document.getElementById('prev-header');
        if (prevHdr) {
            prevHdr.style.backgroundColor = colHeader;
            prevHdr.style.borderColor = colBorder;
            prevHdr.style.color = colTextMain;
        }

        const prevIcon = document.getElementById('prev-accent-icon');
        if (prevIcon) prevIcon.style.color = colAccent;

        const prevBtn = document.getElementById('prev-btn-primary');
        if (prevBtn) {
            prevBtn.style.backgroundColor = colPrimary;
            prevBtn.style.color = '#ffffff';
        }

        const prevBadge = document.getElementById('prev-badge-crit');
        if (prevBadge) {
            prevBadge.style.backgroundColor = 'rgba(239, 68, 68, 0.2)';
            prevBadge.style.color = '#ef4444';
            prevBadge.style.border = '1px solid #b91c1c';
        }

        const prevSb = document.getElementById('prev-sidebar');
        if (prevSb) {
            prevSb.style.backgroundColor = colSidebar;
            prevSb.style.borderColor = colBorder;
        }

        const prevActive = document.getElementById('prev-nav-active');
        if (prevActive) {
            prevActive.style.backgroundColor = colSelection;
            prevActive.style.color = colAccent;
            prevActive.style.borderLeftColor = colPrimary;
        }

        const prevCard = document.getElementById('prev-card');
        if (prevCard) {
            prevCard.style.backgroundColor = colCard;
            prevCard.style.borderColor = colBorder;
            prevCard.style.color = colTextMain;
        }

        const prevCardHdr = document.getElementById('prev-card-hdr');
        if (prevCardHdr) {
            prevCardHdr.style.backgroundColor = colCardHdr;
            prevCardHdr.style.borderColor = colBorder;
        }

        const prevTextSample = document.getElementById('prev-text-sample');
        if (prevTextSample) prevTextSample.style.color = colTextMuted;
    }

    function saveAndApplyCustomTheme() {
        const getVal = (k) => document.getElementById(`picker-${k}`).value;
        const name = (document.getElementById('custom-theme-name').value || 'Tema Personalizado').trim();

        const customTheme = {
            name: name,
            header_bg: getVal('header-bg'),
            sidebar_bg: getVal('sidebar-bg'),
            sidebar_hover: getVal('sidebar-hover'),
            selection: getVal('selection'),
            selection_text: getVal('accent'),
            selection_border: getVal('primary'),
            primary: getVal('primary'),
            primary_hover: getVal('primary'),
            accent: getVal('accent'),
            bg_main: getVal('bg-main'),
            card_bg: getVal('card-bg'),
            card_header: getVal('card-header'),
            border: getVal('border'),
            text_main: getVal('text-main'),
            text_muted: getVal('text-muted')
        };

        applyTheme('custom', customTheme, true);
        closeThemeCustomizer();
        showToast(`Tema personalizado guardado: "${name}"`);
    }

    function duplicateCustomTheme() {
        const nameInput = document.getElementById('custom-theme-name');
        nameInput.value = `${nameInput.value} (Copia)`;
        showToast('Tema duplicado en el editor. Haz clic en "Guardar y Aplicar" para conservarlo.');
    }

    function resetToDefaultTheme() {
        const user = getCurrentAnalyst();
        localStorage.removeItem(`openrecon_theme_${user}`);
        localStorage.removeItem(`openrecon_custom_data_${user}`);
        applyTheme('jade', null, true);
        closeThemeCustomizer();
        showToast('Tema restablecido al predeterminado Fortinet (Jade).');
    }

    // Load initial theme on DOM ready
    (function initThemeEngine() {
        const user = getCurrentAnalyst();
        const savedTheme = localStorage.getItem(`openrecon_theme_${user}`);
        const customData = localStorage.getItem(`openrecon_custom_data_${user}`);

        if (savedTheme === 'custom' && customData) {
            try {
                applyTheme('custom', JSON.parse(customData), false);
            } catch(e) {
                applyTheme('jade', null, false);
            }
        } else if (savedTheme && FORTI_THEMES[savedTheme]) {
            applyTheme(savedTheme, null, false);
        } else {
            applyTheme('jade', null, false);
        }

        // Restore Density
        if (localStorage.getItem('openrecon_density') === 'compact') {
            document.documentElement.setAttribute('data-density', 'compact');
        }

        // Restore Sidebar State
        if (localStorage.getItem('openrecon_sidebar_collapsed') === '1') {
            document.addEventListener('DOMContentLoaded', () => {
                const sb = document.getElementById('forti-sidebar');
                if (sb) {
                    sb.classList.add('collapsed');
                    document.body.classList.add('sidebar-collapsed');
                    const icon = document.getElementById('sidebar-toggle-icon');
                    if (icon) icon.className = 'fa-solid fa-angles-right';
                }
            });
        }
    })();
    </script>


    <script>
    // Module Titles and Categories Dictionary for FortiOS Breadcrumb Navigation
    const FORTI_MODULE_META = {
        'mitre': { cat: 'Threat Intelligence (CTI)', title: 'Matriz MITRE ATT&CK Enterprise' },
        'iocs': { cat: 'Threat Intelligence (CTI)', title: 'Centro de Gestión de IoCs (STIX 2.1)' },
        'ransomware': { cat: 'Threat Intelligence (CTI)', title: 'Telemetría de Ransomware & Extorsión' },
        'riskscoring': { cat: 'Vulnerabilidades & Postura', title: 'Motor Explicable de Riesgo' },
        'reports': { cat: 'Centro de Reportes', title: 'Generación de Reportes & Exportación' },
        'easm': { cat: 'Superficie de Ataque (EASM)', title: 'Inventario Perimetral Descubierto' },
        'graph': { cat: 'Dashboard & Topología', title: 'Grafo de Relaciones y Amenazas' },
        'vulns': { cat: 'Vulnerabilidades & Postura', title: 'Centro de Vulnerabilidades & CISA KEV' },
        'drp': { cat: 'Threat Intelligence & DRP', title: 'Protección Digital de Marca' },
        'leaks': { cat: 'Threat Intelligence & DRP', title: 'Fugas de Credenciales y Secretos' },
        'cti': { cat: 'Threat Intelligence & DRP', title: 'Inteligencia de Amenazas (CTI Feeds)' },
        'seeds': { cat: 'Superficie de Ataque (EASM)', title: 'Semillas y Perímetro Corporativo' },
        'strix': { cat: 'Operaciones Ofensivas & Pentest', title: 'Sackmesser Suite (Strix & AutoPentestX)' },
        'loginrecon': { cat: 'Operaciones Ofensivas & Pentest', title: 'LoginRecon OSINT & Identidades' },
        'php2shell': { cat: 'Vulnerabilidades & Postura', title: 'PHP2Shell Scanner (CVE-2026)' },
        'connectors': { cat: 'Security Fabric & Conectores', title: 'Conectores OSINT & APIs de Ciberseguridad' },
        'scope': { cat: 'Políticas & Alcance', title: 'Alcance Autorizado & Protección Anti-SSRF' },
        'cloud': { cat: 'Superficie de Ataque (EASM)', title: 'Auditoría de Exposición Cloud & Buckets' },
        'ai': { cat: 'Security Fabric & IA', title: 'Correlación de Evidencias Asistida por IA' },
        'darkintel': { cat: 'Threat Intelligence (CTI)', title: 'Dark Intelligence, Onion OSINT & CTI' },
        'emailintel': { cat: 'OSINT & Identidades', title: 'Email Intelligence (Zehef OSINT)' }
    };

    // Override switchTab with FortiOS sidebar navigation support
    const previousSwitchTab = typeof switchTab === 'function' ? switchTab : null;
    switchTab = function(tabId) {
        // 1. Update FortiOS Sidebar Active States
        document.querySelectorAll('.forti-nav-item').forEach(btn => {
            btn.classList.remove('active');
        });
        const activeBtn = document.getElementById(`tab-btn-${tabId}`);
        if (activeBtn) {
            activeBtn.classList.add('active');
        }

        // 2. Update Breadcrumb Text
        const meta = FORTI_MODULE_META[tabId] || { cat: 'OpenRecon', title: tabId.toUpperCase() };
        const bcCat = document.getElementById('bc-category');
        const bcMod = document.getElementById('bc-module');
        if (bcCat) bcCat.innerText = meta.cat;
        if (bcMod) bcMod.innerText = meta.title;

        // 3. Toggle Visibility of 14 Tab Content Sections
        const allTabs = ['easm', 'graph', 'vulns', 'drp', 'leaks', 'cti', 'seeds', 'strix', 'loginrecon', 'php2shell', 'connectors', 'scope', 'cloud', 'ai', 'darkintel', 'emailintel'];
        allTabs.forEach(t => {
            const el = document.getElementById(`tab-content-${t}`);
            if (el) el.classList.toggle('hidden', t !== tabId);
        });

        // 4. Trigger Specific Module Loaders
        if (tabId === 'connectors' && typeof loadConnectors === 'function') loadConnectors();
        if (tabId === 'scope' && typeof loadScope === 'function') loadScope();
        if (tabId === 'cloud' && typeof loadCloudExposure === 'function') loadCloudExposure();
        if (tabId === 'graph' && typeof networkInstance !== 'undefined' && networkInstance) {
            setTimeout(() => { networkInstance.fit(); }, 120);
        }
        if (tabId === 'strix' && typeof populateStrixAssetDropdown === 'function') populateStrixAssetDropdown();
        if (tabId === 'loginrecon' && typeof populateLoginReconPresets === 'function') populateLoginReconPresets();
        if (tabId === 'php2shell' && typeof updatePhp2shellSelectedSeed === 'function') updatePhp2shellSelectedSeed(activeSeed);
        if (tabId === 'darkintel' && typeof darkIntelLoadOverview === 'function') darkIntelLoadOverview();
        if (tabId === 'emailintel' && typeof emailIntelLoadOverview === 'function') emailIntelLoadOverview();

        // Scroll main viewport to top on tab switch
        const vp = document.getElementById('forti-main-viewport');
        if (vp) vp.scrollTop = 0;
    };
    </script>
