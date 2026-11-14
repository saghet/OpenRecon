<!-- TAB CONTENT: DOMAIN INTELLIGENCE (OSINT & CTI) -->
<div id="tab-content-domainintel" class="hidden space-y-6">
    <!-- Header & Search Bar -->
    <div class="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl">
        <div class="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
            <div>
                <div class="flex items-center gap-2">
                    <i class="fa-solid fa-globe text-cyan-400 text-xl"></i>
                    <h2 class="text-xl font-bold text-slate-100 tracking-tight">Domain Intelligence &amp; Threat Correlation</h2>
                    <span class="px-2 py-0.5 text-[11px] font-mono rounded bg-cyan-950 text-cyan-300 border border-cyan-800">RDAP · VT · OTX · CT · CTI</span>
                </div>
                <p class="text-xs text-slate-400 mt-1">Investigación pasiva y correlación multi-fuente restringida exclusivamente a dominios autorizados en Semillas / Perímetro (RoE).</p>
            </div>
            <div class="flex items-center gap-2">
                <button onclick="domainIntelToggleKeysModal()" class="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs border border-slate-700 flex items-center gap-2">
                    <i class="fa-solid fa-key text-amber-400"></i> API Keys
                </button>
                <button onclick="domainIntelLoadHistory()" class="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs border border-slate-700 flex items-center gap-2">
                    <i class="fa-solid fa-clock-rotate-left text-cyan-400"></i> Actualizar Historial
                </button>
            </div>
        </div>

        <div class="mt-5 flex flex-col lg:flex-row gap-3">
            <div class="flex-1 flex flex-col sm:flex-row gap-2">
                <select id="di-seed-select"
                        class="flex-1 bg-slate-950 border border-slate-700 rounded-xl px-4 py-3 text-sm text-slate-100 focus:outline-none focus:border-cyan-500 font-mono">
                    <option value="">Cargando semillas autorizadas...</option>
                </select>
                <button onclick="domainIntelLoadSeeds()" title="Recargar Semillas"
                        class="px-3 py-3 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs border border-slate-700">
                    <i class="fa-solid fa-rotate"></i>
                </button>
            </div>
            <label class="flex items-center gap-2 text-xs text-slate-300 px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl cursor-pointer">
                <input id="di-use-cache" type="checkbox" checked class="accent-cyan-500">
                Usar caché
            </label>
            <button id="di-run-btn" onclick="domainIntelRunInvestigation()"
                    class="px-5 py-3 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-sm flex items-center justify-center gap-2 transition shadow-lg shadow-cyan-950/50">
                <i class="fa-solid fa-magnifying-glass-chart"></i>
                <span>INVESTIGAR SEMILLA</span>
            </button>
            <button id="di-run-all-btn" onclick="domainIntelRunAllSeeds()"
                    class="px-5 py-3 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-sm flex items-center justify-center gap-2 transition shadow-lg shadow-indigo-950/50">
                <i class="fa-solid fa-layer-group"></i>
                <span>INVESTIGAR TODAS (<span id="di-seeds-count">0</span>)</span>
            </button>
            <button id="di-stop-all-btn" onclick="domainIntelStopBatch()" class="hidden px-4 py-3 rounded-xl bg-rose-700 hover:bg-rose-600 text-white font-semibold text-xs">
                <i class="fa-solid fa-stop mr-1"></i> Detener
            </button>
        </div>

        <div id="di-progress-bar" class="hidden mt-4 p-3 rounded-xl bg-slate-950 border border-cyan-900/60 flex items-center gap-3 text-xs text-cyan-300">
            <i class="fa-solid fa-spinner fa-spin"></i>
            <span id="di-progress-text">Consultando RDAP/WHOIS, VirusTotal, AlienVault OTX, DNS, crt.sh y feeds CTI...</span>
        </div>
        <div id="di-error-banner" class="hidden mt-4 p-3 rounded-xl bg-rose-950/60 border border-rose-800 text-xs text-rose-200"></div>
    </div>

    <!-- API Keys Modal -->
    <div id="di-keys-panel" class="hidden bg-slate-900/95 border border-slate-700 rounded-2xl p-5 space-y-4">
        <div class="flex items-center justify-between">
            <h3 class="text-sm font-bold text-slate-100"><i class="fa-solid fa-shield-halved text-amber-400 mr-2"></i>Gestión Segura de API Keys (Cifradas en Backend)</h3>
            <button onclick="domainIntelToggleKeysModal()" class="text-xs text-slate-400 hover:text-white">Cerrar</button>
        </div>
        <div id="di-keys-status-list" class="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs"></div>
        <div class="grid grid-cols-1 md:grid-cols-4 gap-3 pt-2 border-t border-slate-800">
            <select id="di-cred-provider" class="bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200">
                <option value="virustotal">VirusTotal</option>
                <option value="otx">AlienVault OTX</option>
                <option value="abuseipdb">AbuseIPDB</option>
                <option value="urlhaus">URLhaus</option>
                <option value="threatfox">ThreatFox</option>
            </select>
            <input id="di-cred-key" type="password" placeholder="Pegar API Key..." class="md:col-span-2 bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200">
            <button onclick="domainIntelSaveCredential()" class="px-4 py-2 rounded-lg bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold">Guardar Cifrada</button>
        </div>
    </div>

    <!-- Results Container -->
    <div id="di-results-container" class="hidden space-y-6">
        <!-- Risk & Export Summary -->
        <div class="grid grid-cols-1 lg:grid-cols-4 gap-4">
            <div class="bg-slate-900 border border-slate-800 rounded-2xl p-5">
                <div class="text-xs text-slate-400 uppercase font-semibold">Clasificación Global</div>
                <div id="di-risk-tier" class="text-2xl font-extrabold mt-2 text-slate-100">UNKNOWN</div>
                <div id="di-target-meta" class="text-xs text-slate-400 mt-1 font-mono"></div>
            </div>
            <div class="bg-slate-900 border border-slate-800 rounded-2xl p-5">
                <div class="text-xs text-slate-400 uppercase font-semibold">Reputación Externa</div>
                <div id="di-ext-score" class="text-2xl font-extrabold mt-2 text-cyan-400">--</div>
                <div class="text-[11px] text-slate-500 mt-1">Riesgo Técnico: <span id="di-tech-score">N/A</span></div>
            </div>
            <div class="bg-slate-900 border border-slate-800 rounded-2xl p-5">
                <div class="text-xs text-slate-400 uppercase font-semibold">Nivel de Confianza</div>
                <div id="di-conf-score" class="text-2xl font-extrabold mt-2 text-emerald-400">--</div>
                <div class="text-[11px] text-slate-500 mt-1">Cobertura real de proveedores</div>
            </div>
            <div class="bg-slate-900 border border-slate-800 rounded-2xl p-5 flex flex-col justify-between">
                <div class="text-xs text-slate-400 uppercase font-semibold">Exportar Expediente</div>
                <div class="flex flex-wrap gap-2 mt-2">
                    <button onclick="domainIntelExport('json')" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-cyan-300 border border-slate-700">JSON</button>
                    <button onclick="domainIntelExport('csv')" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-emerald-300 border border-slate-700">CSV</button>
                    <button onclick="domainIntelExport('html')" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-amber-300 border border-slate-700">HTML</button>
                </div>
            </div>
        </div>

        <!-- Explainable Risk & Provider Status -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div class="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-3">
                <h3 class="text-sm font-bold text-slate-100">Evaluación Explicable de Riesgo</h3>
                <p id="di-risk-explanation" class="text-xs text-slate-300"></p>
                <div id="di-evidences-list" class="space-y-1.5 text-xs"></div>
                <div id="di-limitations-list" class="text-[11px] text-amber-300/90 space-y-1"></div>
            </div>
            <div class="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-3">
                <h3 class="text-sm font-bold text-slate-100">Estado de Proveedores</h3>
                <div id="di-provider-badges" class="grid grid-cols-2 gap-2 text-xs"></div>
            </div>
        </div>

        <!-- Panels: WHOIS/RDAP, VirusTotal, OTX, DNS & CT -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div class="bg-slate-900 border border-slate-800 rounded-2xl p-5">
                <h3 class="text-sm font-bold text-slate-100 mb-3"><i class="fa-solid fa-id-card text-cyan-400 mr-2"></i>Perfil WHOIS / RDAP</h3>
                <div id="di-panel-rdap" class="text-xs text-slate-300 space-y-1.5"></div>
            </div>
            <div class="bg-slate-900 border border-slate-800 rounded-2xl p-5">
                <h3 class="text-sm font-bold text-slate-100 mb-3"><i class="fa-solid fa-shield-virus text-rose-400 mr-2"></i>VirusTotal (Consulta Pasiva)</h3>
                <div id="di-panel-vt" class="text-xs text-slate-300 space-y-1.5"></div>
            </div>
            <div class="bg-slate-900 border border-slate-800 rounded-2xl p-5">
                <h3 class="text-sm font-bold text-slate-100 mb-3"><i class="fa-solid fa-satellite-dish text-purple-400 mr-2"></i>AlienVault OTX (Pulses &amp; Malware)</h3>
                <div id="di-panel-otx" class="text-xs text-slate-300 space-y-2 max-h-64 overflow-y-auto"></div>
            </div>
            <div class="bg-slate-900 border border-slate-800 rounded-2xl p-5">
                <h3 class="text-sm font-bold text-slate-100 mb-3"><i class="fa-solid fa-network-wired text-emerald-400 mr-2"></i>DNS &amp; Certificate Transparency (crt.sh)</h3>
                <div id="di-panel-dns" class="text-xs text-slate-300 space-y-2 max-h-64 overflow-y-auto"></div>
            </div>
        </div>

        <!-- Correlation Graph + Indicators Table -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div class="bg-slate-900 border border-slate-800 rounded-2xl p-5">
                <h3 class="text-sm font-bold text-slate-100 mb-3"><i class="fa-solid fa-diagram-project text-cyan-400 mr-2"></i>Grafo de Correlación CTI</h3>
                <div id="di-correlation-graph" class="h-80 bg-slate-950 rounded-xl border border-slate-800"></div>
            </div>
            <div class="bg-slate-900 border border-slate-800 rounded-2xl p-5">
                <h3 class="text-sm font-bold text-slate-100 mb-3"><i class="fa-solid fa-list-check text-amber-400 mr-2"></i>Indicadores Relacionados</h3>
                <div class="max-h-80 overflow-y-auto">
                    <table class="w-full text-xs text-left">
                        <thead class="text-slate-400 border-b border-slate-800">
                            <tr><th class="py-2">Tipo</th><th>Valor</th><th>Fuente</th><th>Relación</th></tr>
                        </thead>
                        <tbody id="di-indicators-tbody" class="divide-y divide-slate-800/60 text-slate-300"></tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <!-- History Table -->
    <div class="bg-slate-900 border border-slate-800 rounded-2xl p-5">
        <h3 class="text-sm font-bold text-slate-100 mb-3"><i class="fa-solid fa-clock-rotate-left text-slate-400 mr-2"></i>Historial de Investigaciones (Domain Intelligence)</h3>
        <div class="overflow-x-auto">
            <table class="w-full text-xs text-left">
                <thead class="text-slate-400 border-b border-slate-800">
                    <tr><th class="py-2">ID</th><th>Dominio / Objetivo</th><th>Tipo</th><th>Origen</th><th>Riesgo</th><th>Confianza</th><th>Fecha</th><th>Acción</th></tr>
                </thead>
                <tbody id="di-history-tbody" class="divide-y divide-slate-800/60 text-slate-300"></tbody>
            </table>
        </div>
    </div>
</div>

<script>
const DI_GATEWAY_URL = 'api.php';
let diCurrentInvestigationId = null;
let diNetwork = null;
let diSeedsList = [];
let diStopBatchFlag = false;

function diGetOrgId() {
    return (typeof currentOrgId !== 'undefined' && currentOrgId) ? currentOrgId : 1;
}

function diEscape(str) {
    return String(str ?? '').replace(/[&<>"']/g, s => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[s]));
}

async function domainIntelLoadSeeds() {
    const sel = document.getElementById('di-seed-select');
    const countEl = document.getElementById('di-seeds-count');
    try {
        const resp = await fetch(`${DI_GATEWAY_URL}?action=get_seeds`);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const rows = await resp.json();
        const unique = [...new Set((Array.isArray(rows) ? rows : []).map(r => String(r.domain || '').trim().toLowerCase()).filter(Boolean))];
        diSeedsList = unique;
        if (countEl) countEl.textContent = unique.length;
        if (!unique.length) {
            sel.innerHTML = '<option value="">Sin semillas registradas (agrega dominios en Semillas / Perímetro)</option>';
            return;
        }
        sel.innerHTML = unique.map(d => `<option value="${diEscape(d)}">${diEscape(d)}</option>`).join('');
    } catch (e) {
        sel.innerHTML = '<option value="">Error cargando semillas</option>';
    }
}

async function domainIntelInvestigateSingle(target, useCache) {
    const resp = await fetch(`${DI_GATEWAY_URL}?action=domain_intel_investigate&organization_id=${diGetOrgId()}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ organization_id: diGetOrgId(), target, use_cache: useCache })
    });
    const data = await resp.json();
    if (!resp.ok) {
        throw new Error(data.detail || `Error HTTP ${resp.status}`);
    }
    return data;
}

async function domainIntelRunInvestigation() {
    const target = document.getElementById('di-seed-select').value.trim();
    const useCache = document.getElementById('di-use-cache').checked;
    const errBox = document.getElementById('di-error-banner');
    const progBox = document.getElementById('di-progress-bar');
    const progText = document.getElementById('di-progress-text');
    errBox.classList.add('hidden');

    if (!target) {
        errBox.textContent = 'Selecciona una semilla autorizada para investigar.';
        errBox.classList.remove('hidden');
        return;
    }

    progText.textContent = `Investigando semilla ${target} (RDAP/WHOIS, VirusTotal, OTX, DNS, crt.sh y CTI)...`;
    progBox.classList.remove('hidden');
    document.getElementById('di-run-btn').disabled = true;
    document.getElementById('di-run-all-btn').disabled = true;

    try {
        const data = await domainIntelInvestigateSingle(target, useCache);
        domainIntelRenderInvestigation(data);
        domainIntelLoadHistory();
    } catch (err) {
        errBox.textContent = `Error: ${err.message}`;
        errBox.classList.remove('hidden');
    } finally {
        progBox.classList.add('hidden');
        document.getElementById('di-run-btn').disabled = false;
        document.getElementById('di-run-all-btn').disabled = false;
    }
}

function domainIntelStopBatch() {
    diStopBatchFlag = true;
}

async function domainIntelRunAllSeeds() {
    if (!diSeedsList.length) await domainIntelLoadSeeds();
    const errBox = document.getElementById('di-error-banner');
    const progBox = document.getElementById('di-progress-bar');
    const progText = document.getElementById('di-progress-text');
    const stopBtn = document.getElementById('di-stop-all-btn');
    errBox.classList.add('hidden');

    if (!diSeedsList.length) {
        errBox.textContent = 'No hay semillas registradas para investigar.';
        errBox.classList.remove('hidden');
        return;
    }

    const useCache = document.getElementById('di-use-cache').checked;
    diStopBatchFlag = false;
    progBox.classList.remove('hidden');
    stopBtn.classList.remove('hidden');
    document.getElementById('di-run-btn').disabled = true;
    document.getElementById('di-run-all-btn').disabled = true;

    let completed = 0;
    const errors = [];
    for (let i = 0; i < diSeedsList.length; i++) {
        if (diStopBatchFlag) break;
        const domain = diSeedsList[i];
        progText.textContent = `Investigando lote de semillas (${i + 1}/${diSeedsList.length}): ${domain}...`;
        try {
            const data = await domainIntelInvestigateSingle(domain, useCache);
            domainIntelRenderInvestigation(data);
            completed++;
        } catch (err) {
            errors.push(`${domain}: ${err.message}`);
        }
    }

    await domainIntelLoadHistory();
    progBox.classList.add('hidden');
    stopBtn.classList.add('hidden');
    document.getElementById('di-run-btn').disabled = false;
    document.getElementById('di-run-all-btn').disabled = false;

    if (errors.length) {
        errBox.textContent = `Completadas ${completed}/${diSeedsList.length}. Errores: ${errors.slice(0, 3).join(' | ')}`;
        errBox.classList.remove('hidden');
    }
}

function domainIntelRenderInvestigation(inv) {
    diCurrentInvestigationId = inv.id;
    document.getElementById('di-results-container').classList.remove('hidden');

    document.getElementById('di-risk-tier').textContent = inv.risk_tier;
    document.getElementById('di-target-meta').textContent = `${inv.normalized_domain} · ${inv.input_type} · ${inv.trigger_source}`;
    document.getElementById('di-ext-score').textContent = inv.external_reputation_score !== null ? `${inv.external_reputation_score} / 100` : 'N/A';
    document.getElementById('di-tech-score').textContent = inv.technical_risk_score !== null ? `${inv.technical_risk_score}` : 'Sin activo vinculado';
    document.getElementById('di-conf-score').textContent = `${Math.round((inv.confidence_score || 0) * 100)}%`;
    document.getElementById('di-risk-explanation').textContent = inv.risk_explanation || '';

    const evDiv = document.getElementById('di-evidences-list');
    const neg = (inv.summary?.negative_evidences || []).map(e => `<div class="text-rose-300">▲ [${diEscape(e.source)}] ${diEscape(e.detail)}</div>`).join('');
    const pos = (inv.summary?.positive_evidences || []).map(e => `<div class="text-emerald-300">● [${diEscape(e.source)}] ${diEscape(e.detail)}</div>`).join('');
    evDiv.innerHTML = neg + pos || '<div class="text-slate-500">Sin evidencias registradas.</div>';

    const limDiv = document.getElementById('di-limitations-list');
    limDiv.innerHTML = (inv.limitations || []).map(l => `<div>⚠ ${diEscape(l)}</div>`).join('');

    const provBadges = document.getElementById('di-provider-badges');
    provBadges.innerHTML = (inv.provider_results || []).map(p => {
        const ok = p.status === 'SUCCESS';
        const cls = ok ? 'border-emerald-800 bg-emerald-950/40 text-emerald-300' : 'border-slate-700 bg-slate-950 text-slate-300';
        return `<div class="p-2 rounded-lg border ${cls} flex justify-between items-center"><span class="font-mono">${diEscape(p.provider_name)}</span><span class="text-[10px]">${diEscape(p.status)}</span></div>`;
    }).join('');

    const byProv = {};
    (inv.provider_results || []).forEach(p => byProv[p.provider_name] = p);

    // RDAP / WHOIS
    const rdap = byProv.rdap_whois;
    const rdapEl = document.getElementById('di-panel-rdap');
    if (rdap && rdap.status === 'SUCCESS') {
        const d = rdap.data || {};
        rdapEl.innerHTML = `
            <div><strong>Protocolo:</strong> ${diEscape(d.source_protocol)} | <strong>Registrador:</strong> ${diEscape(d.registrar)}</div>
            <div><strong>Creación:</strong> ${diEscape(d.created_at || 'N/D')} | <strong>Expiración:</strong> ${diEscape(d.expires_at || 'N/D')}</div>
            <div><strong>Organización:</strong> ${diEscape(d.registrant_org)} | <strong>País:</strong> ${diEscape(d.country)}</div>
            <div><strong>Nameservers:</strong> ${diEscape((d.nameservers || []).join(', ') || 'N/D')}</div>
            <div><strong>Abuse:</strong> ${diEscape((d.abuse_contacts || []).join(', ') || 'N/D')}</div>`;
    } else {
        rdapEl.innerHTML = `<span class="text-slate-400">Estado: ${diEscape(rdap?.status || 'NO_CONSULTADO')} — ${diEscape(rdap?.error_message || '')}</span>`;
    }

    // VirusTotal
    const vt = byProv.virustotal;
    const vtEl = document.getElementById('di-panel-vt');
    if (vt && vt.status === 'SUCCESS') {
        const s = vt.data?.stats || {};
        vtEl.innerHTML = `
            <div><strong>Reputación:</strong> ${diEscape(vt.data?.reputation)} | <strong>Último análisis:</strong> ${diEscape(vt.data?.last_analysis_date || 'N/D')}</div>
            <div class="flex gap-3 font-mono mt-1">
                <span class="text-rose-400">Malicious: ${s.malicious ?? 0}</span>
                <span class="text-amber-400">Suspicious: ${s.suspicious ?? 0}</span>
                <span class="text-emerald-400">Harmless: ${s.harmless ?? 0}</span>
                <span class="text-slate-400">Undetected: ${s.undetected ?? 0}</span>
            </div>`;
    } else {
        vtEl.innerHTML = `<span class="text-slate-400">Estado: ${diEscape(vt?.status || 'NO_CONSULTADO')} — ${diEscape(vt?.error_message || '')}</span>`;
    }

    // OTX
    const otx = byProv.otx;
    const otxEl = document.getElementById('di-panel-otx');
    if (otx && otx.status === 'SUCCESS') {
        const pulses = (otx.data?.pulses || []).slice(0, 8).map(p => `<div class="p-2 rounded bg-slate-950 border border-slate-800"><div class="font-semibold text-purple-300">${diEscape(p.name)}</div><div class="text-[11px] text-slate-400">${diEscape(p.description)}</div></div>`).join('');
        otxEl.innerHTML = `<div><strong>Pulse Count:</strong> ${otx.data?.pulse_count ?? 0} | <strong>Malware:</strong> ${diEscape((otx.data?.malware_families || []).join(', ') || 'Ninguna')}</div>${pulses}`;
    } else {
        otxEl.innerHTML = `<span class="text-slate-400">Estado: ${diEscape(otx?.status || 'NO_CONSULTADO')} — ${diEscape(otx?.error_message || '')}</span>`;
    }

    // DNS & CT
    const dns = byProv.dns;
    const ct = byProv.crt_sh;
    const dnsEl = document.getElementById('di-panel-dns');
    const dnsData = dns?.data || {};
    const ctData = ct?.data || {};
    dnsEl.innerHTML = `
        <div><strong>A:</strong> ${diEscape((dnsData.A || []).join(', ') || 'N/D')} | <strong>AAAA:</strong> ${diEscape((dnsData.AAAA || []).join(', ') || 'N/D')}</div>
        <div><strong>NS:</strong> ${diEscape((dnsData.NS || []).join(', ') || 'N/D')}</div>
        <div><strong>MX:</strong> ${diEscape((dnsData.MX || []).map(m => m.host || m).join(', ') || 'N/D')}</div>
        <div><strong>crt.sh Subdominios (${(ctData.subdomains || []).length}):</strong> ${diEscape((ctData.subdomains || []).slice(0, 10).join(', ') || 'N/D')}</div>`;

    // Indicators Table
    const tbody = document.getElementById('di-indicators-tbody');
    tbody.innerHTML = (inv.indicators || []).map(i => `
        <tr>
            <td class="py-1.5 font-mono text-cyan-300">${diEscape(i.indicator_type)}</td>
            <td class="font-mono">${diEscape(i.indicator_value)}</td>
            <td>${diEscape(i.source)}</td>
            <td>${diEscape(i.relationship_type)} (${i.confidence}%)</td>
        </tr>`).join('') || '<tr><td colspan="4" class="py-3 text-slate-500">Sin indicadores relacionados.</td></tr>';

    // Graph
    const graphBox = document.getElementById('di-correlation-graph');
    if (typeof vis !== 'undefined' && inv.correlation_graph) {
        const nodes = new vis.DataSet((inv.correlation_graph.nodes || []).map(n => ({ id: n.id, label: n.label, group: n.type })));
        const edges = new vis.DataSet((inv.correlation_graph.edges || []).map(e => ({ from: e.from, to: e.to, label: e.relationship, arrows: 'to' })));
        diNetwork = new vis.Network(graphBox, { nodes, edges }, { physics: { stabilization: true }, nodes: { font: { color: '#e2e8f0', size: 11 } }, edges: { font: { color: '#94a3b8', size: 9 } } });
    }
}

async function domainIntelLoadHistory() {
    try {
        const resp = await fetch(`${DI_GATEWAY_URL}?action=domain_intel_list&organization_id=${diGetOrgId()}&limit=25`);
        if (!resp.ok) return;
        const rows = await resp.json();
        const tbody = document.getElementById('di-history-tbody');
        tbody.innerHTML = rows.map(r => `
            <tr>
                <td class="py-2 font-mono">#${r.id}</td>
                <td class="font-mono text-cyan-300">${diEscape(r.normalized_domain)}</td>
                <td>${diEscape(r.input_type)}</td>
                <td>${diEscape(r.trigger_source)}</td>
                <td>${diEscape(r.risk_tier)}</td>
                <td>${Math.round((r.confidence_score || 0) * 100)}%</td>
                <td>${diEscape(r.created_at)}</td>
                <td><button onclick="domainIntelOpenInvestigation(${r.id})" class="text-cyan-400 hover:underline">Ver</button></td>
            </tr>`).join('') || '<tr><td colspan="8" class="py-3 text-slate-500">Sin investigaciones registradas.</td></tr>';
    } catch (_) {}
}

async function domainIntelOpenInvestigation(id) {
    const resp = await fetch(`${DI_GATEWAY_URL}?action=domain_intel_get&id=${id}&organization_id=${diGetOrgId()}`);
    if (resp.ok) {
        const data = await resp.json();
        domainIntelRenderInvestigation(data);
    }
}

function domainIntelExport(fmt) {
    if (!diCurrentInvestigationId) return;
    window.open(`${DI_GATEWAY_URL}?action=domain_intel_export&id=${diCurrentInvestigationId}&organization_id=${diGetOrgId()}&format=${fmt}`, '_blank');
}

function domainIntelToggleKeysModal() {
    const el = document.getElementById('di-keys-panel');
    el.classList.toggle('hidden');
    if (!el.classList.contains('hidden')) domainIntelLoadCredentials();
}

async function domainIntelLoadCredentials() {
    const resp = await fetch(`${DI_GATEWAY_URL}?action=domain_intel_credentials_get&organization_id=${diGetOrgId()}`);
    if (!resp.ok) return;
    const rows = await resp.json();
    document.getElementById('di-keys-status-list').innerHTML = rows.map(r => `
        <div class="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex justify-between">
            <span class="font-mono text-slate-200">${diEscape(r.provider_name)}</span>
            <span class="${r.is_configured ? 'text-emerald-400' : 'text-slate-500'}">${r.is_configured ? diEscape(r.masked_hint) : 'No configurada'}</span>
        </div>`).join('');
}

async function domainIntelSaveCredential() {
    const provider_name = document.getElementById('di-cred-provider').value;
    const api_key = document.getElementById('di-cred-key').value.trim();
    if (!api_key) return;
    const resp = await fetch(`${DI_GATEWAY_URL}?action=domain_intel_credentials_set&organization_id=${diGetOrgId()}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ organization_id: diGetOrgId(), provider_name, api_key, is_enabled: true })
    });
    if (resp.ok) {
        document.getElementById('di-cred-key').value = '';
        domainIntelLoadCredentials();
    }
}
</script>
