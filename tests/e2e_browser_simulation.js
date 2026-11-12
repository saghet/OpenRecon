const elements = {};
function mockElement(id) {
    return {
        id,
        innerText: '--',
        innerHTML: 'Cargando...',
        value: '',
        classList: {
            add: (c) => {},
            remove: (c) => {},
            toggle: (c, v) => {}
        },
        querySelectorAll: () => [],
        appendChild: () => {}
    };
}

global.document = {
    readyState: 'complete',
    getElementById: (id) => {
        if (!elements[id]) {
            elements[id] = mockElement(id);
        }
        return elements[id];
    },
    querySelectorAll: (sel) => [],
    addEventListener: () => {}
};

global.window = {
    open: () => {}
};

global.alert = (msg) => {
    console.log('[ALERT POPUP]:', msg);
};

// Real HTTP fetch via http module
const http = require('http');
global.fetch = async (url, opts) => {
    return new Promise((resolve, reject) => {
        const fullUrl = url.startsWith('http') ? url : `http://localhost/FortiRecon/web_dashboard/${url}`;
        http.get(fullUrl, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                resolve({
                    status: res.statusCode,
                    json: async () => JSON.parse(data)
                });
            });
        }).on('error', reject);
    });
};

const fs = require('fs');
const code = fs.readFileSync('tests/darkintel_test_syntax.js', 'utf8');

eval(code);

async function runAudit() {
    console.log("=== EXECUTING AUDIT OF ALL DARK INTEL CONTROLLER FUNCTIONS ===");
    
    // 1. Overview
    console.log("[1] Testing darkIntelLoadOverview...");
    await darkIntelLoadOverview();
    console.log("  Stat Sources:", elements['darkintel-stat-sources']?.innerText);
    console.log("  Stat Ransomware:", elements['darkintel-stat-ransomware']?.innerText);
    console.log("  Stat Leaks:", elements['darkintel-stat-leaks']?.innerText);
    console.log("  Stat Actors:", elements['darkintel-stat-actors']?.innerText);
    console.log("  Ransom Feed Length:", elements['darkintel-overview-ransomware-feed']?.innerHTML?.length);
    console.log("  Leaks Feed Length:", elements['darkintel-overview-leaks-feed']?.innerHTML?.length);

    // 2. Search
    console.log("[2] Testing darkIntelExecuteSearch for fdn.com.co...");
    elements['darkintel-search-input'] = { value: 'fdn.com.co' };
    await darkIntelExecuteSearch();
    console.log("  Search container HTML snippet:", elements['darkintel-search-results-container']?.innerHTML?.substring(0, 150));

    // 3. Onion Sources
    console.log("[3] Testing darkIntelLoadSources...");
    await darkIntelLoadSources();
    console.log("  Sources Table Body rows len:", elements['darkintel-sources-table-body']?.innerHTML?.length);

    // 4. Leaks
    console.log("[4] Testing darkIntelLoadLeaks...");
    await darkIntelLoadLeaks();
    console.log("  Leaks Table Body rows len:", elements['darkintel-leaks-table-body']?.innerHTML?.length);

    // 5. Ransomware
    console.log("[5] Testing darkIntelLoadRansomware...");
    await darkIntelLoadRansomware();
    console.log("  Ransomware Table Body rows len:", elements['darkintel-ransomware-table-body']?.innerHTML?.length);

    // 6. Actors
    console.log("[6] Testing darkIntelLoadActors...");
    await darkIntelLoadActors();
    console.log("  Actors Grid HTML len:", elements['darkintel-actors-grid']?.innerHTML?.length);

    // 7. IOCs
    console.log("[7] Testing darkIntelLoadIOCs...");
    await darkIntelLoadIOCs();
    console.log("  IOCs Table Body rows len:", elements['darkintel-iocs-table-body']?.innerHTML?.length);

    // 8. Exposure Assessment
    console.log("[8] Testing darkIntelRunExposureAssessment for fdn.com.co...");
    elements['darkintel-exposure-seed-select'] = { value: 'fdn.com.co' };
    await darkIntelRunExposureAssessment();
    console.log("  Exposure result box HTML snippet:", elements['darkintel-exposure-result-box']?.innerHTML?.substring(0, 200));

    // 9. Investigations
    console.log("[9] Testing darkIntelLoadInvestigations...");
    await darkIntelLoadInvestigations();
    console.log("  Investigations List HTML len:", elements['darkintel-investigations-list']?.innerHTML?.length);

    // 10. Vault
    console.log("[10] Testing darkIntelLoadVault...");
    await darkIntelLoadVault();
    console.log("  Vault Display HTML len:", elements['darkintel-vault-inspect-display']?.innerHTML?.length);

    // 11. Sync
    console.log("[11] Testing darkIntelSyncRansomwareFeed...");
    await darkIntelSyncRansomwareFeed();

    console.log("=== ALL CONTROLLER FUNCTIONS TESTED SUCCESSFULLY WITH ZERO CRASHES ===");
}

runAudit().catch(err => {
    console.error("AUDIT FAILED WITH ERROR:", err);
    process.exit(1);
});
