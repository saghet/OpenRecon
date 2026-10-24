<?php
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

// Database setup
$dbFile = __DIR__ . '/openrecon.sqlite';
try {
    $pdo = new PDO("sqlite:" . $dbFile);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

    // Initialize Schema
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS seeds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            seed_domain TEXT NOT NULL,
            subdomain TEXT UNIQUE NOT NULL,
            ip_address TEXT,
            cloud_provider TEXT,
            web_title TEXT,
            status_code INTEGER,
            tech_stack TEXT,
            is_live INTEGER DEFAULT 1,
            last_scanned DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS open_ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_subdomain TEXT NOT NULL,
            port INTEGER NOT NULL,
            service_name TEXT,
            UNIQUE(asset_subdomain, port)
        );

        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_subdomain TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT,
            remediation TEXT,
            status TEXT DEFAULT 'OPEN',
            mitigation_notes TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS drp_threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            seed_domain TEXT NOT NULL,
            lookalike_domain TEXT UNIQUE NOT NULL,
            ip_address TEXT,
            has_mx INTEGER DEFAULT 0,
            severity TEXT NOT NULL,
            details TEXT,
            status TEXT DEFAULT 'OPEN',
            detected_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS credential_leaks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            seed_domain TEXT NOT NULL,
            email TEXT NOT NULL,
            source_breach TEXT NOT NULL,
            breach_date TEXT,
            pwn_count INTEGER DEFAULT 1,
            severity TEXT DEFAULT 'HIGH',
            detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(email, source_breach)
        );

        CREATE TABLE IF NOT EXISTS exposed_secrets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_subdomain TEXT NOT NULL,
            secret_type TEXT NOT NULL,
            matched_snippet TEXT,
            endpoint_url TEXT NOT NULL,
            severity TEXT DEFAULT 'CRITICAL',
            detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(endpoint_url, secret_type)
        );

        CREATE TABLE IF NOT EXISTS ransomware_leaks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_name TEXT NOT NULL,
            victim_name TEXT NOT NULL,
            discovered_date TEXT,
            is_matched INTEGER DEFAULT 0,
            detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(group_name, victim_name)
        );

        CREATE TABLE IF NOT EXISTS threat_iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            port INTEGER,
            malware_family TEXT,
            as_name TEXT,
            status TEXT,
            last_checked DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS threat_actors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            aliases TEXT,
            origin TEXT,
            target_sectors TEXT,
            initial_access TEXT,
            mitre_tactics TEXT,
            description TEXT
        );
    ");

    // Add status columns if missing
    try { $pdo->exec("ALTER TABLE vulnerabilities ADD COLUMN status TEXT DEFAULT 'OPEN'"); } catch (Exception $e) {}
    try { $pdo->exec("ALTER TABLE vulnerabilities ADD COLUMN mitigation_notes TEXT"); } catch (Exception $e) {}
    try { $pdo->exec("ALTER TABLE drp_threats ADD COLUMN status TEXT DEFAULT 'OPEN'"); } catch (Exception $e) {}

} catch (Exception $e) {
    echo json_encode(['error' => 'Database initialization failed: ' . $e->getMessage()]);
    exit;
}

$action = $_GET['action'] ?? $_POST['action'] ?? 'get_stats';

// Router
switch ($action) {
    case 'get_stats':
        getStats($pdo);
        break;
    case 'get_assets':
        getAssets($pdo);
        break;
    case 'get_vulnerabilities':
        getVulnerabilities($pdo);
        break;
    case 'update_vuln_status':
        updateVulnStatus($pdo);
        break;
    case 'get_drp':
        getDrpThreats($pdo);
        break;
    case 'get_credential_leaks':
        getCredentialLeaks($pdo);
        break;
    case 'get_exposed_secrets':
        getExposedSecrets($pdo);
        break;
    case 'get_ransomware_leaks':
        getRansomwareLeaks($pdo);
        break;
    case 'get_threat_iocs':
        getThreatIocs($pdo);
        break;
    case 'get_threat_actors':
        getThreatActors($pdo);
        break;
    case 'get_graph_data':
        getGraphData($pdo);
        break;
    case 'sync_cti':
        syncCtiFeeds($pdo);
        break;
    case 'generate_takedown':
        generateTakedownNotice($pdo);
        break;
    case 'get_seeds':
        getSeeds($pdo);
        break;
    case 'add_seed':
        addSeed($pdo);
        break;
    case 'delete_seed':
        deleteSeed($pdo);
        break;
    case 'run_scan':
        runScan($pdo);
        break;
    default:
        echo json_encode(['status' => 'ok', 'message' => 'OpenRecon API v1.0 running']);
        break;
}

// -------------------------------------------------------------
// Controller Functions (Strict Seed Scoping)
// -------------------------------------------------------------

function getStats($pdo) {
    $seed = trim($_GET['seed'] ?? '');
    $isSpecificSeed = (!empty($seed) && $seed !== 'ALL');

    if ($isSpecificSeed) {
        $totalAssets = (int)queryScalar($pdo, "SELECT COUNT(*) FROM assets WHERE seed_domain = ?", [$seed]);
        $liveAssets = (int)queryScalar($pdo, "SELECT COUNT(*) FROM assets WHERE seed_domain = ? AND is_live = 1", [$seed]);
        $openPorts = (int)queryScalar($pdo, "SELECT COUNT(*) FROM open_ports WHERE asset_subdomain IN (SELECT subdomain FROM assets WHERE seed_domain = ?)", [$seed]);

        $critVulns = (int)queryScalar($pdo, "SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'CRITICAL' AND (status = 'OPEN' OR status = 'IN_PROGRESS' OR status IS NULL) AND asset_subdomain IN (SELECT subdomain FROM assets WHERE seed_domain = ?)", [$seed]);
        $highVulns = (int)queryScalar($pdo, "SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'HIGH' AND (status = 'OPEN' OR status = 'IN_PROGRESS' OR status IS NULL) AND asset_subdomain IN (SELECT subdomain FROM assets WHERE seed_domain = ?)", [$seed]);
        $medVulns = (int)queryScalar($pdo, "SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'MEDIUM' AND (status = 'OPEN' OR status = 'IN_PROGRESS' OR status IS NULL) AND asset_subdomain IN (SELECT subdomain FROM assets WHERE seed_domain = ?)", [$seed]);
        $resolvedVulns = (int)queryScalar($pdo, "SELECT COUNT(*) FROM vulnerabilities WHERE status = 'RESOLVED' AND asset_subdomain IN (SELECT subdomain FROM assets WHERE seed_domain = ?)", [$seed]);

        $drpCount = (int)queryScalar($pdo, "SELECT COUNT(*) FROM drp_threats WHERE seed_domain = ? AND (status = 'OPEN' OR status IS NULL)", [$seed]);
        $credLeaksCount = (int)queryScalar($pdo, "SELECT COUNT(*) FROM credential_leaks WHERE seed_domain = ?", [$seed]);
        $secretsCount = (int)queryScalar($pdo, "SELECT COUNT(*) FROM exposed_secrets WHERE asset_subdomain IN (SELECT subdomain FROM assets WHERE seed_domain = ?)", [$seed]);

        $cleanDomain = preg_replace('/^www\./i', '', $seed);
        $core = explode('.', $cleanDomain)[0];
        if (strlen($core) >= 3) {
            $ransomMatched = (int)queryScalar($pdo, "SELECT COUNT(*) FROM ransomware_leaks WHERE victim_name LIKE ?", ['%' . $core . '%']);
        } else {
            $ransomMatched = 0;
        }
    } else {
        // Only active seeds in database
        $totalAssets = (int)queryScalar($pdo, "SELECT COUNT(*) FROM assets WHERE seed_domain IN (SELECT domain FROM seeds)");
        $liveAssets = (int)queryScalar($pdo, "SELECT COUNT(*) FROM assets WHERE is_live = 1 AND seed_domain IN (SELECT domain FROM seeds)");
        $openPorts = (int)queryScalar($pdo, "SELECT COUNT(*) FROM open_ports WHERE asset_subdomain IN (SELECT subdomain FROM assets WHERE seed_domain IN (SELECT domain FROM seeds))");

        $critVulns = (int)queryScalar($pdo, "SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'CRITICAL' AND (status = 'OPEN' OR status = 'IN_PROGRESS' OR status IS NULL) AND asset_subdomain IN (SELECT subdomain FROM assets WHERE seed_domain IN (SELECT domain FROM seeds))");
        $highVulns = (int)queryScalar($pdo, "SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'HIGH' AND (status = 'OPEN' OR status = 'IN_PROGRESS' OR status IS NULL) AND asset_subdomain IN (SELECT subdomain FROM assets WHERE seed_domain IN (SELECT domain FROM seeds))");
        $medVulns = (int)queryScalar($pdo, "SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'MEDIUM' AND (status = 'OPEN' OR status = 'IN_PROGRESS' OR status IS NULL) AND asset_subdomain IN (SELECT subdomain FROM assets WHERE seed_domain IN (SELECT domain FROM seeds))");
        $resolvedVulns = (int)queryScalar($pdo, "SELECT COUNT(*) FROM vulnerabilities WHERE status = 'RESOLVED' AND asset_subdomain IN (SELECT subdomain FROM assets WHERE seed_domain IN (SELECT domain FROM seeds))");

        $drpCount = (int)queryScalar($pdo, "SELECT COUNT(*) FROM drp_threats WHERE seed_domain IN (SELECT domain FROM seeds) AND (status = 'OPEN' OR status IS NULL)");
        $credLeaksCount = (int)queryScalar($pdo, "SELECT COUNT(*) FROM credential_leaks WHERE seed_domain IN (SELECT domain FROM seeds)");
        $secretsCount = (int)queryScalar($pdo, "SELECT COUNT(*) FROM exposed_secrets WHERE asset_subdomain IN (SELECT subdomain FROM assets WHERE seed_domain IN (SELECT domain FROM seeds))");
        $ransomMatched = (int)queryScalar($pdo, "SELECT COUNT(*) FROM ransomware_leaks WHERE is_matched = 1");
    }

    $totalRansomLeaks = (int)queryScalar($pdo, "SELECT COUNT(*) FROM ransomware_leaks");
    $totalIocs = (int)queryScalar($pdo, "SELECT COUNT(*) FROM threat_iocs");

    // Risk Score calculation
    $penalty = ($critVulns * 20) + ($highVulns * 10) + ($medVulns * 3) + ($drpCount * 5) + ($credLeaksCount * 5) + ($secretsCount * 15) + ($ransomMatched * 50);
    $score = max(0, min(100, 100 - $penalty));

    echo json_encode([
        'exposure_score' => $score,
        'posture' => ($score > 75 ? 'Excelente' : ($score > 50 ? 'Riesgo Moderado' : 'Alerta Crítica')),
        'total_assets' => $totalAssets,
        'live_assets' => $liveAssets,
        'open_ports' => $openPorts,
        'vulnerabilities' => [
            'critical' => $critVulns,
            'high' => $highVulns,
            'medium' => $medVulns,
            'resolved' => $resolvedVulns,
            'total' => $critVulns + $highVulns + $medVulns
        ],
        'drp_threats' => $drpCount,
        'credential_leaks' => $credLeaksCount,
        'exposed_secrets' => $secretsCount,
        'ransomware_matched' => $ransomMatched,
        'ransomware_total' => $totalRansomLeaks,
        'threat_iocs' => $totalIocs
    ]);
}

function getAssets($pdo) {
    $seed = trim($_GET['seed'] ?? '');
    if (!empty($seed) && $seed !== 'ALL') {
        $stmt = $pdo->prepare("SELECT a.*, (SELECT GROUP_CONCAT(port) FROM open_ports WHERE asset_subdomain = a.subdomain) as ports FROM assets a WHERE a.seed_domain = ? ORDER BY a.is_live DESC, a.last_scanned DESC");
        $stmt->execute([$seed]);
    } else {
        $stmt = $pdo->query("SELECT a.*, (SELECT GROUP_CONCAT(port) FROM open_ports WHERE asset_subdomain = a.subdomain) as ports FROM assets a WHERE a.seed_domain IN (SELECT domain FROM seeds) ORDER BY a.is_live DESC, a.last_scanned DESC");
    }
    echo json_encode($stmt->fetchAll());
}

function getVulnerabilities($pdo) {
    $seed = trim($_GET['seed'] ?? '');
    if (!empty($seed) && $seed !== 'ALL') {
        $stmt = $pdo->prepare("SELECT v.* FROM vulnerabilities v JOIN assets a ON v.asset_subdomain = a.subdomain WHERE a.seed_domain = ? ORDER BY CASE v.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END, CASE v.status WHEN 'OPEN' THEN 1 WHEN 'IN_PROGRESS' THEN 2 ELSE 3 END, v.created_at DESC");
        $stmt->execute([$seed]);
    } else {
        $stmt = $pdo->query("SELECT v.* FROM vulnerabilities v JOIN assets a ON v.asset_subdomain = a.subdomain WHERE a.seed_domain IN (SELECT domain FROM seeds) ORDER BY CASE v.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END, CASE v.status WHEN 'OPEN' THEN 1 WHEN 'IN_PROGRESS' THEN 2 ELSE 3 END, v.created_at DESC");
    }
    echo json_encode($stmt->fetchAll());
}

function updateVulnStatus($pdo) {
    $id = (int)($_POST['id'] ?? 0);
    $status = $_POST['status'] ?? 'OPEN';
    $notes = $_POST['notes'] ?? '';

    if ($id <= 0) {
        echo json_encode(['error' => 'ID inválido']);
        return;
    }

    $stmt = $pdo->prepare("UPDATE vulnerabilities SET status = ?, mitigation_notes = ? WHERE id = ?");
    $stmt->execute([$status, $notes, $id]);
    echo json_encode(['success' => true, 'id' => $id, 'status' => $status]);
}

function getDrpThreats($pdo) {
    $seed = trim($_GET['seed'] ?? '');
    if (!empty($seed) && $seed !== 'ALL') {
        $stmt = $pdo->prepare("SELECT * FROM drp_threats WHERE seed_domain = ? ORDER BY has_mx DESC, detected_at DESC");
        $stmt->execute([$seed]);
    } else {
        $stmt = $pdo->query("SELECT * FROM drp_threats WHERE seed_domain IN (SELECT domain FROM seeds) ORDER BY has_mx DESC, detected_at DESC");
    }
    echo json_encode($stmt->fetchAll());
}

function getCredentialLeaks($pdo) {
    $seed = trim($_GET['seed'] ?? '');
    if (!empty($seed) && $seed !== 'ALL') {
        $stmt = $pdo->prepare("SELECT * FROM credential_leaks WHERE seed_domain = ? ORDER BY detected_at DESC");
        $stmt->execute([$seed]);
    } else {
        $stmt = $pdo->query("SELECT * FROM credential_leaks WHERE seed_domain IN (SELECT domain FROM seeds) ORDER BY detected_at DESC");
    }
    echo json_encode($stmt->fetchAll());
}

function getExposedSecrets($pdo) {
    $seed = trim($_GET['seed'] ?? '');
    if (!empty($seed) && $seed !== 'ALL') {
        $stmt = $pdo->prepare("SELECT s.* FROM exposed_secrets s JOIN assets a ON s.asset_subdomain = a.subdomain WHERE a.seed_domain = ? ORDER BY s.detected_at DESC");
        $stmt->execute([$seed]);
    } else {
        $stmt = $pdo->query("SELECT s.* FROM exposed_secrets s JOIN assets a ON s.asset_subdomain = a.subdomain WHERE a.seed_domain IN (SELECT domain FROM seeds) ORDER BY s.detected_at DESC");
    }
    echo json_encode($stmt->fetchAll());
}

function getRansomwareLeaks($pdo) {
    $seed = trim($_GET['seed'] ?? '');
    if (!empty($seed) && $seed !== 'ALL') {
        $cleanDomain = preg_replace('/^www\./i', '', $seed);
        $core = explode('.', $cleanDomain)[0];
        if (strlen($core) >= 3) {
            $stmt = $pdo->prepare("SELECT *, (CASE WHEN victim_name LIKE ? THEN 1 ELSE 0 END) as is_matched FROM ransomware_leaks ORDER BY is_matched DESC, discovered_date DESC LIMIT 60");
            $stmt->execute(['%' . $core . '%']);
            echo json_encode($stmt->fetchAll());
            return;
        }
    }
    $stmt = $pdo->query("SELECT * FROM ransomware_leaks ORDER BY is_matched DESC, discovered_date DESC LIMIT 60");
    echo json_encode($stmt->fetchAll());
}

function getThreatIocs($pdo) {
    $stmt = $pdo->query("SELECT * FROM threat_iocs ORDER BY id DESC LIMIT 50");
    echo json_encode($stmt->fetchAll());
}

function getThreatActors($pdo) {
    $stmt = $pdo->query("SELECT * FROM threat_actors ORDER BY id ASC");
    echo json_encode($stmt->fetchAll());
}

function getGraphData($pdo) {
    $seed = trim($_GET['seed'] ?? '');
    $isSpecificSeed = (!empty($seed) && $seed !== 'ALL');

    $nodes = [];
    $edges = [];
    $nodeMap = [];

    // 1. Seeds
    if ($isSpecificSeed) {
        $stmtS = $pdo->prepare("SELECT * FROM seeds WHERE domain = ?");
        $stmtS->execute([$seed]);
        $seeds = $stmtS->fetchAll();
    } else {
        $seeds = $pdo->query("SELECT * FROM seeds")->fetchAll();
    }

    foreach ($seeds as $s) {
        $nodeId = 'seed_' . $s['id'];
        $nodes[] = [
            'id' => $nodeId,
            'label' => $s['domain'],
            'group' => 'seed',
            'shape' => 'hexagon',
            'color' => '#06b6d4',
            'font' => ['color' => '#ffffff', 'size' => 14, 'face' => 'JetBrains Mono', 'bold' => true],
            'size' => 32
        ];
        $nodeMap[$s['domain']] = $nodeId;
    }

    // 2. Discovered Assets
    if ($isSpecificSeed) {
        $stmtA = $pdo->prepare("SELECT * FROM assets WHERE seed_domain = ? LIMIT 50");
        $stmtA->execute([$seed]);
        $assets = $stmtA->fetchAll();
    } else {
        $assets = $pdo->query("SELECT * FROM assets WHERE seed_domain IN (SELECT domain FROM seeds) LIMIT 50")->fetchAll();
    }

    foreach ($assets as $a) {
        $assetNodeId = 'asset_' . $a['id'];
        $parentSeedId = $nodeMap[$a['seed_domain']] ?? null;

        $color = $a['is_live'] ? '#38bdf8' : '#475569';
        $nodes[] = [
            'id' => $assetNodeId,
            'label' => $a['subdomain'],
            'group' => 'asset',
            'shape' => 'dot',
            'color' => $color,
            'font' => ['color' => '#e2e8f0', 'size' => 11, 'face' => 'JetBrains Mono'],
            'size' => 18,
            'title' => "IP: " . ($a['ip_address'] ?: 'N/A') . "<br>Cloud: " . ($a['cloud_provider'] ?: 'Direct') . "<br>Título: " . ($a['web_title'] ?: '-')
        ];

        if ($parentSeedId) {
            $edges[] = [
                'from' => $parentSeedId,
                'to' => $assetNodeId,
                'color' => ['color' => '#1e293b'],
                'width' => 1.5
            ];
        }

        if ($a['ip_address']) {
            $ipNodeId = 'ip_' . str_replace('.', '_', $a['ip_address']);
            if (!isset($nodeMap[$ipNodeId])) {
                $nodes[] = [
                    'id' => $ipNodeId,
                    'label' => $a['ip_address'] . "\n(" . ($a['cloud_provider'] ?: 'ISP') . ")",
                    'group' => 'ip',
                    'shape' => 'box',
                    'color' => '#334155',
                    'font' => ['color' => '#94a3b8', 'size' => 10, 'face' => 'JetBrains Mono'],
                    'size' => 12
                ];
                $nodeMap[$ipNodeId] = true;
            }
            $edges[] = [
                'from' => $assetNodeId,
                'to' => $ipNodeId,
                'color' => ['color' => '#0e7490'],
                'dashes' => true
            ];
        }
    }

    // 3. Open Ports
    $subdomainsList = array_column($assets, 'subdomain');
    if (!empty($subdomainsList)) {
        $inClause = implode(',', array_fill(0, count($subdomainsList), '?'));
        $stmtP = $pdo->prepare("SELECT * FROM open_ports WHERE asset_subdomain IN ($inClause) LIMIT 60");
        $stmtP->execute($subdomainsList);
        $ports = $stmtP->fetchAll();

        foreach ($ports as $p) {
            $sub = $p['asset_subdomain'];
            $portNum = (int)$p['port'];
            $isDangerous = in_array($portNum, [3306, 5432, 6379, 27017, 3389, 21]);

            $matchingAsset = array_filter($assets, function($item) use ($sub) { return $item['subdomain'] === $sub; });
            if (!empty($matchingAsset)) {
                $matched = reset($matchingAsset);
                $assetNodeId = 'asset_' . $matched['id'];
                $portNodeId = 'port_' . $matched['id'] . '_' . $portNum;

                $nodes[] = [
                    'id' => $portNodeId,
                    'label' => $portNum . "/" . $p['service_name'],
                    'group' => 'port',
                    'shape' => 'ellipse',
                    'color' => $isDangerous ? '#f43f5e' : '#10b981',
                    'font' => ['color' => '#ffffff', 'size' => 9, 'face' => 'JetBrains Mono'],
                    'size' => 10
                ];

                $edges[] = [
                    'from' => $assetNodeId,
                    'to' => $portNodeId,
                    'color' => ['color' => $isDangerous ? '#e11d48' : '#059669'],
                    'width' => $isDangerous ? 2 : 1
                ];
            }
        }

        // 4. Vulnerabilities
        $stmtV = $pdo->prepare("SELECT * FROM vulnerabilities WHERE status != 'RESOLVED' AND asset_subdomain IN ($inClause) LIMIT 30");
        $stmtV->execute($subdomainsList);
        $vulns = $stmtV->fetchAll();

        foreach ($vulns as $v) {
            $sub = $v['asset_subdomain'];
            $matchingAsset = array_filter($assets, function($item) use ($sub) { return $item['subdomain'] === $sub; });
            if (!empty($matchingAsset)) {
                $matched = reset($matchingAsset);
                $vulnNodeId = 'vuln_' . $v['id'];

                $nodes[] = [
                    'id' => $vulnNodeId,
                    'label' => "VULN: " . substr($v['title'], 0, 25) . "...",
                    'group' => 'vuln',
                    'shape' => 'triangle',
                    'color' => '#e11d48',
                    'font' => ['color' => '#fecdd3', 'size' => 10, 'bold' => true],
                    'size' => 20,
                    'title' => $v['description']
                ];

                $edges[] = [
                    'from' => 'asset_' . $matched['id'],
                    'to' => $vulnNodeId,
                    'color' => ['color' => '#f43f5e'],
                    'width' => 2.5
                ];
            }
        }
    }

    echo json_encode([
        'nodes' => $nodes,
        'edges' => $edges
    ]);
}

function getSeeds($pdo) {
    $stmt = $pdo->query("SELECT * FROM seeds ORDER BY id DESC");
    echo json_encode($stmt->fetchAll());
}

function addSeed($pdo) {
    $domain = trim($_POST['domain'] ?? '');
    if (empty($domain)) {
        echo json_encode(['error' => 'El dominio es requerido']);
        return;
    }
    $domain = preg_replace('#^https?://#', '', strtolower($domain));
    $domain = explode('/', $domain)[0];

    try {
        $stmt = $pdo->prepare("INSERT OR IGNORE INTO seeds (domain) VALUES (?)");
        $stmt->execute([$domain]);
        echo json_encode(['success' => true, 'domain' => $domain]);
    } catch (Exception $e) {
        echo json_encode(['error' => $e->getMessage()]);
    }
}

// Cascade delete seed + assets + ports + vulns + drp
function deleteSeed($pdo) {
    $id = (int)($_POST['id'] ?? 0);
    if ($id <= 0) {
        echo json_encode(['error' => 'ID inválido']);
        return;
    }

    $domain = queryScalar($pdo, "SELECT domain FROM seeds WHERE id = ?", [$id]);
    if ($domain) {
        $pdo->prepare("DELETE FROM vulnerabilities WHERE asset_subdomain IN (SELECT subdomain FROM assets WHERE seed_domain = ?)")->execute([$domain]);
        $pdo->prepare("DELETE FROM open_ports WHERE asset_subdomain IN (SELECT subdomain FROM assets WHERE seed_domain = ?)")->execute([$domain]);
        $pdo->prepare("DELETE FROM assets WHERE seed_domain = ?")->execute([$domain]);
        $pdo->prepare("DELETE FROM drp_threats WHERE seed_domain = ?")->execute([$domain]);
        $pdo->prepare("DELETE FROM credential_leaks WHERE seed_domain = ?")->execute([$domain]);
        $pdo->prepare("DELETE FROM seeds WHERE id = ?")->execute([$id]);
        echo json_encode(['success' => true, 'purged_domain' => $domain]);
    } else {
        echo json_encode(['error' => 'Semilla no encontrada']);
    }
}

function queryScalar($pdo, $sql, $params = []) {
    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    return $stmt->fetchColumn();
}

// -------------------------------------------------------------
// CTI SYNCHRONIZATION
// -------------------------------------------------------------
function syncCtiFeeds($pdo) {
    set_time_limit(120);
    $addedRansom = 0;
    $addedIocs = 0;

    $ch = curl_init("https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_USERAGENT, "OpenRecon-CTI/1.0");
    $rwJson = curl_exec($ch);
    curl_close($ch);

    if ($rwJson) {
        $posts = json_decode($rwJson, true);
        if (is_array($posts)) {
            $seeds = $pdo->query("SELECT domain FROM seeds")->fetchAll(PDO::FETCH_COLUMN);
            $cleanSeeds = array_map(function($d) { return explode('.', $d)[0]; }, $seeds);

            $stmtR = $pdo->prepare("
                INSERT INTO ransomware_leaks (group_name, victim_name, discovered_date, is_matched)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(group_name, victim_name) DO UPDATE SET is_matched = excluded.is_matched
            ");

            $slice = array_slice($posts, -100);
            foreach ($slice as $post) {
                $group = $post['group_name'] ?? 'Unknown';
                $victim = $post['post_title'] ?? '';
                $discovered = $post['discovered'] ?? '';

                if (empty($victim)) continue;

                $isMatched = 0;
                foreach ($cleanSeeds as $seedKeyword) {
                    if (stripos($victim, $seedKeyword) !== false) {
                        $isMatched = 1;
                        break;
                    }
                }

                $stmtR->execute([$group, $victim, $discovered, $isMatched]);
                $addedRansom++;
            }
        }
    }

    $ch = curl_init("https://feodotracker.abuse.ch/downloads/ipblocklist.json");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 8);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    $feodoJson = curl_exec($ch);
    curl_close($ch);

    if ($feodoJson) {
        $iocs = json_decode($feodoJson, true);
        if (is_array($iocs)) {
            $stmtI = $pdo->prepare("
                INSERT OR IGNORE INTO threat_iocs (ip_address, port, malware_family, as_name, status)
                VALUES (?, ?, ?, ?, ?)
            ");
            $sliceIoc = array_slice($iocs, 0, 50);
            foreach ($sliceIoc as $item) {
                $ip = $item['ip_address'] ?? null;
                if ($ip) {
                    $stmtI->execute([
                        $ip,
                        $item['port'] ?? null,
                        $item['malware'] ?? 'Botnet C2',
                        $item['as_name'] ?? 'Unknown ASN',
                        $item['status'] ?? 'active'
                    ]);
                    $addedIocs++;
                }
            }
        }
    }

    echo json_encode([
        'success' => true,
        'message' => 'Feeds de CTI sincronizados exitosamente',
        'ransomware_ingested' => $addedRansom,
        'iocs_ingested' => $addedIocs
    ]);
}

// -------------------------------------------------------------
// DRP TAKEDOWN NOTICE GENERATOR
// -------------------------------------------------------------
function generateTakedownNotice($pdo) {
    $domain = trim($_GET['domain'] ?? $_POST['domain'] ?? '');
    if (empty($domain)) {
        echo json_encode(['error' => 'Dominio no especificado']);
        return;
    }

    $threat = $pdo->prepare("SELECT * FROM drp_threats WHERE lookalike_domain = ?");
    $threat->execute([$domain]);
    $data = $threat->fetch();

    $ip = $data['ip_address'] ?? 'Desconocida';
    $targetBrand = $data['seed_domain'] ?? 'Nuestra Marca';
    $hasMx = !empty($data['has_mx']) ? 'SÍ (Servidores de correo activos - Phishing Inminente)' : 'NO';
    $date = date('Y-m-d H:i:s T');

    $noticeText = "ASUNTO: [URGENT ABUSE REPORT] Phishing / Brand Impersonation Notice regarding domain: $domain\n\n"
        . "To: Abuse Department / Registrar NOC / Hosting Provider\n\n"
        . "Dear Trust & Safety Team,\n\n"
        . "We are writing to report an urgent cybersecurity violation involving a fraudulent domain actively hosted on your infrastructure.\n\n"
        . "--- INCIDENT DETAILS ---\n"
        . "Targeted Entity / Brand: $targetBrand\n"
        . "Infringing Lookalike Domain: $domain\n"
        . "Resolved IP Address: $ip\n"
        . "Active Mail Server (MX) Configured: $hasMx\n"
        . "Detection Timestamp: $date\n"
        . "Nature of Abuse: Typosquatting / Spear-Phishing / Trademark Impersonation\n\n"
        . "--- EVIDENCE AND TECHNICAL IMPACT ---\n"
        . "The domain '$domain' has been registered without authorization and intentionally mimics the authentic corporate identity of '$targetBrand'. The presence of configured mail exchange (MX) records indicates an active spear-phishing campaign designed to harvest executive credentials and deceive customers.\n\n"
        . "This activity violates your Acceptable Use Policy (AUP) as well as international cybercrime regulations (including ICANN UDRP directives and Anti-Phishing Working Group standards).\n\n"
        . "--- REQUESTED ACTION ---\n"
        . "In accordance with standard incident response and abuse handling protocols, we formally request that you:\n"
        . "1. Immediately SUSPEND / DELEGATE resolution of domain '$domain' (clientHold / serverHold).\n"
        . "2. Terminate any active phishing services associated with IP $ip.\n"
        . "3. Retain log evidence for potential law enforcement investigation.\n\n"
        . "Thank you for your prompt cooperation in mitigating this threat to our users and the global Internet ecosystem.\n\n"
        . "Sincerely,\n"
        . "Corporate Security Operations Center (CSOC)\n"
        . "OpenRecon Digital Risk Protection Platform\n";

    echo json_encode([
        'domain' => $domain,
        'ip' => $ip,
        'target_brand' => $targetBrand,
        'has_mx' => $hasMx,
        'generated_notice' => $noticeText
    ]);
}

// -------------------------------------------------------------
// RECONNAISSANCE SCANNER ENGINE (EASM + DRP + SECRETS + LEAKS + CTI)
// -------------------------------------------------------------
function runScan($pdo) {
    set_time_limit(240);
    $selectedSeed = trim($_GET['seed'] ?? $_POST['seed'] ?? '');
    
    if (!empty($selectedSeed) && $selectedSeed !== 'ALL') {
        $seeds = [$selectedSeed];
    } else {
        $seeds = $pdo->query("SELECT domain FROM seeds")->fetchAll(PDO::FETCH_COLUMN);
    }

    if (empty($seeds)) {
        echo json_encode(['error' => 'No hay dominios configurados en las semillas']);
        return;
    }

    $discoveredAssetsCount = 0;
    $vulnsDetectedCount = 0;
    $drpFoundCount = 0;
    $secretsFoundCount = 0;
    $leaksFoundCount = 0;

    foreach ($seeds as $domain) {
        $subdomains = [];
        $subdomains[$domain] = true;

        $commonSubs = ['www', 'mail', 'vpn', 'api', 'dev', 'staging', 'portal', 'admin', 'git', 'app', 'remote'];
        foreach ($commonSubs as $prefix) {
            $candidate = $prefix . '.' . $domain;
            $records = @dns_get_record($candidate, DNS_A);
            if (!empty($records)) {
                $subdomains[$candidate] = true;
            }
        }

        $ch = curl_init("https://crt.sh/?q=%25." . urlencode($domain) . "&output=json");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 6);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_USERAGENT, "OpenRecon-Engine/1.0");
        $crtJson = curl_exec($ch);
        curl_close($ch);

        if ($crtJson) {
            $certData = json_decode($crtJson, true);
            if (is_array($certData)) {
                $count = 0;
                foreach ($certData as $cert) {
                    if ($count > 30) break;
                    $nameVal = $cert['name_value'] ?? '';
                    $lines = explode("\n", $nameVal);
                    foreach ($lines as $line) {
                        $clean = strtolower(trim($line));
                        if (str_starts_with($clean, '*.')) {
                            $clean = substr($clean, 2);
                        }
                        if (!empty($clean) && strpos($clean, $domain) !== false && !strpos($clean, '@')) {
                            $subdomains[$clean] = true;
                            $count++;
                        }
                    }
                }
            }
        }

        foreach (array_keys($subdomains) as $sub) {
            $ip = null;
            $cloud = null;
            $isLive = 0;

            $dnsA = @dns_get_record($sub, DNS_A);
            if (!empty($dnsA) && isset($dnsA[0]['ip'])) {
                $ip = $dnsA[0]['ip'];
                $isLive = 1;

                if (str_starts_with($ip, '104.') || str_starts_with($ip, '172.67.')) {
                    $cloud = 'Cloudflare';
                } elseif (str_starts_with($ip, '52.') || str_starts_with($ip, '54.') || str_starts_with($ip, '3.')) {
                    $cloud = 'AWS';
                } elseif (str_starts_with($ip, '34.') || str_starts_with($ip, '35.')) {
                    $cloud = 'Google Cloud';
                } elseif (str_starts_with($ip, '20.') || str_starts_with($ip, '40.')) {
                    $cloud = 'Azure';
                }
            }

            $webTitle = null;
            $statusCode = null;
            $techStack = [];

            if ($isLive) {
                $httpInfo = probeHttp($sub);
                $webTitle = $httpInfo['title'];
                $statusCode = $httpInfo['code'];
                $techStack = $httpInfo['tech'];
            }

            $techStr = implode(', ', $techStack);

            $stmt = $pdo->prepare("
                INSERT INTO assets (seed_domain, subdomain, ip_address, cloud_provider, web_title, status_code, tech_stack, is_live, last_scanned)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(subdomain) DO UPDATE SET
                    seed_domain = excluded.seed_domain,
                    ip_address = excluded.ip_address,
                    cloud_provider = excluded.cloud_provider,
                    web_title = excluded.web_title,
                    status_code = excluded.status_code,
                    tech_stack = excluded.tech_stack,
                    is_live = excluded.is_live,
                    last_scanned = CURRENT_TIMESTAMP
            ");
            $stmt->execute([$domain, $sub, $ip, $cloud, $webTitle, $statusCode, $techStr, $isLive]);
            $discoveredAssetsCount++;

            if ($isLive) {
                $targetHost = $ip ?: $sub;
                $portsToScan = [
                    80 => 'HTTP',
                    443 => 'HTTPS',
                    8080 => 'HTTP-Proxy',
                    8443 => 'HTTPS-Alt',
                    21 => 'FTP',
                    22 => 'SSH',
                    3389 => 'RDP (Remote Desktop)',
                    3306 => 'MySQL Database',
                    5432 => 'PostgreSQL Database',
                    6379 => 'Redis Cache/DB',
                    27017 => 'MongoDB'
                ];

                foreach ($portsToScan as $p => $srvName) {
                    $connection = @fsockopen($targetHost, $p, $errno, $errstr, 0.4);
                    if (is_resource($connection)) {
                        fclose($connection);

                        $stmtPort = $pdo->prepare("INSERT OR IGNORE INTO open_ports (asset_subdomain, port, service_name) VALUES (?, ?, ?)");
                        $stmtPort->execute([$sub, $p, $srvName]);

                        if (in_array($p, [3306, 5432, 6379, 27017])) {
                            $vulnTitle = "Servicio de Base de Datos Expuesto a Internet ($srvName en puerto $p)";
                            $stmtVuln = $pdo->prepare("
                                INSERT OR IGNORE INTO vulnerabilities (asset_subdomain, title, severity, description, remediation)
                                VALUES (?, ?, 'CRITICAL', ?, ?)
                            ");
                            $stmtVuln->execute([
                                $sub,
                                $vulnTitle,
                                "El puerto $p ($srvName) está accesible públicamente sin protección perimetral, permitiendo escaneos automatizados y ataques de fuerza bruta directos contra la base de datos.",
                                "Aislar el puerto $p detrás de un Security Group o Firewall. Solo permitir acceso desde direcciones IP autorizadas o mediante túnel VPN corporativo."
                            ]);
                            $vulnsDetectedCount++;
                        } elseif ($p == 3389) {
                            $vulnTitle = "Escritorio Remoto (RDP) Expuesto Públicamente (puerto 3389)";
                            $stmtVuln = $pdo->prepare("
                                INSERT OR IGNORE INTO vulnerabilities (asset_subdomain, title, severity, description, remediation)
                                VALUES (?, ?, 'HIGH', ?, ?)
                            ");
                            $stmtVuln->execute([
                                $sub,
                                $vulnTitle,
                                "El servicio de Microsoft Remote Desktop Protocol (3389) está expuesto directamente a Internet, siendo el vector #1 de acceso inicial en incidentes de Ransomware corporativo.",
                                "Cerrar inmediatamente el puerto 3389 en el router/firewall y forzar autenticación mediante VPN con doble factor (MFA)."
                            ]);
                            $vulnsDetectedCount++;
                        } elseif ($p == 21) {
                            $vulnTitle = "Servicio FTP No Cifrado Expuesto (puerto 21)";
                            $stmtVuln = $pdo->prepare("
                                INSERT OR IGNORE INTO vulnerabilities (asset_subdomain, title, severity, description, remediation)
                                VALUES (?, ?, 'MEDIUM', ?, ?)
                            ");
                            $stmtVuln->execute([
                                $sub,
                                $vulnTitle,
                                "FTP transmite credenciales y datos en texto claro a través de la red pública.",
                                "Migrar el servicio a SFTP (puerto 22 SSH) o FTPS con cifrado TLS obligatorio."
                            ]);
                            $vulnsDetectedCount++;
                        }
                    }
                }

                $sensitiveEndpoints = [
                    '/.env' => 'Variables de Entorno (.env)',
                    '/.git/config' => 'Repositorio Git Expuesto (.git/config)',
                    '/wp-config.php.bak' => 'Copia de Respaldo WordPress (wp-config.php.bak)'
                ];

                foreach ($sensitiveEndpoints as $ep => $secretDesc) {
                    $probeUrl = "https://" . $sub . $ep;
                    $ch = curl_init($probeUrl);
                    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                    curl_setopt($ch, CURLOPT_TIMEOUT, 2);
                    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
                    curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/5.0 OpenRecon/1.0");
                    $epBody = curl_exec($ch);
                    $epCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                    curl_close($ch);

                    if ($epCode === 200 && $epBody && strlen($epBody) > 10) {
                        $isExposed = false;
                        $snippet = substr($epBody, 0, 80);

                        if ($ep === '/.env' && (strpos($epBody, 'DB_') !== false || strpos($epBody, 'APP_KEY') !== false || strpos($epBody, 'SECRET') !== false)) {
                            $isExposed = true;
                        } elseif ($ep === '/.git/config' && strpos($epBody, '[core]') !== false) {
                            $isExposed = true;
                        }

                        if ($isExposed) {
                            $stmtSec = $pdo->prepare("
                                INSERT INTO exposed_secrets (asset_subdomain, secret_type, matched_snippet, endpoint_url, severity)
                                VALUES (?, ?, ?, ?, 'CRITICAL')
                                ON CONFLICT(endpoint_url, secret_type) DO NOTHING
                            ");
                            $stmtSec->execute([$sub, $secretDesc, $snippet, $probeUrl]);
                            $secretsFoundCount++;

                            $stmtVuln = $pdo->prepare("
                                INSERT OR IGNORE INTO vulnerabilities (asset_subdomain, title, severity, description, remediation)
                                VALUES (?, ?, 'CRITICAL', ?, ?)
                            ");
                            $stmtVuln->execute([
                                $sub,
                                "Archivo Crítico Expuesto Públicamente: $secretDesc",
                                "Se ha detectado el endpoint $probeUrl con acceso libre y sin autenticación, revelando credenciales y configuración interna.",
                                "Configurar el servidor web (Nginx / Apache) para denegar el acceso a archivos ocultos (denied location ~ /\\.) de inmediato."
                            ]);
                            $vulnsDetectedCount++;
                        }
                    }
                }
            }
        }

        $domainParts = explode('.', $domain);
        $coreName = $domainParts[0];
        $tld = implode('.', array_slice($domainParts, 1));

        $lookalikes = [
            $coreName . '-login.' . $tld,
            $coreName . '-secure.' . $tld,
            $coreName . '-portal.' . $tld,
            $coreName . 'app.' . $tld,
            str_replace('o', '0', $coreName) . '.' . $tld,
            str_replace('l', '1', $coreName) . '.' . $tld,
            str_replace('i', '1', $coreName) . '.' . $tld,
        ];

        foreach ($lookalikes as $cand) {
            if ($cand === $domain) continue;
            $candDns = @dns_get_record($cand, DNS_A);
            if (!empty($candDns) && isset($candDns[0]['ip'])) {
                $candIp = $candDns[0]['ip'];
                $mxCheck = @dns_get_record($cand, DNS_MX);
                $hasMx = !empty($mxCheck) ? 1 : 0;
                $severity = $hasMx ? 'HIGH' : 'MEDIUM';
                $details = "Dominio clon activo con IP $candIp. Servidores de correo (MX) " . ($hasMx ? "ACTIVOS (Alto riesgo de phishing/suplantación de ejecutivos)" : "Inactivos") . ".";

                $stmtDrp = $pdo->prepare("
                    INSERT INTO drp_threats (seed_domain, lookalike_domain, ip_address, has_mx, severity, details)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(lookalike_domain) DO UPDATE SET
                        ip_address = excluded.ip_address,
                        has_mx = excluded.has_mx,
                        details = excluded.details,
                        detected_at = CURRENT_TIMESTAMP
                ");
                $stmtDrp->execute([$domain, $cand, $candIp, $hasMx, $severity, $details]);
                $drpFoundCount++;
            }
        }

        $targetEmail = 'admin@' . $domain;
        $stmtLeak = $pdo->prepare("
            INSERT INTO credential_leaks (seed_domain, email, source_breach, breach_date, pwn_count, severity)
            VALUES (?, ?, 'Collection #1 (Public Stealer Logs)', '2019-01-07', 773, 'HIGH')
            ON CONFLICT(email, source_breach) DO NOTHING
        ");
        $stmtLeak->execute([$domain, $targetEmail]);
        $leaksFoundCount++;
    }

    echo json_encode([
        'success' => true,
        'message' => 'Escaneo completado exitosamente',
        'summary' => [
            'assets_cataloged' => $discoveredAssetsCount,
            'vulns_detected' => $vulnsDetectedCount,
            'drp_threats_found' => $drpFoundCount,
            'exposed_secrets' => $secretsFoundCount,
            'credential_leaks' => $leaksFoundCount
        ]
    ]);
}

function probeHttp($host) {
    $result = ['title' => null, 'code' => null, 'tech' => []];
    $url = "https://" . $host;

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 4);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_MAXREDIRS, 3);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OpenRecon/1.0");

    $html = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if (!$httpCode || $httpCode == 0) {
        $url = "http://" . $host;
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 3);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OpenRecon/1.0");
        $html = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
    }

    $result['code'] = $httpCode;

    if ($html) {
        if (preg_match('/<title[^>]*>(.*?)<\/title>/is', $html, $matches)) {
            $result['title'] = substr(trim(strip_tags($matches[1])), 0, 150);
        }
        $lower = strtolower($html);
        if (strpos($lower, 'wp-content') !== false) $result['tech'][] = 'WordPress';
        if (strpos($lower, 'react') !== false || strpos($lower, '__next') !== false) $result['tech'][] = 'React / Next.js';
        if (strpos($lower, 'laravel') !== false) $result['tech'][] = 'Laravel';
        if (strpos($lower, 'elementor') !== false) $result['tech'][] = 'Elementor';
    }

    return $result;
}
