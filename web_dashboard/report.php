<?php
// Database connection
$dbFile = __DIR__ . '/openrecon.sqlite';
try {
    $pdo = new PDO("sqlite:" . $dbFile);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

    $requestedSeed = trim($_GET['seed'] ?? '');
    if (!empty($requestedSeed) && $requestedSeed !== 'ALL') {
        $domainTitle = $requestedSeed;
        $totalAssets = (int)$pdo->prepare("SELECT COUNT(*) FROM assets WHERE seed_domain = ?")->execute([$requestedSeed]) ? $pdo->query("SELECT COUNT(*) FROM assets WHERE seed_domain = " . $pdo->quote($requestedSeed))->fetchColumn() : 0;
        $liveAssets = (int)$pdo->query("SELECT COUNT(*) FROM assets WHERE seed_domain = " . $pdo->quote($requestedSeed) . " AND is_live = 1")->fetchColumn();
        $openPorts = (int)$pdo->query("SELECT COUNT(*) FROM open_ports WHERE asset_subdomain IN (SELECT subdomain FROM assets WHERE seed_domain = " . $pdo->quote($requestedSeed) . ")")->fetchColumn();

        $critVulns = (int)$pdo->query("SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'CRITICAL' AND (status = 'OPEN' OR status = 'IN_PROGRESS' OR status IS NULL) AND asset_subdomain IN (SELECT subdomain FROM assets WHERE seed_domain = " . $pdo->quote($requestedSeed) . ")")->fetchColumn();
        $highVulns = (int)$pdo->query("SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'HIGH' AND (status = 'OPEN' OR status = 'IN_PROGRESS' OR status IS NULL) AND asset_subdomain IN (SELECT subdomain FROM assets WHERE seed_domain = " . $pdo->quote($requestedSeed) . ")")->fetchColumn();
        $medVulns = (int)$pdo->query("SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'MEDIUM' AND (status = 'OPEN' OR status = 'IN_PROGRESS' OR status IS NULL) AND asset_subdomain IN (SELECT subdomain FROM assets WHERE seed_domain = " . $pdo->quote($requestedSeed) . ")")->fetchColumn();
        $resolvedVulns = (int)$pdo->query("SELECT COUNT(*) FROM vulnerabilities WHERE status = 'RESOLVED' AND asset_subdomain IN (SELECT subdomain FROM assets WHERE seed_domain = " . $pdo->quote($requestedSeed) . ")")->fetchColumn();

        $drpCount = (int)$pdo->query("SELECT COUNT(*) FROM drp_threats WHERE seed_domain = " . $pdo->quote($requestedSeed) . " AND (status = 'OPEN' OR status IS NULL)")->fetchColumn();
        $credLeaksCount = (int)$pdo->query("SELECT COUNT(*) FROM credential_leaks WHERE seed_domain = " . $pdo->quote($requestedSeed))->fetchColumn();
        $secretsCount = (int)$pdo->query("SELECT COUNT(*) FROM exposed_secrets WHERE asset_subdomain IN (SELECT subdomain FROM assets WHERE seed_domain = " . $pdo->quote($requestedSeed) . ")")->fetchColumn();
        
        $core = explode('.', $requestedSeed)[0];
        $ransomMatched = (int)$pdo->query("SELECT COUNT(*) FROM ransomware_leaks WHERE victim_name LIKE " . $pdo->quote('%' . $core . '%'))->fetchColumn();

        $assets = $pdo->query("SELECT * FROM assets WHERE seed_domain = " . $pdo->quote($requestedSeed) . " ORDER BY is_live DESC LIMIT 25")->fetchAll();
        $vulns = $pdo->query("SELECT v.* FROM vulnerabilities v JOIN assets a ON v.asset_subdomain = a.subdomain WHERE a.seed_domain = " . $pdo->quote($requestedSeed) . " AND (v.status != 'RESOLVED' OR v.status IS NULL) ORDER BY CASE v.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 ELSE 3 END LIMIT 15")->fetchAll();
        $threats = $pdo->query("SELECT * FROM drp_threats WHERE seed_domain = " . $pdo->quote($requestedSeed) . " LIMIT 10")->fetchAll();
        $leaks = $pdo->query("SELECT * FROM credential_leaks WHERE seed_domain = " . $pdo->quote($requestedSeed))->fetchAll();
        $totalIocs = (int)$pdo->query("SELECT COUNT(*) FROM threat_iocs")->fetchColumn();

    } else {
        $seeds = $pdo->query("SELECT domain FROM seeds")->fetchAll(PDO::FETCH_COLUMN);
        $domainTitle = !empty($seeds) ? implode(', ', $seeds) : 'Entidad Monitoreada';

        // Stats
        $totalAssets = (int)$pdo->query("SELECT COUNT(*) FROM assets WHERE seed_domain IN (SELECT domain FROM seeds)")->fetchColumn();
        $liveAssets = (int)$pdo->query("SELECT COUNT(*) FROM assets WHERE is_live = 1 AND seed_domain IN (SELECT domain FROM seeds)")->fetchColumn();
        $openPorts = (int)$pdo->query("SELECT COUNT(*) FROM open_ports WHERE asset_subdomain IN (SELECT subdomain FROM assets WHERE seed_domain IN (SELECT domain FROM seeds))")->fetchColumn();
        
        $critVulns = (int)$pdo->query("SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'CRITICAL' AND (status = 'OPEN' OR status = 'IN_PROGRESS' OR status IS NULL) AND asset_subdomain IN (SELECT subdomain FROM assets WHERE seed_domain IN (SELECT domain FROM seeds))")->fetchColumn();
        $highVulns = (int)$pdo->query("SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'HIGH' AND (status = 'OPEN' OR status = 'IN_PROGRESS' OR status IS NULL) AND asset_subdomain IN (SELECT subdomain FROM assets WHERE seed_domain IN (SELECT domain FROM seeds))")->fetchColumn();
        $medVulns = (int)$pdo->query("SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'MEDIUM' AND (status = 'OPEN' OR status = 'IN_PROGRESS' OR status IS NULL) AND asset_subdomain IN (SELECT subdomain FROM assets WHERE seed_domain IN (SELECT domain FROM seeds))")->fetchColumn();
        $resolvedVulns = (int)$pdo->query("SELECT COUNT(*) FROM vulnerabilities WHERE status = 'RESOLVED' AND asset_subdomain IN (SELECT subdomain FROM assets WHERE seed_domain IN (SELECT domain FROM seeds))")->fetchColumn();

        $drpCount = (int)$pdo->query("SELECT COUNT(*) FROM drp_threats WHERE seed_domain IN (SELECT domain FROM seeds) AND (status = 'OPEN' OR status IS NULL)")->fetchColumn();
        $credLeaksCount = (int)$pdo->query("SELECT COUNT(*) FROM credential_leaks WHERE seed_domain IN (SELECT domain FROM seeds)")->fetchColumn();
        $secretsCount = (int)$pdo->query("SELECT COUNT(*) FROM exposed_secrets WHERE asset_subdomain IN (SELECT subdomain FROM assets WHERE seed_domain IN (SELECT domain FROM seeds))")->fetchColumn();
        $ransomMatched = (int)$pdo->query("SELECT COUNT(*) FROM ransomware_leaks WHERE is_matched = 1")->fetchColumn();

        $assets = $pdo->query("SELECT * FROM assets WHERE seed_domain IN (SELECT domain FROM seeds) ORDER BY is_live DESC LIMIT 25")->fetchAll();
        $vulns = $pdo->query("SELECT v.* FROM vulnerabilities v JOIN assets a ON v.asset_subdomain = a.subdomain WHERE a.seed_domain IN (SELECT domain FROM seeds) AND (v.status != 'RESOLVED' OR v.status IS NULL) ORDER BY CASE v.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 ELSE 3 END LIMIT 15")->fetchAll();
        $threats = $pdo->query("SELECT * FROM drp_threats WHERE seed_domain IN (SELECT domain FROM seeds) LIMIT 10")->fetchAll();
        $leaks = $pdo->query("SELECT * FROM credential_leaks WHERE seed_domain IN (SELECT domain FROM seeds)")->fetchAll();
        $totalIocs = (int)$pdo->query("SELECT COUNT(*) FROM threat_iocs")->fetchColumn();
    }

} catch (Exception $e) {
    die("Error cargando base de datos: " . $e->getMessage());
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte Ejecutivo de Ciberseguridad Perimetral | <?php echo htmlspecialchars($domainTitle); ?></title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');
        body { font-family: 'Inter', sans-serif; }
        .font-mono { font-family: 'JetBrains Mono', monospace; }
        @media print {
            .no-print { display: none !important; }
            body { background: white !important; color: black !important; padding: 0 !important; }
            .page-break { page-break-before: always; }
        }
    </style>
</head>
<body class="bg-slate-100 text-slate-800 p-4 sm:p-8">

    <!-- Top Action Toolbar -->
    <div class="max-w-4xl mx-auto mb-6 flex items-center justify-between no-print">
        <a href="index.php" class="px-4 py-2 rounded-xl bg-white border border-slate-300 text-slate-700 text-xs font-semibold hover:bg-slate-50 transition flex items-center gap-2 shadow-sm">
            <i class="fa-solid fa-arrow-left"></i>
            <span>Volver a la Consola</span>
        </a>

        <button onclick="window.print()" class="px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 text-white text-xs font-bold shadow-md hover:from-cyan-500 hover:to-blue-500 transition flex items-center gap-2">
            <i class="fa-solid fa-print"></i>
            <span>Imprimir / Guardar en PDF</span>
        </button>
    </div>

    <!-- Printable Formal Document Container -->
    <div class="max-w-4xl mx-auto bg-white border border-slate-200 rounded-2xl shadow-xl p-8 sm:p-12 space-y-8">

        <!-- Report Header -->
        <div class="border-b border-slate-200 pb-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
                <div class="flex items-center gap-2.5 mb-1">
                    <span class="w-8 h-8 rounded-lg bg-cyan-600 text-white flex items-center justify-center font-bold text-sm shadow">
                        <i class="fa-solid fa-shield-halved"></i>
                    </span>
                    <span class="font-extrabold text-xl tracking-tight text-slate-900">Open<span class="text-cyan-600">Recon</span></span>
                    <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-100 text-slate-600 border border-slate-300 uppercase">EASM &bull; DRP &bull; CTI</span>
                </div>
                <h1 class="text-2xl font-black text-slate-900 mt-2">Informe Ejecutivo de Postura de Ciberseguridad</h1>
                <p class="text-xs text-slate-500">Evaluación de Superficie de Ataque Externa, Riesgo Digital y Amenazas en la Dark Web</p>
            </div>

            <div class="text-right sm:text-right text-xs text-slate-500 font-mono space-y-1">
                <span class="inline-block px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-rose-50 text-rose-700 border border-rose-200">CONFIDENCIAL</span>
                <p class="mt-1">Fecha: <strong><?php echo date('d/m/Y H:i T'); ?></strong></p>
                <p>Objetivo: <strong><?php echo htmlspecialchars($domainTitle); ?></strong></p>
            </div>
        </div>

        <!-- Executive Summary & Score Banner -->
        <div class="grid grid-cols-1 md:grid-cols-12 gap-6 bg-slate-50 border border-slate-200 rounded-2xl p-6">
            <div class="md:col-span-4 flex flex-col items-center justify-center text-center border-b md:border-b-0 md:border-r border-slate-200 pb-4 md:pb-0 md:pr-6">
                <span class="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">Exposure Score</span>
                <div class="relative w-32 h-32 flex items-center justify-center">
                    <div class="text-4xl font-black <?php echo $score >= 75 ? 'text-emerald-600' : ($score >= 50 ? 'text-amber-600' : 'text-rose-600'); ?>">
                        <?php echo $score; ?><span class="text-sm text-slate-400 font-normal">/100</span>
                    </div>
                </div>
                <span class="px-3 py-1 rounded-full text-xs font-bold <?php echo $score >= 75 ? 'bg-emerald-100 text-emerald-800' : ($score >= 50 ? 'bg-amber-100 text-amber-800' : 'bg-rose-100 text-rose-800'); ?> mt-2">
                    <?php echo $score >= 75 ? 'Postura Defensiva Alta' : ($score >= 50 ? 'Riesgo Moderado' : 'Alerta Crítica de Exposición'); ?>
                </span>
            </div>

            <div class="md:col-span-8 flex flex-col justify-center space-y-3">
                <h3 class="text-sm font-bold text-slate-900 uppercase tracking-wider">Resumen para la Dirección</h3>
                <p class="text-xs text-slate-600 leading-relaxed">
                    Este documento sintetiza la auditoría de exposición perimetral realizada sobre los activos asociados a <strong><?php echo htmlspecialchars($domainTitle); ?></strong>. 
                    Se identificaron <strong><?php echo $liveAssets; ?></strong> activos accesibles desde Internet con <strong><?php echo $openPorts; ?></strong> puertos de red abiertos.
                    <?php if ($critVulns + $highVulns > 0): ?>
                        Se detectaron <strong class="text-rose-600"><?php echo $critVulns + $highVulns; ?> vulnerabilidades de severidad alta o crítica</strong> que requieren atención prioritaria para mitigar vectores directos de intrusión o ransomware.
                    <?php else: ?>
                        No se detectaron servicios administrativos o bases de datos expuestos sin protección cortafuegos.
                    <?php endif; ?>
                </p>
                <div class="grid grid-cols-4 gap-2 pt-2 border-t border-slate-200 text-center font-mono">
                    <div class="p-2 bg-white rounded-lg border border-slate-200">
                        <span class="block text-base font-bold text-slate-900"><?php echo $liveAssets; ?></span>
                        <span class="text-[10px] text-slate-500">Activos</span>
                    </div>
                    <div class="p-2 bg-white rounded-lg border border-slate-200">
                        <span class="block text-base font-bold text-slate-900"><?php echo $openPorts; ?></span>
                        <span class="text-[10px] text-slate-500">Puertos</span>
                    </div>
                    <div class="p-2 bg-white rounded-lg border border-slate-200">
                        <span class="block text-base font-bold text-rose-600"><?php echo $critVulns + $highVulns; ?></span>
                        <span class="text-[10px] text-slate-500">Críticas/Altas</span>
                    </div>
                    <div class="p-2 bg-white rounded-lg border border-slate-200">
                        <span class="block text-base font-bold text-emerald-600"><?php echo $resolvedVulns; ?></span>
                        <span class="text-[10px] text-slate-500">Mitigadas</span>
                    </div>
                </div>
            </div>
        </div>

        <!-- Findings Table -->
        <div class="space-y-3">
            <h3 class="text-sm font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                <i class="fa-solid fa-triangle-exclamation text-rose-500"></i>
                Hallazgos Perimetrales y Prioridades de Remediación
            </h3>

            <?php if (empty($vulns)): ?>
                <p class="text-xs text-slate-500 italic p-4 bg-slate-50 rounded-xl border border-slate-200">
                    No se registran vulnerabilidades activas abiertas en este momento.
                </p>
            <?php else: ?>
                <div class="overflow-x-auto border border-slate-200 rounded-xl">
                    <table class="w-full text-left text-xs">
                        <thead class="bg-slate-50 text-slate-600 uppercase text-[10px] border-b border-slate-200">
                            <tr>
                                <th class="p-3">Severidad</th>
                                <th class="p-3">Hallazgo Técnico</th>
                                <th class="p-3">Activo Afectado</th>
                                <th class="p-3">Acción Recomendada</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-slate-200 text-slate-700">
                            <?php foreach ($vulns as $v): ?>
                            <tr>
                                <td class="p-3 font-bold whitespace-nowrap">
                                    <span class="px-2 py-0.5 rounded text-[10px] uppercase <?php echo $v['severity'] === 'CRITICAL' ? 'bg-rose-100 text-rose-800' : ($v['severity'] === 'HIGH' ? 'bg-orange-100 text-orange-800' : 'bg-amber-100 text-amber-800'); ?>">
                                        <?php echo $v['severity']; ?>
                                    </span>
                                </td>
                                <td class="p-3 font-semibold text-slate-900"><?php echo htmlspecialchars($v['title']); ?></td>
                                <td class="p-3 font-mono text-[11px] text-slate-500 whitespace-nowrap"><?php echo htmlspecialchars($v['asset_subdomain']); ?></td>
                                <td class="p-3 text-[11px] text-slate-600"><?php echo htmlspecialchars($v['remediation']); ?></td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
        </div>

        <!-- Attack Surface Inventory Sample -->
        <div class="space-y-3">
            <h3 class="text-sm font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                <i class="fa-solid fa-network-wired text-cyan-600"></i>
                Inventario Perimetral Descubierto (Muestra de Activos)
            </h3>

            <div class="overflow-x-auto border border-slate-200 rounded-xl">
                <table class="w-full text-left text-xs">
                    <thead class="bg-slate-50 text-slate-600 uppercase text-[10px] border-b border-slate-200">
                        <tr>
                            <th class="p-3">Subdominio</th>
                            <th class="p-3">Dirección IP</th>
                            <th class="p-3">Proveedor / Infraestructura</th>
                            <th class="p-3">Tecnologías</th>
                            <th class="p-3 text-center">Estado</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-slate-200 text-slate-700">
                        <?php foreach ($assets as $a): ?>
                        <tr>
                            <td class="p-3 font-mono font-semibold text-slate-900"><?php echo htmlspecialchars($a['subdomain']); ?></td>
                            <td class="p-3 font-mono text-slate-500"><?php echo htmlspecialchars($a['ip_address'] ?: '-'); ?></td>
                            <td class="p-3"><?php echo htmlspecialchars($a['cloud_provider'] ?: 'Directo / On-Premise'); ?></td>
                            <td class="p-3 text-[11px] text-slate-600"><?php echo htmlspecialchars($a['tech_stack'] ?: '-'); ?></td>
                            <td class="p-3 text-center">
                                <span class="px-2 py-0.5 rounded text-[10px] font-bold <?php echo $a['is_live'] ? 'bg-emerald-100 text-emerald-800' : 'bg-slate-100 text-slate-500'; ?>">
                                    <?php echo $a['is_live'] ? 'ONLINE' : 'OFFLINE'; ?>
                                </span>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Breach Intelligence & Identity Exposure Detail -->
        <div class="space-y-3 pt-4 border-t border-slate-200">
            <h3 class="text-sm font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                <i class="fa-solid fa-key text-amber-600"></i>
                Fugas de Credenciales e Inteligencia de Identidad (Breach Intelligence)
            </h3>

            <?php if (empty($leaks)): ?>
                <p class="text-xs text-slate-500 italic p-4 bg-slate-50 rounded-xl border border-slate-200">
                    No se han registrado credenciales asociadas al dominio corporativo en bases de datos públicas o volcados analizados.
                </p>
            <?php else: ?>
                <div class="space-y-3">
                    <?php foreach ($leaks as $l): ?>
                    <div class="p-4 bg-amber-50/60 border border-amber-200 rounded-xl space-y-2">
                        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-1 border-b border-amber-200/80 pb-2">
                            <div class="flex items-center gap-2">
                                <span class="font-mono font-bold text-slate-900 text-xs"><?php echo htmlspecialchars($l['email']); ?></span>
                                <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-100 text-rose-800 uppercase"><?php echo htmlspecialchars($l['severity']); ?> (<?php echo htmlspecialchars($l['pwn_count']); ?> Registros Pwned)</span>
                            </div>
                            <span class="text-[11px] text-slate-500 font-mono">Brecha: <?php echo htmlspecialchars($l['source_breach']); ?> (<?php echo htmlspecialchars($l['breach_date']); ?>)</span>
                        </div>
                        <div class="text-xs text-slate-700">
                            <strong>Clases de Datos Comprometidas:</strong> <?php echo htmlspecialchars($l['data_classes'] ?: 'Contraseñas en texto plano, Hashes'); ?>
                        </div>
                        <div class="text-[11px] text-slate-600 leading-relaxed bg-white/80 p-2.5 rounded border border-amber-100">
                            <strong>Justificación Técnica de Severidad ALTA:</strong> <?php echo htmlspecialchars($l['risk_justification'] ?: 'Riesgo inminente de Account Takeover por reutilización de contraseñas (MITRE T1078/T1110).'); ?>
                        </div>
                        <div class="text-[11px] text-slate-700 font-mono bg-slate-100 p-2.5 rounded whitespace-pre-line border border-slate-200">
<strong>Playbook de Remediación Inmediata:</strong>
<?php echo htmlspecialchars($l['playbook_actions'] ?: '1. Reset de contraseñas. 2. Forzar MFA FIDO2.'); ?>
                        </div>
                    </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>

        <!-- DRP & Threat Landscape Summary -->
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-4 border-t border-slate-200">
            <div class="p-4 bg-slate-50 border border-slate-200 rounded-xl">
                <h4 class="text-xs font-bold text-slate-900 uppercase flex items-center gap-2 mb-2">
                    <i class="fa-solid fa-masks-theater text-amber-600"></i>
                    Riesgo Digital y Phishing (DRP)
                </h4>
                <p class="text-xs text-slate-600">
                    Se han identificado <strong><?php echo $drpCount; ?> dominios suplantadores</strong> activos. Se recomienda remitir notificaciones de abuso (Takedown) a registradores para prevenir campañas de phishing corporativo.
                </p>
            </div>

            <div class="p-4 bg-slate-50 border border-slate-200 rounded-xl">
                <h4 class="text-xs font-bold text-slate-900 uppercase flex items-center gap-2 mb-2">
                    <i class="fa-solid fa-radiation text-purple-600"></i>
                    Vigilancia en la Dark Web & CTI (<?php echo $totalIocs; ?> C2s Activos)
                </h4>
                <p class="text-xs text-slate-600">
                    <?php if ($ransomMatched > 0): ?>
                        <strong class="text-rose-600">Alerta:</strong> Se detectaron <?php echo $ransomMatched; ?> menciones de la marca en blogs de extorsión de sindicatos de ransomware. Se sugiere auditoría forense urgente.
                    <?php else: ?>
                        No se han encontrado filtraciones o anuncios de secuestro de datos activos vinculados a la entidad en foros o blogs de ransomware monitoreados.
                    <?php endif; ?>
                    Se mantienen sincronizados <strong><?php echo $totalIocs; ?> servidores de Comando y Control (C2)</strong> hostiles listos para bloqueo perimetral.
                </p>
            </div>
        </div>

        <!-- Footer / Certification -->
        <div class="pt-6 border-t border-slate-200 flex flex-col sm:flex-row items-center justify-between text-[11px] text-slate-500 gap-2">
            <p>Generado automáticamente por <strong>OpenRecon Platform v1.0 (Suite Abierta de Ciberseguridad)</strong>.</p>
            <p class="font-mono">Evaluación no invasiva &bull; Soberanía de Datos</p>
        </div>

    </div>

</body>
</html>
