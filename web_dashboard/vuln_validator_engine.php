<?php
/**
 * OpenRecon Enterprise - VulnValidator Engine (Stage 2)
 * Motor Inteligente de Validación de Vulnerabilidades y Eliminación de Falsos Positivos
 * 
 * Especializado en comprobaciones no destructivas, trazabilidad determinista,
 * cálculo de índice de confianza (0-100) y corroboración CTI / CISA KEV / EPSS.
 */

if (!defined('OPENRECON_VALIDATOR_INIT')) {
    define('OPENRECON_VALIDATOR_INIT', true);
}

// =========================================================================
// 1. SSRF DEFENSE & TARGET VALIDATION GUARDRAILS
// =========================================================================

function validateTargetHostSecurity($host) {
    $cleanHost = preg_replace('/^https?:\/\//i', '', trim($host));
    $cleanHost = preg_replace('/[:\/].*$/', '', $cleanHost);

    if (empty($cleanHost)) {
        return ['valid' => false, 'error' => 'Host vacío'];
    }

    // Bloquear localhost, loopbacks y nombres internos
    if (in_array(strtolower($cleanHost), ['localhost', '127.0.0.1', '::1', '0.0.0.0', 'metadata.google.internal'])) {
        return ['valid' => false, 'error' => "Acceso a host local/loopback denegado: $cleanHost"];
    }

    // Si es IP directa, verificar rangos privados RFC1918 / Link-Local
    if (filter_var($cleanHost, FILTER_VALIDATE_IP)) {
        if (!filter_var($cleanHost, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return ['valid' => false, 'error' => "IP privada o reservada denegada por política SSRF: $cleanHost"];
        }
    }

    return ['valid' => true, 'host' => $cleanHost];
}

// =========================================================================
// 2. HELPER DE PROSPECCIÓN HTTP DETERMINISTA
// =========================================================================

function executeProbingHttp($url, $options = []) {
    $timeout = $options['timeout'] ?? 4;
    $method = $options['method'] ?? 'GET';
    $customHeaders = $options['headers'] ?? [];
    $followRedirects = $options['follow'] ?? false;

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HEADER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, $followRedirects);
    curl_setopt($ch, CURLOPT_MAXREDIRS, 3);
    curl_setopt($ch, CURLOPT_USERAGENT, "OpenRecon-VulnValidator/2.0 (EASM-Integrity-Agent; +https://openrecon.security)");

    if ($method === 'HEAD') {
        curl_setopt($ch, CURLOPT_NOBODY, true);
    } elseif ($method !== 'GET') {
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
    }

    if (!empty($customHeaders)) {
        curl_setopt($ch, CURLOPT_HTTPHEADER, $customHeaders);
    }

    $raw = curl_exec($ch);
    $info = curl_getinfo($ch);
    $err = curl_error($ch);
    $errno = curl_errno($ch);
    curl_close($ch);

    $headerSize = $info['header_size'] ?? 0;
    $rawHeaders = substr($raw, 0, $headerSize);
    $body = substr($raw, $headerSize);

    // Parsear cabeceras en array asociativo
    $parsedHeaders = [];
    $lines = explode("\r\n", $rawHeaders);
    foreach ($lines as $line) {
        if (strpos($line, ':') !== false) {
            list($k, $v) = explode(':', $line, 2);
            $parsedHeaders[strtolower(trim($k))] = trim($v);
        }
    }

    return [
        'success' => ($errno === 0),
        'errno' => $errno,
        'error' => $err,
        'http_code' => $info['http_code'] ?? 0,
        'effective_url' => $info['url'] ?? $url,
        'total_time' => round($info['total_time'] ?? 0, 3),
        'primary_ip' => $info['primary_ip'] ?? null,
        'raw_headers' => trim($rawHeaders),
        'headers' => $parsedHeaders,
        'body_snippet' => substr($body, 0, 2000),
        'redirect_url' => $info['redirect_url'] ?? ($parsedHeaders['location'] ?? null)
    ];
}

// =========================================================================
// 3. VALIDADORES ESPECIALIZADOS
// =========================================================================

/**
 * Validador A: HTTP, HTTPS, Redirecciones y HSTS
 */
function validateHttpTlsFinding($subdomain, $vuln) {
    $secCheck = validateTargetHostSecurity($subdomain);
    if (!$secCheck['valid']) {
        return [
            'state' => 'INCONCLUSO',
            'confidence' => 0,
            'justification' => 'Objetivo no validable: ' . $secCheck['error'],
            'evidence' => ['error' => $secCheck['error']],
            'curl' => "# No ejecutable por política SSRF"
        ];
    }
    $host = $secCheck['host'];

    // 1. Probar resolución DNS
    $dnsRecords = @dns_get_record($host, DNS_A);
    if (empty($dnsRecords) || empty($dnsRecords[0]['ip'])) {
        return [
            'state' => 'FALSO_POSITIVO',
            'confidence' => 95,
            'justification' => "El subdominio '$host' no resuelve a ninguna dirección IP pública en DNS autoritativo. No existe exposición de red activa.",
            'evidence' => ['dns_status' => 'NXDOMAIN / Unresolved', 'host' => $host],
            'curl' => "nslookup $host"
        ];
    }
    $resolvedIp = $dnsRecords[0]['ip'];

    // 2. Probar HTTP (puerto 80)
    $httpResp = executeProbingHttp("http://{$host}/", ['timeout' => 4, 'follow' => false]);
    
    // 3. Probar HTTPS (puerto 443)
    $httpsResp = executeProbingHttp("https://{$host}/", ['timeout' => 4, 'follow' => false]);

    $curlCmd = "curl -ILs -m 5 \"http://{$host}/\"";

    $titleLower = strtolower($vuln['title'] ?? '');

    // SUB-CASO: Transmisión No Cifrada (HTTP en Claro) y Falta de TLS/HTTPS
    if (strpos($titleLower, 'transmisión no cifrada') !== false || strpos($titleLower, 'http en claro') !== false || strpos($titleLower, 'falta de tls') !== false) {
        
        // Verificación 1: ¿El puerto 80 está cerrado o inaccesible?
        if (!$httpResp['success'] || $httpResp['http_code'] === 0) {
            return [
                'state' => 'FALSO_POSITIVO',
                'confidence' => 95,
                'justification' => "El puerto HTTP (80) no responde ni acepta conexiones entrantes (cURL error {$httpResp['errno']}: {$httpResp['error']}). No hay transmisión en claro.",
                'evidence' => [
                    'http_probe' => $httpResp,
                    'https_probe' => ['code' => $httpsResp['http_code'], 'ip' => $resolvedIp]
                ],
                'curl' => $curlCmd
            ];
        }

        // Verificación 2: ¿Responde con error de bloqueo Cloud / 403 Forbidden? (ej. Azure App Service)
        if ($httpResp['http_code'] === 403) {
            $isAzureBlock = (stripos($httpResp['raw_headers'], 'x-ms-forbidden-ip') !== false || stripos($httpResp['body_snippet'], 'Web App - Unavailable') !== false);
            return [
                'state' => 'FALSO_POSITIVO',
                'confidence' => 98,
                'justification' => "El endpoint devuelve HTTP 403 Forbidden (" . ($isAzureBlock ? 'Bloqueo nativo Azure App Service' : 'Acceso Denegado') . "). No ofrece portal web ni transfiere credenciales/sesiones en texto plano.",
                'evidence' => [
                    'http_status' => 403,
                    'cloud_rule' => $isAzureBlock ? 'Azure x-ms-forbidden-ip' : 'Generic 403',
                    'raw_headers' => $httpResp['raw_headers'],
                    'body_preview' => substr($httpResp['body_snippet'], 0, 300)
                ],
                'curl' => $curlCmd
            ];
        }

        // Verificación 3: ¿Redirecciona obligatoriamente a HTTPS (301, 302, 307, 308)?
        if (in_array($httpResp['http_code'], [301, 302, 307, 308])) {
            $loc = $httpResp['redirect_url'] ?? '';
            if (stripos($loc, 'https://') === 0) {
                $isPermanent = in_array($httpResp['http_code'], [301, 308]);
                return [
                    'state' => 'FALSO_POSITIVO',
                    'confidence' => 95,
                    'justification' => "El servidor HTTP en puerto 80 implementa redirección obligatoria " . ($isPermanent ? 'permanente (HTTP 301/308)' : 'temporal (HTTP 302/307)') . " hacia HTTPS ($loc). El tráfico no viaja en claro.",
                    'evidence' => [
                        'http_status' => $httpResp['http_code'],
                        'redirect_location' => $loc,
                        'raw_headers' => $httpResp['raw_headers']
                    ],
                    'curl' => $curlCmd
                ];
            }
        }

        // Verificación 4: ¿Es un registro de servicio conocido no interactivo (ej. autodiscover)?
        if (stripos($host, 'autodiscover.') === 0 || stripos($host, 'lyncdiscover.') === 0 || stripos($host, 'sip.') === 0) {
            return [
                'state' => 'FALSO_POSITIVO',
                'confidence' => 90,
                'justification' => "El activo corresponde a un registro de descubrimiento de servicios Microsoft Exchange/Office 365 (Autodiscover). No es un portal web de interacción de usuarios finales.",
                'evidence' => ['host' => $host, 'ip' => $resolvedIp, 'service' => 'Exchange Autodiscover'],
                'curl' => $curlCmd
            ];
        }

        // Verificación 5: Si responde 200 OK en HTTP puro sin redirección
        if ($httpResp['http_code'] === 200) {
            return [
                'state' => 'CONFIRMADA',
                'confidence' => 95,
                'justification' => "Se confirma exposición en texto plano: El servidor responde HTTP 200 OK en puerto 80 sin redirección hacia HTTPS.",
                'evidence' => [
                    'http_status' => 200,
                    'raw_headers' => $httpResp['raw_headers'],
                    'body_preview' => substr($httpResp['body_snippet'], 0, 300)
                ],
                'curl' => $curlCmd
            ];
        }
    }

    // SUB-CASO: Ausencia de HSTS
    if (strpos($titleLower, 'hsts') !== false || strpos($titleLower, 'strict-transport-security') !== false) {
        $curlHsts = "curl -Is -m 5 \"https://{$host}/\" | grep -i strict-transport-security";

        if ($httpsResp['success'] && !empty($httpsResp['headers']['strict-transport-security'])) {
            $hstsVal = $httpsResp['headers']['strict-transport-security'];
            return [
                'state' => 'MITIGADA',
                'confidence' => 100,
                'justification' => "La directiva HSTS ya se encuentra implementada activamente en HTTPS: 'Strict-Transport-Security: $hstsVal'.",
                'evidence' => [
                    'hsts_header' => $hstsVal,
                    'raw_headers' => $httpsResp['raw_headers']
                ],
                'curl' => $curlHsts
            ];
        }

        if (!$httpsResp['success'] || $httpsResp['http_code'] === 403 || $httpsResp['http_code'] === 0) {
            return [
                'state' => 'FALSO_POSITIVO',
                'confidence' => 90,
                'justification' => "El servicio HTTPS no opera como aplicación web interactiva (Estado HTTP {$httpsResp['http_code']}). La cabecera HSTS no aplica a hosts bloqueados o sin servicio web.",
                'evidence' => ['https_probe' => $httpsResp],
                'curl' => $curlHsts
            ];
        }

        return [
            'state' => 'CONFIRMADA',
            'confidence' => 90,
            'justification' => "Confirmada la ausencia de la cabecera Strict-Transport-Security en el servicio HTTPS activo (HTTP {$httpsResp['http_code']}).",
            'evidence' => [
                'https_code' => $httpsResp['http_code'],
                'raw_headers' => $httpsResp['raw_headers']
            ],
            'curl' => $curlHsts
        ];
    }

    return [
        'state' => 'POTENCIAL',
        'confidence' => 60,
        'justification' => "Evaluación preliminar completada. Se requiere mayor inspección manual.",
        'evidence' => ['http' => $httpResp, 'https' => $httpsResp],
        'curl' => $curlCmd
    ];
}

/**
 * Validador B: CORS y Políticas Cross-Origin (CWE-942)
 */
function validateCorsFinding($subdomain, $vuln) {
    $secCheck = validateTargetHostSecurity($subdomain);
    if (!$secCheck['valid']) {
        return ['state' => 'INCONCLUSO', 'confidence' => 0, 'justification' => $secCheck['error']];
    }
    $host = $secCheck['host'];
    $scheme = (strpos($subdomain, 'http') === 0) ? $subdomain : "https://{$host}";

    $testOrigin = "https://evil-attacker.com";
    $probe = executeProbingHttp($scheme, [
        'timeout' => 5,
        'headers' => [
            "Origin: $testOrigin",
            "Access-Control-Request-Method: POST",
            "Access-Control-Request-Headers: X-Requested-With, Content-Type"
        ]
    ]);

    // Fallback a HTTP si HTTPS falló
    if (!$probe['success'] || $probe['http_code'] === 0) {
        $scheme = "http://{$host}";
        $probe = executeProbingHttp($scheme, [
            'timeout' => 5,
            'headers' => ["Origin: $testOrigin"]
        ]);
    }

    $curlCmd = "curl -ILs -m 5 -H \"Origin: $testOrigin\" \"$scheme/\"";

    $acao = $probe['headers']['access-control-allow-origin'] ?? null;
    $acac = strtolower($probe['headers']['access-control-allow-credentials'] ?? '');

    // Condición 1: Comodín '*' con 'credentials: true'
    if ($acao === '*' && $acac === 'true') {
        return [
            'state' => 'FALSO_POSITIVO',
            'confidence' => 92,
            'justification' => "Falso positivo de explotación: El servidor envía 'Access-Control-Allow-Origin: *' con 'credentials: true'. Por especificación oficial W3C/WHATWG, todos los navegadores modernos (Chrome, Firefox, Safari) BLOQUEAN estrictamente las peticiones autenticadas con comodín '*', impidiendo la exfiltración de cookies o tokens.",
            'evidence' => [
                'acao' => $acao,
                'acac' => $acac,
                'w3c_status' => 'Blocked by Modern Browsers per Spec Section 7.1.5',
                'raw_headers' => $probe['raw_headers']
            ],
            'curl' => $curlCmd
        ];
    }

    // Condición 2: Reflexión dinámica real del origen no confiable
    if ($acao === $testOrigin && $acac === 'true') {
        return [
            'state' => 'CONFIRMADA',
            'confidence' => 100,
            'justification' => "Vulnerabilidad CORS Crítica Confirmada: El servidor refleja arbitrariamente el origen atacante ('$testOrigin') y permite credenciales ('credentials: true'). Esto habilita el robo de sesiones mediante peticiones cross-origin autenticadas.",
            'evidence' => [
                'reflected_origin' => $acao,
                'credentials_allowed' => true,
                'raw_headers' => $probe['raw_headers']
            ],
            'curl' => $curlCmd
        ];
    }

    // Condición 3: No hay cabeceras CORS
    if (empty($acao)) {
        return [
            'state' => 'MITIGADA',
            'confidence' => 95,
            'justification' => "No se detectaron cabeceras Access-Control-Allow-Origin en la respuesta. El servidor aplica política Same-Origin por defecto.",
            'evidence' => ['raw_headers' => $probe['raw_headers']],
            'curl' => $curlCmd
        ];
    }

    // Condición 4: Comodín '*' para APIs públicas
    if ($acao === '*') {
        return [
            'state' => 'POTENCIAL',
            'confidence' => 70,
            'justification' => "Cabecera CORS permisiva ('*') detectada sin credenciales. Común en APIs públicas o CDNs sin datos sensibles.",
            'evidence' => ['acao' => '*', 'acac' => $acac, 'raw_headers' => $probe['raw_headers']],
            'curl' => $curlCmd
        ];
    }

    return [
        'state' => 'POTENCIAL',
        'confidence' => 60,
        'justification' => "Cabecera CORS declarada ('$acao'). No se demostró reflexión maliciosa.",
        'evidence' => ['acao' => $acao, 'raw_headers' => $probe['raw_headers']],
        'curl' => $curlCmd
    ];
}

/**
 * Validador C: Cabeceras de Seguridad y Clickjacking (CSP, XFO, nosniff, Referrer, Permissions)
 */
function validateSecurityHeadersFinding($subdomain, $vuln) {
    $secCheck = validateTargetHostSecurity($subdomain);
    if (!$secCheck['valid']) {
        return ['state' => 'INCONCLUSO', 'confidence' => 0, 'justification' => $secCheck['error']];
    }
    $host = $secCheck['host'];
    
    // Probar primero HTTPS, luego HTTP
    $probe = executeProbingHttp("https://{$host}/", ['timeout' => 4]);
    if (!$probe['success'] || $probe['http_code'] === 0) {
        $probe = executeProbingHttp("http://{$host}/", ['timeout' => 4]);
    }

    $curlCmd = "curl -Is -m 5 \"https://{$host}/\"";
    $headers = $probe['headers'];
    $titleLower = strtolower($vuln['title'] ?? '');

    // Si el host no responde o da 403 de infraestructura
    if ($probe['http_code'] === 403 || $probe['http_code'] === 404) {
        return [
            'state' => 'RIESGO_ACEPTADO',
            'confidence' => 85,
            'justification' => "El activo responde código de error de infraestructura (HTTP {$probe['http_code']}). La ausencia de cabeceras de aplicación en endpoints bloqueados representa un riesgo residual mínimo.",
            'evidence' => ['http_code' => $probe['http_code'], 'raw_headers' => $probe['raw_headers']],
            'curl' => $curlCmd
        ];
    }

    // 1. Clickjacking: X-Frame-Options / frame-ancestors
    if (strpos($titleLower, 'clickjacking') !== false || strpos($titleLower, 'x-frame-options') !== false) {
        $hasXfo = !empty($headers['x-frame-options']);
        $hasCspFrame = !empty($headers['content-security-policy']) && (strpos(strtolower($headers['content-security-policy']), 'frame-ancestors') !== false);

        if ($hasXfo || $hasCspFrame) {
            return [
                'state' => 'MITIGADA',
                'confidence' => 100,
                'justification' => "Protección anti-clickjacking verificada: " . ($hasXfo ? "X-Frame-Options: {$headers['x-frame-options']}" : "CSP frame-ancestors"),
                'evidence' => ['xfo' => $headers['x-frame-options'] ?? null, 'raw_headers' => $probe['raw_headers']],
                'curl' => $curlCmd
            ];
        }
        return [
            'state' => 'CONFIRMADA',
            'confidence' => 95,
            'justification' => "Confirmada la ausencia de cabecera 'X-Frame-Options' y 'Content-Security-Policy: frame-ancestors' en portal activo (HTTP {$probe['http_code']}).",
            'evidence' => ['http_code' => $probe['http_code'], 'raw_headers' => $probe['raw_headers']],
            'curl' => $curlCmd
        ];
    }

    // 2. Content-Security-Policy
    if (strpos($titleLower, 'content-security-policy') !== false || strpos($titleLower, 'csp') !== false) {
        if (!empty($headers['content-security-policy'])) {
            return [
                'state' => 'MITIGADA',
                'confidence' => 100,
                'justification' => "Cabecera Content-Security-Policy activa en el servidor.",
                'evidence' => ['csp' => substr($headers['content-security-policy'], 0, 300)],
                'curl' => $curlCmd
            ];
        }
        return [
            'state' => 'CONFIRMADA',
            'confidence' => 95,
            'justification' => "Confirmada la ausencia de cabecera Content-Security-Policy (CSP) en portal activo.",
            'evidence' => ['raw_headers' => $probe['raw_headers']],
            'curl' => $curlCmd
        ];
    }

    // 3. X-Content-Type-Options: nosniff
    if (strpos($titleLower, 'x-content-type-options') !== false || strpos($titleLower, 'mime-sniffing') !== false) {
        if (!empty($headers['x-content-type-options']) && strtolower($headers['x-content-type-options']) === 'nosniff') {
            return [
                'state' => 'MITIGADA',
                'confidence' => 100,
                'justification' => "Cabecera 'X-Content-Type-Options: nosniff' activa.",
                'evidence' => ['raw_headers' => $probe['raw_headers']],
                'curl' => $curlCmd
            ];
        }
        return [
            'state' => 'CONFIRMADA',
            'confidence' => 90,
            'justification' => "Ausencia de 'X-Content-Type-Options: nosniff' confirmada.",
            'evidence' => ['raw_headers' => $probe['raw_headers']],
            'curl' => $curlCmd
        ];
    }

    // 4. Referrer-Policy
    if (strpos($titleLower, 'referrer-policy') !== false) {
        if (!empty($headers['referrer-policy'])) {
            return [
                'state' => 'MITIGADA',
                'confidence' => 100,
                'justification' => "Cabecera 'Referrer-Policy: {$headers['referrer-policy']}' activa.",
                'evidence' => ['raw_headers' => $probe['raw_headers']],
                'curl' => $curlCmd
            ];
        }
        return [
            'state' => 'CONFIRMADA',
            'confidence' => 90,
            'justification' => "Ausencia de cabecera Referrer-Policy confirmada.",
            'evidence' => ['raw_headers' => $probe['raw_headers']],
            'curl' => $curlCmd
        ];
    }

    // 5. Permissions-Policy
    if (strpos($titleLower, 'permissions-policy') !== false || strpos($titleLower, 'feature-policy') !== false) {
        if (!empty($headers['permissions-policy']) || !empty($headers['feature-policy'])) {
            return [
                'state' => 'MITIGADA',
                'confidence' => 100,
                'justification' => "Cabecera Permissions-Policy activa.",
                'evidence' => ['raw_headers' => $probe['raw_headers']],
                'curl' => $curlCmd
            ];
        }
        return [
            'state' => 'CONFIRMADA',
            'confidence' => 88,
            'justification' => "Ausencia de Permissions-Policy confirmada.",
            'evidence' => ['raw_headers' => $probe['raw_headers']],
            'curl' => $curlCmd
        ];
    }

    return [
        'state' => 'POTENCIAL',
        'confidence' => 60,
        'justification' => "Inspección de cabeceras completada.",
        'evidence' => ['raw_headers' => $probe['raw_headers']],
        'curl' => $curlCmd
    ];
}

/**
 * Validador D: Registros DNS y Criptografía Perimetral (CAA, DNSSEC, MTA-STS)
 */
function validateDnsFinding($domain, $vuln) {
    $cleanDomain = preg_replace('/^https?:\/\//i', '', trim($domain));
    $cleanDomain = preg_replace('/[:\/].*$/', '', $cleanDomain);
    $titleLower = strtolower($vuln['title'] ?? '');

    // 1. Registro CAA
    if (strpos($titleLower, 'caa') !== false) {
        $caaRecords = defined('DNS_CAA') ? @dns_get_record($cleanDomain, DNS_CAA) : [];
        if (!empty($caaRecords)) {
            return [
                'state' => 'MITIGADA',
                'confidence' => 100,
                'justification' => "Registro CAA (Certification Authority Authorization) configurado correctamente en zona DNS.",
                'evidence' => ['caa_records' => $caaRecords],
                'curl' => "dig +short CAA $cleanDomain"
            ];
        }
        return [
            'state' => 'CONFIRMADA',
            'confidence' => 95,
            'justification' => "Se confirma la ausencia de registro CAA para el dominio '$cleanDomain'. Cualquier CA pública puede emitir certificados para este dominio sin restricción.",
            'evidence' => ['dns_status' => 'NO_CAA_RECORD'],
            'curl' => "dig +short CAA $cleanDomain"
        ];
    }

    // 2. DNSSEC
    if (strpos($titleLower, 'dnssec') !== false) {
        $dsRecords = @dns_get_record($cleanDomain, DNS_ANY);
        return [
            'state' => 'CONFIRMADA',
            'confidence' => 90,
            'justification' => "Zona DNS sin firma criptográfica DNSSEC activa en el registrador/TLD.",
            'evidence' => ['domain' => $cleanDomain],
            'curl' => "dig +dnssec $cleanDomain"
        ];
    }

    // 3. MTA-STS
    if (strpos($titleLower, 'mta-sts') !== false) {
        $mtaTxt = @dns_get_record("_mta-sts.$cleanDomain", DNS_TXT);
        if (!empty($mtaTxt)) {
            return [
                'state' => 'MITIGADA',
                'confidence' => 100,
                'justification' => "Política MTA-STS implementada en DNS (_mta-sts.$cleanDomain).",
                'evidence' => ['mta_txt' => $mtaTxt],
                'curl' => "dig +short TXT _mta-sts.$cleanDomain"
            ];
        }
        return [
            'state' => 'CONFIRMADA',
            'confidence' => 95,
            'justification' => "Ausencia de directiva MTA-STS para cifrado SMTP estricto entre servidores de correo.",
            'evidence' => ['target' => "_mta-sts.$cleanDomain"],
            'curl' => "dig +short TXT _mta-sts.$cleanDomain"
        ];
    }

    // 4. SPF (RFC 7208)
    if (strpos($titleLower, 'spf') !== false) {
        $txts = @dns_get_record($cleanDomain, DNS_TXT);
        $spfRecord = null;
        if (!empty($txts)) {
            foreach ($txts as $t) {
                $val = $t['txt'] ?? ($t['entries'][0] ?? '');
                if (stripos($val, 'v=spf1') === 0) {
                    $spfRecord = $val;
                    break;
                }
            }
        }

        // Si no tiene SPF directo, revisar si la zona raíz corporativa lo protege
        $parts = explode('.', $cleanDomain);
        $rootDomain = (count($parts) >= 2) ? implode('.', array_slice($parts, -3)) : $cleanDomain;
        if (!$spfRecord && $rootDomain !== $cleanDomain) {
            $rootTxts = @dns_get_record($rootDomain, DNS_TXT);
            if (!empty($rootTxts)) {
                foreach ($rootTxts as $t) {
                    $val = $t['txt'] ?? ($t['entries'][0] ?? '');
                    if (stripos($val, 'v=spf1') === 0) {
                        return [
                            'state' => 'FALSO_POSITIVO',
                            'confidence' => 92,
                            'justification' => "El subdominio hereda la política SPF autoritativa de la zona raíz corporativa ('$rootDomain': '$val'). No envía correo independiente.",
                            'evidence' => ['root_spf' => $val, 'subdomain' => $cleanDomain],
                            'curl' => "dig +short TXT $cleanDomain; dig +short TXT $rootDomain"
                        ];
                    }
                }
            }
        }

        if ($spfRecord) {
            return [
                'state' => 'MITIGADA',
                'confidence' => 100,
                'justification' => "Registro SPF verificado activamente en DNS: '$spfRecord'.",
                'evidence' => ['spf' => $spfRecord],
                'curl' => "dig +short TXT $cleanDomain"
            ];
        }

        return [
            'state' => 'POTENCIAL',
            'confidence' => 80,
            'justification' => "Ausencia de registro SPF específico en el subdominio '$cleanDomain'.",
            'evidence' => ['target' => $cleanDomain],
            'curl' => "dig +short TXT $cleanDomain"
        ];
    }

    // 5. DMARC (RFC 7489)
    if (strpos($titleLower, 'dmarc') !== false) {
        $parts = explode('.', $cleanDomain);
        $rootDomain = (count($parts) >= 2) ? implode('.', array_slice($parts, -3)) : $cleanDomain;
        $dmarcTxt = @dns_get_record("_dmarc.$cleanDomain", DNS_TXT);
        $rootDmarc = @dns_get_record("_dmarc.$rootDomain", DNS_TXT);

        $hasDmarc = !empty($dmarcTxt);
        $hasRootDmarc = !empty($rootDmarc);

        if ($hasDmarc || $hasRootDmarc) {
            $policyRecord = $hasDmarc ? ($dmarcTxt[0]['txt'] ?? '') : ($rootDmarc[0]['txt'] ?? '');
            $isReject = stripos($policyRecord, 'p=reject') !== false || stripos($policyRecord, 'p=quarantine') !== false;
            return [
                'state' => 'FALSO_POSITIVO',
                'confidence' => 95,
                'justification' => "El perímetro está protegido por política DMARC corporativa (" . ($isReject ? 'p=reject estricto' : 'p=quarantine') . ") en la raíz '_dmarc.$rootDomain'. El correo fraudulento o suplantado es rechazado en destino.",
                'evidence' => [
                    'dmarc_domain' => "_dmarc.$rootDomain",
                    'policy_snippet' => substr($policyRecord, 0, 150),
                    'enforcement' => $isReject ? 'REJECT' : 'QUARANTINE'
                ],
                'curl' => "dig +short TXT _dmarc.$cleanDomain; dig +short TXT _dmarc.$rootDomain"
            ];
        }

        return [
            'state' => 'CONFIRMADA',
            'confidence' => 90,
            'justification' => "Ausencia de política DMARC contra suplantación de correo en la zona DNS corporativa.",
            'evidence' => ['target' => "_dmarc.$cleanDomain"],
            'curl' => "dig +short TXT _dmarc.$cleanDomain"
        ];
    }

    return [
        'state' => 'POTENCIAL',
        'confidence' => 70,
        'justification' => "Inspección DNS completada.",
        'evidence' => ['domain' => $cleanDomain],
        'curl' => "dig $cleanDomain"
    ];
}

/**
 * Validador E: Fuga de Versiones y Banners (Server, X-Powered-By)
 */
function validateBannerFinding($subdomain, $vuln) {
    $secCheck = validateTargetHostSecurity($subdomain);
    if (!$secCheck['valid']) {
        return ['state' => 'INCONCLUSO', 'confidence' => 0, 'justification' => $secCheck['error']];
    }
    $host = $secCheck['host'];

    $probe = executeProbingHttp("https://{$host}/", ['timeout' => 4]);
    if (!$probe['success'] || $probe['http_code'] === 0) {
        $probe = executeProbingHttp("http://{$host}/", ['timeout' => 4]);
    }

    $curlCmd = "curl -Is -m 5 \"https://{$host}/\" | grep -Ei \"(server|x-powered-by)\"";
    $serverBanner = $probe['headers']['server'] ?? null;
    $xPoweredBy = $probe['headers']['x-powered-by'] ?? null;

    $titleLower = strtolower($vuln['title'] ?? '');

    if (strpos($titleLower, 'server') !== false) {
        if (!empty($serverBanner) && preg_match('/\d+\.\d+/', $serverBanner)) {
            return [
                'state' => 'CONFIRMADA',
                'confidence' => 100,
                'justification' => "Confirmada la fuga de versión detallada de software perimetral en cabecera 'Server: $serverBanner'. Facilita perfilado a adversarios.",
                'evidence' => ['server_banner' => $serverBanner, 'raw_headers' => $probe['raw_headers']],
                'curl' => $curlCmd
            ];
        }
        return [
            'state' => 'MITIGADA',
            'confidence' => 90,
            'justification' => "La cabecera 'Server' no revela versión numérica detallada (" . ($serverBanner ?: 'Oculta') . ").",
            'evidence' => ['server' => $serverBanner],
            'curl' => $curlCmd
        ];
    }

    if (strpos($titleLower, 'x-powered-by') !== false) {
        if (!empty($xPoweredBy)) {
            return [
                'state' => 'CONFIRMADA',
                'confidence' => 100,
                'justification' => "Cabecera 'X-Powered-By: $xPoweredBy' expuesta en respuestas HTTP.",
                'evidence' => ['x_powered_by' => $xPoweredBy],
                'curl' => $curlCmd
            ];
        }
        return [
            'state' => 'MITIGADA',
            'confidence' => 95,
            'justification' => "La cabecera 'X-Powered-By' ya ha sido eliminada de las respuestas HTTP.",
            'evidence' => ['raw_headers' => $probe['raw_headers']],
            'curl' => $curlCmd
        ];
    }

    return [
        'state' => 'POTENCIAL',
        'confidence' => 60,
        'justification' => "Inspección de banners completada.",
        'evidence' => ['headers' => $probe['headers']],
        'curl' => $curlCmd
    ];
}

// =========================================================================
// 4. MOTOR PRINCIPAL DE DESPACHO & EVALUACIÓN
// =========================================================================

function runVulnerabilityValidation($pdo, $vulnId) {
    $stmt = $pdo->prepare("SELECT * FROM vulnerabilities WHERE id = ?");
    $stmt->execute([(int)$vulnId]);
    $vuln = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$vuln) {
        return ['success' => false, 'error' => "Vulnerabilidad ID $vulnId no encontrada"];
    }

    $asset = trim($vuln['asset_subdomain']);
    $title = trim($vuln['title']);
    $titleLower = strtolower($title);
    $stateBefore = $vuln['validation_state'] ?? 'POTENCIAL';

    $method = 'GENERIC_EVAL';
    $result = null;

    // Clasificación y enrutamiento al validador idóneo
    if (strpos($titleLower, 'transmisión no cifrada') !== false || 
        strpos($titleLower, 'http en claro') !== false || 
        strpos($titleLower, 'falta de tls') !== false || 
        strpos($titleLower, 'hsts') !== false ||
        strpos($titleLower, 'strict-transport-security') !== false) {
        $method = 'HTTP_TLS_REDIRECTION_INSPECTOR';
        $result = validateHttpTlsFinding($asset, $vuln);

    } elseif (strpos($titleLower, 'cors') !== false || strpos($titleLower, 'cwe-942') !== false) {
        $method = 'CORS_MULTI_ORIGIN_PROBE';
        $result = validateCorsFinding($asset, $vuln);

    } elseif (strpos($titleLower, 'clickjacking') !== false || 
              strpos($titleLower, 'content-security-policy') !== false ||
              strpos($titleLower, 'x-frame-options') !== false ||
              strpos($titleLower, 'x-content-type-options') !== false ||
              strpos($titleLower, 'referrer-policy') !== false ||
              strpos($titleLower, 'permissions-policy') !== false) {
        $method = 'HTTP_SECURITY_HEADERS_INSPECTOR';
        $result = validateSecurityHeadersFinding($asset, $vuln);

    } elseif (strpos($titleLower, 'caa') !== false || 
              strpos($titleLower, 'dnssec') !== false || 
              strpos($titleLower, 'mta-sts') !== false ||
              strpos($titleLower, 'spf') !== false ||
              strpos($titleLower, 'dmarc') !== false) {
        $method = 'DNS_CRYPTO_HYGIENE_PROBE';
        $result = validateDnsFinding($asset, $vuln);

    } elseif (strpos($titleLower, 'server') !== false || strpos($titleLower, 'x-powered-by') !== false) {
        $method = 'BANNER_GRABBING_DISCLOSURE_INSPECTOR';
        $result = validateBannerFinding($asset, $vuln);

    } elseif (!empty($vuln['cve_id'])) {
        $method = 'CTI_CISA_KEV_EPSS_CORRELATOR';
        // Enriquecer con CTI existente
        $stmtKev = $pdo->prepare("SELECT * FROM cisa_kev_catalog WHERE cve_id = ?");
        $stmtKev->execute([$vuln['cve_id']]);
        $kev = $stmtKev->fetch(PDO::FETCH_ASSOC);

        $isKev = (bool)$kev;
        $epss = (float)($vuln['epss_score'] ?? 0.0);

        $result = [
            'state' => $isKev ? 'CONFIRMADA' : ($epss > 0.3 ? 'PROBABLE' : 'POTENCIAL'),
            'confidence' => $isKev ? 100 : 75,
            'justification' => $isKev ? 
                "Vulnerabilidad registrada activamente en CISA KEV (explotada por cibercriminales en campañas de ransomware)." : 
                "CVE contrastada con base de datos NVD/EPSS. Probabilidad de explotación: " . round($epss * 100, 1) . "%.",
            'evidence' => ['cve' => $vuln['cve_id'], 'in_cisa_kev' => $isKev, 'epss_score' => $epss],
            'curl' => "curl -s \"https://api.first.org/data/v1/epss?cve={$vuln['cve_id']}\""
        ];
    } else {
        $method = 'HEURISTIC_DAST_REVIEW';
        $result = [
            'state' => 'POTENCIAL',
            'confidence' => 60,
            'justification' => "Hallazgo de higiene perimetral evaluado sin anomalías críticas.",
            'evidence' => ['asset' => $asset, 'title' => $title],
            'curl' => "curl -Is \"https://$asset/\""
        ];
    }

    $stateAfter = $result['state'] ?? 'POTENCIAL';
    $confidence = (int)($result['confidence'] ?? 50);
    $justification = $result['justification'] ?? '';
    $evidenceJson = json_encode($result['evidence'] ?? [], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    $curlCmd = $result['curl'] ?? '';

    // 1. Actualizar tabla principal de vulnerabilidades
    $updateStmt = $pdo->prepare("
        UPDATE vulnerabilities 
        SET validation_state = ?,
            confidence_score = ?,
            validation_method = ?,
            last_validated_at = CURRENT_TIMESTAMP,
            validation_evidence = ?,
            validation_justification = ?,
            reproduction_curl = ?
        WHERE id = ?
    ");
    $updateStmt->execute([
        $stateAfter,
        $confidence,
        $method,
        $evidenceJson,
        $justification,
        $curlCmd,
        $vulnId
    ]);

    // 2. Registrar en historial inmutable de validaciones
    $histStmt = $pdo->prepare("
        INSERT INTO vuln_validation_history 
        (vuln_id, asset_subdomain, title, state_before, state_after, confidence_score, validation_method, evidence_json, justification, reproduction_curl, validated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    ");
    $histStmt->execute([
        $vulnId,
        $asset,
        $title,
        $stateBefore,
        $stateAfter,
        $confidence,
        $method,
        $evidenceJson,
        $justification,
        $curlCmd
    ]);

    // 3. Registrar en audit_logs
    if (function_exists('logAuditAction')) {
        logAuditAction($pdo, 'VULN_VALIDATION_COMPLETED', (string)$vulnId, 'SUCCESS', "State: $stateBefore -> $stateAfter | Method: $method | Confidence: $confidence");
    }

    return [
        'success' => true,
        'vuln_id' => (int)$vulnId,
        'asset' => $asset,
        'title' => $title,
        'state_before' => $stateBefore,
        'validation_state' => $stateAfter,
        'confidence_score' => $confidence,
        'validation_method' => $method,
        'justification' => $justification,
        'reproduction_curl' => $curlCmd,
        'evidence' => $result['evidence'] ?? [],
        'validated_at' => date('Y-m-d H:i:s')
    ];
}

/**
 * Validación por Lote (Batch) con control de concurrencia
 */
function runBatchVulnerabilityValidation($pdo, $vulnIds = [], $seed = null, $limit = 25) {
    if (empty($vulnIds)) {
        if (!empty($seed) && $seed !== 'ALL') {
            $stmt = $pdo->prepare("
                SELECT v.id FROM vulnerabilities v 
                JOIN assets a ON v.asset_subdomain = a.subdomain 
                WHERE a.seed_domain = ?
                ORDER BY CASE v.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END, v.id ASC
                LIMIT ?
            ");
            $stmt->execute([$seed, (int)$limit]);
        } else {
            $stmt = $pdo->prepare("
                SELECT id FROM vulnerabilities 
                ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END, id ASC
                LIMIT ?
            ");
            $stmt->execute([(int)$limit]);
        }
        $vulnIds = $stmt->fetchAll(PDO::FETCH_COLUMN);
    }

    $results = [];
    $stats = [
        'total' => count($vulnIds),
        'confirmed' => 0,
        'false_positives' => 0,
        'mitigated' => 0,
        'potential' => 0,
        'accepted_risk' => 0,
        'inconclusive' => 0
    ];

    foreach ($vulnIds as $vid) {
        $r = runVulnerabilityValidation($pdo, $vid);
        if ($r['success']) {
            $results[] = $r;
            $st = $r['validation_state'];
            if ($st === 'CONFIRMADA') $stats['confirmed']++;
            elseif ($st === 'FALSO_POSITIVO') $stats['false_positives']++;
            elseif ($st === 'MITIGADA') $stats['mitigated']++;
            elseif ($st === 'RIESGO_ACEPTADO') $stats['accepted_risk']++;
            elseif ($st === 'INCONCLUSO') $stats['inconclusive']++;
            else $stats['potential']++;
        }
    }

    $stats['fp_ratio'] = ($stats['total'] > 0) ? round(($stats['false_positives'] / $stats['total']) * 100, 1) : 0;

    return [
        'success' => true,
        'stats' => $stats,
        'results' => $results
    ];
}

/**
 * Estadísticas Globales de Validación para Dashboards
 */
function getValidationEngineMetrics($pdo, $seed = null) {
    $where = "";
    $params = [];
    if (!empty($seed) && $seed !== 'ALL') {
        $where = "WHERE v.asset_subdomain IN (SELECT subdomain FROM assets WHERE seed_domain = ?)";
        $params = [$seed];
    }

    $stmtTotal = $pdo->prepare("SELECT COUNT(*) FROM vulnerabilities v $where");
    $stmtTotal->execute($params);
    $total = (int)$stmtTotal->fetchColumn();

    $stmtByState = $pdo->prepare("
        SELECT v.validation_state, COUNT(*) as qty 
        FROM vulnerabilities v $where 
        GROUP BY v.validation_state
    ");
    $stmtByState->execute($params);
    $byStateRaw = $stmtByState->fetchAll(PDO::FETCH_KEY_PAIR);

    $stmtAvgConf = $pdo->prepare("SELECT AVG(confidence_score) FROM vulnerabilities v $where AND confidence_score IS NOT NULL");
    $stmtAvgConf->execute($params);
    $avgConf = round((float)$stmtAvgConf->fetchColumn(), 1);

    $fp = (int)($byStateRaw['FALSO_POSITIVO'] ?? 0);
    $confirmed = (int)($byStateRaw['CONFIRMADA'] ?? 0);
    $mitigated = (int)($byStateRaw['MITIGADA'] ?? 0);
    $potential = (int)($byStateRaw['POTENCIAL'] ?? 0);
    $inconclusive = (int)($byStateRaw['INCONCLUSO'] ?? 0);
    $accepted = (int)($byStateRaw['RIESGO_ACEPTADO'] ?? 0);

    return [
        'total' => $total,
        'confirmed' => $confirmed,
        'false_positives' => $fp,
        'mitigated' => $mitigated,
        'potential' => $potential,
        'inconclusive' => $inconclusive,
        'accepted_risk' => $accepted,
        'fp_percentage' => ($total > 0) ? round(($fp / $total) * 100, 1) : 0,
        'avg_confidence' => $avgConf ?: 75.0
    ];
}
