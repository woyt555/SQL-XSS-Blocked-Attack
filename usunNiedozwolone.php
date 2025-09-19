<?php
function usunNiedozwolone($input): string {
    if ($input === null || $input === '') {  return ''; }    
    $originalInput = $input = trim((string)$input);    
    // Lista krytycznych słów SQL (blokada całkowita)
    $blockWords = [
        'select', 'update', 'delete', 'insert', 'drop', 'alter', 
        'create', 'truncate', 'union', 'exec', 'execute', 'declare'
    ];    
    // Lista krytycznych sekwencji (blokada całkowita)
    $blockSequences = ['--', ';', '/*', '*/', '1=1', 'or 1=1'];
    foreach ($blockWords as $word) {
        if (preg_match('/\b' . preg_quote($word, '/') . '\b/i', $input)) {
            logSecurityAttempt('SQL-BLOCK', $originalInput, $word);
            return ''; // **NATYCHMIAST BLOKUJ**
        }
    }    
    // 2. SPRAWDŹ i BLOKUJ niebezpieczne sekwencje
    foreach ($blockSequences as $seq) {
        if (stripos($input, $seq) !== false) {
            logSecurityAttempt('SQL-BLOCK', $originalInput, $seq);
            return ''; // **NATYCHMIAST BLOKUJ**
        }
    }    
    // 3. SPRAWDŹ i BLOKUJ XSS patterns
    $xssPatterns = [
        '/<script\b/i',
        '/on\w+\s*=/i',
        '/javascript\s*:/i',
        '/vbscript\s*:/i',
        '/alert\s*\(/i',
        '/document\./i',
        '/window\./i'
    ];    
    foreach ($xssPatterns as $xssPattern) {
        if (preg_match($xssPattern, $input)) {
            logSecurityAttempt('XSS-BLOCK', $originalInput, $xssPattern);
            return ''; // **NATYCHMIAST BLOKUJ**
        }
    }    
    // 4. Jeśli przeszedł wszystkie testy - tylko wtedy czyść
    $input = preg_replace('/[^a-zA-Z0-9.@\-_ ]/', '', $input); // Pozwól spacje
    $input = trim($input);    
    // 5. Ostateczna walidacja długości
    if (strlen($input) > 255) {
        logSecurityAttempt('LENGTH-BLOCK', $originalInput, 'Too long');
        return substr($input, 0, 255);
    }
    return $input;
}
function logSecurityAttempt($type, $input, $match): void {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    
    $logDir = 'logs';
    $logFile = $logDir . '/security_attempts.log';
    // *** DEBUG - pokaż pełną ścieżkę ***
    //$fullPath = realpath($logDir . '/security_attempts.log');
    //echo "LOG FILE PATH: " . $fullPath . "<br>";
    
    if (!is_dir($logDir)) {
        mkdir($logDir, 0755, true);
        echo "Created directory: $logDir<br>";
    }
    
    $logMessage = sprintf(
        "[%s] %s Attack: '%s' | Pattern: %s | IP: %s\n",
        date('Y-m-d H:i:s'),
        $type,
        substr($input, 0, 50),
        $match,
        $ip
    );
    
    file_put_contents($logFile, $logMessage, FILE_APPEND | LOCK_EX);
    echo "Logged to: $logFile<br>";
}
?>