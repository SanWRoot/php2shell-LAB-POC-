<?php
/*
 * PHP2Shell local vulnerability checker — CVE-2026-109618 / CVE-2026-109619
 * (C: Serializable branch + E: enum-autoload branch of var_unserializer.re)
 *
 * Drop this file on the server to check (DocumentRoot + browser, or `php check.php`
 * over SSH), read the report, delete it. It is safe: both probes use 1-property
 * objects — no HT resize, no free, no crash, no UAF trigger. Pure correctness
 * oracles on the var_hash-sharing behavior itself.
 *
 * From your own servers only. It tells you whether your ENGINE is vulnerable and
 * whether your APP has unserialize() sinks; it is not a scanner for other
 * people's machines.
 */

error_reporting(0);
if (php_sapi_name() !== 'cli') { header('Content-Type: text/plain; charset=utf-8'); }

function line($s = '') { echo $s, "\n"; }

line('=== PHP2Shell checker: CVE-2026-109618 / CVE-2026-109619 ===');
line('date(UTC): ' . gmdate('Y-m-d H:i') . '   PHP: ' . PHP_VERSION . '   SAPI: ' . php_sapi_name());
line('');

/* -------- Probe 1: C: branch (Serializable) — CVE class since PHP 5.1 -------- */
class P2SCheckC implements Serializable {
    public function serialize(): string { return ''; }
    public function unserialize(string $data): void {
        $GLOBALS['p2s_inner_c'] = unserialize($data);
    }
}
$innerC = 'O:8:"stdClass":1:{s:1:"a";s:6:"nested";}';
$cn = 'P2SCheckC';
$payloadC = 'a:3:{i:0;C:' . strlen($cn) . ':"' . $cn . '":' . strlen($innerC) . ':{' . $innerC . '}'
          . 'i:1;O:8:"stdClass":1:{s:1:"a";s:5:"outer";}'
          . 'i:2;r:3;}';
$vC = @unserialize($payloadC);
$cLeak = is_array($vC) && is_object($vC[2] ?? null) && (($vC[2]->a ?? '') === 'nested');

/* -------- Probe 2: E: branch (enum autoload) — CVE class since PHP 8.1 -------- */
$eLeak = null;
if (PHP_VERSION_ID >= 80100) {
    spl_autoload_register(function ($class) {
        $GLOBALS['p2s_inner_e'] = unserialize('O:8:"stdClass":1:{s:1:"a";s:6:"nested";}');
        eval("enum $class { case On; }");
    });
    $en = 'P2Lazy:On';
    $vE = @unserialize('a:3:{i:0;E:' . strlen($en) . ':"' . $en . '";i:1;O:8:"stdClass":1:{s:1:"a";s:5:"outer";}i:2;r:3;}');
    $eLeak = is_array($vE) && is_object($vE[2] ?? null) && (($vE[2]->a ?? '') === 'nested');
}

line('[1] C: branch (Serializable var_hash sharing):   ' .
     ($cLeak  === true  ? 'VULNERABLE  (outer context leaks into autoloader/Serializable reentry)' :
      ($cLeak === false ? 'not present (fixed or patched build)' : 'probe inconclusive')));
line('[2] E: branch (enum-autoload var_hash sharing):   ' .
     ($eLeak  === true  ? 'VULNERABLE' :
      ($eLeak === false ? 'not present (fixed, or sharing removed)' :
       ($eLeak === null ? 'n/a (PHP < 8.1, no enums)' : 'probe inconclusive'))));
line('');

/* -------- Version guidance -------- */
$fixedUnknown = true; // becomes false when the fixed release numbers are known below
$fixed = array(
    '8.5' => '8.5.12', '8.4' => '8.4.27', '8.3' => '8.3.36', '8.2' => '8.2.35',
);
$ver = PHP_VERSION;
$branch = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
if (isset($fixed[$branch])) {
    $fixedUnknown = false;
    $ok = version_compare($ver, $fixed[$branch], '>=');
    line("[3] version: $ver on branch $branch; fix ships in {$fixed[$branch]} (2026-10-21 OOB release): "
       . ($ok ? 'you are on/above the fixed release' : 'you are BELOW the fixed release'));
}
if ($fixedUnknown) {
    line('[3] version: ' . $ver . ' — no fixed release recorded for this branch; if probes above say'
       . ' VULNERABLE, treat as exposed until the 2026-10-21 security release or later is installed.');
}
line('');

/* -------- App sink scan (same directory tree as this file) -------- */
line('[4] unserialize() sinks under ' . __DIR__ . ' (depth 4, code files only):');
$found = 0;
$rdi = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator(__DIR__, FilesystemIterator::SKIP_DOTS),
    RecursiveIteratorIterator::LEAVES_ONLY);
foreach ($rdi as $f) {
    if ($rdi->getDepth() > 4) continue;
    $ext = strtolower($f->getExtension());
    if (!in_array($ext, array('php', 'inc', 'phtml', 'phar'), true)) continue;
    $txt = @file_get_contents($f->getPathname());
    if ($txt === false || strpos($txt, 'unserialize') === false) continue;
    $userinput = preg_match('/unserialize\s*\([^)]*(\$_(GET|POST|REQUEST|COOKIE|SERVER)|file_get_contents|php:\/\/input)/i', $txt);
    ++$found;
    line('    ' . $f->getPathname() . ($userinput ? '   <-- USER INPUT INTO unserialize(): EXPLOITABLE SINK' : ''));
}
if (!$found) line('    (none)');
line('');
line('Reading the report:');
line(' - engine VULNERABLE + at least one user-input sink = patch PHP NOW; the sink');
line('   converts the engine bug into pre-auth RCE (PHPGGC-class gadget chains apply).');
line(' - engine VULNERABLE, no sink = patch on schedule (phar:// metadata, cache and');
line('   session codecs can hide sinks; treat any unserialize of stored data as a sink).');
line(' - EOL branches (<=8.1) receive no fix; upgrade.');
