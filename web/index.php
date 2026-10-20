<?php
/*
 * mailcow report dashboard - admin-only web page.
 *
 * Lives in mailcow's web root (data/web/<slug>/index.php) and reuses mailcow's own
 * session, admin check (protect_route), CSRF check and page layout (base.twig,
 * Bootstrap 5.1), so it looks and behaves like a native mailcow page. Data comes
 * from _data/dashboard.json written by the collector; direct HTTP access to _data/
 * is denied by the nginx snippet site.mailcow-reports.custom.
 *
 * Files written here (www-data) and read by the container:
 *   _data/settings.json     settings tab
 *   _data/credentials.json  app password (IMAP + SMTP only) of the report mailbox
 *   _data/mailcow.json      domain list (the container has no database access)
 *   _data/ack.json          issues marked as done: {id: {ts, title}}
 *   _data/run-now           apply settings / recount after "done" right away
 * Written by the container: _data/container.json (is _data/ blocked by nginx?), dashboard.json
 */
require_once $_SERVER['DOCUMENT_ROOT'] . '/inc/prerequisites.inc.php';

protect_route(['admin'], ['unauthenticated' => '/admin']);

require_once $_SERVER['DOCUMENT_ROOT'] . '/inc/header.inc.php';
$_SESSION['return_to'] = $_SERVER['REQUEST_URI'];

$data_dir = __DIR__ . '/_data';
$data_file = $data_dir . '/dashboard.json';
$settings_file = $data_dir . '/settings.json';
$ack_file = $data_dir . '/ack.json';
$cred_file = $data_dir . '/credentials.json';
$app_name = 'mailcow-report-dashboard';

$read_json = function ($f) {
  $v = is_readable($f) ? json_decode((string) file_get_contents($f), true) : null;
  return is_array($v) ? $v : [];
};
$write_json = function ($file, $value) use ($data_dir) {
  if (!is_dir($data_dir) || !is_writable($data_dir)) { return false; }
  $tmp = tempnam($data_dir, '.tmp-');
  if ($tmp === false) { return false; }
  if (file_put_contents($tmp, json_encode($value, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) === false) {
    @unlink($tmp);
    return false;
  }
  @chmod($tmp, 0640);
  return rename($tmp, $file);
};

$data = $read_json($data_file) ?: null;
$settings = $read_json($settings_file);
$acks = $read_json($ack_file);
$container = $read_json($data_dir . '/container.json');
$protected = !empty($container['protected']);   // nginx blocks _data/ (checked by the container)
// texts: lang/<mailcow locale>.json on top of lang/en-gb.json. The page follows the language chosen in
// mailcow (flag menu / browser); the "language" setting only applies to the alert mails.
$lang_files = [];
foreach ((array) glob(__DIR__ . '/lang/*.json') as $f) {
  if (preg_match('/^[a-z]{2}-[a-z]{2}$/', basename($f, '.json'))) { $lang_files[basename($f, '.json')] = $f; }
}
$pick_lang = function ($code) use ($lang_files) {
  $code = strtolower((string) $code);
  if (isset($lang_files[$code])) { return $code; }
  foreach ($lang_files as $c => $f) { if (substr($c, 0, 2) === substr($code, 0, 2)) { return $c; } }
  return 'en-gb';
};
$lang_code = $pick_lang($_SESSION['mailcow_locale'] ?? 'en-gb');
$L = $read_json(__DIR__ . '/lang/en-gb.json');
if ($lang_code !== 'en-gb') {
  foreach ($read_json($lang_files[$lang_code]) as $k => $v) { if (is_string($v) && $v !== '') { $L[$k] = $v; } }
}
$lang_names = [];
foreach ($lang_files as $c => $f) { $lang_names[$c] = $read_json($f)['_name'] ?? $c; }
asort($lang_names);
$alert_lang = $pick_lang(['de' => 'de-de', 'en' => 'en-gb'][$settings['language'] ?? ''] ?? ($settings['language'] ?? 'en-gb'));
// fill {placeholders}; a missing translation key falls back to the key itself
$tx = function ($key, $p = []) use (&$L) {
  $text = $L[$key] ?? $key;
  foreach ((array) $p as $k => $v) { $text = str_replace('{' . $k . '}', (string) $v, $text); }
  return $text;
};
$base_url = strtok($_SERVER['REQUEST_URI'], '?#');

// all mailcow domains incl. alias domains, and all mailboxes (admin session → full access)
$all_domains = [];
$all_mailboxes = [];
foreach ((array) mailbox('get', 'domains') as $dom) {
  $all_domains[] = $dom;
  foreach ((array) mailbox('get', 'alias_domains', $dom) as $ad) { $all_domains[] = $ad; }
  foreach ((array) mailbox('get', 'mailboxes', $dom) as $mb) { $all_mailboxes[] = $mb; }
}
$all_domains = array_values(array_unique($all_domains));
$main_domains = array_values(array_filter((array) mailbox('get', 'domains')));
sort($all_mailboxes);

$flash = function ($type, $msg) { $_SESSION['return'][] = ['type' => $type, 'msg' => $msg]; };

// password that passes any mailcow password policy (upper/lower case, digit, special char)
$strong_pw = function () { return bin2hex(random_bytes(16)) . 'Aa1-' . bin2hex(random_bytes(8)); };
// app password for the report mailbox, IMAP + SMTP only; replaces the one this page created before
$setup_access = function ($mb) use (&$settings, $protected, $app_name, $strong_pw, $write_json, $cred_file) {
  if (!$protected) { return false; }
  foreach (array_unique(array_filter([$settings['mailbox'] ?? '', $mb])) as $box) {
    foreach ((array) app_passwd('get', ['username' => $box]) as $ap) {
      if (($ap['name'] ?? '') === $app_name) { app_passwd('delete', ['id' => [$ap['id']]]); }
    }
  }
  $pw = $strong_pw();
  $ok = app_passwd('add', ['username' => $mb, 'app_name' => $app_name, 'app_passwd' => $pw, 'app_passwd2' => $pw,
                           'active' => '1', 'protocols' => ['imap_access', 'smtp_access']]);
  return $ok !== false && $write_json($cred_file, ['user' => $mb, 'password' => $pw]);
};
// Apps menu entry via mailcow's own customize(); existing entries are kept
$add_app_link = function () use (&$L) {
  $link = '/' . trim((string) ($GLOBALS['container']['slug'] ?? basename(__DIR__)), '/') . '/';
  $apps = $hrefs = $user_hrefs = $hide = [];
  foreach ((array) customize('get', 'app_links') as $entry) {
    foreach ((array) $entry as $name => $a) {
      if (($a['link'] ?? '') === $link) { return true; }
      $apps[] = $name; $hrefs[] = $a['link'] ?? ''; $user_hrefs[] = $a['user_link'] ?? ($a['link'] ?? '');
      $hide[] = empty($a['hide']) ? '0' : '1';
    }
  }
  $apps[] = $L['app_name']; $hrefs[] = $link; $user_hrefs[] = $link; $hide[] = '1';   // not on the login page; admin-only display via CSS (see run.py)
  return customize('edit', 'app_links', ['app' => $apps, 'href' => $hrefs, 'user_href' => $user_hrefs, 'hide' => $hide]) !== false;
};
$configured = !empty($settings['mailbox']) && is_readable($cred_file);
// the container has no database access: hand it the domain list
if ($protected && ($read_json($data_dir . '/mailcow.json')['domains'] ?? null) !== $all_domains) {
  $write_json($data_dir . '/mailcow.json', ['domains' => $all_domains]);
  @touch($data_dir . '/run-now');               // recount with the new domain list
}

// ---------------------------------------------------------------- actions (POST)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['mr_action'])) {
  $action = $_POST['mr_action'];
  $go_tab = 'overview';
  // mailcow validates and consumes csrf_token for every POST; a token still present = check failed
  if (isset($_POST['csrf_token'])) {
    $flash('danger', 'CSRF check failed');
  }
  elseif (($_SESSION['mailcow_cc_api_access'] ?? '') === 'ro') {   // read-only API key: look, don't touch
    $flash('danger', 'read-only API key');
  }
  elseif ($action === 'save') {
    $go_tab = 'settings';
    $mb = strtolower(trim($_POST['mailbox'] ?? ''));
    $alert = array_values(array_filter(array_map('trim', preg_split('/[\s,;]+/', $_POST['alert_to'] ?? ''))));
    $ips_mode = ($_POST['own_ips_mode'] ?? 'auto') === 'manual' ? 'manual' : 'auto';
    $ips = array_values(array_filter(array_map('trim', preg_split('/[\s,;]+/', $_POST['own_ips'] ?? ''))));
    $lang = isset($lang_files[$_POST['language'] ?? '']) ? $_POST['language'] : 'en-gb';
    $run_time = preg_match('/^([01]\d|2[0-3]):[0-5]\d$/', $_POST['run_time'] ?? '') ? $_POST['run_time'] : '07:30';
    $errors = [];
    if (!in_array($mb, $all_mailboxes, true)) { $errors[] = 'mailbox: ' . htmlspecialchars($mb); }
    foreach ($alert as $a) {
      if (!in_array(strtolower($a), $all_mailboxes, true) || strtolower($a) === $mb) { $errors[] = 'alert_to: ' . htmlspecialchars($a); }
    }
    if (!$alert) { $errors[] = 'alert_to'; }
    foreach ($ips as $ip) { if (!filter_var($ip, FILTER_VALIDATE_IP)) { $errors[] = 'IP: ' . htmlspecialchars($ip); } }
    if ($ips_mode === 'manual' && !$ips) { $errors[] = 'IP'; }
    if (!$protected) { $errors[] = $L['not_protected_t'] ?? 'nginx'; }
    elseif (!$errors && ($mb !== ($settings['mailbox'] ?? '') || !is_readable($cred_file)) && !$setup_access($mb)) {
      $errors[] = 'app password';
    }
    if ($errors) {
      $flash('danger', $L['invalid'] . ': ' . implode(', ', $errors));
    } elseif ($write_json($settings_file, ['mailbox' => $mb, 'alert_to' => implode(',', $alert), 'own_ips' => $ips,
                                          'own_ips_mode' => $ips_mode, 'language' => $lang, 'run_time' => $run_time])) {
      @touch($data_dir . '/run-now');   // apply right away (e.g. watch a newly selected mailbox)
      $flash('success', $L['saved']);
    } else {
      $flash('danger', 'Cannot write ' . basename($settings_file));
    }
  }
  elseif ($action === 'setup') {
    $go_tab = 'settings';                         // DNS records are shown there
    $errors = [];
    if (!$protected) { $errors[] = $L['not_protected_t']; }
    if (($_POST['mb_mode'] ?? '') === 'new') {
      $local = strtolower(trim($_POST['local_part'] ?? ''));
      $dom = strtolower(trim($_POST['domain'] ?? ''));
      $mb = $local . '@' . $dom;
      if (!preg_match('/^[a-z0-9._-]{1,64}$/', $local) || !in_array($dom, $main_domains, true)) { $errors[] = $L['invalid_address']; }
      elseif (in_array($mb, $all_mailboxes, true)) { $errors[] = 'mailbox: ' . htmlspecialchars($mb); }
    } else {
      $mb = strtolower(trim($_POST['mailbox'] ?? ''));
      if (!in_array($mb, $all_mailboxes, true)) { $errors[] = 'mailbox: ' . htmlspecialchars($mb); }
    }
    $alert = array_values(array_filter(array_map('trim', preg_split('/[\s,;]+/', strtolower($_POST['alert_to'] ?? '')))));
    foreach ($alert as $a) { if (!in_array($a, $all_mailboxes, true) || $a === $mb) { $errors[] = 'alert_to: ' . htmlspecialchars($a); } }
    if (!$alert) { $errors[] = $L['alert_to']; }
    if (!$errors && ($_POST['mb_mode'] ?? '') === 'new') {
      $pw = $strong_pw();
      if (mailbox('add', 'mailbox', ['local_part' => $local, 'domain' => $dom, 'name' => 'DMARC/TLS reports',
            'quota' => 200, 'password' => $pw, 'password2' => $pw, 'active' => '1', 'force_pw_update' => '0',
            'tls_enforce_in' => '0', 'tls_enforce_out' => '0']) === false) { $errors[] = 'mailbox'; }
    }
    if (!$errors && !$setup_access($mb)) { $errors[] = 'app password'; }
    if (!$errors && !$write_json($settings_file, ['mailbox' => $mb, 'alert_to' => implode(',', $alert), 'own_ips' => [],
          'own_ips_mode' => 'auto', 'language' => $lang_code, 'run_time' => '07:30'])) { $errors[] = basename($settings_file); }
    if ($errors) {
      $flash('danger', $L['invalid'] . ': ' . implode(', ', $errors));
      $go_tab = 'overview';
    } else {
      if (!empty($_POST['app_link']) && !$add_app_link()) { $flash('warning', 'Apps menu'); }
      @touch($data_dir . '/run-now');
      $flash('success', $L['setup_done']);
    }
  }
  elseif ($action === 'create_mailbox') {
    $go_tab = 'settings';
    $local = strtolower(trim($_POST['local_part'] ?? ''));
    $dom = strtolower(trim($_POST['domain'] ?? ''));
    if (!$protected) {
      $flash('danger', $L['not_protected_t'] ?? 'nginx');
    } elseif (!preg_match('/^[a-z0-9._-]{1,64}$/', $local) || !in_array($dom, $main_domains, true)) {
      $flash('danger', $L['invalid_address']);
    } else {
      $pw = $strong_pw();   // nobody logs in with it; the container uses an app password
      $ok = mailbox('add', 'mailbox', [
        'local_part' => $local, 'domain' => $dom, 'name' => 'DMARC/TLS reports (mailcow-report-dashboard)',
        'quota' => 200, 'password' => $pw, 'password2' => $pw, 'active' => '1',
        'force_pw_update' => '0', 'tls_enforce_in' => '0', 'tls_enforce_out' => '0',
      ]);
      if ($ok !== false && $setup_access($local . '@' . $dom)) {
        $new = $settings; $new['mailbox'] = $local . '@' . $dom;
        $write_json($settings_file, array_intersect_key($new, array_flip(['mailbox', 'alert_to', 'own_ips', 'own_ips_mode', 'language', 'run_time'])));
        @touch($data_dir . '/run-now');
      }
    }
  }
  elseif (in_array($action, ['ack', 'ack_all', 'unack'], true)) {
    // "done" = hide until something new happens; the collector only counts reports received later
    $ids = $action === 'ack_all' ? (array) ($_POST['ids'] ?? []) : [(string) ($_POST['id'] ?? '')];
    foreach ($ids as $id) {
      if (!preg_match('/^[a-z0-9_:.-]{1,80}$/', (string) $id)) { continue; }
      if ($action === 'unack') {
        unset($acks[$id]);
      } else {
        $acks[$id] = ['ts' => time(), 'title' => mb_substr((string) ($_POST['title'][$id] ?? $_POST['title'] ?? $id), 0, 200),
                      'count' => (int) ($_POST['count'][$id] ?? $_POST['count'] ?? 0)];
      }
    }
    if ($write_json($ack_file, $acks)) {
      @touch($data_dir . '/run-now');   // recount the remaining issues right away
    } else {
      $flash('danger', 'Cannot write ' . basename($ack_file));
    }
  }
  header('Location: ' . $base_url . '#' . $go_tab);
  exit();
}

// ---------------------------------------------------------------- public IPs (like mailcow's DNS check)
$detected_ips = [];
foreach (['SNAT_TO_SOURCE' => [CURL_IPRESOLVE_V4, 'http://ip4.mailcow.email'], 'SNAT6_TO_SOURCE' => [CURL_IPRESOLVE_V6, 'http://ip6.mailcow.email']] as $env => [$res, $url]) {
  $ip = trim((string) getenv($env));
  if (!filter_var($ip, FILTER_VALIDATE_IP)) {
    $ch = curl_init($url);
    curl_setopt_array($ch, [CURLOPT_IPRESOLVE => $res, CURLOPT_RETURNTRANSFER => 1, CURLOPT_CONNECTTIMEOUT => 3, CURLOPT_TIMEOUT => 4]);
    $ip = trim((string) curl_exec($ch));
    curl_close($ch);
  }
  if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) { $detected_ips[] = $ip; }
}

// ---------------------------------------------------------------- schedule
$run_time = $settings['run_time'] ?? '07:30';
$next_run = strtotime(date('Y-m-d') . ' ' . $run_time);
$last_daily = $data['last_daily'] ?? 0;
if (($last_daily && date('Y-m-d', $last_daily) === date('Y-m-d')) || $next_run < time() - 3600) { $next_run = strtotime('+1 day', $next_run); }
$run_pending = file_exists($data_dir . '/run-now');

// ---------------------------------------------------------------- DNS assistant
$dns = [];
$report_mb = $settings['mailbox'] ?? '';
$report_dom = $report_mb ? substr(strrchr($report_mb, '@'), 1) : '';
$fresh = !empty($_GET['fresh']);
if ($report_mb) {
  // ?fresh=1 ("Check again"): bypass mailcow's caching resolver (unbound) and ask a public
  // resolver via DNS-over-HTTPS, so DNS changes show up immediately
  $txt = function ($name) use ($fresh) {
    $out = [];
    if ($fresh) {
      $ch = curl_init('https://cloudflare-dns.com/dns-query?type=TXT&name=' . rawurlencode($name));
      curl_setopt_array($ch, [CURLOPT_HTTPHEADER => ['accept: application/dns-json'], CURLOPT_RETURNTRANSFER => 1,
                              CURLOPT_CONNECTTIMEOUT => 3, CURLOPT_TIMEOUT => 5]);
      $res = json_decode((string) curl_exec($ch), true);
      curl_close($ch);
      if (is_array($res) && isset($res['Status'])) {
        foreach ($res['Answer'] ?? [] as $a) {
          if (($a['type'] ?? 0) !== 16) { continue; }
          preg_match_all('/"((?:[^"\\\\]|\\\\.)*)"/', $a['data'], $m);   // TXT = one or more quoted strings
          $v = $m[1] ? implode('', $m[1]) : $a['data'];
          $v = preg_replace_callback('/\\\\(\d{3})/', function ($x) { return chr((int) $x[1]); }, $v);   // \DDD (decimal)
          $out[] = preg_replace('/\\\\(.)/', '$1', $v);
        }
        return $out;
      }
    }
    foreach ((array) @dns_get_record($name, DNS_TXT) as $r) { $out[] = $r['txt'] ?? implode('', $r['entries'] ?? []); }
    return $out;
  };
  $want = 'mailto:' . $report_mb;
  foreach ($all_domains as $d) {
    $tls = $txt('_smtp._tls.' . $d);
    $dmarc_all = $txt('_dmarc.' . $d);
    $dmarc = array_values(array_filter($dmarc_all, function ($v) { return stripos(ltrim($v), 'v=DMARC1') === 0; }));
    $dmarc_invalid = array_values(array_diff($dmarc_all, $dmarc));   // e.g. the name pasted into the value
    $tls_ok = (bool) array_filter($tls, function ($v) use ($want) { return stripos($v, 'v=TLSRPTv1') !== false && stripos($v, $want) !== false; });
    $dmarc_cur = $dmarc[0] ?? '';
    if (!$dmarc_cur && $dmarc_invalid) {           // repair the broken value instead of proposing p=none
      $fixed = preg_replace('/^.*?(v=DMARC1)/is', '$1', $dmarc_invalid[0]);
      $dmarc_cur = stripos($fixed, 'v=DMARC1') === 0 ? $fixed : '';
    }
    $dmarc_ok = $dmarc_cur && stripos($dmarc_cur, $want) !== false && count($dmarc) === 1 && !$dmarc_invalid;
    if ($dmarc_cur && stripos($dmarc_cur, $want) !== false) {
      $dmarc_suggest = $dmarc_cur;
    } elseif ($dmarc_cur) {
      $dmarc_suggest = preg_match('/rua=([^;]*)/i', $dmarc_cur)
        ? preg_replace('/rua=([^;]*)/i', 'rua=$1,' . $want, $dmarc_cur, 1)
        : rtrim($dmarc_cur, '; ') . '; rua=' . $want;
    } else {
      $dmarc_suggest = 'v=DMARC1; p=none; rua=' . $want;
    }
    $auth_needed = strcasecmp($d, $report_dom) !== 0;
    $auth_name = $d . '._report._dmarc.' . $report_dom;
    $auth_ok = !$auth_needed || (bool) array_filter($txt($auth_name), function ($v) { return stripos($v, 'v=DMARC1') === 0; });
    $todo = [];
    if (!$tls_ok) { $todo[] = ['zone' => $d, 'name' => '_smtp._tls', 'value' => 'v=TLSRPTv1; rua=' . $want, 'action' => $tls ? 'edit' : 'add', 'current' => implode(' | ', $tls)]; }
    if (!$dmarc_ok) { $todo[] = ['zone' => $d, 'name' => '_dmarc', 'value' => $dmarc_suggest, 'action' => ($dmarc || $dmarc_invalid) ? 'edit' : 'add', 'current' => implode(' | ', array_merge($dmarc, $dmarc_invalid))]; }
    if (!$auth_ok) { $todo[] = ['zone' => $report_dom, 'name' => $d . '._report._dmarc', 'value' => 'v=DMARC1', 'action' => 'add', 'current' => '']; }
    $dns[] = ['domain' => $d, 'todo' => $todo, 'tls_ok' => $tls_ok, 'dmarc_ok' => $dmarc_ok,
              'dmarc_state' => $dmarc_ok ? 'ok' : (($dmarc_invalid || count($dmarc) > 1) ? 'invalid' : 'missing'),
              'auth_needed' => $auth_needed, 'auth_ok' => $auth_ok];
  }
}
$dns_by_domain = [];
$dns_todo = [];
foreach ($dns as $r) {
  $dns_by_domain[$r['domain']] = $r;
  foreach ($r['todo'] as $x) { $dns_todo[] = $x; }
}
$dns_ok_n = count(array_filter($dns, function ($r) { return !$r['todo']; }));


// ---------------------------------------------------------------- collector texts (language keys) → viewer's language
$why = function ($items) use ($tx, &$L) {
  $out = [];
  foreach ((array) $items as $w) {
    if (is_string($w)) { $out[] = $w; continue; }               // dashboard.json from an older collector
    $k = $w['k'] ?? '?';
    $t = $tx(isset($L[$k]) ? $k : ($w['fb'] ?? $k), $w['p'] ?? []);
    $out[] = $t . (!empty($w['c']) ? ' (' . $w['c'] . ')' : '');
  }
  return $out;
};
foreach (($data['own_fail_causes'] ?? []) as $n => $c) { $data['own_fail_causes'][$n]['why'] = $why($c['why'] ?? []); }
foreach (($data['recent'] ?? []) as $n => $r) {
  foreach (($r['rows'] ?? []) as $m => $row) {
    if (isset($row['why'])) { $data['recent'][$n]['rows'][$m]['why'] = $why($row['why']); }
  }
}

// ---------------------------------------------------------------- issues (collector + web-only ones)
$issues = [];
foreach (($data['issues'] ?? []) as $i) {
  $a = $acks[$i['id'] ?? ''] ?? null;
  if ($a && ($a['ts'] ?? 0) >= ($i['last'] ?? 0)) { continue; }   // done; collector recount pending
  if (isset($i['text'])) {
    foreach (['title', 'what', 'todo'] as $f) { $i[$f] = $tx($i['text'][$f] ?? '', $i['p'] ?? []); }
  }
  $i['ackable'] = true;
  $issues[] = $i;
}
if (!empty($data['alert_error'])) {
  array_unshift($issues, ['id' => 'alert_error', 'severity' => 'error', 'ackable' => false, 'title' => $L['alert_failed_t'],
                          'what' => str_replace('{r}', $data['alert_error'], $L['alert_failed_w']), 'todo' => $L['alert_failed_d']]);
}
$dns_bad = count($dns) - $dns_ok_n;
if ($dns_bad) {
  $issues[] = ['id' => 'dns', 'severity' => 'warn', 'ackable' => false, 'title' => str_replace('{n}', $dns_bad, $L['dns_issue_t']),
               'what' => $L['dns_issue_w'], 'todo' => $L['dns_issue_d'], 'link' => '#settings'];
}
$unproc = (int) ($data['unprocessed'] ?? 0);
if ($unproc > (int) ($acks['unprocessed']['count'] ?? 0)) {
  $issues[] = ['id' => 'unprocessed', 'severity' => 'info', 'ackable' => true, 'count' => $unproc,
               'title' => str_replace('{n}', $unproc, $L['unproc_t']), 'what' => str_replace('{mb}', $report_mb, $L['unproc_w']), 'todo' => $L['unproc_d']];
}
$rank = ['error' => 3, 'warn' => 2, 'info' => 1, 'ok' => 0];
usort($issues, function ($a, $b) use ($rank) { return ($rank[$b['severity']] ?? 0) <=> ($rank[$a['severity']] ?? 0); });
$open_n = count(array_filter($issues, function ($i) { return in_array($i['severity'], ['error', 'warn'], true); }));
$worst = 0;
foreach ($issues as $i) { $worst = max($worst, $rank[$i['severity']] ?? 0); }
$has_open = function ($prefix) use ($issues) {
  foreach ($issues as $i) { if (strpos($i['id'] ?? '', $prefix) === 0 && in_array($i['severity'], ['error', 'warn'], true)) { return true; } }
  return false;
};
$kpi = $data['kpi'] ?? [];
$pct_badge = function ($pct, $open) {   // colour only signals what is still open
  if ($pct === null) { return 'bg-secondary'; }
  return !$open ? 'bg-success' : ($pct >= 95 ? 'bg-warning text-dark' : 'bg-danger');
};
$acked_list = [];
foreach ($acks as $id => $a) { $acked_list[] = ['id' => $id, 'title' => $a['title'] ?? $id, 'ts' => $a['ts'] ?? 0]; }
usort($acked_list, function ($a, $b) { return $b['ts'] <=> $a['ts']; });

// ---------------------------------------------------------------- weekly chart (stacked SVG bars, no JS)
$series_keys = ['own_pass' => '#28a745', 'own_fail' => '#dc3545', 'spoof' => '#fd7e14', 'tls_ok' => '#17a2b8', 'tls_fail' => '#6f1d1b'];
$chart = null;
if ($data && !empty($data['series'])) {
  $max = 1; $has = false;
  foreach ($data['series'] as $w) {
    $sum = 0;
    foreach ($series_keys as $k => $c) { $sum += $w[$k] ?? 0; }
    $max = max($max, $sum); $has = $has || $sum > 0;
  }
  $bars = []; $bw = 14; $gap = 4; $h = 120;
  foreach ($data['series'] as $i => $w) {
    $y = $h; $parts = [];
    foreach ($series_keys as $k => $color) {
      $ph = round(($w[$k] ?? 0) / $max * ($h - 2), 1);
      if ($ph > 0) { $ph = max($ph, 1.5); $y -= $ph; $parts[] = ['y' => $y, 'h' => $ph, 'color' => $color]; }
    }
    $bars[] = ['x' => $i * ($bw + $gap), 'parts' => $parts, 'week' => $w['week'], 'w' => $w, 'label' => $i % 4 === 0];
  }
  $chart = ['bars' => $bars, 'width' => count($bars) * ($bw + $gap), 'height' => $h, 'bw' => $bw, 'max' => $max, 'has' => $has];
}

$tpl = <<<'TWIG'
{% extends 'base.twig' %}
{% block content %}
<style>
  .mr-chart{width:100%;height:auto;max-height:200px} .mr-chart text{fill:currentColor;opacity:.6;font-size:9px}
  .mr-legend span{margin-right:1rem;white-space:nowrap} .mr-legend i{display:inline-block;width:.8rem;height:.8rem;margin-right:.3rem;vertical-align:-1px}
  .mr-sm{font-size:.85em} .mr-nowrap{white-space:nowrap} details summary{cursor:pointer}
  .mr-issue-what{font-size:.9em;opacity:.8}
</style>

{% if not protected %}
<div class="alert alert-warning"><b>{{ L.not_protected_t }}</b><br>{{ L.not_protected_d }}<br><code>docker compose restart nginx-mailcow</code></div>
{% endif %}
{% if not configured %}
<div class="card mb-4 border-primary"><div class="card-header fs-5"><i class="bi bi-magic me-2"></i>{{ L.setup_t }}</div><div class="card-body">
  <p class="text-muted">{{ L.setup_intro }}</p>
  <div class="alert alert-info py-2"><i class="bi bi-bookmark me-1"></i>{{ L.setup_bookmark }} <code class="user-select-all">https://{{ host }}{{ base_url }}</code></div>
  {% if protected %}
  <form method="post"><input type="hidden" name="mr_action" value="setup">
    <div class="row mb-3"><label class="col-sm-3 col-form-label">{{ L.mailbox }}</label><div class="col-sm-9">
      <div class="form-check"><input class="form-check-input" type="radio" name="mb_mode" value="new" id="mbnew" checked>
        <label class="form-check-label" for="mbnew">{{ L.setup_new_mb }}</label></div>
      <div class="d-flex align-items-center gap-2 ms-4 mb-2"><input name="local_part" class="form-control" style="max-width:12rem" value="reports" pattern="[a-z0-9._-]+">
        <span>@</span><select name="domain" class="form-control" style="max-width:20rem">{% for dm in main_domains %}<option>{{ dm }}</option>{% endfor %}</select></div>
      <div class="form-check"><input class="form-check-input" type="radio" name="mb_mode" value="existing" id="mbold">
        <label class="form-check-label" for="mbold">{{ L.setup_existing_mb }}</label></div>
      <div class="ms-4"><select name="mailbox" class="form-control" style="max-width:33rem">{% for mb in mailboxes %}<option value="{{ mb }}">{{ mb }}</option>{% endfor %}</select></div>
      <small class="form-text d-block">{{ L.setup_mb_help }}</small></div></div>
    <div class="row mb-3"><label class="col-sm-3 col-form-label">{{ L.alert_to }}</label><div class="col-sm-9">
      <input name="alert_to" class="form-control" style="max-width:33rem" required><small class="form-text d-block">{{ L.alert_help }}</small></div></div>
    <div class="row mb-3"><div class="col-sm-9 offset-sm-3"><div class="form-check">
      <input class="form-check-input" type="checkbox" name="app_link" value="1" id="applink" checked>
      <label class="form-check-label" for="applink">{{ L.setup_app_link|replace({'{name}': L.app_name}) }}</label></div></div></div>
    <div class="row"><div class="col-sm-9 offset-sm-3"><button class="btn btn-success"><i class="bi bi-check-lg me-1"></i>{{ L.setup_go }}</button></div></div>
  </form>
  {% endif %}
</div></div>
{% else %}
<ul class="nav nav-tabs" role="tablist" id="mr-tabs">
  {% for id, label in {'overview': L.overview, 'history': L.history, 'errors': L.errors, 'senders': L.senders, 'reports': L.reports, 'settings': L.settings} %}
  <li class="nav-item" role="presentation"><button class="nav-link {{ loop.first ? 'active' }}" data-bs-toggle="tab" data-bs-target="#tab-{{ id }}" type="button" role="tab">
    {{ label }}{% if id == 'overview' and open_n %} <span class="badge bg-danger">{{ open_n }}</span>{% endif %}{% if id == 'settings' and dns_bad %} <span class="badge bg-warning text-dark">!</span>{% endif %}</button></li>
  {% endfor %}
</ul>

<div class="row"><div class="col-md-12"><div class="tab-content" style="padding-top:20px">

{# ================================================================ overview #}
<div role="tabpanel" class="tab-pane active" id="tab-overview">
  <div class="card mb-4">
    <div class="card-header d-flex align-items-center fs-5"><span>{{ L.status }}</span>
      <span class="ms-auto mr-sm text-muted">{% if d %}{{ L.updated }} {{ d.generated|date('d.m.Y H:i') }}{% endif %}</span></div>
    <div class="card-body">
      {% if not d or not d.total_reports %}
        <p class="mb-0"><span class="badge bg-secondary fs-6">{{ L.no_reports_yet }}</span></p>
        <p class="text-muted mt-2 mb-0">{{ L.no_reports_hint }}</p>
      {% else %}
      <div class="row">
        <div class="col-md-6">
          <table class="table table-striped w-100 mb-md-0"><tbody>
            <tr><td>{{ L.state }}</td><td>{% if open_n == 0 %}<span class="badge bg-success fs-6">{{ L.all_ok }}</span>{% else %}<span class="badge {{ worst >= 3 ? 'bg-danger' : 'bg-warning text-dark' }} fs-6">{{ open_n == 1 ? L.open_1 : L.open_n|replace({'{n}': open_n}) }}</span>{% endif %}</td></tr>
            <tr><td>{{ L.own_genuine }}</td><td>{% if kpi.own_pct is null %}–{% else %}<span class="badge {{ own_badge }}">{{ kpi.own_pct|number_format(1, dec, thou) }} %</span> <span class="text-muted mr-sm">{{ kpi.own_ok }} {{ L.of }} {{ kpi.own_total }}</span>{% endif %}</td></tr>
            <tr><td>{{ L.tls_ok }}</td><td>{% if kpi.tls_pct is null %}–{% else %}<span class="badge {{ tls_badge }}">{{ kpi.tls_pct|number_format(1, dec, thou) }} %</span> <span class="text-muted mr-sm">{{ kpi.tls_total - kpi.tls_bad }} {{ L.of }} {{ kpi.tls_total }}</span>{% endif %}</td></tr>
            <tr><td>{{ L.spoof_blocked }}</td><td><b>{{ kpi.spoofed|default(0) }}</b>{% if kpi.forwarded|default(0) %} <span class="text-muted mr-sm">· {{ L.forwarded_n }}: {{ kpi.forwarded }}</span>{% endif %}</td></tr>
            <tr><td>{{ L.reports_30 }}</td><td>{{ kpi.reports30|default(0) }} <span class="text-muted mr-sm">({{ L.last_30 }})</span></td></tr>
          </tbody></table>
        </div>
        <div class="col-md-6">
          <table class="table table-striped w-100 mb-2"><tbody>
            <tr><td>{{ L.last_run }}</td><td>{{ d.last_run ? d.last_run.ts|date('d.m.Y H:i') : '–' }}</td></tr>
            <tr><td>{{ L.next_run }}</td><td>{{ next_run|date('d.m.Y H:i') }}</td></tr>
            <tr><td>{{ L.dns_state }}</td><td>{% if dns|length %}<span class="badge {{ dns_bad ? 'bg-warning text-dark' : 'bg-success' }}">{{ L.dns_n_ok|replace({'{ok}': dns_ok_n, '{n}': dns|length}) }}</span>{% else %}–{% endif %}</td></tr>
          </tbody></table>
          <div class="text-muted mr-sm">{% if run_pending %}<span class="spinner-border spinner-border-sm me-1"></span>{{ L.run_pending }}{% else %}{{ L.live_hint }}{% endif %}</div>
        </div>
      </div>
      {% endif %}
    </div>
  </div>

  <div class="card mb-4">
    <div class="card-header d-flex align-items-center fs-5"><span>{{ L.issues }}</span>
      {% set ackable = issues|filter(i => i.ackable) %}
      {% if ackable|length > 1 %}
      <form method="post" class="ms-auto"><input type="hidden" name="mr_action" value="ack_all">
        {% for i in ackable %}<input type="hidden" name="ids[]" value="{{ i.id }}"><input type="hidden" name="title[{{ i.id }}]" value="{{ i.title }}"><input type="hidden" name="count[{{ i.id }}]" value="{{ i.count|default(0) }}">{% endfor %}
        <button class="btn btn-sm btn-success"><i class="bi bi-check2-all me-1"></i>{{ L.ack_all }}</button></form>
      {% endif %}
    </div>
    {% if not issues %}
      <div class="card-body"><span class="text-success"><i class="bi bi-check-circle me-1"></i>{{ L.no_issues }}</span></div>
    {% else %}
    <div class="table-responsive"><table class="table table-striped w-100 mb-0 align-middle">
      <thead><tr><th>{{ L.severity }}</th><th>{{ L.issue }}</th><th>{{ L.todo }}</th><th class="mr-nowrap">{{ L.period }}</th><th></th></tr></thead><tbody>
      {% for i in issues %}<tr>
        <td><span class="badge {{ {'error': 'bg-danger', 'warn': 'bg-warning text-dark', 'info': 'bg-info', 'ok': 'bg-success'}[i.severity] }}">{{ attribute(L, 'sev_' ~ i.severity) }}</span></td>
        <td><b>{{ i.title }}</b><div class="mr-issue-what">{{ i.what }}</div></td>
        <td class="mr-sm">{{ i.todo }}{% if i.link is defined %} <a href="{{ i.link }}" class="mr-tab-link">{{ L.dns_t }} ›</a>{% endif %}</td>
        <td class="mr-sm mr-nowrap">{% if i.first is defined and i.first %}{{ i.first|date('d.m.') }}{% if i.last != i.first %}–{{ i.last|date('d.m.') }}{% endif %}{% endif %}</td>
        <td class="text-end">{% if i.ackable %}<form method="post"><input type="hidden" name="mr_action" value="ack"><input type="hidden" name="id" value="{{ i.id }}"><input type="hidden" name="title" value="{{ i.title }}"><input type="hidden" name="count" value="{{ i.count|default(0) }}">
          <button class="btn btn-sm btn-light"><i class="bi bi-check2 me-1"></i>{{ L.ack }}</button></form>{% else %}<span class="text-muted mr-sm">{{ L.not_ackable }}</span>{% endif %}</td>
      </tr>{% endfor %}
    </tbody></table></div>
    {% endif %}
    {% if acked %}
    <div class="card-footer mr-sm"><details><summary>{{ L.acked|replace({'{n}': acked|length}) }}</summary>
      <p class="text-muted mt-2 mb-2">{{ L.ack_hint }}</p>
      <table class="table table-sm mb-0">{% for a in acked %}<tr><td>{{ a.title }}</td><td class="text-muted mr-nowrap">{{ L.acked_at }} {{ a.ts|date('d.m.Y H:i') }}</td>
        <td class="text-end"><form method="post"><input type="hidden" name="mr_action" value="unack"><input type="hidden" name="id" value="{{ a.id }}"><button class="btn btn-sm btn-light">{{ L.unack }}</button></form></td></tr>{% endfor %}</table>
    </details></div>
    {% endif %}
  </div>

  {% if d %}
  <div class="card mb-4">
    <div class="card-header fs-5">{{ L.domains }} <span class="mr-sm text-muted">({{ L.last_30 }})</span></div>
    <div class="table-responsive"><table class="table table-striped w-100 mb-0 align-middle">
      <thead><tr><th>{{ L.domain }}</th><th>{{ L.status }}</th><th>{{ L.dns }}</th><th class="text-end">{{ L.own_mail }} {{ L.ok }} / {{ L.failed }}</th><th class="text-end">{{ L.tls }} {{ L.ok }} / {{ L.failed }}</th><th class="text-end">{{ L.spoofed }}</th><th>{{ L.policy }}</th><th>{{ L.last_report }}</th></tr></thead>
      <tbody>{% for x in d.domains %}{% set dr = dns_by_domain[x.domain]|default(null) %}<tr>
        <td><b>{{ x.domain }}</b>{% if not x.configured %} <span class="badge bg-secondary">{{ L.not_configured }}</span>{% endif %}</td>
        <td><span class="badge {{ {'red': 'bg-danger', 'green': 'bg-success', 'grey': 'bg-secondary'}[x.status] }}">{{ attribute(L, 'd_' ~ x.note) }}</span>{% if x.reject_ready %} <span class="badge bg-info">{{ L.reject_ready }}</span>{% endif %}</td>
        <td>{% if dr is null %}–{% elseif dr.todo %}<a href="#settings" class="badge bg-warning text-dark text-decoration-none mr-tab-link">{{ dr.todo|length }} ✗</a>{% else %}<span class="badge bg-success">✓</span>{% endif %}</td>
        <td class="text-end">{% if x.own_pass or x.own_fail %}{{ x.own_pass }} / <span class="{{ x.own_fail ? 'text-danger fw-bold' }}">{{ x.own_fail }}</span>{% else %}–{% endif %}</td>
        <td class="text-end">{% if x.tls_ok or x.tls_fail %}{{ x.tls_ok }} / <span class="{{ x.tls_fail ? 'text-danger fw-bold' }}">{{ x.tls_fail }}</span>{% else %}–{% endif %}</td>
        <td class="text-end">{{ x.spoof ?: '–' }}</td>
        <td>{{ x.policy ? 'p=' ~ x.policy : '–' }}</td>
        <td>{{ x.last ? x.last|date('d.m.Y') : '–' }}</td>
      </tr>{% endfor %}</tbody>
    </table></div>
  </div>
  {% endif %}
</div>

{# ================================================================ history #}
<div role="tabpanel" class="tab-pane" id="tab-history">
  <div class="card mb-4"><div class="card-header fs-5">{{ L.trend }}</div><div class="card-body">
    {% if not chart or not chart.has %}<span class="text-muted">{{ L.no_trend }}</span>{% else %}
    <svg class="mr-chart" viewBox="0 0 {{ chart.width }} {{ chart.height + 16 }}" role="img" aria-label="{{ L.trend }}">
      {% for b in chart.bars %}<g><title>{{ L.week_of }} {{ b.week|date('d.m.Y') }} – {{ L.c_own_ok }}: {{ b.w.own_pass }}, {{ L.c_own_fail }}: {{ b.w.own_fail }}, {{ L.c_spoof }}: {{ b.w.spoof }}, {{ L.c_tls }}: {{ b.w.tls_ok }}, {{ L.c_tls_fail }}: {{ b.w.tls_fail }}</title>
        <rect x="{{ b.x }}" y="0" width="{{ chart.bw }}" height="{{ chart.height }}" rx="2" style="fill:rgba(127,127,127,.12)"></rect>
        {% for p in b.parts %}<rect x="{{ b.x }}" y="{{ p.y }}" width="{{ chart.bw }}" height="{{ p.h }}" style="fill:{{ p.color }}"></rect>{% endfor %}
        {% if b.label %}<text x="{{ b.x }}" y="{{ chart.height + 12 }}">{{ b.week|date('d.m.') }}</text>{% endif %}</g>{% endfor %}
    </svg>
    <div class="mr-legend mr-sm text-muted mt-2">{% for k, c in colors %}<span><i style="background:{{ c }}"></i>{{ attribute(L, 'c_' ~ {'own_pass': 'own_ok', 'own_fail': 'own_fail', 'spoof': 'spoof', 'tls_ok': 'tls', 'tls_fail': 'tls_fail'}[k]) }}</span>{% endfor %}<span>{{ L.per_week }} · max {{ chart.max }}</span></div>
    {% endif %}
  </div></div>

  <div class="card mb-4"><div class="card-header fs-5">{{ L.by_reporter }}</div>
    <div class="table-responsive"><table class="table table-striped w-100 mb-0">
      <thead><tr><th>{{ L.org }}</th><th class="text-end">DMARC {{ L.ok }}</th><th class="text-end">DMARC {{ L.failed }}</th><th class="text-end">TLS {{ L.ok }}</th><th class="text-end">TLS {{ L.failed }}</th><th class="text-end">{{ L.reports }}</th></tr></thead>
      <tbody>{% for r in d.reporters|default([]) %}<tr><td>{{ r.org }}</td>
        <td class="text-end">{{ r.dmarc_reports|default(0) ? r.own_pass : '–' }}</td><td class="text-end {{ r.own_fail ? 'text-danger fw-bold' }}">{{ r.dmarc_reports|default(0) ? r.own_fail : '–' }}</td>
        <td class="text-end">{{ r.tls_reports|default(0) ? r.tls_ok : '–' }}</td><td class="text-end {{ r.tls_fail|default(0) ? 'text-danger fw-bold' }}">{{ r.tls_reports|default(0) ? r.tls_fail : '–' }}</td>
        <td class="text-end">{{ r.reports }}</td></tr>{% else %}<tr><td colspan="6" class="text-muted">–</td></tr>{% endfor %}</tbody>
    </table></div>
    <div class="card-footer mr-sm text-muted">{{ L.reporter_hint }}</div>
  </div>
</div>

{# ================================================================ errors #}
<div role="tabpanel" class="tab-pane" id="tab-errors">
  <div class="card mb-4"><div class="card-header fs-5">{{ L.causes }}</div>
    {% if d.own_fail_causes|default([]) %}
    <div class="table-responsive"><table class="table table-striped w-100 mb-0 align-top">
      <thead><tr><th>{{ L.why }}</th><th class="text-end">{{ L.mails }}</th><th>{{ L.domain }}</th><th>{{ L.org }}</th><th>{{ L.period }}</th></tr></thead>
      <tbody>{% for c in d.own_fail_causes %}<tr>
        <td>{% for w in c.why %}<div>{{ w }}</div>{% endfor %}<div class="text-muted mr-sm">IP: {{ c.ips|join(', ') }}</div></td>
        <td class="text-end text-danger fw-bold">{{ c.count }}</td><td>{{ c.domains|join(', ') }}</td><td>{{ c.orgs|join(', ') }}</td>
        <td class="mr-sm mr-nowrap">{% if c.first %}{{ c.first|date('d.m.') }}–{% endif %}{{ c.last ? c.last|date('d.m.Y') }}</td></tr>{% endfor %}</tbody>
    </table></div>
    {% else %}<div class="card-body text-muted">{{ L.causes_none }}</div>{% endif %}
  </div>
  <div class="card mb-4"><div class="card-header fs-5">{{ L.tls_failures }}</div>
    {% if d.tls_failures|default([]) %}
    <div class="table-responsive"><table class="table table-striped w-100 mb-0">
      <thead><tr><th>{{ L.period }}</th><th>{{ L.org }}</th><th>{{ L.domain }}</th><th>{{ L.result }}</th><th class="text-end">#</th><th>{{ L.mx }}</th><th>{{ L.sender_ip }}</th></tr></thead>
      <tbody>{% for f in d.tls_failures %}<tr><td>{{ f.when|date('d.m.Y') }}</td><td>{{ f.org }}</td><td>{{ f.domain }}</td>
        <td><span class="text-danger">{{ f.result }}</span>{% if f.reason %}<div class="text-muted mr-sm">{{ f.reason }}</div>{% endif %}</td>
        <td class="text-end">{{ f.count }}</td><td class="mr-sm">{{ f.mx }}</td><td class="mr-sm">{{ f.ip }}</td></tr>{% endfor %}</tbody>
    </table></div>
    {% else %}<div class="card-body text-muted">{{ L.tls_none }}</div>{% endif %}
  </div>
</div>

{# ================================================================ foreign senders #}
<div role="tabpanel" class="tab-pane" id="tab-senders">
  {% for sec in [
      {'title': L.spoof_t, 'hint': L.spoof_hint, 'rows': d.spoof|default([]), 'empty': L.spoof_none, 'kind': 'spoof'},
      {'title': L.fwd_t, 'hint': L.fwd_hint, 'rows': d.forwarded|default([]), 'empty': '–', 'kind': 'fwd'},
      {'title': L.pass_t, 'hint': L.pass_hint, 'rows': d.other_pass|default([]), 'empty': '–', 'kind': 'pass'}] %}
  <div class="card mb-4"><div class="card-header fs-5">{{ sec.title }}</div>
    <div class="card-body pb-0"><p class="text-muted mr-sm">{{ sec.hint }}</p></div>
    {% if sec.rows %}
    <div class="table-responsive"><table class="table table-striped w-100 mb-0">
      <thead><tr><th>{{ L.ip }}</th><th>{{ L.hostname }}</th><th>{{ L.domain }}</th><th class="text-end">{{ L.mails }}</th>{% if sec.kind == 'spoof' %}<th>{{ L.period }}</th><th>{{ L.handling }}</th>{% elseif sec.kind == 'fwd' %}<th>{{ L.why }}</th>{% endif %}</tr></thead>
      <tbody>{% for s in sec.rows %}<tr><td>{{ s.ip }}</td><td class="mr-sm">{{ s.ptr ?: '–' }}</td><td>{{ s.domains|join(', ') }}</td><td class="text-end">{{ s.count }}</td>
        {% if sec.kind == 'spoof' %}<td class="mr-sm mr-nowrap">{{ s.first|date('d.m.') }}–{{ s.last|date('d.m.Y') }}</td><td>{{ s.disposition }}</td>{% elseif sec.kind == 'fwd' %}<td class="mr-sm">{{ s.reasons|join(', ') }}</td>{% endif %}</tr>{% endfor %}</tbody>
    </table></div>
    {% else %}<div class="card-body pt-0 text-muted">{{ sec.empty }}</div>{% endif %}
  </div>
  {% endfor %}
</div>

{# ================================================================ reports #}
<div role="tabpanel" class="tab-pane" id="tab-reports">
  <div class="card mb-4"><div class="card-header fs-5">{{ L.recent }}</div>
    <div class="table-responsive"><table class="table table-striped w-100 mb-0 align-top">
      <thead><tr><th>{{ L.received }}</th><th>{{ L.type }}</th><th>{{ L.org }}</th><th>{{ L.domain }}</th><th>{{ L.period }}</th><th>{{ L.summary }}</th></tr></thead>
      <tbody>{% for r in d.recent|default([]) %}<tr>
        <td class="mr-nowrap">{{ r.received|date('d.m.Y') }}</td>
        <td><span class="badge {{ r.kind == 'tls' ? 'bg-info' : 'bg-primary' }}">{{ r.kind|upper }}</span></td>
        <td>{{ r.org }}</td><td>{{ r.domain }}{% if r.policy %} <span class="text-muted mr-sm">{{ r.policy }}</span>{% endif %}</td>
        <td class="mr-sm mr-nowrap">{% if r.begin %}{{ r.begin|date('d.m.') }}–{{ r.end|date('d.m.Y') }}{% endif %}</td>
        <td><details><summary class="{{ r.problem|default(false) ? 'text-danger fw-bold' }}">{% if r.stats is defined %}{% if r.kind == 'dmarc' %}{{ L.sum_dmarc|replace({'{t}': r.stats.total, '{ok}': r.stats.own_ok, '{fail}': r.stats.own_fail, '{sp}': r.stats.spoof}) }}{% else %}{{ L.sum_tls|replace({'{ok}': r.stats.tls_ok, '{fail}': r.stats.tls_fail}) }}{% endif %}{% endif %}</summary>
          <table class="table table-sm mr-sm mt-2 mb-0">
          {% if r.kind == 'dmarc' %}{% for row in r.rows %}
            <tr class="{{ row.own and not (row.dkim == 'pass' or row.spf == 'pass') ? 'text-danger' }}"><td>{{ row.ip }}</td><td>{{ row.own ? L.own : L.foreign }}</td><td class="text-end">{{ row.count }}</td><td>DKIM {{ row.dkim }}</td><td>SPF {{ row.spf }}</td><td>{{ row.disposition }}</td></tr>
            {% if row.why|default([]) %}<tr><td></td><td colspan="5" class="text-muted">{% for w in row.why %}<div>↳ {{ w }}</div>{% endfor %}</td></tr>{% endif %}
          {% endfor %}{% else %}{% for row in r.rows %}<tr><td>{{ row.policy }}</td><td>{{ row.ok }} {{ L.ok }}</td><td class="{{ row.fail ? 'text-danger' }}">{{ row.fail }} {{ L.failed }}</td></tr>{% endfor %}{% endif %}
          </table></details></td></tr>
      {% else %}<tr><td colspan="6" class="text-muted">–</td></tr>{% endfor %}</tbody>
    </table></div>
    {% if d and d.total_reports %}<div class="card-footer mr-sm text-muted">{{ L.footer|replace({'{n}': d.total_reports, '{since}': d.since ? d.since|date('d.m.Y') : '–', '{days}': d.retention_days}) }}</div>{% endif %}
  </div>
</div>

{# ================================================================ settings #}
<div role="tabpanel" class="tab-pane" id="tab-settings">
  <div class="row">
    <div class="col-xl-6">
      <div class="card mb-4"><div class="card-header fs-5">{{ L.s_general }}</div><div class="card-body">
        <form method="post"><input type="hidden" name="mr_action" value="save">
          <div class="row mb-3"><label class="col-sm-4 col-form-label">{{ L.mailbox }}</label><div class="col-sm-8">
            <select name="mailbox" class="form-control" data-live-search="true" data-width="100%">{% if not s.mailbox %}<option value="">–</option>{% endif %}
              {% for mb in mailboxes %}<option value="{{ mb }}" {{ mb == s.mailbox ? 'selected' }}>{{ mb }}</option>{% endfor %}</select>
            <small class="form-text d-block">{{ L.mailbox_help }}</small></div></div>
          <div class="row mb-3"><label class="col-sm-4 col-form-label">{{ L.alert_to }}</label><div class="col-sm-8">
            <input name="alert_to" class="form-control" value="{{ s.alert_to }}"><small class="form-text d-block">{{ L.alert_help }}</small></div></div>
          <div class="row mb-3"><label class="col-sm-4 col-form-label">{{ L.own_ips }}</label><div class="col-sm-8">
            {% set ips_mode = s.own_ips_mode|default('auto') %}
            <div class="form-check"><input class="form-check-input" type="radio" name="own_ips_mode" value="auto" id="ipauto" {{ ips_mode == 'auto' ? 'checked' }}>
              <label class="form-check-label" for="ipauto">{{ L.ips_auto }}{% if detected_ips %}: {{ detected_ips|join(', ') }}{% else %} <span class="text-danger">({{ L.ips_not_detected }})</span>{% endif %}</label></div>
            <div class="form-check mb-1"><input class="form-check-input" type="radio" name="own_ips_mode" value="manual" id="ipman" {{ ips_mode == 'manual' ? 'checked' }}>
              <label class="form-check-label" for="ipman">{{ L.ips_manual }}</label></div>
            <textarea name="own_ips" class="form-control" rows="2">{{ s.own_ips|default([])|join("\n") }}</textarea><small class="form-text d-block">{{ L.ips_help }}</small></div></div>
          <div class="row mb-3"><label class="col-sm-4 col-form-label">{{ L.run_time }}</label><div class="col-sm-8">
            <input type="time" name="run_time" class="form-control" style="max-width:10rem" value="{{ run_time }}"><small class="form-text d-block">{{ L.run_time_help }}</small></div></div>
          <div class="row mb-3"><label class="col-sm-4 col-form-label">{{ L.language }}</label><div class="col-sm-8">
            <select name="language" class="form-control" data-width="100%">{% for c, n in lang_names %}<option value="{{ c }}" {{ c == alert_lang ? 'selected' }}>{{ n }}</option>{% endfor %}</select>
            <small class="form-text d-block">{{ L.language_help }}</small></div></div>
          <button class="btn btn-sm btn-success"><i class="bi bi-check-lg me-1"></i>{{ L.save }}</button>
        </form>
      </div></div>
    </div>
    <div class="col-xl-6">
      <div class="card mb-4"><div class="card-header fs-5">{{ L.new_mailbox }}</div><div class="card-body">
        <p class="text-muted mr-sm">{{ L.new_mailbox_help }}</p>
        <form method="post" class="row g-2 align-items-center"><input type="hidden" name="mr_action" value="create_mailbox">
          <div class="col-auto"><input name="local_part" class="form-control" value="reports" pattern="[a-z0-9._-]+" required></div>
          <div class="col-auto">@</div>
          <div class="col-auto"><select name="domain" class="form-control">{% for dm in main_domains %}<option>{{ dm }}</option>{% endfor %}</select></div>
          <div class="col-auto"><button class="btn btn-sm btn-success"><i class="bi bi-plus-lg me-1"></i>{{ L.create }}</button></div>
        </form>
      </div></div>
    </div>
  </div>

  <div class="card mb-4">
    <div class="card-header d-flex align-items-center fs-5"><span>{{ L.dns_t }}</span>
      <span class="ms-auto mr-sm text-muted me-2">{{ L.checked }} {{ "now"|date('H:i:s') }}{% if fresh %} ({{ L.direct }}){% endif %}</span>
      <a href="?fresh=1#settings" class="btn btn-sm btn-secondary"><i class="bi bi-arrow-repeat me-1"></i>{{ L.check_again }}</a></div>
    {% if not s.mailbox %}<div class="card-body text-muted">{{ L.no_mailbox }}</div>{% else %}
    <div class="card-body pb-0"><p class="text-muted mr-sm">{{ L.dns_help|replace({'{mb}': s.mailbox}) }}</p></div>
    <div class="table-responsive"><table class="table table-striped w-100 mb-0 align-middle">
      <thead><tr><th>{{ L.domain }}</th><th>{{ L.dns_tls }}</th><th>{{ L.dns_dmarc }}</th><th>{{ L.dns_auth }}</th></tr></thead>
      <tbody>{% for r in dns %}<tr><td><b>{{ r.domain }}</b></td>
        <td>{% if r.tls_ok %}<span class="badge bg-success">✓</span>{% else %}<span class="badge bg-danger">{{ L.missing }}</span>{% endif %}</td>
        <td>{% if r.dmarc_ok %}<span class="badge bg-success">✓</span>{% else %}<span class="badge bg-danger">{{ attribute(L, r.dmarc_state) }}</span>{% endif %}</td>
        <td>{% if not r.auth_needed %}<span class="text-muted mr-sm">{{ L.not_needed }}</span>{% elseif r.auth_ok %}<span class="badge bg-success">✓</span>{% else %}<span class="badge bg-danger">{{ L.missing }}</span>{% endif %}</td></tr>{% endfor %}</tbody>
    </table></div>
    {% if dns_todo %}
    <div class="card-body"><h6>{{ L.dns_todo }}</h6>
      <div class="table-responsive"><table class="table table-sm table-striped w-100 mb-0 mr-sm align-top">
        <thead><tr><th>{{ L.action }}</th><th>{{ L.zone }}</th><th>{{ L.name }}</th><th>TXT {{ L.value }}</th></tr></thead>
        <tbody>{% for x in dns_todo %}<tr><td><span class="badge {{ x.action == 'add' ? 'bg-primary' : 'bg-warning text-dark' }}">{{ attribute(L, x.action) }}</span></td><td>{{ x.zone }}</td><td><code class="user-select-all">{{ x.name }}</code></td>
          <td><code class="user-select-all text-break">{{ x.value }}</code>{% if x.current %}<div class="text-muted mt-1">{{ L.current }}: {{ x.current }}</div>{% endif %}</td></tr>{% endfor %}</tbody>
      </table></div></div>
    {% else %}<div class="card-body pt-0"><span class="text-success"><i class="bi bi-check-circle me-1"></i>{{ L.dns_all_ok }}</span></div>{% endif %}
    {% endif %}
  </div>
</div>

</div></div></div>
{% endif %}

<script>
  // open the tab named in the URL hash (#settings, #errors, ...) and keep links like "#settings" inside the page
  window.addEventListener('load', function () {
    function show(name) {
      var btn = document.querySelector('#mr-tabs [data-bs-target="#tab-' + name + '"]');
      if (btn && window.bootstrap) { bootstrap.Tab.getOrCreateInstance(btn).show(); }
    }
    if (location.hash) { show(location.hash.substring(1)); }
    document.querySelectorAll('a.mr-tab-link').forEach(function (a) {
      a.addEventListener('click', function (e) { e.preventDefault(); show(a.getAttribute('href').substring(1)); history.replaceState(null, '', a.getAttribute('href')); });
    });
    document.querySelectorAll('#mr-tabs [data-bs-toggle="tab"]').forEach(function (b) {
      b.addEventListener('shown.bs.tab', function () { history.replaceState(null, '', '#' + b.getAttribute('data-bs-target').replace('#tab-', '')); });
    });
  });
</script>
{% endblock %}
TWIG;

// register our template next to mailcow's own ones; footer.inc.php adds its globals and renders it
$twig->setLoader(new \Twig\Loader\ChainLoader([
  new \Twig\Loader\ArrayLoader(['mailcow-report-dashboard.twig' => $tpl]),
  $twig->getLoader(),
]));
$template = 'mailcow-report-dashboard.twig';
$template_data = [
  'd' => $data, 'L' => $L, 's' => $settings, 'alert_lang' => $alert_lang, 'lang_names' => $lang_names, 'dec' => $L['_decimal'] ?? '.', 'thou' => $L['_thousands'] ?? ',',
  'issues' => $issues, 'open_n' => $open_n, 'worst' => $worst, 'kpi' => $kpi, 'acked' => $acked_list,
  'own_badge' => $pct_badge($kpi['own_pct'] ?? null, $has_open('own:')), 'tls_badge' => $pct_badge($kpi['tls_pct'] ?? null, $has_open('tls:')),
  'chart' => $chart, 'colors' => $series_keys,
  'mailboxes' => $all_mailboxes, 'main_domains' => $main_domains, 'detected_ips' => $detected_ips, 'run_time' => $run_time,
  'next_run' => $next_run, 'run_pending' => $run_pending, 'protected' => $protected, 'configured' => $configured, 'host' => $_SERVER['HTTP_HOST'] ?? '', 'base_url' => $base_url,
  'dns' => $dns, 'dns_todo' => $dns_todo, 'dns_by_domain' => $dns_by_domain, 'dns_ok_n' => $dns_ok_n, 'dns_bad' => $dns_bad, 'fresh' => $fresh,
];

require_once $_SERVER['DOCUMENT_ROOT'] . '/inc/footer.inc.php';
