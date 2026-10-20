<?php
// Loader for the mailcow-report-dashboard page. mailcow runs PHP with opcache.validate_timestamps=Off,
// so the container deploys the page under a new file name per version and this file never changes.
$v = trim((string) @file_get_contents(__DIR__ . '/_data/version'));
if (!preg_match('/^[a-f0-9]{12}$/', $v) || !is_file(__DIR__ . '/page-' . $v . '.php')) {
  http_response_code(503);
  exit('mailcow-report-dashboard: page not deployed');
}
require __DIR__ . '/page-' . $v . '.php';
