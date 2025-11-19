<?php
require_once __DIR__ . '/../includes/license.php';

function setup_test_db(string $date): PDO
{
    $pdo = new PDO('sqlite::memory:');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec('CREATE TABLE license_settings (id INTEGER PRIMARY KEY, license_expire_date TEXT NOT NULL, updated_at TEXT DEFAULT CURRENT_TIMESTAMP)');
    $stmt = $pdo->prepare('INSERT INTO license_settings (id, license_expire_date) VALUES (1, ?)');
    $stmt->execute([$date]);
    return $pdo;
}

function assert_true($condition, string $message)
{
    if (!$condition) {
        throw new RuntimeException('Test failed: ' . $message);
    }
}

$results = [];

// Test 1: Expired license blocks normal admin
$_SESSION = [];
$_POST = [];
$expiredPdo = setup_test_db(date('Y-m-d', strtotime('-1 day')));
$blocked = false;
$blocker = function ($title, $message) use (&$blocked) {
    $blocked = stripos($title, 'süresi') !== false;
};
enforce_license($expiredPdo, ['license_check' => true], $blocker);
$results[] = ['Expired license blocks normal user', $blocked];
assert_true($blocked, 'Expired license should block normal users');

// Test 2: Expired license allows super admin session
$_SESSION = ['super_admin' => true, 'admin_user' => ['username' => 'ilhan', 'role' => 'super']];
$_POST = [];
$blocked = false;
enforce_license($expiredPdo, ['license_check' => true], function () use (&$blocked) {
    $blocked = true;
});
$results[] = ['Super admin bypass', !$blocked];
assert_true(!$blocked, 'Super admin should bypass license block');

// Test 3: License check disabled
$_SESSION = [];
$_POST = [];
$futurePdo = setup_test_db(date('Y-m-d', strtotime('+10 days')));
$blocked = false;
enforce_license($futurePdo, ['license_check' => false], function () use (&$blocked) {
    $blocked = true;
});
$results[] = ['License check disabled', !$blocked];
assert_true(!$blocked, 'License check disabled should skip enforcement');

echo "License middleware tests passed:\n";
foreach ($results as [$label, $status]) {
    echo sprintf("- %s: %s\n", $label, $status ? 'OK' : 'FAIL');
}
