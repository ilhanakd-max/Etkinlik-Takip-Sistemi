<?php

/**
 * Helper methods for enforcing license expiry.
 */
function is_super_admin_session(): bool
{
    if (!isset($_SESSION)) {
        return false;
    }
    if (!empty($_SESSION['super_admin'])) {
        return true;
    }
    $user = $_SESSION['admin_user'] ?? null;
    if (!$user || !is_array($user)) {
        return false;
    }
    if (($user['username'] ?? '') === 'ilhan') {
        return true;
    }
    return ($user['role'] ?? '') === 'super';
}

function is_super_admin_request(): bool
{
    if (is_super_admin_session()) {
        return true;
    }
    if (!empty($_POST['admin_login'])) {
        $username = $_POST['username'] ?? '';
        return trim($username) === 'ilhan';
    }
    return false;
}

function fetch_license_expire_date(PDO $pdo): ?array
{
    $stmt = $pdo->prepare('SELECT license_expire_date, updated_at FROM license_settings WHERE id = 1 LIMIT 1');
    $stmt->execute();
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return $row ?: null;
}

function render_license_block_screen(string $title, string $message): void
{
    http_response_code(403);
    echo "<div style='padding:40px; font-family:Arial; text-align:center'>";
    echo "<h2 style='color:#e3342f'>" . htmlspecialchars($title) . "</h2>";
    echo "<p>" . nl2br(htmlspecialchars($message)) . "</p>";
    echo "<p><strong>Lisans sahibi süper admin (ilhan) giriş yaparak sistemi yeniden etkinleştirebilir.</strong></p>";
    echo "<form method='post' style='max-width:320px;margin:20px auto;text-align:left'>";
    echo "<input type='hidden' name='admin_login' value='1'>";
    echo "<div style='margin-bottom:10px'><label>Kullanıcı Adı";
    echo "<input type='text' name='username' value='ilhan' style='width:100%;padding:8px;margin-top:4px'></label></div>";
    echo "<div style='margin-bottom:10px'><label>Şifre";
    echo "<input type='password' name='password' style='width:100%;padding:8px;margin-top:4px' placeholder='Cfm102.5'></label></div>";
    echo "<button type='submit' style='width:100%;padding:10px;background:#2563eb;color:#fff;border:none;border-radius:4px'>Süper Admin Girişi</button>";
    echo "</form>";
    echo "<p><a href='index.php' style='color:#2563eb'>Girişe Dön</a></p>";
    echo "</div>";
    exit;
}

function enforce_license(PDO $pdo, array $config = [], ?callable $onBlock = null): void
{
    $checkEnabled = $config['license_check'] ?? true;
    if (!$checkEnabled) {
        return;
    }

    if (is_super_admin_request()) {
        return;
    }

    try {
        $licenseRow = fetch_license_expire_date($pdo);
    } catch (Throwable $e) {
        $handler = $onBlock ?? 'render_license_block_screen';
        $handler('Lisans kontrol hatası', 'Lisans tablosu okunamadı: ' . $e->getMessage());
        return;
    }

    if (!$licenseRow) {
        $handler = $onBlock ?? 'render_license_block_screen';
        $handler('Lisans kaydı bulunamadı', 'license_settings tablosunda herhangi bir kayıt bulunamadı.');
        return;
    }

    $licenseDate = DateTime::createFromFormat('Y-m-d', $licenseRow['license_expire_date']);
    if (!$licenseDate) {
        $handler = $onBlock ?? 'render_license_block_screen';
        $handler('Geçersiz lisans tarihi', 'Lisans tarihi okunamadı: ' . $licenseRow['license_expire_date']);
        return;
    }

    $today = new DateTime('today');
    if ($today > $licenseDate && !is_super_admin_session()) {
        $handler = $onBlock ?? 'render_license_block_screen';
        $handler('Lisans süresi doldu', 'Belirlenen lisans tarihi: ' . $licenseDate->format('Y-m-d'));
    }
}
