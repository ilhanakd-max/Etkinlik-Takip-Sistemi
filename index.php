<?php
// index.php - Küçük İşletmeler İçin Sektörel Ajanda
header('Content-Type: text/html; charset=utf-8');

$appConfig = require __DIR__ . '/config.php';
require_once __DIR__ . '/includes/license.php';

// --- OTURUM VE AYARLAR ---
ini_set('session.use_strict_mode', '1');
$session_secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (isset($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443);
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'domain' => '',
    'secure' => $session_secure,
    'httponly' => true,
    'samesite' => 'Strict',
]);
session_start();

// --- VERİTABANI AYARLARI ---
// Güvenlik ve esneklik için, veritabanı kimlik bilgileri artık
// bu dosyanın dışındaki `database.php` dosyasından yüklenmektedir.
// Kurulum için `database.example.php` dosyasını kopyalayın.

$db_config_path = __DIR__ . '/database.php';

if (!file_exists($db_config_path)) {
    die("<h1 style='color: orange;'>Kurulum Eksik</h1>" .
        "<p><code>database.php</code> dosyası bulunamadı. Lütfen <code>database.example.php</code> dosyasını kopyalayıp " .
        "adını <code>database.php</code> olarak değiştirin ve kendi veritabanı bilgilerinizi girin.</p>");
}

$db_config = require $db_config_path;

try {
    $dsn = sprintf(
        "mysql:host=%s;dbname=%s;charset=%s",
        $db_config['db_host'],
        $db_config['db_name'],
        $db_config['db_charset'] ?? 'utf8mb4'
    );
    $options = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
    ];
    $pdo = new PDO($dsn, $db_config['db_user'], $db_config['db_pass'], $options);
    $pdo->exec("SET time_zone = '+03:00'");
} catch(PDOException $e) {
    error_log("Veritabanı bağlantı hatası: " . $e->getMessage());
    die("<h1 style='color: red;'>Sistem Hatası: Veritabanı Bağlantısı Kurulamadı.</h1>" .
        "<p>Lütfen <code>database.php</code> dosyasındaki bilgilerin doğru olduğundan emin olun.</p>");
}

// --- LISANS KONTROLÜ ---
// Sisteme giriş yapılmadan hemen önce lisans durumu denetlenir.
enforce_license($pdo, $appConfig);

// Yardımcı Fonksiyonlar
function clean_input($data) {
    $sanitized = trim(strip_tags((string) $data));
    return preg_replace('/[\x00-\x1F\x7F]/u', '', $sanitized);
}

function is_admin() { return isset($_SESSION['admin']) && $_SESSION['admin'] === true; }
function is_super_admin() {
    // Hem eski `super_admin` anahtarını hem de yeni rol tabanlı sistemi destekler
    if (isset($_SESSION['super_admin']) && $_SESSION['super_admin'] === true) {
        return true;
    }
    return isset($_SESSION['admin_user']['role']) && $_SESSION['admin_user']['role'] === 'super_admin';
}
function generateCSRFToken() { if (!isset($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32)); return $_SESSION['csrf_token']; }
function validateCSRFToken($token) { return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token); }
function is_valid_date_string($date) { if (!is_string($date) || $date === '') return false; $dt = DateTime::createFromFormat('Y-m-d', $date); return $dt && $dt->format('Y-m-d') === $date; }

// Dinamik Durum ve Ödeme Bilgilerini Çek
global $all_event_statuses, $all_payment_statuses;
try {
    $all_event_statuses = [];
    foreach ($pdo->query("SELECT * FROM event_statuses") as $row) {
        $all_event_statuses[$row['status_key']] = $row;
    }
    $all_payment_statuses = [];
    foreach ($pdo->query("SELECT * FROM payment_statuses") as $row) {
        $all_payment_statuses[$row['status_key']] = $row;
    }
} catch (PDOException $e) {
    // Tablo hatası durumunda varsayılan değerleri kullan
    $all_event_statuses = ['confirmed' => ['display_name' => 'Onaylı', 'color' => '#2ecc71'], 'pending' => ['display_name' => 'Beklemede', 'color' => '#f1c40f'], 'cancelled' => ['display_name' => 'İptal', 'color' => '#e74c3c'], 'completed' => ['display_name' => 'Tamamlandı', 'color' => '#34495e']];
    $all_payment_statuses = ['paid' => ['display_name' => 'Ödendi', 'color' => '#27ae60'], 'unpaid' => ['display_name' => 'Ödenmedi', 'color' => '#c0392b'], 'partial' => ['display_name' => 'Kaporası Alındı', 'color' => '#e67e22']];
}


// Global Ayarları Çek
$settings = [];
try {
    foreach ($pdo->query("SELECT * FROM app_settings") as $row) {
        $settings[$row['setting_key']] = $row['setting_value'];
    }
} catch (PDOException $e) {
    $settings['active_sector'] = 'generic';
}
$active_sector = $settings['active_sector'] ?? 'generic';


// --- SEKTÖR VERİSİNİ DİNAMİK OLARAK ÇEKME ---
$sector_configs = [];
try {
    $sector_configs_db = $pdo->query("SELECT * FROM app_sectors ORDER BY sector_name")->fetchAll();
    foreach ($sector_configs_db as $s) {
        $sector_configs[$s['sector_key']] = [
            'title' => $s['sector_name'],
            'unit_label' => $s['unit_label'],
            'unit_placeholder' => $s['unit_label'], // Basit tutmak için
            'event_label' => $s['event_label'],
            'event_placeholder' => $s['event_label'] . ' Detay',
            'contact_label' => $s['contact_label'],
            'time_label' => $s['time_label'],
            'icon' => $s['icon'],
            'is_active' => $s['is_active']
        ];
    }
} catch (PDOException $e) {
    // app_sectors tablosu yoksa veya hata verirse yedek olarak generic sektörü statik tanımla
    $sector_configs['generic'] = [
        'title' => 'Genel Ajanda (YEDEK)', 'unit_label' => 'Birim / Oda', 'unit_placeholder' => 'Toplantı Odası A',
        'event_label' => 'Etkinlik', 'event_placeholder' => 'Yönetim Toplantısı', 'contact_label' => 'İletişim Kişisi',
        'time_label' => 'Saat', 'icon' => 'fa-calendar-check', 'is_active' => 1
    ];
    $active_sector = 'generic';
}

// Geçerli dil etiketlerini al
$lang = $sector_configs[$active_sector] ?? $sector_configs['generic'];

// Türkçe Tarih Fonksiyonları
$turkish_months = [1=>'Ocak', 2=>'Şubat', 3=>'Mart', 4=>'Nisan', 5=>'Mayıs', 6=>'Haziran', 7=>'Temmuz', 8=>'Ağustos', 9=>'Eylül', 10=>'Ekim', 11=>'Kasım', 12=>'Aralık'];
$turkish_days_full = ['Monday'=>'Pazartesi', 'Tuesday'=>'Salı', 'Wednesday'=>'Çarşamba', 'Thursday'=>'Perşembe', 'Friday'=>'Cuma', 'Saturday'=>'Cumartesi', 'Sunday'=>'Pazar'];

function turkish_date($format, $timestamp = null) {
    global $turkish_months, $turkish_days_full;
    $timestamp = $timestamp ?? time();
    $date = date($format, $timestamp);
    $month_num = date('n', $timestamp);
    $day_en = date('l', $timestamp);
    
    // Ay isimlerini çevir
    $date = str_replace(date('F', $timestamp), $turkish_months[$month_num], $date);
    $date = str_replace(date('M', $timestamp), mb_substr($turkish_months[$month_num], 0, 3, 'UTF-8'), $date);
    
    // Gün isimlerini çevir
    if (isset($turkish_days_full[$day_en])) {
        $date = str_replace($day_en, $turkish_days_full[$day_en], $date);
    }
    
    return $date;
}

/**
 * Otomatik Yinelenen (Ulusal) Sabit Tatilleri Hesaplar
 */
function get_recurring_holidays($year) {
    $holidays = [];
    
    // Sabit Tarihli Ulusal Tatiller
    $national_holidays = [
        '01-01' => 'Yılbaşı',
        '04-23' => 'Ulusal Egemenlik ve Çocuk Bayramı',
        '05-01' => 'Emek ve Dayanışma Günü',
        '05-19' => 'Atatürk\'ü Anma, Gençlik ve Spor Bayramı',
        '07-15' => 'Demokrasi ve Milli Birlik Günü',
        '08-30' => 'Zafer Bayramı',
        '10-29' => 'Cumhuriyet Bayramı', // 29 Ekim tüm gün
    ];

    foreach ($national_holidays as $md => $name) {
        $holidays["$year-$md"] = $name;
    }
    
    // 28 Ekim Öğleden Sonra Tatili
    $holidays["$year-10-28"] = 'Cumhuriyet Bayramı Arefesi (Yarım Gün)'; 
    
    return $holidays;
}

/**
 * Belirtilen tarihin tatil olup olmadığını kontrol eder.
 */
function is_holiday($date, $pdo) {
    $year = date('Y', strtotime($date));
    
    // 1. Yinelenen (Otomatik) Tatilleri Kontrol Et
    $recurring_holidays = get_recurring_holidays($year);
    if (isset($recurring_holidays[$date])) {
        return ['holiday_name' => $recurring_holidays[$date]];
    }
    
    // 2. Veritabanındaki Manuel Kayıtları Kontrol Et
    try {
        $sql = "SELECT holiday_name FROM holidays WHERE holiday_date = ?";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([$date]);
        $db_holiday = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($db_holiday) {
            return $db_holiday;
        }
    } catch (PDOException $e) {
        error_log("Tatil sorgulama hatası: " . $e->getMessage());
    }

    return false;
}


// DOC Rapor Oluşturma Fonksiyonu (HTML formatında DOC)
function generateDOC($data, $title, $date_range, $filters) {
    global $all_event_statuses, $all_payment_statuses, $pdo;
    // Buffer temizleme
    if (ob_get_level() > 0) ob_end_clean(); 
    
    header('Content-Type: application/msword; charset=utf-8');
    header('Content-Disposition: attachment; filename="rapor_' . date('Ymd_His') . '.doc"');
    
    $output = '<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"><title>' . htmlspecialchars($title) . '</title>
    <style>
        body { font-family: Calibri, sans-serif; font-size: 11pt; }
        h1 { font-size: 16pt; text-align: center; }
        table { border-collapse: collapse; width: 100%; margin-top: 15px; }
        th, td { border: 1px solid #000; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; font-weight: bold; }
        .holiday-day { background-color: #f8e1a4; }
    </style>
    </head><body>';
    
    $output .= '<h1>' . htmlspecialchars($title) . '</h1>';
    $output .= '<p><strong>Tarih Aralığı:</strong> ' . htmlspecialchars($date_range) . '</p>';
    if (!empty($filters)) {
        $output .= '<p><strong>Filtreler:</strong> ' . htmlspecialchars($filters) . '</p>';
    }
    
    $output .= '<table>';
    $output .= '<thead><tr><th>Tarih</th><th>Gün</th><th>Birim</th><th>Etkinlik Adı</th><th>Saat</th><th>İletişim</th><th>Durum</th><th>Ödeme</th></tr></thead>';
    $output .= '<tbody>';
    
    foreach ($data as $event) {
        $event_status = $event['status'] ?? '';
        $status_text = $all_event_statuses[$event_status]['display_name'] ?? $event_status;
        
        $payment_text = '-';
        $event_payment_status = $event['payment_status'] ?? '';
        if (!empty($event_payment_status)) {
            $payment_text = $all_payment_statuses[$event_payment_status]['display_name'] ?? '-';
        }
        
        $is_weekend = date('N', strtotime($event['event_date'])) >= 6;
        $is_holiday = is_holiday($event['event_date'], $pdo);
        $row_class = '';
        if ($is_holiday || $is_weekend) {
             $row_class = 'holiday-day';
        }

        $output .= '<tr class="' . $row_class . '">';
        $output .= '<td>' . turkish_date('d M Y', strtotime($event['event_date'] ?? 'now')) . '</td>';
        $output .= '<td>' . turkish_date('l', strtotime($event['event_date'] ?? 'now')) . '</td>';
        $output .= '<td>' . htmlspecialchars($event['unit_name'] ?? '') . '</td>';
        $output .= '<td>' . htmlspecialchars($event['event_name'] ?? '') . '</td>';
        $output .= '<td>' . htmlspecialchars($event['event_time'] ?? '') . '</td>';
        $output .= '<td>' . htmlspecialchars($event['contact_info'] ?? '') . '</td>';
        $output .= '<td>' . htmlspecialchars($status_text) . '</td>';
        $output .= '<td>' . htmlspecialchars($payment_text) . '</td>';
        $output .= '</tr>';
    }
    
    $output .= '</tbody></table>';
    $output .= '<p style="margin-top: 20px;"><strong>Toplam Kayıt:</strong> ' . count($data) . '</p>';
    $output .= '<p>Rapor Oluşturma Tarihi: ' . turkish_date('d M Y H:i:s') . '</p>';
    $output .= '</body></html>';
    
    echo $output;
    exit;
}

// XLSX Rapor Oluşturma Fonksiyonu (Basitleştirilmiş HTML/XLS formatı)
function generateXLS($data, $title, $date_range, $filters) {
    global $all_event_statuses, $all_payment_statuses, $pdo;
    // Buffer temizleme
    if (ob_get_level() > 0) ob_end_clean(); 
    
    header('Content-Type: application/vnd.ms-excel; charset=utf-8');
    header('Content-Disposition: attachment; filename="rapor_' . date('Ymd_His') . '.xls"');
    header('Cache-Control: max-age=0');
    
    $output = '<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:x="urn:schemas-microsoft-com:office:excel" xmlns="http://www.w3.org/TR/REC-html40">';
    $output .= '<head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head><body>';
    
    $output .= '<h2>' . htmlspecialchars($title) . '</h2>';
    $output .= '<p><strong>Tarih Aralığı:</strong> ' . htmlspecialchars($date_range) . '</p>';
    if (!empty($filters)) {
        $output .= '<p><strong>Filtreler:</strong> ' . htmlspecialchars($filters) . '</p>';
    }
    
    $output .= '<table border="1">';
    $output .= '<thead><tr><th>Tarih</th><th>Gün</th><th>Birim</th><th>Etkinlik Adı</th><th>Saat</th><th>İletişim</th><th>Durum</th><th>Ödeme</th></tr></thead>';
    $output .= '<tbody>';
    
    foreach ($data as $event) {
        $event_status = $event['status'] ?? '';
        $status_text = $all_event_statuses[$event_status]['display_name'] ?? $event_status;
        
        $payment_text = '-';
        $event_payment_status = $event['payment_status'] ?? '';
        if (!empty($event_payment_status)) {
            $payment_text = $all_payment_statuses[$event_payment_status]['display_name'] ?? '-';
        }
        
        $is_weekend = date('N', strtotime($event['event_date'])) >= 6;
        $is_holiday = is_holiday($event['event_date'], $pdo);
        $row_style = '';
        if ($is_holiday) {
             $row_style = 'style="background-color: #ffeeb0;"'; // Excel için basit stil
        } else if ($is_weekend) {
            $row_style = 'style="background-color: #f0f0f0;"';
        }


        $output .= '<tr ' . $row_style . '>';
        $output .= '<td>' . turkish_date('d M Y', strtotime($event['event_date'] ?? 'now')) . '</td>';
        $output .= '<td>' . turkish_date('l', strtotime($event['event_date'] ?? 'now')) . '</td>';
        $output .= '<td>' . htmlspecialchars($event['unit_name'] ?? '') . '</td>';
        $output .= '<td>' . htmlspecialchars($event['event_name'] ?? '') . '</td>';
        $output .= '<td>' . htmlspecialchars($event['event_time'] ?? '') . '</td>';
        $output .= '<td>' . htmlspecialchars($event['contact_info'] ?? '') . '</td>';
        $output .= '<td>' . htmlspecialchars($status_text) . '</td>';
        $output .= '<td>' . htmlspecialchars($payment_text) . '</td>';
        $output .= '</tr>';
    }
    
    $output .= '</tbody></table>';
    $output .= '<p><strong>Toplam Kayıt:</strong> ' . count($data) . '</p>';
    $output .= '</body></html>';
    
    echo $output;
    exit;
}


// --- POST İŞLEMLERİ ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Admin Girişi
    if (isset($_POST['admin_login'])) {
        $username = clean_input($_POST['username']);
        $password = $_POST['password']; 
        
        try {
            $stmt = $pdo->prepare("SELECT * FROM admin_users WHERE username = ? AND is_active = 1");
            $stmt->execute([$username]);
            $user = $stmt->fetch();
            
            if ($user && password_verify($password, $user['password'])) {
                session_regenerate_id(true);
                $_SESSION['admin'] = true;
                $_SESSION['admin_user'] = $user;

                // Eğer kullanıcı `super_admin` rolüne sahipse, oturumda bunu belirt
                if (isset($user['role']) && $user['role'] === 'super_admin') {
                    $_SESSION['super_admin'] = true;
                }

                header('Location: ?page=admin'); exit;
            } else {
                $login_error = "Hatalı kullanıcı adı veya şifre.";
            }
        } catch (PDOException $e) {
            error_log("Admin giriş sorgusu hatası: " . $e->getMessage());
            $login_error = "Sistem hatası oluştu, lütfen logları kontrol edin.";
        }
    }
    
    // Admin Çıkışı
    if (isset($_POST['admin_logout'])) {
        $_SESSION = [];
        session_destroy();
        header('Location: ?page=index'); exit;
    }

    // Etkinlik Kaydetme (Create/Update)
    if (isset($_POST['save_event']) && is_admin() && validateCSRFToken($_POST['csrf_token'])) {
        $id = (int)$_POST['event_id'];
        $data = [
            clean_input($_POST['unit_id']), clean_input($_POST['event_date']), clean_input($_POST['event_name']), 
            clean_input($_POST['event_time']), clean_input($_POST['event_contact']), clean_input($_POST['event_notes']), 
            clean_input($_POST['event_status']), empty($_POST['payment_status']) ? null : clean_input($_POST['payment_status'])
        ];
        try {
            if ($id > 0) {
                $sql = "UPDATE events SET unit_id=?, event_date=?, event_name=?, event_time=?, contact_info=?, notes=?, status=?, payment_status=? WHERE id=?";
                $data[] = $id;
                $stmt = $pdo->prepare($sql);
            } else {
                $sql = "INSERT INTO events (unit_id, event_date, event_name, event_time, contact_info, notes, status, payment_status) VALUES (?,?,?,?,?,?,?,?)";
                $stmt = $pdo->prepare($sql);
            }
            $stmt->execute($data);
            $_SESSION['message'] = "Kayıt başarıyla kaydedildi!";
        } catch (PDOException $e) {
            error_log("Etkinlik kaydetme hatası: " . $e->getMessage());
            $_SESSION['error'] = "Veritabanı hatası oluştu.";
        }
        header("Location: " . ($_POST['source_page'] == 'admin' ? "?page=admin&tab=events" : "?page=index")); exit;
    }

    // Silme İşlemleri (Genel)
    if (isset($_POST['delete_item']) && is_admin() && validateCSRFToken($_POST['csrf_token'])) {
        $table = clean_input($_POST['table']);
        $id = (int)$_POST['id'];
        if (in_array($table, ['events', 'units', 'holidays', 'admin_users', 'announcements'])) {
             try {
                $pdo->prepare("DELETE FROM $table WHERE id=?")->execute([$id]);
                $_SESSION['message'] = "Kayıt başarıyla silindi!";
             } catch (PDOException $e) {
                 error_log("Silme hatası ($table): " . $e->getMessage());
                 $_SESSION['error'] = "Kayıt silinirken veritabanı hatası oluştu.";
             }
        }
        header("Location: " . $_SERVER['REQUEST_URI']); exit;
    }

    // Birim Kaydet/Güncelle
    if (isset($_POST['save_unit']) && is_admin() && validateCSRFToken($_POST['csrf_token'])) {
        $id = (int)$_POST['unit_id'];
        $name = clean_input($_POST['unit_name']);
        $color = clean_input($_POST['unit_color']);
        $active = isset($_POST['unit_active']) ? 1 : 0;
        try {
            if ($id > 0) {
                $pdo->prepare("UPDATE units SET unit_name = ?, color = ?, is_active = ? WHERE id = ?")
                    ->execute([$name, $color, $active, $id]);
            } else {
                $pdo->prepare("INSERT INTO units (unit_name, color, is_active) VALUES (?, ?, ?)")
                    ->execute([$name, $color, $active]);
            }
            $_SESSION['message'] = $id > 0 ? "Birim güncellendi!" : "Birim eklendi!";
        } catch (PDOException $e) {
            error_log("Birim kaydetme hatası: " . $e->getMessage());
            $_SESSION['error'] = "Veritabanı hatası oluştu.";
        }
        header("Location: ?page=admin&tab=units"); exit;
    }
    
    // SEKTÖR KAYDET/GÜNCELLE
    if (isset($_POST['save_sector']) && is_admin() && validateCSRFToken($_POST['csrf_token'])) {
        $key = clean_input($_POST['sector_key']);
        $new_key = clean_input($_POST['new_sector_key']);

        $data = [
            clean_input($_POST['sector_name']), clean_input($_POST['unit_label']), clean_input($_POST['event_label']), 
            clean_input($_POST['contact_label']), clean_input($_POST['time_label']), clean_input($_POST['icon']), 
            isset($_POST['is_active']) ? 1 : 0
        ];
        
        try {
            if ($key !== 'new') {
                $sql = "UPDATE app_sectors SET sector_name=?, unit_label=?, event_label=?, contact_label=?, time_label=?, icon=?, is_active=? WHERE sector_key=?";
                $data[] = $key;
                $pdo->prepare($sql)->execute($data);
                $_SESSION['message'] = "Sektör başarıyla güncellendi!";
            } else {
                 if (empty($new_key) || !preg_match('/^[a-z0-9_]+$/', $new_key)) {
                    $_SESSION['error'] = "Sektör anahtarı sadece küçük harf, rakam ve alt çizgi içermelidir.";
                    header("Location: ?page=admin&tab=sectors"); exit;
                 }
                $sql = "INSERT INTO app_sectors (sector_key, sector_name, unit_label, event_label, contact_label, time_label, icon, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
                array_unshift($data, $new_key);
                $pdo->prepare($sql)->execute($data);
                $_SESSION['message'] = "Yeni sektör başarıyla eklendi!";
            }
        } catch (PDOException $e) {
            $error_msg = (strpos($e->getMessage(), 'Duplicate entry') !== false) ? "Bu sektör anahtarı zaten mevcut!" : "Veritabanı hatası oluştu.";
            error_log("Sektör kaydetme hatası: " . $e->getMessage());
            $_SESSION['error'] = $error_msg;
        }
        header("Location: ?page=admin&tab=sectors"); exit;
    }
    
    // SEKTÖR SİLME
    if (isset($_POST['delete_sector']) && is_admin() && validateCSRFToken($_POST['csrf_token'])) {
        $key = clean_input($_POST['sector_key']);
        if ($key === $active_sector) {
            $_SESSION['error'] = "Aktif sektörü silemezsiniz. Lütfen önce başka bir sektörü aktif yapın.";
        } else {
             try {
                $pdo->prepare("DELETE FROM app_sectors WHERE sector_key=?")->execute([$key]);
                $_SESSION['message'] = "Sektör başarıyla silindi!";
             } catch (PDOException $e) {
                error_log("Sektör silme hatası: " . $e->getMessage());
                $_SESSION['error'] = "Silme işlemi sırasında bir hata oluştu.";
             }
        }
        header("Location: ?page=admin&tab=sectors"); exit;
    }


    // YÖNETİCİ KULLANICI KAYDET/GÜNCELLE
    if (isset($_POST['save_admin_user']) && is_admin() && validateCSRFToken($_POST['csrf_token'])) {
        $id = isset($_POST['user_id']) ? (int)$_POST['user_id'] : 0;
        $username = clean_input($_POST['username']);
        $password = $_POST['password']; 
        $full_name = clean_input($_POST['full_name']);
        $email = clean_input($_POST['email']);
        $is_active = isset($_POST['is_active']) ? 1 : 0;

        try {
            // Kullanıcı adı benzersizlik kontrolü
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM admin_users WHERE username = ? AND id <> ?");
            $stmt->execute([$username, $id]);
            if ($stmt->fetchColumn() > 0) {
                $_SESSION['error'] = "Bu kullanıcı adı zaten kullanılıyor!";
                header("Location: ?page=admin&tab=users"); exit;
            }

            if ($id > 0) {
                // Güncelleme
                $sql = "UPDATE admin_users SET username=?, full_name=?, email=?, is_active=?";
                $params = [$username, $full_name, $email, $is_active];
                if (!empty($password)) {
                    $sql .= ", password=?";
                    $params[] = password_hash($password, PASSWORD_DEFAULT);
                }
                $sql .= " WHERE id=?";
                $params[] = $id;
                $pdo->prepare($sql)->execute($params);
                $_SESSION['message'] = "Yönetici hesabı güncellendi!";
            } else {
                // Yeni Kayıt
                if (empty($password)) {
                    $_SESSION['error'] = "Yeni kullanıcı için şifre zorunludur!";
                    header("Location: ?page=admin&tab=users"); exit;
                }
                $hashed_password = password_hash($password, PASSWORD_DEFAULT);
                $sql = "INSERT INTO admin_users (username, password, full_name, email, is_active) VALUES (?, ?, ?, ?, ?)";
                $pdo->prepare($sql)->execute([$username, $hashed_password, $full_name, $email, $is_active]);
                $_SESSION['message'] = "Yeni yönetici başarıyla eklendi!";
            }
        } catch (PDOException $e) {
            error_log("Yönetici kaydetme hatası: " . $e->getMessage());
            $_SESSION['error'] = "Veritabanı hatası oluştu.";
        }
        header("Location: ?page=admin&tab=users"); exit;
    }

    // YÖNETİCİ KULLANICI SİLME
    if (isset($_POST['delete_admin_user']) && is_admin() && validateCSRFToken($_POST['csrf_token'])) {
        $id = (int)$_POST['user_id'];
        if ($id === ($_SESSION['admin_user']['id'] ?? 0)) {
            $_SESSION['error'] = "Kendi hesabınızı silemezsiniz!";
        } else {
            try {
                $pdo->prepare("DELETE FROM admin_users WHERE id=?")->execute([$id]);
                $_SESSION['message'] = "Yönetici hesabı başarıyla silindi!";
            } catch (PDOException $e) {
                error_log("Yönetici silme hatası: " . $e->getMessage());
                $_SESSION['error'] = "Silme işlemi sırasında bir hata oluştu.";
            }
        }
        header("Location: ?page=admin&tab=users"); exit;
    }


    // AYARLARI KAYDET (Aktif Sektör Değişimi)
    if (isset($_POST['save_settings']) && is_admin() && validateCSRFToken($_POST['csrf_token'])) {
        $sector = clean_input($_POST['active_sector']);
        try {
            $pdo->prepare("INSERT INTO app_settings (setting_key, setting_value) VALUES ('active_sector', ?) ON DUPLICATE KEY UPDATE setting_value=?")
                ->execute([$sector, $sector]);
            $_SESSION['message'] = "Sektör ayarı başarıyla güncellendi! Yeni mod: " . $sector;
        } catch (PDOException $e) {
             error_log("Ayar kaydetme hatası: " . $e->getMessage());
            $_SESSION['error'] = "Veritabanı hatası oluştu.";
        }
        header("Location: ?page=admin&tab=settings"); exit;
    }
    
    // LİSANS AYARLARINI KAYDET
    if (isset($_POST['save_license'])) {
        if (!is_super_admin() || !validateCSRFToken($_POST['csrf_token'])) {
            $_SESSION['error'] = "Bu alan yalnızca süper admin tarafından kullanılabilir.";
            header("Location: ?page=admin&tab=license"); exit;
        }
        $license_date = clean_input($_POST['license_expire_date']);
        if (!is_valid_date_string($license_date)) {
            $_SESSION['error'] = "Geçersiz lisans tarihi.";
            header("Location: ?page=admin&tab=license"); exit;
        }
        try {
            $pdo->prepare("INSERT INTO license_settings (id, license_expire_date) VALUES (1, ?) ON DUPLICATE KEY UPDATE license_expire_date = VALUES(license_expire_date)")
                ->execute([$license_date]);
            $_SESSION['message'] = "Lisans tarihi güncellendi!";
        } catch (PDOException $e) {
            error_log("Lisans kaydetme hatası: " . $e->getMessage());
            $_SESSION['error'] = "Lisans kaydedilirken veritabanı hatası oluştu.";
        }
        header("Location: ?page=admin&tab=license"); exit;
    }

    // RAPOR OLUŞTURMA İŞLEMİ
    if (isset($_POST['generate_report']) && is_admin() && validateCSRFToken($_POST['csrf_token'])) {
        $start_date = clean_input($_POST['start_date']);
        $end_date = clean_input($_POST['end_date']);
        $unit_id_filter = clean_input($_POST['unit_id_filter']);
        $status_filter = clean_input($_POST['status_filter']);
        $payment_filter = clean_input($_POST['payment_filter']);
        $export_type = clean_input($_POST['generate_report']); // 'view', 'xls', 'doc'

        if (!is_valid_date_string($start_date) || !is_valid_date_string($end_date)) {
            $_SESSION['error'] = "Geçersiz tarih aralığı.";
            header("Location: ?page=admin&tab=events"); exit;
        }

        try {
            $sql = "SELECT e.*, u.unit_name
                    FROM events e
                    JOIN units u ON e.unit_id = u.id
                    WHERE e.event_date BETWEEN ? AND ?";
            $params = [$start_date, $end_date];

            if (!empty($unit_id_filter)) {
                $sql .= " AND e.unit_id = ?";
                $params[] = $unit_id_filter;
            }
            if (!empty($status_filter)) {
                $sql .= " AND e.status = ?";
                $params[] = $status_filter;
            }
            if (!empty($payment_filter)) {
                $sql .= " AND e.payment_status = ?";
                $params[] = $payment_filter;
            }
            
            $sql .= " ORDER BY e.event_date, e.event_time";
            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);
            $report_data = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // Filtre metinlerini hazırla
            $date_range_text = turkish_date('d M Y', strtotime($start_date)) . ' - ' . turkish_date('d M Y', strtotime($end_date));
            $filters_array = [];
            if (!empty($unit_id_filter)) {
                $unit_name = $pdo->prepare("SELECT unit_name FROM units WHERE id = ?");
                $unit_name->execute([$unit_id_filter]);
                $filters_array[] = "Birim: " . ($unit_name->fetchColumn() ?: 'Bilinmiyor');
            }
            if (!empty($status_filter)) $filters_array[] = "Durum: " . ($all_event_statuses[$status_filter]['display_name'] ?? $status_filter);
            if (!empty($payment_filter)) $filters_array[] = "Ödeme: " . ($all_payment_statuses[$payment_filter]['display_name'] ?? $payment_filter);
            $filters_text = implode(" | ", $filters_array);
            
            // Eğer dosya indirme isteniyorsa
            if ($export_type === 'xls') {
                generateXLS($report_data, $lang['title'] . " Raporu", $date_range_text, $filters_text);
            } elseif ($export_type === 'doc') {
                generateDOC($report_data, $lang['title'] . " Raporu", $date_range_text, $filters_text);
            }

            // Sayfa içi gösterim için oturuma kaydet
            $_SESSION['report_data'] = $report_data;
            $_SESSION['report_params'] = [
                'date_range' => $date_range_text,
                'filters' => $filters_text,
                'title' => $lang['title'] . " Raporu"
            ];
            header("Location: ?page=admin&tab=events"); exit;
            
        } catch(PDOException $e) {
            error_log("Rapor oluşturma hatası: " . $e->getMessage());
            $_SESSION['error'] = "Rapor oluşturulurken bir veritabanı hatası oluştu.";
            header("Location: ?page=admin&tab=events"); exit;
        }
    }
}

// --- VERİ GETİRME VE GÖRÜNÜM AYARLARI ---
$page = $_GET['page'] ?? 'index';
$current_year = date('Y');
$current_month = date('n');
$selected_month = filter_input(INPUT_GET, 'month', FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 12]]) ?? $current_month;
$selected_year = filter_input(INPUT_GET, 'year', FILTER_VALIDATE_INT, ['options' => ['min_range' => $current_year - 5, 'max_range' => $current_year + 5]]) ?? $current_year;

// Mesaj ve hata kontrolü
$message = $_SESSION['message'] ?? null; unset($_SESSION['message']);
$error = $_SESSION['error'] ?? null; unset($_SESSION['error']);


try {
    $units = $pdo->query("SELECT * FROM units WHERE is_active=1 ORDER BY unit_name")->fetchAll();
} catch (PDOException $e) {
    $units = []; 
}

$selected_unit = filter_input(INPUT_GET, 'unit_id', FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]) ?? null;
if (!$selected_unit && count($units) > 0) $selected_unit = $units[0]['id'];

?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($lang['title']); ?> - Rezervasyon Paneli</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary-color: #2c3e50;
            --secondary-color: #34495e;
            --accent-color: #3498db;
            --bg-light: #ecf0f1;
        }
        body { 
            font-family: 'Segoe UI', sans-serif; 
            background-color: var(--bg-light); 
        }
        
        /* Genel Mobil Uyumluluk */
        .container {
            padding-left: 10px;
            padding-right: 10px;
        }

        .navbar { 
            background-color: var(--primary-color); 
            box-shadow: 0 2px 4px rgba(0,0,0,0.1); 
        }
        .card { 
            border: none; 
            border-radius: 8px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.05); 
            margin-bottom: 20px; 
        }
        
        /* Takvim Görünümü (Mobile First: Tek Sütun) */
        .calendar-grid { 
            display: grid; 
            grid-template-columns: 1fr; /* Mobil: Tek sütun */
            gap: 15px; /* Mobil: Daha büyük boşluk */
        }
        
        /* Tablet ve Masaüstü Görünümü (992px üstü) */
        @media (min-width: 992px) { 
            .calendar-grid { 
                grid-template-columns: repeat(7, 1fr); /* Masaüstü: 7 sütun */
                gap: 8px; /* Masaüstü: Daha küçük boşluk */
            }
            .day-card {
                min-height: 150px;
            }
            .admin-nav-tabs .nav-link {
                /* Yatay düzen için */
                border-bottom: 2px solid transparent !important;
            }
        }
        
        /* Gün Kartları ve Etkinlikler (Dokunmatik Kullanım İçin Büyütme) */
        .day-card { 
            background: white; 
            border-radius: 8px; 
            border: 1px solid #dee2e6; 
            transition: transform 0.2s; 
            min-height: 100px; /* Mobil min yükseklik */
        }
        .day-card:hover { 
            transform: translateY(-3px); 
            box-shadow: 0 5px 15px rgba(0,0,0,0.1); 
        }
        .day-header { 
            background: #f8f9fa; 
            padding: 10px 15px; /* Mobil: Daha büyük padding */
            font-weight: bold; 
            border-radius: 8px 8px 0 0; 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
        }
        
        .day-card.weekend .day-header { background-color: #ffeaa7; color: #d35400; }
        .day-card.holiday .day-header { background-color: #fcebeb; color: #e74c3c; } 

        .event-item { 
            font-size: 0.9rem; /* Mobil: Daha okunaklı font */
            padding: 10px; /* Mobil: Büyük dokunmatik hedef */
            margin-bottom: 8px; 
            border-radius: 6px; 
            border-left: 5px solid #3498db; /* Kalın border */
            background: #fdfdfd; 
            cursor: pointer; 
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }
        .event-item:hover { background: #eee; }
        
        /* Yönetim Paneli Navigasyonu (Mobil) */
        .admin-nav-tabs .list-group-item {
            border-radius: 4px;
            margin-bottom: 5px;
            border: 1px solid #ddd;
        }

        .admin-nav-tabs .list-group-item.active {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
        }
        
        /* Form Elementleri (Dokunmatik uyum) */
        .form-control, .form-select, .btn {
            padding: 10px 15px;
            font-size: 1rem;
            border-radius: 6px;
        }


        .badge-status { font-size: 0.7rem; }
        .report-table th { background-color: var(--primary-color) !important; color: white !important; }
        .report-summary { background-color: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #dee2e6;}

        <?php
        // Dinamik Badge Stilleri
        function generateBadgeStyle($status) {
            $style = "background-color: " . htmlspecialchars($status['color']) . " !important; color: white !important; font-weight: 500;";
            $hex = ltrim($status['color'], '#');
            if (strlen($hex) == 6) {
                $r = hexdec(substr($hex, 0, 2));
                $g = hexdec(substr($hex, 2, 2));
                $b = hexdec(substr($hex, 4, 2));
                $luminance = (0.299 * $r + 0.587 * $g + 0.114 * $b) / 255;
                if ($luminance > 0.65) $style .= " color: #212529 !important; text-shadow: none;";
            }
            return $style;
        }

        foreach ($all_event_statuses as $key => $status) {
            echo ".badge-status-$key { " . generateBadgeStyle($status) . " }\n";
        }
        foreach ($all_payment_statuses as $key => $status) {
            echo ".badge-payment-$key { " . generateBadgeStyle($status) . " }\n";
        }
        ?>
    </style>
</head>
<body>

<nav class="navbar navbar-expand-lg navbar-dark mb-4">
    <div class="container">
        <a class="navbar-brand" href="?page=index">
            <i class="fas <?php echo $lang['icon']; ?> me-2"></i><?php echo htmlspecialchars($lang['title']); ?>
        </a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav"><span class="navbar-toggler-icon"></span></button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav ms-auto">
                <li class="nav-item"><a class="nav-link <?php echo $page=='index'?'active':''; ?>" href="?page=index">Takvim</a></li>
                <?php if(is_admin()): ?>
                    <li class="nav-item"><a class="nav-link <?php echo $page=='admin'?'active':''; ?>" href="?page=admin&tab=events">Yönetim Paneli</a></li>
                    <li class="nav-item d-flex align-items-center ms-2">
                        <span class="badge bg-light text-dark me-2"><?php echo htmlspecialchars($_SESSION['admin_user']['username']); ?></span>
                        <form method="post"><button name="admin_logout" class="btn btn-sm btn-outline-danger">Çıkış</button></form>
                    </li>
                <?php else: ?>
                    <li class="nav-item"><a class="nav-link" href="#" data-bs-toggle="modal" data-bs-target="#loginModal">Giriş</a></li>
                <?php endif; ?>
            </ul>
        </div>
    </div>
</nav>

<div class="container">
    <?php if (isset($error) && $error): ?>
        <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
    <?php endif; ?>
    <?php if (isset($message) && $message): ?>
        <div class="alert alert-success"><?php echo htmlspecialchars($message); ?></div>
    <?php endif; ?>
    <?php if(isset($login_error) && $login_error): // Giriş denemesi başarısızsa ?>
        <div class="alert alert-danger"><?php echo htmlspecialchars($login_error); ?></div>
    <?php endif; ?>

    <?php if($page === 'index'): ?>
        <div class="card p-3">
            <form method="get" class="row g-3 align-items-center">
                <div class="col-md-4">
                    <label class="form-label fw-bold"><?php echo $lang['unit_label']; ?></label>
                    <select name="unit_id" class="form-select" onchange="this.form.submit()">
                        <?php if (empty($units)): ?>
                            <option value="">Lütfen yönetici panelinden birim/kaynak ekleyin.</option>
                        <?php endif; ?>
                        <?php foreach($units as $u): ?>
                            <option value="<?php echo $u['id']; ?>" <?php echo $selected_unit==$u['id']?'selected':''; ?>><?php echo htmlspecialchars($u['unit_name']); ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-md-3">
                    <label class="form-label fw-bold">Ay</label>
                    <select name="month" class="form-select" onchange="this.form.submit()">
                        <?php for($k=1; $k<=12; $k++): ?>
                            <option value="<?php echo $k; ?>" <?php echo $selected_month==$k?'selected':''; ?>><?php echo $turkish_months[$k]; ?></option>
                        <?php endfor; ?>
                    </select>
                </div>
                <div class="col-md-3">
                    <label class="form-label fw-bold">Yıl</label>
                    <input type="number" name="year" class="form-control" value="<?php echo $selected_year; ?>" onchange="this.form.submit()">
                </div>
                <div class="col-md-2 text-end">
                    <?php if(is_admin()): ?>
                        <label class="form-label d-block">&nbsp;</label>
                        <button type="button" class="btn btn-success w-100" onclick="newEvent()">
                            <i class="fas fa-plus"></i> Yeni Ekle
                        </button>
                    <?php endif; ?>
                </div>
            </form>
        </div>
        
        <div class="card p-2 mb-4">
            <div class="d-flex gap-3 flex-wrap justify-content-center">
                <h6>Durumlar:</h6>
                <?php foreach($all_event_statuses as $key=>$st): ?>
                    <span class="badge badge-status-<?php echo $key; ?>"><?php echo $st['display_name']; ?></span>
                <?php endforeach; ?>
                <h6>Ödeme:</h6>
                <?php foreach($all_payment_statuses as $key=>$st): ?>
                    <span class="badge badge-payment-<?php echo $key; ?>"><?php echo $st['display_name']; ?></span>
                <?php endforeach; ?>
            </div>
        </div>

        <?php if ($selected_unit): ?>
        <div class="calendar-grid mb-5">
            <?php
            $days_in_month = cal_days_in_month(CAL_GREGORIAN, $selected_month, $selected_year);
            $first_day_w = date('N', strtotime("$selected_year-$selected_month-01"));
            
            // Boş kutular (Pazartesi başlangıç)
            for($i=1; $i<$first_day_w; $i++) echo '<div class="d-none d-lg-block"></div>';

            // Etkinlikleri Çek
            $events_by_date = [];
            try {
                $raw_events = $pdo->prepare("SELECT * FROM events WHERE unit_id = ? AND event_date BETWEEN ? AND ? ORDER BY event_time");
                $raw_events->execute([$selected_unit, "$selected_year-$selected_month-01", "$selected_year-$selected_month-$days_in_month"]);
                foreach($raw_events->fetchAll() as $row) {
                    $events_by_date[$row['event_date']][] = $row;
                }
            } catch (PDOException $e) {
                echo '<div class="alert alert-danger w-100">Etkinlikler yüklenemedi. Veritabanı yapısını kontrol edin.</div>';
            }


            for($day=1; $day<=$days_in_month; $day++):
                $date = sprintf("%04d-%02d-%02d", $selected_year, $selected_month, $day);
                $is_weekend = (date('N', strtotime($date)) >= 6);
                $is_holiday_data = is_holiday($date, $pdo);
                $is_holiday_flag = $is_holiday_data !== false;
                
                $card_class = '';
                if ($is_holiday_flag) {
                    $card_class = 'holiday';
                } elseif ($is_weekend) {
                    $card_class = 'weekend';
                }
            ?>
                <div class="day-card <?php echo $card_class; ?>">
                    <div class="day-header">
                        <span><?php echo $day; ?> <small class="fw-normal"><?php echo mb_substr($turkish_months[$selected_month],0,3); ?></small></span>
                        <small class="text-muted"><?php echo turkish_date('l', strtotime($date)); ?></small>
                        <?php if($is_holiday_flag): ?>
                            <span class="badge bg-danger"><?php echo htmlspecialchars($is_holiday_data['holiday_name']); ?></span>
                        <?php endif; ?>
                        <?php if(is_admin()): ?>
                            <a href="#" class="text-success" onclick="newEventForDay('<?php echo $date; ?>')" title="Yeni <?php echo $lang['event_label']; ?> Ekle"><i class="fas fa-plus-circle"></i></a>
                        <?php endif; ?>
                    </div>
                    <div class="p-2">
                        <?php if (empty($day_events)): ?>
                            <p class="text-muted text-center" style="font-size: 0.8rem;">Kayıt yok.</p>
                        <?php endif; ?>
                        <?php foreach($day_events as $evt): 
                            $status_color = $all_event_statuses[$evt['status']]['color'] ?? '#ccc';
                            $payment_text = '';
                            if (!empty($evt['payment_status'])) {
                                $payment_data = $all_payment_statuses[$evt['payment_status']] ?? null;
                                if ($payment_data) {
                                    $payment_text = ' <span class="badge badge-payment-' . $evt['payment_status'] . ' ms-1">' . $payment_data['display_name'] . '</span>';
                                }
                            }
                        ?>
                            <div class="event-item" style="border-left-color: <?php echo $status_color; ?>" 
                                 onclick='editEvent(<?php echo json_encode($evt); ?>)'>
                                <strong><?php echo htmlspecialchars($evt['event_time']); ?></strong>
                                <?php echo $payment_text; ?><br>
                                <?php echo htmlspecialchars($evt['event_name']); ?>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            <?php endfor; ?>
        </div>
        <?php else: ?>
             <div class="alert alert-warning">Yönetilecek birim veya kaynak bulunamadı. Lütfen Admin Panelinden (Yönetim Paneli) birim/kaynak ekleyin.</div>
        <?php endif; ?>

    <?php elseif($page === 'admin'): if(!is_admin()) header("Location: ?page=index"); ?>
        <div class="row">
            <div class="col-md-3">
                <div class="list-group admin-nav-tabs">
                    <a href="?page=admin&tab=units" class="list-group-item list-group-item-action <?php echo ($_GET['tab']??'units')=='units'?'active':''; ?>"><?php echo $lang['unit_label']; ?> Yönetimi</a>
                    <a href="?page=admin&tab=events" class="list-group-item list-group-item-action <?php echo ($_GET['tab']??'')=='events'?'active':''; ?>">Raporlama & Etkinlik</a>
                    <a href="?page=admin&tab=users" class="list-group-item list-group-item-action <?php echo ($_GET['tab']??'')=='users'?'active':''; ?>">Yöneticiler</a>
                    <a href="?page=admin&tab=sectors" class="list-group-item list-group-item-action <?php echo ($_GET['tab']??'')=='sectors'?'active':''; ?>">Sektörler</a>
                    <a href="?page=admin&tab=settings" class="list-group-item list-group-item-action <?php echo ($_GET['tab']??'')=='settings'?'active':''; ?>">Aktif Sektör Ayarı</a>
                    <?php if (is_super_admin()): ?>
                        <a href="?page=admin&tab=license" class="list-group-item list-group-item-action <?php echo ($_GET['tab']??'')=='license'?'active':''; ?>">Lisans Yönetimi</a>
                    <?php endif; ?>
                </div>
            </div>
            <div class="col-md-9">
                <div class="card p-4">
                    <?php 
                    $tab = $_GET['tab'] ?? 'events';
                    if($tab == 'settings'): 
                    ?>
                        <h4>Aktif Sektör Seçimi</h4>
                        <p>İşletme tipinize göre arayüzü özelleştirin. Seçiminiz, takvimdeki **Birim/Oda** ve **Etkinlik** gibi tüm terimleri değiştirecektir.</p>
                        <form method="post">
                            <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                            <div class="mb-3">
                                <label class="form-label">Aktif Sektör Modu</label>
                                <select name="active_sector" class="form-select form-select-lg">
                                    <?php foreach($sector_configs as $key => $conf): ?>
                                        <option value="<?php echo $key; ?>" <?php echo $active_sector==$key?'selected':''; ?>>
                                            <?php echo $conf['title']; ?> (<?php echo $conf['unit_label']; ?> / <?php echo $conf['event_label']; ?>)
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                            <button type="submit" name="save_settings" class="btn btn-primary">Ayarları Kaydet</button>
                        </form>
                    
                    <?php elseif($tab == 'users'): 
                        try {
                            $admin_users = $pdo->query("SELECT id, username, full_name, email, is_active, created_at FROM admin_users ORDER BY username")->fetchAll();
                        } catch (PDOException $e) {
                             $admin_users = [];
                        }
                    ?>
                        <div class="d-flex justify-content-between mb-3">
                            <h4>Yönetici Kullanıcıları</h4>
                            <button class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#adminUserModal" onclick="newAdminUser()">Yeni Yönetici Ekle</button>
                        </div>
                        <div class="table-responsive">
                            <table class="table table-hover">
                                <thead>
                                    <tr>
                                        <th>Kullanıcı Adı</th>
                                        <th>Tam Ad</th>
                                        <th>E-posta</th>
                                        <th>Aktif</th>
                                        <th>Oluşturulma</th>
                                        <th>İşlemler</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach($admin_users as $user): ?>
                                    <tr>
                                        <td><?php echo htmlspecialchars($user['username']); ?></td>
                                        <td><?php echo htmlspecialchars($user['full_name'] ?: '-'); ?></td>
                                        <td><?php echo htmlspecialchars($user['email'] ?: '-'); ?></td>
                                        <td><?php echo $user['is_active'] ? 'Evet' : 'Hayır'; ?></td>
                                        <td><?php echo turkish_date('d M Y', strtotime($user['created_at'])); ?></td>
                                        <td>
                                            <button class="btn btn-sm btn-outline-primary" 
                                                    onclick='editAdminUser(<?php echo json_encode($user); ?>)'>Düzenle</button>
                                            <form method="post" class="d-inline" onsubmit="return confirm('Bu yöneticiyi silmek istediğinize emin misiniz?');">
                                                <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                                                <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                                                <button name="delete_admin_user" class="btn btn-sm btn-outline-danger" 
                                                        <?php echo ($user['id'] === ($_SESSION['admin_user']['id'] ?? 0)) ? 'disabled' : ''; ?>>Sil</button>
                                            </form>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>

                    <?php elseif($tab == 'sectors'): ?>
                        <?php 
                            $all_sectors = [];
                            try {
                                $all_sectors = $pdo->query("SELECT * FROM app_sectors ORDER BY sector_name")->fetchAll();
                            } catch (PDOException $e) {
                                echo '<div class="alert alert-danger">Sektör tablosu bulunamadı. Lütfen SQL Adım 1\'deki sorguyu çalıştırın.</div>';
                            }
                        ?>
                        <div class="d-flex justify-content-between mb-3">
                            <h4>Sektör Yönetimi</h4>
                            <button class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#sectorModal" onclick="newSector()">Yeni Sektör Ekle</button>
                        </div>
                        <?php if (!empty($all_sectors)): ?>
                        <div class="table-responsive">
                            <table class="table table-hover">
                                <thead><tr>
                                    <th>Anahtar</th><th>Ad</th><th>Birim Etiketi</th><th>Etkinlik Etiketi</th><th>Durum</th><th>İşlem</th>
                                </tr></thead>
                                <tbody>
                                    <?php foreach($all_sectors as $s): ?>
                                    <tr>
                                        <td><strong><?php echo htmlspecialchars($s['sector_key']); ?></strong></td>
                                        <td><?php echo htmlspecialchars($s['sector_name']); ?></td>
                                        <td><?php echo htmlspecialchars($s['unit_label']); ?></td>
                                        <td><?php echo htmlspecialchars($s['event_label']); ?></td>
                                        <td><?php echo $s['is_active'] ? 'Aktif' : 'Pasif'; ?></td>
                                        <td>
                                            <button class="btn btn-sm btn-outline-primary" onclick='editSector(<?php echo json_encode($s); ?>)'>Düzenle</button>
                                            <form method="post" class="d-inline" onsubmit="return confirm('Bu sektörü silmek istediğinize emin misiniz? Anahtar: <?php echo $s['sector_key']; ?>');">
                                                <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                                                <input type="hidden" name="sector_key" value="<?php echo $s['sector_key']; ?>">
                                                <button name="delete_sector" class="btn btn-sm btn-outline-danger" <?php echo ($s['sector_key'] == $active_sector) ? 'disabled' : ''; ?>>Sil</button>
                                            </form>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                        <?php endif; ?>
                    
                    <?php elseif($tab == 'license'): ?>
                        <?php if (!is_super_admin()): ?>
                            <div class="alert alert-danger">Bu alan sadece süper admin (ilhan) tarafından kullanılabilir.</div>
                        <?php else:
                            $license_error = '';
                            try {
                                $license_info = fetch_license_expire_date($pdo);
                            } catch (PDOException $e) {
                                $license_info = null;
                                $license_error = 'Lisans bilgisi okunurken hata oluştu: ' . $e->getMessage();
                            }
                        ?>
                            <h4>Lisans Yönetimi</h4>
                            <p>Sistemin kullanım süresini buradan uzatabilirsiniz. Lisans süresi dolduğunda yalnızca süper admin giriş yapabilir.</p>
                            <?php if ($license_error): ?>
                                <div class="alert alert-warning"><?php echo htmlspecialchars($license_error); ?></div>
                            <?php endif; ?>
                            <form method="post" class="mt-3">
                                <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                                <div class="mb-3">
                                    <label class="form-label">Lisans Bitiş Tarihi</label>
                                    <input type="date" name="license_expire_date" class="form-control" value="<?php echo htmlspecialchars($license_info['license_expire_date'] ?? date('Y-m-d', strtotime('+30 days'))); ?>" required>
                                </div>
                                <button type="submit" name="save_license" class="btn btn-primary">Lisans Tarihini Güncelle</button>
                            </form>
                            <?php if (!empty($license_info['updated_at'])): ?>
                                <p class="text-muted mt-3"><small>Son Güncelleme: <?php echo turkish_date('d M Y H:i', strtotime($license_info['updated_at'])); ?></small></p>
                            <?php endif; ?>
                        <?php endif; ?>

                    <?php elseif($tab == 'units'): ?>
                        <div class="d-flex justify-content-between mb-3">
                            <h4><?php echo $lang['unit_label']; ?> Listesi</h4>
                            <button class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#unitModal" onclick="newUnit()">Yeni <?php echo $lang['unit_label']; ?> Ekle</button>
                        </div>
                        <div class="table-responsive">
                            <table class="table table-hover">
                                <thead><tr><th>Ad</th><th>Renk</th><th>Durum</th><th>İşlem</th></tr></thead>
                                <tbody>
                                    <?php 
                                    $all_units = $pdo->query("SELECT * FROM units ORDER BY unit_name")->fetchAll();
                                    foreach($all_units as $u): ?>
                                    <tr>
                                        <td><?php echo htmlspecialchars($u['unit_name']); ?></td>
                                        <td><span class="badge" style="background-color:<?php echo $u['color']; ?>"><?php echo $u['color']; ?></span></td>
                                        <td><?php echo $u['is_active']?'Aktif':'Pasif'; ?></td>
                                        <td>
                                            <button class="btn btn-sm btn-outline-primary" onclick='editUnit(<?php echo json_encode($u); ?>)'>Düzenle</button>
                                            <form method="post" class="d-inline" onsubmit="return confirm('Bu kaydı silmek tüm ilgili etkinlikleri etkileyecektir. Emin misiniz?')">
                                                <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                                                <input type="hidden" name="table" value="units">
                                                <input type="hidden" name="id" value="<?php echo $u['id']; ?>">
                                                <button name="delete_item" class="btn btn-sm btn-outline-danger">Sil</button>
                                            </form>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php elseif($tab == 'events'): ?>
                        <h4>Raporlama ve Etkinlik Yönetimi</h4>
                        <p>Belirlenen tarihler arasındaki rezervasyonları filtreleyin ve raporları indirin veya sayfada görüntüleyin.</p>

                        <div class="card p-3 mb-4 bg-light">
                            <form method="post" onsubmit="return validateReportDates(this)" id="reportForm">
                                <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                                <div class="row g-3">
                                    <div class="col-md-3">
                                        <label for="start_date" class="form-label">Başlangıç Tarihi</label>
                                        <input type="date" class="form-control" id="start_date_report" name="start_date" required value="<?php echo date('Y-m-01'); ?>">
                                    </div>
                                    <div class="col-md-3">
                                        <label for="end_date" class="form-label">Bitiş Tarihi</label>
                                        <input type="date" class="form-control" id="end_date_report" name="end_date" required value="<?php echo date('Y-m-t'); ?>">
                                    </div>
                                    <div class="col-md-3">
                                        <label for="unit_id_filter" class="form-label"><?php echo $lang['unit_label']; ?></label>
                                        <select class="form-select" id="unit_id_filter" name="unit_id_filter">
                                            <option value="">Tümü</option>
                                            <?php foreach($units as $u): ?>
                                                <option value="<?php echo $u['id']; ?>"><?php echo htmlspecialchars($u['unit_name']); ?></option>
                                            <?php endforeach; ?>
                                        </select>
                                    </div>
                                    <div class="col-md-3">
                                        <label for="status_filter" class="form-label">Durum</label>
                                        <select class="form-select" id="status_filter" name="status_filter">
                                            <option value="">Tümü</option>
                                            <?php foreach($all_event_statuses as $key => $st): ?>
                                                <option value="<?php echo $key; ?>"><?php echo $st['display_name']; ?></option>
                                            <?php endforeach; ?>
                                        </select>
                                    </div>
                                    <div class="col-md-3">
                                        <label for="payment_filter" class="form-label">Ödeme</label>
                                        <select class="form-select" id="payment_filter" name="payment_filter">
                                            <option value="">Tümü</option>
                                            <?php foreach($all_payment_statuses as $key => $st): ?>
                                                <option value="<?php echo $key; ?>"><?php echo $st['display_name']; ?></option>
                                            <?php endforeach; ?>
                                        </select>
                                    </div>
                                    <div class="col-md-9 d-flex align-items-end gap-2">
                                        <button type="submit" name="generate_report" value="view" class="btn btn-primary flex-fill">
                                            <i class="fas fa-eye me-1"></i> Sayfada Görüntüle
                                        </button>
                                        <button type="submit" name="generate_report" value="xls" class="btn btn-success">
                                            <i class="fas fa-file-excel me-1"></i> XLS İndir
                                        </button>
                                        <button type="submit" name="generate_report" value="doc" class="btn btn-info">
                                            <i class="fas fa-file-word me-1"></i> DOC İndir
                                        </button>
                                    </div>
                                </div>
                            </form>
                        </div>
                        
                        <?php if (isset($_SESSION['report_data'])): 
                            $report_data = $_SESSION['report_data'];
                            $report_params = $_SESSION['report_params'];
                            unset($_SESSION['report_data']);
                            unset($_SESSION['report_params']);
                        ?>
                            <div class="report-view mt-4">
                                <h5><?php echo htmlspecialchars($report_params['title']); ?></h5>
                                <div class="report-summary">
                                    <p><strong>Tarih Aralığı:</strong> <?php echo htmlspecialchars($report_params['date_range']); ?></p>
                                    <p><strong>Filtreler:</strong> <?php echo htmlspecialchars($report_params['filters']); ?></p>
                                    <p><strong>Toplam Kayıt:</strong> <?php echo count($report_data); ?></p>
                                </div>
                                
                                <?php if (empty($report_data)): ?>
                                    <div class="alert alert-info">Belirtilen kriterlere uygun kayıt bulunamadı.</div>
                                <?php else: ?>
                                    <div class="table-responsive">
                                        <table class="table table-bordered table-striped report-table">
                                            <thead>
                                                <tr>
                                                    <th>Tarih</th>
                                                    <th>Gün</th>
                                                    <th><?php echo $lang['unit_label']; ?></th>
                                                    <th><?php echo $lang['event_label']; ?></th>
                                                    <th>Saat</th>
                                                    <th>İletişim</th>
                                                    <th>Durum</th>
                                                    <th>Ödeme</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <?php foreach ($report_data as $event): 
                                                    $is_weekend = date('N', strtotime($event['event_date'])) >= 6;
                                                    $is_holiday_data = is_holiday($event['event_date'], $pdo);
                                                    $row_class = '';
                                                    if ($is_holiday_data) $row_class = 'bg-warning-subtle'; // Tatilse hafif sarı
                                                    elseif ($is_weekend) $row_class = 'bg-secondary-subtle'; // Hafta sonu ise hafif gri
                                                ?>
                                                    <tr class="<?php echo $row_class; ?>">
                                                        <td><?php echo turkish_date('d M Y', strtotime($event['event_date'])); ?></td>
                                                        <td><?php echo turkish_date('l', strtotime($event['event_date'])); ?></td>
                                                        <td><?php echo htmlspecialchars($event['unit_name']); ?></td>
                                                        <td><?php echo htmlspecialchars($event['event_name']); ?></td>
                                                        <td><?php echo htmlspecialchars($event['event_time']); ?></td>
                                                        <td><?php echo htmlspecialchars($event['contact_info']); ?></td>
                                                        <td><span class="badge badge-status-<?php echo $event['status']; ?>"><?php echo $all_event_statuses[$event['status']]['display_name']; ?></span></td>
                                                        <td>
                                                            <?php 
                                                                $p_status = $event['payment_status'];
                                                                if ($p_status) {
                                                                    echo '<span class="badge badge-payment-' . $p_status . '">' . $all_payment_statuses[$p_status]['display_name'] . '</span>';
                                                                } else {
                                                                    echo '-';
                                                                }
                                                            ?>
                                                        </td>
                                                    </tr>
                                                <?php endforeach; ?>
                                            </tbody>
                                        </table>
                                    </div>
                                <?php endif; ?>
                            </div>
                        <?php endif; ?>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    <?php endif; ?>
</div>

<div class="modal fade" id="sectorModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <form method="post" class="modal-content">
            <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
            <input type="hidden" name="sector_key" id="sector_key">
            <div class="modal-header"><h5 class="modal-title" id="sectorModalLabel">Sektör Ekle/Düzenle</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
             <div class="modal-body">
                <div class="alert alert-info" id="sectorAlert">Sektör anahtarı (Key), küçük harf ve alt çizgi içermelidir ve kaydedildikten sonra değiştirilemez.</div>
                <div class="row">
                    <div class="col-md-6 mb-3">
                        <label class="form-label">Sektör Anahtarı (Key)</label>
                        <input type="text" name="new_sector_key" id="new_sector_key" class="form-control" placeholder="orn_sektor_adi" required>
                    </div>
                    <div class="col-md-6 mb-3">
                        <label class="form-label">Sektör Adı</label>
                        <input type="text" name="sector_name" id="sector_name" class="form-control" required>
                    </div>
                </div>
                <h6>Etiket Tanımları</h6>
                <div class="row">
                    <div class="col-md-4 mb-3">
                        <label class="form-label">Kaynak/Birim Etiketi</label>
                        <input type="text" name="unit_label" id="unit_label" class="form-control" placeholder="Örn: Araç / Avukat" required>
                    </div>
                    <div class="col-md-4 mb-3">
                        <label class="form-label">Etkinlik Etiketi</label>
                        <input type="text" name="event_label" id="event_label" class="form-control" placeholder="Örn: Kiralama / Seans" required>
                    </div>
                    <div class="col-md-4 mb-3">
                        <label class="form-label">İletişim Etiketi</label>
                        <input type="text" name="contact_label" id="contact_label" class="form-control" placeholder="Örn: Müşteri / Danışan" required>
                    </div>
                    <div class="col-md-4 mb-3">
                        <label class="form-label">Zaman Etiketi</label>
                        <input type="text" name="time_label" id="time_label" class="form-control" placeholder="Örn: Saat / Dönüş Saati" required>
                    </div>
                    <div class="col-md-4 mb-3">
                        <label class="form-label">İkon Sınıfı (Font Awesome)</label>
                        <input type="text" name="icon" id="icon" class="form-control" placeholder="Örn: fa-car, fa-gavel" required>
                    </div>
                    <div class="col-md-4 mb-3 d-flex align-items-end">
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" name="is_active" id="sector_is_active" value="1" checked>
                            <label class="form-check-label">Aktif (Görünsün)</label>
                        </div>
                    </div>
                </div>
            </div>
             <div class="modal-footer"><button type="submit" name="save_sector" class="btn btn-primary">Kaydet</button></div>
        </form>
    </div>
</div>


<div class="modal fade" id="adminUserModal" tabindex="-1">
    <div class="modal-dialog">
        <form method="post" class="modal-content">
            <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
            <input type="hidden" name="user_id" id="user_id">
            <div class="modal-header"><h5 class="modal-title" id="adminUserModalLabel">Yönetici Ekle/Düzenle</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
            <div class="modal-body">
                <div class="mb-3">
                    <label class="form-label">Kullanıcı Adı</label>
                    <input type="text" name="username" id="username" class="form-control" required>
                </div>
                <div class="mb-3">
                    <label class="form-label">Şifre (Değiştirmek istemiyorsanız boş bırakın)</label>
                    <input type="password" name="password" id="password" class="form-control">
                </div>
                <div class="mb-3">
                    <label class="form-label">Tam Ad</label>
                    <input type="text" name="full_name" id="full_name" class="form-control">
                </div>
                <div class="mb-3">
                    <label class="form-label">E-posta</label>
                    <input type="email" name="email" id="email" class="form-control">
                </div>
                <div class="mb-3 form-check">
                    <input class="form-check-input" type="checkbox" name="is_active" id="user_is_active" value="1" checked>
                    <label class="form-check-label">Aktif Hesap</label>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">İptal</button>
                <button type="submit" name="save_admin_user" class="btn btn-primary">Kaydet</button>
            </div>
        </form>
    </div>
</div>


<div class="modal fade" id="loginModal" tabindex="-1">
    <div class="modal-dialog">
        <form method="post" class="modal-content">
            <div class="modal-header"><h5 class="modal-title">Admin Girişi</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
            <div class="modal-body">
                <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                <div class="mb-3"><label>Kullanıcı Adı</label><input type="text" name="username" class="form-control" required></div>
                <div class="mb-3"><label>Şifre</label><input type="password" name="password" class="form-control" required></div>
            </div>
            <div class="modal-footer"><button type="button" class="btn btn-secondary" data-bs-dismiss="modal">İptal</button><button type="submit" name="admin_login" class="btn btn-primary">Giriş Yap</button></div>
        </form>
    </div>
</div>

<div class="modal fade" id="eventModal" tabindex="-1">
    <div class="modal-dialog">
        <form method="post" class="modal-content" id="eventForm">
            <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
            <input type="hidden" name="event_id" id="event_id">
            <input type="hidden" name="source_page" value="<?php echo $page; ?>">
            <div class="modal-header">
                <h5 class="modal-title">Kayıt Ekle/Düzenle</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div class="mb-3">
                    <label class="form-label"><?php echo $lang['unit_label']; ?></label>
                    <select name="unit_id" id="modal_unit_id" class="form-select" required>
                        <?php foreach($units as $u): ?>
                            <option value="<?php echo $u['id']; ?>"><?php echo htmlspecialchars($u['unit_name']); ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="row">
                    <div class="col-6 mb-3">
                        <label class="form-label">Tarih</label>
                        <input type="date" name="event_date" id="event_date" class="form-control" required>
                    </div>
                    <div class="col-6 mb-3">
                        <label class="form-label"><?php echo $lang['time_label']; ?></label>
                        <input type="text" name="event_time" id="event_time" class="form-control" placeholder="Örn: 14:00-15:00" required>
                    </div>
                </div>
                <div class="mb-3">
                    <label class="form-label"><?php echo $lang['event_label']; ?></label>
                    <input type="text" name="event_name" id="event_name" class="form-control" placeholder="<?php echo $lang['event_placeholder']; ?>" required>
                </div>
                <div class="mb-3">
                    <label class="form-label"><?php echo $lang['contact_label']; ?></label>
                    <input type="text" name="event_contact" id="event_contact" class="form-control">
                </div>
                <div class="row">
                    <div class="col-6 mb-3">
                        <label class="form-label">Durum</label>
                        <select name="event_status" id="event_status" class="form-select">
                            <?php foreach($all_event_statuses as $key=>$st): ?>
                                <option value="<?php echo $key; ?>"><?php echo $st['display_name']; ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="col-6 mb-3">
                        <label class="form-label">Ödeme</label>
                        <select name="payment_status" id="payment_status" class="form-select">
                            <option value="">Seçiniz</option>
                            <?php foreach($all_payment_statuses as $key=>$st): ?>
                                <option value="<?php echo $key; ?>"><?php echo $st['display_name']; ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                </div>
                <div class="mb-3">
                    <label class="form-label">Notlar</label>
                    <textarea name="event_notes" id="event_notes" class="form-control"></textarea>
                </div>
            </div>
            <div class="modal-footer d-flex justify-content-between">
                <button type="button" class="btn btn-danger" id="btnDeleteEvent" style="display:none;" onclick="deleteEvent()">Sil</button>
                <div>
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">İptal</button>
                    <button type="submit" name="save_event" class="btn btn-primary">Kaydet</button>
                </div>
            </div>
        </form>
    </div>
</div>

<div class="modal fade" id="unitModal" tabindex="-1">
    <div class="modal-dialog">
        <form method="post" class="modal-content">
            <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
            <input type="hidden" name="unit_id" id="form_unit_id">
             <div class="modal-header"><h5 class="modal-title"><?php echo $lang['unit_label']; ?> Düzenle</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
             <div class="modal-body">
                 <div class="mb-3"><label>Ad</label><input type="text" name="unit_name" id="form_unit_name" class="form-control" placeholder="<?php echo $lang['unit_placeholder']; ?>" required></div>
                 <div class="mb-3"><label>Renk</label><input type="color" name="unit_color" id="form_unit_color" class="form-control form-control-color"></div>
                 <div class="mb-3 form-check"><input type="checkbox" name="unit_active" id="form_unit_active" class="form-check-input" checked><label class="form-check-label">Aktif (Takvimde Görünsün)</label></div>
             </div>
             <div class="modal-footer"><button type="submit" name="save_unit" class="btn btn-primary">Kaydet</button></div>
        </form>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
    const eventModal = new bootstrap.Modal(document.getElementById('eventModal'));
    const unitModal = new bootstrap.Modal(document.getElementById('unitModal'));
    const sectorModal = new bootstrap.Modal(document.getElementById('sectorModal'));
    const adminUserModal = new bootstrap.Modal(document.getElementById('adminUserModal'));
    const currentUnitId = '<?php echo $selected_unit; ?>';
    
    // Global form oluşturucu
    const deleteFormHtml = `
        <form method="post" id="deleteItemForm" style="display:none;">
            <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
            <input type="hidden" name="table" id="delete_table_input">
            <input type="hidden" name="id" id="delete_id_input">
            <input type="hidden" name="delete_item" value="1">
        </form>
    `;
    document.body.insertAdjacentHTML('beforeend', deleteFormHtml);

    function newEvent() {
        document.getElementById('eventForm').reset();
        document.getElementById('event_id').value = '';
        document.getElementById('modal_unit_id').value = currentUnitId;
        document.getElementById('event_date').value = new Date().toISOString().split('T')[0];
        document.getElementById('event_status').value = 'pending';
        document.getElementById('payment_status').value = 'unpaid';
        document.getElementById('btnDeleteEvent').style.display = 'none';
        eventModal.show();
    }

    function newEventForDay(date) {
        newEvent();
        document.getElementById('event_date').value = date;
    }

    function editEvent(evt) {
        if(!<?php echo is_admin()?'true':'false'; ?>) return;
        document.getElementById('event_id').value = evt.id;
        document.getElementById('modal_unit_id').value = evt.unit_id;
        document.getElementById('event_date').value = evt.event_date;
        document.getElementById('event_time').value = evt.event_time;
        document.getElementById('event_name').value = evt.event_name;
        document.getElementById('event_contact').value = evt.contact_info;
        document.getElementById('event_notes').value = evt.notes;
        document.getElementById('event_status').value = evt.status;
        document.getElementById('payment_status').value = evt.payment_status || '';
        document.getElementById('btnDeleteEvent').style.display = 'block';
        eventModal.show();
    }

    function deleteEvent() {
        if(confirm('Bu kaydı silmek istediğinizden emin misiniz?')) {
            document.getElementById('delete_id_input').value = document.getElementById('event_id').value;
            document.getElementById('delete_table_input').value = 'events';
            document.getElementById('deleteItemForm').submit();
        }
    }

    function newUnit() {
        document.getElementById('form_unit_id').value = '';
        document.getElementById('form_unit_name').value = '';
        document.getElementById('form_unit_color').value = '#3498db';
        document.getElementById('form_unit_active').checked = true;
        unitModal.show();
    }

    function editUnit(u) {
        document.getElementById('form_unit_id').value = u.id;
        document.getElementById('form_unit_name').value = u.unit_name;
        document.getElementById('form_unit_color').value = u.color;
        document.getElementById('form_unit_active').checked = (u.is_active == 1);
        unitModal.show();
    }
    
    // --- SEKTÖR MODAL İŞLEMLERİ ---
    
    function newSector() {
        document.getElementById('sectorModalLabel').innerText = 'Yeni Sektör Ekle';
        document.getElementById('sector_key').value = 'new';
        document.getElementById('new_sector_key').value = '';
        document.getElementById('new_sector_key').readOnly = false;
        document.getElementById('sector_name').value = '';
        document.getElementById('unit_label').value = '';
        document.getElementById('event_label').value = '';
        document.getElementById('contact_label').value = '';
        document.getElementById('time_label').value = '';
        document.getElementById('icon').value = '';
        document.getElementById('sector_is_active').checked = true;
        sectorModal.show();
    }
    
    function editSector(s) {
        document.getElementById('sectorModalLabel').innerText = 'Sektör Düzenle: ' + s.sector_name;
        document.getElementById('sector_key').value = s.sector_key;
        document.getElementById('new_sector_key').value = s.sector_key;
        document.getElementById('new_sector_key').readOnly = true; // Anahtar değiştirilemez
        document.getElementById('sector_name').value = s.sector_name;
        document.getElementById('unit_label').value = s.unit_label;
        document.getElementById('event_label').value = s.event_label;
        document.getElementById('contact_label').value = s.contact_label;
        document.getElementById('time_label').value = s.time_label;
        document.getElementById('icon').value = s.icon;
        document.getElementById('sector_is_active').checked = (s.is_active == 1);
        sectorModal.show();
    }
    
    // --- YÖNETİCİ MODAL İŞLEMLERİ ---

    function newAdminUser() {
        document.getElementById('adminUserModalLabel').innerText = 'Yeni Yönetici Ekle';
        document.getElementById('user_id').value = 0;
        document.getElementById('username').value = '';
        document.getElementById('full_name').value = '';
        document.getElementById('email').value = '';
        document.getElementById('password').value = '';
        document.getElementById('user_is_active').checked = true;
        adminUserModal.show();
    }

    function editAdminUser(u) {
        document.getElementById('adminUserModalLabel').innerText = 'Yönetici Düzenle: ' + u.username;
        document.getElementById('user_id').value = u.id;
        document.getElementById('username').value = u.username;
        document.getElementById('full_name').value = u.full_name;
        document.getElementById('email').value = u.email;
        document.getElementById('password').value = ''; // Şifreyi boş bırak
        document.getElementById('user_is_active').checked = (u.is_active == 1);
        adminUserModal.show();
    }


    // --- RAPORLAMA İŞLEMLERİ ---
    
    function validateReportDates(form) {
        const start = new Date(form.start_date.value);
        const end = new Date(form.end_date.value);
        if (start > end) {
            alert("Başlangıç tarihi, bitiş tarihinden sonra olamaz!");
            return false;
        }
        
        // Hangi butonun tıklandığını tespit etme (formun kendisi değil, basılan buton)
        const submitButton = document.activeElement;
        const exportType = submitButton.getAttribute('name') === 'generate_report' ? submitButton.value : 'view';

        // Hidden input'u oluştur veya güncelle
        let hiddenInput = form.querySelector('input[name="generate_report_type"]');
        if (!hiddenInput) {
            hiddenInput = document.createElement('input');
            hiddenInput.type = 'hidden';
            hiddenInput.name = 'generate_report'; // POST işlemi bunu kullanır
            form.appendChild(hiddenInput);
        }
        hiddenInput.value = exportType;
        
        return true;
    }

    // Başlangıç ve bitiş tarihlerini bugünün ayı ile otomatik doldurur
    document.addEventListener('DOMContentLoaded', function() {
        const today = new Date();
        const firstDayOfMonth = new Date(today.getFullYear(), today.getMonth(), 1).toISOString().split('T')[0];
        const lastDayOfMonth = new Date(today.getFullYear(), today.getMonth() + 1, 0).toISOString().split('T')[0];

        const startDateInput = document.getElementById('start_date_report');
        const endDateInput = document.getElementById('end_date_report');

        if (startDateInput && !startDateInput.value) {
            startDateInput.value = firstDayOfMonth;
        }
        if (endDateInput && !endDateInput.value) {
            endDateInput.value = lastDayOfMonth;
        }
    });
</script>
</body>
</html>
