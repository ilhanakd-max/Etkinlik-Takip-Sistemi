# Etkinlik Takip Sistemi v2

Bu depo küçük işletmeler için geliştirilen PHP tabanlı ajanda ve rezervasyon panelini içerir. Tek dosyalı (index.php) uygulama PDO kullanarak MySQL veritabanına bağlanır ve farklı sektörler için özelleştirilebilir.

## Kurulum
1. `db.sql` dosyasını veya `database/migrations/` dizinindeki SQL dosyalarını MySQL sunucunuza uygulayın.
   - `20251119_create_license_settings.sql` betiği yeni lisans tablosunu oluşturur ve ilk kaydı (şu andan +30 gün) ekler.
2. `index.php` içindeki veritabanı kimlik bilgilerini düzenleyin.
3. Uygulamayı PHP 8+ çalıştıran bir sunucuda barındırın.

## Lisans Yönetimi
- Yönetim panelindeki **Lisans Yönetimi** sekmesi yalnızca süper admin kullanıcıya (varsayılan: `ilhan`) görünür.
- Süper admin varsayılan kimlik bilgileri: `ilhan` / `Cfm102.5`.
- Bu panelden lisans bitiş tarihini güncelleyebilirsiniz. Tarih `license_settings` tablosundaki `license_expire_date` alanında tutulur.
- Lisans süresi dolduğunda sistem tüm kullanıcıları bloklar; sadece süper admin giriş yapabilir ve tarihi uzatabilir.

## Lisans Kontrolünü Devre Dışı Bırakma
Yerel geliştirme sırasında lisans kontrolünü devre dışı bırakmak için çevre değişkeni tanımlayabilirsiniz:

```bash
export LICENSE_CHECK=false
```

veya `config.php` içinde `license_check` değerini manuel olarak `false` yapabilirsiniz. Bu ayar yalnızca geliştirme amaçlıdır.

## Testler
Lisans kontrolüne ait basit entegrasyon testleri `tests/license_middleware_test.php` dosyasında bulunur. Çalıştırmak için:

```bash
php tests/license_middleware_test.php
```

Testler, lisans süresi dolduğunda normal kullanıcıların engellendiğini ve süper adminin erişmeye devam edebildiğini doğrular.
