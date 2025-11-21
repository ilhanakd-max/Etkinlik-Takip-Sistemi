-- phpMyAdmin SQL Dump
-- version 4.9.0.1
-- https://www.phpmyadmin.net/
--
-- Anamakine: sql211.infinityfree.com
-- Üretim Zamanı: 19 Kas 2025, 11:31:58
-- Sunucu sürümü: 11.4.7-MariaDB
-- PHP Sürümü: 7.2.22

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET AUTOCOMMIT = 0;
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Veritabanı: `if0_40197167_test`
--

-- --------------------------------------------------------

--
-- Tablo için tablo yapısı `active_sector`
--

CREATE TABLE `active_sector` (
  `id` int(11) NOT NULL,
  `active_sector_key` varchar(50) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_turkish_ci;

--
-- Tablo döküm verisi `active_sector`
--

INSERT INTO `active_sector` (`id`, `active_sector_key`) VALUES
(1, 'generic');

-- --------------------------------------------------------

--
-- Tablo için tablo yapısı `admin_users`
--

CREATE TABLE `admin_users` (
  `id` int(11) NOT NULL,
  `username` varchar(100) NOT NULL,
  `password` varchar(255) NOT NULL,
  `full_name` varchar(150) DEFAULT NULL,
  `email` varchar(150) DEFAULT NULL,
  `role` varchar(50) NOT NULL DEFAULT 'admin',
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_turkish_ci;

--
-- Tablo döküm verisi `admin_users`
--

INSERT INTO `admin_users` (`id`, `username`, `password`, `full_name`, `email`, `role`, `is_active`, `created_at`) VALUES
(1, 'admin', '$2y$12$5j7pxLshNc7IXE5DZ9pMK.hjmMKIc1QoB3Y8vCheymQ0eJEN5f3TS', 'Süper Yönetici', 'admin@example.com', 'super_admin', 1, '2025-11-19 13:45:19');

-- --------------------------------------------------------

--
-- Tablo için tablo yapısı `app_sectors`
--

CREATE TABLE `app_sectors` (
  `sector_key` varchar(50) NOT NULL,
  `sector_name` varchar(100) NOT NULL,
  `unit_label` varchar(50) NOT NULL,
  `event_label` varchar(50) NOT NULL,
  `contact_label` varchar(50) NOT NULL,
  `time_label` varchar(50) NOT NULL,
  `icon` varchar(50) NOT NULL,
  `is_active` tinyint(1) DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_turkish_ci;

--
-- Tablo döküm verisi `app_sectors`
--

INSERT INTO `app_sectors` (`sector_key`, `sector_name`, `unit_label`, `event_label`, `contact_label`, `time_label`, `icon`, `is_active`) VALUES
('car_rental', 'Araç Kiralama Ajandası', 'Araç / Plaka', 'Kiralama Durumu', 'Müşteri / Sürücü', 'Alış - Teslim Saati', 'fa-car', 1),
('generic', 'Genel Ajanda', 'Birim / Oda', 'Etkinlik', 'İletişim Kişisi', 'Saat', 'fa-calendar-check', 1),
('lawyer', 'Avukat Ajandası', 'Avukat / Mahkeme', 'Dava / Görüşme', 'Müvekkil', 'Duruşma Saati', 'fa-gavel', 1),
('photographer', 'Fotoğrafçı Paneli', 'Stüdyo', 'Çekim Türü', 'Müşteri', 'Çekim Saati', 'fa-camera-retro', 1),
('psychologist', 'Psikolog Paneli', 'Oda', 'Seans', 'Danışan', 'Seans Saati', 'fa-user-md', 1);

-- --------------------------------------------------------

--
-- Tablo için tablo yapısı `events`
--

CREATE TABLE `events` (
  `id` int(11) NOT NULL,
  `unit_id` int(11) NOT NULL,
  `sector_key` varchar(50) NOT NULL,
  `event_date` date NOT NULL,
  `event_name` varchar(255) NOT NULL,
  `event_time` varchar(100) NOT NULL,
  `contact_info` varchar(255) DEFAULT NULL,
  `notes` text DEFAULT NULL,
  `status` varchar(50) NOT NULL DEFAULT 'option',
  `payment_status` varchar(50) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_turkish_ci;

-- --------------------------------------------------------

--
-- Tablo için tablo yapısı `event_statuses`
--

CREATE TABLE `event_statuses` (
  `id` int(11) NOT NULL,
  `status_key` varchar(50) NOT NULL,
  `display_name` varchar(100) NOT NULL,
  `color` varchar(20) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_turkish_ci;

--
-- Tablo döküm verisi `event_statuses`
--

INSERT INTO `event_statuses` (`id`, `status_key`, `display_name`, `color`) VALUES
(1, 'confirmed', 'Onaylı', '#2d6a4f'),
(2, 'option', 'Opsiyonlu', '#0ea5e9'),
(3, 'cancelled', 'İptal', '#ef4444'),
(4, 'free', 'Ücretsiz', '#10b981');

-- --------------------------------------------------------

--
-- Tablo için tablo yapısı `holidays`
--

CREATE TABLE `holidays` (
  `id` int(11) NOT NULL,
  `holiday_name` varchar(150) NOT NULL,
  `holiday_date` date NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_turkish_ci;

-- --------------------------------------------------------

--
-- Tablo için tablo yapısı `license_settings`
--

CREATE TABLE `license_settings` (
  `id` int(11) NOT NULL,
  `license_expire_date` date NOT NULL,
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_turkish_ci;

--
-- Tablo döküm verisi `license_settings`
--

INSERT INTO `license_settings` (`id`, `license_expire_date`, `updated_at`) VALUES
(1, '2025-12-18', '2025-11-19 13:59:40');

-- --------------------------------------------------------

--
-- Tablo için tablo yapısı `payment_statuses`
--

CREATE TABLE `payment_statuses` (
  `id` int(11) NOT NULL,
  `status_key` varchar(50) NOT NULL,
  `display_name` varchar(100) NOT NULL,
  `color` varchar(20) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_turkish_ci;

--
-- Tablo döküm verisi `payment_statuses`
--

INSERT INTO `payment_statuses` (`id`, `status_key`, `display_name`, `color`) VALUES
(1, 'paid', 'Ödendi', '#16a34a'),
(2, 'not_paid', 'Ödenmedi', '#ef4444'),
(3, 'to_be_paid', 'Ödeme Bekleniyor', '#f97316');

-- --------------------------------------------------------

--
-- Tablo için tablo yapısı `units`
--

CREATE TABLE `units` (
  `id` int(11) NOT NULL,
  `unit_name` varchar(150) NOT NULL,
  `color` varchar(20) NOT NULL DEFAULT '#3498db',
  `is_active` tinyint(1) NOT NULL DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_turkish_ci;

--
-- Tablo döküm verisi `units`
--

INSERT INTO `units` (`id`, `unit_name`, `color`, `is_active`) VALUES
(1, 'Genel Takvim', '#3498db', 1);

--
-- Dökümü yapılmış tablolar için indeksler
--

--
-- Tablo için indeksler `active_sector`
--
ALTER TABLE `active_sector`
  ADD PRIMARY KEY (`id`);

--
-- Tablo için indeksler `admin_users`
--
ALTER TABLE `admin_users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`);

--
-- Tablo için indeksler `app_sectors`
--
ALTER TABLE `app_sectors`
  ADD PRIMARY KEY (`sector_key`);

--
-- Tablo için indeksler `events`
--
ALTER TABLE `events`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_event_unit` (`unit_id`),
  ADD KEY `idx_event_sector` (`sector_key`);

--
-- Tablo için indeksler `event_statuses`
--
ALTER TABLE `event_statuses`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `status_key_unique` (`status_key`);

--
-- Tablo için indeksler `holidays`
--
ALTER TABLE `holidays`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `holiday_date_unique` (`holiday_date`);

--
-- Tablo için indeksler `license_settings`
--
ALTER TABLE `license_settings`
  ADD PRIMARY KEY (`id`);

--
-- Tablo için indeksler `payment_statuses`
--
ALTER TABLE `payment_statuses`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `payment_status_key_unique` (`status_key`);

--
-- Tablo için indeksler `units`
--
ALTER TABLE `units`
  ADD PRIMARY KEY (`id`);

--
-- Dökümü yapılmış tablolar için AUTO_INCREMENT değeri
--

--
-- Tablo için AUTO_INCREMENT değeri `active_sector`
--
ALTER TABLE `active_sector`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- Tablo için AUTO_INCREMENT değeri `admin_users`
--
ALTER TABLE `admin_users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- Tablo için AUTO_INCREMENT değeri `events`
--
ALTER TABLE `events`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- Tablo için AUTO_INCREMENT değeri `event_statuses`
--
ALTER TABLE `event_statuses`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5;

--
-- Tablo için AUTO_INCREMENT değeri `holidays`
--
ALTER TABLE `holidays`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- Tablo için AUTO_INCREMENT değeri `payment_statuses`
--
ALTER TABLE `payment_statuses`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- Tablo için AUTO_INCREMENT değeri `units`
--
ALTER TABLE `units`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- Dökümü yapılmış tablolar için kısıtlamalar
--

--
-- Tablo kısıtlamaları `events`
--
ALTER TABLE `events`
  ADD CONSTRAINT `fk_events_sector` FOREIGN KEY (`sector_key`) REFERENCES `app_sectors` (`sector_key`) ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_events_units` FOREIGN KEY (`unit_id`) REFERENCES `units` (`id`) ON UPDATE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
