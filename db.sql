-- Ajanda ve Rezervasyon Paneli - MySQL Başlangıç Şeması
SET NAMES utf8mb4;
SET time_zone = '+03:00';

CREATE DATABASE IF NOT EXISTS `etkinlik_takip` CHARACTER SET utf8mb4 COLLATE utf8mb4_turkish_ci;
USE `etkinlik_takip`;

-- Admin kullanıcıları
CREATE TABLE IF NOT EXISTS `admin_users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(100) NOT NULL UNIQUE,
  `password` varchar(255) NOT NULL,
  `full_name` varchar(150) DEFAULT NULL,
  `email` varchar(150) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_turkish_ci;

INSERT INTO `admin_users` (`username`,`password`,`full_name`,`email`,`is_active`) VALUES
('djmaster','$2y$12$5j7pxLshNc7IXE5DZ9pMK.hjmMKIc1QoB3Y8vCheymQ0eJEN5f3TS','Varsayılan Yönetici',NULL,1)
ON DUPLICATE KEY UPDATE username=username;

-- Lisans Ayarları
CREATE TABLE IF NOT EXISTS `license_settings` (
  `id` int NOT NULL,
  `license_expire_date` date NOT NULL,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_turkish_ci;

INSERT INTO `license_settings` (`id`, `license_expire_date`)
VALUES (1, DATE_ADD(CURDATE(), INTERVAL 30 DAY))
ON DUPLICATE KEY UPDATE license_expire_date = license_expire_date;

-- Sektörler
CREATE TABLE IF NOT EXISTS `sektorler` (
  `id` int NOT NULL AUTO_INCREMENT,
  `ad` varchar(150) NOT NULL,
  `slug` varchar(150) NOT NULL,
  `aciklama` text NULL,
  `aktif` tinyint(1) NOT NULL DEFAULT 1,
  PRIMARY KEY (`id`),
  UNIQUE KEY `slug_unique` (`slug`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_turkish_ci;

INSERT INTO `sektorler` (`ad`,`slug`,`aciklama`,`aktif`) VALUES
('Avukat','avukat','Avukatlar için görüşme takvimi',1),
('Psikolog','psikolog','Psikologlar için seans planlama',1),
('Araç Kiralama','arac-kiralama','Araç kiralama firmaları için araç takvimi',1),
('Fotoğrafçı','fotografci','Fotoğrafçılar için çekim rezervasyonu',1)
ON DUPLICATE KEY UPDATE ad=VALUES(ad), aciklama=VALUES(aciklama), aktif=VALUES(aktif);

-- Birimler
CREATE TABLE IF NOT EXISTS `units` (
  `id` int NOT NULL AUTO_INCREMENT,
  `unit_name` varchar(150) NOT NULL,
  `color` varchar(20) NOT NULL DEFAULT '#3498db',
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_turkish_ci;

INSERT INTO `units` (`id`,`unit_name`,`color`,`is_active`) VALUES
(1,'Genel Takvim','#3498db',1)
ON DUPLICATE KEY UPDATE unit_name=VALUES(unit_name), color=VALUES(color), is_active=VALUES(is_active);

-- Etkinlik Durumları
CREATE TABLE IF NOT EXISTS `event_statuses` (
  `id` int NOT NULL AUTO_INCREMENT,
  `status_key` varchar(50) NOT NULL,
  `display_name` varchar(100) NOT NULL,
  `color` varchar(20) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `status_key_unique` (`status_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_turkish_ci;

INSERT INTO `event_statuses` (`status_key`,`display_name`,`color`) VALUES
('confirmed','Onaylı','#2d6a4f'),
('option','Opsiyonlu','#0ea5e9'),
('cancelled','İptal','#ef4444'),
('free','Ücretsiz','#10b981')
ON DUPLICATE KEY UPDATE display_name=VALUES(display_name), color=VALUES(color);

-- Ödeme Durumları
CREATE TABLE IF NOT EXISTS `payment_statuses` (
  `id` int NOT NULL AUTO_INCREMENT,
  `status_key` varchar(50) NOT NULL,
  `display_name` varchar(100) NOT NULL,
  `color` varchar(20) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `payment_status_key_unique` (`status_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_turkish_ci;

INSERT INTO `payment_statuses` (`status_key`,`display_name`,`color`) VALUES
('paid','Ödendi','#16a34a'),
('not_paid','Ödenmedi','#ef4444'),
('to_be_paid','Ödeme Bekleniyor','#f97316')
ON DUPLICATE KEY UPDATE display_name=VALUES(display_name), color=VALUES(color);

-- Etkinlikler
CREATE TABLE IF NOT EXISTS `events` (
  `id` int NOT NULL AUTO_INCREMENT,
  `unit_id` int NOT NULL,
  `sektor_id` int NOT NULL,
  `event_date` date NOT NULL,
  `event_name` varchar(255) NOT NULL,
  `event_time` varchar(100) NOT NULL,
  `contact_info` varchar(255) DEFAULT NULL,
  `notes` text,
  `status` varchar(50) NOT NULL DEFAULT 'option',
  `payment_status` varchar(50) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_event_unit` (`unit_id`),
  KEY `idx_event_sector` (`sektor_id`),
  CONSTRAINT `fk_events_units` FOREIGN KEY (`unit_id`) REFERENCES `units`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT `fk_events_sektorler` FOREIGN KEY (`sektor_id`) REFERENCES `sektorler`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_turkish_ci;

-- Tatiller
CREATE TABLE IF NOT EXISTS `holidays` (
  `id` int NOT NULL AUTO_INCREMENT,
  `holiday_name` varchar(150) NOT NULL,
  `holiday_date` date NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `holiday_date_unique` (`holiday_date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_turkish_ci;

-- Duyurular
CREATE TABLE IF NOT EXISTS `announcements` (
  `id` int NOT NULL AUTO_INCREMENT,
  `content` text NOT NULL,
  `admin_user_id` int NOT NULL,
  `start_date` datetime DEFAULT NULL,
  `end_date` datetime DEFAULT NULL,
  `show_author` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_announcement_user` (`admin_user_id`),
  CONSTRAINT `fk_announcement_user` FOREIGN KEY (`admin_user_id`) REFERENCES `admin_users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_turkish_ci;

