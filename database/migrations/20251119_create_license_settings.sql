CREATE TABLE IF NOT EXISTS `license_settings` (
  `id` int NOT NULL,
  `license_expire_date` date NOT NULL,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_turkish_ci;

INSERT INTO `license_settings` (`id`, `license_expire_date`)
VALUES (1, DATE_ADD(CURDATE(), INTERVAL 30 DAY))
ON DUPLICATE KEY UPDATE license_expire_date = license_expire_date;
