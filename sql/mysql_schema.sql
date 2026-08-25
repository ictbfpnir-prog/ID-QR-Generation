-- =====================================================================
-- BFP-NIR QR Profile System — MySQL / MariaDB schema (final version)
-- Adds admin_users for real authentication on top of the previous
-- personnel / personnel_photo / personnel_sensitive / scan_log tables.
-- =====================================================================

CREATE DATABASE IF NOT EXISTS bfp_qr_system
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE bfp_qr_system;

-- ---------------------------------------------------------------------
-- admin_users: accounts allowed to log into the admin/records interface.
-- Passwords are bcrypt hashes — never plaintext. Created via the
-- seed-admin.js script, never inserted by hand.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin_users (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  username      VARCHAR(50) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  role          ENUM('admin','records_staff') NOT NULL DEFAULT 'admin',
  is_active     BOOLEAN NOT NULL DEFAULT TRUE,
  created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_login_at TIMESTAMP NULL
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- personnel: fields safe to show on the public QR-scan profile page.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS personnel (
  id_number       VARCHAR(20)  PRIMARY KEY,
  `rank`          VARCHAR(50)  NOT NULL,
  full_name       VARCHAR(150) NOT NULL,
  officer_type    VARCHAR(50)  NOT NULL DEFAULT 'Commissioned Officer',
  unit_assignment VARCHAR(150),
  unit_code       VARCHAR(20)  DEFAULT 'BFP-NIR',
  status          ENUM('Active','Inactive','Revoked') NOT NULL DEFAULT 'Active',
  date_issued     DATE,
  expiry_date     DATE,
  created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- personnel_photo: photo bytes stored separately from the main record.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS personnel_photo (
  id_number   VARCHAR(20) PRIMARY KEY,
  mime_type   VARCHAR(50),
  photo_blob  LONGBLOB,
  FOREIGN KEY (id_number) REFERENCES personnel(id_number) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- personnel_sensitive: TIN, GSIS, PAG-IBIG, PhilHealth, address, DOB,
-- emergency contact. Only ever reachable through an authenticated
-- admin session — never on the public profile page or in the QR.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS personnel_sensitive (
  id_number         VARCHAR(20) PRIMARY KEY,
  date_of_birth     DATE,
  blood_type        VARCHAR(5),
  height            VARCHAR(20),
  weight            VARCHAR(20),
  eyes              VARCHAR(30),
  hair              VARCHAR(30),
  religion          VARCHAR(50),
  home_address      VARCHAR(255),
  tin               VARCHAR(20),
  gsis_no           VARCHAR(20),
  pagibig_no        VARCHAR(20),
  philhealth_no     VARCHAR(20),
  emergency_contact VARCHAR(150),
  FOREIGN KEY (id_number) REFERENCES personnel(id_number) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- scan_log: audit trail of every profile view / admin access attempt.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_log (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  id_number   VARCHAR(20),
  role        VARCHAR(20),
  result      VARCHAR(10),
  reason      VARCHAR(255),
  scanned_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_scan_log_id_number (id_number),
  INDEX idx_scan_log_scanned_at (scanned_at)
) ENGINE=InnoDB;
