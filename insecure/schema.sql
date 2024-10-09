-- User Table
CREATE TABLE User (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(64) NOT NULL,  -- Hash of the password using HMAC + Salt
    salt VARCHAR(32) NOT NULL,            -- Salt stored in hexadecimal format
    is_admin BOOLEAN DEFAULT 0 NOT NULL,  -- Admin flag (0: non-admin, 1: admin)
    reset_token VARCHAR(40),              -- Token for password resets
    token_expiry DATETIME                 -- Expiry time for reset token
);

-- Clients Table (Associated with a User)
CREATE TABLE Clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) NOT NULL,              -- Client name
    user_code VARCHAR(20) NOT NULL,             -- Unique code for the client
    address VARCHAR(255),                       -- Client address
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP -- Timestamp for when the client was created
);