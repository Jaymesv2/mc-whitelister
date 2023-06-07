-- Add up migration script here
CREATE TABLE IF NOT EXISTS user (
    id varchar(255) PRIMARY KEY NOT NULL,
    name varchar(255) NOT NULL
);

-- The id is useless but it works 
CREATE TABLE IF NOT EXISTS user_access_token (
    user_id varchar(255) PRIMARY KEY NOT NULL,
    token varchar(4096) NOT NULL,
    issued DATETIME NOT NULL,
    expires DATETIME NULL,
    FOREIGN KEY (user_id) REFERENCES user (id)
);

CREATE INDEX user_access_token_user_id_index ON user_access_token (user_id);

CREATE TABLE IF NOT EXISTS user_refresh_token (
    user_id varchar(255) PRIMARY KEY NOT NULL,
    token varchar(4096) NOT NULL,
    issued DATETIME NOT NULL,
    expires DATETIME NULL,
    FOREIGN KEY (user_id) REFERENCES user (id)
);

CREATE INDEX user_refresh_token_user_id_index ON user_refresh_token (user_id);

CREATE TABLE IF NOT EXISTS microsoft_account (
    microsoft_id varchar(64) PRIMARY KEY NOT NULL,
    user_id varchar(255) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES user (id)
);

CREATE TABLE IF NOT EXISTS microsoft_access_token (
    microsoft_id varchar(64) PRIMARY KEY NOT NULL,
    token varchar(4096) NOT NULL,
    issued DATETIME NOT NULL,
    expires DATETIME NULL,
    FOREIGN KEY (microsoft_id) REFERENCES microsoft_account (microsoft_id)
);

CREATE TABLE IF NOT EXISTS microsoft_refresh_token (
    microsoft_id varchar(64) PRIMARY KEY NOT NULL,
    token varchar(4096) NOT NULL,
    issued DATETIME NOT NULL,
    expires DATETIME NULL,
    FOREIGN KEY (microsoft_id) REFERENCES microsoft_account (microsoft_id)
);

CREATE TABLE IF NOT EXISTS minecraft_token (
    microsoft_id varchar(64) PRIMARY KEY NOT NULL,
    token VARCHAR(255) NOT NULL,
    expires DATETIME NULL,
    issued DATETIME NOT NULL,
    FOREIGN KEY (microsoft_id) REFERENCES microsoft_account (microsoft_id)
);

CREATE TABLE IF NOT EXISTS minecraft_profile (
    microsoft_id VARCHAR(255) PRIMARY KEY NOT NULL,
    uuid VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL,
    skin_id VARCHAR(255) NOT NULL,
    skin_url VARCHAR(512) NOT NULL,
    skin_variant VARCHAR(255) NOT NULL,
    skin_alias VARCHAR(255) NOT NULL,
    FOREIGN KEY (microsoft_id) REFERENCES microsoft_account(microsoft_id)
);
