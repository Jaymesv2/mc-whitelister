-- Add up migration script here
CREATE TABLE IF NOT EXISTS users (
    id varchar(255) PRIMARY KEY NOT NULL,
    name varchar(255) NOT NULL
);

-- The id is useless but it works 
CREATE TABLE IF NOT EXISTS user_access_token (
    user_id varchar(255) PRIMARY KEY NOT NULL,
    token varchar(4096) NOT NULL,
    issued TIMESTAMP NOT NULL,
    expires TIMESTAMP NULL,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE INDEX user_access_token_user_id_index ON user_access_token (user_id);

CREATE TABLE IF NOT EXISTS user_refresh_token (
    user_id varchar(255) PRIMARY KEY NOT NULL,
    token varchar(4096) NOT NULL,
    issued TIMESTAMP NOT NULL,
    expires TIMESTAMP NULL,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE INDEX user_refresh_token_user_id_index ON user_refresh_token (user_id);

CREATE TABLE IF NOT EXISTS minecraft_profile (
    uuid VARCHAR(255) PRIMARY KEY NOT NULL,
    microsoft_id VARCHAR(255) UNIQUE NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    -- is_primary BIT NOT NULL, -- TERRIBLE
    username VARCHAR(255) NOT NULL,
    skin_id VARCHAR(255) NOT NULL,
    skin_url VARCHAR(512) NOT NULL,
    skin_variant VARCHAR(255) NOT NULL,
    skin_alias VARCHAR(255) NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);


-- CREATE TABLE IF NOT EXISTS microsoft_account (
--     -- The microsoft id is a unique identifier for this specific application
--     user_id varchar(255) NOT NULL,
--     FOREIGN KEY (user_id) REFERENCES users (id)
-- );

-- CREATE TABLE IF NOT EXISTS microsoft_access_token (
--     microsoft_id varchar(64) PRIMARY KEY NOT NULL, 
--     token varchar(4096) NOT NULL,
--     issued TIMESTAMP NOT NULL,
--     expires TIMESTAMP NULL,
--     FOREIGN KEY (microsoft_id) REFERENCES microsoft_account (microsoft_id)
-- );

-- CREATE TABLE IF NOT EXISTS microsoft_refresh_token (
--     microsoft_id varchar(64) PRIMARY KEY NOT NULL,
--     token varchar(4096) NOT NULL,
--     issued TIMESTAMP NOT NULL,
--     expires TIMESTAMP NULL,
--     FOREIGN KEY (microsoft_id) REFERENCES microsoft_account (microsoft_id)
-- );


-- CREATE TABLE IF NOT EXISTS xbl_access_token ();
--
-- CREATE TABLE IF NOT EXISTS xsts_refresh_token ();
--
-- CREATE TABLE IF NOT EXISTS minecraft_access_token ();



-- CREATE INDEX minecraft_profile_uuid_index ON minecraft_profile (uuid);

-- CREATE TABLE IF NOT EXISTS minecraft_token (
--     microsoft_id VARCHAR(255) NOT NULL PRIMARY KEY,
--     token VARCHAR(4096) NOT NULL,
--     expires TIMESTAMP NULL,
--     issued TIMESTAMP NOT NULL,
--     FOREIGN KEY (microsoft_id) REFERENCES microsoft_account(microsoft_id)
-- );
