-- Add down migration script here
-- Add up migration script here
DROP TABLE user;

DELETE INDEX user_access_token_user_id_index;
DROP TABLE user_access_token;

DELETE INDEX user_refresh_token_user_id_index;
DROP TABLE user_refresh_token;

DROP TABLE microsoft_account;
DROP TABLE microsoft_access_token;
DROP TABLE microsoft_refresh_token;

DROP TABLE minecraft_token;
DROP TABLE minecraft_profile;