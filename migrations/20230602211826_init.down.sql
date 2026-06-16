-- Add down migration script here
-- Add up migration script here

DROP INDEX user_access_token_user_id_index;
DROP TABLE user_access_token;

DROP INDEX user_refresh_token_user_id_index;
DROP TABLE user_refresh_token;

DROP TABLE minecraft_profile;

DROP TABLE users;
