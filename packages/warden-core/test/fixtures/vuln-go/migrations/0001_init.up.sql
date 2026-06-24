CREATE TABLE users (id serial primary key, email text);
ALTER TABLE users DROP COLUMN phone;
DROP TABLE legacy_sessions;
