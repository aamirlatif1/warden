-- Runs once on an empty data volume. Dev-only credentials.
CREATE USER keycloak WITH PASSWORD 'keycloak';
CREATE DATABASE keycloak OWNER keycloak;

CREATE USER warden WITH PASSWORD 'warden';
CREATE DATABASE warden OWNER warden;
