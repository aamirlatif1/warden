-- Runs once on an empty data volume. Dev-only credentials.
CREATE USER keycloak WITH PASSWORD 'keycloak';
CREATE DATABASE keycloak OWNER keycloak;

CREATE USER warden WITH PASSWORD 'warden';
CREATE DATABASE warden OWNER warden;

-- Separate database for pgstore integration tests (make test-db), so test
-- rows never mix with the demo seed.
CREATE DATABASE warden_test OWNER warden;
