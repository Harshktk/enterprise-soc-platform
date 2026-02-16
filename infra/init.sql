-- TimescaleDB init script
-- Runs once on first container start

-- Enable TimescaleDB extension
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;

-- The alerts table will be created by SQLAlchemy on startup.
-- This file handles DB-level setup that SQLAlchemy can't do.

-- Create a read-only reporting role (for dashboards, BI tools)
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'soc_readonly') THEN
    CREATE ROLE soc_readonly WITH LOGIN PASSWORD 'readonly_password';
    GRANT CONNECT ON DATABASE socdb TO soc_readonly;
    GRANT USAGE ON SCHEMA public TO soc_readonly;
    GRANT SELECT ON ALL TABLES IN SCHEMA public TO soc_readonly;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO soc_readonly;
  END IF;
END
$$;
