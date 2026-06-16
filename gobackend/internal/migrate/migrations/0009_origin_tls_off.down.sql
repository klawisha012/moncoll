-- PostgreSQL cannot DROP a value from an enum type without recreating it.
-- The 'off' value is harmless when unused, so the down migration is a no-op.
SELECT 1;
