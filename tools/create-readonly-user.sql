-- TRAPD ClickHouse Read-Only User
-- Create a user with SELECT-only permissions

CREATE USER IF NOT EXISTS trapd_ro IDENTIFIED BY 'readonly_pwd';
GRANT SELECT ON trapd.* TO trapd_ro;
SHOW GRANTS FOR trapd_ro;
