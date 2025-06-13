-- User-Table Privilege Matrix
-- Shows each user's privileges on each table in a matrix format

WITH table_list AS (
    -- Get all tables that have privileges granted
    SELECT DISTINCT owner, table_name
    FROM dba_tab_privs
    WHERE owner NOT IN ('SYS', 'SYSTEM', 'OUTLN', 'DIP', 'ORACLE_OCM', 'DBSNMP', 'APPQOSSYS', 'WMSYS', 'EXFSYS', 'CTXSYS', 'ANONYMOUS', 'XDB', 'ORDPLUGINS', 'ORDSYS', 'SI_INFORMTN_SCHEMA', 'MDSYS', 'OLAPSYS', 'MDDATA', 'XS$NULL', 'OJVMSYS', 'GSMADMIN_INTERNAL', 'FLOWS_FILES', 'APEX_030200', 'APEX_PUBLIC_USER', 'SPATIAL_CSW_ADMIN_USR', 'SPATIAL_WFS_ADMIN_USR')
    AND grantee IN (SELECT username FROM dba_users WHERE oracle_maintained = 'N')
    ORDER BY owner, table_name
),
user_list AS (
    -- Get all non-Oracle maintained users
    SELECT username
    FROM dba_users
    WHERE oracle_maintained = 'N'
    ORDER BY username
),
direct_privileges AS (
    -- Direct table privileges
    SELECT 
        grantee,
        owner,
        table_name,
        privilege,
        grantable,
        'DIRECT' as grant_type
    FROM dba_tab_privs
    WHERE grantee IN (SELECT username FROM user_list)
),
role_privileges AS (
    -- Privileges granted through roles
    SELECT 
        u.username as grantee,
        t.owner,
        t.table_name,
        t.privilege,
        t.grantable,
        'ROLE:' || r.granted_role as grant_type
    FROM user_list u
    JOIN dba_role_privs r ON u.username = r.grantee
    JOIN dba_tab_privs t ON r.granted_role = t.grantee
),
all_privileges AS (
    SELECT * FROM direct_privileges
    UNION ALL
    SELECT * FROM role_privileges
),
privilege_matrix AS (
    SELECT 
        u.username,
        t.owner,
        t.table_name,
        MAX(CASE WHEN ap.privilege = 'SELECT' THEN 'Y' ELSE 'N' END) as SELECT_PRIV,
        MAX(CASE WHEN ap.privilege = 'INSERT' THEN 'Y' ELSE 'N' END) as INSERT_PRIV,
        MAX(CASE WHEN ap.privilege = 'UPDATE' THEN 'Y' ELSE 'N' END) as UPDATE_PRIV,
        MAX(CASE WHEN ap.privilege = 'DELETE' THEN 'Y' ELSE 'N' END) as DELETE_PRIV,
        MAX(CASE WHEN ap.privilege = 'ALTER' THEN 'Y' ELSE 'N' END) as ALTER_PRIV,
        MAX(CASE WHEN ap.privilege = 'INDEX' THEN 'Y' ELSE 'N' END) as INDEX_PRIV,
        MAX(CASE WHEN ap.privilege = 'REFERENCES' THEN 'Y' ELSE 'N' END) as REFERENCES_PRIV,
        MAX(CASE WHEN ap.privilege = 'EXECUTE' THEN 'Y' ELSE 'N' END) as EXECUTE_PRIV,
        MAX(CASE WHEN ap.grantable = 'YES' THEN 'Y' ELSE 'N' END) as GRANTABLE,
        LISTAGG(CASE WHEN ap.grant_type LIKE 'ROLE:%' THEN SUBSTR(ap.grant_type, 6) END, ',') 
            WITHIN GROUP (ORDER BY ap.grant_type) as GRANTED_THROUGH_ROLES
    FROM user_list u
    CROSS JOIN table_list t
    LEFT JOIN all_privileges ap ON u.username = ap.grantee 
                                AND t.owner = ap.owner 
                                AND t.table_name = ap.table_name
    GROUP BY u.username, t.owner, t.table_name
    HAVING MAX(CASE WHEN ap.privilege IS NOT NULL THEN 1 ELSE 0 END) = 1  -- Only show tables where user has privileges
)
SELECT 
    username as "USER_NAME",
    owner as "SCHEMA_OWNER",
    table_name as "TABLE_NAME",
    SELECT_PRIV as "SELECT",
    INSERT_PRIV as "INSERT",
    UPDATE_PRIV as "UPDATE",
    DELETE_PRIV as "DELETE",
    ALTER_PRIV as "ALTER",
    INDEX_PRIV as "INDEX",
    REFERENCES_PRIV as "REFERENCES",
    EXECUTE_PRIV as "EXECUTE",
    GRANTABLE as "GRANTABLE",
    GRANTED_THROUGH_ROLES as "VIA_ROLES"
FROM privilege_matrix
ORDER BY username, owner, table_name;