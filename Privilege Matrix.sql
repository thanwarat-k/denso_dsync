-- Comprehensive User Privilege Matrix Report
-- This creates a matrix showing users and their privileges in a structured format

WITH user_base AS (
    SELECT username, account_status, default_tablespace, profile, created
    FROM dba_users 
    WHERE oracle_maintained = 'N'
),
user_roles AS (
    SELECT 
        username,
        MAX(CASE WHEN role_name = 'DBA' THEN 'Y' ELSE 'N' END) as DBA_ROLE,
        MAX(CASE WHEN role_name = 'CONNECT' THEN 'Y' ELSE 'N' END) as CONNECT_ROLE,
        MAX(CASE WHEN role_name = 'RESOURCE' THEN 'Y' ELSE 'N' END) as RESOURCE_ROLE,
        MAX(CASE WHEN role_name = 'SELECT_CATALOG_ROLE' THEN 'Y' ELSE 'N' END) as SELECT_CATALOG,
        MAX(CASE WHEN role_name = 'EXECUTE_CATALOG_ROLE' THEN 'Y' ELSE 'N' END) as EXECUTE_CATALOG,
        MAX(CASE WHEN role_name = 'EXP_FULL_DATABASE' THEN 'Y' ELSE 'N' END) as EXP_FULL_DB,
        MAX(CASE WHEN role_name = 'IMP_FULL_DATABASE' THEN 'Y' ELSE 'N' END) as IMP_FULL_DB,
        MAX(CASE WHEN role_name = 'DATAPUMP_EXP_FULL_DATABASE' THEN 'Y' ELSE 'N' END) as DATAPUMP_EXP,
        MAX(CASE WHEN role_name = 'DATAPUMP_IMP_FULL_DATABASE' THEN 'Y' ELSE 'N' END) as DATAPUMP_IMP
    FROM (
        SELECT u.username, r.granted_role as role_name
        FROM user_base u
        LEFT JOIN dba_role_privs r ON u.username = r.grantee
    ) 
    GROUP BY username
),
user_sys_privs AS (
    SELECT 
        username,
        MAX(CASE WHEN privilege = 'CREATE SESSION' THEN 'Y' ELSE 'N' END) as CREATE_SESSION,
        MAX(CASE WHEN privilege = 'CREATE TABLE' THEN 'Y' ELSE 'N' END) as CREATE_TABLE,
        MAX(CASE WHEN privilege = 'CREATE VIEW' THEN 'Y' ELSE 'N' END) as CREATE_VIEW,
        MAX(CASE WHEN privilege = 'CREATE PROCEDURE' THEN 'Y' ELSE 'N' END) as CREATE_PROCEDURE,
        MAX(CASE WHEN privilege = 'CREATE SEQUENCE' THEN 'Y' ELSE 'N' END) as CREATE_SEQUENCE,
        MAX(CASE WHEN privilege = 'CREATE USER' THEN 'Y' ELSE 'N' END) as CREATE_USER,
        MAX(CASE WHEN privilege = 'ALTER USER' THEN 'Y' ELSE 'N' END) as ALTER_USER,
        MAX(CASE WHEN privilege = 'DROP USER' THEN 'Y' ELSE 'N' END) as DROP_USER,
        MAX(CASE WHEN privilege = 'CREATE ANY TABLE' THEN 'Y' ELSE 'N' END) as CREATE_ANY_TABLE,
        MAX(CASE WHEN privilege = 'SELECT ANY TABLE' THEN 'Y' ELSE 'N' END) as SELECT_ANY_TABLE,
        MAX(CASE WHEN privilege = 'INSERT ANY TABLE' THEN 'Y' ELSE 'N' END) as INSERT_ANY_TABLE,
        MAX(CASE WHEN privilege = 'UPDATE ANY TABLE' THEN 'Y' ELSE 'N' END) as UPDATE_ANY_TABLE,
        MAX(CASE WHEN privilege = 'DELETE ANY TABLE' THEN 'Y' ELSE 'N' END) as DELETE_ANY_TABLE,
        MAX(CASE WHEN privilege = 'DROP ANY TABLE' THEN 'Y' ELSE 'N' END) as DROP_ANY_TABLE
    FROM (
        -- Direct system privileges
        SELECT u.username, s.privilege
        FROM user_base u
        LEFT JOIN dba_sys_privs s ON u.username = s.grantee
        UNION
        -- System privileges through roles
        SELECT u.username, s.privilege
        FROM user_base u
        JOIN dba_role_privs r ON u.username = r.grantee
        JOIN dba_sys_privs s ON r.granted_role = s.grantee
    ) 
    GROUP BY username
),
user_obj_privs AS (
    SELECT 
        username,
        COUNT(DISTINCT owner||'.'||table_name) as objects_accessible,
        MAX(CASE WHEN privilege = 'SELECT' THEN 'Y' ELSE 'N' END) as HAS_SELECT,
        MAX(CASE WHEN privilege = 'INSERT' THEN 'Y' ELSE 'N' END) as HAS_INSERT,
        MAX(CASE WHEN privilege = 'UPDATE' THEN 'Y' ELSE 'N' END) as HAS_UPDATE,
        MAX(CASE WHEN privilege = 'DELETE' THEN 'Y' ELSE 'N' END) as HAS_DELETE,
        MAX(CASE WHEN privilege = 'EXECUTE' THEN 'Y' ELSE 'N' END) as HAS_EXECUTE
    FROM (
        -- Direct object privileges
        SELECT u.username, t.owner, t.table_name, t.privilege
        FROM user_base u
        LEFT JOIN dba_tab_privs t ON u.username = t.grantee
        UNION
        -- Object privileges through roles
        SELECT u.username, t.owner, t.table_name, t.privilege
        FROM user_base u
        JOIN dba_role_privs r ON u.username = r.grantee
        JOIN dba_tab_privs t ON r.granted_role = t.grantee
    ) 
    GROUP BY username
)
SELECT 
    ub.username,
    ub.account_status,
    ub.default_tablespace,
    ub.profile,
    ub.created,
    -- Role assignments
    ur.DBA_ROLE,
    ur.CONNECT_ROLE,
    ur.RESOURCE_ROLE,
    ur.SELECT_CATALOG,
    ur.EXECUTE_CATALOG,
    ur.EXP_FULL_DB,
    ur.IMP_FULL_DB,
    ur.DATAPUMP_EXP,
    ur.DATAPUMP_IMP,
    -- System privileges
    usp.CREATE_SESSION,
    usp.CREATE_TABLE,
    usp.CREATE_VIEW,
    usp.CREATE_PROCEDURE,
    usp.CREATE_SEQUENCE,
    usp.CREATE_USER,
    usp.ALTER_USER,
    usp.DROP_USER,
    usp.CREATE_ANY_TABLE,
    usp.SELECT_ANY_TABLE,
    usp.INSERT_ANY_TABLE,
    usp.UPDATE_ANY_TABLE,
    usp.DELETE_ANY_TABLE,
    usp.DROP_ANY_TABLE,
    -- Object privilege summary
    uop.objects_accessible,
    uop.HAS_SELECT,
    uop.HAS_INSERT,
    uop.HAS_UPDATE,
    uop.HAS_DELETE,
    uop.HAS_EXECUTE
FROM user_base ub
LEFT JOIN user_roles ur ON ub.username = ur.username
LEFT JOIN user_sys_privs usp ON ub.username = usp.username
LEFT JOIN user_obj_privs uop ON ub.username = uop.username
ORDER BY ub.username;


-- Administrative Privilege Matrix
SELECT 
    username,
    MAX(CASE WHEN privilege = 'SYSDBA' THEN 'Y' ELSE 'N' END) as SYSDBA,
    MAX(CASE WHEN privilege = 'SYSOPER' THEN 'Y' ELSE 'N' END) as SYSOPER,
    MAX(CASE WHEN privilege = 'SYSASM' THEN 'Y' ELSE 'N' END) as SYSASM,
    MAX(CASE WHEN privilege = 'SYSBACKUP' THEN 'Y' ELSE 'N' END) as SYSBACKUP,
    MAX(CASE WHEN privilege = 'SYSDG' THEN 'Y' ELSE 'N' END) as SYSDG,
    MAX(CASE WHEN privilege = 'SYSKM' THEN 'Y' ELSE 'N' END) as SYSKM,
    MAX(CASE WHEN role_name = 'DBA' THEN 'Y' ELSE 'N' END) as DBA_ROLE,
    MAX(CASE WHEN admin_sys_priv > 0 THEN 'Y' ELSE 'N' END) as HAS_ADMIN_OPTION,
    MAX(CASE WHEN admin_role_priv > 0 THEN 'Y' ELSE 'N' END) as HAS_ROLE_ADMIN
FROM (
    SELECT u.username, s.privilege, NULL as role_name, 0 as admin_sys_priv, 0 as admin_role_priv
    FROM dba_users u
    LEFT JOIN v$pwfile_users p ON u.username = p.username
    LEFT JOIN dba_sys_privs s ON p.username = s.grantee
    WHERE u.oracle_maintained = 'N'
    UNION
    SELECT u.username, NULL as privilege, r.granted_role as role_name, 0 as admin_sys_priv, 0 as admin_role_priv
    FROM dba_users u
    LEFT JOIN dba_role_privs r ON u.username = r.grantee
    WHERE u.oracle_maintained = 'N'
    UNION
    SELECT u.username, NULL as privilege, NULL as role_name, 
           COUNT(s.privilege) as admin_sys_priv, 0 as admin_role_priv
    FROM dba_users u
    LEFT JOIN dba_sys_privs s ON u.username = s.grantee AND s.admin_option = 'YES'
    WHERE u.oracle_maintained = 'N'
    GROUP BY u.username
    UNION
    SELECT u.username, NULL as privilege, NULL as role_name, 
           0 as admin_sys_priv, COUNT(r.granted_role) as admin_role_priv
    FROM dba_users u
    LEFT JOIN dba_role_privs r ON u.username = r.grantee AND r.admin_option = 'YES'
    WHERE u.oracle_maintained = 'N'
    GROUP BY u.username
) admin_data
GROUP BY username
ORDER BY username;


-- CSV format output with headers
SELECT 
    'USERNAME,ACCOUNT_STATUS,DBA_ROLE,CONNECT_ROLE,RESOURCE_ROLE,CREATE_SESSION,CREATE_TABLE,CREATE_VIEW,SELECT_ANY_TABLE,OBJECTS_ACCESSIBLE' as csv_header
FROM dual
UNION ALL
SELECT 
    username||','||
    account_status||','||
    DBA_ROLE||','||
    CONNECT_ROLE||','||
    RESOURCE_ROLE||','||
    CREATE_SESSION||','||
    CREATE_TABLE||','||
    CREATE_VIEW||','||
    SELECT_ANY_TABLE||','||
    NVL(TO_CHAR(objects_accessible),'0') as csv_data
FROM (
    -- Your matrix query here (from artifact above)
    -- Simplified version for CSV export
    SELECT username, account_status, 'Y' as DBA_ROLE, 'Y' as CONNECT_ROLE, 
           'N' as RESOURCE_ROLE, 'Y' as CREATE_SESSION, 'Y' as CREATE_TABLE,
           'N' as CREATE_VIEW, 'Y' as SELECT_ANY_TABLE, 5 as objects_accessible
    FROM dba_users WHERE username = 'SAMPLE_USER'
);


