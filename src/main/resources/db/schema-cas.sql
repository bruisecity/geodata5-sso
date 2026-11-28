-- ==============================================================================================
-- geodata5-sso - CAS compatibility layer schema
--
-- Design provenance (architecture doc, revision 28):
--   5.2A / 5.7.2  attribute names are data, not code -> cas_attribute_mapping
--   5.2B          service registry must persist (legacy used an empty in-memory registry while
--                 forcing an authorization check, a combination we refuse to reproduce)
--   5.7.3         password: keep the legacy column read-only, add our own BCrypt + upgrade flag
--   5.7.4         strategy S1: share the legacy user table read-only; ALL writes go to our tables
--
-- NOTE: executed by Spring ScriptUtils, which only recognises "--" line comments. Never write a
-- block-comment opener anywhere in this file (not even inside a comment), it is parsed as real SQL.
-- ==============================================================================================

-- -------------------------------------------------------------------------------------------
-- 1. Attribute dialect, table-driven (5.2A / 5.7.2)
--    The eight legacy names are seeded verbatim, including the capital I in "userId".
--    role_id / role_name were commented out in the legacy source, so they are seeded with
--    emitted = false: present for traceability, absent from the XML response (T-17).
-- -------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cas_attribute_mapping (
    attribute_name varchar(64) NOT NULL,
    source_key     varchar(128) NOT NULL,
    emitted        boolean NOT NULL DEFAULT true,
    sort_order     int NOT NULL DEFAULT 0,
    note           varchar(512),
    PRIMARY KEY (attribute_name)
);

INSERT INTO cas_attribute_mapping (attribute_name, source_key, emitted, sort_order, note)
SELECT 'username', 'legacy.username', true, 1, 't_customer.username -> cas:username'
WHERE NOT EXISTS (SELECT 1 FROM cas_attribute_mapping WHERE attribute_name = 'username');

INSERT INTO cas_attribute_mapping (attribute_name, source_key, emitted, sort_order, note)
SELECT 'userId', 'legacy.userid', true, 2, 't_customer.userid -> cas:userId; capital I is part of the contract'
WHERE NOT EXISTS (SELECT 1 FROM cas_attribute_mapping WHERE attribute_name = 'userId');

INSERT INTO cas_attribute_mapping (attribute_name, source_key, emitted, sort_order, note)
SELECT 'realName', 'legacy.realName', true, 3, 't_customer.real_name -> cas:realName'
WHERE NOT EXISTS (SELECT 1 FROM cas_attribute_mapping WHERE attribute_name = 'realName');

INSERT INTO cas_attribute_mapping (attribute_name, source_key, emitted, sort_order, note)
SELECT 'workFor', 'legacy.workFor', true, 4, 't_customer.work_for -> cas:workFor'
WHERE NOT EXISTS (SELECT 1 FROM cas_attribute_mapping WHERE attribute_name = 'workFor');

INSERT INTO cas_attribute_mapping (attribute_name, source_key, emitted, sort_order, note)
SELECT 'email', 'legacy.email', true, 5, 't_customer.email -> cas:email'
WHERE NOT EXISTS (SELECT 1 FROM cas_attribute_mapping WHERE attribute_name = 'email');

INSERT INTO cas_attribute_mapping (attribute_name, source_key, emitted, sort_order, note)
SELECT 'mobile', 'legacy.mobile', true, 6, 't_customer.mobile -> cas:mobile'
WHERE NOT EXISTS (SELECT 1 FROM cas_attribute_mapping WHERE attribute_name = 'mobile');

INSERT INTO cas_attribute_mapping (attribute_name, source_key, emitted, sort_order, note)
SELECT 'createdFrom', 'legacy.createdFrom', true, 7, 't_customer.created_from -> cas:createdFrom; raw value set preserved'
WHERE NOT EXISTS (SELECT 1 FROM cas_attribute_mapping WHERE attribute_name = 'createdFrom');

INSERT INTO cas_attribute_mapping (attribute_name, source_key, emitted, sort_order, note)
SELECT 'isEnabled', 'legacy.isEnabled', false, 8, 'NOT in the golden capture (user-supplied 2026-11-27): the running legacy server does not emit it; flip emitted=true only after confirming with the legacy side'
WHERE NOT EXISTS (SELECT 1 FROM cas_attribute_mapping WHERE attribute_name = 'isEnabled');

INSERT INTO cas_attribute_mapping (attribute_name, source_key, emitted, sort_order, note)
SELECT 'roleId', 'legacy.roleId', false, 9, 'commented out in legacy resultAttributeMapping -> NOT emitted'
WHERE NOT EXISTS (SELECT 1 FROM cas_attribute_mapping WHERE attribute_name = 'roleId');

INSERT INTO cas_attribute_mapping (attribute_name, source_key, emitted, sort_order, note)
SELECT 'roleName', 'legacy.roleName', false, 10, 'commented out in legacy resultAttributeMapping -> NOT emitted'
WHERE NOT EXISTS (SELECT 1 FROM cas_attribute_mapping WHERE attribute_name = 'roleName');

-- -------------------------------------------------------------------------------------------
-- 2. Service registry, persisted (5.2B). Legacy in-memory registry lost everything on restart
--    and was empty to begin with, which is why LENIENT is the default mode.
-- -------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cas_service_registry (
    id              bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    service_pattern varchar(2048) NOT NULL,
    name            varchar(255),
    enabled         boolean NOT NULL DEFAULT true,
    allow_proxy     boolean NOT NULL DEFAULT false,
    created_at      timestamp with time zone NOT NULL DEFAULT now()
);

INSERT INTO cas_service_registry (service_pattern, name, enabled, allow_proxy)
SELECT '^http://localhost:8080/.+$', '本地联调样例应用', true, false
WHERE NOT EXISTS (SELECT 1 FROM cas_service_registry WHERE service_pattern = '^http://localhost:8080/.+$');

-- -------------------------------------------------------------------------------------------
-- 3. Legacy user table (LOCAL PROFILE ONLY)
--
--    PRODUCTION NOTE: this table already exists in the shared MySQL database and the new
--    service connects to it READ-ONLY (strategy S1). It is created here solely so the local
--    profile is self-contained.
--
--    Types below are the REAL production DDL, obtained 2026-11-27 (T-18 closed), not guesses:
--      username varchar(120)   - NO unique index in production (uniqueness not guaranteed);
--                                 the legacy login SQL matched on username+enabled+created_from
--                                 and so does ours. Local H2 still needs a key for row identity,
--                                 hence the local-only surrogate below.
--      userid   varchar(36)    - unique index in production, "CAS" + digits.
--      password varchar(50)    - hex_md5(pw + "{username}") digest is 32 chars, fits;
--                                 BCrypt is 60 chars and does NOT fit -> BCrypt lives ONLY in
--                                 sso_user_credential, the legacy column is never rewritten.
--      created_from           - value set fixed at the 5 legacy values from source.
--      charset utf8 -> new store is utf8mb4, lossless direction.
--    Production scale reference: ~380k rows (AUTO_INCREMENT = 385417).
-- -------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS t_customer (
    -- local surrogate key; production has no primary key on username
    username     varchar(120) NOT NULL PRIMARY KEY,
    userid       varchar(36),
    real_name    varchar(128),
    work_for     varchar(255),
    email        varchar(255),
    mobile       varchar(64),
    created_from varchar(32),
    enabled      int NOT NULL DEFAULT 1,
    -- legacy semantics: hex_md5(pw + braced username) stored as plain text, compared verbatim;
    -- varchar(50) per production DDL - physically cannot hold BCrypt(60)
    password     varchar(50)
);

-- -------------------------------------------------------------------------------------------
-- 4. Our credential sidecar: BCrypt hash + upgrade flag (5.7.3). The legacy column is never
--    rewritten; this is where the "next login uses BCrypt" decision lives.
-- -------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sso_user_credential (
    username        varchar(64) NOT NULL PRIMARY KEY,
    password_hash   varchar(100),
    password_scheme varchar(32) NOT NULL DEFAULT 'BCRYPT',
    upgraded        boolean NOT NULL DEFAULT false,
    updated_at      timestamp with time zone DEFAULT now()
);

-- -------------------------------------------------------------------------------------------
-- 5. Login audit + modern lock policy (5.7.4: never write lock state into t_customer, or it
--    fights the legacy is_password_invalid logic).
-- -------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sso_login_audit (
    id          bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    username    varchar(64),
    event       varchar(64) NOT NULL,
    client_ip   varchar(64),
    occurred_at timestamp with time zone NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_login_audit_user_time ON sso_login_audit (username, occurred_at);

-- -------------------------------------------------------------------------------------------
-- 6. Third-party identity binding (architecture chapter 6). Present in phase 1 so the table
--    model is settled even though only one OIDC IdP is wired up.
-- -------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_identity_binding (
    id              bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    provider        varchar(64) NOT NULL,
    external_sub    varchar(255) NOT NULL,
    user_id         varchar(64) NOT NULL,
    bound_at        timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT uk_provider_external UNIQUE (provider, external_sub)
);
