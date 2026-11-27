-- ==============================================================================================
-- geodata5-sso - core schema (Spring Authorization Server tables)
--
-- These three tables are the official Spring Authorization Server 7.1.3 DDL, copied verbatim
-- from the jar (org/springframework/security/oauth2/server/authorization/ *.sql files) with the
-- PostgreSQL guidance in their header applied: every timestamp column is timestamp with time zone, so
-- stored instants stay exact. See sql/postgres/ for the production variant.
--
-- NOTE: this file is executed by Spring's ScriptUtils. Only "--" line comments are safe here;
-- do not put a block-comment opener in any comment text, it is parsed as a real comment start.
-- ==============================================================================================

CREATE TABLE IF NOT EXISTS oauth2_registered_client (
    id varchar(100) NOT NULL,
    client_id varchar(100) NOT NULL,
    client_id_issued_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    client_secret varchar(200) DEFAULT NULL,
    client_secret_expires_at timestamp with time zone DEFAULT NULL,
    client_name varchar(200) NOT NULL,
    client_authentication_methods varchar(1000) NOT NULL,
    authorization_grant_types varchar(1000) NOT NULL,
    redirect_uris varchar(1000) DEFAULT NULL,
    post_logout_redirect_uris varchar(1000) DEFAULT NULL,
    scopes varchar(1000) NOT NULL,
    client_settings varchar(2000) NOT NULL,
    token_settings varchar(2000) NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS oauth2_authorization (
    id varchar(100) NOT NULL,
    registered_client_id varchar(100) NOT NULL,
    principal_name varchar(200) NOT NULL,
    authorization_grant_type varchar(100) NOT NULL,
    authorized_scopes varchar(1000) DEFAULT NULL,
    attributes bytea DEFAULT NULL,
    state varchar(500) DEFAULT NULL,
    authorization_code_value bytea DEFAULT NULL,
    authorization_code_issued_at timestamp with time zone DEFAULT NULL,
    authorization_code_expires_at timestamp with time zone DEFAULT NULL,
    authorization_code_metadata bytea DEFAULT NULL,
    access_token_value bytea DEFAULT NULL,
    access_token_issued_at timestamp with time zone DEFAULT NULL,
    access_token_expires_at timestamp with time zone DEFAULT NULL,
    access_token_metadata bytea DEFAULT NULL,
    access_token_type varchar(100) DEFAULT NULL,
    access_token_scopes varchar(1000) DEFAULT NULL,
    oidc_id_token_value bytea DEFAULT NULL,
    oidc_id_token_issued_at timestamp with time zone DEFAULT NULL,
    oidc_id_token_expires_at timestamp with time zone DEFAULT NULL,
    oidc_id_token_metadata bytea DEFAULT NULL,
    refresh_token_value bytea DEFAULT NULL,
    refresh_token_issued_at timestamp with time zone DEFAULT NULL,
    refresh_token_expires_at timestamp with time zone DEFAULT NULL,
    refresh_token_metadata bytea DEFAULT NULL,
    user_info bytea DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS oauth2_authorization_consent (
    registered_client_id varchar(100) NOT NULL,
    principal_name varchar(200) NOT NULL,
    authorities varchar(1000) NOT NULL,
    PRIMARY KEY (registered_client_id, principal_name)
);
