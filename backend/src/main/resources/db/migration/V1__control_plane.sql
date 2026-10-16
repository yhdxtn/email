-- PostgreSQL ONLY. Agent's local SQLite ledger is a separate embedded node concern.
CREATE TABLE system_setup (id smallint PRIMARY KEY CHECK(id=1), initialized boolean NOT NULL DEFAULT false);
INSERT INTO system_setup(id) VALUES (1);
CREATE TABLE admin_user (
 id uuid PRIMARY KEY, username varchar(64) UNIQUE NOT NULL,
 password_hash varchar(100) NOT NULL, role varchar(24) NOT NULL CHECK(role IN ('Owner','MailAdmin','DnsAdmin','Operator','Auditor','WebsiteUserAdmin')),
 active boolean NOT NULL DEFAULT true, mfa_secret text, mfa_enabled boolean NOT NULL DEFAULT false,
 last_totp_step bigint NOT NULL DEFAULT -1, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE admin_session (
 token_hash char(64) PRIMARY KEY, id uuid UNIQUE NOT NULL, admin_id uuid NOT NULL REFERENCES admin_user(id),
 mfa_verified boolean NOT NULL DEFAULT false, reauth_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
 ip_hash char(64) NOT NULL, user_agent varchar(160) NOT NULL
);
CREATE INDEX session_admin_idx ON admin_session(admin_id);
CREATE TABLE rate_bucket (bucket varchar(160) PRIMARY KEY, window_start timestamptz NOT NULL, attempts integer NOT NULL);
CREATE TABLE audit_event (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, actor varchar(100) NOT NULL,
 action varchar(80) NOT NULL, target varchar(255) NOT NULL, outcome varchar(40) NOT NULL,
 request_id uuid NOT NULL, summary jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_time_idx ON audit_event(created_at DESC);
CREATE FUNCTION deny_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Audit rows are append-only'; END $$;
CREATE TRIGGER audit_append_only BEFORE UPDATE OR DELETE ON audit_event FOR EACH ROW EXECUTE FUNCTION deny_audit_mutation();
CREATE TABLE settings (id smallint PRIMARY KEY CHECK(id=1), value jsonb NOT NULL DEFAULT '{}', updated_at timestamptz NOT NULL DEFAULT now());
INSERT INTO settings(id) VALUES(1);
CREATE TABLE mail_node (
 id uuid PRIMARY KEY, name varchar(80) NOT NULL, instance_id varchar(64) UNIQUE NOT NULL,
 connection_ref varchar(32) UNIQUE NOT NULL DEFAULT 'primary', readonly boolean NOT NULL DEFAULT true,
 status varchar(32) NOT NULL DEFAULT 'unknown', inventory jsonb NOT NULL DEFAULT '{}', last_seen timestamptz
);
CREATE TABLE mail_domain (
 id uuid PRIMARY KEY, name varchar(253) UNIQUE NOT NULL, mail_host varchar(253) NOT NULL, public_ipv4 varchar(15) NOT NULL,
 registrar varchar(80) NOT NULL DEFAULT '', dkim_selector varchar(63) NOT NULL, dkim_public text NOT NULL DEFAULT '',
 spf varchar(2048) NOT NULL, dmarc varchar(2048) NOT NULL, ttl integer NOT NULL DEFAULT 300 CHECK(ttl BETWEEN 60 AND 86400),
 node_id uuid REFERENCES mail_node(id), created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE dns_provider_config (
 domain_id uuid PRIMARY KEY REFERENCES mail_domain(id), provider varchar(20) NOT NULL CHECK(provider IN ('manual','cloudflare')),
 zone_id varchar(32), secret_cipher text, updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE dns_plan (
 id uuid PRIMARY KEY, domain_id uuid NOT NULL REFERENCES mail_domain(id), actor_id uuid NOT NULL REFERENCES admin_user(id),
 provider varchar(20) NOT NULL, provider_version char(64) NOT NULL, state varchar(32) NOT NULL,
 before_records jsonb NOT NULL, desired_records jsonb NOT NULL, after_records jsonb,
 changes jsonb NOT NULL, expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE mailbox (
 id uuid PRIMARY KEY, domain_id uuid NOT NULL REFERENCES mail_domain(id), node_id uuid NOT NULL REFERENCES mail_node(id),
 address varchar(254) UNIQUE NOT NULL, quota_bytes bigint NOT NULL CHECK(quota_bytes BETWEEN 1048576 AND 1099511627776),
 state varchar(24) NOT NULL DEFAULT 'pending', desired_state varchar(24) NOT NULL DEFAULT 'active',
 used_bytes bigint, last_login timestamptz, last_failure timestamptz, deleted_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE mailbox_alias (
 id uuid PRIMARY KEY, node_id uuid NOT NULL REFERENCES mail_node(id), domain_id uuid NOT NULL REFERENCES mail_domain(id),
 address varchar(254) UNIQUE NOT NULL, destination varchar(254) NOT NULL, state varchar(24) NOT NULL DEFAULT 'pending',
 created_at timestamptz NOT NULL DEFAULT now(), CHECK(address<>destination)
);
CREATE TABLE task (
 id uuid PRIMARY KEY, actor_id uuid NOT NULL REFERENCES admin_user(id), kind varchar(80) NOT NULL,
 node_id uuid REFERENCES mail_node(id), entity_id uuid, idempotency_key varchar(100) NOT NULL,
 fingerprint char(64) NOT NULL, payload_cipher text, status varchar(32) NOT NULL DEFAULT 'queued',
 result jsonb NOT NULL DEFAULT '{}', error_code varchar(80), attempts integer NOT NULL DEFAULT 0,
 created_at timestamptz NOT NULL DEFAULT now(), started_at timestamptz, finished_at timestamptz,
 UNIQUE(actor_id,idempotency_key)
);
CREATE INDEX task_claim_idx ON task(created_at) WHERE status='queued';
CREATE TABLE action_plan (
 id uuid PRIMARY KEY, actor_id uuid NOT NULL REFERENCES admin_user(id), kind varchar(80) NOT NULL,
 node_id uuid REFERENCES mail_node(id), entity_id uuid, params_cipher text NOT NULL,
 preview jsonb NOT NULL, confirmation varchar(300) NOT NULL, fingerprint char(64) NOT NULL,
 used boolean NOT NULL DEFAULT false, task_id uuid REFERENCES task(id), idempotency_key varchar(100), expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE mail_send (
 id uuid PRIMARY KEY REFERENCES task(id), actor_id uuid NOT NULL REFERENCES admin_user(id), sender varchar(254) NOT NULL,
 recipient varchar(254) NOT NULL, message_id varchar(300), state varchar(40) NOT NULL DEFAULT 'queued',
 recipient_confirmation varchar(40) NOT NULL DEFAULT 'unconfirmed', created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX mail_rate_idx ON mail_send(actor_id,recipient,created_at DESC);
CREATE TABLE monitor_check (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, node_id uuid REFERENCES mail_node(id), domain_id uuid REFERENCES mail_domain(id),
 name varchar(100) NOT NULL, state varchar(24) NOT NULL, detail jsonb NOT NULL DEFAULT '{}',
 source varchar(80) NOT NULL, latency_ms bigint NOT NULL DEFAULT 0, checked_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX monitor_time_idx ON monitor_check(checked_at DESC);
CREATE TABLE alert (
 id uuid PRIMARY KEY, dedupe_key varchar(200) UNIQUE NOT NULL, state varchar(24) NOT NULL DEFAULT 'open',
 message varchar(400) NOT NULL, first_seen timestamptz NOT NULL DEFAULT now(), last_seen timestamptz NOT NULL DEFAULT now(),
 silenced_until timestamptz, recovered_at timestamptz
);
CREATE TABLE backup (
 id uuid PRIMARY KEY, node_id uuid NOT NULL REFERENCES mail_node(id), task_id uuid NOT NULL REFERENCES task(id),
 archive_id uuid, status varchar(32) NOT NULL DEFAULT 'queued', summary jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE restore_drill (
 id uuid PRIMARY KEY, backup_id uuid NOT NULL REFERENCES backup(id), task_id uuid NOT NULL REFERENCES task(id),
 state varchar(32) NOT NULL DEFAULT 'queued', report jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE website_connector (
 id smallint PRIMARY KEY CHECK(id=1), enabled boolean NOT NULL DEFAULT false, connector_type varchar(24) NOT NULL DEFAULT 'disabled'
);
INSERT INTO website_connector(id) VALUES(1);

-- Runtime SQL credentials cannot change audit rows or schema; migration credentials are separate.
DO $$
BEGIN
 IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='astrogate_app') THEN
  GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO astrogate_app;
  GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO astrogate_app;
  REVOKE UPDATE,DELETE,TRUNCATE ON audit_event FROM astrogate_app;
  REVOKE ALL ON flyway_schema_history FROM astrogate_app;
 END IF;
END $$;
