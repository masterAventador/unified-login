CREATE TABLE app_user (
    id                  uuid         NOT NULL,
    email               varchar(320) NOT NULL,
    password_hash       varchar(255) NOT NULL,
    status              varchar(16)  NOT NULL DEFAULT 'ACTIVE',
    email_verified      boolean      NOT NULL DEFAULT true,
    is_platform_admin   boolean      NOT NULL DEFAULT false,
    password_changed_at timestamptz  NOT NULL,
    created_at          timestamptz  NOT NULL,
    updated_at          timestamptz  NOT NULL,
    PRIMARY KEY (id)
);

CREATE UNIQUE INDEX ux_app_user_email ON app_user (email);
CREATE INDEX ix_app_user_status ON app_user (status);
