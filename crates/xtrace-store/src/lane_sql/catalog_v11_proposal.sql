-- Proposed v0011 catalog link and static route eligibility DDL (Refs #112).
-- This rebuild preserves the installed migration prefix and the v3 observation rows.
-- Do not register until ADR 0015 and the typed readers and writers are ready.
PRAGMA defer_foreign_keys = ON;

CREATE TABLE operations_v11 (
    operation_id                BLOB PRIMARY KEY CHECK(length(operation_id) = 16
                                    AND substr(hex(operation_id), 13, 1) = '7'
                                    AND substr(hex(operation_id), 17, 1) IN ('8', '9', 'A', 'B')),
    project_id                  BLOB NOT NULL CHECK(length(project_id) = 16)
                                    REFERENCES projects(project_id),
    transport                   TEXT NOT NULL CHECK(transport = 'http'),
    method                      TEXT NOT NULL CHECK(method IN
                                    ('GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'TRACE', 'CONNECT')),
    route_template              TEXT NOT NULL CHECK(length(CAST(route_template AS BLOB)) BETWEEN 1 AND 1024
                                    AND substr(route_template, 1, 1) = '/'
                                    AND instr(route_template, '?') = 0
                                    AND instr(route_template, '#') = 0
                                    AND instr(CAST(route_template AS BLOB), x'00') = 0
                                    AND route_template NOT GLOB '*[' || char(1) || '-' || char(31) || char(127) || ']*'),
    application_component       TEXT NOT NULL CHECK(length(CAST(application_component AS BLOB)) BETWEEN 1 AND 128
                                    AND instr(CAST(application_component AS BLOB), x'00') = 0
                                    AND application_component NOT GLOB '*[^A-Za-z0-9._:-]*'),
    binding_key                 TEXT NOT NULL CHECK(length(CAST(binding_key AS BLOB)) BETWEEN 1 AND 128
                                    AND instr(CAST(binding_key AS BLOB), x'00') = 0
                                    AND binding_key NOT GLOB '*[^A-Za-z0-9._:-]*'),
    fingerprint_format_version INTEGER NOT NULL CHECK(fingerprint_format_version = 1),
    endpoint_fingerprint        BLOB NOT NULL CHECK(length(endpoint_fingerprint) = 32),
    created_at                  TEXT NOT NULL,
    UNIQUE(project_id, operation_id),
    UNIQUE(project_id, fingerprint_format_version, endpoint_fingerprint),
    UNIQUE(project_id, application_component, binding_key, transport, method, route_template),
    UNIQUE(project_id, operation_id, application_component, binding_key, method, route_template),
    UNIQUE(project_id, operation_id, endpoint_fingerprint)
) STRICT;

INSERT INTO operations_v11 (operation_id, project_id, transport, method, route_template,
                           application_component, binding_key, fingerprint_format_version,
                           endpoint_fingerprint, created_at)
SELECT operation_id, project_id, transport, method, route_template,
       application_component, binding_key, fingerprint_format_version,
       endpoint_fingerprint, created_at
FROM operations;

-- Runtime rows must agree with the catalog operation as well as the observed alias.
CREATE UNIQUE INDEX catalog_operations_runtime_link_identity
    ON catalog_operations(project_id, operation_id, application_component, binding_key,
                          method, route_template, endpoint_fingerprint);

-- Positive scan evidence is scoped to one immutable revision member. Old scans get no rows.
CREATE TABLE catalog_runtime_link_routes (
    project_id   BLOB NOT NULL CHECK(length(project_id) = 16),
    revision_id  BLOB NOT NULL CHECK(length(revision_id) = 16),
    operation_id BLOB NOT NULL CHECK(length(operation_id) = 16),
    PRIMARY KEY(project_id, revision_id, operation_id),
    FOREIGN KEY(project_id, revision_id, operation_id)
        REFERENCES catalog_revision_entries(project_id, revision_id, operation_id)
        ON DELETE RESTRICT
) STRICT;

CREATE TABLE recording_endpoint_observations_v11 (
    recording_id          BLOB PRIMARY KEY CHECK(length(recording_id) = 16),
    project_id            BLOB NOT NULL CHECK(length(project_id) = 16),
    disposition           TEXT NOT NULL CHECK(disposition IN ('linked', 'unmatched')),
    observation_policy_id TEXT CHECK(observation_policy_id IS NULL OR
                               observation_policy_id IN ('spring-orders-v1', 'runtime-route-v1')),
    operation_id          BLOB CHECK(operation_id IS NULL OR (length(operation_id) = 16
                               AND substr(hex(operation_id), 13, 1) = '7'
                               AND substr(hex(operation_id), 17, 1) IN ('8', '9', 'A', 'B'))),
    application_component TEXT,
    binding_key           TEXT,
    method                TEXT,
    route_template        TEXT,
    reason_code           TEXT,
    catalog_revision_id   BLOB CHECK(catalog_revision_id IS NULL OR length(catalog_revision_id) = 16),
    operation_fingerprint BLOB CHECK(operation_fingerprint IS NULL OR length(operation_fingerprint) = 32),
    CHECK((application_component IS NULL AND binding_key IS NULL)
       OR (application_component IS NOT NULL AND binding_key IS NOT NULL
           AND length(CAST(application_component AS BLOB)) BETWEEN 1 AND 128
           AND instr(CAST(application_component AS BLOB), x'00') = 0
           AND application_component NOT GLOB '*[^A-Za-z0-9._:-]*'
           AND length(CAST(binding_key AS BLOB)) BETWEEN 1 AND 128
           AND instr(CAST(binding_key AS BLOB), x'00') = 0
           AND binding_key NOT GLOB '*[^A-Za-z0-9._:-]*')),
    CHECK(coalesce(CASE disposition
      WHEN 'linked' THEN operation_id IS NOT NULL AND reason_code IS NULL
        AND application_component IS NOT NULL AND method IS NOT NULL AND route_template IS NOT NULL
        AND ((observation_policy_id = 'runtime-route-v1' AND catalog_revision_id IS NOT NULL
              AND operation_fingerprint IS NOT NULL)
          OR (observation_policy_id = 'spring-orders-v1' AND catalog_revision_id IS NULL
              AND operation_fingerprint IS NULL
              AND application_component = 'spring-fixture' AND binding_key = 'default'
              AND method = 'POST' AND route_template = '/orders'))
      WHEN 'unmatched' THEN operation_id IS NULL AND method IS NULL AND route_template IS NULL
        AND operation_fingerprint IS NULL
        AND CASE reason_code
          WHEN 'observation_policy_missing' THEN observation_policy_id IS NULL
            AND catalog_revision_id IS NULL AND (application_component IS NULL
              OR (application_component = 'spring-fixture' AND binding_key = 'default'))
          WHEN 'observation_policy_invalid' THEN observation_policy_id IS NULL
            AND catalog_revision_id IS NULL AND (application_component IS NULL
              OR (application_component = 'spring-fixture' AND binding_key = 'default'))
          WHEN 'identity_context_missing' THEN observation_policy_id IS NOT NULL
            AND application_component IS NULL AND catalog_revision_id IS NULL
          WHEN 'identity_context_invalid' THEN observation_policy_id IS NOT NULL
            AND application_component IS NULL AND catalog_revision_id IS NULL
          WHEN 'catalog_revision_unavailable' THEN observation_policy_id = 'runtime-route-v1'
            AND application_component IS NULL AND catalog_revision_id IS NULL
          WHEN 'method_unsupported' THEN
            (observation_policy_id = 'spring-orders-v1' AND catalog_revision_id IS NULL
              AND application_component = 'spring-fixture' AND binding_key = 'default')
            OR (observation_policy_id = 'runtime-route-v1'
              AND catalog_revision_id IS NOT NULL AND application_component IS NOT NULL)
          WHEN 'route_unapproved' THEN observation_policy_id = 'spring-orders-v1'
            AND catalog_revision_id IS NULL
            AND application_component = 'spring-fixture' AND binding_key = 'default'
          WHEN 'no_catalog_match' THEN observation_policy_id = 'runtime-route-v1'
            AND catalog_revision_id IS NOT NULL AND application_component IS NOT NULL
          WHEN 'route_unmatched_after_normalization' THEN observation_policy_id = 'runtime-route-v1'
            AND catalog_revision_id IS NOT NULL AND application_component IS NOT NULL
          ELSE 0
        END
      ELSE 0
    END, 0)),
    FOREIGN KEY(recording_id, project_id) REFERENCES recordings(recording_id, project_id),
    FOREIGN KEY(project_id, operation_id, application_component, binding_key, method, route_template)
        REFERENCES operations_v11(project_id, operation_id, application_component, binding_key, method, route_template),
    FOREIGN KEY(project_id, operation_id, operation_fingerprint)
        REFERENCES operations_v11(project_id, operation_id, endpoint_fingerprint),
    FOREIGN KEY(project_id, operation_id, application_component, binding_key, method, route_template, operation_fingerprint)
        REFERENCES catalog_operations(project_id, operation_id, application_component, binding_key, method, route_template, endpoint_fingerprint),
    FOREIGN KEY(project_id, catalog_revision_id)
        REFERENCES catalog_revisions(project_id, revision_id),
    FOREIGN KEY(project_id, catalog_revision_id, operation_id)
        REFERENCES catalog_runtime_link_routes(project_id, revision_id, operation_id)
) STRICT;

INSERT INTO recording_endpoint_observations_v11 (
    recording_id, project_id, disposition, observation_policy_id, operation_id,
    application_component, binding_key, method, route_template, reason_code
)
SELECT recording_id, project_id, disposition, observation_policy_id, operation_id,
       application_component, binding_key, method, route_template, reason_code
FROM recording_endpoint_observations;

DROP TABLE recording_endpoint_observations;
DROP TABLE operations;
ALTER TABLE operations_v11 RENAME TO operations;
ALTER TABLE recording_endpoint_observations_v11 RENAME TO recording_endpoint_observations;

CREATE INDEX operations_project_order
    ON operations(project_id, method, route_template, application_component, binding_key, operation_id);
CREATE INDEX endpoint_observations_operation_recording
    ON recording_endpoint_observations(project_id, operation_id, recording_id);
CREATE INDEX endpoint_observations_unmatched_recording
    ON recording_endpoint_observations(project_id, disposition, recording_id);
