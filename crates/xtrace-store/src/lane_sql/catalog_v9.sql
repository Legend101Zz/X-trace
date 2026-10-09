-- v0009_general_endpoint_links (lane K authors, lane C registers).
--
-- Relaxes the fixture-only CHECKs of the v3 `operations` and `recording_endpoint_observations`
-- tables to structural checks so any normalized HTTP route can be an operation and a recording
-- link. Every v3 row is copied unchanged (operation ids, fingerprints, timestamps and the sidecar
-- tuple stay byte-identical). `spring-orders-v1` keeps classifying exactly as before; the new
-- policy id `runtime-route-v1` and the reason codes `no_catalog_match` and
-- `route_unmatched_after_normalization` are added.
--
-- The sidecar keeps its foreign key to the legacy `operations` table (OPEN-13). The key now also
-- binds the endpoint tuple, so a link row can never disagree with the operation it points at.
-- Rebuild order: new parent, new child (references the new parent, SQLite rewrites the reference on
-- rename), drop old child, drop old parent, rename. Foreign keys are
-- enforced inside the migration transaction, so violations are deferred to commit.
PRAGMA defer_foreign_keys = ON;

CREATE TABLE operations_v9 (
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
                                    AND route_template NOT GLOB '*[' || char(1) || '-' || char(31) || char(127) || ']*'),
    application_component       TEXT NOT NULL CHECK(length(application_component) BETWEEN 1 AND 128
                                    AND application_component NOT GLOB '*[^A-Za-z0-9._:-]*'),
    binding_key                 TEXT NOT NULL CHECK(length(binding_key) BETWEEN 1 AND 128
                                    AND binding_key NOT GLOB '*[^A-Za-z0-9._:-]*'),
    fingerprint_format_version INTEGER NOT NULL CHECK(fingerprint_format_version = 1),
    endpoint_fingerprint        BLOB NOT NULL CHECK(length(endpoint_fingerprint) = 32),
    created_at                  TEXT NOT NULL,
    UNIQUE(project_id, operation_id),
    UNIQUE(project_id, fingerprint_format_version, endpoint_fingerprint),
    UNIQUE(project_id, application_component, binding_key, transport, method, route_template),
    UNIQUE(project_id, operation_id, application_component, binding_key, method, route_template)
) STRICT;

INSERT INTO operations_v9 (operation_id, project_id, transport, method, route_template,
                           application_component, binding_key, fingerprint_format_version,
                           endpoint_fingerprint, created_at)
SELECT operation_id, project_id, transport, method, route_template,
       application_component, binding_key, fingerprint_format_version,
       endpoint_fingerprint, created_at
FROM operations;

CREATE TABLE recording_endpoint_observations_v9 (
    recording_id         BLOB PRIMARY KEY CHECK(length(recording_id) = 16),
    project_id           BLOB NOT NULL CHECK(length(project_id) = 16),
    disposition          TEXT NOT NULL CHECK(disposition IN ('linked', 'unmatched')),
    observation_policy_id TEXT CHECK(observation_policy_id IS NULL
                              OR observation_policy_id IN ('spring-orders-v1', 'runtime-route-v1')),
    operation_id         BLOB CHECK(operation_id IS NULL OR (length(operation_id) = 16
                              AND substr(hex(operation_id), 13, 1) = '7'
                              AND substr(hex(operation_id), 17, 1) IN ('8', '9', 'A', 'B'))),
    application_component TEXT,
    binding_key          TEXT,
    method               TEXT,
    route_template       TEXT,
    reason_code          TEXT,
    -- component and binding are either both absent or both structurally valid
    CHECK((application_component IS NULL AND binding_key IS NULL)
       OR (application_component IS NOT NULL AND binding_key IS NOT NULL
           AND length(application_component) BETWEEN 1 AND 128
           AND application_component NOT GLOB '*[^A-Za-z0-9._:-]*'
           AND length(binding_key) BETWEEN 1 AND 128
           AND binding_key NOT GLOB '*[^A-Za-z0-9._:-]*')),
    CHECK((disposition = 'linked' AND observation_policy_id IS NOT NULL
           AND operation_id IS NOT NULL AND application_component IS NOT NULL
           AND method IN ('GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'TRACE', 'CONNECT')
           AND route_template IS NOT NULL AND length(CAST(route_template AS BLOB)) BETWEEN 1 AND 1024
           AND substr(route_template, 1, 1) = '/'
           AND reason_code IS NULL
           AND (observation_policy_id = 'runtime-route-v1'
                OR (application_component = 'spring-fixture' AND binding_key = 'default'
                    AND method = 'POST' AND route_template = '/orders')))
       OR (disposition = 'unmatched' AND operation_id IS NULL AND method IS NULL
           AND route_template IS NULL AND reason_code IN
           ('observation_policy_missing', 'observation_policy_invalid',
            'identity_context_missing', 'identity_context_invalid',
            'method_unsupported', 'route_unapproved',
            'no_catalog_match', 'route_unmatched_after_normalization'))),
    CHECK(reason_code NOT IN ('observation_policy_missing', 'observation_policy_invalid')
          OR observation_policy_id IS NULL),
    CHECK(reason_code NOT IN ('identity_context_missing', 'identity_context_invalid')
          OR (observation_policy_id IS NOT NULL AND application_component IS NULL AND binding_key IS NULL)),
    CHECK(reason_code NOT IN ('method_unsupported', 'route_unapproved')
          OR (observation_policy_id = 'spring-orders-v1'
              AND application_component = 'spring-fixture' AND binding_key = 'default')),
    CHECK(reason_code NOT IN ('no_catalog_match', 'route_unmatched_after_normalization')
          OR (observation_policy_id = 'runtime-route-v1' AND application_component IS NOT NULL)),
    FOREIGN KEY(recording_id, project_id) REFERENCES recordings(recording_id, project_id),
    FOREIGN KEY(project_id, operation_id, application_component, binding_key, method, route_template)
        REFERENCES operations_v9(project_id, operation_id, application_component, binding_key, method, route_template)
) STRICT;

INSERT INTO recording_endpoint_observations_v9 (recording_id, project_id, disposition,
                                                observation_policy_id, operation_id,
                                                application_component, binding_key, method,
                                                route_template, reason_code)
SELECT recording_id, project_id, disposition, observation_policy_id, operation_id,
       application_component, binding_key, method, route_template, reason_code
FROM recording_endpoint_observations;

DROP TABLE recording_endpoint_observations;
DROP TABLE operations;
ALTER TABLE operations_v9 RENAME TO operations;
ALTER TABLE recording_endpoint_observations_v9 RENAME TO recording_endpoint_observations;

CREATE INDEX operations_project_order
    ON operations(project_id, method, route_template, application_component, binding_key, operation_id);
CREATE INDEX endpoint_observations_operation_recording
    ON recording_endpoint_observations(project_id, operation_id, recording_id);
CREATE INDEX endpoint_observations_unmatched_recording
    ON recording_endpoint_observations(project_id, disposition, recording_id);
