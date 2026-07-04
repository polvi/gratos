-- Relationship tuples: <object_type>:<object_id>#<relation>@<subject>
-- subject_relation = '' means a direct subject (user:abc, folder:root);
-- non-empty means a subject set (group:eng#member). '' rather than NULL so the
-- column participates in PK uniqueness (SQLite treats NULLs as distinct).
CREATE TABLE relationships (
    tenant           TEXT NOT NULL,
    object_type      TEXT NOT NULL,
    object_id        TEXT NOT NULL,
    relation         TEXT NOT NULL,
    subject_type     TEXT NOT NULL,
    subject_id       TEXT NOT NULL,
    subject_relation TEXT NOT NULL DEFAULT '',
    created_at       INTEGER NOT NULL,
    PRIMARY KEY (tenant, object_type, object_id, relation,
                 subject_type, subject_id, subject_relation)
) WITHOUT ROWID;

-- Subject-side access: filtered reads by subject, future lookup-resources.
CREATE INDEX idx_rel_subject ON relationships
    (tenant, subject_type, subject_id, subject_relation, object_type, relation);

-- One schema document per tenant. version doubles as a future revision/zookie hook.
CREATE TABLE schemas (
    tenant     TEXT PRIMARY KEY,
    document   TEXT NOT NULL,
    version    INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
