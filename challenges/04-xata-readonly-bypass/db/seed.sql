CREATE TABLE IF NOT EXISTS tenant_documents (
    id SERIAL PRIMARY KEY,
    tenant TEXT NOT NULL,
    title TEXT NOT NULL,
    contents TEXT NOT NULL
);

INSERT INTO tenant_documents (tenant, title, contents) VALUES
    ('alpha', 'Quarterly Plan', 'Keep focus on ARR growth.'),
    ('bravo', 'Incident Report', 'FLAG{transaction_commit_escapes_readonly}');
