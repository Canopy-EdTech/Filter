CREATE TABLE rules (
    id      SERIAL PRIMARY KEY,
    type    VARCHAR(16) NOT NULL CHECK (type IN ('domain', 'keyword')),
    pattern TEXT NOT NULL,
    action  VARCHAR(16) NOT NULL CHECK (action IN ('block', 'accept'))
);

CREATE TABLE rule_schedules (
    rule_id    INTEGER NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
    start_time TIME NOT NULL,
    end_time   TIME NOT NULL,
    days_mask  INTEGER NOT NULL -- bit 0 = Monday ... bit 6 = Sunday (ISODOW - 1)
);

CREATE TABLE rule_groups (
    rule_id  INTEGER NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
    group_id INTEGER NOT NULL
);

CREATE INDEX idx_rule_groups_group_id ON rule_groups(group_id);
CREATE INDEX idx_rule_schedules_rule_id ON rule_schedules(rule_id);
