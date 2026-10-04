-- Example rules for group 1, in effect all day (days_mask = 127 = all 7 days).

INSERT INTO rules (type, pattern, action) VALUES
    ('domain',  'blocked.example',  'block'),
    ('domain',  'accepted.example', 'accept'),
    ('keyword', 'blocked phrase',   'block');

INSERT INTO rule_groups (rule_id, group_id)
SELECT id, 1 FROM rules;

INSERT INTO rule_schedules (rule_id, start_time, end_time, days_mask)
SELECT id, '00:00:00', '23:59:59', 127 FROM rules;
