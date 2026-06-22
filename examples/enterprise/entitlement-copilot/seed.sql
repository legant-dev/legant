-- A tiny enterprise data warehouse: a sales schema everyone in revops may read,
-- and a finance schema only finance/execs may read. The point of the demo is that
-- the SHARED analytics copilot must not let a sales rep read finance just by asking.
CREATE SCHEMA IF NOT EXISTS sales;
CREATE SCHEMA IF NOT EXISTS finance;

CREATE TABLE IF NOT EXISTS sales.pipeline (
  id      serial PRIMARY KEY,
  account text,
  stage   text,
  amount  numeric
);
CREATE TABLE IF NOT EXISTS finance.salaries (
  id       serial PRIMARY KEY,
  employee text,
  title    text,
  base     numeric,
  bonus    numeric
);

INSERT INTO sales.pipeline (account, stage, amount) VALUES
  ('Acme Corp',   'Negotiation', 120000),
  ('Globex',      'Proposal',     80000),
  ('Initech',     'Closed Won',   45000)
ON CONFLICT DO NOTHING;

INSERT INTO finance.salaries (employee, title, base, bonus) VALUES
  ('Jordan Lee',  'CEO',       950000, 500000),
  ('Sam Rivera',  'VP Sales',  280000, 120000),
  ('Pat Chen',    'Engineer',  180000,  20000)
ON CONFLICT DO NOTHING;

-- Every authorized AND denied query is recorded with the HUMAN named (sub/act
-- provenance), so the audit answers "who asked for what, on whose behalf" — the
-- record SOX / SOC 2 / EU-AI-Act Art. 12 demand and a shared service account can't give.
CREATE TABLE IF NOT EXISTS query_audit (
  id         serial PRIMARY KEY,
  ts         timestamptz DEFAULT now(),
  provenance text,    -- e.g. "user:bob -> agent:analytics-copilot"
  schema_q   text,
  allowed    boolean,
  reason     text
);
TRUNCATE query_audit;
