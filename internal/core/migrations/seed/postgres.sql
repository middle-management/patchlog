-- Rows the core expects to exist, inserted after the migrations on every
-- start (package dbmigrate): safe to run again.

-- cache_gen's one row, which the tailer reads (tailer.go).
INSERT INTO cache_gen (id, gen) VALUES (1, 0) ON CONFLICT DO NOTHING;
