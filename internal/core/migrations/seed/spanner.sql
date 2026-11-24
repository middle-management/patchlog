-- Rows the core expects to exist, inserted after the migrations on every
-- start (package dbmigrate): safe to run again.

-- cache_gen's one row, which the tailer reads (tailer.go).
INSERT INTO cache_gen (id, gen) VALUES (1, 0) ON CONFLICT (id) DO NOTHING;
-- The id blocks of the chain-ordered tables (spannerids.go), from 1.
INSERT INTO id_blocks (name, next) VALUES ('revisions', 1) ON CONFLICT (name) DO NOTHING;
INSERT INTO id_blocks (name, next) VALUES ('ns_log', 1) ON CONFLICT (name) DO NOTHING;
INSERT INTO id_blocks (name, next) VALUES ('ns_config', 1) ON CONFLICT (name) DO NOTHING;
INSERT INTO id_blocks (name, next) VALUES ('archives', 1) ON CONFLICT (name) DO NOTHING;
