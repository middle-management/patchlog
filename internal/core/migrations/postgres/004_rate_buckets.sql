-- Migration: rate buckets
-- Created: 2026-10-27T13:41:22Z
-- Checksum: 423ad4ba9900ed0176261e225db87c69cfe724add9087d8f00e1ef87af9cb743
-- Chain: b00dfaeb01df401a3ffa596cc067ab38487b7e6e68c8b837e40613468b360b39
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- The rate-limit buckets of §6.6, shared by every instance on the database
-- (ratebuckets.go). key is the bucket (auth.go), tokens what it held when
-- last drawn on, last when (Unix microseconds), and rate and burst those
-- it was drawn on under, for the sweep; a bucket without a row is full.
CREATE TABLE IF NOT EXISTS rate_buckets (
  key    bytea            PRIMARY KEY,
  tokens double precision NOT NULL,
  last   bigint           NOT NULL,
  rate   double precision NOT NULL,
  burst  double precision NOT NULL
);
-- rate_draw is a request's draw, one statement: it adds the buckets of ks
-- never drawn on, full as of now_us (Unix microseconds), in key order;
-- then it locks every row of ks in key order, refills each to now_us at
-- its rate in rs, up to its burst in bs (a row last drawn on later isn't
-- refilled: time doesn't run backwards for a bucket), and if every one has
-- a row and, unless forced (a charge), holds a token, deducts its cost in
-- cs. It returns each row's tokens before the deduction, and whether it
-- deducted. ks is sorted and distinct.
CREATE OR REPLACE FUNCTION rate_draw(ks bytea[], rs float8[], bs float8[], cs float8[], now_us bigint, forced boolean)
RETURNS TABLE (k bytea, t float8, admitted boolean) LANGUAGE plpgsql AS $draw$
BEGIN
  INSERT INTO rate_buckets (key, tokens, last, rate, burst)
  SELECT w.key, w.burst, now_us, w.rate, w.burst FROM unnest(ks, rs, bs) AS w (key, rate, burst) ORDER BY w.key
  ON CONFLICT (key) DO NOTHING;
  RETURN QUERY
  WITH w AS (
    SELECT * FROM unnest(ks, rs, bs, cs) AS w (key, rate, burst, cost)
  ), cur AS (
    SELECT b.key, w.rate, w.burst, w.cost,
           CASE WHEN now_us > b.last THEN LEAST(w.burst, b.tokens + (now_us - b.last) * w.rate / 1e6) ELSE b.tokens END AS tokens,
           GREATEST(b.last, now_us) AS last
    FROM rate_buckets b JOIN w ON w.key = b.key
    ORDER BY b.key
    FOR UPDATE OF b
  ), ok AS (
    SELECT count(*) = cardinality(ks) AND (forced OR coalesce(bool_and(cur.tokens >= 1), true)) AS ok FROM cur
  ), upd AS (
    UPDATE rate_buckets b SET tokens = cur.tokens - cur.cost, last = cur.last, rate = cur.rate, burst = cur.burst
    FROM cur, ok WHERE ok.ok AND b.key = cur.key
    RETURNING b.key
  )
  SELECT cur.key, cur.tokens, ok.ok FROM cur, ok;
END
$draw$;
