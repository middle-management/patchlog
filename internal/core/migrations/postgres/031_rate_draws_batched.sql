-- Migration: rate draws batched
-- Created: 2026-11-21T18:57:55Z
-- Checksum: 3ca1d2ced6ec3eba64df7f19817904091aa44fc0887c13693d70559ae3491f9c
-- Chain: 2cfe78668bd73fbad9e92a2b9f1ec5b0888d535657621e872777f6c561239bb9
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- rate_draws is the draws of a batch of requests, one statement
-- (ratebuckets.go, drawBatch): what rate_draw would do for each request in
-- turn, with every bucket row locked once for the batch. Item i of ks, rs,
-- bs and cs is a draw of request rq[i] (1, 2, ... in the batch's order;
-- a request's items are adjacent, its keys distinct); request q draws at
-- nows[q] (Unix microseconds), deducting whatever its buckets hold if
-- forced[q] (a charge).
--
-- It adds the buckets never drawn on, full as of the first request that
-- draws on each, in key order; then it locks every row of ks in key order,
-- so batches and draws never wait on each other in a cycle. Then, request
-- by request, it refills each of the request's buckets to its time at its
-- rate, up to its burst, from what the requests before it left (a row last
-- drawn on later isn't refilled), and if every one holds a token, or the
-- request is forced, deducts the request's costs. Each row changed is
-- written once, as the last request admitted on it left it. It returns,
-- for each item, its request, key, the bucket's tokens before the
-- request's deduction, and whether the request deducted; or nothing at all
-- if a row went (a sweep deleted it between the insert and the lock),
-- having deducted nothing.
CREATE OR REPLACE FUNCTION rate_draws(rq int[], ks bytea[], rs float8[], bs float8[], cs float8[], nows bigint[], forced boolean[])
RETURNS TABLE (r int, k bytea, t float8, admitted boolean) LANGUAGE plpgsql AS $draws$
DECLARE
  n   int := cardinality(ks);
  m   int;          -- distinct keys
  uk  bytea[];      -- the distinct keys, sorted
  ix  int[];        -- each item's index in uk
  tok float8[];     -- each key's tokens, as the requests so far left them
  lst bigint[];     -- and when it was last drawn on
  rat float8[];     -- the rate and burst of the last request admitted on it
  bur float8[];
  chg boolean[];    -- whether a request was admitted on it
  cur float8[];     -- each item's tokens at its request's turn
  oks boolean[];    -- each request's verdict
  i   int := 1;
  e   int;
  j   int;
  q   int;
  x   int;
  c   float8;
  ok  boolean;
BEGIN
  IF n = 0 THEN
    RETURN;
  END IF;
  INSERT INTO rate_buckets (key, tokens, last, rate, burst)
  SELECT DISTINCT ON (w.key) w.key, w.burst, nows[w.q], w.rate, w.burst
  FROM unnest(rq, ks, rs, bs) WITH ORDINALITY AS w (q, key, rate, burst, o)
  ORDER BY w.key, w.o
  ON CONFLICT (key) DO NOTHING;

  SELECT array_agg(u.key ORDER BY u.key) INTO uk FROM (SELECT DISTINCT u.key FROM unnest(ks) AS u (key)) u;
  m := cardinality(uk);
  SELECT array_agg(d.x ORDER BY d.o) INTO ix
  FROM (SELECT u.o, dense_rank() OVER (ORDER BY u.key)::int AS x FROM unnest(ks) WITH ORDINALITY AS u (key, o)) d;

  SELECT array_agg(b.tokens ORDER BY b.key), array_agg(b.last ORDER BY b.key)
  INTO tok, lst
  FROM (SELECT key, tokens, last FROM rate_buckets WHERE key = ANY (uk) ORDER BY key FOR UPDATE) b;
  IF coalesce(cardinality(tok), 0) <> m THEN
    RETURN;
  END IF;

  rat := array_fill(0::float8, ARRAY[m]);
  bur := array_fill(0::float8, ARRAY[m]);
  chg := array_fill(false, ARRAY[m]);
  cur := array_fill(0::float8, ARRAY[n]);
  oks := array_fill(false, ARRAY[cardinality(nows)]);
  WHILE i <= n LOOP
    q := rq[i];
    e := i;
    WHILE e < n AND rq[e + 1] = q LOOP
      e := e + 1;
    END LOOP;
    ok := true;
    FOR j IN i..e LOOP
      x := ix[j];
      c := tok[x];
      IF nows[q] > lst[x] THEN
        c := LEAST(bs[j], c + (nows[q] - lst[x]) * rs[j] / 1e6);
      END IF;
      cur[j] := c;
      IF c < 1 THEN
        ok := false;
      END IF;
    END LOOP;
    ok := ok OR forced[q];
    oks[q] := ok;
    IF ok THEN
      FOR j IN i..e LOOP
        x := ix[j];
        tok[x] := cur[j] - cs[j];
        lst[x] := GREATEST(lst[x], nows[q]);
        rat[x] := rs[j];
        bur[x] := bs[j];
        chg[x] := true;
      END LOOP;
    END IF;
    i := e + 1;
  END LOOP;

  UPDATE rate_buckets b SET tokens = u.tokens, last = u.last, rate = u.rate, burst = u.burst
  FROM unnest(uk, tok, lst, rat, bur, chg) AS u (key, tokens, last, rate, burst, chg)
  WHERE u.chg AND b.key = u.key;

  RETURN QUERY SELECT rq[u.o::int], u.key, cur[u.o::int], oks[rq[u.o::int]]
  FROM unnest(ks) WITH ORDINALITY AS u (key, o);
END
$draws$;
