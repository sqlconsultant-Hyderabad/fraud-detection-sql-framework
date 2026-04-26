-- ============================================================
-- FRAUD DETECTION ANALYTICS FRAMEWORK
-- Based on real enterprise fraud detection systems
-- Detects anomalies, velocity patterns, and suspicious behaviour
-- across high-volume transaction data ($2B+ scale)
-- ============================================================

-- ── STEP 1: Transaction Velocity Check ───────────────────────
-- Flags accounts with unusually high transaction frequency
-- within short time windows (common fraud signal)

WITH velocity_check AS (
  SELECT
    account_id,
    COUNT(*)                                      AS txn_count_1hr,
    SUM(amount)                                   AS total_amount_1hr,
    MIN(created_at)                               AS window_start,
    MAX(created_at)                               AS window_end
  FROM transactions
  WHERE created_at >= NOW() - INTERVAL '1 hour'
    AND status     = 'completed'
  GROUP BY account_id
  HAVING COUNT(*) > 10                            -- threshold: >10 txns/hr
      OR SUM(amount) > 5000                       -- threshold: >$5K/hr
),

-- ── STEP 2: Geographic Anomaly Detection ─────────────────────
-- Flags accounts transacting from multiple countries
-- within an impossible travel window (24 hours)

geo_anomaly AS (
  SELECT
    t.account_id,
    COUNT(DISTINCT t.country_code)                AS countries_24hr,
    ARRAY_AGG(DISTINCT t.country_code)            AS country_list,
    MIN(t.created_at)                             AS first_txn,
    MAX(t.created_at)                             AS last_txn
  FROM transactions t
  WHERE t.created_at >= NOW() - INTERVAL '24 hours'
  GROUP BY t.account_id
  HAVING COUNT(DISTINCT t.country_code) > 1
),

-- ── STEP 3: Baseline Deviation ────────────────────────────────
-- Compares current spend to 90-day historical average
-- Flags accounts deviating more than 3x their normal pattern

spend_baseline AS (
  SELECT
    account_id,
    AVG(daily_spend)                              AS avg_daily_spend_90d,
    STDDEV(daily_spend)                           AS stddev_spend_90d,
    MAX(daily_spend)                              AS max_daily_spend_90d
  FROM (
    SELECT
      account_id,
      DATE_TRUNC('day', created_at)               AS txn_day,
      SUM(amount)                                 AS daily_spend
    FROM transactions
    WHERE created_at BETWEEN NOW() - INTERVAL '90 days'
                         AND NOW() - INTERVAL '1 day'
      AND status = 'completed'
    GROUP BY account_id, DATE_TRUNC('day', created_at)
  ) daily
  GROUP BY account_id
),

today_spend AS (
  SELECT
    account_id,
    SUM(amount)                                   AS spend_today
  FROM transactions
  WHERE DATE_TRUNC('day', created_at) = CURRENT_DATE
    AND status = 'completed'
  GROUP BY account_id
),

deviation_flags AS (
  SELECT
    t.account_id,
    t.spend_today,
    b.avg_daily_spend_90d,
    b.stddev_spend_90d,
    ROUND(t.spend_today / NULLIF(b.avg_daily_spend_90d, 0), 2)
                                                  AS spend_multiplier
  FROM today_spend t
  JOIN spend_baseline b ON t.account_id = b.account_id
  WHERE t.spend_today > b.avg_daily_spend_90d * 3  -- 3x deviation threshold
),

-- ── STEP 4: Composite Risk Scoring ───────────────────────────
-- Combines all signals into a single risk score per account
-- Score 0-100: >70 = High Risk, 40-70 = Medium, <40 = Low

risk_scores AS (
  SELECT
    a.account_id,
    a.email,
    a.account_type,
    a.created_at                                  AS account_created,

    -- Risk signal flags
    CASE WHEN v.account_id IS NOT NULL THEN 1 ELSE 0 END
                                                  AS velocity_flag,
    CASE WHEN g.account_id IS NOT NULL THEN 1 ELSE 0 END
                                                  AS geo_flag,
    CASE WHEN d.account_id IS NOT NULL THEN 1 ELSE 0 END
                                                  AS deviation_flag,
    CASE WHEN DATEDIFF(NOW(), a.created_at) < 7  THEN 1 ELSE 0 END
                                                  AS new_account_flag,

    -- Supporting metrics
    COALESCE(v.txn_count_1hr, 0)                  AS txn_count_1hr,
    COALESCE(v.total_amount_1hr, 0)               AS amount_1hr,
    COALESCE(g.countries_24hr, 0)                 AS countries_24hr,
    COALESCE(d.spend_multiplier, 0)               AS spend_multiplier,

    -- Composite risk score (weighted)
    (
      CASE WHEN v.account_id IS NOT NULL THEN 35 ELSE 0 END +
      CASE WHEN g.account_id IS NOT NULL THEN 30 ELSE 0 END +
      CASE WHEN d.account_id IS NOT NULL THEN 25 ELSE 0 END +
      CASE WHEN DATEDIFF(NOW(), a.created_at) < 7 THEN 10 ELSE 0 END
    )                                             AS risk_score

  FROM accounts a
  LEFT JOIN velocity_check  v ON a.account_id = v.account_id
  LEFT JOIN geo_anomaly      g ON a.account_id = g.account_id
  LEFT JOIN deviation_flags  d ON a.account_id = d.account_id
  WHERE (
    v.account_id IS NOT NULL OR
    g.account_id IS NOT NULL OR
    d.account_id IS NOT NULL
  )
)

-- ── FINAL OUTPUT: Prioritised Risk Queue ─────────────────────
SELECT
  account_id,
  email,
  account_type,
  account_created,
  risk_score,
  CASE
    WHEN risk_score >= 70 THEN 'HIGH RISK — Immediate Review'
    WHEN risk_score >= 40 THEN 'MEDIUM RISK — Monitor Closely'
    ELSE                       'LOW RISK — Flag for Review'
  END                                             AS risk_category,
  velocity_flag,
  geo_flag,
  deviation_flag,
  new_account_flag,
  txn_count_1hr,
  amount_1hr,
  countries_24hr,
  spend_multiplier
FROM risk_scores
ORDER BY risk_score DESC, amount_1hr DESC;
