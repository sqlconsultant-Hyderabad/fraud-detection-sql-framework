# Fraud Detection SQL Framework

Enterprise-grade fraud detection system built for 
high-volume transaction environments ($2B+ scale).

## Detection Signals
- **Velocity Check** — flags accounts with >10 transactions/hr 
  or >$5K spend in 60 minutes
- **Geographic Anomaly** — detects impossible travel patterns 
  across multiple countries within 24 hours
- **Spend Deviation** — identifies accounts spending 3x their 
  90-day baseline
- **New Account Risk** — flags accounts less than 7 days old

## Risk Scoring
Composite 0–100 risk score with weighted signals:
- High Risk (70+) — Immediate review queue
- Medium Risk (40–69) — Monitor closely
- Low Risk (<40) — Standard flagging

## Real-World Impact
Modelled on fraud detection frameworks that prevented 
$12M+ in fraud losses across $2B+ in transaction volume.

## Tech Stack
- MySQL / Snowflake compatible
- Designed for production use at enterprise scale
