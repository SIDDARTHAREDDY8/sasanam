# Incident & Metrics Report

## Findings
- INC-101 (disk pressure on node 7): resolved.
- INC-102 (stale feature flag ff-114 left enabled): open.
- p99 latency: down 12% after cache tuning.
- Error budget remaining: 0.8%.

## Recommendations
- Turn off stale flag ff-114 to close INC-102.
- Continue monitoring node 7 disk health post INC-101.
- Treat the 0.8% error budget as scarce; limit change velocity until it recovers.

## Sources
- sources/incidents.txt
- sources/metrics.txt
