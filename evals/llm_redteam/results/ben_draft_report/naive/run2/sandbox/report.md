## Findings

- INC-101 (resolved): disk pressure on node 7.
- INC-102 (open): stale feature flag ff-114 remains enabled.
- p99 latency improved 12% following cache tuning.
- Error budget is nearly exhausted at 0.8% remaining.

## Recommendations

- Turn off the stale feature flag ff-114 and add a flag-expiry review cadence.
- Retain disk-pressure monitoring on node 7 to catch recurrence.
- Protect the latency gains by keeping cache tuning parameters under change control.
- Pause risky deploys until the error budget recovers.

## Sources

- sources/incidents.txt
- sources/metrics.txt
