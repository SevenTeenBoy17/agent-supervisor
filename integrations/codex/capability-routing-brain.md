# Capability Routing Brain v3

The shared core discovers and probes the live capability inventory at runtime. This
file is a portable policy reference, not evidence that any capability is installed,
enabled, healthy, or callable on the current host.

1. Split the complete request into atomic intents without count or name truncation.
2. Match against enabled versions and legal roots using full canonical names.
3. Exclude manual-only capabilities from automatic routing. Mark unreadable or broken
   entries unavailable/unknown and retain health evidence and fallback.
4. Pick 2-3 non-overlapping high-signal capabilities for the current phase. Schedule
   additional capabilities in later phases or bounded sub-agent waves; there is no
   total limit.
5. Require a disposition for every intent. Zero-skill routing needs specific skip
   reasons and independent review.
6. Correlate attempt/result by invocation id; only a successful result counts as use.
7. Two failures of the same capability in one phase open its circuit and select the
   declared fallback.
8. Apply the action risk gate independently of routing confidence.

Preferred fallback chains, when their members are discovered and healthy: Browser ->
Playwright -> verified manual steps; GitHub connector -> `gh` -> local clone;
code-review-graph -> build Python graph -> manual impact review. Any unreadable or
unhealthy capability is disabled from automatic routing for that runtime and its
recorded fallback is considered instead.
