package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"sort"
	"sync"
	"sync/atomic"
)

const (
	// metricsOriginAppsec labels requests blocked by the AppSec (WAF) component.
	metricsOriginAppsec = "appsec"
	// metricsRemediationBan / Captcha / Challenge label the remediation applied.
	metricsRemediationBan       = "ban"
	metricsRemediationCaptcha   = "captcha"
	metricsRemediationChallenge = "challenge"
)

// droppedRequests counts dropped requests per origin, then per remediation,
// since the last successful metrics push. Nested string maps (not struct keys)
// keep it friendly to the Yaegi interpreter Traefik runs plugins in.
//
//nolint:gochecknoglobals
var (
	droppedMu       sync.Mutex
	droppedRequests = map[string]map[string]int64{}
)

// decisionOrigin returns the origin label CrowdSec remediation components use:
// blocklist decisions are reported as "lists:<list name>", like the firewall bouncer.
func decisionOrigin(decision Decision) string {
	if decision.Origin == "lists" && decision.Scenario != "" {
		return "lists:" + decision.Scenario
	}
	return decision.Origin
}

// countDropped records one dropped request for the usage metrics.
func countDropped(origin, remediation string) {
	atomic.AddInt64(&blockedRequests, 1)
	droppedMu.Lock()
	defer droppedMu.Unlock()
	byRemediation, ok := droppedRequests[origin]
	if !ok {
		byRemediation = map[string]int64{}
		droppedRequests[origin] = byRemediation
	}
	byRemediation[remediation]++
}

// takeDropped returns the counts gathered so far and starts a new window.
func takeDropped() map[string]map[string]int64 {
	droppedMu.Lock()
	defer droppedMu.Unlock()
	taken := droppedRequests
	droppedRequests = map[string]map[string]int64{}
	return taken
}

// restoreDropped puts back counts that could not be pushed to LAPI.
func restoreDropped(counts map[string]map[string]int64) {
	droppedMu.Lock()
	defer droppedMu.Unlock()
	for origin, byRemediation := range counts {
		current, ok := droppedRequests[origin]
		if !ok {
			current = map[string]int64{}
			droppedRequests[origin] = current
		}
		for remediation, count := range byRemediation {
			current[remediation] += count
		}
	}
}

// droppedMetricItems turns the counts into LAPI usage-metrics items, one per
// origin/remediation pair, sorted for a stable payload. With nothing dropped it
// still reports a single zero item so the push keeps its heartbeat.
func droppedMetricItems(counts map[string]map[string]int64) ([]map[string]interface{}, int64) {
	origins := make([]string, 0, len(counts))
	for origin := range counts {
		origins = append(origins, origin)
	}
	sort.Strings(origins)

	var total int64
	items := []map[string]interface{}{}
	for _, origin := range origins {
		remediations := make([]string, 0, len(counts[origin]))
		for remediation := range counts[origin] {
			remediations = append(remediations, remediation)
		}
		sort.Strings(remediations)
		for _, remediation := range remediations {
			count := counts[origin][remediation]
			total += count
			labels := map[string]string{"remediation": remediation}
			if origin != "" {
				labels["origin"] = origin
			}
			items = append(items, map[string]interface{}{
				"name":   "dropped",
				"value":  count,
				"unit":   "request",
				"labels": labels,
			})
		}
	}
	if len(items) == 0 {
		items = append(items, map[string]interface{}{
			"name":  "dropped",
			"value": 0,
			"unit":  "request",
		})
	}
	return items, total
}
