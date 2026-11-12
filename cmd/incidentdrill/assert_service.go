package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"voice-timeline-renderer/internal/domain"
)

// assertServiceBoundary proves that isolating the affected render ids leaves
// the rest of the service usable, and that divergent reads stay inside the
// existing HTTP response envelope rather than being silently corrected.
func (d *drill) assertServiceBoundary() error {
	const step = "service-boundary"

	// Health and an unaffected resource keep serving normally.
	status, body, err := d.requestJSON("GET", "/healthz", nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return failf(step, "health endpoint returned %d", status)
	}
	status, body, err = d.requestJSON("GET", "/v1/sources/"+idHealthySource, nil)
	if err != nil || status != http.StatusOK {
		return failf(step, "unaffected source read failed: status=%d body=%s err=%v", status, body, err)
	}
	status, body, err = d.requestJSON("GET", "/v1/timelines/"+idHealthyTL, nil)
	if err != nil || status != http.StatusOK {
		return failf(step, "unaffected timeline read failed: status=%d body=%s err=%v", status, body, err)
	}
	status, body, err = d.requestJSON("GET", "/v1/renders/"+idHealthyRender, nil)
	if err != nil || status != http.StatusOK {
		return failf(step, "healthy render read failed: status=%d body=%s", status, body)
	}
	status, body, err = d.requestJSON("GET", "/v1/renders/"+idHealthyRender+"/output", nil)
	if err != nil || status != http.StatusOK {
		return failf(step, "healthy render output failed: status=%d body=%s", status, body)
	}

	// New, unrelated registration and render work still have a usable path.
	freshWAV, err := sineWAV(48000, 1, 100, 660, 0.2)
	if err != nil {
		return err
	}
	if err := d.putSource("drill_fresh_source", "post-incident registration", freshWAV); err != nil {
		return failf(step, "new source registration was blocked: %v", err)
	}
	if _, err := d.putTimeline("drill_fresh_timeline", []domain.TimelineSpan{
		{SourceID: "drill_fresh_source", SourceStartFrame: 0, SourceEndFrame: 2400, GainDB: 0},
	}); err != nil {
		return failf(step, "new timeline composition was blocked: %v", err)
	}
	if _, err := d.putRender("drill_fresh_render", "drill_fresh_timeline"); err != nil {
		return failf(step, "new render execution was blocked: %v", err)
	}

	// Affected completed renders hit different existing boundaries depending
	// on where the divergence lives. The drill pins the real behavior so the
	// runbook never promises protection the service does not provide.

	// Missing artifacts: the state gate passes but storage cannot read the
	// receipt, so callers receive the existing 409 render_not_completed
	// envelope instead of a fabricated success.
	status, body, err = d.requestJSON("GET", "/v1/renders/"+idMissingOutput+"/output", nil)
	if err != nil {
		return err
	}
	if status != http.StatusConflict || !containsCode(body, "render_not_completed") {
		return failf(step, "missing-output render boundary = %d body=%s, want 409 render_not_completed",
			status, string(body))
	}
	status, body, err = d.requestJSON("GET", "/v1/renders/"+idMissingOutput+"/receipt", nil)
	if err != nil || status != http.StatusConflict || !containsCode(body, "render_not_completed") {
		return failf(step, "missing-output receipt boundary = %d body=%s", status, body)
	}

	// Digest divergence: the read path performs no re-hashing, so HTTP still
	// answers 200 for both receipt and output. The disagreement is only
	// detectable from disk-side verification, which is exactly what the scan
	// fixes as evidence. The drill asserts this limitation explicitly rather
	// than assuming a guard that does not exist.
	status, body, err = d.requestJSON("GET", "/v1/renders/"+idDigestMismatch, nil)
	if err != nil || status != http.StatusOK || !strings.Contains(string(body), `"state":"completed"`) {
		return failf(step, "digest-mismatch job read = %d body=%s", status, body)
	}
	status, _, err = d.requestJSON("GET", "/v1/renders/"+idDigestMismatch+"/receipt", nil)
	if err != nil || status != http.StatusOK {
		return failf(step, "digest-mismatch receipt read = %d err=%v; HTTP cannot detect this class", status, err)
	}
	status, body, err = d.requestJSON("GET", "/v1/renders/"+idDigestMismatch+"/output", nil)
	if err != nil || status != http.StatusOK {
		return failf(step, "digest-mismatch output read = %d err=%v; HTTP cannot detect this class", status, err)
	}
	servedDigest := sha256Hex(body)
	finding, findErr := d.jobFinding(idDigestMismatch)
	if findErr != nil {
		return failf(step, "%v", findErr)
	}
	if servedDigest != finding.OutputSHA256 || servedDigest == finding.ReceiptDigest {
		return failf(step, "served bytes no longer match the scan-recorded disk facts")
	}

	// The failed-with-files render must stay masked behind the same boundary:
	// callers cannot download the artifacts that contradict its terminal state.
	status, body, err = d.requestJSON("GET", "/v1/renders/"+idFailedWithFiles+"/output", nil)
	if err != nil || status != http.StatusConflict {
		return failf(step, "failed render leaked artifacts through HTTP: status=%d body=%s", status, body)
	}

	// Re-PUTting an affected render is idempotent and cannot create a second
	// execution path around the divergence.
	status, body, err = d.requestJSON("PUT", "/v1/renders/"+idMissingOutput, map[string]any{
		"timeline_id": idScenarioTL,
	})
	if err != nil || status != http.StatusOK {
		return failf(step, "idempotent re-PUT boundary = %d body=%s err=%v", status, body, err)
	}
	return nil
}

func containsCode(body []byte, code string) bool {
	return strings.Contains(string(body), `"code":"`+code+`"`)
}

func sha256Hex(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}
