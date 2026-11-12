package main

import (
	"os"
	"path/filepath"

	"voice-timeline-renderer/internal/incident"
)

// assertPreservation runs while the HTTP server is still live, mirroring the
// runbook requirement that the data root is fixed without stopping service.
// It verifies the bundle contains the whole tree, including the unlinked
// staging entries and the job record that proves the divergence.
func (d *drill) assertPreservation() error {
	const step = "preservation"
	_, bundleRoot, err := incident.PreserveFullCopy(d.root, d.bundleParent, "drill")
	if err != nil {
		return failf(step, "full copy failed: %v", err)
	}
	if err := incident.WriteBundleReport(bundleRoot, d.report.report); err != nil {
		return failf(step, "report write failed: %v", err)
	}
	verified, err := incident.VerifyBundle(bundleRoot)
	if err != nil {
		return failf(step, "bundle verification failed: %v", err)
	}
	d.bundleRoot = bundleRoot

	required := []string{
		filepath.Join("jobs", idMissingOutput+".json"),
		filepath.Join("jobs", idDigestMismatch+".json"),
		filepath.Join("jobs", idStuckActive+".json"),
		filepath.Join("jobs", idFailedWithFiles+".json"),
		filepath.Join("renders", idDigestMismatch, "output.wav"),
		filepath.Join("renders", idDigestMismatch, "receipt.json"),
		filepath.Join("renders", idOrphanArtifacts, "output.wav"),
		filepath.Join("renders", idHealthyRender, "output.wav"),
		filepath.Join("sources", idHealthySource, "source.wav"),
		filepath.Join("sources", idHealthySource, "metadata.json"),
		filepath.Join("tmp", "render-missing-output", "output.wav"),
		filepath.Join("tmp", "render-missing-output", "receipt.json"),
		filepath.Join("tmp", "render-unlinked-bytes", "output.wav"),
		filepath.Join("tmp", "render-ancient-unlinked", "output.wav"),
		filepath.Join("timelines", idScenarioTL+".json"),
	}
	manifestIndex := map[string]bool{}
	for _, record := range verified.Files {
		manifestIndex[record.RelPath] = true
	}
	for _, rel := range required {
		if !manifestIndex[filepath.ToSlash(rel)] {
			return failf(step, "bundle is missing required evidence file %s", rel)
		}
		if _, err := os.Stat(filepath.Join(bundleRoot, "data-snapshot", rel)); err != nil {
			return failf(step, "evidence file %s not present in snapshot: %v", rel, err)
		}
	}

	// A second verification on the closed bundle must stay deterministic, and
	// re-verifying must not require or touch the live data root.
	if _, err := incident.VerifyBundle(bundleRoot); err != nil {
		return failf(step, "repeated verification diverged: %v", err)
	}
	if _, err := os.Stat(filepath.Join(bundleRoot, "divergence-report.json")); err != nil {
		return failf(step, "divergence report not archived in bundle: %v", err)
	}

	// The live root must still contain every staging entry: preservation is a
	// copy, never a move or cleanup.
	for _, rel := range []string{
		filepath.Join("tmp", "render-ancient-unlinked", "output.wav"),
		filepath.Join("tmp", "render-missing-output", "output.wav"),
	} {
		if _, err := os.Stat(filepath.Join(d.root, rel)); err != nil {
			return failf(step, "preservation altered the live root at %s: %v", rel, err)
		}
	}
	return nil
}

// assertNoStateRewrite compares every terminal/active job record against the
// hashes captured before live service traffic. The service surface contains
// no state rewrite path, so the bytes must be identical.
func (d *drill) assertNoStateRewrite() error {
	const step = "no-state-rewrite"
	for id, baseline := range d.baselineJobHashes {
		current, err := hashPath(d.jobPath(id))
		if err != nil {
			return failf(step, "job %s became unreadable: %v", id, err)
		}
		if current != baseline {
			return failf(step, "job %s was rewritten through the service surface", id)
		}
	}
	// The fresh render created during the boundary step must itself be
	// completed through the legitimate lifecycle, never patched by tooling.
	fresh, err := d.loadJob("drill_fresh_render")
	if err != nil {
		return failf(step, "fresh render cannot be read: %v", err)
	}
	if fresh.State != "completed" || fresh.Output == nil {
		return failf(step, "fresh render state=%s output=%v", fresh.State, fresh.Output)
	}
	return nil
}
