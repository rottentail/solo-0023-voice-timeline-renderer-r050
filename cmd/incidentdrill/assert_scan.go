package main

import (
	"errors"
	"fmt"

	"voice-timeline-renderer/internal/incident"
)

// reportSnapshot indexes the scan result for assertion lookups.
type reportSnapshot struct {
	report  *incident.Report
	job     map[string]incident.JobFinding
	staging map[string]incident.StagingFinding
}

func (d *drill) assertScan() error {
	report, err := incident.Scan(d.root)
	if err != nil {
		return err
	}
	snapshot := &reportSnapshot{
		report:  report,
		job:     map[string]incident.JobFinding{},
		staging: map[string]incident.StagingFinding{},
	}
	for _, finding := range report.Jobs {
		snapshot.job[finding.RenderID] = finding
	}
	for _, finding := range report.Staging {
		snapshot.staging[finding.Path] = finding
	}
	d.report = snapshot

	const step = "scan"
	expectations := []struct {
		id    string
		class incident.DivergenceClass
	}{
		{idHealthyRender, incident.ClassConsistent},
		{"drill_donor_render", incident.ClassConsistent},
		{idMissingOutput, incident.ClassCompletedMissingArtifacts},
		{idDigestMismatch, incident.ClassReceiptDigestMismatch},
		{idStuckActive, incident.ClassActiveWithPublishedArtifacts},
		{idFailedWithFiles, incident.ClassFailedWithPublishedArtifacts},
		{idOrphanArtifacts, incident.ClassOrphanArtifactsNoJob},
	}
	for _, expectation := range expectations {
		finding, ok := snapshot.job[expectation.id]
		if !ok {
			return failf(step, "render %s is missing from the scan entirely", expectation.id)
		}
		if finding.Class != expectation.class {
			return failf(step, "render %s classified %s, want %s",
				expectation.id, finding.Class, expectation.class)
		}
		if len(finding.Uncertainties) == 0 && expectation.class != incident.ClassConsistent {
			return failf(step, "divergent render %s carries no retained uncertainty", expectation.id)
		}
	}

	// The fixed facts the runbook requires for the headline incident.
	missing := snapshot.job[idMissingOutput]
	if missing.ArtifactDirExists || missing.OutputPresent || missing.ReceiptPresent {
		return failf(step, "missing-output scenario must report absent artifacts")
	}
	if missing.State != "completed" || missing.TimelineID != idScenarioTL {
		return failf(step, "missing-output finding dropped the job identity facts")
	}
	mismatch := snapshot.job[idDigestMismatch]
	if mismatch.OutputSHA256 == "" || mismatch.ReceiptDigest == "" ||
		mismatch.OutputSHA256 == mismatch.ReceiptDigest {
		return failf(step, "digest mismatch scenario did not fix both hashes as facts")
	}

	// Staging classification must follow provenance, not age.
	linked, ok := snapshot.staging["tmp/render-linked-healthy"]
	if !ok {
		return failf(step, "linked staging entry was not inventoried")
	}
	if linked.Disposition != incident.DispositionEligibleAfterPreservation ||
		linked.LinkedRenderID != idHealthyRender || linked.LinkedJobState != "completed" {
		return failf(step, "linked staging entry misclassified: %+v", linked)
	}
	unlinked, ok := snapshot.staging["tmp/render-unlinked-bytes"]
	if !ok {
		return failf(step, "unlinked staging entry was not inventoried")
	}
	if unlinked.Disposition != incident.DispositionRetain || unlinked.LinkedRenderID != "" {
		return failf(step, "unlinked staging entry must be retained, got %+v", unlinked)
	}
	ancient, ok := snapshot.staging["tmp/render-ancient-unlinked"]
	if !ok {
		return failf(step, "ancient staging entry was not inventoried")
	}
	if ancient.Disposition != incident.DispositionRetain {
		return failf(step, "ancient staging entry was treated as garbage by age")
	}
	if ancient.AgeSecondsAtScan <= 0 {
		return failf(step, "staging age should be recorded as a fact even when it is not a decision input")
	}
	if len(report.Jobs) != len(expectations) {
		return failf(step, "scan found %d job findings, want %d", len(report.Jobs), len(expectations))
	}
	return nil
}

func (d *drill) jobFinding(id string) (incident.JobFinding, error) {
	if d.report == nil {
		return incident.JobFinding{}, errors.New("scan snapshot is not available")
	}
	finding, ok := d.report.job[id]
	if !ok {
		return incident.JobFinding{}, fmt.Errorf("finding for %s is absent", id)
	}
	return finding, nil
}
