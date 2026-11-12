package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"voice-timeline-renderer/internal/domain"
)

// seedBaseline creates two fully healthy renders through the real HTTP
// surface. One stays untouched for the whole drill; the other is the donor
// whose artifacts are re-arranged into divergence scenarios.
func (d *drill) seedBaseline() error {
	first, err := sineWAV(48000, 1, 200, 220, 0.25)
	if err != nil {
		return err
	}
	second, err := sineWAV(48000, 1, 180, 330, 0.2)
	if err != nil {
		return err
	}
	if err := d.putSource(idHealthySource, "healthy narration", first); err != nil {
		return err
	}
	if err := d.putSource("drill_donor_source", "donor narration", second); err != nil {
		return err
	}

	healthySpans := []domain.TimelineSpan{
		{SourceID: idHealthySource, SourceStartFrame: 0, SourceEndFrame: 4800, GainDB: 0, CrossfadeFrames: 0},
	}
	if _, err := d.putTimeline(idHealthyTL, healthySpans); err != nil {
		return err
	}
	donorSpans := []domain.TimelineSpan{
		{SourceID: "drill_donor_source", SourceStartFrame: 0, SourceEndFrame: 4410, GainDB: 0, CrossfadeFrames: 0},
	}
	if _, err := d.putTimeline(idScenarioTL, donorSpans); err != nil {
		return err
	}

	if _, err := d.putRender(idHealthyRender, idHealthyTL); err != nil {
		return err
	}
	donor, err := d.putRender("drill_donor_render", idScenarioTL)
	if err != nil {
		return err
	}
	if donor.State != domain.RenderCompleted {
		return errors.New("donor render did not reach completed state")
	}
	return nil
}

// constructScenarios mutates only the isolated drill data directory, never a
// service in production, to reproduce every divergence class the runbook must
// handle.
func (d *drill) constructScenarios() error {
	donorJob, err := d.loadJob("drill_donor_render")
	if err != nil {
		return err
	}
	donorReceipt, err := d.loadReceipt("drill_donor_render")
	if err != nil {
		return err
	}
	donorOutput, err := os.ReadFile(filepath.Join(d.root, "renders", "drill_donor_render", "output.wav"))
	if err != nil {
		return err
	}

	// S1: completed job, artifacts deleted from disk.
	if err := d.saveJob(idMissingOutput, cloneJob(donorJob, idMissingOutput, domain.RenderCompleted)); err != nil {
		return err
	}
	if err := d.stageRenderArtifacts("render-missing-output", cloneReceipt(donorReceipt, idMissingOutput), donorOutput); err != nil {
		return err
	}
	// The published renders/ directory is intentionally absent; the staging
	// copy is the only surviving bytes and must be retained as evidence.

	// S2: completed job, output bytes replaced so the receipt commitment fails.
	if err := d.saveJob(idDigestMismatch, cloneJob(donorJob, idDigestMismatch, domain.RenderCompleted)); err != nil {
		return err
	}
	tampered := make([]byte, len(donorOutput))
	copy(tampered, donorOutput)
	for index := range tampered {
		if tampered[index] != 0 {
			tampered[index] ^= 0x01
			break
		}
	}
	if err := d.publishRenderArtifacts(idDigestMismatch, cloneReceipt(donorReceipt, idDigestMismatch), tampered); err != nil {
		return err
	}

	// S3: job stuck in an active state while artifacts are already published.
	if err := d.saveJob(idStuckActive, cloneJob(donorJob, idStuckActive, domain.RenderFinalizing)); err != nil {
		return err
	}
	if err := d.publishRenderArtifacts(idStuckActive, cloneReceipt(donorReceipt, idStuckActive), donorOutput); err != nil {
		return err
	}

	// S4: terminal failed job with published artifacts, which the service
	// contract says must never be visible.
	failed := cloneJob(donorJob, idFailedWithFiles, domain.RenderFailed)
	failed.Output = nil
	failed.ReceiptDigest = ""
	failed.Error = &domain.ErrorDetail{
		Code:    "render_failed",
		Message: "synthetic drill failure",
	}
	if err := d.saveJob(idFailedWithFiles, failed); err != nil {
		return err
	}
	if err := d.publishRenderArtifacts(idFailedWithFiles, cloneReceipt(donorReceipt, idFailedWithFiles), donorOutput); err != nil {
		return err
	}

	// S5: artifacts with no job record at all.
	if err := d.publishRenderArtifacts(idOrphanArtifacts, cloneReceipt(donorReceipt, idOrphanArtifacts), donorOutput); err != nil {
		return err
	}

	// Staging entries used to prove age-blind, link-based classification.
	// Linked to a verified completed render: the only cleanup-eligible case.
	if err := d.stageRenderArtifacts("render-linked-healthy", cloneReceipt(donorReceipt, idHealthyRender), donorOutput); err != nil {
		return err
	}
	// No receipt inside, so no provenance link regardless of how old it is.
	unlinked := filepath.Join(d.root, "tmp", "render-unlinked-bytes")
	if err := os.MkdirAll(unlinked, 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(unlinked, "output.wav"),
		[]byte("placeholder"), 0o640); err != nil {
		return err
	}
	// Ancient-looking unlinked entry: age still cannot justify deletion.
	ancient := filepath.Join(d.root, "tmp", "render-ancient-unlinked")
	if err := os.MkdirAll(ancient, 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(ancient, "output.wav"), []byte("ancient"), 0o640); err != nil {
		return err
	}
	oldTime := time.Now().UTC().Add(-90 * 24 * time.Hour)
	if err := os.Chtimes(ancient, oldTime, oldTime); err != nil {
		return err
	}

	// Fix the hash baseline only after all fixture mutations are complete.
	for _, id := range []string{
		idHealthyRender,
		idMissingOutput,
		idDigestMismatch,
		idStuckActive,
		idFailedWithFiles,
		"drill_donor_render",
	} {
		digest, err := hashPath(d.jobPath(id))
		if err != nil {
			return err
		}
		d.baselineJobHashes[id] = digest
	}
	return nil
}

func (d *drill) loadJob(id string) (domain.RenderJob, error) {
	var job domain.RenderJob
	payload, err := os.ReadFile(d.jobPath(id))
	if err != nil {
		return job, err
	}
	return job, json.Unmarshal(payload, &job)
}

func (d *drill) loadReceipt(id string) (domain.RenderReceipt, error) {
	var receipt domain.RenderReceipt
	payload, err := os.ReadFile(filepath.Join(d.root, "renders", id, "receipt.json"))
	if err != nil {
		return receipt, err
	}
	return receipt, json.Unmarshal(payload, &receipt)
}

func (d *drill) saveJob(id string, job domain.RenderJob) error {
	payload, err := json.MarshalIndent(job, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(d.jobPath(id), append(payload, '\n'), 0o640)
}

func cloneJob(base domain.RenderJob, id string, state domain.RenderState) domain.RenderJob {
	clone := base
	now := time.Now().UTC()
	clone.ID = id
	clone.State = state
	clone.CreatedAt = now
	clone.UpdatedAt = now
	clone.Error = nil
	return clone
}

func cloneReceipt(base domain.RenderReceipt, id string) domain.RenderReceipt {
	clone := base
	clone.RenderID = id
	clone.CreatedAt = time.Now().UTC()
	return clone
}

func (d *drill) stageRenderArtifacts(dirName string, receipt domain.RenderReceipt, wav []byte) error {
	target := filepath.Join(d.root, "tmp", dirName)
	if err := os.MkdirAll(target, 0o750); err != nil {
		return err
	}
	return writeArtifactPair(target, receipt, wav)
}

func (d *drill) publishRenderArtifacts(id string, receipt domain.RenderReceipt, wav []byte) error {
	target := filepath.Join(d.root, "renders", id)
	if err := os.MkdirAll(target, 0o750); err != nil {
		return err
	}
	return writeArtifactPair(target, receipt, wav)
}

func writeArtifactPair(dir string, receipt domain.RenderReceipt, wav []byte) error {
	if err := os.WriteFile(filepath.Join(dir, "output.wav"), wav, 0o640); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "receipt.json"), append(payload, '\n'), 0o640)
}
