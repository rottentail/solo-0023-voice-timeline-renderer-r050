// Package incident provides read-only divergence scanning and forensic
// preservation for a voice-timeline data directory.
//
// The package never mutates the scanned data root: there is no code path that
// creates, renames, chmods, or removes anything inside it. All writes target a
// separately named preservation destination supplied by the caller.
package incident

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"voice-timeline-renderer/internal/domain"
)

// SchemaVersion is bumped whenever the on-disk report or manifest shape changes.
const SchemaVersion = 1

// DivergenceClass is the read-only classification of one render id.
type DivergenceClass string

const (
	// ClassConsistent means the job record and its published artifacts tell
	// the same story and the receipt digest verifies the output bytes.
	ClassConsistent DivergenceClass = "consistent"
	// ClassCompletedMissingArtifacts is the headline incident: a terminal
	// completed job whose output directory or files are absent.
	ClassCompletedMissingArtifacts DivergenceClass = "completed_missing_artifacts"
	// ClassActiveWithPublishedArtifacts means a queued/rendering/finalizing
	// job already has a published render directory, so the outcome cannot be
	// inferred from either side alone.
	ClassActiveWithPublishedArtifacts DivergenceClass = "active_with_published_artifacts"
	// ClassFailedWithPublishedArtifacts means a terminal failed job
	// nonetheless has downloadable artifacts, contradicting the invariant
	// that failed renders never expose output.
	ClassFailedWithPublishedArtifacts DivergenceClass = "failed_with_published_artifacts"
	// ClassReceiptDigestMismatch means output bytes fail the receipt's own
	// SHA-256 commitment, or the job's receipt digest does not agree.
	ClassReceiptDigestMismatch DivergenceClass = "receipt_digest_mismatch"
	// ClassReceiptJobMismatch means a receipt names a different render or
	// timeline than the job record it sits next to.
	ClassReceiptJobMismatch DivergenceClass = "receipt_job_mismatch"
	// ClassJobUnreadable means the job JSON cannot be decoded; its true
	// state is unknown and must stay unknown to the investigation.
	ClassJobUnreadable DivergenceClass = "job_unreadable"
	// ClassOrphanArtifactsNoJob means a render directory exists without any
	// job record claiming it.
	ClassOrphanArtifactsNoJob DivergenceClass = "orphan_artifacts_no_job"
)

// StagingDisposition states what may ever happen to a tmp/ entry. The package
// itself contains no deletion capability; the strongest disposition is only a
// recommendation that applies after preservation and separate approval.
type StagingDisposition string

const (
	// DispositionRetain means the entry cannot be proven redundant, so it is
	// evidence and must be kept for the investigation.
	DispositionRetain StagingDisposition = "retain_for_investigation"
	// DispositionEligibleAfterPreservation means the entry was positively
	// linked to a terminal job whose published outcome is already verified;
	// even then deletion is out of scope for this tool and requires the
	// preserved bundle plus an approved change.
	DispositionEligibleAfterPreservation StagingDisposition = "cleanup_eligible_only_after_preservation_and_approval"
)

// JobFinding captures everything observable about one render id. Fields are
// facts collected from disk; Uncertainties lists what the facts cannot settle.
type JobFinding struct {
	RenderID          string          `json:"render_id"`
	JobPath           string          `json:"job_path"`
	State             string          `json:"state,omitempty"`
	TimelineID        string          `json:"timeline_id,omitempty"`
	Class             DivergenceClass `json:"class"`
	ArtifactDirExists bool            `json:"artifact_dir_exists"`
	OutputPresent     bool            `json:"output_present"`
	ReceiptPresent    bool            `json:"receipt_present"`
	OutputSHA256      string          `json:"output_sha256,omitempty"`
	ReceiptDigest     string          `json:"receipt_digest,omitempty"`
	JobReceiptDigest  string          `json:"job_receipt_digest,omitempty"`
	Details           []string        `json:"details,omitempty"`
	Uncertainties     []string        `json:"uncertainties,omitempty"`
}

// StagingFinding describes one immediate child of the tmp/ staging directory.
type StagingFinding struct {
	Path             string             `json:"path"`
	Prefix           string             `json:"prefix"`
	IsDir            bool               `json:"is_dir"`
	ModTimeUTC       time.Time          `json:"mod_time_utc"`
	AgeSecondsAtScan float64            `json:"age_seconds_at_scan"`
	LinkedRenderID   string             `json:"linked_render_id,omitempty"`
	LinkedJobState   string             `json:"linked_job_state,omitempty"`
	Contents         []string           `json:"contents,omitempty"`
	Disposition      StagingDisposition `json:"disposition"`
	Rationale        []string           `json:"rationale"`
}

// Report is the complete read-only scan result.
type Report struct {
	SchemaVersion int              `json:"schema_version"`
	ScannedAtUTC  time.Time        `json:"scanned_at_utc"`
	DataRoot      string           `json:"data_root"`
	Jobs          []JobFinding     `json:"jobs"`
	Staging       []StagingFinding `json:"staging"`
	Counts        map[string]int   `json:"counts"`
}

// Scan walks dataRoot using only read/stat operations and classifies every
// job record, render directory, and staging entry it finds.
func Scan(dataRoot string) (*Report, error) {
	root, err := filepath.Abs(dataRoot)
	if err != nil {
		return nil, err
	}
	if info, err := os.Stat(root); err != nil {
		return nil, fmt.Errorf("scan data root: %w", err)
	} else if !info.IsDir() {
		return nil, fmt.Errorf("scan data root %s is not a directory", root)
	}

	now := time.Now().UTC()
	report := &Report{
		SchemaVersion: SchemaVersion,
		ScannedAtUTC:  now,
		DataRoot:      root,
		Jobs:          []JobFinding{},
		Staging:       []StagingFinding{},
		Counts:        map[string]int{},
	}

	jobStates := map[string]string{}
	jobTimelines := map[string]string{}
	jobReceiptDigests := map[string]string{}

	jobEntries, err := readDirNames(root, "jobs")
	if err != nil {
		return nil, err
	}
	for _, name := range jobEntries {
		if filepath.Ext(name) != ".json" {
			continue
		}
		id := name[:len(name)-len(".json")]
		finding := JobFinding{
			RenderID: id,
			JobPath:  filepath.Join("jobs", name),
		}
		payload, readErr := os.ReadFile(filepath.Join(root, "jobs", name))
		if readErr != nil {
			finding.Class = ClassJobUnreadable
			finding.Details = append(finding.Details, "job record cannot be read: "+readErr.Error())
			finding.Uncertainties = append(finding.Uncertainties,
				"true job state is unknown because the record is unreadable")
			report.Jobs = append(report.Jobs, finding)
			continue
		}
		var job domain.RenderJob
		if decodeErr := json.Unmarshal(payload, &job); decodeErr != nil {
			finding.Class = ClassJobUnreadable
			finding.Details = append(finding.Details, "job record cannot be decoded: "+decodeErr.Error())
			finding.Uncertainties = append(finding.Uncertainties,
				"true job state is unknown because the record is not valid JSON")
			report.Jobs = append(report.Jobs, finding)
			continue
		}
		finding.State = string(job.State)
		finding.TimelineID = job.TimelineID
		finding.JobReceiptDigest = job.ReceiptDigest
		jobStates[id] = string(job.State)
		jobTimelines[id] = job.TimelineID
		jobReceiptDigests[id] = job.ReceiptDigest
		classifyJob(root, &finding, job, now)
		report.Jobs = append(report.Jobs, finding)
	}

	// Render directories without any job record are orphans.
	renderEntries, err := readDirNames(root, "renders")
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, finding := range report.Jobs {
		known[finding.RenderID] = true
	}
	for _, name := range renderEntries {
		if known[name] {
			continue
		}
		finding := JobFinding{
			RenderID:          name,
			JobPath:           filepath.Join("jobs", name+".json"),
			Class:             ClassOrphanArtifactsNoJob,
			ArtifactDirExists: true,
			Details: []string{
				"render artifacts exist but no job record is present",
			},
			Uncertainties: []string{
				"the producing job and its terminal state are unknown",
			},
		}
		orphanDir := filepath.Join(root, "renders", name)
		if _, err := os.Stat(filepath.Join(orphanDir, "output.wav")); err == nil {
			finding.OutputPresent = true
			if digest, hashErr := hashFile(filepath.Join(orphanDir, "output.wav")); hashErr == nil {
				finding.OutputSHA256 = digest
			}
		}
		if payload, err := os.ReadFile(filepath.Join(orphanDir, "receipt.json")); err == nil {
			finding.ReceiptPresent = true
			var receipt domain.RenderReceipt
			if json.Unmarshal(payload, &receipt) == nil {
				finding.ReceiptDigest = receipt.Output.Digest
				if receipt.TimelineID != "" {
					finding.TimelineID = receipt.TimelineID
				}
			}
		}
		report.Jobs = append(report.Jobs, finding)
	}

	stage, err := scanStaging(root, now, jobStates, jobTimelines, jobReceiptDigests)
	if err != nil {
		return nil, err
	}
	if stage == nil {
		stage = []StagingFinding{}
	}
	report.Staging = stage

	sort.Slice(report.Jobs, func(i, j int) bool { return report.Jobs[i].RenderID < report.Jobs[j].RenderID })
	sort.Slice(report.Staging, func(i, j int) bool { return report.Staging[i].Path < report.Staging[j].Path })
	for _, finding := range report.Jobs {
		report.Counts[string(finding.Class)]++
	}
	for _, finding := range report.Staging {
		report.Counts["staging:"+string(finding.Disposition)]++
	}
	return report, nil
}

func classifyJob(root string, finding *JobFinding, job domain.RenderJob, now time.Time) {
	renderDir := filepath.Join(root, "renders", job.ID)
	outputPath := filepath.Join(renderDir, "output.wav")
	receiptPath := filepath.Join(renderDir, "receipt.json")

	if dirInfo, err := os.Stat(renderDir); err == nil && dirInfo.IsDir() {
		finding.ArtifactDirExists = true
	}
	if _, err := os.Stat(outputPath); err == nil {
		finding.OutputPresent = true
		if digest, hashErr := hashFile(outputPath); hashErr == nil {
			finding.OutputSHA256 = digest
		} else {
			finding.Details = append(finding.Details, "output cannot be hashed: "+hashErr.Error())
		}
	}
	var receipt domain.RenderReceipt
	if payload, err := os.ReadFile(receiptPath); err == nil {
		finding.ReceiptPresent = true
		if decodeErr := json.Unmarshal(payload, &receipt); decodeErr != nil {
			finding.Details = append(finding.Details, "receipt cannot be decoded: "+decodeErr.Error())
			finding.Uncertainties = append(finding.Uncertainties,
				"receipt content is unreadable, so output provenance cannot be confirmed")
		} else {
			finding.ReceiptDigest = receipt.Output.Digest
		}
	}

	terminal := job.State == domain.RenderCompleted || job.State == domain.RenderFailed
	active := job.State == domain.RenderQueued ||
		job.State == domain.RenderRendering ||
		job.State == domain.RenderFinalizing

	switch {
	case job.State == domain.RenderCompleted && (!finding.ArtifactDirExists || !finding.OutputPresent || !finding.ReceiptPresent):
		finding.Class = ClassCompletedMissingArtifacts
		finding.Details = append(finding.Details,
			"job is terminal completed but the committed output and/or receipt is absent")
		finding.Uncertainties = append(finding.Uncertainties,
			"whether the render ever completed successfully cannot be proven from disk",
			"the cause and timing of the loss are unknown")
		return
	case active && finding.ArtifactDirExists:
		finding.Class = ClassActiveWithPublishedArtifacts
		finding.Details = append(finding.Details,
			"job is still in an active state while a render directory is already present")
		finding.Uncertainties = append(finding.Uncertainties,
			"a crash may have interrupted publication; the authoritative terminal state is unknown")
		return
	case job.State == domain.RenderFailed && finding.ArtifactDirExists:
		finding.Class = ClassFailedWithPublishedArtifacts
		finding.Details = append(finding.Details,
			"failed job must never expose artifacts, yet a render directory exists")
		finding.Uncertainties = append(finding.Uncertainties,
			"whether the artifacts predate or postdate the failure is unknown")
		return
	}

	if finding.ReceiptPresent && receipt.RenderID != "" && receipt.RenderID != job.ID {
		finding.Class = ClassReceiptJobMismatch
		finding.Details = append(finding.Details,
			fmt.Sprintf("receipt names render %q but sits under job %q", receipt.RenderID, job.ID))
		finding.Uncertainties = append(finding.Uncertainties, "the true ownership of the artifacts is unknown")
		return
	}
	if finding.ReceiptPresent && receipt.TimelineID != "" && receipt.TimelineID != job.TimelineID {
		finding.Class = ClassReceiptJobMismatch
		finding.Details = append(finding.Details,
			fmt.Sprintf("receipt names timeline %q but job records %q", receipt.TimelineID, job.TimelineID))
		finding.Uncertainties = append(finding.Uncertainties, "the true ownership of the artifacts is unknown")
		return
	}
	if finding.OutputPresent && finding.ReceiptDigest != "" && finding.OutputSHA256 != finding.ReceiptDigest {
		finding.Class = ClassReceiptDigestMismatch
		finding.Details = append(finding.Details,
			"stored output bytes do not match the receipt SHA-256 commitment")
		finding.Uncertainties = append(finding.Uncertainties,
			"which copy of the bytes is authoritative is unknown")
		return
	}
	if finding.OutputPresent && job.ReceiptDigest != "" && finding.OutputSHA256 != job.ReceiptDigest {
		finding.Class = ClassReceiptDigestMismatch
		finding.Details = append(finding.Details,
			"stored output bytes do not match the digest stored on the completed job")
		finding.Uncertainties = append(finding.Uncertainties,
			"which copy of the bytes is authoritative is unknown")
		return
	}
	if !terminal && !active {
		finding.Class = ClassJobUnreadable
		finding.Details = append(finding.Details, "job carries an unrecognized state: "+string(job.State))
		finding.Uncertainties = append(finding.Uncertainties, "unknown state value has no defined transition semantics")
		return
	}
	finding.Class = ClassConsistent
}

// scanStaging inventories every tmp/ entry and decides its disposition from
// provenance links rather than age.
func scanStaging(
	root string,
	now time.Time,
	jobStates map[string]string,
	jobTimelines map[string]string,
	jobReceiptDigests map[string]string,
) ([]StagingFinding, error) {
	_ = jobTimelines
	_ = jobReceiptDigests
	tmpRoot := filepath.Join(root, "tmp")
	entries, err := os.ReadDir(tmpRoot)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return []StagingFinding{}, nil
		}
		return nil, fmt.Errorf("read staging directory: %w", err)
	}
	findings := make([]StagingFinding, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("stat staging entry %s: %w", entry.Name(), err)
		}
		finding := StagingFinding{
			Path:             filepath.Join("tmp", entry.Name()),
			IsDir:            entry.IsDir(),
			ModTimeUTC:       info.ModTime().UTC(),
			AgeSecondsAtScan: now.Sub(info.ModTime().UTC()).Seconds(),
			Disposition:      DispositionRetain,
			Prefix:           stagingPrefix(entry.Name()),
		}
		if entry.IsDir() {
			children, err := os.ReadDir(filepath.Join(tmpRoot, entry.Name()))
			if err != nil {
				return nil, fmt.Errorf("read staging subdirectory %s: %w", entry.Name(), err)
			}
			for _, child := range children {
				finding.Contents = append(finding.Contents, child.Name())
			}
			sort.Strings(finding.Contents)
			if linked, ok := readLinkedRenderID(tmpRoot, entry.Name()); ok {
				finding.LinkedRenderID = linked
				finding.LinkedJobState = jobStates[linked]
			}
		}
		decideStaging(&finding, root, jobStates)
		findings = append(findings, finding)
	}
	return findings, nil
}

// decideStaging encodes the rule that age is never evidence: only a positive
// link to a terminal job whose own artifacts already verify can make a staging
// entry redundant. Everything else, regardless of age, is retained.
func decideStaging(finding *StagingFinding, root string, jobStates map[string]string) {
	if finding.LinkedRenderID == "" {
		finding.Rationale = append(finding.Rationale,
			"no receipt inside the staging entry names a render id, so its origin cannot be established",
			"modification age is recorded but is not a valid basis for deletion")
		return
	}
	state := jobStates[finding.LinkedRenderID]
	if state == "" {
		finding.Rationale = append(finding.Rationale,
			"staging entry references render "+finding.LinkedRenderID+" but no job record exists")
		return
	}
	if state != string(domain.RenderCompleted) && state != string(domain.RenderFailed) {
		finding.Rationale = append(finding.Rationale,
			"linked render "+finding.LinkedRenderID+" is in state "+state+", which is not terminal")
		return
	}
	if state == string(domain.RenderCompleted) {
		// Redundancy requires the published side to already be self-consistent.
		outputPath := filepath.Join(root, "renders", finding.LinkedRenderID, "output.wav")
		receiptPath := filepath.Join(root, "renders", finding.LinkedRenderID, "receipt.json")
		payload, err := os.ReadFile(receiptPath)
		if err != nil {
			finding.Rationale = append(finding.Rationale,
				"linked completed render has no readable receipt, so redundancy is unprovable")
			return
		}
		var receipt domain.RenderReceipt
		if err := json.Unmarshal(payload, &receipt); err != nil {
			finding.Rationale = append(finding.Rationale, "linked receipt is undecodable")
			return
		}
		digest, err := hashFile(outputPath)
		if err != nil || digest != receipt.Output.Digest {
			finding.Rationale = append(finding.Rationale,
				"linked completed render fails digest verification, so the staging copy may be the only good bytes")
			return
		}
	}
	finding.Disposition = DispositionEligibleAfterPreservation
	finding.Rationale = append(finding.Rationale,
		"positively linked to terminal "+state+" render "+finding.LinkedRenderID+
			" whose committed outcome is verified or defined as empty",
		"deletion still requires a preserved bundle and separate change approval; this tool never deletes")
}

func readLinkedRenderID(tmpRoot, dirName string) (string, bool) {
	payload, err := os.ReadFile(filepath.Join(tmpRoot, dirName, "receipt.json"))
	if err != nil {
		return "", false
	}
	var receipt domain.RenderReceipt
	if err := json.Unmarshal(payload, &receipt); err != nil || receipt.RenderID == "" {
		return "", false
	}
	return receipt.RenderID, true
}

func stagingPrefix(name string) string {
	switch {
	case len(name) >= 7 && name[:7] == "render-":
		return "render"
	case len(name) >= 7 && name[:7] == "source-":
		return "source"
	case len(name) >= 7 && name[:7] == ".write-":
		return "write-temp"
	default:
		return "other"
	}
}

func readDirNames(root string, child string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(root, child))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s directory: %w", child, err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
}

func hashFile(path string) (string, error) {
	handle, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer handle.Close()
	hasher := sha256.New()
	if _, err := copyWithLimit(hasher, handle); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}
