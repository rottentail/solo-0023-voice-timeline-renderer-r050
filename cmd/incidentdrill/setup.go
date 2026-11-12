package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"time"

	"voice-timeline-renderer/internal/audiocodec"
	"voice-timeline-renderer/internal/domain"
	"voice-timeline-renderer/internal/httpapi"
	"voice-timeline-renderer/internal/service"
	"voice-timeline-renderer/internal/storage"
)

// Scenario render ids used across the drill.
const (
	idHealthyRender   = "drill_healthy_render"
	idMissingOutput   = "drill_missing_output"
	idDigestMismatch  = "drill_digest_mismatch"
	idStuckActive     = "drill_stuck_active"
	idFailedWithFiles = "drill_failed_with_files"
	idOrphanArtifacts = "drill_orphan_artifacts"

	idHealthySource = "drill_healthy_source"
	idHealthyTL     = "drill_healthy_timeline"
	idScenarioTL    = "drill_scenario_timeline"
)

type drill struct {
	root         string
	bundleParent string
	server       *httptest.Server
	client       *http.Client

	// Baseline job bytes captured before any traffic so the drill can prove
	// no terminal state was rewritten through the service surface.
	baselineJobHashes map[string]string

	report     *reportSnapshot
	bundleRoot string

	removeOnClose bool
}

func newDrill() (*drill, error) {
	root, err := os.MkdirTemp("", "incident-drill-data-*")
	if err != nil {
		return nil, err
	}
	bundleParent, err := os.MkdirTemp("", "incident-drill-bundles-*")
	if err != nil {
		_ = os.RemoveAll(root)
		return nil, err
	}
	repo, err := storage.NewRepository(root)
	if err != nil {
		_ = os.RemoveAll(root)
		_ = os.RemoveAll(bundleParent)
		return nil, err
	}
	serviceLayer := service.New(repo, service.DefaultConfig())
	api := httpapi.New(serviceLayer, httpapi.Options{
		MaxSourceRequestBytes: 48 << 20,
		MaxJSONBytes:          2 << 20,
	})
	server := httptest.NewServer(api.Handler())
	return &drill{
		root:              root,
		bundleParent:      bundleParent,
		server:            server,
		client:            &http.Client{Timeout: 30 * time.Second},
		baselineJobHashes: map[string]string{},
	}, nil
}

func (d *drill) close(keep bool) {
	d.server.Close()
	if keep || d.removeOnClose {
		return
	}
	_ = os.RemoveAll(d.root)
	_ = os.RemoveAll(d.bundleParent)
}

func (d *drill) requestJSON(method, path string, payload any) (int, []byte, error) {
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return 0, nil, err
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(context.Background(), method, d.server.URL+path, body)
	if err != nil {
		return 0, nil, err
	}
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := d.client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	return response.StatusCode, raw, err
}

func (d *drill) putSource(id, name string, wav []byte) error {
	status, body, err := d.requestJSON("PUT", "/v1/sources/"+id, map[string]any{
		"name":       name,
		"wav_base64": encodeBase64(wav),
	})
	if err != nil {
		return err
	}
	if status != http.StatusCreated {
		return fmt.Errorf("PUT source %s returned %d: %s", id, status, string(body))
	}
	return nil
}

func (d *drill) putTimeline(id string, spans []domain.TimelineSpan) (domain.Timeline, error) {
	status, body, err := d.requestJSON("PUT", "/v1/timelines/"+id, map[string]any{
		"name":             "drill timeline " + id,
		"sample_rate":      48000,
		"output_channels":  1,
		"target_peak_dbfs": -1,
		"spans":            spans,
	})
	if err != nil {
		return domain.Timeline{}, err
	}
	if status != http.StatusCreated {
		return domain.Timeline{}, fmt.Errorf("PUT timeline %s returned %d: %s", id, status, string(body))
	}
	var plan domain.Timeline
	if err := json.Unmarshal(body, &plan); err != nil {
		return domain.Timeline{}, err
	}
	return plan, nil
}

func (d *drill) putRender(id, timelineID string) (domain.RenderJob, error) {
	status, body, err := d.requestJSON("PUT", "/v1/renders/"+id, map[string]any{
		"timeline_id": timelineID,
	})
	if err != nil {
		return domain.RenderJob{}, err
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return domain.RenderJob{}, fmt.Errorf("PUT render %s returned %d: %s", id, status, string(body))
	}
	var job domain.RenderJob
	if err := json.Unmarshal(body, &job); err != nil {
		return domain.RenderJob{}, err
	}
	return job, nil
}

func sineWAV(sampleRate, channels, durationMS int, frequency, amplitude float64) ([]byte, error) {
	frames := sampleRate * durationMS / 1000
	samples := make([]float32, frames*channels)
	for frame := 0; frame < frames; frame++ {
		seconds := float64(frame) / float64(sampleRate)
		value := float32(math.Sin(2*math.Pi*frequency*seconds) * amplitude)
		if channels == 1 {
			samples[frame] = value
			continue
		}
		samples[frame*2] = value
		samples[frame*2+1] = value * 0.7
	}
	return audiocodec.EncodePCM16(sampleRate, channels, samples)
}

func encodeBase64(payload []byte) string {
	return base64.StdEncoding.EncodeToString(payload)
}

// hashPath returns the SHA-256 of a file, used to prove job records are
// untouched by service traffic.
func hashPath(path string) (string, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

func (d *drill) jobPath(id string) string {
	return filepath.Join(d.root, "jobs", id+".json")
}
