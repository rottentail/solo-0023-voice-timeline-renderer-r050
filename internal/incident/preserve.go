package incident

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// FileRecord is one preserved file with the facts needed to prove the bundle
// is a faithful copy.
type FileRecord struct {
	RelPath    string    `json:"rel_path"`
	Mode       uint32    `json:"mode"`
	SizeBytes  int64     `json:"size_bytes"`
	ModTimeUTC time.Time `json:"mod_time_utc"`
	SHA256     string    `json:"sha256"`
}

// Manifest describes a complete preservation bundle.
type Manifest struct {
	SchemaVersion int          `json:"schema_version"`
	CreatedAtUTC  time.Time    `json:"created_at_utc"`
	SourceRoot    string       `json:"source_root"`
	BundleRoot    string       `json:"bundle_root"`
	FileCount     int          `json:"file_count"`
	TotalBytes    int64        `json:"total_bytes"`
	Files         []FileRecord `json:"files"`
}

const manifestName = "preservation-manifest.json"
const reportName = "divergence-report.json"
const bundleDataDir = "data-snapshot"

// PreserveFullCopy makes a bit-for-bit, whole-tree copy of dataRoot into a
// fresh bundle directory under bundleParent and returns the written manifest.
//
// Guarantees:
//   - dataRoot is only opened for reading; no file inside it is created,
//     modified, renamed, or removed.
//   - the destination must not already exist and must not sit inside the data
//     root (and vice versa), so preservation can never overwrite or nest into
//     live state.
//   - every copied file is hashed and recorded with size, mode, and mtime.
func PreserveFullCopy(dataRoot, bundleParent string, label string) (*Manifest, string, error) {
	sourceRoot, err := filepath.Abs(dataRoot)
	if err != nil {
		return nil, "", err
	}
	parent, err := filepath.Abs(bundleParent)
	if err != nil {
		return nil, "", err
	}
	if info, err := os.Stat(sourceRoot); err != nil || !info.IsDir() {
		return nil, "", fmt.Errorf("source data root is not a directory: %s", sourceRoot)
	}
	if isPathWithin(sourceRoot, parent) || isPathWithin(parent, sourceRoot) {
		return nil, "", errors.New("preservation destination must be outside the data root and must not contain it")
	}
	if err := os.MkdirAll(parent, 0o750); err != nil {
		return nil, "", fmt.Errorf("create bundle parent: %w", err)
	}
	bundleName := "incident-" + sanitizeLabel(label) + "-" + time.Now().UTC().Format("20060102T150405Z")
	bundleRoot := filepath.Join(parent, bundleName)
	if err := os.Mkdir(bundleRoot, 0o750); err != nil {
		return nil, "", fmt.Errorf("create bundle directory: %w", err)
	}
	snapshotRoot := filepath.Join(bundleRoot, bundleDataDir)
	if err := os.Mkdir(snapshotRoot, 0o750); err != nil {
		return nil, "", bundleError(bundleRoot, err)
	}

	manifest := &Manifest{
		SchemaVersion: SchemaVersion,
		CreatedAtUTC:  time.Now().UTC(),
		SourceRoot:    sourceRoot,
		BundleRoot:    bundleRoot,
	}

	walkErr := filepath.WalkDir(sourceRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(sourceRoot, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if rel == "." {
				return nil
			}
			return os.MkdirAll(filepath.Join(snapshotRoot, rel), info.Mode().Perm())
		}
		if !info.Mode().IsRegular() {
			// Symlinks, sockets, and device files are not part of the service
			// storage contract; record them as an explicit failure instead of
			// silently following or dropping them.
			return fmt.Errorf("non-regular file %s (mode %v) is outside the storage contract", rel, info.Mode())
		}
		record, err := copyHashed(rel, path, filepath.Join(snapshotRoot, rel), info)
		if err != nil {
			return err
		}
		manifest.Files = append(manifest.Files, record)
		manifest.TotalBytes += record.SizeBytes
		return nil
	})
	if walkErr != nil {
		return nil, "", bundleError(bundleRoot, walkErr)
	}

	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].RelPath < manifest.Files[j].RelPath })
	manifest.FileCount = len(manifest.Files)
	if err := writeBundleJSON(filepath.Join(bundleRoot, manifestName), manifest); err != nil {
		return nil, "", bundleError(bundleRoot, err)
	}
	return manifest, bundleRoot, nil
}

// WriteBundleReport stores the read-only scan report next to the manifest.
func WriteBundleReport(bundleRoot string, report *Report) error {
	return writeBundleJSON(filepath.Join(bundleRoot, reportName), report)
}

// VerifyBundle re-hashes every file in a bundle and compares it with the
// manifest. A nil error means the bundle is internally complete and faithful.
// It never touches the original data root.
func VerifyBundle(bundleRoot string) (*Manifest, error) {
	root, err := filepath.Abs(bundleRoot)
	if err != nil {
		return nil, err
	}
	payload, err := os.ReadFile(filepath.Join(root, manifestName))
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var manifest Manifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}
	snapshotRoot := filepath.Join(root, bundleDataDir)
	seen := make(map[string]bool, len(manifest.Files))
	for _, record := range manifest.Files {
		target := filepath.Join(snapshotRoot, record.RelPath)
		info, err := os.Stat(target)
		if err != nil {
			return &manifest, fmt.Errorf("manifest file missing: %s: %w", record.RelPath, err)
		}
		if info.Size() != record.SizeBytes {
			return &manifest, fmt.Errorf("size mismatch for %s: manifest=%d disk=%d",
				record.RelPath, record.SizeBytes, info.Size())
		}
		digest, err := hashFile(target)
		if err != nil {
			return &manifest, fmt.Errorf("hash %s: %w", record.RelPath, err)
		}
		if digest != record.SHA256 {
			return &manifest, fmt.Errorf("digest mismatch for %s", record.RelPath)
		}
		seen[record.RelPath] = true
	}
	extra := []string{}
	walkErr := filepath.WalkDir(snapshotRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(snapshotRoot, path)
		if err != nil {
			return err
		}
		if !seen[rel] {
			extra = append(extra, rel)
		}
		return nil
	})
	if walkErr != nil {
		return &manifest, walkErr
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return &manifest, fmt.Errorf("bundle contains files absent from the manifest: %v", extra)
	}
	return &manifest, nil
}

func copyHashed(rel, src, dst string, info fs.FileInfo) (FileRecord, error) {
	in, err := os.Open(src)
	if err != nil {
		return FileRecord{}, err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return FileRecord{}, err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm())
	if err != nil {
		return FileRecord{}, err
	}
	hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(out, hasher), in); err != nil {
		_ = out.Close()
		return FileRecord{}, err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return FileRecord{}, err
	}
	if err := out.Close(); err != nil {
		return FileRecord{}, err
	}
	return FileRecord{
		RelPath:    filepath.ToSlash(rel),
		Mode:       uint32(info.Mode().Perm()),
		SizeBytes:  info.Size(),
		ModTimeUTC: info.ModTime().UTC(),
		SHA256:     hex.EncodeToString(hasher.Sum(nil)),
	}, nil
}

func writeBundleJSON(path string, value any) error {
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	return os.WriteFile(path, payload, 0o640)
}

func isPathWithin(candidate, base string) bool {
	rel, err := filepath.Rel(base, candidate)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	// Any relative path that does not start with ".." is contained by base.
	return rel != ".." && filepath.IsLocal(rel)
}

func sanitizeLabel(label string) string {
	if label == "" {
		return "bundle"
	}
	cleaned := make([]rune, 0, len(label))
	for _, r := range label {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			cleaned = append(cleaned, r)
		default:
			cleaned = append(cleaned, '-')
		}
	}
	if len(cleaned) == 0 {
		return "bundle"
	}
	return string(cleaned)
}

func bundleError(bundleRoot string, err error) error {
	return fmt.Errorf("preservation into %s failed: %w", bundleRoot, err)
}
