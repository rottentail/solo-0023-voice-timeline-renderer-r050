// Command incidentpreserve is the offline, read-only preservation tool used by
// the on-call runbook. It scans a voice-timeline data directory for render
// state divergence, snapshots the entire data root into an immutable-named
// evidence bundle, and verifies the bundle byte-for-byte.
//
// It deliberately exposes no repair or state-rewriting capability: the only
// mutation it performs is creating new files under the bundle destination.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"voice-timeline-renderer/internal/incident"
)

func main() {
	dataRoot := flag.String("data", "", "voice-timeline data directory to preserve (read-only)")
	bundleParent := flag.String("bundle-parent", "", "directory that will receive a new incident bundle")
	label := flag.String("label", "bundle", "short label embedded in the bundle directory name")
	verifyOnly := flag.String("verify", "", "verify an existing bundle directory and exit")
	scanOnly := flag.Bool("scan-only", false, "print the divergence report without creating a bundle")
	flag.Parse()

	if *verifyOnly != "" {
		manifest, err := incident.VerifyBundle(*verifyOnly)
		if err != nil {
			fmt.Fprintf(os.Stderr, "bundle verification failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("bundle verified: %d files, %d bytes, created_at=%s\n",
			manifest.FileCount, manifest.TotalBytes, manifest.CreatedAtUTC.Format("20060102T150405Z"))
		return
	}

	if *dataRoot == "" {
		fmt.Fprintln(os.Stderr, "missing required -data flag")
		flag.Usage()
		os.Exit(2)
	}

	report, err := incident.Scan(*dataRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
		os.Exit(1)
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode report: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(encoded))

	if *scanOnly {
		if diverging := divergentCount(report); diverging > 0 {
			os.Exit(3)
		}
		return
	}
	if *bundleParent == "" {
		fmt.Fprintln(os.Stderr, "missing required -bundle-parent flag (or use -scan-only)")
		os.Exit(2)
	}

	manifest, bundleRoot, err := incident.PreserveFullCopy(*dataRoot, *bundleParent, *label)
	if err != nil {
		fmt.Fprintf(os.Stderr, "preservation failed: %v\n", err)
		os.Exit(1)
	}
	if err := incident.WriteBundleReport(bundleRoot, report); err != nil {
		fmt.Fprintf(os.Stderr, "write report into bundle: %v\n", err)
		os.Exit(1)
	}
	if _, err := incident.VerifyBundle(bundleRoot); err != nil {
		fmt.Fprintf(os.Stderr, "bundle self-verification failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("preservation complete: bundle=%s files=%d bytes=%d\n",
		bundleRoot, manifest.FileCount, manifest.TotalBytes)

	if diverging := divergentCount(report); diverging > 0 {
		// Non-zero tells the on-call rotation that divergence is present while
		// the evidence has already been preserved successfully.
		fmt.Printf("divergent findings retained for investigation: %d\n", diverging)
		os.Exit(3)
	}
}

func divergentCount(report *incident.Report) int {
	total := 0
	for _, finding := range report.Jobs {
		if finding.Class != incident.ClassConsistent {
			total++
		}
	}
	for _, finding := range report.Staging {
		if finding.Disposition == incident.DispositionRetain {
			total++
		}
	}
	return total
}
