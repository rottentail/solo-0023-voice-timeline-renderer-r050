// Command incidentdrill runs an isolated, end-to-end rehearsal of the render
// state divergence runbook against throwaway data. It never touches a real
// data directory: every fixture lives under a temporary root that is removed
// on exit.
//
// The drill proves, by construction and assertion, that:
//
//  1. the read-only scan fixes every affected render id together with its
//     job record, timeline, receipt, output bytes, staging entries, and the
//     uncertainty each divergence leaves open;
//  2. staging entries are classified by provenance links, never by age;
//  3. an unaffected source and render keep working through the real HTTP
//     surface while divergent reads stay inside explicit response boundaries;
//  4. preservation copies the whole data root and the bundle self-verifies;
//  5. the service path never rewrites a terminal job, and the tooling contains
//     no recovery endpoint.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
)

func main() {
	keep := flag.Bool("keep-root", false, "keep the temporary drill root for manual inspection")
	flag.Parse()

	drill, err := newDrill()
	if err != nil {
		fmt.Fprintf(os.Stderr, "drill setup failed: %v\n", err)
		os.Exit(1)
	}
	defer drill.close(*keep)

	steps := []struct {
		name string
		run  func() error
	}{
		{"seed baseline fixtures", drill.seedBaseline},
		{"construct divergence scenarios", drill.constructScenarios},
		{"scan classifies every fixed object and fact", drill.assertScan},
		{"service boundary stays explicit for affected and unaffected traffic", drill.assertServiceBoundary},
		{"preservation fixes the full data root and self-verifies", drill.assertPreservation},
		{"live traffic cannot rewrite terminal job state", drill.assertNoStateRewrite},
	}

	failed := false
	for index, step := range steps {
		fmt.Printf("[%d/%d] %s ... ", index+1, len(steps), step.name)
		if err := step.run(); err != nil {
			failed = true
			fmt.Println("FAIL")
			fmt.Fprintf(os.Stderr, "  %v\n", err)
			continue
		}
		fmt.Println("ok")
	}
	if failed {
		fmt.Fprintf(os.Stderr, "\nincident drill FAILED; drill root retained at %s\n", drill.root)
		drill.removeOnClose = false
		os.Exit(1)
	}
	fmt.Printf("\nincident drill passed; evidence bundle at %s\n", drill.bundleRoot)
}

// failf builds a step error with a stable prefix so failures point at the
// exact assertion that broke.
func failf(step string, format string, args ...any) error {
	return errors.New(step + ": " + fmt.Sprintf(format, args...))
}
