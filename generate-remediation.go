package main

// generate-remediation — reads snyk-test.json, applies remediation analysis,
// and writes snyk-remediation.json and snyk-remediation.txt.
//
// The analysis logic is a direct Go conversion of the inline Python scripts
// used to produce those files during the initial investigation session.
// A future version will incorporate Snyk Breakability data.
//
// Usage:
//   go run generate-remediation.go
//   go run generate-remediation.go --input=snyk-test.json
//   go run generate-remediation.go --input=snyk-test.json --out-json=out.json --out-txt=out.txt
//   go run generate-remediation.go --help

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// ── Input structures (snyk-test.json) ─────────────────────────────────────────

type SnykOutput struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	DepGraph        DepGraph        `json:"depGraph"`
	ProjectName     string          `json:"projectName"`
	PackageManager  string          `json:"packageManager"`
	TargetFile      string          `json:"targetFile"`
	Summary         string          `json:"summary"`
}

type Vulnerability struct {
	Title       string      `json:"title"`
	Severity    string      `json:"severity"`
	PackageName string      `json:"packageName"`
	Version     string      `json:"version"`
	FixedIn     []string    `json:"fixedIn"`
	Identifiers Identifiers `json:"identifiers"`
}

type Identifiers struct {
	CVE []string `json:"CVE"`
}

type DepGraph struct {
	Pkgs  []DepPkg  `json:"pkgs"`
	Graph GraphData `json:"graph"`
}

type DepPkg struct {
	ID   string      `json:"id"`
	Info DepPkgInfo  `json:"info"`
}

type DepPkgInfo struct {
	Version string `json:"version"`
}

type GraphData struct {
	RootNodeID string      `json:"rootNodeId"`
	Nodes      []GraphNode `json:"nodes"`
}

type GraphNode struct {
	NodeID string   `json:"nodeId"`
	PkgID  string   `json:"pkgId"`
	Deps   []DepRef `json:"deps"`
}

type DepRef struct {
	NodeID string `json:"nodeId"`
}

// ── Output structures (snyk-remediation.json) ─────────────────────────────────

type RemediationReport struct {
	Meta                    ReportMeta  `json:"meta"`
	DependencyTree          TreeNode    `json:"dependencyTree"`
	UpgradeEfficiencyMatrix []MatrixRow `json:"upgradeEfficiencyMatrix"`
	RecommendedGoModDiff    GoModDiff   `json:"recommendedGoModDiff"`
}

type ReportMeta struct {
	GeneratedFrom             string `json:"generatedFrom"`
	ProjectName               string `json:"projectName"`
	PackageManager            string `json:"packageManager"`
	TargetFile                string `json:"targetFile"`
	SnykSummary               string `json:"snykSummary"`
	TotalVulnerabilityRecords int    `json:"totalVulnerabilityRecords"`
	TotalPackages             int    `json:"totalPackages"`
}

type TreeNode struct {
	ID           string       `json:"id"`
	NodeID       string       `json:"nodeId"`
	Pruned       bool         `json:"pruned"`
	Version      string       `json:"version,omitempty"`
	Vulnerable   bool         `json:"vulnerable"`
	Severities   *Severities  `json:"severities,omitempty"`
	CVEs         []CVEEntry   `json:"cves,omitempty"`
	Remediation  *Remediation `json:"remediation,omitempty"`
	Dependencies []TreeNode   `json:"dependencies,omitempty"`
}

type Severities struct {
	High   int `json:"HIGH"`
	Medium int `json:"MEDIUM"`
}

type CVEEntry struct {
	CVE      string `json:"cve"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	FixedIn  string `json:"fixedIn"`
}

type Remediation struct {
	ChangeType       string             `json:"changeType"`
	TargetVersion    string             `json:"targetVersion,omitempty"`
	GoModChange      string             `json:"goModChange"`
	APIRisk          string             `json:"apiRisk"`
	Notes            string             `json:"notes"`
	FixMilestones    []FixMilestone     `json:"fixMilestones"`
	PointAlternative *PointAlt          `json:"pointAlternative,omitempty"`
	Options          map[string]RepOpt  `json:"options,omitempty"`
}

type FixMilestone struct {
	Version   string   `json:"version"`
	CVEsFixed []string `json:"cvesFixed"`
}

type PointAlt struct {
	TargetVersion      string `json:"targetVersion"`
	CVEsFixed          int    `json:"cvesFixed"`
	CVEsRemaining      int    `json:"cvesRemaining"`
	RemainingHighCount int    `json:"remainingHighCount"`
	Verdict            string `json:"verdict"`
}

type RepOpt struct {
	Strategy       string   `json:"strategy"`
	GoModChange    string   `json:"goModChange"`
	CodeChanges    []string `json:"codeChanges"`
	Pro            string   `json:"pro"`
	Con            string   `json:"con"`
	Recommendation bool     `json:"recommendation,omitempty"`
}

type MatrixRow struct {
	Package         string `json:"package"`
	From            string `json:"from"`
	To              string `json:"to"`
	ChangeType      string `json:"changeType"`
	GoModTouches    int    `json:"goModTouches"`
	CodeChanges     int    `json:"codeChanges,omitempty"`
	CVEsClosedTotal int    `json:"cvesClosedTotal"`
	HighClosed      int    `json:"highClosed"`
	MediumClosed    int    `json:"mediumClosed"`
	CVEsRemaining   int    `json:"cvesRemaining"`
	Verdict         string `json:"verdict"`
}

type GoModDiff struct {
	Description string        `json:"description"`
	Changes     []GoModChange `json:"changes"`
}

type GoModChange struct {
	Action             string   `json:"action"`
	Remove             string   `json:"remove,omitempty"`
	Add                string   `json:"add,omitempty"`
	Note               string   `json:"note,omitempty"`
	CodeChangeRequired bool     `json:"codeChangeRequired"`
	Files              []string `json:"files,omitempty"`
}

// ── Known package metadata ─────────────────────────────────────────────────────
// Information that cannot be derived from snyk JSON alone:
//   knownReplacements — abandoned packages that require a full swap
//   knownAutoResolved — transitive deps fixed automatically by a parent upgrade
//   knownModules      — sub-package path → Go module root (for go.mod entries)

type knownReplacement struct {
	goModChange string
	notes       string
	options     map[string]RepOpt
}

// knownAutoResolved maps a vulnerable package to the direct dep whose upgrade
// resolves it automatically (no separate go.mod entry needed).
var knownAutoResolved = map[string]string{
	"github.com/tidwall/match": "github.com/tidwall/gjson",
}

// knownModules maps a Snyk sub-package ID prefix to the actual Go module path.
var knownModules = map[string]string{
	"golang.org/x/net/html":    "golang.org/x/net",
	"golang.org/x/text/":       "golang.org/x/text",
	"golang.org/x/sys/":        "golang.org/x/sys",
	"golang.org/x/crypto/":     "golang.org/x/crypto",
}

// moduleFor returns the Go module path for a given snyk package name.
func moduleFor(pkgName string) string {
	for prefix, mod := range knownModules {
		if pkgName == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(pkgName, prefix) {
			return mod
		}
	}
	return pkgName
}

// goVersion adds the "v" prefix expected by go.mod if not already present.
func goVersion(v string) string {
	v = strings.TrimSuffix(v, "+incompatible")
	if strings.HasPrefix(v, "v") {
		return v
	}
	return "v" + v
}

var knownReplacements = map[string]knownReplacement{
	"github.com/dgrijalva/jwt-go": {
		goModChange: "require github.com/golang-jwt/jwt/v5 v5.2.1",
		notes:       "Package abandoned. fixedIn=4.0.0-preview1 is a dead-end pre-release. No safe upgrade within dgrijalva/jwt-go.",
		options: map[string]RepOpt{
			"optionA_repackage": {
				Strategy:    "go.mod replace directive pointing to local fork",
				GoModChange: "replace github.com/dgrijalva/jwt-go => ./local/jwt-go",
				CodeChanges: []string{"none — import paths unchanged"},
				Pro:         "zero import-path changes in handlers/jwt.go",
				Con:         "team owns ongoing security maintenance of private fork",
			},
			"optionB_swap": {
				Strategy:       "swap to golang-jwt/jwt/v5 (community successor)",
				GoModChange:    "require github.com/golang-jwt/jwt/v5 v5.2.1",
				CodeChanges:    []string{"handlers/jwt.go: update import path", "handlers/jwt.go: ParseWithClaims gains Options arg — minor update"},
				Pro:            "actively maintained; CVE-2020-26160 closed; alg-pinning built-in",
				Con:            "requires code change at import + 1-2 call sites",
				Recommendation: true,
			},
		},
	},
}

// ── Semver helpers ─────────────────────────────────────────────────────────────

type semver struct {
	major, minor, patch int
	raw                 string
}

func parseSemver(v string) (semver, bool) {
	v = strings.TrimPrefix(v, "v")
	v = strings.Split(v, "+")[0] // strip +incompatible
	v = strings.Split(v, "-")[0] // strip pre-release suffix
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return semver{raw: v}, false
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	patch := 0
	var err3 error
	if len(parts) >= 3 {
		patch, err3 = strconv.Atoi(parts[2])
	}
	if err1 != nil || err2 != nil || err3 != nil {
		return semver{raw: v}, false
	}
	return semver{major, minor, patch, v}, true
}

// classifyChange returns POINT, STEP, or REPLACE by comparing semver distance.
func classifyChange(pkgName, currentVer, targetVer string) string {
	if _, isReplacement := knownReplacements[pkgName]; isReplacement {
		return "REPLACE"
	}
	cur, okC := parseSemver(currentVer)
	tgt, okT := parseSemver(targetVer)
	if !okC || !okT {
		return "STEP"
	}
	if cur.major != tgt.major {
		return "REPLACE"
	}
	if cur.minor != tgt.minor {
		return "STEP"
	}
	return "POINT"
}

func apiRiskFor(changeType string) string {
	switch changeType {
	case "POINT":
		return "none"
	case "STEP":
		return "low"
	default:
		return "medium"
	}
}

// ── CVE aggregation ────────────────────────────────────────────────────────────

type cveKey struct{ cve, fixedIn string }

// buildPkgCVEMap returns pkgID → deduplicated []CVEEntry.
func buildPkgCVEMap(vulns []Vulnerability) map[string][]CVEEntry {
	seen := map[string]map[cveKey]bool{}
	result := map[string][]CVEEntry{}

	for _, v := range vulns {
		pkgID := v.PackageName + "@" + v.Version
		fixed := ""
		if len(v.FixedIn) > 0 {
			fixed = v.FixedIn[0]
		}
		for _, cve := range v.Identifiers.CVE {
			k := cveKey{cve, fixed}
			if seen[pkgID] == nil {
				seen[pkgID] = map[cveKey]bool{}
			}
			if !seen[pkgID][k] {
				seen[pkgID][k] = true
				result[pkgID] = append(result[pkgID], CVEEntry{
					CVE:      cve,
					Severity: v.Severity,
					Title:    v.Title,
					FixedIn:  fixed,
				})
			}
		}
	}
	return result
}

// ── Remediation computation ────────────────────────────────────────────────────

// buildMilestones groups CVEs by their fixedIn version and sorts chronologically.
func buildMilestones(cves []CVEEntry) []FixMilestone {
	byVer := map[string][]string{}
	for _, c := range cves {
		if c.FixedIn != "" {
			byVer[c.FixedIn] = append(byVer[c.FixedIn], c.CVE)
		}
	}
	vers := make([]string, 0, len(byVer))
	for v := range byVer {
		vers = append(vers, v)
	}
	sort.Slice(vers, func(i, j int) bool {
		a, okA := parseSemver(vers[i])
		b, okB := parseSemver(vers[j])
		if !okA || !okB {
			return vers[i] < vers[j]
		}
		if a.major != b.major {
			return a.major < b.major
		}
		if a.minor != b.minor {
			return a.minor < b.minor
		}
		return a.patch < b.patch
	})
	out := make([]FixMilestone, 0, len(vers))
	for _, v := range vers {
		out = append(out, FixMilestone{Version: v, CVEsFixed: byVer[v]})
	}
	return out
}

// maxFixedIn returns the version that closes all CVEs (last milestone).
func maxFixedIn(milestones []FixMilestone) string {
	if len(milestones) == 0 {
		return ""
	}
	return milestones[len(milestones)-1].Version
}

// pointAlternative finds the earliest version that closes all HIGHs (if it
// doesn't also close all CVEs), to illustrate the cost of stopping short.
func pointAlternative(cves []CVEEntry, milestones []FixMilestone, targetVer string) *PointAlt {
	totalHigh := 0
	for _, c := range cves {
		if c.Severity == "high" {
			totalHigh++
		}
	}
	// Walk milestones accumulating fixed CVEs; find first version that closes
	// all HIGHs but not all CVEs.
	fixedHigh := 0
	fixedTotal := 0
	for _, ms := range milestones {
		for _, cve := range ms.CVEsFixed {
			fixedTotal++
			for _, orig := range cves {
				if orig.CVE == cve && orig.Severity == "high" {
					fixedHigh++
				}
			}
		}
		if fixedHigh >= totalHigh && fixedTotal < len(cves) && ms.Version != targetVer {
			remaining := len(cves) - fixedTotal
			remainHigh := 0 // all highs are fixed at this point
			_ = remainHigh
			return &PointAlt{
				TargetVersion:      ms.Version,
				CVEsFixed:          fixedTotal,
				CVEsRemaining:      remaining,
				RemainingHighCount: 0,
				Verdict:            fmt.Sprintf("insufficient — %d MED%s from later releases remain open", remaining, plural(remaining)),
			}
		}
		// Also catch the case where point stops short and leaves HIGHs open.
		if ms.Version != targetVer && fixedTotal < len(cves) && fixedHigh < totalHigh {
			remaining := len(cves) - fixedTotal
			remainHigh := totalHigh - fixedHigh
			return &PointAlt{
				TargetVersion:      ms.Version,
				CVEsFixed:          fixedTotal,
				CVEsRemaining:      remaining,
				RemainingHighCount: remainHigh,
				Verdict:            fmt.Sprintf("insufficient — %d HIGH CVE%s remain", remainHigh, plural(remainHigh)),
			}
		}
	}
	return nil
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// computeRemediation builds the full Remediation struct for a vulnerable package.
func computeRemediation(pkgName, currentVer string, cves []CVEEntry, isDirect bool) *Remediation {
	milestones := buildMilestones(cves)
	targetVer := maxFixedIn(milestones)

	// Special case: known replacements override everything
	if repl, ok := knownReplacements[pkgName]; ok {
		return &Remediation{
			ChangeType:    "REPLACE",
			TargetVersion: "",
			GoModChange:   repl.goModChange,
			APIRisk:       "medium",
			Notes:         repl.notes,
			FixMilestones: milestones,
			Options:       repl.options,
		}
	}

	// Normalise package path to Go module root and apply v-prefix to version.
	modPath := moduleFor(pkgName)
	targetVerStr := goVersion(targetVer)

	changeType := classifyChange(pkgName, currentVer, targetVer)
	pa := pointAlternative(cves, milestones, targetVer)

	// Auto-resolved transitive deps don't need a separate go.mod entry.
	if resolver, isAutoResolved := knownAutoResolved[pkgName]; isAutoResolved {
		return &Remediation{
			ChangeType:       changeType,
			TargetVersion:    targetVer,
			GoModChange:      fmt.Sprintf("// auto-resolved — upgrading %s pulls a fixed %s", resolver, modPath),
			APIRisk:          "none",
			Notes:            fmt.Sprintf("Resolved automatically by upgrading %s. No separate go.mod entry required.", resolver),
			FixMilestones:    milestones,
			PointAlternative: pa,
		}
	}

	goModLine := fmt.Sprintf("require %s %s", modPath, targetVerStr)
	notes := ""
	if !isDirect {
		goModLine += "  // override transitive dep"
		notes = fmt.Sprintf("Indirect dep. go.mod override is valid if upstream pins no upper bound on %s.", modPath)
	}

	return &Remediation{
		ChangeType:       changeType,
		TargetVersion:    targetVer,
		GoModChange:      goModLine,
		APIRisk:          apiRiskFor(changeType),
		Notes:            notes,
		FixMilestones:    milestones,
		PointAlternative: pa,
	}
}

// ── Tree building ──────────────────────────────────────────────────────────────

func buildTree(
	nodeID string,
	nodes map[string][]string,  // nodeID → child nodeIDs
	nodeToPackage map[string]string, // nodeID → pkgID
	cveMap map[string][]CVEEntry,
	remMap map[string]*Remediation,
) TreeNode {
	pruned := strings.HasSuffix(nodeID, ":pruned")
	baseID := strings.TrimSuffix(nodeID, ":pruned")
	pkgID := nodeToPackage[baseID]
	if pkgID == "" {
		pkgID = baseID
	}

	ver := ""
	if idx := strings.LastIndex(pkgID, "@"); idx >= 0 {
		ver = pkgID[idx+1:]
	}

	cves := cveMap[pkgID]
	vuln := len(cves) > 0

	node := TreeNode{
		ID:         pkgID,
		NodeID:     nodeID,
		Pruned:     pruned,
		Version:    ver,
		Vulnerable: vuln,
	}

	if vuln {
		high, med := 0, 0
		for _, c := range cves {
			if c.Severity == "high" {
				high++
			} else {
				med++
			}
		}
		node.Severities = &Severities{High: high, Medium: med}
		node.CVEs = cves
		node.Remediation = remMap[pkgID]
	}

	if !pruned {
		for _, childID := range nodes[nodeID] {
			node.Dependencies = append(node.Dependencies, buildTree(childID, nodes, nodeToPackage, cveMap, remMap))
		}
	}
	return node
}

// ── Matrix building ────────────────────────────────────────────────────────────

func countSevs(cves []CVEEntry) (high, med int) {
	for _, c := range cves {
		if c.Severity == "high" {
			high++
		} else {
			med++
		}
	}
	return
}

func buildMatrix(tree TreeNode, cveMap map[string][]CVEEntry, remMap map[string]*Remediation, directPkgs map[string]bool) []MatrixRow {
	// Collect unique vulnerable pkg IDs, preserving tree order
	seen := map[string]bool{}
	var order []string
	var walk func(TreeNode)
	walk = func(n TreeNode) {
		if n.Vulnerable && !seen[n.ID] {
			seen[n.ID] = true
			order = append(order, n.ID)
		}
		for _, c := range n.Dependencies {
			walk(c)
		}
	}
	walk(tree)

	icons := map[string]string{"POINT": "⚡", "STEP": "⬆", "REPLACE": "⇄"}
	var rows []MatrixRow

	for _, pkgID := range order {
		cves := cveMap[pkgID]
		rem := remMap[pkgID]
		if rem == nil {
			continue
		}

		h, m := countSevs(cves)
		total := len(cves)
		currentVer := ""
		if idx := strings.LastIndex(pkgID, "@"); idx >= 0 {
			currentVer = pkgID[idx+1:]
		}
		pkg := pkgID
		if idx := strings.LastIndex(pkgID, "@"); idx >= 0 {
			pkg = pkgID[:idx]
		}

		ct := rem.ChangeType
		icon := icons[ct]

		// Point-alternative row (if exists)
		if pa := rem.PointAlternative; pa != nil {
			paH, paM := 0, 0
			fixedByPA := map[string]bool{}
			for _, ms := range rem.FixMilestones {
				sv, ok := parseSemver(ms.Version)
				paTarget, _ := parseSemver(pa.TargetVersion)
				if ok {
					if sv.major < paTarget.major ||
						(sv.major == paTarget.major && sv.minor < paTarget.minor) ||
						(sv.major == paTarget.major && sv.minor == paTarget.minor && sv.patch <= paTarget.patch) {
						for _, cve := range ms.CVEsFixed {
							fixedByPA[cve] = true
						}
					}
				}
			}
			for _, c := range cves {
				if fixedByPA[c.CVE] {
					if c.Severity == "high" {
						paH++
					} else {
						paM++
					}
				}
			}
			remain := total - pa.CVEsFixed
			rows = append(rows, MatrixRow{
				Package:         pkg,
				From:            currentVer,
				To:              pa.TargetVersion,
				ChangeType:      "POINT",
				GoModTouches:    1,
				CVEsClosedTotal: pa.CVEsFixed,
				HighClosed:      paH,
				MediumClosed:    paM,
				CVEsRemaining:   remain,
				Verdict:         fmt.Sprintf("insufficient — %d %s remain, requires second touch later", remain, verdictLabel(pa)),
			})
			_ = icon
		}

		// Optimal row
		targetTo := rem.TargetVersion
		if ct == "REPLACE" {
			// Extract the replacement version from the go.mod change
			parts := strings.Fields(rem.GoModChange)
			if len(parts) >= 3 {
				targetTo = parts[len(parts)-1]
			}
		}
		codeChanges := 0
		if ct == "REPLACE" {
			codeChanges = 1
		}
		rows = append(rows, MatrixRow{
			Package:         pkg,
			From:            currentVer,
			To:              targetTo,
			ChangeType:      ct,
			GoModTouches:    1,
			CodeChanges:     codeChanges,
			CVEsClosedTotal: total,
			HighClosed:      h,
			MediumClosed:    m,
			CVEsRemaining:   0,
			Verdict:         "optimal",
		})
	}
	return rows
}

func verdictLabel(pa *PointAlt) string {
	if pa.RemainingHighCount > 0 {
		return fmt.Sprintf("%d HIGH CVEs", pa.RemainingHighCount)
	}
	return "MEDs"
}

// ── go.mod diff ────────────────────────────────────────────────────────────────

func buildGoModDiff(cveMap map[string][]CVEEntry, remMap map[string]*Remediation, directPkgs map[string]bool) GoModDiff {
	// Order: REPLACE first, then UPGRADE by pkg name, then ADD OVERRIDE for transitive
	type diffEntry struct {
		pkgID  string
		action string
		rem    *Remediation
	}

	var replaces, upgrades, overrides []diffEntry

	for pkgID, rem := range remMap {
		pkgName := pkgID
		if idx := strings.LastIndex(pkgID, "@"); idx >= 0 {
			pkgName = pkgID[:idx]
		}
		// Skip transitive deps that are resolved automatically by a parent upgrade.
		if _, isAutoResolved := knownAutoResolved[pkgName]; isAutoResolved {
			continue
		}
		if rem.ChangeType == "REPLACE" {
			replaces = append(replaces, diffEntry{pkgID, "replace", rem})
		} else if directPkgs[pkgID] {
			upgrades = append(upgrades, diffEntry{pkgID, "upgrade", rem})
		} else {
			overrides = append(overrides, diffEntry{pkgID, "add_override", rem})
		}
	}

	sort.Slice(replaces, func(i, j int) bool { return replaces[i].pkgID < replaces[j].pkgID })
	sort.Slice(upgrades, func(i, j int) bool { return upgrades[i].pkgID < upgrades[j].pkgID })
	sort.Slice(overrides, func(i, j int) bool { return overrides[i].pkgID < overrides[j].pkgID })

	all := append(append(replaces, upgrades...), overrides...)
	changes := make([]GoModChange, 0, len(all))

	for _, e := range all {
		currentVer := ""
		pkgName := e.pkgID
		if idx := strings.LastIndex(e.pkgID, "@"); idx >= 0 {
			pkgName = e.pkgID[:idx]
			currentVer = e.pkgID[idx+1:]
		}

		switch e.action {
		case "replace":
			changes = append(changes, GoModChange{
				Action:             "replace",
				Remove:             pkgName + " " + goVersion(currentVer),
				Add:                strings.TrimPrefix(e.rem.GoModChange, "require "),
				CodeChangeRequired: true,
				Files:              []string{"handlers/jwt.go"},
			})
		case "upgrade":
			changes = append(changes, GoModChange{
				Action: "upgrade",
				Remove: pkgName + " " + goVersion(currentVer),
				Add:    e.rem.GoModChange,
			})
		case "add_override":
			note := "override transitive dep"
			if e.rem.Notes != "" {
				note = e.rem.Notes
			}
			changes = append(changes, GoModChange{
				Action: "add_override",
				Add:    e.rem.GoModChange,
				Note:   note,
			})
		}
	}

	return GoModDiff{
		Description: "Minimal go.mod changes to close all vulnerability records",
		Changes:     changes,
	}
}

// ── txt rendering ──────────────────────────────────────────────────────────────

const (
	bannerWidth = 80
	colPkg      = 36
	colType     = 10
	colFrom     = 8
	colTo       = 26
	colClosed   = 7
	colRemain   = 7
)

func renderTxt(r RemediationReport) string {
	var sb strings.Builder

	// Banner
	sb.WriteString(strings.Repeat("=", bannerWidth) + "\n")
	sb.WriteString(fmt.Sprintf("  SNYK REMEDIATION REPORT — %s\n", r.Meta.ProjectName))
	sb.WriteString(fmt.Sprintf("  %s · %s\n", r.Meta.PackageManager, r.Meta.TargetFile))
	sb.WriteString(fmt.Sprintf("  %s\n", r.Meta.SnykSummary))
	sb.WriteString(fmt.Sprintf("  %d vulnerability records · %d packages\n",
		r.Meta.TotalVulnerabilityRecords, r.Meta.TotalPackages))
	sb.WriteString(strings.Repeat("=", bannerWidth) + "\n\n")

	// Dependency tree
	sb.WriteString("DEPENDENCY TREE\n")
	sb.WriteString(strings.Repeat("-", bannerWidth) + "\n\n")
	sb.WriteString("  Legend:  [H] HIGH   [M] MEDIUM   ✓ clean   ⚡ POINT   ⬆ STEP   ⇄ REPLACE\n")
	sb.WriteString("           H×n / M×n = vulnerability count   →  = target fix version\n\n")
	renderNode(&sb, r.DependencyTree, "", true, 0)
	sb.WriteString("\n")

	// Matrix
	sb.WriteString("\nUPGRADE EFFICIENCY MATRIX\n")
	sb.WriteString(strings.Repeat("-", bannerWidth) + "\n\n")
	hdr := fmt.Sprintf("  %-*s %-*s %-*s %-*s %*s %*s  Verdict",
		colPkg, "Package", colType, "Type", colFrom, "From", colTo, "To",
		colClosed, "Closed", colRemain, "Remain")
	sb.WriteString(hdr + "\n")
	sb.WriteString(fmt.Sprintf("  %s %s %s %s %s %s  %s\n",
		strings.Repeat("-", colPkg), strings.Repeat("-", colType),
		strings.Repeat("-", colFrom), strings.Repeat("-", colTo),
		strings.Repeat("-", colClosed), strings.Repeat("-", colRemain),
		strings.Repeat("-", 30)))

	icons := map[string]string{"POINT": "⚡", "STEP": "⬆", "REPLACE": "⇄"}
	for _, row := range r.UpgradeEfficiencyMatrix {
		shortPkg := shortName(row.Package)
		ct := icons[row.ChangeType] + " " + row.ChangeType
		closed := fmt.Sprintf("H×%d M×%d", row.HighClosed, row.MediumClosed)
		remain := strconv.Itoa(row.CVEsRemaining)
		verdict := "✓ optimal"
		if row.Verdict != "optimal" {
			verdict = "⚠ " + strings.SplitN(row.Verdict, "—", 2)[0]
		}
		sb.WriteString(fmt.Sprintf("  %-*s %-*s %-*s %-*s %*s %*s  %s\n",
			colPkg, shortPkg, colType, ct, colFrom, row.From, colTo, row.To,
			colClosed, closed, colRemain, remain, verdict))
	}
	sb.WriteString("\n")

	// go.mod diff
	sb.WriteString("\nRECOMMENDED go.mod CHANGES  (closes all vulnerability records)\n")
	sb.WriteString(strings.Repeat("-", bannerWidth) + "\n\n")
	for _, c := range r.RecommendedGoModDiff.Changes {
		sb.WriteString(fmt.Sprintf("  [%s]\n", strings.ToUpper(strings.ReplaceAll(c.Action, "_", " "))))
		if c.Remove != "" {
			sb.WriteString(fmt.Sprintf("    - %s\n", c.Remove))
		}
		if c.Add != "" {
			sb.WriteString(fmt.Sprintf("    + %s\n", c.Add))
		}
		if c.Note != "" {
			sb.WriteString(fmt.Sprintf("      // %s\n", c.Note))
		}
		if c.CodeChangeRequired {
			sb.WriteString(fmt.Sprintf("      // ⚠  code change required: %s\n", strings.Join(c.Files, ", ")))
		}
		sb.WriteString("\n")
	}
	sb.WriteString(strings.Repeat("=", bannerWidth) + "\n")

	return sb.String()
}

func renderNode(sb *strings.Builder, node TreeNode, prefix string, isLast bool, depth int) {
	connector, childPrefix := "", ""
	if depth > 0 {
		if isLast {
			connector, childPrefix = "└── ", prefix+"    "
		} else {
			connector, childPrefix = "├── ", prefix+"│   "
		}
	}

	name := node.ID
	if idx := strings.LastIndex(node.ID, "@"); idx >= 0 {
		name = node.ID[:idx] + "@" + node.ID[idx+1:]
	}

	line := prefix + connector + name

	if node.Vulnerable {
		if s := node.Severities; s != nil {
			if s.High > 0 {
				line += fmt.Sprintf("  H×%d", s.High)
			}
			if s.Medium > 0 {
				line += fmt.Sprintf(" M×%d", s.Medium)
			}
		}
		if rem := node.Remediation; rem != nil {
			iconMap := map[string]string{"POINT": "⚡", "STEP": "⬆", "REPLACE": "⇄"}
			if icon, ok := iconMap[rem.ChangeType]; ok {
				line += "  " + icon + " " + rem.ChangeType
			}
			if rem.TargetVersion != "" {
				line += "  →  " + rem.TargetVersion
			} else if rem.ChangeType == "REPLACE" {
				line += "  →  REPLACE"
			}
		}
	} else if !node.Pruned {
		line += "  ✓"
	}

	if node.Pruned {
		line += "  [pruned]"
	}
	sb.WriteString(line + "\n")

	if node.Pruned {
		return
	}

	inner := childPrefix + "│  "

	if node.Vulnerable && node.Remediation != nil {
		rem := node.Remediation

		for _, c := range node.CVEs {
			tag := "[M]"
			if c.Severity == "high" {
				tag = "[H]"
			}
			sb.WriteString(fmt.Sprintf("%s%s %-22s  fixedIn: %-18s %s\n",
				inner, tag, c.CVE, c.FixedIn, c.Title))
		}

		if len(rem.FixMilestones) > 0 {
			sb.WriteString(inner + "\n")
			sb.WriteString(inner + "  Fix milestones:\n")
			for _, ms := range rem.FixMilestones {
				marker := ""
				if ms.Version == rem.TargetVersion {
					marker = " ◀ TARGET"
				}
				sb.WriteString(fmt.Sprintf("%s    ▶ %-22s %s%s\n",
					inner, ms.Version, strings.Join(ms.CVEsFixed, ", "), marker))
			}
		}

		if pa := rem.PointAlternative; pa != nil {
			sb.WriteString(inner + "\n")
			sb.WriteString(fmt.Sprintf("%s  ⚠ Point alt %s: %d/%d CVEs — %s\n",
				inner, pa.TargetVersion, pa.CVEsFixed, pa.CVEsFixed+pa.CVEsRemaining, pa.Verdict))
		}

		if rem.GoModChange != "" {
			sb.WriteString(inner + "\n")
			sb.WriteString(fmt.Sprintf("%s  go.mod: %s\n", inner, rem.GoModChange))
		}

		if len(rem.Options) > 0 {
			sb.WriteString(inner + "\n")
			sb.WriteString(inner + "  Options:\n")
			for _, key := range []string{"optionA_repackage", "optionB_swap"} {
				opt, ok := rem.Options[key]
				if !ok {
					continue
				}
				rec := ""
				if opt.Recommendation {
					rec = "  ★ RECOMMENDED"
				}
				label := strings.ToUpper(strings.ReplaceAll(key, "_", " "))
				sb.WriteString(fmt.Sprintf("%s    %s%s\n", inner, label, rec))
				sb.WriteString(fmt.Sprintf("%s      + %s\n", inner, opt.Pro))
				sb.WriteString(fmt.Sprintf("%s      - %s\n", inner, opt.Con))
			}
		}

		sb.WriteString(inner + "\n")
	}

	for i, child := range node.Dependencies {
		renderNode(sb, child, childPrefix, i == len(node.Dependencies)-1, depth+1)
	}
}

func shortName(pkgID string) string {
	// Remove @version suffix first
	if idx := strings.LastIndex(pkgID, "@"); idx >= 0 {
		pkgID = pkgID[:idx]
	}
	// Return last path segment
	parts := strings.Split(pkgID, "/")
	return parts[len(parts)-1]
}

// ── Analysis entry point ───────────────────────────────────────────────────────

func analyze(snyk SnykOutput, inputFile string) RemediationReport {
	// Build nodeID → pkgID lookup
	nodeToPackage := map[string]string{"root-node": "weak-go-app@0.0.0"}
	for _, p := range snyk.DepGraph.Pkgs {
		name := p.ID
		if idx := strings.LastIndex(p.ID, "@"); idx >= 0 {
			name = p.ID[:idx]
		}
		nodeToPackage[name] = p.ID
	}

	// Build nodeID → child nodeIDs
	nodeChildren := map[string][]string{}
	for _, n := range snyk.DepGraph.Graph.Nodes {
		for _, d := range n.Deps {
			nodeChildren[n.NodeID] = append(nodeChildren[n.NodeID], d.NodeID)
		}
	}

	// Direct dependencies of root
	directPkgs := map[string]bool{}
	for _, childID := range nodeChildren["root-node"] {
		base := strings.TrimSuffix(childID, ":pruned")
		if pkgID := nodeToPackage[base]; pkgID != "" {
			directPkgs[pkgID] = true
		}
	}

	cveMap := buildPkgCVEMap(snyk.Vulnerabilities)

	// Compute remediation for each vulnerable package
	remMap := map[string]*Remediation{}
	for pkgID, cves := range cveMap {
		pkgName := pkgID
		currentVer := ""
		if idx := strings.LastIndex(pkgID, "@"); idx >= 0 {
			pkgName = pkgID[:idx]
			currentVer = pkgID[idx+1:]
		}
		remMap[pkgID] = computeRemediation(pkgName, currentVer, cves, directPkgs[pkgID])
	}

	tree := buildTree(snyk.DepGraph.Graph.RootNodeID, nodeChildren, nodeToPackage, cveMap, remMap)
	matrix := buildMatrix(tree, cveMap, remMap, directPkgs)
	diff := buildGoModDiff(cveMap, remMap, directPkgs)

	return RemediationReport{
		Meta: ReportMeta{
			GeneratedFrom:             inputFile,
			ProjectName:               snyk.ProjectName,
			PackageManager:            snyk.PackageManager,
			TargetFile:                snyk.TargetFile,
			SnykSummary:               snyk.Summary,
			TotalVulnerabilityRecords: len(snyk.Vulnerabilities),
			TotalPackages:             len(snyk.DepGraph.Pkgs),
		},
		DependencyTree:          tree,
		UpgradeEfficiencyMatrix: matrix,
		RecommendedGoModDiff:    diff,
	}
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	inputFlag  := flag.String("input",    "snyk-test.json",       "path to snyk test JSON output")
	outJSON    := flag.String("out-json", "snyk-remediation.json", "path for remediation JSON output")
	outTxt     := flag.String("out-txt",  "snyk-remediation.txt",  "path for remediation txt output")

	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, `generate-remediation — converts snyk test JSON output into a remediation report.

Reads snyk-test.json (produced by: snyk test --print-deps --json --show-vulnerable-paths=all)
and writes snyk-remediation.json and snyk-remediation.txt.

The analysis applies:
  - Per-CVE fix cascade (fixedIn milestones from Snyk data)
  - Automatic POINT / STEP / REPLACE classification via semver comparison
  - Point-alternative warnings (cost of stopping at the lowest fixedIn)
  - Hardcoded entries for known abandoned packages (e.g. dgrijalva/jwt-go)

A future version will incorporate Snyk Breakability data.

USAGE
  go run generate-remediation.go [OPTIONS]
  ./generate-remediation         [OPTIONS]

OPTIONS
  --input=FILE     Path to snyk test JSON  (default: snyk-test.json)
  --out-json=FILE  Path for remediation JSON output (default: snyk-remediation.json)
  --out-txt=FILE   Path for remediation txt output  (default: snyk-remediation.txt)
  --help           Show this message and exit.

EXAMPLES
  go run generate-remediation.go
  go run generate-remediation.go --input=my-scan.json
  go run generate-remediation.go --out-json=report.json --out-txt=report.txt

PIPELINE
  snyk test --print-deps --json --show-vulnerable-paths=all > snyk-test.json
  go run generate-remediation.go
  go run expand-dep-tree.go | less -R`)
	}
	flag.Parse()

	// Read input
	raw, err := os.ReadFile(*inputFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error reading input:", err)
		os.Exit(1)
	}

	var snyk SnykOutput
	if err := json.Unmarshal(raw, &snyk); err != nil {
		fmt.Fprintln(os.Stderr, "error parsing JSON:", err)
		os.Exit(1)
	}

	report := analyze(snyk, *inputFlag)

	// Write JSON
	jsonBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error marshalling JSON:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*outJSON, jsonBytes, 0644); err != nil {
		fmt.Fprintln(os.Stderr, "error writing JSON:", err)
		os.Exit(1)
	}

	// Write txt
	txt := renderTxt(report)
	if err := os.WriteFile(*outTxt, []byte(txt), 0644); err != nil {
		fmt.Fprintln(os.Stderr, "error writing txt:", err)
		os.Exit(1)
	}

	fmt.Printf("%-20s %s\n", *outJSON, fmt.Sprintf("(%d bytes)", len(jsonBytes)))
	fmt.Printf("%-20s %s\n", *outTxt, fmt.Sprintf("(%d bytes)", len(txt)))
	fmt.Printf("Packages: %d  Vulnerability records: %d  Matrix rows: %d  go.mod changes: %d\n",
		report.Meta.TotalPackages,
		report.Meta.TotalVulnerabilityRecords,
		len(report.UpgradeEfficiencyMatrix),
		len(report.RecommendedGoModDiff.Changes))
}
