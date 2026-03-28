package main

// expand-dep-tree — ANSI true-color renderer for snyk-remediation .txt files.
//
// Usage:
//   go run expand-dep-tree.go                        # reads snyk-remediation.txt in cwd
//   go run expand-dep-tree.go report.txt             # positional path
//   go run expand-dep-tree.go --input=report.txt     # explicit flag
//   cat report.txt | go run expand-dep-tree.go -     # stdin
//   go run expand-dep-tree.go | less -R              # pipe to pager

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"
)

// ── ANSI helpers ──────────────────────────────────────────────────────────────

const (
	ansiReset = "\033[0m"
	ansiBold  = "\033[1m"
)

func fg(r, g, b int) string { return fmt.Sprintf("\033[38;2;%d;%d;%dm", r, g, b) }
func bg(r, g, b int) string { return fmt.Sprintf("\033[48;2;%d;%d;%dm", r, g, b) }

// ── Palette ───────────────────────────────────────────────────────────────────

var (
	cText    = fg(226, 232, 240)
	cMuted   = fg(100, 116, 139)
	cBorder  = fg(46, 51, 80)
	cHigh    = fg(239, 68, 68)
	cMed     = fg(245, 158, 11)
	cClean   = fg(34, 197, 94)
	cInfo    = fg(56, 189, 248)
	cPurple  = fg(123, 69, 231)
	cReplace = fg(167, 139, 250)
	cStep    = fg(251, 146, 60)
	cPoint   = fg(52, 211, 153)

	bgSurface  = bg(26, 29, 39)
	bgSurface2 = bg(34, 38, 58)
	bgHighBg   = bg(45, 21, 21)
	bgCleanBg  = bg(13, 40, 24)
)

// ── Pre-compiled regexps ──────────────────────────────────────────────────────

var (
	reBoxDraw    = regexp.MustCompile(`[│├└─]+`)
	reHighTag    = regexp.MustCompile(`\[H\]`)
	reMedTag     = regexp.MustCompile(`\[M\]`)
	reCVE        = regexp.MustCompile(`CVE-\d{4}-\d+`)
	reHighCount  = regexp.MustCompile(`H×\d+`)
	reMedCount   = regexp.MustCompile(`M×\d+`)
	reFixedIn    = regexp.MustCompile(`fixedIn:\s*`)
	reNonSpace   = regexp.MustCompile(`\S+`)
	reTarget     = regexp.MustCompile(`◀ TARGET`)
	reWarn       = regexp.MustCompile(`⚠[^\n]*`)
	reStar       = regexp.MustCompile(`★ RECOMMENDED`)
	rePointBadge = regexp.MustCompile(`⚡ POINT`)
	reStepBadge  = regexp.MustCompile(`⬆ STEP`)
	reRepBadge   = regexp.MustCompile(`⇄ REPLACE`)
	reCheck      = regexp.MustCompile(`✓(\s*(optimal|clean))?`)
	reArrow      = regexp.MustCompile(`→\s+\S+`)
	reAtVer      = regexp.MustCompile(`@[\w.#-]+`)
	rePruned     = regexp.MustCompile(`\[pruned\]`)
	reGoMod      = regexp.MustCompile(`go\.mod:\s*`)
	reMilestone  = regexp.MustCompile(`▶\s+(\S+)`)
	reOptPlus    = regexp.MustCompile(`\+\s`)
	reOptMinus   = regexp.MustCompile(`-\s`)
	reComment    = regexp.MustCompile(`//[^\n]*`)
	rePipeOnly   = regexp.MustCompile(`^[│\s]+$`)
	reDiffLine   = regexp.MustCompile(`^(\s+)([-+])\s`)

	// classify helpers
	clBannerRule  = regexp.MustCompile(`^={10,}$`)
	clSectionRule = regexp.MustCompile(`^-{10,}$`)
	clBannerMeta  = regexp.MustCompile(`^\s+\d+ `)
	clMatrixHdr   = regexp.MustCompile(`\s+Package\s+Type\s+From\s`)
	clMatrixRule  = regexp.MustCompile(`\s+-{3,}\s+-{3,}`)
	clMatrixRow   = regexp.MustCompile(`\s+(yaml\.v2|gjson|net\s|jwt-go)\s`)
	clDiffAction  = regexp.MustCompile(`\s+\[(REPLACE|UPGRADE|ADD OVERRIDE)\]`)
)

// ── Segment ───────────────────────────────────────────────────────────────────

type segment struct {
	text string
	fg   string
	bg   string
	bold bool
}

func (s segment) emit() string {
	out := s.bg + s.fg
	if s.bold {
		out += ansiBold
	}
	return out + s.text + ansiReset
}

// ── Colorizer ─────────────────────────────────────────────────────────────────

// colorize applies ANSI color rules to a single line and returns segments.
func colorize(line string) []segment {
	n := len(line)
	if n == 0 {
		return nil
	}

	fgs   := make([]string, n)
	bgs   := make([]string, n)
	bolds := make([]bool, n)
	for i := range fgs {
		fgs[i] = cText
	}

	paint := func(start, end int, fg, background string, bold bool) {
		for i := start; i < end && i < n; i++ {
			if fg != ""         { fgs[i] = fg }
			if background != "" { bgs[i] = background }
			if bold             { bolds[i] = true }
		}
	}

	// Tree box-drawing characters
	for _, m := range reBoxDraw.FindAllStringIndex(line, -1) {
		paint(m[0], m[1], cBorder, "", false)
	}

	// [H] / [M] severity tags
	for _, m := range reHighTag.FindAllStringIndex(line, -1) {
		paint(m[0], m[1], cHigh, "", true)
	}
	for _, m := range reMedTag.FindAllStringIndex(line, -1) {
		paint(m[0], m[1], cMed, "", true)
	}

	// CVE IDs — colour by nearest [H]/[M] tag to the left
	for _, m := range reCVE.FindAllStringIndex(line, -1) {
		c := cMed
		if strings.Contains(line[:m[0]], "[H]") {
			c = cHigh
		}
		paint(m[0], m[1], c, "", true)
	}

	// H×n / M×n counts
	for _, m := range reHighCount.FindAllStringIndex(line, -1) {
		paint(m[0], m[1], cHigh, "", true)
	}
	for _, m := range reMedCount.FindAllStringIndex(line, -1) {
		paint(m[0], m[1], cMed, "", true)
	}

	// fixedIn: <value>
	for _, m := range reFixedIn.FindAllStringIndex(line, -1) {
		paint(m[0], m[1], cMuted, "", false)
		if vm := reNonSpace.FindStringIndex(line[m[1]:]); vm != nil {
			paint(m[1]+vm[0], m[1]+vm[1], cClean, "", true)
		}
	}

	// ◀ TARGET
	for _, m := range reTarget.FindAllStringIndex(line, -1) {
		paint(m[0], m[1], cClean, "", true)
	}

	// ⚠ warning (colours rest of token)
	for _, m := range reWarn.FindAllStringIndex(line, -1) {
		paint(m[0], m[1], cMed, "", false)
		paint(m[0], m[0]+len("⚠"), cMed, "", true)
	}

	// ★ RECOMMENDED
	for _, m := range reStar.FindAllStringIndex(line, -1) {
		paint(m[0], m[1], cPurple, "", true)
	}

	// Change-type badges
	for _, m := range rePointBadge.FindAllStringIndex(line, -1) {
		paint(m[0], m[1], cPoint, "", true)
	}
	for _, m := range reStepBadge.FindAllStringIndex(line, -1) {
		paint(m[0], m[1], cStep, "", true)
	}
	for _, m := range reRepBadge.FindAllStringIndex(line, -1) {
		paint(m[0], m[1], cReplace, "", true)
	}

	// ✓ clean / optimal
	for _, m := range reCheck.FindAllStringIndex(line, -1) {
		paint(m[0], m[1], cClean, "", true)
	}

	// → <version>
	arrowLen := len("→")
	for _, m := range reArrow.FindAllStringIndex(line, -1) {
		paint(m[0], m[0]+arrowLen, cMuted, "", false)
		paint(m[0]+arrowLen, m[1], cClean, "", true)
	}

	// @version strings
	for _, m := range reAtVer.FindAllStringIndex(line, -1) {
		paint(m[0], m[1], cMuted, "", false)
	}

	// [pruned]
	for _, m := range rePruned.FindAllStringIndex(line, -1) {
		paint(m[0], m[1], cMuted, "", false)
	}

	// go.mod: <value>
	for _, m := range reGoMod.FindAllStringIndex(line, -1) {
		paint(m[0], m[1], cMuted, "", false)
		paint(m[1], n, cInfo, "", false)
	}

	// Milestone ▶ <version> lines
	if strings.ContainsRune(line, '▶') {
		paint(0, n, cMuted, "", false) // dim the whole line first
		for _, m := range reMilestone.FindAllStringSubmatchIndex(line, -1) {
			if len(m) >= 4 {
				paint(m[2], m[3], cInfo, "", true) // highlight captured version
			}
		}
	}

	// Option +/- bullets inside tree blocks (not diff lines)
	if strings.ContainsRune(line, '│') {
		if m := reOptPlus.FindStringIndex(line); m != nil {
			paint(m[0], m[0]+1, cClean, "", true)
		}
		if m := reOptMinus.FindStringIndex(line); m != nil && !strings.Contains(line, "fixedIn") {
			paint(m[0], m[0]+1, cHigh, "", true)
		}
	}

	// Diff action labels
	for pat, col := range map[*regexp.Regexp]string{
		regexp.MustCompile(`\[REPLACE\]`):     cReplace,
		regexp.MustCompile(`\[UPGRADE\]`):     cStep,
		regexp.MustCompile(`\[ADD OVERRIDE\]`): cInfo,
	} {
		for _, m := range pat.FindAllStringIndex(line, -1) {
			paint(m[0], m[1], col, "", true)
		}
	}

	// Diff +/- lines (no tree characters)
	if !strings.ContainsAny(line, "│├└") {
		if m := reDiffLine.FindStringSubmatchIndex(line); m != nil {
			sym := line[m[4]:m[5]]
			if sym == "+" {
				paint(0, n, cClean, bgCleanBg, false)
				paint(m[4], m[5], cClean, bgCleanBg, true)
			} else {
				paint(0, n, cHigh, bgHighBg, false)
				paint(m[4], m[5], cHigh, bgHighBg, true)
			}
		}
	}

	// // comments
	for _, m := range reComment.FindAllStringIndex(line, -1) {
		paint(m[0], m[1], cMuted, "", false)
		for _, wm := range reWarn.FindAllStringIndex(line[m[0]:], -1) {
			paint(m[0]+wm[0], m[0]+wm[1], cMed, "", false)
		}
	}

	// Pure pipe-only rows (dim entirely)
	if rePipeOnly.MatchString(line) {
		paint(0, n, cBorder, "", false)
	}

	// Legend / column-header annotation lines
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "Legend:") || strings.HasPrefix(trimmed, "H×n") {
		paint(0, n, cMuted, "", false)
	}

	// ── Collapse into segments (walk rune by rune) ────────────────────────────
	var segs []segment
	i := 0
	for i < n {
		_, size := utf8.DecodeRuneInString(line[i:])
		j := i + size
		for j < n {
			_, sz := utf8.DecodeRuneInString(line[j:])
			if fgs[j] == fgs[i] && bgs[j] == bgs[i] && bolds[j] == bolds[i] {
				j += sz
			} else {
				break
			}
		}
		segs = append(segs, segment{
			text: line[i:j],
			fg:   fgs[i],
			bg:   bgs[i],
			bold: bolds[i],
		})
		i = j
	}
	return segs
}

// ── Line classifier ───────────────────────────────────────────────────────────

func classify(line string) string {
	s := strings.TrimRight(line, " \t")
	switch {
	case clBannerRule.MatchString(s):
		return "BANNER_RULE"
	case clSectionRule.MatchString(s):
		return "SECTION_RULE"
	case strings.HasPrefix(s, "  SNYK REMEDIATION REPORT"):
		return "BANNER_TITLE"
	case strings.HasPrefix(s, "  gomodules"), clBannerMeta.MatchString(s):
		return "BANNER_META"
	case s == "DEPENDENCY TREE",
		s == "UPGRADE EFFICIENCY MATRIX",
		s == "RECOMMENDED go.mod CHANGES  (closes all vulnerability records)":
		return "SECTION_TITLE"
	case clMatrixHdr.MatchString(s):
		return "MATRIX_HDR"
	case clMatrixRule.MatchString(s):
		return "MATRIX_RULE"
	case clMatrixRow.MatchString(s):
		return "MATRIX_ROW"
	case clDiffAction.MatchString(s):
		return "DIFF_ACTION"
	case s == "":
		return "BLANK"
	default:
		return "CONTENT"
	}
}

// ── Render helpers ────────────────────────────────────────────────────────────

func termWidth() int {
	if col := os.Getenv("COLUMNS"); col != "" {
		var n int
		if _, err := fmt.Sscanf(col, "%d", &n); err == nil && n > 0 {
			return n
		}
	}
	return 120
}

func repeat(ch string, n int) string {
	if n <= 0 {
		return ""
	}
	var sb strings.Builder
	for i := 0; i < n; i++ {
		sb.WriteString(ch)
	}
	return sb.String()
}

func ruleLine(ch, color string, width int) string {
	lim := width
	if lim > 100 {
		lim = 100
	}
	return color + repeat(ch, lim) + ansiReset
}

func sectionBar(title string, width int) string {
	lim := width
	if lim > 100 {
		lim = 100
	}
	label := "  " + strings.ToUpper(title) + "  "
	runeLen := utf8.RuneCountInString(label)
	pad := repeat(" ", lim-runeLen)
	return "\n" + bgSurface2 + cMuted + ansiBold + label + pad + ansiReset
}

func emitSegs(w *bufio.Writer, segs []segment, rowBg string) {
	for _, s := range segs {
		if rowBg != "" {
			w.WriteString(rowBg)
		}
		w.WriteString(s.fg)
		if s.bold {
			w.WriteString(ansiBold)
		}
		w.WriteString(s.text)
		w.WriteString(ansiReset)
	}
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	inputFlag := flag.String("input", "", "path to .txt file")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, `expand-dep-tree — ANSI true-color renderer for snyk-remediation .txt files.

USAGE
  go run expand-dep-tree.go [OPTIONS] [FILE]
  ./expand-dep-tree         [OPTIONS] [FILE]

ARGUMENTS
  FILE   Path to a snyk-remediation .txt file.
         Omit to read snyk-remediation.txt in the current directory.
         Pass - to read from stdin.

OPTIONS
  --input=FILE   Explicit path to the .txt file (alternative to positional FILE).
  --help         Show this message and exit.

EXAMPLES
  # Default — reads snyk-remediation.txt in cwd
  go run expand-dep-tree.go

  # Explicit file via flag
  go run expand-dep-tree.go --input=snyk-remediation.txt

  # Positional path (shorter)
  go run expand-dep-tree.go snyk-remediation.txt

  # Pipe from stdin
  cat snyk-remediation.txt | go run expand-dep-tree.go -

  # Page through long output
  go run expand-dep-tree.go snyk-remediation.txt | less -R

  # Compiled binary (no go run overhead)
  go build -o expand-dep-tree expand-dep-tree.go
  ./expand-dep-tree snyk-remediation.txt | less -R

COLOR CODING
  [H] / H×n          Red     — HIGH severity CVE
  [M] / M×n          Amber   — MEDIUM severity CVE
  fixedIn: <ver>     Green   — version that closes the CVE
  ◀ TARGET           Green   — recommended fix milestone
  ⚡ POINT            Mint    — patch/minor bump within semver range
  ⬆ STEP             Orange  — minor version jump, same major
  ⇄ REPLACE          Purple  — package swap required
  ✓ / ✓ optimal      Green   — no known vulnerabilities
  ⚠ <message>        Amber   — point-alternative warning
  ★ RECOMMENDED      Purple  — preferred remediation option
  go.mod: <change>   Blue    — exact go.mod line to apply
  @version           Gray    — version string
  [pruned]           Gray    — duplicate node omitted from tree
  diff + lines       Green bg — addition in go.mod diff
  diff - lines       Red bg  — removal in go.mod diff`)
	}
	flag.Parse()

	src := *inputFlag
	if src == "" && flag.NArg() > 0 {
		src = flag.Arg(0)
	}

	var scanner *bufio.Scanner
	switch src {
	case "", ".":
		f, err := os.Open("snyk-remediation.txt")
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		defer f.Close()
		scanner = bufio.NewScanner(f)
	case "-":
		scanner = bufio.NewScanner(os.Stdin)
	default:
		f, err := os.Open(src)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		defer f.Close()
		scanner = bufio.NewScanner(f)
	}

	cols   := termWidth()
	w      := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	matAlt := false

	for scanner.Scan() {
		line := scanner.Text()

		switch classify(line) {
		case "BLANK":
			fmt.Fprintln(w)

		case "BANNER_RULE":
			fmt.Fprintln(w, ruleLine("━", cBorder, cols))

		case "SECTION_RULE":
			fmt.Fprintln(w, ruleLine("─", cBorder, cols))

		case "BANNER_TITLE":
			fmt.Fprintln(w, ansiBold+cText+strings.TrimSpace(line)+ansiReset)

		case "BANNER_META":
			fmt.Fprintln(w, cMuted+strings.TrimSpace(line)+ansiReset)

		case "SECTION_TITLE":
			fmt.Fprintln(w, sectionBar(line, cols))

		case "MATRIX_HDR":
			fmt.Fprintln(w, bgSurface2+cMuted+ansiBold+line+ansiReset)
			matAlt = false

		case "MATRIX_RULE":
			runeLen := utf8.RuneCountInString(line)
			fmt.Fprintln(w, cBorder+repeat("─", runeLen)+ansiReset)

		case "MATRIX_ROW":
			rowBg := bgSurface
			if matAlt {
				rowBg = bgSurface2
			}
			matAlt = !matAlt
			emitSegs(w, colorize(line), rowBg)
			fmt.Fprintln(w)

		case "DIFF_ACTION":
			accentCol := cInfo
			switch {
			case strings.Contains(line, "[REPLACE]"):
				accentCol = cReplace
			case strings.Contains(line, "[UPGRADE]"):
				accentCol = cStep
			}
			w.WriteString(accentCol + "▌" + ansiReset + " ")
			emitSegs(w, colorize(line), "")
			fmt.Fprintln(w)

		default: // CONTENT
			emitSegs(w, colorize(line), "")
			fmt.Fprintln(w)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "error reading input:", err)
		os.Exit(1)
	}
}
