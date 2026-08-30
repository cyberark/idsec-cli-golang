package actions

import (
	"fmt"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	sdkactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/doctor/actions"
	doctormodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/doctor/models"
)

// CLIAction defines the SIA Doctor sub-command for the Idsec CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "doctor",
		ActionDescription: "SIA compatibility check-ups for client, target, connector, and domain-controller.",
		ActionVersion:     1,
		Schemas:           sdkactions.ActionToSchemaMap,
	},
	Formatters: map[string]actions.CLIFormatter{
		"check":                   doctorFormatter{},
		"check-client":            doctorFormatter{},
		"check-target":            doctorFormatter{},
		"check-connector":         doctorFormatter{},
		"check-domain-controller": doctorFormatter{},
	},
}

// doctorFormatter renders an *IdsecSIADoctorReport as a human-readable terminal table.
type doctorFormatter struct{}

func (doctorFormatter) Format(result any) string {
	report, ok := result.(*doctormodels.IdsecSIADoctorReport)
	if !ok || report == nil {
		return fmt.Sprintf("%v", result)
	}

	bold := color.New(color.Bold)
	dim := color.New(color.Faint)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)
	yellow := color.New(color.FgYellow)
	cyan := color.New(color.FgCyan)

	const divider = "═══════════════════════════════════════════════════════════════════════════════"
	const subDiv = "───────────────────────────────────────────────────────────────────────────────"

	var sb strings.Builder

	sb.WriteString(divider + "\n")
	sb.WriteString(bold.Sprintf("  SIA Doctor Report — %s\n", strings.ToUpper(report.Mode)))
	sb.WriteString(divider + "\n\n")

	flowTitleOverride := map[string]string{
		doctormodels.FlowZSPLocalEphemeral: "ZSP LOCAL EPHEMERAL / JIT ELEVATION",
	}
	flowTitle := func(flow string) string {
		if flow == "" {
			return "PROTOCOLS"
		}
		if t, ok := flowTitleOverride[flow]; ok {
			return t
		}
		return strings.ToUpper(strings.ReplaceAll(flow, "-", " "))
	}

	flowSubtitle := map[string]string{
		doctormodels.FlowZSPLocalEphemeral:  "connector → target  RPC(135) + SMB(445)  [RDP only — ephemeral local account creation / JIT elevation]",
		doctormodels.FlowZSPDomainEphemeral: "connector → target WinRM  +  connector → DC  LDAP/Kerberos  [RDP / MSSQL / DB2]",
	}

	// connectorIDOf extracts the connector ID from a backend section key
	// ("backend:connector:<id>"), or "" when the section is not per-connector.
	connectorIDOf := func(k string) string {
		cf := strings.TrimPrefix(k, "backend:")
		if id := strings.TrimPrefix(cf, "connector:"); id != cf && id != "" {
			return id
		}
		return ""
	}

	// Index connector metadata by ID so each connector section header can show
	// the host / IP / platform that identifies which connector needs attention.
	connInfoByID := make(map[string]doctormodels.IdsecSIADoctorConnectorInfo, len(report.Connectors))
	for _, ci := range report.Connectors {
		connInfoByID[ci.ID] = ci
	}
	connectorSubtitle := func(k string) string {
		ci, ok := connInfoByID[connectorIDOf(k)]
		if !ok {
			return ""
		}
		var parts []string
		if ci.HostName != "" {
			parts = append(parts, "host: "+ci.HostName)
		}
		if ci.HostIP != "" {
			parts = append(parts, "ip: "+ci.HostIP)
		}
		if ci.HostType != "" {
			parts = append(parts, "platform: "+ci.HostType)
		}
		if ci.OS != "" {
			parts = append(parts, "os: "+ci.OS)
		}
		if ci.Version != "" {
			parts = append(parts, "version: "+ci.Version)
		}
		if ci.Status != "" {
			parts = append(parts, "status: "+ci.Status)
		}
		if ci.Region != "" {
			parts = append(parts, "region: "+ci.Region)
		}
		return strings.Join(parts, "  •  ")
	}

	// Canonical section order: base protocols first, then extras. ZSP
	// local-ephemeral and JIT elevation share the same RPC/SMB ports and are
	// reported together under FlowZSPLocalEphemeral. The FlowBackend slot expands
	// into every per-connector backend section (first-seen order).
	knownOrder := []string{
		"",
		doctormodels.FlowGW,
		doctormodels.FlowRelay,
		doctormodels.FlowBackend,
		doctormodels.FlowZSPLocalEphemeral,
		doctormodels.FlowZSPDomainEphemeral,
		doctormodels.FlowZSPSSHCerts,
		doctormodels.FlowVaulted,
		doctormodels.FlowDC,
	}

	// Column widths are derived from every check so columns line up across all
	// mode bands, regardless of how long a hostname is.
	hostPortStr := func(c doctormodels.IdsecSIADoctorCheckResult) string {
		if c.Port > 0 {
			return fmt.Sprintf("%s:%d", c.Host, c.Port)
		}
		return c.Host
	}
	protoW, hostW := 8, 20
	for _, c := range report.Checks {
		if l := len(c.Protocol); l > protoW {
			protoW = l
		}
		if l := len(hostPortStr(c)); l > hostW {
			hostW = l
		}
	}

	// certRank orders rows within a flow by TLS certificate validation, surfacing
	// untrusted / unverified rows first, then trusted, then rows with no cert check.
	certRank := func(certStatus string) int {
		switch certStatus {
		case doctormodels.CertStatusUntrusted:
			return 0
		case doctormodels.CertStatusUnverified:
			return 1
		case doctormodels.CertStatusTrusted:
			return 2
		default:
			return 3
		}
	}

	// certIcon renders the certificate-validation indicator for a row.
	certIcon := func(certStatus string) string {
		switch certStatus {
		case doctormodels.CertStatusTrusted:
			return green.Sprint("🔒")
		case doctormodels.CertStatusUntrusted:
			return red.Sprint("🔓")
		case doctormodels.CertStatusUnverified:
			return yellow.Sprint("🔓")
		default:
			return " "
		}
	}

	// renderGroup writes the per-flow / per-connector sections for one subset of
	// checks. The unified report calls it once per mode band; single-mode reports
	// call it once with every check.
	renderGroup := func(groupChecks []doctormodels.IdsecSIADoctorCheckResult) {
		// Group checks into sections. Normally one section per flow, but the
		// backend checks are split into one section per connector (keyed by which
		// connector ran them) rather than collapsing every connector under a
		// single "Backend" section.
		sectionKeyOf := func(c doctormodels.IdsecSIADoctorCheckResult) string {
			if c.Flow == doctormodels.FlowBackend {
				return "backend:" + c.CheckedFrom
			}
			return "flow:" + c.Flow
		}
		bySection := make(map[string][]doctormodels.IdsecSIADoctorCheckResult)
		sectionFlow := map[string]string{}
		var sectionsSeen []string
		for _, c := range groupChecks {
			// Inactive connectors are reflected only in the skipped summary count —
			// don't render a per-connector section for them.
			if c.Flow == doctormodels.FlowBackend && c.Status == doctormodels.CheckStatusSkipped {
				continue
			}
			k := sectionKeyOf(c)
			if _, ok := bySection[k]; !ok {
				sectionsSeen = append(sectionsSeen, k)
			}
			bySection[k] = append(bySection[k], c)
			sectionFlow[k] = c.Flow
		}

		sectionTitle := func(k string) string {
			if sectionFlow[k] == doctormodels.FlowBackend {
				if id := connectorIDOf(k); id != "" {
					return "CONNECTOR " + id
				}
				return "CONNECTOR CONFIG"
			}
			return flowTitle(sectionFlow[k])
		}

		var sectionOrder []string
		placed := map[string]bool{}
		for _, f := range knownOrder {
			if f == doctormodels.FlowBackend {
				for _, k := range sectionsSeen {
					if sectionFlow[k] == doctormodels.FlowBackend && !placed[k] {
						sectionOrder = append(sectionOrder, k)
						placed[k] = true
					}
				}
				continue
			}
			k := "flow:" + f
			if _, ok := bySection[k]; ok && !placed[k] {
				sectionOrder = append(sectionOrder, k)
				placed[k] = true
			}
		}
		// Append any sections not in the known list in first-seen order.
		for _, k := range sectionsSeen {
			if !placed[k] {
				sectionOrder = append(sectionOrder, k)
				placed[k] = true
			}
		}

		for _, k := range sectionOrder {
			checks := bySection[k]
			sort.SliceStable(checks, func(i, j int) bool {
				return certRank(checks[i].CertStatus) < certRank(checks[j].CertStatus)
			})
			sb.WriteString(bold.Sprintf("  %s\n", sectionTitle(k)))
			if sub, ok := flowSubtitle[sectionFlow[k]]; ok {
				sb.WriteString(dim.Sprintf("  %s\n", sub))
			}
			if sectionFlow[k] == doctormodels.FlowBackend {
				if sub := connectorSubtitle(k); sub != "" {
					sb.WriteString(dim.Sprintf("  %s\n", sub))
				}
			}
			sb.WriteString("  " + subDiv + "\n")

			for _, c := range checks {
				var statusIcon string
				switch c.Status {
				case doctormodels.CheckStatusPass:
					statusIcon = green.Sprint("✔")
				case doctormodels.CheckStatusFail:
					statusIcon = red.Sprint("✗")
				case doctormodels.CheckStatusSkipped:
					statusIcon = yellow.Sprint("○")
				default:
					statusIcon = dim.Sprint("?")
				}

				target := cyan.Sprintf("%-*s", hostW, hostPortStr(c))

				latStr := "—"
				if c.LatencyMs > 0 {
					latStr = fmt.Sprintf("%dms", c.LatencyMs)
				}
				latency := dim.Sprintf("%6s", latStr)

				desc := ""
				if c.Description != "" && c.Description != "reachable" {
					desc = dim.Sprintf("  %s", c.Description)
				}

				from := ""
				if c.CheckedFrom != "" {
					from = dim.Sprintf("  [%s]", c.CheckedFrom)
				}

				warning := ""
				if c.Warning != "" {
					warning = yellow.Sprintf("  ⚠ %s", c.Warning)
				}

				sb.WriteString(fmt.Sprintf("  %s %s  %-*s  %s  %s%s%s%s\n",
					statusIcon,
					certIcon(c.CertStatus),
					protoW,
					c.Protocol,
					target,
					latency,
					desc,
					from,
					warning,
				))
			}
			sb.WriteString("\n")
		}
	}

	// The unified "check" report is banded by mode; single-mode reports render
	// as one group exactly as before.
	if report.Mode == "all" {
		byMode := map[string][]doctormodels.IdsecSIADoctorCheckResult{}
		var modeSeen []string
		for _, c := range report.Checks {
			if _, ok := byMode[c.Mode]; !ok {
				modeSeen = append(modeSeen, c.Mode)
			}
			byMode[c.Mode] = append(byMode[c.Mode], c)
		}
		var ordered []string
		placedMode := map[string]bool{}
		for _, m := range []string{"client", "connector", "target", "domain-controller"} {
			if _, ok := byMode[m]; ok {
				ordered = append(ordered, m)
				placedMode[m] = true
			}
		}
		for _, m := range modeSeen {
			if !placedMode[m] {
				ordered = append(ordered, m)
				placedMode[m] = true
			}
		}
		modeTitle := func(m string) string {
			if m == "" {
				return "OTHER"
			}
			return strings.ToUpper(strings.ReplaceAll(m, "-", " "))
		}
		for _, m := range ordered {
			sb.WriteString(bold.Sprintf("  ▸ %s\n", modeTitle(m)))
			sb.WriteString(divider + "\n")
			renderGroup(byMode[m])
		}
	} else {
		renderGroup(report.Checks)
	}

	if len(report.UnreachableTargets) > 0 {
		sb.WriteString(bold.Sprintf("  UNREACHABLE TARGETS\n"))
		sb.WriteString(dim.Sprintf("  no protocol could be confirmed reachable from any connector\n"))
		sb.WriteString("  " + subDiv + "\n")
		for _, host := range report.UnreachableTargets {
			sb.WriteString(fmt.Sprintf("  %s  %s\n", red.Sprint("✗"), cyan.Sprint(host)))
		}
		sb.WriteString("\n")
	}

	sb.WriteString(divider + "\n")

	passStr := green.Sprintf("✔ %d passed", report.Summary.Passed)
	failStr := red.Sprintf("✗ %d failed", report.Summary.Failed)
	warnStr := yellow.Sprintf("⚠ %d warnings", report.Summary.Warnings)
	naStr := dim.Sprintf("— %d n/a", report.Summary.NA)
	skipStr := yellow.Sprintf("○ %d skipped", report.Summary.Skipped)
	totalStr := dim.Sprintf("(%d total)", report.Summary.Total)

	sb.WriteString(bold.Sprintf("  Summary  "))
	sb.WriteString(fmt.Sprintf("%s  %s  %s  %s  %s  %s\n", passStr, failStr, warnStr, naStr, skipStr, totalStr))
	if report.DurationMs > 0 {
		sb.WriteString(dim.Sprintf("  Completed in %s\n", formatDuration(report.DurationMs)))
	}
	sb.WriteString(divider + "\n")

	return sb.String()
}

// formatDuration renders a millisecond duration compactly: sub-second values as
// milliseconds, otherwise seconds with two decimals.
func formatDuration(ms int64) string {
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	return fmt.Sprintf("%.2fs", float64(ms)/1000)
}
