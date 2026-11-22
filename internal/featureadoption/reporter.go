// Copyright (c) CyberArk.
// SPDX-License-Identifier: Apache-2.0

package featureadoption

import (
	"context"
	"fmt"
	"time"

	"github.com/cyberark/idsec-cli-golang/pkg/agentmode"
	api "github.com/cyberark/idsec-sdk-golang/pkg"
	sdkcommon "github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/config"
	sdkfeatureadoption "github.com/cyberark/idsec-sdk-golang/pkg/featureadoption"
)

const (
	// MetricKey is the FAS metric key for the CLI.
	MetricKey = "IDSGO.idsec_cli_golang.usage"

	// TagKeyCLIService is the FAS tag key for CLI service context.
	TagKeyCLIService = "cls"
	// TagKeyCLIOperation is the FAS tag key for CLI operation context.
	TagKeyCLIOperation = "clo"
	// TagKeyCLIVersion is the FAS tag key for CLI version.
	TagKeyCLIVersion = "clv"
	// TagKeyCLIResource is the FAS tag key for CLI resource path context.
	TagKeyCLIResource = "clr"
	// TagKeyCLIAgent is the FAS tag key for the invocation's agent source.
	// It is present on every report. Its value is a slug from the agentmode
	// detector registry when agent mode is enabled and an agent was detected,
	// "unknown" when agent mode is enabled but no agent was detected, and
	// "human" when agent mode is not enabled; never raw environment content.
	TagKeyCLIAgent = "cla"
	// AgentUnknownSlug is the cla value when agent mode is enabled but no
	// specific agent was detected via the detector registry.
	AgentUnknownSlug = "unknown"
	// AgentHumanSlug is the cla value when agent mode is not enabled.
	AgentHumanSlug = "human"
)

// ReportOptions holds optional parameters for FAS reporting.
type ReportOptions struct {
	// OperationDuration is how long the operation took.
	OperationDuration *time.Duration
	// OperationStatus is the outcome of the operation ("success" or "failure").
	OperationStatus string
	// Message is the output status/details of the operation.
	Message string
	// ExtraTags adds optional report tags.
	ExtraTags map[string]string
}

// ReportOperationDefer returns a function to be used with defer.
// It reports execution metrics when the calling function returns.
// extraTags are merged into the FAS report tags (e.g. cls, clo, clr, clv).
// The cla tag is always added by the reporter (agent slug, "unknown" or "human")
// and cannot be overridden.
func ReportOperationDefer(ctx context.Context, idsecAPI *api.IdsecAPI, logger *sdkcommon.IdsecLogger, status *string, message *string, extraTags map[string]string) func() {
	start := time.Now()
	return func() {
		dur := time.Since(start)
		opStatus := "success"
		if status != nil && *status != "" {
			opStatus = *status
		}

		opMessage := ""
		if message != nil {
			opMessage = *message
		}
		ReportAsync(ctx, idsecAPI, logger, &ReportOptions{
			OperationDuration: &dur,
			OperationStatus:   opStatus,
			Message:           opMessage,
			ExtraTags:         extraTags,
		})
	}
}

// ReportAsync sends a feature adoption report to FAS.
// Report failures are non-blocking and never affect command execution.
func ReportAsync(ctx context.Context, idsecAPI *api.IdsecAPI, logger *sdkcommon.IdsecLogger, opts *ReportOptions) {
	_ = ctx

	tags := buildTags(opts)
	customData := buildCustomData(opts)
	reportOpts := &sdkfeatureadoption.ReportOpts{
		CustomData: customData,
	}

	msg, err := sdkfeatureadoption.ReportWithAPI(context.Background(), idsecAPI, MetricKey, tags, reportOpts)

	log := logger
	if log == nil {
		log = sdkcommon.GetLogger("IdsecCLIFeatureAdoption", sdkcommon.Unknown)
	}
	if err != nil {
		log.Warning("FAS report failed: %s", err.Error())
		return
	}
	if msg != "" {
		log.Debug("%s [metric_key=%s]", msg, MetricKey)
	}
}

func buildTags(opts *ReportOptions) map[string]string {
	tags := make(map[string]string)
	if opts != nil {
		for k, v := range opts.ExtraTags {
			if k != "" && v != "" {
				tags[k] = v
			}
		}
	}
	// cla is owned by the reporter and is always set: a caller-supplied value is
	// overwritten so the tag only ever carries a registry slug or a sentinel.
	if agentmode.IsEnabled() {
		if slug := agentmode.DetectedAgent(); slug != "" {
			tags[TagKeyCLIAgent] = slug
		} else {
			tags[TagKeyCLIAgent] = AgentUnknownSlug
		}
	} else {
		tags[TagKeyCLIAgent] = AgentHumanSlug
	}
	return tags
}

func buildCustomData(opts *ReportOptions) map[string]interface{} {
	customData := make(map[string]interface{})
	customData["correlation_id"] = config.CorrelationID()

	if opts == nil {
		return customData
	}
	if opts.OperationDuration != nil {
		customData["duration"] = fmt.Sprintf("%d", opts.OperationDuration.Milliseconds())
	}
	if opts.OperationStatus != "" {
		customData["ops"] = opts.OperationStatus
	}
	if opts.Message != "" {
		customData["message"] = opts.Message
	}
	return customData
}
