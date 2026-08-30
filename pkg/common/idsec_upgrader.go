// Package common provides utility functions for the IDSEC CLI, including self-update functionality
// for checking and managing application versions using GitHub releases.
package common

import (
	"fmt"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/blang/semver"
	"github.com/rhysd/go-github-selfupdate/selfupdate"
	"github.com/cyberark/idsec-sdk-golang/pkg/config"
)

const latestVersionCheckTimeout = 5 * time.Second
const publicGitHubHost = "github.com"
const releaseRepoFallback = "github.com/cyberark/idsec-cli-golang"

var releaseRepoOverride = ""

// releaseRepoHostAndSlug resolves the host and the "owner/name" slug of the
// repository publishing the release binaries.
//
// The two are always resolved together from a single location string. Splitting
// them across independent sources lets them drift, which silently sends the
// upgrade check to a host that does not hold the target repository.
//
// Resolution order is the link-time override, then the module path recorded in
// the binary's build information, then releaseRepoFallback.
func releaseRepoHostAndSlug() (string, string) {
	if host, slug, ok := parseRepoLocation(releaseRepoOverride); ok {
		return host, slug
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if host, slug, ok := parseRepoLocation(info.Main.Path); ok {
			return host, slug
		}
	}
	host, slug, _ := parseRepoLocation(releaseRepoFallback)
	return host, slug
}

// parseRepoLocation splits a "host/owner/name" location, such as a Go module
// path, into its host and "owner/name" slug.
//
// Any trailing path elements, for example a "/v2" major-version suffix or a
// "/cmd/idsec" package path, are ignored. The boolean result reports whether
// location held a usable host and slug.
func parseRepoLocation(location string) (string, string, bool) {
	parts := strings.Split(strings.Trim(location, "/"), "/")
	if len(parts) < 3 {
		return "", "", false
	}
	host, owner, name := parts[0], parts[1], parts[2]
	// A host without a dot is not a registry we can reach; this also rejects
	// placeholder module paths such as Go's "command-line-arguments".
	if !strings.Contains(host, ".") || owner == "" || name == "" {
		return "", "", false
	}
	return host, owner + "/" + name, true
}

// UpgradeRepoSlug returns the GitHub "owner/name" slug that release binaries
// are published to, for use as the repository argument of the self-updater's
// detection calls.
func UpgradeRepoSlug() string {
	_, slug := releaseRepoHostAndSlug()
	return slug
}

// upgradeAPIHost resolves the GitHub host to query for releases.
//
// It defaults to the host owning the release repository, so upgrades work on
// GitHub Enterprise installations without any environment setup. GITHUB_URL
// overrides it, which both retargets the check at another instance and lets
// tests point it at a local server.
func upgradeAPIHost() string {
	if envHost := os.Getenv("GITHUB_URL"); envHost != "" {
		return envHost
	}
	host, _ := releaseRepoHostAndSlug()
	return host
}

// GetSelfUpgrader creates and configures a GitHub self-updater instance.
func GetSelfUpgrader() (*selfupdate.Updater, error) {
	host := upgradeAPIHost()
	config := selfupdate.Config{}
	if host != publicGitHubHost {
		config.EnterpriseUploadURL = fmt.Sprintf("https://%s/api/uploads/", host)
		config.EnterpriseBaseURL = fmt.Sprintf("https://%s/api/v3/", host)
	}
	return selfupdate.NewUpdater(config)
}

// IsLatestVersion checks if the current application version is the latest
// available, bounded by latestVersionCheckTimeout.
//
// On timeout the function returns a non-nil error; callers using the
// established `if err == nil && !isLatest` pattern (e.g. CommonActionsExecution)
// silently treat the result as inconclusive, surfacing nothing to the user.
// The in-flight HTTP request is left to complete in the background and its
// result is discarded; this is a deliberate trade-off because the vendored
// selfupdate library does not expose a context for cancellation.
func IsLatestVersion() (bool, *semver.Version, error) {
	type result struct {
		isLatest bool
		latest   *semver.Version
		err      error
	}
	ch := make(chan result, 1)
	go func() {
		updater, err := GetSelfUpgrader()
		if err != nil {
			ch <- result{err: err}
			return
		}
		latest, found, err := updater.DetectLatest(UpgradeRepoSlug())
		if err != nil {
			ch <- result{err: err}
			return
		}
		if !found {
			ch <- result{isLatest: true}
			return
		}
		currentVersion, err := semver.Parse(config.IdsecVersion())
		if err != nil {
			ch <- result{err: err}
			return
		}
		ch <- result{
			isLatest: !latest.Version.GT(currentVersion),
			latest:   &latest.Version,
		}
	}()
	select {
	case r := <-ch:
		return r.isLatest, r.latest, r.err
	case <-time.After(latestVersionCheckTimeout):
		return false, nil, fmt.Errorf("upgrade check timed out after %s", latestVersionCheckTimeout)
	}
}
