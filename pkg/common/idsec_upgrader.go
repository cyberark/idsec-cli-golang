// Package common provides utility functions for the IDSEC CLI, including self-update functionality
// for checking and managing application versions using GitHub releases.
package common

import (
	"fmt"
	"os"
	"time"

	"github.com/blang/semver"
	"github.com/rhysd/go-github-selfupdate/selfupdate"
	"github.com/cyberark/idsec-sdk-golang/pkg/config"
)

const latestVersionCheckTimeout = 5 * time.Second

// GetSelfUpgrader creates and configures a GitHub self-updater instance.
func GetSelfUpgrader() (*selfupdate.Updater, error) {
	githubURL := os.Getenv("GITHUB_URL")
	config := selfupdate.Config{}
	if githubURL != "" {
		config.EnterpriseUploadURL = fmt.Sprintf("https://%s/api/uploads/", githubURL)
		config.EnterpriseBaseURL = fmt.Sprintf("https://%s/api/v3/", githubURL)
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
		latest, found, err := updater.DetectLatest(config.IdsecPath())
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
