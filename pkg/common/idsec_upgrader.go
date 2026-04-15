// Package common provides utility functions for the IDSEC CLI, including self-update functionality
// for checking and managing application versions using GitHub releases.
package common

import (
	"fmt"
	"os"

	"github.com/blang/semver"
	"github.com/rhysd/go-github-selfupdate/selfupdate"
	"github.com/cyberark/idsec-sdk-golang/pkg/config"
)

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

// IsLatestVersion checks if the current application version is the latest available.
func IsLatestVersion() (bool, *semver.Version, error) {
	updater, err := GetSelfUpgrader()
	if err != nil {
		return false, nil, err
	}
	latest, found, err := updater.DetectLatest(config.IdsecPath())
	if err != nil {
		return false, nil, err
	}
	if !found {
		return true, nil, nil
	}
	currentVersion, err := semver.Parse(config.IdsecVersion())
	if err != nil {
		return false, nil, err
	}
	return !latest.Version.GT(currentVersion), &latest.Version, nil
}
