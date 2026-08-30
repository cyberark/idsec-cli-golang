package common

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/google/go-github/v30/github"
	"github.com/inconshreveable/go-update"
	"github.com/rhysd/go-github-selfupdate/selfupdate"
	gitconfig "github.com/tcnksm/go-gitconfig"
	"github.com/ulikunitz/xz"
	"golang.org/x/oauth2"
)

// executableModeMask matches the owner, group and other execute bits.
const executableModeMask = 0o111

// ApplyUpgrade replaces the executable at cmdPath with the binary packaged in
// the given release's asset.
//
// This exists instead of selfupdate.Updater.UpdateTo because that method locates
// the payload inside the archive by matching the running executable's file name.
// Release archives package the binary as "idsec-<os>", so the match only
// succeeds for a binary still carrying its published name: an `idsec` installed
// through `go install`, a renamed download, or the Docker image would detect the
// new version and then fail to apply it. Selecting the payload by file mode
// instead keeps the upgrade working regardless of what the binary is called.
func ApplyUpgrade(rel *selfupdate.Release, cmdPath string) error {
	ctx := context.Background()
	asset, err := downloadReleaseAsset(ctx, rel)
	if err != nil {
		return err
	}
	payload, err := extractExecutable(asset, rel.AssetURL)
	if err != nil {
		return err
	}
	return update.Apply(payload, update.Options{TargetPath: cmdPath})
}

// newReleaseAPIClient builds a GitHub client aimed at the host publishing the
// release binaries.
//
// Token resolution and Enterprise wiring mirror selfupdate.NewUpdater so that
// downloading an asset succeeds wherever detecting it already succeeds, which
// matters for private and GitHub Enterprise repositories.
func newReleaseAPIClient(ctx context.Context) (*github.Client, error) {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		token, _ = gitconfig.GithubToken()
	}
	httpClient := http.DefaultClient
	if token != "" {
		httpClient = oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}))
	}
	host := upgradeAPIHost()
	if host == publicGitHubHost {
		return github.NewClient(httpClient), nil
	}
	baseURL := fmt.Sprintf("https://%s/api/v3/", host)
	return github.NewEnterpriseClient(baseURL, baseURL, httpClient)
}

// downloadReleaseAsset fetches the release asset over the GitHub API, falling
// back to the redirect target when the API answers with one. The asset is held
// in memory because both archive formats need to seek or restart the stream.
func downloadReleaseAsset(ctx context.Context, rel *selfupdate.Release) ([]byte, error) {
	client, err := newReleaseAPIClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create GitHub client: %w", err)
	}
	var redirectFollower http.Client
	src, redirectURL, err := client.Repositories.DownloadReleaseAsset(ctx, rel.RepoOwner, rel.RepoName, rel.AssetID, &redirectFollower)
	if err != nil {
		return nil, fmt.Errorf("failed to download asset %d from %s/%s: %w", rel.AssetID, rel.RepoOwner, rel.RepoName, err)
	}
	if redirectURL != "" {
		if src, err = getURL(ctx, redirectURL); err != nil {
			return nil, err
		}
	}
	defer func() { _ = src.Close() }()
	data, err := io.ReadAll(src)
	if err != nil {
		return nil, fmt.Errorf("failed to read asset body: %w", err)
	}
	return data, nil
}

// getURL downloads a release asset straight from a URL, used when the API
// responds with a redirect that the authenticated client cannot follow.
func getURL(ctx context.Context, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for %s: %w", url, err)
	}
	req.Header.Set("Accept", "application/octet-stream")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download %s: %w", url, err)
	}
	if res.StatusCode != http.StatusOK {
		_ = res.Body.Close()
		return nil, fmt.Errorf("failed to download %s: unexpected status %d", url, res.StatusCode)
	}
	return res.Body, nil
}

// archiveEntry describes one candidate file inside a release archive.
type archiveEntry struct {
	name       string
	executable bool
}

// extractExecutable returns a reader over the executable packaged in asset.
//
// The archive format is taken from assetURL, matching how the release assets are
// named. An asset that is not an archive is assumed to be the executable itself.
func extractExecutable(asset []byte, assetURL string) (io.Reader, error) {
	switch {
	case hasAnySuffix(assetURL, ".tar.gz", ".tgz"):
		return extractFromTar(asset, newGzipReader)
	case hasAnySuffix(assetURL, ".tar.xz"):
		return extractFromTar(asset, newXzReader)
	case hasAnySuffix(assetURL, ".zip"):
		return extractFromZip(asset)
	default:
		return bytes.NewReader(asset), nil
	}
}

func hasAnySuffix(s string, suffixes ...string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(s, suffix) {
			return true
		}
	}
	return false
}

func newGzipReader(r io.Reader) (io.Reader, error) {
	return gzip.NewReader(r)
}

func newXzReader(r io.Reader) (io.Reader, error) {
	return xz.NewReader(r)
}

// extractFromTar walks a tar archive twice: once to choose the executable among
// all entries, and once to return a reader positioned on it. Two passes avoid
// buffering the whole payload a second time while still allowing the choice to
// consider every entry.
func extractFromTar(asset []byte, decompress func(io.Reader) (io.Reader, error)) (io.Reader, error) {
	var entries []archiveEntry
	if err := walkTar(asset, decompress, func(header *tar.Header, _ io.Reader) (bool, error) {
		if header.Typeflag == tar.TypeReg {
			entries = append(entries, archiveEntry{
				name:       path.Base(header.Name),
				executable: header.FileInfo().Mode()&executableModeMask != 0,
			})
		}
		return false, nil
	}); err != nil {
		return nil, err
	}

	target, err := chooseExecutable(entries)
	if err != nil {
		return nil, err
	}

	var payload io.Reader
	if err := walkTar(asset, decompress, func(header *tar.Header, r io.Reader) (bool, error) {
		if header.Typeflag != tar.TypeReg || path.Base(header.Name) != target {
			return false, nil
		}
		data, readErr := io.ReadAll(r)
		if readErr != nil {
			return true, fmt.Errorf("failed to read %s from archive: %w", target, readErr)
		}
		payload = bytes.NewReader(data)
		return true, nil
	}); err != nil {
		return nil, err
	}
	if payload == nil {
		return nil, fmt.Errorf("executable %q vanished from archive between passes", target)
	}
	return payload, nil
}

// walkTar calls visit for each entry until visit reports that it is done.
func walkTar(asset []byte, decompress func(io.Reader) (io.Reader, error),
	visit func(*tar.Header, io.Reader) (bool, error)) error {
	decompressed, err := decompress(bytes.NewReader(asset))
	if err != nil {
		return fmt.Errorf("failed to decompress asset: %w", err)
	}
	reader := tar.NewReader(decompressed)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to read tar archive: %w", err)
		}
		done, err := visit(header, reader)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
}

func extractFromZip(asset []byte) (io.Reader, error) {
	reader, err := zip.NewReader(bytes.NewReader(asset), int64(len(asset)))
	if err != nil {
		return nil, fmt.Errorf("failed to read zip archive: %w", err)
	}
	entries := make([]archiveEntry, 0, len(reader.File))
	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}
		entries = append(entries, archiveEntry{
			name:       path.Base(file.Name),
			executable: file.FileInfo().Mode()&executableModeMask != 0,
		})
	}
	target, err := chooseExecutable(entries)
	if err != nil {
		return nil, err
	}
	for _, file := range reader.File {
		if file.FileInfo().IsDir() || path.Base(file.Name) != target {
			continue
		}
		opened, err := file.Open()
		if err != nil {
			return nil, fmt.Errorf("failed to open %s in archive: %w", target, err)
		}
		defer func() { _ = opened.Close() }()
		data, err := io.ReadAll(opened)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s from archive: %w", target, err)
		}
		return bytes.NewReader(data), nil
	}
	return nil, fmt.Errorf("executable %q vanished from archive", target)
}

// chooseExecutable picks the release binary out of an archive's entries.
//
// Selection is by executable mode bit so that renaming the binary, or renaming
// it inside the archive, cannot break upgrades. Archives also ship
// documentation and signature files, which are not executable. When several
// entries qualify, the one named after the project wins to keep the choice
// deterministic.
func chooseExecutable(entries []archiveEntry) (string, error) {
	var candidates []string
	for _, entry := range entries {
		if entry.executable {
			candidates = append(candidates, entry.name)
		}
	}
	switch len(candidates) {
	case 0:
		var names []string
		for _, entry := range entries {
			names = append(names, entry.name)
		}
		return "", fmt.Errorf("no executable found in release archive (contains: %s)", strings.Join(names, ", "))
	case 1:
		return candidates[0], nil
	}
	for _, name := range candidates {
		if strings.HasPrefix(name, idsecExecutablePrefix) {
			return name, nil
		}
	}
	return candidates[0], nil
}

// idsecExecutablePrefix disambiguates the CLI binary from any other executable
// that a release archive might carry.
const idsecExecutablePrefix = "idsec"
