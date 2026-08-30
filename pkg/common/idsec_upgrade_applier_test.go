package common

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"io/fs"
	"testing"
)

// archiveFile describes a file to place into a test archive.
type archiveFile struct {
	name    string
	mode    fs.FileMode
	content string
}

// releaseArchiveFiles mirrors the layout goreleaser produces: documentation
// alongside a single executable.
func releaseArchiveFiles(binaryName, binaryContent string) []archiveFile {
	return []archiveFile{
		{name: "LICENSE.txt", mode: 0o644, content: "license"},
		{name: "README.md", mode: 0o644, content: "readme"},
		{name: binaryName, mode: 0o755, content: binaryContent},
	}
}

func buildTarGz(t *testing.T, files []archiveFile) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range files {
		header := &tar.Header{
			Name:     f.name,
			Mode:     int64(f.mode),
			Size:     int64(len(f.content)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatalf("Failed writing tar header: %v", err)
		}
		if _, err := tw.Write([]byte(f.content)); err != nil {
			t.Fatalf("Failed writing tar content: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("Failed closing tar writer: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("Failed closing gzip writer: %v", err)
	}
	return buf.Bytes()
}

func buildZip(t *testing.T, files []archiveFile) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range files {
		header := &zip.FileHeader{Name: f.name}
		header.SetMode(f.mode)
		w, err := zw.CreateHeader(header)
		if err != nil {
			t.Fatalf("Failed creating zip entry: %v", err)
		}
		if _, err := w.Write([]byte(f.content)); err != nil {
			t.Fatalf("Failed writing zip content: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("Failed closing zip writer: %v", err)
	}
	return buf.Bytes()
}

// TestExtractExecutableIgnoresBinaryName is the regression test for the reason
// this applier exists: the payload must be found no matter what the binary is
// called, because the selfupdate library's own matching only accepts the
// published "idsec-<os>" name and so failed for `go install`, renamed downloads
// and the Docker image.
func TestExtractExecutableIgnoresBinaryName(t *testing.T) {
	const payload = "binary-payload"

	binaryNames := []string{
		"idsec-darwin",
		"idsec-linux",
		"idsec-windows.exe",
		"idsec",
		"idsec-renamed-by-user",
	}

	for _, binaryName := range binaryNames {
		t.Run(binaryName, func(t *testing.T) {
			t.Parallel()

			asset := buildTarGz(t, releaseArchiveFiles(binaryName, payload))

			reader, err := extractExecutable(asset, "https://example.com/idsec_1.0.0_darwin_arm64.tar.gz")
			if err != nil {
				t.Fatalf("Expected no error, got %v", err)
			}
			got, err := io.ReadAll(reader)
			if err != nil {
				t.Fatalf("Failed reading payload: %v", err)
			}
			if string(got) != payload {
				t.Errorf("Expected payload %q, got %q", payload, string(got))
			}
		})
	}
}

func TestExtractExecutable(t *testing.T) {
	const payload = "binary-payload"

	tests := []struct {
		name            string
		asset           func(t *testing.T) []byte
		assetURL        string
		expectedPayload string
		expectedError   bool
	}{
		{
			name: "tgz_extension",
			asset: func(t *testing.T) []byte {
				return buildTarGz(t, releaseArchiveFiles("idsec-linux", payload))
			},
			assetURL:        "https://example.com/idsec_1.0.0_linux_amd64.tgz",
			expectedPayload: payload,
		},
		{
			name: "zip_archive",
			asset: func(t *testing.T) []byte {
				return buildZip(t, releaseArchiveFiles("idsec-windows.exe", payload))
			},
			assetURL:        "https://example.com/idsec_1.0.0_windows_amd64.zip",
			expectedPayload: payload,
		},
		{
			name: "nested_directory_entries",
			asset: func(t *testing.T) []byte {
				return buildTarGz(t, []archiveFile{
					{name: "docs/README.md", mode: 0o644, content: "readme"},
					{name: "bin/idsec-darwin", mode: 0o755, content: payload},
				})
			},
			assetURL:        "https://example.com/idsec_1.0.0_darwin_arm64.tar.gz",
			expectedPayload: payload,
		},
		{
			name: "signature_files_are_not_selected",
			asset: func(t *testing.T) []byte {
				return buildTarGz(t, []archiveFile{
					{name: "idsec-darwin.sig", mode: 0o644, content: "signature"},
					{name: "LICENSE.txt", mode: 0o644, content: "license"},
					{name: "idsec-darwin", mode: 0o755, content: payload},
				})
			},
			assetURL:        "https://example.com/idsec_1.0.0_darwin_arm64.tar.gz",
			expectedPayload: payload,
		},
		{
			name: "uncompressed_asset_is_the_executable",
			asset: func(_ *testing.T) []byte {
				return []byte(payload)
			},
			assetURL:        "https://example.com/idsec_1.0.0_darwin_arm64",
			expectedPayload: payload,
		},
		{
			name: "archive_without_executable_is_an_error",
			asset: func(t *testing.T) []byte {
				return buildTarGz(t, []archiveFile{
					{name: "LICENSE.txt", mode: 0o644, content: "license"},
					{name: "README.md", mode: 0o644, content: "readme"},
				})
			},
			assetURL:      "https://example.com/idsec_1.0.0_darwin_arm64.tar.gz",
			expectedError: true,
		},
		{
			name: "corrupt_archive_is_an_error",
			asset: func(_ *testing.T) []byte {
				return []byte("not a gzip stream")
			},
			assetURL:      "https://example.com/idsec_1.0.0_darwin_arm64.tar.gz",
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			reader, err := extractExecutable(tt.asset(t), tt.assetURL)

			if tt.expectedError {
				if err == nil {
					t.Fatal("Expected an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Expected no error, got %v", err)
			}
			got, err := io.ReadAll(reader)
			if err != nil {
				t.Fatalf("Failed reading payload: %v", err)
			}
			if string(got) != tt.expectedPayload {
				t.Errorf("Expected payload %q, got %q", tt.expectedPayload, string(got))
			}
		})
	}
}

func TestChooseExecutable(t *testing.T) {
	tests := []struct {
		name          string
		entries       []archiveEntry
		expectedName  string
		expectedError bool
	}{
		{
			name: "single_executable",
			entries: []archiveEntry{
				{name: "LICENSE.txt"},
				{name: "idsec-darwin", executable: true},
			},
			expectedName: "idsec-darwin",
		},
		{
			name: "project_binary_preferred_over_other_executables",
			entries: []archiveEntry{
				{name: "helper.sh", executable: true},
				{name: "idsec-darwin", executable: true},
			},
			expectedName: "idsec-darwin",
		},
		{
			name: "falls_back_to_first_executable",
			entries: []archiveEntry{
				{name: "helper.sh", executable: true},
				{name: "tool", executable: true},
			},
			expectedName: "helper.sh",
		},
		{
			name: "no_executable_is_an_error",
			entries: []archiveEntry{
				{name: "LICENSE.txt"},
				{name: "README.md"},
			},
			expectedError: true,
		},
		{
			name:          "empty_archive_is_an_error",
			entries:       nil,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			name, err := chooseExecutable(tt.entries)

			if tt.expectedError {
				if err == nil {
					t.Fatal("Expected an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Expected no error, got %v", err)
			}
			if name != tt.expectedName {
				t.Errorf("Expected %q, got %q", tt.expectedName, name)
			}
		})
	}
}
