package tsync

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"

	zip "github.com/abyii/zip-xxh3"
	"golang.org/x/crypto/nacl/box"
)

// ---------------------------------------------------------
// Shared helpers for path-name tests (also used by the fuzzer)
// ---------------------------------------------------------

var windowsReservedBaseNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true, "COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true, "LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

// isPathExtractableOn reports whether a slash-separated archive path maps 1:1 onto
// a real file path on the given OS. ZIP names with `\`, reserved characters or
// device names are valid archive names but cannot be materialised faithfully on Windows.
func isPathExtractableOn(p, goos string) bool {
	if (goos == "windows" || goos == "darwin") && !utf8.ValidString(p) {
		return false
	}
	if goos != "windows" {
		return true
	}
	for _, comp := range strings.Split(strings.TrimSuffix(p, "/"), "/") {
		if strings.ContainsAny(comp, `\:*?"<>|`) {
			return false
		}
		for i := range len(comp) {
			if comp[i] < 0x20 {
				return false
			}
		}
		if strings.HasSuffix(comp, " ") || strings.HasSuffix(comp, ".") {
			return false
		}
		base, _, _ := strings.Cut(comp, ".")
		if windowsReservedBaseNames[strings.ToUpper(strings.TrimRight(base, " "))] {
			return false
		}
	}
	return true
}

// buildTestZip writes files and directory entries (names ending in "/") into a ZIP
// using the exact names given, optionally ZipCrypto-encrypted with password.
func buildTestZip(t *testing.T, files map[string][]byte, dirs []string, password string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zipw := zip.NewWriter(&buf)
	for _, d := range dirs {
		if _, err := zipw.Create(d, zip.Store, 0, zip.NoEncryption, ""); err != nil {
			t.Fatalf("failed to create dir entry %q: %v", d, err)
		}
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		enc := zip.NoEncryption
		if password != "" {
			enc = zip.StandardEncryption
		}
		w, err := zipw.Create(name, zip.Deflate, -1, enc, password)
		if err != nil {
			t.Fatalf("failed to create zip entry %q: %v", name, err)
		}
		if _, err := w.Write(files[name]); err != nil {
			t.Fatalf("failed to write zip entry %q: %v", name, err)
		}
	}
	if err := zipw.Close(); err != nil {
		t.Fatalf("failed to close zip writer: %v", err)
	}
	return buf.Bytes()
}

// readZipEntries returns the exact file names -> content and directory names
// (without trailing "/") stored in a ZIP archive.
func readZipEntries(t *testing.T, zipBytes []byte, password string) (map[string][]byte, map[string]bool) {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("failed to parse restored zip: %v", err)
	}
	files := make(map[string][]byte)
	dirs := make(map[string]bool)
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "/") {
			dirs[strings.TrimSuffix(f.Name, "/")] = true
			continue
		}
		if _, dup := files[f.Name]; dup {
			t.Fatalf("restored zip contains duplicate entry %q", f.Name)
		}
		if password != "" {
			f.SetPassword(password)
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("failed to open restored entry %q: %v", f.Name, err)
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("failed to read restored entry %q: %v", f.Name, err)
		}
		files[f.Name] = data
	}
	return files, dirs
}

func assertZipFilesEqual(t *testing.T, got, want map[string][]byte) {
	t.Helper()
	for name, data := range want {
		g, ok := got[name]
		if !ok {
			t.Errorf("restored zip is missing entry %q", name)
			continue
		}
		if !bytes.Equal(g, data) {
			t.Errorf("restored zip entry %q content mismatch: got %q, want %q", name, g, data)
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			t.Errorf("restored zip has unexpected entry %q", name)
		}
	}
}

// ---------------------------------------------------------
// Regression tests: backslashes are ordinary name characters
// ---------------------------------------------------------

func TestBackslashNamesZipRoundTrip(t *testing.T) {
	vmPub, vmPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	// `a\b.txt` and `a/b.txt` are distinct archive entries that Windows tools would
	// map to the same file; both must survive byte-exactly.
	files := map[string][]byte{
		`a\b.txt`:                 []byte("top-level name containing a backslash"),
		`a/b.txt`:                 []byte("real directory a"),
		`dir/sub\file.txt`:        []byte("backslash in leaf under a real dir"),
		`dir\with\bs/inner.txt`:   []byte("backslash in a directory component"),
		`\leading.txt`:            []byte("leading backslash"),
		`trailing\`:               []byte("trailing backslash is a file, not a dir"),
		`..\up.txt`:               []byte("dot-dot then backslash"),
		`a\..\..\escape.txt`:      []byte("traversal-looking single component"),
		`.\dot.txt`:               []byte("dot then backslash"),
		`\\server\share\unc.txt`:  []byte("UNC-looking single component"),
		`C:\Windows\drive.txt`:    []byte("drive-letter-looking single component"),
		`nested/deep/x\y\z.bin`:   {0x00, 0x01, 0xff},
		`nested/deep/empty\file`:  {},
	}
	dirs := []string{`empty\bs dir/`, `nest/empty\leaf/`}
	wantDirs := map[string]bool{`empty\bs dir`: true, `nest/empty\leaf`: true}

	cases := []struct {
		name      string
		encrypted bool
	}{
		{"UnencryptedZipSource", false},
		{"EncryptedZipSource", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			opts := BackupOptions{
				Label:      "backslash-names",
				KeyID:      "key-1",
				PublicKeys: map[string][]byte{"key-1": vmPub[:]},
			}
			srcPass := ""
			if tc.encrypted {
				srcPass, _ = GenerateZipCryptoPassword()
				opts.EphPublicKey, opts.EncryptedPassword, err = EncryptPassword(srcPass, vmPub[:])
				if err != nil {
					t.Fatalf("failed to encrypt source password: %v", err)
				}
			}

			srcStore := NewMemStorage()
			_ = srcStore.Write(ctx, "src.zip", buildTestZip(t, files, dirs, srcPass))
			destStore := NewMemStorage()
			client := NewClient(destStore)

			v1, err := client.Backup(ctx, NewZipFileSource(srcStore, "src.zip", tc.encrypted), opts)
			if err != nil {
				t.Fatalf("backup of zip with backslash names failed: %v", err)
			}

			// Second version adds one more entry; deleting v1 + GC walks every tree
			// through walkCollect, which validates names too.
			files2 := map[string][]byte{`v2\added.txt`: []byte("only in v2")}
			for k, v := range files {
				files2[k] = v
			}
			_ = srcStore.Write(ctx, "src.zip", buildTestZip(t, files2, dirs, srcPass))
			v2, err := client.Backup(ctx, NewZipFileSource(srcStore, "src.zip", tc.encrypted), opts)
			if err != nil {
				t.Fatalf("second backup failed: %v", err)
			}
			if err := client.DeleteVersion(ctx, v1.SnowflakeId); err != nil {
				t.Fatalf("DeleteVersion failed: %v", err)
			}
			if err := client.GC(ctx); err != nil {
				t.Fatalf("GC failed: %v", err)
			}

			listed, err := client.ListFiles(ctx, v2.SnowflakeId)
			if err != nil {
				t.Fatalf("ListFiles failed: %v", err)
			}
			listedSet := make(map[string]bool, len(listed))
			for _, p := range listed {
				listedSet[p] = true
			}
			for name := range files2 {
				if !listedSet[name] {
					t.Errorf("ListFiles is missing %q", name)
				}
			}

			for _, newPass := range []string{"", "rekeyed-pass"} {
				var out bytes.Buffer
				if err := client.Restore(ctx, v2.SnowflakeId, RestoreOptions{
					ZipWriter:   &out,
					PrivateKey:  vmPriv[:],
					NewPassword: newPass,
				}); err != nil {
					t.Fatalf("restore to zip (newPass=%q) failed: %v", newPass, err)
				}
				gotFiles, gotDirs := readZipEntries(t, out.Bytes(), newPass)
				assertZipFilesEqual(t, gotFiles, files2)
				for d := range wantDirs {
					if !gotDirs[d] {
						t.Errorf("restored zip (newPass=%q) is missing empty dir %q", newPass, d)
					}
				}
				if len(gotDirs) != len(wantDirs) {
					t.Errorf("restored zip (newPass=%q) dirs = %v, want %v", newPass, gotDirs, wantDirs)
				}
			}
		})
	}
}

func TestBackslashNamesExtractDir(t *testing.T) {
	vmPub, vmPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}
	ctx := context.Background()

	backupFiles := func(t *testing.T, files map[string][]byte) (*Client, uint64) {
		t.Helper()
		srcStore := NewMemStorage()
		for name, data := range files {
			_ = srcStore.Write(ctx, name, data)
		}
		client := NewClient(NewMemStorage())
		v, err := client.Backup(ctx, NewFolderSource(srcStore, ""), BackupOptions{
			Label:      "extract-backslash",
			KeyID:      "key-1",
			PublicKeys: map[string][]byte{"key-1": vmPub[:]},
		})
		if err != nil {
			t.Fatalf("backup failed: %v", err)
		}
		return client, v.SnowflakeId
	}

	t.Run("TraversalLookingNameNeverEscapesExtractDir", func(t *testing.T) {
		client, vid := backupFiles(t, map[string][]byte{`..\up.txt`: []byte("must stay inside")})
		parent := t.TempDir()
		extractDir := filepath.Join(parent, "out")

		rErr := client.Restore(ctx, vid, RestoreOptions{ExtractDir: extractDir, PrivateKey: vmPriv[:]})

		if _, statErr := os.Stat(filepath.Join(parent, "up.txt")); statErr == nil {
			t.Fatalf("restore wrote outside ExtractDir")
		}
		if runtime.GOOS == "windows" {
			if rErr == nil || !strings.Contains(rErr.Error(), "directory traversal") {
				t.Fatalf("expected directory traversal error on Windows, got %v", rErr)
			}
			return
		}
		if rErr != nil {
			t.Fatalf("restore failed: %v", rErr)
		}
		data, err := os.ReadFile(filepath.Join(extractDir, `..\up.txt`))
		if err != nil || string(data) != "must stay inside" {
			t.Fatalf("expected literal file %q in ExtractDir: err=%v data=%q", `..\up.txt`, err, data)
		}
	})

	t.Run("BackslashIsSeparatorOnlyOnWindows", func(t *testing.T) {
		client, vid := backupFiles(t, map[string][]byte{`a\b.txt`: []byte("payload")})
		extractDir := t.TempDir()
		if err := client.Restore(ctx, vid, RestoreOptions{ExtractDir: extractDir, PrivateKey: vmPriv[:]}); err != nil {
			t.Fatalf("restore failed: %v", err)
		}
		want := filepath.Join(extractDir, `a\b.txt`) // literal name on Unix
		if runtime.GOOS == "windows" {
			want = filepath.Join(extractDir, "a", "b.txt")
		}
		data, err := os.ReadFile(want)
		if err != nil || string(data) != "payload" {
			t.Fatalf("expected %s to contain payload: err=%v data=%q", want, err, data)
		}
	})

	t.Run("DotDotPrefixedNamesAreNotTraversal", func(t *testing.T) {
		files := map[string][]byte{
			"..a.txt":       []byte("file starting with two dots"),
			"..cfg/x.txt":   []byte("dir starting with two dots"),
			"..cfg/..b.txt": []byte("nested two-dot file"),
		}
		client, vid := backupFiles(t, files)
		extractDir := t.TempDir()
		if err := client.Restore(ctx, vid, RestoreOptions{ExtractDir: extractDir, PrivateKey: vmPriv[:]}); err != nil {
			t.Fatalf("restore of '..'-prefixed names failed: %v", err)
		}
		for name, want := range files {
			got, err := os.ReadFile(filepath.Join(extractDir, filepath.FromSlash(name)))
			if err != nil || !bytes.Equal(got, want) {
				t.Errorf("restored %q mismatch: err=%v got=%q", name, err, got)
			}
		}
	})
}
