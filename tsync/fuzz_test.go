package tsync

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"fmt"
	"io"
	mrand "math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	zip "github.com/abyii/zip-xxh3"
	"golang.org/x/crypto/nacl/box"
)

// ---------------------------------------------------------
// Fuzzer State Machine & Property-Based Test Engine
// ---------------------------------------------------------

type oracleVersionSnapshot struct {
	files     map[string][]byte // Path -> Expected byte content
	emptyDirs map[string]bool   // DirPath -> Expected directory existence
}

func (s *oracleVersionSnapshot) clone() oracleVersionSnapshot {
	cpFiles := make(map[string][]byte, len(s.files))
	for k, v := range s.files {
		dataCp := make([]byte, len(v))
		copy(dataCp, v)
		cpFiles[k] = dataCp
	}
	cpDirs := make(map[string]bool, len(s.emptyDirs))
	for k, v := range s.emptyDirs {
		cpDirs[k] = v
	}
	return oracleVersionSnapshot{
		files:     cpFiles,
		emptyDirs: cpDirs,
	}
}

// TestTsyncFuzzStateMachine runs a deterministic randomized state-machine test loop
func TestTsyncFuzzStateMachine(t *testing.T) {
	seeds := []int64{1, 42, 1337, 20260824, 999999}
	for _, seed := range seeds {
		t.Run(fmt.Sprintf("Seed_%d", seed), func(t *testing.T) {
			runFuzzEngine(t, seed, 25)
		})
	}
}

// FuzzTsyncSDK exposes the state-machine fuzzer to Go standard fuzzing engine
func FuzzTsyncSDK(f *testing.F) {
	f.Add(int64(12345), 15)
	f.Add(int64(98765), 20)

	f.Fuzz(func(t *testing.T, seed int64, stepCount int) {
		if stepCount <= 0 {
			stepCount = 10
		}
		if stepCount > 40 {
			stepCount = 40
		}
		runFuzzEngine(t, seed, stepCount)
	})
}

func runFuzzEngine(t *testing.T, seed int64, totalSteps int) {
	t.Helper()
	rng := mrand.New(mrand.NewSource(seed))
	ctx := context.Background()

	// Keys
	vmPub, vmPriv, err := box.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatalf("fuzz: failed to generate box keypair: %v", err)
	}

	srcStore := NewMemStorage()
	destStore := NewMemStorage()
	client := NewClient(destStore)

	// State Machine Tracking
	activeVersionIDs := make([]uint64, 0)
	versionSnapshots := make(map[uint64]oracleVersionSnapshot)
	currentSourceSnapshot := oracleVersionSnapshot{
		files:     make(map[string][]byte),
		emptyDirs: make(map[string]bool),
	}

	// Helper to generate a random path (including deep paths up to 100 levels)
	genRandomPath := func(forceDeep bool) string {
		if forceDeep || rng.Intn(4) == 0 {
			// Generate deep tree depth up to 100 levels
			depth := rng.Intn(95) + 5 // 5 to 100 depth
			var parts []string
			for i := 1; i <= depth; i++ {
				parts = append(parts, fmt.Sprintf("d%02d", i))
			}
			parts = append(parts, fmt.Sprintf("leaf_%d.txt", rng.Intn(100)))
			return strings.Join(parts, "/")
		}

		prefixes := []string{"", "docs/", "sub/folder/", "nested/deep/", ".config/", "space dir/"}
		p := prefixes[rng.Intn(len(prefixes))]
		names := []string{"file.txt", "data.bin", ".gitkeep", "image.png", "notes.md", "app.log"}
		return p + fmt.Sprintf("%d_%s", rng.Intn(50), names[rng.Intn(len(names))])
	}

	// Seed initial source files
	for i := 0; i < 5; i++ {
		p := genRandomPath(false)
		payload := []byte(fmt.Sprintf("initial seed payload %d", i))
		_ = srcStore.Write(ctx, p, payload)
		currentSourceSnapshot.files[p] = payload
	}
	// Initial empty directory (deep 100-level path)
	var deepParts []string
	for d := 1; d <= 100; d++ {
		deepParts = append(deepParts, fmt.Sprintf("level%03d", d))
	}
	deepDirPath := strings.Join(deepParts, "/") + "/"
	_ = srcStore.Write(ctx, deepDirPath, []byte(""))
	currentSourceSnapshot.emptyDirs[strings.TrimSuffix(deepDirPath, "/")] = true

	for step := 1; step <= totalSteps; step++ {
		opChoice := rng.Intn(100)

		if len(activeVersionIDs) == 0 || opChoice < 50 {
			// ---------------------------------------------------------
			// ACTION: BACKUP
			// ---------------------------------------------------------
			// Mutate source state randomly
			mutationCount := rng.Intn(4) + 1
			for m := 0; m < mutationCount; m++ {
				action := rng.Intn(3)
				switch action {
				case 0: // Add or edit file
					p := genRandomPath(rng.Intn(5) == 0)
					var data []byte
					sizeKind := rng.Intn(6)
					switch sizeKind {
					case 0: // 0-byte file
						data = []byte("")
					case 1: // 1-byte file
						data = []byte{byte(rng.Intn(256))}
					case 2: // 2-byte file
						data = []byte{byte(rng.Intn(256)), byte(rng.Intn(256))}
					case 3: // Tiny file (3–15 bytes)
						data = make([]byte, rng.Intn(13)+3)
						rng.Read(data)
					case 4: // Small string payload (30-35 B)
						data = []byte(fmt.Sprintf("small payload %d", rng.Int63()))
					case 5: // Medium file (30 KB)
						data = bytes.Repeat([]byte{byte(rng.Intn(256))}, 30*1024)
					}
					_ = srcStore.Write(ctx, p, data)
					currentSourceSnapshot.files[p] = data
				case 1: // Create empty directory
					depth := rng.Intn(95) + 5
					var parts []string
					for k := 1; k <= depth; k++ {
						parts = append(parts, fmt.Sprintf("dir_lvl%d", k))
					}
					dPath := strings.Join(parts, "/") + "/"
					_ = srcStore.Write(ctx, dPath, []byte(""))
					currentSourceSnapshot.emptyDirs[strings.TrimSuffix(dPath, "/")] = true
				case 2: // Delete existing file or empty dir
					if len(currentSourceSnapshot.files) > 0 {
						var toDelete string
						for k := range currentSourceSnapshot.files {
							toDelete = k
							break
						}
						_ = srcStore.Delete(ctx, toDelete)
						delete(currentSourceSnapshot.files, toDelete)
					}
				}
			}

			// Randomize Backup Source
			srcType := rng.Intn(3) // 0: FolderSource, 1: ZipSource (Unencrypted), 2: ZipSource (Encrypted)
			var source Source
			var clearZipPass string
			var ephPub []byte
			var encPass []byte

			if srcType == 0 {
				source = NewFolderSource(srcStore, "")
			} else {
				// Construct ZIP Source
				var zipBuf bytes.Buffer
				zipw := zip.NewWriter(&zipBuf)
				isEnc := (srcType == 2)
				if isEnc {
					clearZipPass, _ = GenerateZipCryptoPassword()
					ephPub, encPass, _ = EncryptPassword(clearZipPass, vmPub[:])
				}

				files, _ := srcStore.List(ctx, "")
				for _, f := range files {
					if f.Name == "fuzz_archive.zip" {
						continue
					}
					isDir := strings.HasSuffix(f.Name, "/")
					if isDir {
						_, _ = zipw.Create(f.Name, zip.Store, 0, zip.NoEncryption, "")
					} else {
						data, _ := srcStore.Read(ctx, f.Name)
						var w io.Writer
						var err error
						if isEnc {
							w, err = zipw.Create(f.Name, zip.Deflate, -1, zip.StandardEncryption, clearZipPass)
						} else {
							w, err = zipw.Create(f.Name, zip.Deflate, -1, zip.NoEncryption, "")
						}
						if err == nil && w != nil {
							_, _ = w.Write(data)
						}
					}
				}
				_ = zipw.Close()
				zipStore := NewMemStorage()
				_ = zipStore.Write(ctx, "fuzz_archive.zip", zipBuf.Bytes())
				source = NewZipFileSource(zipStore, "fuzz_archive.zip", isEnc)
			}

			// Randomize Backup Options
			useEncryption := rng.Intn(2) == 1
			singleVersion := rng.Intn(4) == 0 // 25% chance of Single Version Mode
			concurrency := rng.Intn(4) + 1
			compLevel := rng.Intn(11) - 1 // -1 to 9

			bOpts := BackupOptions{
				Label:             fmt.Sprintf("fuzz-v-step%d", step),
				Concurrency:       concurrency,
				SingleVersionMode: singleVersion,
				EphPublicKey:      ephPub,
				EncryptedPassword: encPass,
			}
			bOpts.PublicKeys = map[string][]byte{"fuzz-key-1": vmPub[:]}
			if useEncryption {
				bOpts.KeyID = "fuzz-key-1"
			}

			if compLevel >= 0 {
				bOpts.GetCompressionLevel = func(path string) *int {
					lvl := compLevel
					return &lvl
				}
			}

			v, backupErr := client.Backup(ctx, source, bOpts)
			if backupErr != nil {
				t.Fatalf("fuzz step %d: Backup failed: %v", step, backupErr)
			}

			if singleVersion {
				// Single version mode purges prior version records
				activeVersionIDs = []uint64{v.SnowflakeId}
				versionSnapshots = make(map[uint64]oracleVersionSnapshot)
				versionSnapshots[v.SnowflakeId] = currentSourceSnapshot.clone()
			} else {
				activeVersionIDs = append(activeVersionIDs, v.SnowflakeId)
				versionSnapshots[v.SnowflakeId] = currentSourceSnapshot.clone()
			}

		} else if opChoice < 80 {
			// ---------------------------------------------------------
			// ACTION: RESTORE (ExtractDir, ZipWriter, or Rekeyed Zip)
			// ---------------------------------------------------------
			targetVer := activeVersionIDs[rng.Intn(len(activeVersionIDs))]
			snapshot := versionSnapshots[targetVer]

			restoreType := rng.Intn(3) // 0: ExtractDir, 1: ZipWriter, 2: Rekeyed Zip
			switch restoreType {
			case 0:
				tmpDir, err := os.MkdirTemp("", "fuzz-restore-*")
				if err != nil {
					t.Fatalf("fuzz step %d: failed to create temp dir: %v", step, err)
				}
				defer safeRemoveAll(tmpDir)

				rErr := client.Restore(ctx, targetVer, RestoreOptions{
					ExtractDir: tmpDir,
					PrivateKey: vmPriv[:],
				})
				if rErr != nil {
					t.Fatalf("fuzz step %d: Restore to ExtractDir failed for version %d: %v", step, targetVer, rErr)
				}

				// Assert all files in oracle match restored files
				for relPath, expectedData := range snapshot.files {
					fullP := filepath.Join(tmpDir, filepath.FromSlash(relPath))
					restoredBytes, rErr := os.ReadFile(fullP)
					if rErr != nil {
						t.Fatalf("fuzz step %d: restored file %s missing: %v", step, relPath, rErr)
					}
					if !bytes.Equal(restoredBytes, expectedData) {
						t.Fatalf("fuzz step %d: restored file %s content mismatch: got %d bytes, expected %d bytes", step, relPath, len(restoredBytes), len(expectedData))
					}
				}

				// Assert empty directories exist on disk
				for relDir := range snapshot.emptyDirs {
					fullD := filepath.Join(tmpDir, filepath.FromSlash(relDir))
					fi, statErr := os.Stat(fullD)
					if statErr != nil || !fi.IsDir() {
						t.Fatalf("fuzz step %d: expected empty directory %s missing or not a directory: %v", step, relDir, statErr)
					}
				}

			case 1: // Unencrypted ZipWriter
				var zipBuf bytes.Buffer
				rErr := client.Restore(ctx, targetVer, RestoreOptions{
					ZipWriter:  &zipBuf,
					PrivateKey: vmPriv[:],
				})
				if rErr != nil {
					t.Fatalf("fuzz step %d: Restore to ZipWriter failed for version %d: %v", step, targetVer, rErr)
				}
				verifyZipExplorerExtractable(t, zipBuf.Bytes(), "")

			case 2: // Rekeyed Encrypted ZipWriter
				var encZipBuf bytes.Buffer
				newPass := fmt.Sprintf("fuzzPass_%d_%d", step, rng.Intn(10000))
				rErr := client.Restore(ctx, targetVer, RestoreOptions{
					ZipWriter:   &encZipBuf,
					PrivateKey:  vmPriv[:],
					NewPassword: newPass,
				})
				if rErr != nil {
					t.Fatalf("fuzz step %d: Restore to rekeyed ZipWriter failed for version %d: %v", step, targetVer, rErr)
				}
				verifyZipExplorerExtractable(t, encZipBuf.Bytes(), newPass)
			}

		} else if opChoice < 90 && len(activeVersionIDs) > 1 {
			// ---------------------------------------------------------
			// ACTION: DELETE VERSION
			// ---------------------------------------------------------
			idxToDelete := rng.Intn(len(activeVersionIDs))
			verToDelete := activeVersionIDs[idxToDelete]

			delErr := client.DeleteVersion(ctx, verToDelete)
			if delErr != nil {
				t.Fatalf("fuzz step %d: DeleteVersion failed for version %d: %v", step, verToDelete, delErr)
			}

			// Remove from state tracking
			activeVersionIDs = append(activeVersionIDs[:idxToDelete], activeVersionIDs[idxToDelete+1:]...)
			delete(versionSnapshots, verToDelete)

			// Verify remaining versions are still extractable
			if len(activeVersionIDs) > 0 {
				remVer := activeVersionIDs[rng.Intn(len(activeVersionIDs))]
				var remBuf bytes.Buffer
				rErr := client.Restore(ctx, remVer, RestoreOptions{
					ZipWriter:  &remBuf,
					PrivateKey: vmPriv[:],
				})
				if rErr != nil {
					t.Fatalf("fuzz step %d: restore of version %d failed after deleting version %d: %v", step, remVer, verToDelete, rErr)
				}
				verifyZipExplorerExtractable(t, remBuf.Bytes(), "")
			}

		} else {
			// ---------------------------------------------------------
			// ACTION: GARBAGE COLLECTION (GC)
			// ---------------------------------------------------------
			orphanKey := fmt.Sprintf("%02x/%08x_12345", rng.Intn(256), rng.Uint32())
			_ = destStore.Write(ctx, orphanKey, []byte("fake orphan data"))

			gcErr := client.GC(ctx)
			if gcErr != nil {
				t.Fatalf("fuzz step %d: GC failed: %v", step, gcErr)
			}

			exists, _ := destStore.Exists(ctx, orphanKey)
			if exists {
				t.Fatalf("fuzz step %d: orphaned part %s was not cleaned up by GC", step, orphanKey)
			}
		}
	}
}

func TestTsyncZip64LargeFileCountBoundary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 65.5k file boundary test in short mode")
	}

	ctx := context.Background()
	srcStore := NewMemStorage()

	// Generate 65,540 entries (exceeding standard ZIP 65,535 entry limit)
	totalFiles := 65540
	for i := 0; i < totalFiles; i++ {
		p := fmt.Sprintf("batch_%02d/file_%05d.txt", i/1000, i)
		_ = srcStore.Write(ctx, p, []byte("x"))
	}

	destStore := NewMemStorage()
	client := NewClient(destStore)

	vmPub, vmPriv, err := box.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	// Run Backup
	v, err := client.Backup(ctx, NewFolderSource(srcStore, ""), BackupOptions{
		Label:       "zip64-65k-boundary",
		KeyID:       "key-65k",
		PublicKeys:  map[string][]byte{"key-65k": vmPub[:]},
		Concurrency: 8,
	})
	if err != nil {
		t.Fatalf("backup failed for 65.5k files: %v", err)
	}

	// Restore to ZIP
	var zipBuf bytes.Buffer
	err = client.Restore(ctx, v.SnowflakeId, RestoreOptions{
		ZipWriter:  &zipBuf,
		PrivateKey: vmPriv[:],
	})
	if err != nil {
		t.Fatalf("restore to zip failed for 65.5k files: %v", err)
	}

	zipBytes := zipBuf.Bytes()
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("failed to parse restored 65.5k zip: %v", err)
	}

	if len(zr.File) != totalFiles {
		t.Fatalf("expected restored zip to contain %d files, got %d", totalFiles, len(zr.File))
	}
}

func safeRemoveAll(dir string) {
	if dir == "" {
		return
	}
	for i := 0; i < 5; i++ {
		err := os.RemoveAll(dir)
		if err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}
