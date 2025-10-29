//go:build windows
// +build windows

package cim

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/backuptar"
	"github.com/Microsoft/go-winio/vhd"
	"github.com/Microsoft/hcsshim/internal/log"
	//"github.com/Microsoft/hcsshim/internal/layers"
	"github.com/Microsoft/hcsshim/internal/longpath"
	"github.com/Microsoft/hcsshim/computestorage"
	"golang.org/x/sys/windows"
)

const tombstonePath = `Windows\container_tombstones.json`
const WhiteoutPrefix = ".wh."

type sandboxTombstones struct {
	UnionId string `json:unionId`
	TombstonePaths [][]interface{} `json:tombstonepaths`
}

func openFileOrDir(path string, mode uint32, createDisposition uint32) (file *os.File, err error) {
	return winio.OpenForBackup(path, mode, syscall.FILE_SHARE_READ, createDisposition)
}

func ExportSandboxVHDToTar(ctx context.Context, w io.Writer, vhdPath string) error {
	root, err := os.MkdirTemp(os.TempDir(), "hcs-mount")
	if err != nil {
		return err
	}
	root += "\\"
	defer func() {
		if err := os.Remove(root); err != nil && !os.IsNotExist(err) {
			log.G(ctx).WithError(err).WithField("root", root).Error("failed to remove temp mount dir")
		}
	}()

	const openFlags = vhd.OpenVirtualDiskFlagCachedIO|vhd.OpenVirtualDiskFlagIgnoreRelativeParentLocator
	handle, err := vhd.OpenVirtualDisk(vhdPath, vhd.VirtualDiskAccessNone, openFlags)
	if err != nil {
		return fmt.Errorf("failed to open VHD: %w", err)
	}
	defer syscall.CloseHandle(handle)

	attachParams := vhd.AttachVirtualDiskParameters{Version: 2}
	err = vhd.AttachVirtualDisk(handle, vhd.AttachVirtualDiskFlagReadOnly, &attachParams)
	if err != nil {
		return fmt.Errorf("failed to attach VHD: %w", err)
	}
	defer func() {
		if err := vhd.DetachVirtualDisk(handle); err != nil  {
			log.G(ctx).WithError(err).WithField("vhd", vhdPath).Error("failed to detach sandbox VHD")
		}
	}()

	volumePath, err := computestorage.GetLayerVhdMountPath(ctx, windows.Handle(handle))
	if err != nil {
		return fmt.Errorf("failed to get VHD mount path: %w", err)
	}

	//if err := layers.MountSandboxVolume(ctx, root, volumePath); err != nil {
	//	return fmt.Errorf("failed to mount sandbox: %w", err)
	//}

	newRoot, err := longpath.LongAbs(volumePath)
	if err != nil {
		return fmt.Errorf("failed to convert to long path: %w", err)
	}
	newRoot += "\\"

	//panic(root)
	
//	defer func() {
//		if err := layers.RemoveSandboxMountPoint(ctx, root); err != nil {
//			log.G(ctx).WithError(err).WithField("vhd", vhdPath).WithField("root", root).Error("failed to remove sandbox mount")
//		}
//	}()

	return writeSandboxVolumeToTar(ctx, w, newRoot)
}

func writeSandboxVolumeToTar(ctx context.Context, w io.Writer, root string) error {
	tw := tar.NewWriter(w)

	err := winio.RunWithPrivileges([]string{winio.SeBackupPrivilege, winio.SeSecurityPrivilege}, func() error {

		// parse and write tombstones
		volumeTombstone := ""
		if tombstoneFile, err := os.Open(filepath.Join(root, tombstonePath)); err == nil {
			if err = func() error {
				defer tombstoneFile.Close()

				var tombstones sandboxTombstones
				err = json.NewDecoder(tombstoneFile).Decode(&tombstones)
				if err != nil {
					return fmt.Errorf("failed to parse tombstones: %w")
				}

				volumeTombstone = fmt.Sprintf(`System Volume Information\{%s}_Tombstones.bin`, tombstones.UnionId)
				for _, ts := range tombstones.TombstonePaths {
					if len(ts) < 1 {
						return fmt.Errorf("tombstone file has no paths")
					}
					path, ok := ts[0].(string)
					if !ok {
						return fmt.Errorf("tombstone file malformed: %v", ts[0])
					}

					whiteoutPath := fmt.Sprintf("%s/%s%s", filepath.Dir(path), WhiteoutPrefix, filepath.Base(path))

					// write a whiteout file
					hdr := &tar.Header{
						Name: filepath.ToSlash(whiteoutPath),
					}
					err = tw.WriteHeader(hdr)
					if err != nil {
						return err
					}
				}

				return nil
			}(); err != nil {
				return err
			}
		}

		return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			// Indirect fix for https://github.com/moby/moby/issues/32838#issuecomment-343610048.
			// Handle failure from what may be a golang bug in the conversion of
			// UTF16 to UTF8 in files which are left in the recycle bin. Os.Lstat
			// which is called by filepath.Walk will fail when a filename contains
			// unicode characters. Skip the recycle bin regardless which is goodness.
			if strings.EqualFold(path, filepath.Join(root, `Files\$Recycle.Bin`)) && info.IsDir() {
				return filepath.SkipDir
			}

			if path == root {
				return nil
			}

			// Rebase path
			relPath, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}

			// skip tombstone paths
			if relPath == tombstonePath || relPath == volumeTombstone {
				return nil
			}


			f, err := openFileOrDir(path, syscall.GENERIC_READ, syscall.OPEN_EXISTING)
			if err != nil {
				return err
			}
			defer f.Close()

			fileInfo, err := winio.GetFileBasicInfo(f)
			if err != nil {
				return err
			}

			bfr := winio.NewBackupFileReader(f, false)
			defer bfr.Close()

			///TODO(mendsley) handle links???

			err = backuptar.WriteTarFileFromBackupStream(tw, bfr, relPath, info.Size(), fileInfo)
			if err != nil {
				return err
			}

			return nil
		})
	})
	if err != nil {
		return err
	}

	return tw.Close()
}

// Import a CIM layer from a sandbox VHDX
func ImportCimLayerFromSandboxVHD(ctx context.Context, vhdPath string, layerPath, cimPath string, parentLayerPaths, parentLayerCimPaths []string) (_ int64, err error) {
	pr, pw := io.Pipe()
	defer pr.Close()
	start := time.Now()
	go func() {
		err := ExportSandboxVHDToTar(ctx, pw, vhdPath)
		end := time.Now()
		pw.CloseWithError(err)
		log.G(ctx).Warnf("EXPORT TOOK %v", float64(end.Sub(start))/float64(time.Millisecond))
	}()

	cimSize, err := ImportCimLayerFromTar(ctx, pr, layerPath, cimPath, parentLayerPaths, parentLayerCimPaths)
	if err != nil {
		return 0, err
	}

	end := time.Now()

	log.G(ctx).Warnf("Imported %d bytes to CIM: %v", cimSize, float64(end.Sub(start))/float64(time.Millisecond))
	return cimSize, nil
}

