// Run with go run .scripts/check-guards.go -out .temp/controls-N.
// Each plant runs in a separate source copy; only the expected assertion counts.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type plant struct{ Name, File, Before, After, Test, Witness string }
type result struct {
	Name, File, SourceSHA, Test, Witness string
	Exit                                 int
	Detected                             bool
}

func main() {
	out := flag.String("out", ".temp/controls", "new output directory")
	flag.Parse()
	root, e := os.Getwd()
	must(e)
	dest, e := filepath.Abs(*out)
	must(e)
	if _, e = os.Stat(dest); !os.IsNotExist(e) {
		panic("output must not already exist")
	}
	must(os.MkdirAll(dest, 0700))
	plants := []plant{
		{"drop-key", "nostrtransport/adapter_send.go", "name := sendFileName(req.IdempotencyKey)", "name := sendFileName(req.IdempotencyKey + time.Now().String())", "TestProvisionalConformance/idempotent_retry", "idempotency key retry changed logical event"},
		{"wrap-sender", "nostrtransport/adapter_sync.go", "Sender: PrincipalID(dm.SenderHex)", "Sender: PrincipalID(dm.WrapperHex)", "TestSeamSenderIsSeal", "sender is not authenticated seal signer"},
		{"foreign-reset", "nostrtransport/adapter_sync.go", "c.Identity != a.core.Identity()", "false", "TestProvisionalConformance/foreign_cursor", "foreign cursor reset or used on wire"},
		{"partial-ack", "nostrtransport/adapter_send.go", "if all {", "if all || !all {", "TestSeamPartialRestart", "partial delivery falsely ACKed"},
		{"media-log-leak", "nostrtransport/adapter_media.go", "decodeMedia(ref.Bytes())", "decodeMedia(leakMedia(ref.Bytes()))", "TestProvisionalConformance/media_privacy", "MediaRef marker exposed"},
		{"media-format-leak", "internal/seamprovisional/transport.go", "io.WriteString(s, r.String())", "io.WriteString(s, r.data)", "TestSeamMediaMarker", "MediaRef marker exposed"},
		{"rumor-seal-mismatch", "nostr/nip59.go", "if rumor.PubKey != seal.PubKey {", "if false && rumor.PubKey != seal.PubKey {", "TestProvisionalConformance/unverifiable_sender", "unverifiable sender delivered or not counted"},
		{"oversize", "nostrtransport/adapter_send.go", "len(m.Text) > seamMaxContent", "len(m.Text) > seamMaxContent+1", "TestProvisionalConformance/content_bound", "oversize reached wire or wrong rejection"},
		{"backdate-window", "nostrtransport/adapter_sync.go", "c.Checkpoint-syncWindow", "c.Checkpoint-60", "TestProvisionalConformance/backdated_publish", "backdated event lost after checkpoint"},
		{"cursor-missing-fields", "nostrtransport/adapter_sync.go", "c = seamCursor{}", "// planted: retain initial defaults", "TestSeamCursorGapsAndBounds", "invalid cursor reset or reached wire"},
	}
	var results []result
	all := true
	for _, p := range plants {
		dir := filepath.Join(dest, p.Name)
		must(os.Mkdir(dir, 0700))
		for _, name := range []string{"nostrtransport", "nostr", "relay", "blossom", "transport", "testrelay", "testblossom", "internal", "go.mod", "go.sum"} {
			must(copyTree(filepath.Join(root, name), filepath.Join(dir, name)))
		}
		if p.Name == "media-log-leak" {
			must(os.WriteFile(filepath.Join(dir, "nostrtransport", "plant_media_log.go"), []byte("package nostrtransport\nimport \"log\"\nfunc leakMedia(b []byte)[]byte{log.Printf(\"%s\",b);return b}\n"), 0600))
		}
		path := filepath.Join(dir, p.File)
		raw, e := os.ReadFile(path)
		must(e)
		sum := sha256.Sum256(raw)
		if strings.Count(string(raw), p.Before) != 1 {
			panic("plant match not unique: " + p.Name)
		}
		must(os.WriteFile(path, []byte(strings.Replace(string(raw), p.Before, p.After, 1)), 0600))
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		cmd := exec.CommandContext(ctx, "go", "test", "-count=1", "./nostrtransport", "-run", "^"+p.Test+"$", "-v")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GOWORK=off")
		log, e := cmd.CombinedOutput()
		cancel()
		code := 0
		if e != nil {
			code = 1
			if x, ok := e.(*exec.ExitError); ok {
				code = x.ExitCode()
			}
		}
		detected := code != 0 && strings.Contains(string(log), p.Witness) && !strings.Contains(string(log), "[build failed]")
		all = all && detected
		must(os.WriteFile(filepath.Join(dest, p.Name+".log"), log, 0600))
		results = append(results, result{p.Name, p.File, hex.EncodeToString(sum[:]), p.Test, p.Witness, code, detected})
		fmt.Printf("%s: detected=%t exit=%d\n", p.Name, detected, code)
	}
	raw, e := json.MarshalIndent(results, "", "  ")
	must(e)
	must(os.WriteFile(filepath.Join(dest, "results.json"), raw, 0600))
	if !all {
		os.Exit(1)
	}
}
func must(e error) {
	if e != nil {
		panic(e)
	}
}
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		rel, e := filepath.Rel(src, p)
		if e != nil {
			return e
		}
		target := filepath.Join(dst, rel)
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink source refused")
		}
		if d.IsDir() {
			return os.MkdirAll(target, 0700)
		}
		raw, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		return os.WriteFile(target, raw, 0600)
	})
}
