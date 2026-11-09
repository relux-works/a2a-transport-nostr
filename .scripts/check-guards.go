// Run with go run .scripts/check-guards.go -out .temp/controls-N.
// Each plant runs in a separate source copy; only the expected assertion counts.
package main

import (
	"bytes"
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
		{"principal-hook-missing", "nostrtransport/adapter_test.go", "PrincipalReferences:    w.principalReferences", "PrincipalReferences:    nil", "TestConformanceReferenceHooks", "missing PrincipalReferences hook"},
		{"conversation-hook-missing", "nostrtransport/adapter_test.go", "ConversationReferences: w.conversationReferences", "ConversationReferences: nil", "TestConformanceReferenceHooks", "missing ConversationReferences hook"},
		{"principal-hook-valid-twice", "nostrtransport/adapter_conformance_test.go", "return w.b.core.Identity(), unsupportedNpub", "return w.b.core.Identity(), w.b.core.Identity()", "TestUpstreamConformance/addressing/principal_references", "invalid principal reference accepted"},
		{"conversation-hook-valid-twice", "nostrtransport/adapter_conformance_test.go", "return string(w.conv), \"{}\"", "return string(w.conv), string(w.conv)", "TestUpstreamConformance/addressing/conversation_references", "invalid conversation reference accepted"},
		{"stored-duplicate", "nostrtransport/adapter_send.go", "ok.Original && ok.Stored()", "ok.Original && ok.Accepted", "TestSeamDuplicateRecovery/false-duplicate", "stored duplicate did not ACK original event"},
		{"drop-key", "nostrtransport/adapter_send.go", "name := sendFileName(req.IdempotencyKey)", "req.IdempotencyKey += time.Now().String(); name := sendFileName(req.IdempotencyKey)", "TestUpstreamConformance/send_idempotency", "idempotency key retry created a second logical event"},
		{"wrap-sender", "nostrtransport/adapter_sync.go", "Sender: PrincipalID(dm.SenderHex)", "Sender: PrincipalID(dm.WrapperHex)", "TestSeamSenderIsSeal", "sender is not authenticated seal signer"},
		{"foreign-reset", "nostrtransport/adapter_sync.go", "c.Identity != a.core.Identity()", "false", "TestUpstreamConformance/cursors", "foreign or invalid cursor accepted"},
		{"partial-ack", "nostrtransport/adapter_send.go", "if all {", "if all || !all {", "TestSeamPartialRestart", "partial delivery falsely ACKed"},
		{"media-log-leak", "nostrtransport/adapter_media.go", "decodeMedia([]byte(ref.Opaque()))", "decodeMedia(leakMedia([]byte(ref.Opaque())))", "TestUpstreamConformance/media_redaction_errors", "received marker in log"},
		{"rumor-seal-mismatch", "nostr/nip59.go", "if rumor.PubKey != seal.PubKey {", "if false && rumor.PubKey != seal.PubKey {", "TestUpstreamConformance/unverifiable_sender", "unverifiable sender delivered"},
		{"oversize", "nostrtransport/adapter_send.go", "len(raw) > seamMaxContent", "len(raw) > seamMaxContent+1", "TestUpstreamConformance/bounds", "oversize content must be refused with zero wire calls"},
		{"backdate-window", "nostrtransport/adapter_sync.go", "c.Checkpoint-syncWindow", "c.Checkpoint-60", "TestUpstreamConformance/resume_backdated_history", "want exactly one"},
		{"history-missing-fields", "nostrtransport/adapter_sync.go", "h.Version != 1 || h.Identity != a.core.Identity() || h.Conversation != c || h.Offset < 1 || h.Offset >= len(h.IDs) || h.IDs == nil", "false", "TestSeamHistoryMissingFields", "incomplete history cursor accepted or used on wire"},
		{"explicit-recipient", "nostrtransport/adapter_send.go", "if len(to) == 0 {", "if true {", "TestSeamExplicitRecipients", "explicit To delivered to excluded party or lost self"},
		{"raw-bound", "nostrtransport/adapter_sync.go", "len(raw) > maxRawBytes", "false && len(raw) > maxRawBytes", "TestSeamRawLimitPositiveNeighbor", "oversized received wrap not refused at raw bound"},
		{"cursor-missing-fields", "nostrtransport/adapter_sync.go", "c = seamCursor{}", "// planted: retain initial defaults", "TestSeamCursorGapsAndBounds", "invalid cursor reset or reached wire"},
	}
	var results []result
	all := true
	for _, p := range plants {
		dir := filepath.Join(dest, p.Name)
		must(os.Mkdir(dir, 0700))
		for _, name := range []string{"nostrtransport", "nostr", "relay", "blossom", "transport", "testrelay", "testblossom", "go.mod", "go.sum"} {
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
		var output bytes.Buffer
		cmd.Stdout, cmd.Stderr = &output, &output
		must(cmd.Start())
		pid := cmd.Process.Pid
		e = cmd.Wait()
		log := append([]byte(fmt.Sprintf("owned test-command PID %d\n", pid)), output.Bytes()...)
		cancel()
		code := 0
		if e != nil {
			code = 1
			if x, ok := e.(*exec.ExitError); ok {
				code = x.ExitCode()
			}
		}
		detected := code == 1 && strings.Contains(string(log), "--- FAIL: "+p.Test) &&
			strings.Contains(string(log), p.Witness) && !strings.Contains(string(log), "[build failed]") &&
			!strings.Contains(string(log), "panic:")
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
