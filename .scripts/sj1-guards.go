// SJ1 JSON controls use Go overlays: no source or live state is modified.
// Run at repository root: go run .scripts/sj1-guards.go -out /absolute/new-dir.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type plant struct{ Name, Module, File, Before, After, Test, Witness, Package string }
type result struct {
	Name, SourceSHA256, MutantSHA256     string
	BaselinePID, PID, BaselineExit, Exit int
	Detected                             bool
}

var plants = []plant{
	{"shared_duplicate", ".", "internal/strictjson/json.go", "!ok || seen[key] ||", "!ok || false ||", "^TestSJ1Guard$", "SJ1 ambiguous JSON admitted", "./internal/strictjson"},
	{"shared_escape", ".", "internal/strictjson/json.go", "bytes.IndexByte(raw[start:d.InputOffset()], '\\\\') >= 0", "false && start >= 0", "^TestSJ1Guard$", "SJ1 ambiguous JSON admitted", "./internal/strictjson"},
	{"typed_map_alias", ".", "internal/strictjson/json.go", "case reflect.Map:", "case reflect.Map:\n return nil\n case reflect.Invalid:", "^TestSJ1Guard$", "typed map alias admitted", "./internal/strictjson"},
	{"event", ".", "nostr/event.go", "strictjson.Unmarshal(raw, &e)", "func() error { _ = strictjson.Unmarshal; return json.Unmarshal(raw, &e) }()", "^TestSJ1EventKeys$", "SJ1 ambiguous event admitted", "./nostr"},
	{"encrypted_inner", ".", "nostr/event.go", "strictjson.Unmarshal(raw, &e)", "func() error { _ = strictjson.Unmarshal; return json.Unmarshal(raw, &e) }()", "^TestSJ1EncryptedKeys$", "SJ1 encrypted JSON not refused at parse layer", "./nostr"},
	{"inbound_envelope", ".", "nostrtransport/adapter.go", "strictjson.Unmarshal(raw, v)", "func() error { _ = strictjson.Unmarshal; return json.Unmarshal(raw, v) }()", "^TestSJ1InboundEnvelope$", "SJ1 ambiguous envelope admitted", "./nostrtransport"},
	{"outgoing_extensions", ".", "internal/strictjson/json.go", "!ok || seen[key] ||", "!ok || false ||", "^TestSJ1OutgoingExtensions$", "SJ1 ambiguous outgoing extension admitted", "./nostrtransport"},
	{"carrier", ".", "nostrtransport/grant_extension.go", "if strictjson.Validate(raw) != nil {\n\t\treturn p,", "if false {\n\t\treturn p,", "^TestSJ1CarrierKeys$", "SJ1 ambiguous carrier admitted", "./nostrtransport"},
	{"durable_retry", ".", "nostrtransport/adapter.go", "strictjson.Unmarshal(raw, v)", "func() error { _ = strictjson.Unmarshal; return json.Unmarshal(raw, v) }()", "^TestSJ1DurableRetry$", "SJ1 corrupt durable retry admitted", "./nostrtransport"},
	{"legacy_send", ".", "nostrtransport/store.go", "strictJSON(raw, &rec)", "json.Unmarshal(raw, &rec)", "^TestSJ1LegacyRecords$", "SJ1 legacy send admitted", "./nostrtransport"},
	{"legacy_cursor", ".", "nostrtransport/store.go", "strictJSON(raw, &c)", "json.Unmarshal(raw, &c)", "^TestSJ1LegacyRecords$", "SJ1 legacy stored cursor admitted", "./nostrtransport"},
	{"explicit_cursor", ".", "nostrtransport/sync.go", "strictJSON(cursor, &c)", "json.Unmarshal(cursor, &c)", "^TestSJ1LegacyRecords$", "SJ1 legacy explicit cursor admitted", "./nostrtransport"},
	{"legacy_conversation", ".", "nostrtransport/transport.go", "strictJSON(id, &c)", "json.Unmarshal(id, &c)", "^TestSJ1LegacyRecords$", "SJ1 legacy conversation admitted", "./nostrtransport"},
	{"batch_prevalidation", ".", "nostrtransport/send.go", "\t\tparsed[recipient] = wrap\n\t}\n\tfor _, recipient := range recipients {\n\t\twrap := parsed[recipient]", "\t\tparsed[recipient] = wrap", "^TestSJ1BatchBeforePublish$", "SJ1 bad batch partially published", "./nostrtransport"},
}

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func hash(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }
func main() {
	out := flag.String("out", "", "new absolute output directory")
	flag.Parse()
	root, e := os.Getwd()
	must(e)
	if !filepath.IsAbs(*out) || flag.NArg() != 0 {
		panic("absolute new output required")
	}
	must(os.Mkdir(*out, 0700))
	var rows []result
	for _, p := range plants {
		module := filepath.Join(root, p.Module)
		source := filepath.Join(module, p.File)
		raw, e := os.ReadFile(source)
		must(e)
		if bytes.Count(raw, []byte(p.Before)) != 1 {
			panic("non-unique plant: " + p.Name)
		}
		mutant := bytes.Replace(raw, []byte(p.Before), []byte(p.After), 1)
		changed := filepath.Join(*out, p.Name+".go")
		must(os.WriteFile(changed, mutant, 0600))
		overlay, _ := json.Marshal(map[string]any{"Replace": map[string]string{source: changed}})
		op := filepath.Join(*out, p.Name+".json")
		must(os.WriteFile(op, overlay, 0600))
		pkg := p.Package
		run := func(plant bool) (int, int, []byte) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			args := []string{"test", "-count=1", "-v", "-run", p.Test}
			name := p.Name + "-baseline.log"
			if plant {
				args = append(args, "-overlay", op)
				name = p.Name + "-plant.log"
			}
			args = append(args, pkg)
			cmd := exec.CommandContext(ctx, "go", args...)
			cmd.Dir = module
			var log bytes.Buffer
			cmd.Stdout = &log
			cmd.Stderr = &log
			must(cmd.Start())
			pid := cmd.Process.Pid
			e := cmd.Wait()
			code := 0
			if e != nil {
				if x, ok := e.(*exec.ExitError); ok {
					code = x.ExitCode()
				} else {
					code = -1
				}
			}
			if ctx.Err() != nil {
				code = -2
			}
			must(os.WriteFile(filepath.Join(*out, name), log.Bytes(), 0600))
			return pid, code, log.Bytes()
		}
		row := result{Name: p.Name, SourceSHA256: hash(raw), MutantSHA256: hash(mutant)}
		var baseline, output []byte
		row.BaselinePID, row.BaselineExit, baseline = run(false)
		if row.BaselineExit != 0 || !bytes.Contains(baseline, []byte("--- PASS:")) {
			panic("baseline not passing: " + p.Name)
		}
		row.PID, row.Exit, output = run(true)
		row.Detected = row.Exit == 1 && bytes.Contains(output, []byte("--- FAIL:")) && bytes.Contains(output, []byte(p.Witness)) && !bytes.Contains(output, []byte("panic:")) && !bytes.Contains(output, []byte("[build failed]"))
		rows = append(rows, row)
		encoded, _ := json.MarshalIndent(rows, "", "  ")
		must(os.WriteFile(filepath.Join(*out, "results.json"), append(encoded, '\n'), 0600))
		fmt.Printf("%s detected=%v baseline=%d plant=%d\n", p.Name, row.Detected, row.BaselineExit, row.Exit)
		if !row.Detected {
			os.Exit(1)
		}
	}
}
