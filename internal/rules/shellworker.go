package rules

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"maps"
	"os"
	"os/exec"
	"strings"
	"sync"

	"mvdan.cc/sh/v3/syntax"
)

// shellWorkerRequest is the IPC request from parent → worker.
type shellWorkerRequest struct {
	Cmd          string            `json:"cmd"`
	Env          map[string]string `json:"env"`
	ParentSymtab map[string]string `json:"symtab,omitempty"`
}

// shellWorkerResponse is the IPC response from worker → parent.
type shellWorkerResponse struct {
	Commands []parsedCommand   `json:"commands"`
	Symtab   map[string]string `json:"symtab"`
	Panicked bool              `json:"panicked"`
}

// shellWorker manages a long-running subprocess for crash-isolated shell
// interpretation. If the interpreter panics in a goroutine (unrecoverable
// in-process), the subprocess crashes and the parent detects the broken pipe.
type shellWorker struct {
	mu      sync.Mutex
	proc    *exec.Cmd
	stdin   io.WriteCloser
	scanner *bufio.Scanner
	exePath string
	ctx     context.Context // lifecycle context; cancellation kills the subprocess
}

func newShellWorker(ctx context.Context, exePath string) (*shellWorker, error) {
	w := &shellWorker{exePath: exePath, ctx: ctx}
	if err := w.start(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *shellWorker) start() (err error) {
	proc := exec.CommandContext(w.ctx, w.exePath) //nolint:gosec // exePath is from os.Executable(), not user input
	proc.Env = append(os.Environ(), "_CRUST_SHELL_WORKER=1")

	stdin, err := proc.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := proc.StdoutPipe()
	if err != nil {
		stdin.Close()
		return err
	}
	defer func() {
		if err != nil {
			stdin.Close()
			stdout.Close()
		}
	}()
	proc.Stderr = io.Discard

	if err = proc.Start(); err != nil {
		return err
	}

	w.proc = proc
	w.stdin = stdin
	w.scanner = bufio.NewScanner(stdout)
	w.scanner.Buffer(make([]byte, 1<<20), 1<<20)
	return nil
}

// eval sends a command to the worker and returns the result.
// Returns crashed=true if the worker process died (goroutine panic).
// The caller should treat crashed the same as panicked.
func (w *shellWorker) eval(req shellWorkerRequest) (resp shellWorkerResponse, crashed bool) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.proc == nil {
		if err := w.start(); err != nil {
			return resp, true
		}
	}

	if err := json.NewEncoder(w.stdin).Encode(req); err != nil {
		w.kill()
		return resp, true
	}

	if !w.scanner.Scan() {
		w.kill()
		return resp, true
	}

	if err := json.Unmarshal(w.scanner.Bytes(), &resp); err != nil {
		w.kill()
		return resp, true
	}

	return resp, false
}

func (w *shellWorker) kill() {
	if w.proc != nil && w.proc.Process != nil {
		w.proc.Process.Kill()
		w.proc.Wait()
	}
	w.proc = nil
	w.stdin = nil
	w.scanner = nil
}

func (w *shellWorker) stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stdin != nil {
		w.stdin.Close()
	}
	w.kill()
}

// RunShellWorkerMain enters the worker loop if invoked as a shell worker
// subprocess. Call at the start of main(). Returns true if this process
// is a worker (caller should return immediately).
func RunShellWorkerMain() bool {
	if os.Getenv("_CRUST_SHELL_WORKER") != "1" {
		return false
	}

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	encoder := json.NewEncoder(os.Stdout)

	for scanner.Scan() {
		var req shellWorkerRequest
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			if err := encoder.Encode(shellWorkerResponse{Panicked: true}); err != nil {
				return true // pipe broken; parent will restart
			}
			continue
		}
		resp := evalShellCommand(req)
		if err := encoder.Encode(resp); err != nil {
			return true // pipe broken; parent will restart
		}
	}

	return true
}

// evalShellCommand runs the shell interpreter for a single command.
// Same-goroutine panics are caught by defer/recover. Goroutine panics
// (from pipe stages, backgrounded commands) crash this process — the
// parent detects the broken pipe.
func evalShellCommand(req shellWorkerRequest) (resp shellWorkerResponse) {
	defer func() {
		if r := recover(); r != nil {
			resp = shellWorkerResponse{
				Panicked: true,
				Symtab:   maps.Clone(req.ParentSymtab),
			}
		}
	}()

	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(req.Cmd), "")
	if err != nil {
		return shellWorkerResponse{Symtab: maps.Clone(req.ParentSymtab)}
	}
	syntax.Simplify(file)

	ext := &Extractor{commandDB: defaultCommandDB(), env: req.Env}
	res := ext.runShellFile(file, req.ParentSymtab)

	return shellWorkerResponse{
		Commands: res.cmds,
		Symtab:   res.sym,
		Panicked: res.panicked,
	}
}
