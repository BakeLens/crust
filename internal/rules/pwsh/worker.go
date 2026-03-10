package pwsh

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

//go:generate go run pwsh_verify.go

//go:embed ps_bootstrap_header.ps1
var psHeader string

//go:embed ps_bootstrap_vars.ps1
var psVars string

//go:embed ps_bootstrap_cmds.ps1
var psCmds string

//go:embed ps_bootstrap_dotnet.ps1
var psDotNet string

//go:embed ps_bootstrap_footer.ps1
var psFooter string

var psBootstrapScript = psHeader + psVars + psCmds + psDotNet + psFooter

// pwshWorkerRequest is the IPC request sent from Go → pwsh worker.
type pwshWorkerRequest struct {
	Command string `json:"command"`
}

// ParsedCommand represents a single command extracted from the PowerShell AST.
// Field names and JSON tags match the PSCustomObject emitted by the bootstrap script.
type ParsedCommand struct {
	Name         string   `json:"name"`
	Args         []string `json:"args"`
	RedirPaths   []string `json:"redir_paths"`
	RedirInPaths []string `json:"redir_in_paths"`
	HasSubst     bool     `json:"has_subst"`
}

// Response is the IPC response received from the pwsh worker subprocess.
type Response struct {
	Commands    []ParsedCommand `json:"commands"`
	ParseErrors []string        `json:"parseErrors"`
}

// Worker manages a persistent pwsh subprocess for accurate PowerShell
// command analysis. It mirrors the shellWorker pattern: JSON over stdin/stdout,
// auto-restart on crash, mutex-serialized access.
type Worker struct {
	mu         sync.Mutex
	proc       *exec.Cmd
	stdin      io.WriteCloser
	scanner    *bufio.Scanner
	encoder    *json.Encoder   // reused across Parse() calls to avoid per-call allocation
	pwshPath   string          // path to pwsh.exe or powershell.exe
	scriptPath string          // temp file holding the bootstrap script
	ctx        context.Context // lifecycle context; cancellation kills the subprocess
}

// FindPwsh returns the path to pwsh.exe or powershell.exe, preferring the
// newer pwsh (PowerShell 7+) over legacy powershell (Windows PowerShell 5.1).
// On supported Windows 10/11 systems, powershell.exe is always present so
// this should always succeed.
func FindPwsh() (string, bool) {
	for _, name := range []string{"pwsh.exe", "powershell.exe"} {
		if p, err := exec.LookPath(name); err == nil {
			return p, true
		}
	}
	return "", false
}

// NewWorker creates and starts a pwsh worker subprocess.
// The context controls the subprocess lifetime; canceling it kills the process.
func NewWorker(ctx context.Context, pwshPath string) (*Worker, error) {
	// Write the bootstrap script to a temp file instead of passing it as a
	// base64-encoded -EncodedCommand argument. The bootstrap script is ~13 KB,
	// which encodes to ~35 KB of base64 — exceeding Windows' 32,767-character
	// command-line limit and causing "filename or extension too long" errors.
	f, err := os.CreateTemp("", "crust-ps-bootstrap-*.ps1")
	if err != nil {
		return nil, err
	}
	scriptPath := f.Name() // capture once; gosec taint analysis requires consistent path source
	if _, err := f.WriteString(psBootstrapScript); err != nil {
		f.Close()
		os.Remove(scriptPath)
		return nil, err
	}
	f.Close()

	w := &Worker{
		pwshPath:   pwshPath,
		scriptPath: scriptPath,
		ctx:        ctx,
	}
	if err := w.start(); err != nil {
		os.Remove(scriptPath)
		return nil, err
	}

	// Readiness probe: verify the worker responds before returning it.
	// Under MSYS2 (MINGW64), PowerShell can hang due to MSYSTEM/SHELL
	// environment conflicts. A quick probe with startTimeout prevents the
	// caller from blocking indefinitely on a dead worker.
	//
	// We bypass w.Parse() (which holds w.mu for up to parseTimeout=30s)
	// and drive stdin/stdout directly. Since NewWorker hasn't returned yet,
	// no other goroutine can access w, so no mutex is needed. This lets
	// w.kill() run immediately on timeout without waiting for a lock.
	probeCh := make(chan error, 1)
	encoder := w.encoder
	scanner := w.scanner
	go func() {
		if err := encoder.Encode(pwshWorkerRequest{Command: "$null"}); err != nil {
			probeCh <- err
			return
		}
		if scanner.Scan() {
			probeCh <- nil
		} else {
			err := scanner.Err()
			if err == nil {
				err = errors.New("pwsh worker: unexpected EOF during startup probe")
			}
			probeCh <- err
		}
	}()
	select {
	case err := <-probeCh:
		if err != nil {
			w.Stop()
			return nil, errors.New("pwsh worker: startup probe failed: " + err.Error())
		}
	case <-time.After(startTimeout):
		// kill() closes stdin/stdout, unblocking the goroutine above.
		// No mutex needed: we are the sole owner of w before returning.
		w.kill()
		os.Remove(scriptPath)
		return nil, errors.New("pwsh worker: startup probe timed out (possible MSYS2/environment conflict)")
	}

	return w, nil
}

func (w *Worker) start() (err error) {
	proc := exec.CommandContext(w.ctx, w.pwshPath, //nolint:gosec // pwshPath from exec.LookPath
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", w.scriptPath)
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
	w.encoder = json.NewEncoder(stdin)
	w.scanner = bufio.NewScanner(stdout)
	w.scanner.Buffer(make([]byte, 1<<20), 1<<20)
	return nil
}

// parseTimeout is the maximum time to wait for a single Parse response.
// pwsh startup + JIT can be slow; 30 s is generous but prevents infinite hangs.
const parseTimeout = 30 * time.Second

// startTimeout is the maximum time to wait for a pwsh process to become
// responsive during startup. Under MSYS2 (MINGW64 shell), PowerShell can
// hang indefinitely due to environment conflicts (MSYSTEM, SHELL, etc.).
// A 15 s timeout lets us fail fast and fall back to heuristic parsing.
const startTimeout = 15 * time.Second

// Parse sends a command to the pwsh worker and returns the parsed result.
// Returns an error if the worker died, timed out, or the response was malformed;
// the worker is automatically restarted on the next call.
func (w *Worker) Parse(cmd string) (Response, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.proc == nil {
		if err := w.start(); err != nil {
			return Response{}, err
		}
	}

	// Start the timer before Encode so the timeout covers both the write
	// (stdin pipe could block if pwsh is dead but pipe not yet detected)
	// and the subsequent scan.
	timer := time.NewTimer(parseTimeout)
	defer timer.Stop()

	// Encode and scan both run in a goroutine so the timer can fire even if
	// Encode() blocks. Capturing scanner as a local avoids a data race when
	// w.kill() clears w.scanner on timeout.
	type scanResult struct {
		line []byte
		err  error
	}
	ch := make(chan scanResult, 1)
	encoder := w.encoder
	scanner := w.scanner
	go func() {
		if err := encoder.Encode(pwshWorkerRequest{Command: cmd}); err != nil {
			ch <- scanResult{err: err}
			return
		}
		if scanner.Scan() {
			ch <- scanResult{line: append([]byte(nil), scanner.Bytes()...)}
		} else {
			err := scanner.Err()
			if err == nil {
				err = errors.New("pwsh worker: unexpected EOF")
			}
			ch <- scanResult{err: err}
		}
	}()

	select {
	case <-timer.C:
		// If the response arrived at the same instant the timer fired, Go's
		// select picks one case randomly — we may discard a valid response here.
		// This race window is ~nanoseconds vs. a 30 s timer, so acceptable.
		// Kill the process — closes stdout, unblocking scanner.Scan() in the
		// goroutine above so it exits cleanly via the buffered ch.
		w.kill()
		// w.proc is now nil; the next Parse() call will restart the worker.
		return Response{}, errors.New("pwsh worker: parse timed out")
	case res := <-ch:
		if res.err != nil {
			w.kill()
			return Response{}, res.err
		}
		var resp Response
		if err := json.Unmarshal(res.line, &resp); err != nil {
			w.kill()
			return Response{}, err
		}
		return resp, nil
	}
}

func (w *Worker) kill() {
	if w.stdin != nil {
		w.stdin.Close() // close write end before Kill to avoid fd leak
	}
	if w.proc != nil && w.proc.Process != nil {
		w.proc.Process.Kill()
		proc := w.proc
		go proc.Wait() // async reap; error irrelevant after Kill()
	}
	w.proc = nil
	w.stdin = nil
	w.encoder = nil
	w.scanner = nil
}

// Stop shuts down the pwsh worker subprocess and removes the temp bootstrap file.
func (w *Worker) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.kill()
	if w.scriptPath != "" {
		os.Remove(w.scriptPath)
		w.scriptPath = ""
	}
}
