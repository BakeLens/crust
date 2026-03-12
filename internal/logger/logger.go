package logger

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Level represents log level
type Level int

const (
	LevelTrace Level = iota
	LevelDebug
	LevelInfo
	LevelWarn
	LevelError
)

var (
	globalLevel   = LevelInfo
	globalColored = true
	globalMu      sync.RWMutex
)

// errorHooks holds registered error hooks keyed by an auto-incrementing ID.
// Multiple hooks can be active simultaneously (e.g. parallel tests). Each hook
// is removed via the cleanup function returned by AddErrorHook.
var (
	errorHooksMu sync.RWMutex
	errorHooks   = map[uint64]func(string){}
	errorHookSeq uint64
)

// AddErrorHook registers fn to be called synchronously on every Error() call
// with the fully-formatted "[prefix] message" string. Returns a cleanup
// function that removes the hook — call it via t.Cleanup to avoid leaks.
// Safe for concurrent use; multiple hooks from parallel tests are all fired.
func AddErrorHook(fn func(msg string)) func() {
	errorHooksMu.Lock()
	errorHookSeq++
	id := errorHookSeq
	errorHooks[id] = fn
	errorHooksMu.Unlock()
	return func() {
		errorHooksMu.Lock()
		delete(errorHooks, id)
		errorHooksMu.Unlock()
	}
}

// Logger provides leveled logging
type Logger struct {
	prefix string
}

// New creates a new logger with the given prefix
func New(prefix string) *Logger {
	return &Logger{prefix: prefix}
}

// SetGlobalLevel sets the global log level
func SetGlobalLevel(level Level) {
	globalMu.Lock()
	defer globalMu.Unlock()
	globalLevel = level
}

// ParseLevel converts a string to a Level, returning an error if unrecognized.
func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(s) {
	case "trace":
		return LevelTrace, nil
	case "debug":
		return LevelDebug, nil
	case "info", "":
		return LevelInfo, nil
	case "warn", "warning":
		return LevelWarn, nil
	case "error":
		return LevelError, nil
	}
	return 0, fmt.Errorf("unknown log level %q (valid: trace, debug, info, warn, error)", s)
}

// SetGlobalLevelFromString sets log level from string
func SetGlobalLevelFromString(level string) {
	if l, err := ParseLevel(level); err == nil {
		SetGlobalLevel(l)
	}
}

// SetColored enables or disables colored output
func SetColored(colored bool) {
	globalMu.Lock()
	defer globalMu.Unlock()
	globalColored = colored
}

func (l *Logger) log(level Level, levelStr string, format string, args ...any) {
	globalMu.RLock()
	if level < globalLevel {
		globalMu.RUnlock()
		return
	}
	colored := globalColored
	globalMu.RUnlock()

	timestamp := time.Now().Format("15:04:05")
	msg := fmt.Sprintf(format, args...)

	if colored {
		renderColored(os.Stderr, timestamp, levelStr, l.prefix, msg)
	} else {
		fmt.Fprintf(os.Stderr, "%s [%s] [%s] %s\n",
			timestamp, levelStr, l.prefix, msg)
	}
}

// Trace logs a trace message (most verbose)
func (l *Logger) Trace(format string, args ...any) {
	l.log(LevelTrace, "TRACE", format, args...)
}

// Debug logs a debug message
func (l *Logger) Debug(format string, args ...any) {
	l.log(LevelDebug, "DEBUG", format, args...)
}

// Info logs an info message
func (l *Logger) Info(format string, args ...any) {
	l.log(LevelInfo, "INFO", format, args...)
}

// Warn logs a warning message
func (l *Logger) Warn(format string, args ...any) {
	l.log(LevelWarn, "WARN", format, args...)
}

// Error logs an error message and fires all registered error hooks.
func (l *Logger) Error(format string, args ...any) {
	l.log(LevelError, "ERROR", format, args...)
	errorHooksMu.RLock()
	hooks := make([]func(string), 0, len(errorHooks))
	for _, fn := range errorHooks {
		hooks = append(hooks, fn)
	}
	errorHooksMu.RUnlock()
	if len(hooks) > 0 {
		msg := fmt.Sprintf("[%s] "+format, append([]any{l.prefix}, args...)...)
		for _, fn := range hooks {
			fn(msg)
		}
	}
}
