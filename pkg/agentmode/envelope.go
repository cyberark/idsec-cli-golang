package agentmode

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"strconv"
	"sync"
)

// Envelope status values.
const (
	StatusSuccess = "success"
	StatusError   = "error"
)

// Envelope is the single JSON object written to stdout in agent mode.
// Field order is the JSON order. Additive changes only.
type Envelope struct {
	Status    string         `json:"status"`
	Data      any            `json:"data,omitempty"`
	Message   string         `json:"message,omitempty"`
	Error     *EnvelopeError `json:"error,omitempty"`
	Count     *int           `json:"count,omitempty"`
	Truncated bool           `json:"truncated,omitempty"`
	Warnings  []string       `json:"warnings,omitempty"`
	Hints     []string       `json:"hints,omitempty"`
	Agent     string         `json:"agent,omitempty"`
}

// EnvelopeError is the error member of an error envelope.
type EnvelopeError struct {
	Code    Code   `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

// Failure is an error that carries an agent-mode code. Error() returns the
// wrapped error's text unchanged so human output and string checks are unaffected.
type Failure struct {
	Code Code
	// Message is the envelope message; it defaults to Err.Error().
	Message string
	// Redacted marks Message as a fixed text that must replace any message a
	// caller derives from Err, because Err's text may echo user input.
	Redacted bool
	// Details holds flag NAMES only, never flag values or secrets.
	Details map[string]any
	// Hints are constants only; never user-controlled text.
	Hints []string
	Err   error
}

// Error returns Err.Error() when Err is set, otherwise Message.
func (f *Failure) Error() string {
	if f.Err != nil {
		return f.Err.Error()
	}
	return f.Message
}

// Unwrap returns the wrapped error.
func (f *Failure) Unwrap() error { return f.Err }

// FailureOption customizes a Failure built by NewFailure.
type FailureOption func(*Failure)

// NewFailure returns a Failure for code wrapping err. Message defaults to
// err.Error() unless WithMessage is given.
func NewFailure(code Code, err error, opts ...FailureOption) *Failure {
	f := &Failure{Code: code, Err: err}
	if err != nil {
		f.Message = err.Error()
	}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

// WithMessage overrides the envelope message.
func WithMessage(msg string) FailureOption {
	return func(f *Failure) { f.Message = msg }
}

// WithRedactedMessage sets a fixed envelope message for an error whose text may
// echo flag values, query input or other user data. msg must be a constant or
// built from flag names only. Err's full text still reaches stderr via Error().
func WithRedactedMessage(msg string) FailureOption {
	return func(f *Failure) {
		f.Message = msg
		f.Redacted = true
	}
}

// WithDetail sets details[key] = v. v must not contain flag values or secrets.
func WithDetail(key string, v any) FailureOption {
	return func(f *Failure) {
		if f.Details == nil {
			f.Details = make(map[string]any)
		}
		f.Details[key] = v
	}
}

// WithHint appends a hint. hint must be a constant, never user-controlled text.
// An empty hint is dropped.
func WithHint(hint string) FailureOption {
	return func(f *Failure) {
		if hint != "" {
			f.Hints = append(f.Hints, hint)
		}
	}
}

// Per-process envelope state. Unlike the resolved mode, it is written while
// commands run, so it is guarded.
var (
	envelopeMu      sync.Mutex
	pendingWarnings []string
	envelopeClaimed bool
)

// AddWarning queues msg for the warnings member of the next envelope.
func AddWarning(msg string) {
	envelopeMu.Lock()
	defer envelopeMu.Unlock()
	pendingWarnings = append(pendingWarnings, msg)
}

// DrainWarnings returns the queued warnings and clears the queue.
func DrainWarnings() []string {
	envelopeMu.Lock()
	defer envelopeMu.Unlock()
	w := pendingWarnings
	pendingWarnings = nil
	return w
}

// ClaimEnvelope reports whether the caller may write this process's single
// envelope. It returns true at most once.
func ClaimEnvelope() bool {
	envelopeMu.Lock()
	defer envelopeMu.Unlock()
	if envelopeClaimed {
		return false
	}
	envelopeClaimed = true
	return true
}

// ResetEnvelopeState clears queued warnings and the envelope claim. It exists
// for tests, which must not call it from t.Parallel().
func ResetEnvelopeState() {
	envelopeMu.Lock()
	defer envelopeMu.Unlock()
	pendingWarnings = nil
	envelopeClaimed = false
}

// NewErrorEnvelope builds the error envelope for f. Agent is DetectedAgent()
// (omitted when ""), and Warnings are drained from the queue.
func NewErrorEnvelope(f *Failure) Envelope {
	e := &EnvelopeError{Code: f.Code, Message: f.Message}
	if e.Message == "" && f.Err != nil {
		e.Message = f.Err.Error()
	}
	if len(f.Details) > 0 {
		e.Details = f.Details
	}
	return Envelope{
		Status:   StatusError,
		Error:    e,
		Warnings: DrainWarnings(),
		Hints:    f.Hints,
		Agent:    DetectedAgent(),
	}
}

// Write encodes env as one compact JSON line followed by "\n". HTML characters
// are not escaped. If error details cannot be marshaled, it retries without
// them so the output is always valid JSON.
func Write(w io.Writer, env Envelope) error {
	b, err := encodeLine(env)
	if err != nil && env.Error != nil && env.Error.Details != nil {
		stripped := *env.Error
		stripped.Details = nil
		env.Error = &stripped
		b, err = encodeLine(env)
	}
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// successWire mirrors Envelope's fields and JSON order, except that data is
// never omitted: a success envelope always carries a data member. Keep it in
// sync with Envelope (a test asserts the key order matches).
type successWire struct {
	Status    string         `json:"status"`
	Data      any            `json:"data"`
	Message   string         `json:"message,omitempty"`
	Error     *EnvelopeError `json:"error,omitempty"`
	Count     *int           `json:"count,omitempty"`
	Truncated bool           `json:"truncated,omitempty"`
	Warnings  []string       `json:"warnings,omitempty"`
	Hints     []string       `json:"hints,omitempty"`
	Agent     string         `json:"agent,omitempty"`
}

// SuccessOption customizes a success envelope built by NewSuccessEnvelope.
type SuccessOption func(*Envelope)

// WithSuccessMessage sets the envelope message.
func WithSuccessMessage(msg string) SuccessOption {
	return func(e *Envelope) { e.Message = msg }
}

// WithCount sets the envelope count member.
func WithCount(n int) SuccessOption {
	return func(e *Envelope) { e.Count = &n }
}

// WithTruncated sets the envelope truncated member.
func WithTruncated(t bool) SuccessOption {
	return func(e *Envelope) { e.Truncated = t }
}

// NewSuccessEnvelope builds a success envelope carrying data. Agent is
// DetectedAgent() (omitted when "") and Warnings are drained from the queue.
func NewSuccessEnvelope(data any, opts ...SuccessOption) Envelope {
	env := Envelope{
		Status:   StatusSuccess,
		Data:     data,
		Warnings: DrainWarnings(),
		Agent:    DetectedAgent(),
	}
	for _, opt := range opts {
		opt(&env)
	}
	return env
}

// ErrMarshal marks an envelope that could not be encoded as JSON. WriteSuccess
// wraps it, so callers can tell it from an output write failure with errors.Is.
var ErrMarshal = errors.New("envelope could not be marshaled")

// WriteSuccess encodes env, claims the process's single envelope and writes it.
// An encode failure is returned wrapping ErrMarshal without claiming, so an
// error envelope can still be written. Otherwise it writes nothing and returns
// nil when the envelope was already claimed; any other error is a write failure.
func WriteSuccess(w io.Writer, env Envelope) error {
	b, err := encodeLine(env)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrMarshal, err)
	}
	if !ClaimEnvelope() {
		return nil
	}
	_, err = w.Write(b)
	return err
}

// StreamList claims the process's single envelope and writes it as one
// compact line whose data member is the array of items, streaming items as
// they are produced. It returns the number of items written and whether the
// stream stopped early because an item could not be marshaled (the envelope is
// still closed as valid JSON, with truncated:true). A write failure stops the
// stream and is returned as err. If the envelope was already claimed, nothing
// is written.
func StreamList(w io.Writer, items iter.Seq[any]) (count int, truncated bool, err error) {
	if !ClaimEnvelope() {
		return 0, false, nil
	}
	if _, err = io.WriteString(w, `{"status":"success","data":[`); err != nil {
		return 0, false, err
	}
	for item := range items {
		b, mErr := encodeValue(item)
		if mErr != nil {
			truncated = true
			break
		}
		if count > 0 {
			b = append([]byte{','}, b...)
		}
		if _, err = w.Write(b); err != nil {
			return count, false, err
		}
		count++
	}
	tail := []byte("],\"count\":")
	tail = strconv.AppendInt(tail, int64(count), 10)
	if truncated {
		tail = append(tail, `,"truncated":true`...)
	}
	if warnings := DrainWarnings(); len(warnings) > 0 {
		wb, _ := encodeValue(warnings)
		tail = append(tail, `,"warnings":`...)
		tail = append(tail, bytes.TrimRight(wb, "\n")...)
	}
	if agent := DetectedAgent(); agent != "" {
		ab, _ := encodeValue(agent)
		tail = append(tail, `,"agent":`...)
		tail = append(tail, bytes.TrimRight(ab, "\n")...)
	}
	tail = append(tail, "}\n"...)
	if _, err = w.Write(tail); err != nil {
		return count, truncated, err
	}
	return count, truncated, nil
}

// encodeValue marshals v compactly without HTML escaping and without a
// trailing newline.
func encodeValue(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func encodeLine(env Envelope) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	var v any = env
	if env.Status == StatusSuccess {
		v = successWire(env)
	}
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
