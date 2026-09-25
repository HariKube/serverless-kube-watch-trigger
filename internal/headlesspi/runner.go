package headlesspi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	defaultTimeout = 10 * time.Minute
	statusSuccess  = "success"
	statusError    = "error"
)

var ansiRegexp = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

type Request struct {
	Prompt       string
	CWD          string
	Provider     string
	Model        string
	NoSession    bool
	NoExtensions bool
	Extensions   []string
	Timeout      time.Duration
}

type Config struct {
	Prompt       string   `json:"prompt"`
	CWD          string   `json:"cwd,omitempty"`
	Provider     string   `json:"provider,omitempty"`
	Model        string   `json:"model,omitempty"`
	NoSession    bool     `json:"noSession,omitempty"`
	NoExtensions bool     `json:"noExtensions,omitempty"`
	Extensions   []string `json:"extensions,omitempty"`
	Timeout      string   `json:"timeout,omitempty"`
}

func LoadRequestFromFile(path string) (Request, error) {
	if path == "" {
		return Request{}, errors.New("empty worker config path")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return Request{}, err
	}
	cfg := Config{}
	if err := json.Unmarshal(payload, &cfg); err != nil {
		return Request{}, err
	}
	request := Request{
		Prompt:       cfg.Prompt,
		CWD:          cfg.CWD,
		Provider:     cfg.Provider,
		Model:        cfg.Model,
		NoSession:    cfg.NoSession,
		NoExtensions: cfg.NoExtensions,
		Extensions:   cfg.Extensions,
	}
	if cfg.Timeout != "" {
		request.Timeout, err = time.ParseDuration(cfg.Timeout)
		if err != nil {
			return Request{}, fmt.Errorf("invalid worker timeout %q: %w", cfg.Timeout, err)
		}
	}
	return request, nil
}

type Result struct {
	RunID              string `json:"runId"`
	LogPath            string `json:"logPath"`
	Status             string `json:"status"`
	ErrorMessage       string `json:"errorMessage,omitempty"`
	TaskCompleted      bool   `json:"taskCompleted"`
	FinalAnswer        string `json:"finalAnswer,omitempty"`
	LastOutputLines    string `json:"lastOutputLines,omitempty"`
	DisplayMessage     string `json:"displayMessage,omitempty"`
	ExitCode           int    `json:"exitCode,omitempty"`
	StopReason         string `json:"stopReason,omitempty"`
	ToolExecutionCount int    `json:"toolExecutionCount,omitempty"`
	NeedsInput         bool   `json:"needsInput,omitempty"`
}

type ndjsonEvent struct {
	Type    string `json:"type"`
	Message struct {
		Role         string `json:"role"`
		ErrorMessage string `json:"errorMessage"`
		StopReason   string `json:"stopReason"`
		Content      []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	} `json:"message"`
	Messages []struct {
		Role         string `json:"role"`
		ErrorMessage string `json:"errorMessage"`
		StopReason   string `json:"stopReason"`
		Content      []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	} `json:"messages"`
}

func Run(ctx context.Context, req Request) (Result, error) {
	cleanPrompt := strings.TrimSpace(req.Prompt)
	if cleanPrompt == "" {
		return Result{Status: statusError, TaskCompleted: false, ErrorMessage: "empty prompt"}, errors.New("empty prompt")
	}

	targetCWD := req.CWD
	if targetCWD == "" {
		var err error
		targetCWD, err = os.Getwd()
		if err != nil {
			return Result{}, err
		}
	}
	provider := req.Provider
	model := req.Model
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	headlessDir := filepath.Join(os.TempDir(), "pi-headless")
	if err := os.MkdirAll(headlessDir, 0o755); err != nil {
		return Result{}, err
	}

	runID := strings.NewReplacer(":", "-", ".", "-").Replace(time.Now().UTC().Format(time.RFC3339Nano))
	logPath := filepath.Join(headlessDir, runID+".log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return Result{}, err
	}
	defer func() {
		if closeErr := logFile.Close(); closeErr != nil {
			fmt.Fprintf(os.Stderr, "failed to close PiTrigger worker log %s: %v\n", logPath, closeErr)
		}
	}()

	formattedPrompt := fmt.Sprintf("Execute the necessary tool or shell commands to complete the request below.\n\nPrompt: %s", cleanPrompt)
	metadata, _ := json.MarshalIndent(map[string]any{
		"runId":        runID,
		"cwd":          targetCWD,
		"provider":     provider,
		"model":        model,
		"noSession":    req.NoSession,
		"noExtensions": req.NoExtensions,
		"extensions":   req.Extensions,
	}, "", "  ")
	if _, err := fmt.Fprintf(logFile, "METADATA: %s\n\nPROMPT: %s\n\n--- RAW OUTPUT START ---\n", metadata, cleanPrompt); err != nil {
		return Result{}, err
	}

	pythonPTYCmd := `import json, pty, sys; argv = json.loads(sys.argv[1]); pty.spawn(argv)`

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	piArgs := []string{"pi", "--mode", "json"}
	if req.NoExtensions {
		piArgs = append(piArgs, "--no-extensions")
	}
	for _, extension := range req.Extensions {
		if strings.TrimSpace(extension) == "" {
			continue
		}
		piArgs = append(piArgs, "--extension", extension)
	}
	if req.NoSession {
		piArgs = append(piArgs, "--no-session")
	}
	if provider != "" {
		piArgs = append(piArgs, "--provider", provider)
	}
	if model != "" {
		piArgs = append(piArgs, "--model", model)
	}
	piArgs = append(piArgs, "-p", formattedPrompt)
	piArgsJSON, err := json.Marshal(piArgs)
	if err != nil {
		return Result{}, err
	}

	cmd := exec.CommandContext(execCtx, "python3", "-c", pythonPTYCmd, string(piArgsJSON))
	cmd.Dir = targetCWD
	cmd.Env = append(os.Environ(),
		"CI=true",
		"PYTHONUNBUFFERED=1",
		"TERM=xterm-256color",
	)

	var output bytes.Buffer
	stream := io.MultiWriter(&output, logFile, os.Stdout)
	cmd.Stdout = stream
	cmd.Stderr = stream

	err = cmd.Run()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else if execCtx.Err() == context.DeadlineExceeded {
			exitCode = -1
		} else {
			result, finalizeErr := finalize(logFile, Result{
				RunID:         runID,
				LogPath:       logPath,
				Status:        statusError,
				TaskCompleted: false,
				ErrorMessage:  fmt.Sprintf("failed to spawn worker process: %v", err),
			})
			if finalizeErr != nil {
				return result, finalizeErr
			}
			return result, err
		}
	}

	cleanText := stripANSI(output.String())
	result := parseResult(cleanText)
	result.RunID = runID
	result.LogPath = logPath
	result.ExitCode = exitCode

	if execCtx.Err() == context.DeadlineExceeded {
		result.Status = statusError
		result.TaskCompleted = false
		result.ErrorMessage = fmt.Sprintf("execution timed out after %s", timeout)
		result.LastOutputLines = extractLastOutputLines(cleanText)
	}

	if strings.Contains(strings.ToLower(cleanText), "reflections allowed, stopping") {
		result.Status = statusError
		result.TaskCompleted = false
		result.ErrorMessage = "max reflections allowed, stopping"
	}

	if result.ErrorMessage == "" && (exitCode != 0 || result.FinalAnswer == "") {
		result.Status = statusError
		result.TaskCompleted = false
		if exitCode != 0 {
			result.ErrorMessage = fmt.Sprintf("worker process exited with code %d", exitCode)
		} else {
			result.ErrorMessage = "worker completed, but no valid answer could be extracted from JSON output"
		}
	}

	if result.ErrorMessage != "" {
		result.LastOutputLines = extractLastOutputLines(cleanText)
		parts := []string{result.ErrorMessage}
		if result.LastOutputLines != "" {
			parts = append(parts, "Last output lines:\n"+result.LastOutputLines)
		}
		parts = append(parts, "Full response logged to: "+logPath)
		result.DisplayMessage = strings.Join(parts, "\n\n")
	}

	result, finalizeErr := finalize(logFile, result)
	if finalizeErr != nil {
		return result, finalizeErr
	}
	if result.Status != statusSuccess {
		return result, errors.New(result.ErrorMessage)
	}
	return result, nil
}

func finalize(logFile *os.File, result Result) (Result, error) {
	footer, _ := json.MarshalIndent(result, "", "  ")
	_, err := fmt.Fprintf(logFile, "\n--- RAW OUTPUT END ---\n\nFINAL METADATA: %s\n", footer)
	if result.Status == "" {
		result.Status = statusSuccess
	}
	if result.Status == statusSuccess {
		result.TaskCompleted = true
	}
	return result, err
}

func parseResult(cleanText string) Result {
	result := Result{Status: statusSuccess, TaskCompleted: true}
	lines := strings.Split(cleanText, "\n")

	captureAssistant := func(role, errorMessage, stopReason string, content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}) {
		if role != "assistant" {
			return
		}
		if strings.TrimSpace(errorMessage) != "" {
			result.ErrorMessage = strings.TrimSpace(errorMessage)
		}
		if strings.TrimSpace(stopReason) != "" {
			result.StopReason = strings.TrimSpace(stopReason)
		}
		texts := make([]string, 0, len(content))
		for _, block := range content {
			if block.Type == "text" && strings.TrimSpace(block.Text) != "" {
				texts = append(texts, block.Text)
			}
		}
		if len(texts) > 0 {
			result.FinalAnswer = strings.TrimSpace(strings.Join(texts, "\n"))
		}
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "{") {
			continue
		}
		var event ndjsonEvent
		if err := json.Unmarshal([]byte(trimmed), &event); err != nil {
			continue
		}
		switch event.Type {
		case "message_end":
			captureAssistant(event.Message.Role, event.Message.ErrorMessage, event.Message.StopReason, event.Message.Content)
		case "tool_execution_end":
			result.ToolExecutionCount++
		case "agent_end":
			for i := len(event.Messages) - 1; i >= 0; i-- {
				msg := event.Messages[i]
				if msg.Role == "assistant" {
					captureAssistant(msg.Role, msg.ErrorMessage, msg.StopReason, msg.Content)
					break
				}
			}
		}
	}

	if result.FinalAnswer == "" {
		result.FinalAnswer = extractHeadlessFinalAnswer(cleanText)
	}
	if result.StopReason == "error" || result.StopReason == "aborted" {
		if result.ErrorMessage == "" {
			result.ErrorMessage = fmt.Sprintf("worker reported stopReason %q without an errorMessage", result.StopReason)
		}
	}
	if result.ToolExecutionCount == 0 && looksLikeClarificationRequest(result.FinalAnswer) {
		result.Status = "needs_input"
		result.TaskCompleted = false
		result.NeedsInput = true
		if result.ErrorMessage == "" {
			result.ErrorMessage = "worker requested additional input before completing the task"
		}
	}

	return result
}

func stripANSI(s string) string {
	s = ansiRegexp.ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return s
}

func extractLastOutputLines(raw string) string {
	scanner := bufio.NewScanner(strings.NewReader(raw))
	lines := make([]string, 0, 2)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), " ")
		if strings.TrimSpace(line) == "" {
			continue
		}
		lines = append(lines, line)
		if len(lines) > 2 {
			lines = lines[1:]
		}
	}
	return strings.Join(lines, "\n")
}

func looksLikeClarificationRequest(text string) bool {
	normalized := strings.ToLower(strings.TrimSpace(text))
	if normalized == "" {
		return false
	}
	clarificationPattern := regexp.MustCompile(`\b(i need\b.*\b(detail|details|info|information|clarification)\b|but i['’]ll need\b|need a bit more detail|please provide|could you clarify|can you clarify|what path|what filename|which path|which file|which filename)\b`)
	if clarificationPattern.MatchString(normalized) {
		return true
	}
	questionPattern := regexp.MustCompile(`^(what|which|where|who|could you|can you|please provide)\b`)
	return strings.HasSuffix(normalized, "?") && questionPattern.MatchString(normalized)
}

func extractHeadlessFinalAnswer(text string) string {
	for _, marker := range []string{"FINAL ANSWER:", "Final answer:", "finalAnswer"} {
		idx := strings.LastIndex(text, marker)
		if idx >= 0 {
			return strings.TrimSpace(text[idx+len(marker):])
		}
	}
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) == 0 {
		return ""
	}
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line != "" && !strings.HasPrefix(line, "{") {
			return line
		}
	}
	return ""
}
