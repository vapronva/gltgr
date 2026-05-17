package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/rs/zerolog"
	flag "github.com/spf13/pflag"
)

const (
	zeroSHA                = "0000000000000000000000000000000000000000"
	tgMaxMessageChars      = 4096
	defaultHTTPTimeout     = 30 * time.Second
	maxWebhookBodyBytes    = 8 << 20
	webhookReplayWindow    = 5 * time.Minute
	pushProcessTimeout     = 90 * time.Second
	shutdownTimeout        = 15 * time.Second
	summaryMaxTokens       = 200
	shortSHALen            = 8
	commitBodyMaxLen       = 240
	tgTruncateMarker       = "\n…<i>(truncated)</i>"
	tgTruncateSuffixBudget = 32
	errBodyPreviewBytes    = 512
	aiResponseMaxBytes     = 1 << 20
	aiErrPreviewBytes      = 256
	tgResponseMaxBytes     = 64 << 10
	maxBMPRune             = 0xFFFF
	recentCommitsCount     = 20
	httpReadHeaderTimeout  = 10 * time.Second
	httpReadTimeout        = 30 * time.Second
	httpWriteTimeout       = 30 * time.Second
	httpIdleTimeout        = 120 * time.Second
	maxConcurrentPushes    = 16
)

type Config struct {
	Listen              string
	TelegramToken       string
	TelegramBaseURL     string
	TelegramChatID      string
	TelegramThreadID    string
	GitlabBaseURL       string
	GitlabToken         string
	GitlabSigningToken  string
	GitlabSecretToken   string
	OpenRouterEnabled   bool
	OpenRouterBaseURL   string
	OpenRouterAPIKey    string
	OpenRouterModel     string
	OpenRouterProxyKey  string
	OpenRouterTimeout   time.Duration
	DiffMaxLinesAI      int
	DiffMaxBytesPerFile int
	LogLevel            string
	LogJSON             bool
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func loadConfig() Config { //nolint:funlen
	var cfg Config
	flag.StringVar(&cfg.Listen, "listen", envOr("LISTEN", ":8080"), "HTTP listen address")
	flag.StringVar(
		&cfg.TelegramToken,
		"telegram-token",
		os.Getenv("TELEGRAM_TOKEN"),
		"Telegram bot token",
	)
	flag.StringVar(
		&cfg.TelegramBaseURL,
		"telegram-base-url",
		envOr("TELEGRAM_BASE_URL", "https://api.telegram.org"),
		"Telegram Bot API base URL",
	)
	flag.StringVar(
		&cfg.TelegramChatID,
		"telegram-chat-id",
		os.Getenv("TELEGRAM_CHAT_ID"),
		"Telegram chat ID",
	)
	flag.StringVar(
		&cfg.TelegramThreadID,
		"telegram-thread-id",
		os.Getenv("TELEGRAM_THREAD_ID"),
		"Optional forum topic ID",
	)
	flag.StringVar(
		&cfg.GitlabBaseURL,
		"gitlab-base-url",
		os.Getenv("GITLAB_BASE_URL"),
		"GitLab base URL (e.g., https://git.horse)",
	)
	flag.StringVar(
		&cfg.GitlabToken,
		"gitlab-token",
		os.Getenv("GITLAB_TOKEN"),
		"GitLab PAT for /api/v4 (with read_repository)",
	)
	flag.StringVar(
		&cfg.GitlabSigningToken,
		"gitlab-signing-token",
		os.Getenv("GITLAB_SIGNING_TOKEN"),
		"GitLab webhook signing token (whsec_...)",
	)
	flag.StringVar(
		&cfg.GitlabSecretToken,
		"gitlab-secret-token",
		os.Getenv("GITLAB_SECRET_TOKEN"),
		"Legacy secret token (X-Gitlab-Token)",
	)
	flag.BoolVar(
		&cfg.OpenRouterEnabled,
		"ai-enabled",
		envBool("AI_ENABLED", true),
		"Enable LLM diff summarisation",
	)
	flag.StringVar(
		&cfg.OpenRouterBaseURL,
		"openrouter-base-url",
		envOr("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
		"OpenRouter base URL",
	)
	flag.StringVar(
		&cfg.OpenRouterAPIKey,
		"openrouter-api-key",
		os.Getenv("OPENROUTER_API_KEY"),
		"OpenRouter API key",
	)
	flag.StringVar(
		&cfg.OpenRouterModel,
		"openrouter-model",
		envOr("OPENROUTER_MODEL", "anthropic/claude-opus-4.7"),
		"OpenRouter model ID",
	)
	flag.StringVar(
		&cfg.OpenRouterProxyKey,
		"openrouter-proxy-key",
		os.Getenv("OPENROUTER_PROXY_KEY"),
		"Value for the x-cmld-aig-proxy-key header",
	)
	flag.DurationVar(
		&cfg.OpenRouterTimeout,
		"openrouter-timeout",
		25*time.Second,
		"OpenRouter call timeout",
	)
	flag.IntVar(
		&cfg.DiffMaxLinesAI,
		"diff-max-lines-ai",
		400,
		"Max diff lines fed to the LLM",
	)
	flag.IntVar(
		&cfg.DiffMaxBytesPerFile,
		"diff-max-bytes-per-file",
		8000,
		"Per-file byte cap before truncation",
	)
	flag.StringVar(
		&cfg.LogLevel,
		"log-level",
		envOr("LOG_LEVEL", "info"),
		"log level: debug, info, warn, error",
	)
	flag.BoolVar(&cfg.LogJSON, "log-json", envBool("LOG_JSON", false), "JSON log output")
	flag.Parse()
	return cfg
}

func setupLogger(cfg Config) zerolog.Logger {
	lvl, err := zerolog.ParseLevel(cfg.LogLevel)
	if err != nil {
		lvl = zerolog.InfoLevel
	}
	var w io.Writer = os.Stderr
	if !cfg.LogJSON {
		w = zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}
	}
	return zerolog.New(w).Level(lvl).With().Timestamp().Logger()
}

func validateConfig(cfg Config, logger zerolog.Logger) error {
	missing := []string{}
	if cfg.TelegramToken == "" {
		missing = append(missing, "telegram-token")
	}
	if cfg.TelegramChatID == "" {
		missing = append(missing, "telegram-chat-id")
	}
	if cfg.GitlabBaseURL == "" {
		missing = append(missing, "gitlab-base-url")
	}
	if cfg.GitlabToken == "" {
		missing = append(missing, "gitlab-token")
	}
	if cfg.OpenRouterEnabled && cfg.OpenRouterAPIKey == "" {
		missing = append(
			missing,
			"openrouter-api-key (or disable with --ai-enabled=false)",
		)
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required config: %s", strings.Join(missing, ", "))
	}
	if cfg.GitlabSigningToken == "" && cfg.GitlabSecretToken == "" {
		logger.Warn().
			Msg("no webhook auth configured (neither signing nor secret token); rejecting all requests")
	}
	return nil
}

type PushEvent struct {
	ObjectKind        string   `json:"object_kind"`
	EventName         string   `json:"event_name"`
	Before            string   `json:"before"`
	After             string   `json:"after"`
	Ref               string   `json:"ref"`
	CheckoutSHA       string   `json:"checkout_sha"`
	UserName          string   `json:"user_name"`
	UserUsername      string   `json:"user_username"`
	UserAvatar        string   `json:"user_avatar"`
	ProjectID         int      `json:"project_id"`
	Project           Project  `json:"project"`
	Commits           []Commit `json:"commits"`
	TotalCommitsCount int      `json:"total_commits_count"`
}

type Project struct {
	ID                int    `json:"id"`
	Name              string `json:"name"`
	PathWithNamespace string `json:"path_with_namespace"`
	WebURL            string `json:"web_url"`
	DefaultBranch     string `json:"default_branch"`
}

type Commit struct {
	ID      string `json:"id"`
	Message string `json:"message"`
	Title   string `json:"title"`
	URL     string `json:"url"`
	Author  struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"author"`
}

type CompareResponse struct {
	Diffs []DiffEntry `json:"diffs"`
}

type DiffEntry struct {
	OldPath     string `json:"old_path"`
	NewPath     string `json:"new_path"`
	NewFile     bool   `json:"new_file"`
	DeletedFile bool   `json:"deleted_file"`
	RenamedFile bool   `json:"renamed_file"`
	Diff        string `json:"diff"`
}

type Server struct {
	cfg      Config
	client   *http.Client
	log      zerolog.Logger
	inflight sync.WaitGroup
	sem      chan struct{}
}

func newServer(cfg Config, logger zerolog.Logger) *Server {
	return &Server{
		cfg:    cfg,
		client: &http.Client{Timeout: defaultHTTPTimeout},
		log:    logger,
		sem:    make(chan struct{}, maxConcurrentPushes),
	}
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/gitlab", s.handleWebhook)
	mux.HandleFunc(
		"/healthz",
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) },
	)
	return mux
}

func (s *Server) handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxWebhookBodyBytes))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	if !s.verifyAuth(r.Header, body) {
		s.log.Warn().Str("remote", r.RemoteAddr).Msg("webhook auth failed")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	event := r.Header.Get("X-Gitlab-Event")
	switch event {
	case "Push Hook", "Tag Push Hook":
	case "":
		http.Error(w, "missing X-Gitlab-Event", http.StatusBadRequest)
		return
	default:
		s.log.Debug().Str("event", event).Msg("ignored event type")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var ev PushEvent
	if err = json.Unmarshal(body, &ev); err != nil {
		s.log.Error().Err(err).Msg("unmarshal push event")
		http.Error(w, "bad payload", http.StatusBadRequest)
		return
	}
	select {
	case s.sem <- struct{}{}:
	default:
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusAccepted)
	s.inflight.Go(func() {
		defer func() { <-s.sem }()
		ctx, cancel := context.WithTimeout(context.Background(), pushProcessTimeout)
		defer cancel()
		if perr := s.processPush(ctx, &ev); perr != nil {
			s.log.Error().
				Err(perr).
				Str("project", ev.Project.PathWithNamespace).
				Msg("process push failed")
		}
	})
}

func (s *Server) verifyAuth(h http.Header, body []byte) bool {
	if s.cfg.GitlabSigningToken != "" {
		return verifySigningToken(h, body, s.cfg.GitlabSigningToken)
	}
	if s.cfg.GitlabSecretToken != "" {
		return hmac.Equal(
			[]byte(h.Get("X-Gitlab-Token")),
			[]byte(s.cfg.GitlabSecretToken),
		)
	}
	return false
}

func verifySigningToken(h http.Header, body []byte, token string) bool {
	id := h.Get("Webhook-Id")
	ts := h.Get("Webhook-Timestamp")
	sigHdr := h.Get("Webhook-Signature")
	if id == "" || ts == "" || sigHdr == "" {
		return false
	}
	n, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return false
	}
	if d := time.Since(time.Unix(n, 0)); d < -webhookReplayWindow ||
		d > webhookReplayWindow {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(token, "whsec_"))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, raw)
	mac.Write([]byte(id + "." + ts + "."))
	mac.Write(body)
	want := "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
	for sig := range strings.FieldsSeq(sigHdr) {
		if hmac.Equal([]byte(sig), []byte(want)) {
			return true
		}
	}
	return false
}

func (s *Server) processPush(ctx context.Context, ev *PushEvent) error {
	refKind, refName := parseRef(ev.Ref)
	logger := s.log.With().
		Str("project", ev.Project.PathWithNamespace).
		Str("ref", refName).
		Str("event", ev.ObjectKind).
		Int("commits", ev.TotalCommitsCount).
		Logger()
	logger.Info().Msg("processing push")
	if len(ev.Commits) == 0 && ev.After == zeroSHA {
		text := fmt.Sprintf("🗑 [%s:%s] %s deleted",
			repoLink(ev.Project), refLink(ev.Project, refKind, refName), refKind)
		return s.sendTelegram(ctx, text)
	}
	var diffs []DiffEntry
	if ev.Before != zeroSHA && ev.After != zeroSHA && s.cfg.GitlabToken != "" {
		cmpResp, err := s.fetchCompare(ctx, ev.ProjectID, ev.Before, ev.After)
		if err != nil {
			logger.Warn().Err(err).Msg("fetch compare failed; proceeding without diff")
		} else {
			diffs = cmpResp.Diffs
		}
	}
	additions, deletions := countDiffStats(diffs)
	fileCount := len(diffs)
	summary := s.maybeSummarise(ctx, ev, refName, diffs)
	text := formatMessage(
		ev,
		refKind,
		refName,
		additions,
		deletions,
		fileCount,
		summary,
	)
	if err := s.sendTelegram(ctx, text); err != nil {
		return fmt.Errorf("telegram: %w", err)
	}
	logger.Info().Msg("notification sent")
	return nil
}

func (s *Server) maybeSummarise(
	ctx context.Context,
	ev *PushEvent,
	refName string,
	diffs []DiffEntry,
) string {
	if !s.cfg.OpenRouterEnabled || len(diffs) == 0 {
		return ""
	}
	diffText := buildDiffForAI(
		diffs,
		s.cfg.DiffMaxLinesAI,
		s.cfg.DiffMaxBytesPerFile,
	)
	commitTitles := make([]string, 0, len(ev.Commits))
	for _, c := range ev.Commits {
		commitTitles = append(commitTitles, "- "+c.Title)
	}
	system := summarySystemPrompt
	user := fmt.Sprintf(
		"Repository: `%s`\nBranch: `%s`\n\n"+
			"Pushed commit titles:\n```\n%s\n```\n\n"+
			"%s"+
			"Diff:\n```\n%s\n```",
		ev.Project.PathWithNamespace,
		refName,
		strings.Join(commitTitles, "\n"),
		s.recentCommitsContext(ctx, ev.ProjectID, refName),
		diffText,
	)
	sum, err := s.summarise(ctx, system, user)
	if err != nil {
		s.log.Warn().Err(err).Msg("summarise failed")
		return ""
	}
	return sum
}

func (s *Server) recentCommitsContext(
	ctx context.Context,
	projectID int,
	ref string,
) string {
	if s.cfg.GitlabToken == "" {
		return ""
	}
	cs, err := s.fetchRecentCommits(ctx, projectID, ref)
	if err != nil {
		s.log.Warn().Err(err).Msg("fetch recent commits failed")
		return ""
	}
	if len(cs) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("Recent commits on branch (newest first):\n```\n")
	for _, c := range cs {
		b.WriteString("- ")
		b.WriteString(c.Title)
		b.WriteString("\n")
	}
	b.WriteString("```\n\n")
	return b.String()
}

func (s *Server) gitlabGetJSON(
	ctx context.Context,
	endpoint, what string,
	out any,
) error {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		endpoint,
		nil,
	)
	if err != nil {
		return fmt.Errorf("%s request: %w", what, err)
	}
	req.Header.Set("Private-Token", s.cfg.GitlabToken)
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("%s request: %w", what, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(
			io.LimitReader(resp.Body, errBodyPreviewBytes),
		)
		return fmt.Errorf("%s %d: %s", what, resp.StatusCode,
			bytes.TrimSpace(b))
	}
	if err = json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("%s decode: %w", what, err)
	}
	return nil
}

func (s *Server) fetchCompare(
	ctx context.Context,
	projectID int,
	from, to string,
) (*CompareResponse, error) {
	u := fmt.Sprintf(
		"%s/api/v4/projects/%d/repository/compare"+
			"?from=%s&to=%s&unidiff=true&straight=true",
		strings.TrimRight(s.cfg.GitlabBaseURL, "/"),
		projectID,
		url.QueryEscape(from),
		url.QueryEscape(to),
	)
	var cmpResp CompareResponse
	if err := s.gitlabGetJSON(ctx, u, "compare", &cmpResp); err != nil {
		return nil, err
	}
	return &cmpResp, nil
}

type repoCommit struct {
	Title string `json:"title"`
}

func (s *Server) fetchRecentCommits(
	ctx context.Context,
	projectID int,
	ref string,
) ([]repoCommit, error) {
	u := fmt.Sprintf(
		"%s/api/v4/projects/%d/repository/commits"+
			"?ref_name=%s&per_page=%d",
		strings.TrimRight(s.cfg.GitlabBaseURL, "/"),
		projectID,
		url.QueryEscape(ref),
		recentCommitsCount,
	)
	var cs []repoCommit
	if err := s.gitlabGetJSON(ctx, u, "commits", &cs); err != nil {
		return nil, err
	}
	return cs, nil
}

type chatReq struct {
	Model     string    `json:"model"`
	Verbosity string    `json:"verbosity,omitempty"`
	Messages  []chatMsg `json:"messages"`
	MaxTokens int       `json:"max_tokens,omitempty"`
}

type chatMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResp struct {
	Choices []struct {
		Message chatMsg `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

const summarySystemPrompt = `# Objective

Produce Slack-ready summaries of Git push diffs for the team.

# Instructions

- Output exactly one sentence
- Use a maximum of 25 words
- Maintain a technical, dry tone
- Use all lowercase
- Final language must always be English
- Semi-informal internet speech is allowed
- Do not include a preamble, markdown, or quotation marks
- Return only the requested sentence
- Prefer concise, information-dense wording
- Apply the length limit only to the final sentence
- The final sentence must not end with a period
- If constraints conflict, preserve the one-sentence, 25-word, lowercase, English-only output contract
- Before finalizing, quickly verify wording, casing, word count, and that the sentence does not end with a period

# Content Guidance

- Focus on the substantive change in the diff
- If the diff is trivial, such as a typo, formatting change, or version bump, state that it is trivial
- If the diff context is insufficient to determine the substantive change, do not guess; briefly state the limitation within the one-sentence limit
- If multiple changes appear, mention the most consequential substantive change`

func (s *Server) summarise(
	ctx context.Context,
	system, user string,
) (string, error) {
	body, err := json.Marshal(chatReq{
		Model:     s.cfg.OpenRouterModel,
		Verbosity: "low",
		MaxTokens: summaryMaxTokens,
		Messages: []chatMsg{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
	})
	if err != nil {
		return "", fmt.Errorf("openrouter marshal: %w", err)
	}
	cctx, cancel := context.WithTimeout(ctx, s.cfg.OpenRouterTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(
		cctx,
		http.MethodPost,
		strings.TrimRight(
			s.cfg.OpenRouterBaseURL,
			"/",
		)+"/chat/completions",
		bytes.NewReader(body),
	)
	if err != nil {
		return "", fmt.Errorf("openrouter request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.cfg.OpenRouterAPIKey)
	if s.cfg.OpenRouterProxyKey != "" {
		req.Header.Set("X-Cmld-Aig-Proxy-Key", s.cfg.OpenRouterProxyKey)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("openrouter request: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, aiResponseMaxBytes))
	var cr chatResp
	if err = json.Unmarshal(rb, &cr); err != nil {
		return "", fmt.Errorf(
			"openrouter decode: %w (body: %s)",
			err,
			truncate(string(rb), aiErrPreviewBytes),
		)
	}
	if cr.Error != nil {
		return "", errors.New(cr.Error.Message)
	}
	if len(cr.Choices) == 0 {
		return "", errors.New("no choices in response")
	}
	return strings.TrimSpace(cr.Choices[0].Message.Content), nil
}

func (s *Server) scrubTG(err error) error {
	if err == nil {
		return nil
	}
	return errors.New(
		strings.ReplaceAll(err.Error(), s.cfg.TelegramToken, "<redacted>"),
	)
}

func (s *Server) sendTelegram(ctx context.Context, text string) error {
	if utf16Len(text) > tgMaxMessageChars {
		text = truncateUTF16(
			text,
			tgMaxMessageChars-tgTruncateSuffixBudget,
		) + tgTruncateMarker
	}
	form := url.Values{
		"chat_id":                  {s.cfg.TelegramChatID},
		"text":                     {text},
		"parse_mode":               {"HTML"},
		"disable_web_page_preview": {"true"},
	}
	if s.cfg.TelegramThreadID != "" {
		form.Set("message_thread_id", s.cfg.TelegramThreadID)
	}
	u := fmt.Sprintf("%s/bot%s/sendMessage",
		strings.TrimRight(s.cfg.TelegramBaseURL, "/"), s.cfg.TelegramToken)
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		u,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return s.scrubTG(fmt.Errorf("telegram request: %w", err))
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.client.Do(req)
	if err != nil {
		return s.scrubTG(fmt.Errorf("telegram request: %w", err))
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, tgResponseMaxBytes))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram %d: %s", resp.StatusCode, bytes.TrimSpace(rb))
	}
	return nil
}

func parseRef(ref string) (string, string) {
	switch {
	case strings.HasPrefix(ref, "refs/heads/"):
		return "branch", strings.TrimPrefix(ref, "refs/heads/")
	case strings.HasPrefix(ref, "refs/tags/"):
		return "tag", strings.TrimPrefix(ref, "refs/tags/")
	default:
		return "ref", ref
	}
}

func repoLink(p Project) string {
	return fmt.Sprintf(
		`<a href="%s">%s</a>`,
		html.EscapeString(p.WebURL),
		html.EscapeString(p.PathWithNamespace),
	)
}

func refLink(p Project, kind, name string) string {
	var u string
	switch kind {
	case "tag":
		u = fmt.Sprintf("%s/-/tags/%s", p.WebURL, url.PathEscape(name))
	default:
		u = fmt.Sprintf("%s/-/tree/%s", p.WebURL, url.PathEscape(name))
	}
	return fmt.Sprintf(
		`<a href="%s">%s</a>`,
		html.EscapeString(u),
		html.EscapeString(name),
	)
}

func formatMessage(
	ev *PushEvent,
	refKind, refName string,
	additions, deletions, fileCount int,
	summary string,
) string {
	var b strings.Builder
	commitWord := "new commit"
	if ev.TotalCommitsCount != 1 {
		commitWord = "new commits"
	}
	fmt.Fprintf(&b, "<b>[%s:%s]</b> %d %s by %s",
		repoLink(ev.Project), refLink(ev.Project, refKind, refName),
		ev.TotalCommitsCount, commitWord,
		html.EscapeString(ev.UserName))
	if ev.UserUsername != "" {
		fmt.Fprintf(&b, " (<code>%s</code>)", html.EscapeString(ev.UserUsername))
	}
	b.WriteString("\n")
	if ev.Before == zeroSHA {
		fmt.Fprintf(&b, "// new %s\n", refKind)
	}
	for _, c := range ev.Commits {
		title, body := splitCommitMessage(c.Message, c.Title)
		fmt.Fprintf(&b, "\n[<a href=\"%s\">%s</a>] %s",
			html.EscapeString(c.URL), shortSHA(c.ID),
			html.EscapeString(title))
		if body != "" {
			fmt.Fprintf(&b, "\n  <i>%s</i>", html.EscapeString(collapseBody(body)))
		}
		// fmt.Fprintf(&b, " — <b>%s</b>", html.EscapeString(c.Author.Name))
	}
	if ev.TotalCommitsCount > len(ev.Commits) {
		fmt.Fprintf(&b, "\n\n<i>… and %d more (gitlab caps payload at 20)</i>",
			ev.TotalCommitsCount-len(ev.Commits))
	}
	if fileCount > 0 {
		compareURL := fmt.Sprintf(
			"%s/-/compare/%s...%s",
			ev.Project.WebURL,
			ev.Before,
			ev.After,
		)
		filesWord := "file"
		if fileCount != 1 {
			filesWord = "files"
		}
		fmt.Fprintf(
			&b,
			"\n\n// +%d/−%d across %d %s · <a href=\"%s\">full diff</a>",
			additions,
			deletions,
			fileCount,
			filesWord,
			html.EscapeString(compareURL),
		)
	}
	if summary != "" {
		fmt.Fprintf(&b, "\n// <i>%s</i>", html.EscapeString(summary))
	}
	return b.String()
}

func shortSHA(id string) string {
	if len(id) > shortSHALen {
		return id[:shortSHALen]
	}
	return id
}

func splitCommitMessage(message, title string) (string, string) {
	message = strings.TrimSpace(message)
	before, after, ok := strings.Cut(message, "\n")
	if title == "" {
		if ok {
			title = strings.TrimSpace(before)
		} else {
			title = message
		}
	}
	if ok {
		return title, strings.TrimSpace(after)
	}
	return title, ""
}

func collapseBody(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	lines := strings.Split(s, "\n")
	cleaned := make([]string, 0, len(lines))
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln != "" {
			cleaned = append(cleaned, ln)
		}
	}
	out := strings.Join(cleaned, " · ")
	return truncate(out, commitBodyMaxLen)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		if r > maxBMPRune {
			n += 2
		} else {
			n++
		}
	}
	return n
}

func truncateUTF16(s string, limit int) string {
	n := 0
	for i, r := range s {
		w := 1
		if r > maxBMPRune {
			w = 2
		}
		if n+w > limit {
			return s[:i]
		}
		n += w
	}
	return s
}

func countDiffStats(diffs []DiffEntry) (int, int) {
	var additions, deletions int
	for _, d := range diffs {
		for ln := range strings.SplitSeq(d.Diff, "\n") {
			switch {
			case strings.HasPrefix(ln, "+++"), strings.HasPrefix(ln, "---"):
				continue
			case strings.HasPrefix(ln, "+"):
				additions++
			case strings.HasPrefix(ln, "-"):
				deletions++
			}
		}
	}
	return additions, deletions
}

func buildDiffForAI(diffs []DiffEntry, maxLines, maxBytesPerFile int) string {
	var b strings.Builder
	remaining := maxLines
	for _, d := range diffs {
		if remaining <= 0 {
			b.WriteString("\n[… additional files truncated]\n")
			break
		}
		path := d.NewPath
		switch {
		case d.DeletedFile:
			path = d.OldPath + " (deleted)"
		case d.NewFile:
			path = d.NewPath + " (new)"
		case d.RenamedFile:
			path = d.OldPath + " → " + d.NewPath
		}
		fmt.Fprintf(&b, "--- %s\n", path)
		diff := d.Diff
		if len(diff) > maxBytesPerFile {
			diff = diff[:maxBytesPerFile] + "\n[… file truncated]"
		}
		lines := strings.Split(diff, "\n")
		if len(lines) > remaining {
			lines = lines[:remaining]
			lines = append(lines, "[… file truncated]")
		}
		b.WriteString(strings.Join(lines, "\n"))
		b.WriteString("\n")
		remaining -= len(lines)
	}
	return b.String()
}

func main() {
	cfg := loadConfig()
	logger := setupLogger(cfg)
	if err := validateConfig(cfg, logger); err != nil {
		logger.Fatal().Err(err).Msg("config invalid")
	}
	srv := newServer(cfg, logger)
	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.routes(),
		ReadHeaderTimeout: httpReadHeaderTimeout,
		ReadTimeout:       httpReadTimeout,
		WriteTimeout:      httpWriteTimeout,
		IdleTimeout:       httpIdleTimeout,
	}
	ctx, stop := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer stop()
	var wg sync.WaitGroup
	wg.Go(func() {
		logger.Info().
			Str("listen", cfg.Listen).
			Str("model", cfg.OpenRouterModel).
			Bool("ai", cfg.OpenRouterEnabled).
			Msg("gitlab-telegram-relay starting")
		if err := httpSrv.ListenAndServe(); err != nil &&
			!errors.Is(err, http.ErrServerClosed) {
			logger.Fatal().Err(err).Msg("server crashed")
		}
	})
	<-ctx.Done()
	logger.Info().Msg("shutdown signal received")
	shutCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := httpSrv.Shutdown(shutCtx); err != nil {
		logger.Error().Err(err).Msg("graceful shutdown failed")
	}
	done := make(chan struct{})
	go func() { srv.inflight.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(shutdownTimeout):
		logger.Warn().Msg("in-flight pushes did not drain before timeout")
	}
	wg.Wait()
}
