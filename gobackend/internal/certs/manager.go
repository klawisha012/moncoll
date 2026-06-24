package certs

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/zwarder/waf/gobackend/internal/storage"
)

// Result mirrors the dict returned by generate_self_signed_certificate /
// trigger_acme_request / regenerate_certificate in service.py.
type Result struct {
	Success         bool
	Message         string
	CertificatePath string // Angie-container path (for nginx config directives)
	KeyPath         string // Angie-container path
	BackendCertPath string // backend-container path (for file ops)
	BackendKeyPath  string // backend-container path
}

// StatusResult mirrors the dict returned by check_certificate_status.
type StatusResult struct {
	CertificateExists bool
	KeyExists         bool
	CertificatePath   *string // Angie path, nil if not exists
	KeyPath           *string // Angie path, nil if not exists
	BackendCertPath   *string // backend path, nil if not exists
	BackendKeyPath    *string // backend path, nil if not exists
}

// Manager holds ACME email and dispatches openssl/certbot via os/exec.
// Mirrors the module-level helpers in service.py.
type Manager struct {
	acmeEmail string
	store     storage.Store
	pub       *storage.Publisher
}

// New reads ACME_EMAIL from the environment (fallback: "admin@localhost"). The
// store + publisher propagate issued certs to the shared source of truth so
// edge nodes converge; key objects are written sensitive (SSE-encrypted, FR-010).
func New(store storage.Store, pub *storage.Publisher) *Manager {
	email := os.Getenv("ACME_EMAIL")
	if email == "" {
		email = "admin@localhost"
	}
	return &Manager{acmeEmail: email, store: store, pub: pub}
}

// uploadCert publishes the just-written cert/key (read from their backend paths)
// to the shared store, the key as a sensitive/SSE object. Best-effort: the cert
// already exists locally, so a propagation failure is logged, not fatal — the
// poller retries on its next tick.
func (m *Manager) uploadCert(connID int64, tenantID *int64, backendCert, backendKey string) {
	if m.store == nil || m.pub == nil {
		return
	}
	certKey, keyKey := sslKeys(connID, tenantID)
	ctx := context.Background()
	certOI, err := m.putFile(ctx, certKey, backendCert, false)
	if err != nil {
		slog.Warn("certs: upload cert failed", "conn", connID, "err", err)
		return
	}
	keyOI, err := m.putFile(ctx, keyKey, backendKey, true)
	if err != nil {
		slog.Warn("certs: upload key failed", "conn", connID, "err", err)
		return
	}
	if err := m.pub.Publish(ctx, storage.ChangeSet{Changed: []storage.ObjectInfo{certOI, keyOI}}); err != nil {
		slog.Warn("certs: publish manifest failed", "conn", connID, "err", err)
	}
}

func (m *Manager) putFile(ctx context.Context, key, path string, sensitive bool) (storage.ObjectInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return storage.ObjectInfo{}, err
	}
	return m.store.Put(ctx, key, bytes.NewReader(data), storage.PutOptions{Sensitive: sensitive})
}

// ensureSSLDirs mirrors _ensure_ssl_dirs: creates /var/lib/angie/http.d.
func (m *Manager) ensureSSLDirs() error {
	return os.MkdirAll(backendHTTPDDir, 0o755)
}

// ensureACMEChallengeDir mirrors _ensure_acme_challenge_dir for non-tenant
// connections. For tenant connections the caller creates the dir inline.
func ensureACMEChallengeDir(connID int64) error {
	dir := filepath.Join(backendHTTPDDir, fmt.Sprintf("conn_%d", connID), "site", ".well-known", "acme-challenge")
	return os.MkdirAll(dir, 0o755)
}

// GenerateSelfSigned mirrors generate_self_signed_certificate.
// It writes files using backend paths and returns Angie paths in Result so
// they can be inserted directly into nginx config directives.
func (m *Manager) GenerateSelfSigned(connID int64, domains []string, tenantID *int64) (Result, error) {
	if err := m.ensureSSLDirs(); err != nil {
		return Result{Success: false, Message: fmt.Sprintf("ensureSSLDirs: %v", err)}, nil
	}

	backendCert, backendKey := BackendSSLPaths(connID, tenantID)
	angieCert, angieKey := AngieSSLPaths(connID, tenantID)

	// CA paths (backend-container view)
	caCertPath := "/var/lib/angie/http.d/ca.crt"
	caKeyPath := "/var/lib/angie/http.d/ca.key"

	// Ensure connection subdirectory exists
	if err := os.MkdirAll(filepath.Dir(backendCert), 0o755); err != nil {
		return Result{Success: false, Message: fmt.Sprintf("mkdir: %v", err)}, nil
	}

	// Generate private key
	if err := runCmd("openssl", "genrsa", "-out", backendKey, "2048"); err != nil {
		return Result{Success: false, Message: fmt.Sprintf("Failed to generate certificate: %v", err)}, nil
	}

	_, caExists := os.Stat(caCertPath)
	_, caKeyExists := os.Stat(caKeyPath)

	if caExists == nil && caKeyExists == nil {
		// Sign with local CA (mirrors the if Path(ca_cert_path).exists() branch)
		cnfFile, err := os.CreateTemp("", "san*.cnf")
		if err != nil {
			return Result{Success: false, Message: fmt.Sprintf("Failed to generate certificate: %v", err)}, nil
		}
		sanCNF := cnfFile.Name()
		defer os.Remove(sanCNF)

		// Build SAN extension list
		sanNames := make([]string, 0, len(domains))
		for _, d := range domains {
			sanNames = append(sanNames, "DNS:"+d)
		}

		fmt.Fprintf(cnfFile, "[req]\n")
		fmt.Fprintf(cnfFile, "distinguished_name = req_distinguished_name\n")
		fmt.Fprintf(cnfFile, "req_extensions = v3_req\n")
		fmt.Fprintf(cnfFile, "prompt = no\n")
		fmt.Fprintf(cnfFile, "[req_distinguished_name]\n")
		fmt.Fprintf(cnfFile, "CN = %s\n", domains[0])
		fmt.Fprintf(cnfFile, "[v3_req]\n")
		fmt.Fprintf(cnfFile, "subjectAltName = %s\n", strings.Join(sanNames, ","))
		cnfFile.Close()

		csrPath := fmt.Sprintf("/tmp/conn_%d.csr", connID)
		defer os.Remove(csrPath)

		if err := runCmd("openssl", "req", "-new", "-key", backendKey, "-out", csrPath, "-config", sanCNF); err != nil {
			return Result{Success: false, Message: fmt.Sprintf("Failed to generate certificate: %v", err)}, nil
		}

		if err := runCmd("openssl", "x509", "-req", "-days", "365",
			"-in", csrPath,
			"-CA", caCertPath,
			"-CAkey", caKeyPath,
			"-CAcreateserial",
			"-out", backendCert,
			"-extfile", sanCNF,
			"-extensions", "v3_req",
		); err != nil {
			return Result{Success: false, Message: fmt.Sprintf("Failed to generate certificate: %v", err)}, nil
		}
	} else {
		// Fallback: self-signed (mirrors the else branch)
		subj := fmt.Sprintf("/C=US/ST=State/L=City/O=Organization/CN=%s", domains[0])
		sanNames := make([]string, 0, len(domains))
		for _, d := range domains {
			sanNames = append(sanNames, "DNS:"+d)
		}
		altNames := "subjectAltName=" + strings.Join(sanNames, ",")

		if err := runCmd("openssl", "req", "-new", "-x509",
			"-key", backendKey,
			"-out", backendCert,
			"-days", "365",
			"-subj", subj,
			"-addext", altNames,
		); err != nil {
			return Result{Success: false, Message: fmt.Sprintf("Failed to generate certificate: %v", err)}, nil
		}
	}

	m.uploadCert(connID, tenantID, backendCert, backendKey)
	return Result{
		Success:         true,
		Message:         fmt.Sprintf("Certificate generated for domains: %s", strings.Join(domains, ", ")),
		CertificatePath: angieCert,
		KeyPath:         angieKey,
		BackendCertPath: backendCert,
		BackendKeyPath:  backendKey,
	}, nil
}

// findExistingLECert mirrors _find_existing_le_cert.
// It searches /etc/letsencrypt/live/ for a cert covering the requested domains.
func findExistingLECert(domains []string) string {
	liveRoot := "/etc/letsencrypt/live"
	info, err := os.Stat(liveRoot)
	if err != nil || !info.IsDir() {
		return ""
	}

	domainSet := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		domainSet[strings.ToLower(d)] = struct{}{}
	}

	entries, err := os.ReadDir(liveRoot)
	if err != nil {
		return ""
	}
	// sort for determinism (mirrors sorted(live_root.iterdir()))
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	sanRe := regexp.MustCompile(`DNS:([^\s,]+)`)
	cnRe := regexp.MustCompile(`Subject:.*?CN\s*=\s*([^\s,]+)`)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		candidate := filepath.Join(liveRoot, entry.Name())
		fullchain := filepath.Join(candidate, "fullchain.pem")
		if _, err := os.Stat(fullchain); err != nil {
			continue
		}

		cmd := exec.Command("openssl", "x509", "-in", fullchain, "-text", "-noout")
		out, err := runCmdOutput(cmd, 10*time.Second)
		if err != nil {
			continue
		}

		certDomains := make(map[string]struct{})
		for _, m := range sanRe.FindAllStringSubmatch(out, -1) {
			certDomains[strings.ToLower(strings.TrimRight(m[1], "."))] = struct{}{}
		}
		if m := cnRe.FindStringSubmatch(out); m != nil {
			certDomains[strings.ToLower(strings.TrimRight(m[1], "."))] = struct{}{}
		}

		// domain_set.issubset(cert_domains) or domain_set & cert_domains
		if domainIsSubset(domainSet, certDomains) || domainIntersects(domainSet, certDomains) {
			return candidate
		}
	}
	return ""
}

// TriggerACME mirrors trigger_acme_request.
// Certbot webroot mode; idempotent re-copy on existing cert; self-signed
// fallback is NOT called here — regenerate_certificate calls trigger_acme_request
// which returns success=false on certbot failure; the Python code does not
// fall back to self-signed inside trigger_acme_request itself.
func (m *Manager) TriggerACME(connID int64, domains []string, tenantID *int64) Result {
	if err := m.ensureSSLDirs(); err != nil {
		return Result{Success: false, Message: fmt.Sprintf("ensureSSLDirs: %v", err)}
	}

	var webroot string
	if tenantID != nil {
		webroot = fmt.Sprintf("/var/lib/waf/tenants/%d/compose/conn_%d/site", *tenantID, connID)
		challengeDir := filepath.Join(webroot, ".well-known", "acme-challenge")
		if err := os.MkdirAll(challengeDir, 0o755); err != nil {
			return Result{Success: false, Message: fmt.Sprintf("mkdir challenge: %v", err)}
		}
	} else {
		webroot = filepath.Join(backendHTTPDDir, fmt.Sprintf("conn_%d", connID), "site")
		if err := ensureACMEChallengeDir(connID); err != nil {
			return Result{Success: false, Message: fmt.Sprintf("mkdir challenge: %v", err)}
		}
	}

	backendCert, backendKey := BackendSSLPaths(connID, tenantID)
	angieCert, angieKey := AngieSSLPaths(connID, tenantID)

	// Ensure connection subdirectory exists
	if err := os.MkdirAll(filepath.Dir(backendCert), 0o755); err != nil {
		return Result{Success: false, Message: fmt.Sprintf("mkdir cert dir: %v", err)}
	}

	certName := fmt.Sprintf("conn_%d", connID)
	liveDir := fmt.Sprintf("/etc/letsencrypt/live/%s", certName)

	// Already have a cert from a previous run? -> re-copy it
	if fi, err := os.Stat(liveDir); err == nil && fi.IsDir() {
		if _, err2 := os.Stat(filepath.Join(liveDir, "fullchain.pem")); err2 == nil {
			slog.Info("cert already exists, re-copying", "conn", connID, "live_dir", liveDir)
			if err := copyFile(filepath.Join(liveDir, "fullchain.pem"), backendCert); err != nil {
				return Result{Success: false, Message: fmt.Sprintf("copy fullchain: %v", err)}
			}
			if err := copyFile(filepath.Join(liveDir, "privkey.pem"), backendKey); err != nil {
				return Result{Success: false, Message: fmt.Sprintf("copy privkey: %v", err)}
			}
			if err := os.Chmod(backendKey, 0o600); err != nil {
				return Result{Success: false, Message: fmt.Sprintf("chmod key: %v", err)}
			}
			m.uploadCert(connID, tenantID, backendCert, backendKey)
			return Result{
				Success:         true,
				Message:         fmt.Sprintf("Let's Encrypt certificate reused for %s", strings.Join(domains, ", ")),
				CertificatePath: angieCert,
				KeyPath:         angieKey,
				BackendCertPath: backendCert,
				BackendKeyPath:  backendKey,
			}
		}
	}

	// No cert at the expected name -> search existing LE certs by domain
	if existing := findExistingLECert(domains); existing != "" {
		slog.Info("found matching LE cert, copying", "conn", connID, "src", existing, "dst", backendCert)
		if err := copyFile(filepath.Join(existing, "fullchain.pem"), backendCert); err != nil {
			return Result{Success: false, Message: fmt.Sprintf("copy fullchain: %v", err)}
		}
		if err := copyFile(filepath.Join(existing, "privkey.pem"), backendKey); err != nil {
			return Result{Success: false, Message: fmt.Sprintf("copy privkey: %v", err)}
		}
		if err := os.Chmod(backendKey, 0o600); err != nil {
			return Result{Success: false, Message: fmt.Sprintf("chmod key: %v", err)}
		}
		existingName := filepath.Base(existing)
		m.uploadCert(connID, tenantID, backendCert, backendKey)
		return Result{
			Success:         true,
			Message:         fmt.Sprintf("Let's Encrypt certificate reused from %s for %s", existingName, strings.Join(domains, ", ")),
			CertificatePath: angieCert,
			KeyPath:         angieKey,
			BackendCertPath: backendCert,
			BackendKeyPath:  backendKey,
		}
	}

	// No cert yet → request a new one
	// certbot is pinned to /tmp for work-dir and logs-dir so the non-root
	// backend user can write; --config-dir stays at /etc/letsencrypt.
	domainArgs := make([]string, 0, len(domains)*2)
	for _, d := range domains {
		domainArgs = append(domainArgs, "-d", d)
	}

	args := []string{
		"certonly",
		"--webroot",
		"-w", webroot,
	}
	args = append(args, domainArgs...)
	args = append(args,
		"--non-interactive",
		"--agree-tos",
		"-m", m.acmeEmail,
		"--cert-name", certName,
		"--key-type", "rsa",
		"--preferred-challenges", "http",
		"--config-dir", "/etc/letsencrypt",
		"--work-dir", "/tmp/certbot-work",
		"--logs-dir", "/tmp/certbot-logs",
	)

	slog.Info("requesting Let's Encrypt cert", "conn", connID, "domains", domains, "webroot", webroot)

	cmd := exec.Command("certbot", args...)
	out, err := runCmdOutput(cmd, 120*time.Second)
	if err != nil {
		// Distinguish timeout vs not-found vs failure
		if isTimeout(err) {
			return Result{Success: false, Message: "certbot timed out after 120 seconds"}
		}
		if isNotFound(err) {
			return Result{Success: false, Message: "certbot is not installed in the backend container"}
		}
		// Extract last line of stderr like Python does
		lines := strings.Split(strings.TrimSpace(out), "\n")
		last := lines[len(lines)-1]
		slog.Error("certbot failed", "conn", connID, "stderr", out)
		return Result{Success: false, Message: fmt.Sprintf("certbot failed: %s", last)}
	}

	slog.Info("certbot success", "conn", connID, "stdout", out)

	if fi, statErr := os.Stat(liveDir); statErr != nil || !fi.IsDir() {
		return Result{Success: false, Message: fmt.Sprintf("certbot output missing: %s", liveDir)}
	}

	if err := copyFile(filepath.Join(liveDir, "fullchain.pem"), backendCert); err != nil {
		return Result{Success: false, Message: fmt.Sprintf("copy fullchain: %v", err)}
	}
	if err := copyFile(filepath.Join(liveDir, "privkey.pem"), backendKey); err != nil {
		return Result{Success: false, Message: fmt.Sprintf("copy privkey: %v", err)}
	}
	if err := os.Chmod(backendKey, 0o600); err != nil {
		return Result{Success: false, Message: fmt.Sprintf("chmod key: %v", err)}
	}

	m.uploadCert(connID, tenantID, backendCert, backendKey)
	return Result{
		Success:         true,
		Message:         fmt.Sprintf("Let's Encrypt certificate issued for %s", strings.Join(domains, ", ")),
		CertificatePath: angieCert,
		KeyPath:         angieKey,
		BackendCertPath: backendCert,
		BackendKeyPath:  backendKey,
	}
}

// CheckStatus mirrors check_certificate_status.
func (m *Manager) CheckStatus(connID int64, tenantID *int64) StatusResult {
	certPath, keyPath := BackendSSLPaths(connID, tenantID)
	angieCert, angieKey := AngieSSLPaths(connID, tenantID)

	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)

	certExists := certErr == nil
	keyExists := keyErr == nil

	r := StatusResult{
		CertificateExists: certExists,
		KeyExists:         keyExists,
	}
	if certExists {
		c := angieCert
		bc := certPath
		r.CertificatePath = &c
		r.BackendCertPath = &bc
	}
	if keyExists {
		k := angieKey
		bk := keyPath
		r.KeyPath = &k
		r.BackendKeyPath = &bk
	}
	return r
}

// Regenerate mirrors regenerate_certificate:
// ensures dirs, removes existing files, then calls TriggerACME.
func (m *Manager) Regenerate(connID int64, domains []string, tenantID *int64) Result {
	if err := m.ensureSSLDirs(); err != nil {
		return Result{Success: false, Message: fmt.Sprintf("ensureSSLDirs: %v", err)}
	}

	certPath, keyPath := BackendSSLPaths(connID, tenantID)

	// Ensure connection subdirectory exists
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return Result{Success: false, Message: fmt.Sprintf("mkdir: %v", err)}
	}

	// Remove existing certificates
	os.Remove(certPath)
	os.Remove(keyPath)

	// Trigger new ACME request
	return m.TriggerACME(connID, domains, tenantID)
}

// ──────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────────────────────────────────────

// runCmd runs a command capturing stdout+stderr; returns error on non-zero exit.
func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// runCmdOutput runs cmd with a timeout. Returns combined output and error.
// On timeout returns ("", timeoutError). On exec.ErrNotFound returns notFoundError.
func runCmdOutput(cmd *exec.Cmd, timeout time.Duration) (string, error) {
	type result struct {
		out []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		out, err := cmd.CombinedOutput()
		ch <- result{out, err}
	}()
	select {
	case r := <-ch:
		return string(r.out), r.err
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		return "", &timeoutErr{}
	}
}

type timeoutErr struct{}

func (e *timeoutErr) Error() string { return "timeout" }

func isTimeout(err error) bool {
	_, ok := err.(*timeoutErr)
	return ok
}

func isNotFound(err error) bool {
	return strings.Contains(err.Error(), "executable file not found") ||
		strings.Contains(err.Error(), "no such file")
}

// copyFile copies src → dst using shutil.copy2 semantics (preserves content).
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

func domainIsSubset(sub, super map[string]struct{}) bool {
	for k := range sub {
		if _, ok := super[k]; !ok {
			return false
		}
	}
	return true
}

func domainIntersects(a, b map[string]struct{}) bool {
	for k := range a {
		if _, ok := b[k]; ok {
			return true
		}
	}
	return false
}
