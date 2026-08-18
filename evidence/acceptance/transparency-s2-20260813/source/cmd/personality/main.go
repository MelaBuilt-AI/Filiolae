package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"filiolae.local/transparency-s2/internal/s2leaf"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/net/netutil"
)

const leafMediaType = "application/vnd.filiolae.receipt-transparency-leaf.v1+json"

var resourcePath = regexp.MustCompile(`^/tile/(?:entries|[0-9]{1,2})/(?:x[0-9]{3}/)*[0-9]{3}(?:\.p/(?:[1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))?$`)

type eventWriter struct {
	mu sync.Mutex
	f  *os.File
}

func (w *eventWriter) write(kind string, fields map[string]any) {
	w.mu.Lock()
	defer w.mu.Unlock()
	value := map[string]any{"event": kind, "observed_at": time.Now().UTC().Format(time.RFC3339Nano)}
	for key, item := range fields {
		value[key] = item
	}
	encoded, _ := json.Marshal(value)
	_, _ = w.f.Write(append(encoded, '\n'))
	_ = w.f.Sync()
}

func safeWriteNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func readSigner(fd uintptr) (note.Signer, error) {
	f := os.NewFile(fd, "synthetic-checkpoint-key")
	if f == nil {
		return nil, fmt.Errorf("checkpoint key descriptor is absent")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("checkpoint key descriptor must reference a mode-0600 regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(raw) == 0 || len(raw) > 4096 {
		return nil, fmt.Errorf("checkpoint key descriptor is invalid")
	}
	return note.NewSigner(strings.TrimSpace(string(raw)))
}

func main() {
	storageDir := flag.String("storage-dir", "", "dedicated Tessera POSIX root")
	eventPath := flag.String("events", "", "local JSONL event record")
	portPath := flag.String("port-file", "", "new mode-0600 selected-port file")
	trustPath := flag.String("trust", "", "checked-in synthetic trust fixture")
	keyFD := flag.Uint64("key-fd", 3, "already-open synthetic checkpoint key descriptor")
	flag.Parse()
	if *storageDir == "" || *eventPath == "" || *portPath == "" || *trustPath == "" {
		fmt.Fprintln(os.Stderr, "all paths are required")
		os.Exit(2)
	}
	if info, err := os.Lstat(*storageDir); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		fmt.Fprintln(os.Stderr, "storage root must be an existing non-symlink directory")
		os.Exit(2)
	}
	trustRaw, err := os.ReadFile(*trustPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot read synthetic trust fixture")
		os.Exit(2)
	}
	trust, err := s2leaf.LoadTrust(trustRaw)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	signer, err := readSigner(uintptr(*keyFD))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if signer.Name() != "filiolae.invalid/synthetic-s2/v1" {
		fmt.Fprintln(os.Stderr, "checkpoint signer has the wrong synthetic origin")
		os.Exit(2)
	}
	eventsFile, err := os.OpenFile(*eventPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot open event record")
		os.Exit(2)
	}
	defer eventsFile.Close()
	events := &eventWriter{f: eventsFile}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	driver, err := posix.New(ctx, posix.Config{Path: *storageDir})
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot initialize Tessera POSIX storage")
		os.Exit(1)
	}
	appender, shutdownAppender, reader, err := tessera.NewAppender(ctx, driver,
		tessera.NewAppendOptions().
			WithCheckpointSigner(signer).
			WithBatching(1, 100*time.Millisecond).
			WithCheckpointInterval(100*time.Millisecond))
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot initialize Tessera appender")
		os.Exit(1)
	}
	awaiter := tessera.NewPublicationAwaiter(ctx, reader.ReadCheckpoint, 20*time.Millisecond)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /add", func(w http.ResponseWriter, r *http.Request) {
		mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != leafMediaType || len(params) != 0 {
			http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
			return
		}
		if r.ContentLength < 0 || r.ContentLength > s2leaf.MaxLeafBytes {
			http.Error(w, "bounded content length required", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, s2leaf.MaxLeafBytes)
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "invalid bounded request body", http.StatusBadRequest)
			return
		}
		meta, err := s2leaf.Validate(raw, trust)
		if err != nil {
			events.write("append.rejected", map[string]any{"reason": "leaf_validation"})
			http.Error(w, "invalid synthetic receipt leaf", http.StatusUnprocessableEntity)
			return
		}
		requestCtx, requestCancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer requestCancel()
		index, _, err := awaiter.Await(requestCtx, appender.Add(requestCtx, tessera.NewEntry(raw)))
		if err != nil {
			events.write("append.failed", map[string]any{"reason": "publication"})
			http.Error(w, "append was not published", http.StatusServiceUnavailable)
			return
		}
		digest := sha256.Sum256(raw)
		leafDigest := hex.EncodeToString(digest[:])
		events.write("append.published", map[string]any{"index": index.Index, "leaf_sha256": leafDigest, "run_id": meta.RunID})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{"index": index.Index, "leaf_sha256": leafDigest})
	})
	mux.HandleFunc("GET /checkpoint", func(w http.ResponseWriter, r *http.Request) {
		serveResource(w, *storageDir, "/checkpoint", false)
	})
	mux.HandleFunc("GET /tile/", func(w http.ResponseWriter, r *http.Request) {
		serveResource(w, *storageDir, r.URL.Path, true)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "not found", http.StatusNotFound)
	})

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot bind loopback listener")
		os.Exit(1)
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || !address.IP.Equal(net.ParseIP("127.0.0.1")) {
		_ = listener.Close()
		fmt.Fprintln(os.Stderr, "listener is not IPv4 loopback")
		os.Exit(1)
	}
	if err := safeWriteNew(*portPath, []byte(strconv.Itoa(address.Port)+"\n"), 0o600); err != nil {
		_ = listener.Close()
		fmt.Fprintln(os.Stderr, "cannot publish selected port")
		os.Exit(1)
	}
	events.write("service.started", map[string]any{"address": "127.0.0.1", "port": address.Port, "pid": os.Getpid()})

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      12 * time.Second,
		IdleTimeout:       5 * time.Second,
		MaxHeaderBytes:    8 * 1024,
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(netutil.LimitListener(listener, 16)) }()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	var exitErr error
	select {
	case sig := <-signals:
		events.write("service.stopping", map[string]any{"signal": sig.String()})
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		exitErr = server.Shutdown(shutdownCtx)
		shutdownCancel()
	case err := <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) {
			exitErr = err
		}
	}
	if err := shutdownAppender(context.Background()); err != nil && exitErr == nil {
		exitErr = err
	}
	cancel()
	events.write("service.stopped", map[string]any{"clean": exitErr == nil})
	if exitErr != nil {
		fmt.Fprintln(os.Stderr, "service shutdown failed")
		os.Exit(1)
	}
}

func serveResource(w http.ResponseWriter, root, requestPath string, requireTile bool) {
	if requireTile && !resourcePath.MatchString(requestPath) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	relative := strings.TrimPrefix(requestPath, "/")
	cleaned := filepath.Clean(relative)
	if cleaned != relative || strings.HasPrefix(cleaned, ".") || filepath.IsAbs(cleaned) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	path := filepath.Join(root, cleaned)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, "resource unavailable", http.StatusServiceUnavailable)
		return
	}
	if requestPath == "/checkpoint" {
		w.Header().Set("Cache-Control", "no-cache")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
	_, _ = w.Write(raw)
}
