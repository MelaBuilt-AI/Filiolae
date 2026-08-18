package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"filiolae.local/transparency-s2/internal/s2leaf"
	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera/api"
	"github.com/transparency-dev/tessera/api/layout"
	"github.com/transparency-dev/tessera/client"
	"golang.org/x/mod/sumdb/note"
)

type state struct {
	Schema        string            `json:"schema"`
	TreeSize      uint64            `json:"tree_size"`
	RootHex       string            `json:"root_hex"`
	CheckpointB64 string            `json:"checkpoint_b64"`
	LeavesB64     []string          `json:"leaves_b64"`
	Resources     map[string]string `json:"resources"`
}

type report struct {
	Schema           string            `json:"schema"`
	Monitor          string            `json:"monitor"`
	Status           string            `json:"status"`
	Reason           string            `json:"reason,omitempty"`
	TreeSize         uint64            `json:"tree_size,omitempty"`
	RootHex          string            `json:"root_hex,omitempty"`
	ConsistencyProof []string          `json:"consistency_proof_hex,omitempty"`
	Resources        map[string]string `json:"resources,omitempty"`
}

type boundedFetcher struct {
	base   *url.URL
	client *http.Client
}

func newFetcher(raw string) (*boundedFetcher, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("base URL must be literal IPv4 loopback HTTP")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("base URL port is invalid")
	}
	u.Path = "/"
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" && network != "tcp4" {
				return nil, fmt.Errorf("disallowed network")
			}
			host, requestedPort, err := net.SplitHostPort(address)
			if err != nil || host != "127.0.0.1" || requestedPort != u.Port() {
				return nil, fmt.Errorf("non-loopback dial refused")
			}
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp4", address)
		},
		DisableKeepAlives: true,
	}
	return &boundedFetcher{base: u, client: &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("redirect refused")
		},
	}}, nil
}

func (f *boundedFetcher) get(ctx context.Context, path string, limit int64) ([]byte, error) {
	if !strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
		return nil, fmt.Errorf("unsafe resource path")
	}
	u := *f.base
	u.Path = path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	response, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return nil, os.ErrNotExist
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("resource returned status %d", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, fmt.Errorf("resource exceeds bound")
	}
	return raw, nil
}

func (f *boundedFetcher) checkpoint(ctx context.Context) ([]byte, error) {
	return f.get(ctx, "/checkpoint", 65536)
}

func (f *boundedFetcher) tile(ctx context.Context, level, index uint64, partial uint8) ([]byte, error) {
	path := "/" + layout.TilePath(level, index, partial)
	raw, err := f.get(ctx, path, 256*32)
	if errors.Is(err, os.ErrNotExist) && partial != 0 {
		return f.get(ctx, "/"+layout.TilePath(level, index, 0), 256*32)
	}
	return raw, err
}

func (f *boundedFetcher) entry(ctx context.Context, index uint64, partial uint8) (string, []byte, error) {
	path := "/" + layout.EntriesPath(index, partial)
	raw, err := f.get(ctx, path, 256*(s2leaf.MaxLeafBytes+2))
	if errors.Is(err, os.ErrNotExist) && partial != 0 {
		path = "/" + layout.EntriesPath(index, 0)
		raw, err = f.get(ctx, path, 256*(s2leaf.MaxLeafBytes+2))
	}
	return path, raw, err
}

func writeJSON(path string, value any, mode os.FileMode) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp := path + ".tmp-" + strconv.Itoa(os.Getpid())
	if err := os.WriteFile(tmp, raw, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func main() {
	baseURL := flag.String("base-url", "", "literal loopback log URL")
	mirror := flag.String("mirror", "", "private independent mirror root")
	verifierPath := flag.String("verifier", "", "synthetic checkpoint verifier key")
	trustPath := flag.String("trust", "", "synthetic leaf trust fixture")
	expected := flag.Uint64("expected-size", 0, "required exact checkpoint size")
	reportPath := flag.String("report", "", "result report path")
	flag.Parse()
	result := report{Schema: "filiolae.transparency-s2-monitor-report.v1", Monitor: "independent-go", Status: "suspect"}
	fail := func(reason string) {
		result.Reason = reason
		_ = writeJSON(*reportPath, result, 0o600)
		fmt.Fprintln(os.Stderr, reason)
		os.Exit(2)
	}
	if *baseURL == "" || *mirror == "" || *verifierPath == "" || *trustPath == "" || *reportPath == "" || *expected == 0 {
		fail("all arguments and nonzero expected size are required")
	}
	info, err := os.Lstat(*mirror)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		fail("mirror root must be an existing mode-0700 directory")
	}
	fetcher, err := newFetcher(*baseURL)
	if err != nil {
		fail(err.Error())
	}
	trustRaw, err := os.ReadFile(*trustPath)
	if err != nil {
		fail("cannot read trust fixture")
	}
	trust, err := s2leaf.LoadTrust(trustRaw)
	if err != nil {
		fail(err.Error())
	}
	verifierRaw, err := os.ReadFile(*verifierPath)
	if err != nil {
		fail("cannot read verifier")
	}
	verifier, err := note.NewVerifier(strings.TrimSpace(string(verifierRaw)))
	if err != nil || verifier.Name() != "filiolae.invalid/synthetic-s2/v1" {
		fail("invalid synthetic checkpoint verifier")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	checkpoint, checkpointRaw, _, err := client.FetchCheckpoint(ctx, fetcher.checkpoint, verifier, verifier.Name())
	if err != nil {
		fail("checkpoint verification failed")
	}
	if checkpoint.Size != *expected {
		fail(fmt.Sprintf("checkpoint size %d does not equal expected %d", checkpoint.Size, *expected))
	}

	statePath := filepath.Join(*mirror, "state.json")
	previous := state{Resources: map[string]string{}}
	if raw, err := os.ReadFile(statePath); err == nil {
		if err := json.Unmarshal(raw, &previous); err != nil || previous.Schema != "filiolae.transparency-s2-monitor-state.v1" {
			fail("prior monitor state is invalid")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		fail("cannot read prior monitor state")
	}
	for resourcePath, digest := range previous.Resources {
		raw, err := fetcher.get(ctx, resourcePath, 256*(s2leaf.MaxLeafBytes+2))
		if err != nil {
			fail("previously immutable resource is unavailable")
		}
		actual := sha256.Sum256(raw)
		if hex.EncodeToString(actual[:]) != digest {
			conflictDir := filepath.Join(*mirror, "conflicts")
			_ = os.MkdirAll(conflictDir, 0o700)
			_ = os.WriteFile(filepath.Join(conflictDir, hex.EncodeToString(actual[:])+".bin"), raw, 0o600)
			fail("previously immutable resource changed")
		}
	}

	leaves := make([][]byte, 0, checkpoint.Size)
	resources := make(map[string]string, len(previous.Resources)+1)
	for key, value := range previous.Resources {
		resources[key] = value
	}
	for rangeInfo := range layout.Range(0, checkpoint.Size, checkpoint.Size) {
		path, raw, err := fetcher.entry(ctx, rangeInfo.Index, rangeInfo.Partial)
		if err != nil {
			fail("entry resource fetch failed")
		}
		digest := sha256.Sum256(raw)
		digestText := hex.EncodeToString(digest[:])
		if old, ok := resources[path]; ok && old != digestText {
			fail("current immutable resource changed")
		}
		resources[path] = digestText
		var bundle api.EntryBundle
		if err := bundle.UnmarshalText(raw); err != nil {
			fail("entry resource is truncated or malformed")
		}
		if int(rangeInfo.First+rangeInfo.N) > len(bundle.Entries) {
			fail("entry bundle does not cover checkpoint range")
		}
		for _, leaf := range bundle.Entries[rangeInfo.First : rangeInfo.First+rangeInfo.N] {
			if _, err := s2leaf.Validate(leaf, trust); err != nil {
				fail("entry leaf validation failed")
			}
			leaves = append(leaves, bytes.Clone(leaf))
		}
	}
	if uint64(len(leaves)) != checkpoint.Size {
		fail("complete mirror entry count mismatch")
	}
	factory := &compact.RangeFactory{Hash: rfc6962.DefaultHasher.HashChildren}
	tree := factory.NewEmptyRange(0)
	for _, leaf := range leaves {
		if err := tree.Append(rfc6962.DefaultHasher.HashLeaf(leaf), nil); err != nil {
			fail("independent root construction failed")
		}
	}
	root, err := tree.GetRootHash(nil)
	if err != nil || !bytes.Equal(root, checkpoint.Hash) {
		fail("complete mirror root differs from checkpoint")
	}
	proofHex := []string{}
	if previous.TreeSize > 0 {
		if previous.TreeSize > checkpoint.Size || len(previous.LeavesB64) > len(leaves) {
			fail("checkpoint rollback detected")
		}
		for i, encoded := range previous.LeavesB64 {
			if base64.StdEncoding.EncodeToString(leaves[i]) != encoded {
				fail("prior complete-mirror prefix changed")
			}
		}
		builder, err := client.NewProofBuilder(ctx, checkpoint.Size, fetcher.tile)
		if err != nil {
			fail("cannot create independent consistency proof builder")
		}
		consistency, err := builder.ConsistencyProof(ctx, previous.TreeSize, checkpoint.Size)
		if err != nil {
			fail("cannot fetch independent consistency proof")
		}
		oldRoot, err := hex.DecodeString(previous.RootHex)
		if err != nil || proof.VerifyConsistency(rfc6962.DefaultHasher, previous.TreeSize, checkpoint.Size, consistency, oldRoot, root) != nil {
			fail("append-only consistency verification failed")
		}
		for _, item := range consistency {
			proofHex = append(proofHex, hex.EncodeToString(item))
		}
	}
	newState := state{
		Schema:        "filiolae.transparency-s2-monitor-state.v1",
		TreeSize:      checkpoint.Size,
		RootHex:       hex.EncodeToString(root),
		CheckpointB64: base64.StdEncoding.EncodeToString(checkpointRaw),
		LeavesB64:     make([]string, len(leaves)),
		Resources:     resources,
	}
	for i, leaf := range leaves {
		newState.LeavesB64[i] = base64.StdEncoding.EncodeToString(leaf)
	}
	for path, digest := range resources {
		resourceDir := filepath.Join(*mirror, "resources")
		if err := os.MkdirAll(resourceDir, 0o700); err != nil {
			fail("cannot create resource mirror")
		}
		raw, err := fetcher.get(ctx, path, 256*(s2leaf.MaxLeafBytes+2))
		if err != nil {
			fail("resource became unavailable before commit")
		}
		actual := sha256.Sum256(raw)
		if hex.EncodeToString(actual[:]) != digest {
			fail("resource changed before atomic state commit")
		}
		if err := os.WriteFile(filepath.Join(resourceDir, digest+".bin"), raw, 0o600); err != nil {
			fail("cannot preserve immutable resource")
		}
	}
	leafDir := filepath.Join(*mirror, "leaves")
	if err := os.MkdirAll(leafDir, 0o700); err != nil {
		fail("cannot create leaf mirror")
	}
	for i, leaf := range leaves {
		if err := os.WriteFile(filepath.Join(leafDir, fmt.Sprintf("%020d.leaf", i)), leaf, 0o600); err != nil {
			fail("cannot preserve complete leaf")
		}
	}
	if err := writeJSON(statePath, newState, 0o600); err != nil {
		fail("cannot atomically commit monitor state")
	}
	result.Status = "healthy"
	result.TreeSize = checkpoint.Size
	result.RootHex = newState.RootHex
	result.ConsistencyProof = proofHex
	result.Resources = resources
	if err := writeJSON(*reportPath, result, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "cannot write healthy report")
		os.Exit(2)
	}
}
