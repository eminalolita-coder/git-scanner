package gitdump

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/eminalolita-coder/git-scanner/internal/model"
)

// DumbOptions bounds a dumb-protocol scan.
type DumbOptions struct {
	MaxCommits   int
	MaxObjects   int
	MaxBlobBytes int
	MaxTotal     int64
	MaxFile      int64
}

// DefaultDumbOptions returns conservative limits.
func DefaultDumbOptions() DumbOptions {
	return DumbOptions{
		MaxCommits:   0, // 0 = unlimited (bounded by objects/bytes)
		MaxObjects:   3000,
		MaxBlobBytes: 1 << 20,
		MaxTotal:     64 << 20,
		MaxFile:      64 << 20,
	}
}

// DumbScan walks a statically-served .git directory over HTTP: it scans the
// metadata files and, when loose objects are available, the reachable blobs.
// It works where the smart protocol is unavailable (go-git clone fails).
func DumbScan(ctx context.Context, base string, client *http.Client, o DumbOptions, t model.Target, h Handler) error {
	base = strings.TrimRight(base, "/")
	if o.MaxObjects == 0 {
		o = DefaultDumbOptions()
	}
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	d := &dumber{ctx: ctx, base: base, client: client, o: o, t: t, h: h, seen: map[string]bool{}}

	// 1. metadata files (cheap, often leaky)
	meta := []string{"HEAD", "config", "description", "packed-refs", "info/refs",
		"COMMIT_EDITMSG", "logs/HEAD", "FETCH_HEAD", "ORIG_HEAD", "MERGE_HEAD"}
	for _, m := range meta {
		if b, err := d.get(base + "/" + m); err == nil && len(b) > 0 {
			h(t, Content{Bytes: b, File: ".git/" + m})
		}
	}
	// refs
	if head, err := d.get(base + "/HEAD"); err == nil {
		if ref := strings.TrimSpace(string(head)); strings.HasPrefix(ref, "ref: ") {
			if b, err := d.get(base + "/" + strings.TrimSpace(strings.TrimPrefix(ref, "ref: "))); err == nil && len(b) > 0 {
				h(t, Content{Bytes: b, File: ".git/" + strings.TrimPrefix(ref, "ref: ")})
			}
		}
	}

	// 2. object walk from HEAD (loose objects only)
	tip := d.resolveHead()
	if tip == "" {
		return nil
	}
	d.walk(tip)
	return nil
}

type dumber struct {
	ctx    context.Context
	base   string
	client *http.Client
	o      DumbOptions
	t      model.Target
	h      Handler

	seen     map[string]bool
	objects  int
	total    int64
	commits  int
	missing  int
	gotBlobs int

	pack      *packFile
	packTried bool
}

func (d *dumber) resolveHead() string {
	b, err := d.get(d.base + "/HEAD")
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(b))
	if !strings.HasPrefix(s, "ref: ") {
		return s
	}
	ref := strings.TrimSpace(strings.TrimPrefix(s, "ref: "))
	if b, err := d.get(d.base + "/" + ref); err == nil {
		if sha := strings.TrimSpace(string(b)); isHex(sha) {
			return sha
		}
	}
	// packed-refs
	if b, err := d.get(d.base + "/packed-refs"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "^") {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) == 2 && parts[1] == ref {
				return parts[0]
			}
		}
	}
	return ""
}

func (d *dumber) get(url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(d.ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "git-scanner")
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, d.o.MaxFile))
}

// getObject fetches and inflates a loose object, falling back to the pack.
func (d *dumber) getObject(sha string) (string, []byte, error) {
	if len(sha) < 3 {
		return "", nil, fmt.Errorf("bad sha")
	}
	raw, err := d.get(d.base + "/objects/" + sha[:2] + "/" + sha[2:])
	if err != nil {
		d.missing++
		// loose object absent: fall back to the packfile
		if d.pack == nil && !d.packTried {
			if p, perr := d.loadPack(); perr == nil {
				d.pack = p
			}
			d.packTried = true
		}
		if d.pack != nil {
			if typ, body, perr := d.packObject(sha); perr == nil {
				return typ, body, nil
			}
		}
		return "", nil, err
	}
	zr, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		return "", nil, err
	}
	defer zr.Close()
	body, err := io.ReadAll(io.LimitReader(zr, int64(d.o.MaxBlobBytes)+4096))
	if err != nil {
		return "", nil, err
	}
	i := bytes.IndexByte(body, 0)
	if i < 0 {
		return "", nil, fmt.Errorf("bad object")
	}
	hdr := string(body[:i])
	typ := hdr
	if sp := strings.IndexByte(hdr, ' '); sp > 0 {
		typ = hdr[:sp]
	}
	return typ, body[i+1:], nil
}

func (d *dumber) walk(tip string) {
	queue := []string{tip}
	for len(queue) > 0 {
		if d.objects >= d.o.MaxObjects || d.total >= d.o.MaxTotal || d.ctx.Err() != nil {
			return
		}
		sha := queue[0]
		queue = queue[1:]
		if d.seen[sha] {
			continue
		}
		d.seen[sha] = true
		d.objects++
		d.total += 160

		typ, body, err := d.getObject(sha)
		if err != nil {
			continue
		}
		switch typ {
		case "commit":
			d.total += int64(len(body))
			unlimited := d.o.MaxCommits == 0
			if unlimited || d.commits < d.o.MaxCommits {
				if !unlimited {
					d.commits++
				}
				meta := body
				if i := bytes.Index(body, []byte("\n\n")); i > 0 {
					meta = body[:i]
				}
				d.h(d.t, Content{Bytes: meta, File: ".git/commit", Commit: sha})
				for _, t := range objectRefs(body, "tree") {
					queue = append(queue, t)
				}
				for _, p := range objectRefs(body, "parent") {
					queue = append(queue, p)
				}
			}
		case "tag":
			for _, t := range objectRefs(body, "object") {
				queue = append(queue, t)
			}
		case "tree":
			d.total += int64(len(body))
			for _, e := range parseTree(body) {
				switch {
				case strings.HasPrefix(e.mode, "100") || e.mode == "120000":
					if blob, err := d.blobContent(e.sha); err == nil && len(blob) > 0 {
						d.h(d.t, Content{Bytes: blob, File: e.name, Commit: sha})
					}
				case e.mode == "40000" || e.mode == "040000":
					queue = append(queue, e.sha)
				}
			}
		}
	}
}

func (d *dumber) blobContent(sha string) ([]byte, error) {
	typ, body, err := d.getObject(sha)
	if err != nil || typ != "blob" {
		return nil, err
	}
	d.total += int64(len(body))
	d.gotBlobs++
	return body, nil
}

func objectRefs(body []byte, key string) []string {
	var out []string
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, key+" ") {
			if v := strings.TrimSpace(strings.TrimPrefix(line, key+" ")); isHex(v) {
				out = append(out, v)
			}
		}
	}
	return out
}

type treeEntry struct {
	mode string
	name string
	sha  string
}

func parseTree(body []byte) []treeEntry {
	var out []treeEntry
	for i := 0; i < len(body); {
		sp := bytes.IndexByte(body[i:], ' ')
		if sp < 0 {
			break
		}
		mode := string(body[i : i+sp])
		i += sp + 1
		nul := bytes.IndexByte(body[i:], 0)
		if nul < 0 {
			break
		}
		name := string(body[i : i+nul])
		i += nul + 1
		if i+20 > len(body) {
			break
		}
		out = append(out, treeEntry{mode: mode, name: name, sha: hex.EncodeToString(body[i : i+20])})
		i += 20
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].name < out[b].name })
	return out
}

func isHex(s string) bool {
	if len(s) != 40 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

var _ = strconv.Itoa
