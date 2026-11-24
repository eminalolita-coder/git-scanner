package gitdump

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"strings"
)

// packFile is a git packfile loaded in memory, with its index.
type packFile struct {
	data    []byte
	offsets map[string]int64
	// cache of resolved objects by pack offset
	cache map[int64]packObj
}

type packObj struct {
	typ  string
	body []byte
}

// loadPack fetches the first pack (with its idx) of a dumb repository.
func (d *dumber) loadPack() (*packFile, error) {
	listing, err := d.get(d.base + "/objects/info/packs")
	if err != nil {
		return nil, err
	}
	var packName string
	for _, line := range strings.Split(string(listing), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "P ") {
			packName = strings.TrimSpace(strings.TrimPrefix(line, "P "))
			break
		}
	}
	if packName == "" {
		return nil, fmt.Errorf("no pack listed")
	}
	idx, err := d.get(d.base + "/objects/pack/" + packName + ".idx")
	if err != nil {
		return nil, err
	}
	pf := &packFile{offsets: map[string]int64{}, cache: map[int64]packObj{}}
	if err := pf.parseIdx(idx); err != nil {
		return nil, err
	}
	data, err := d.get(d.base + "/objects/pack/" + packName + ".pack")
	if err != nil {
		return nil, err
	}
	pf.data = data
	return pf, nil
}

// parseIdx parses a version 2 pack index.
func (pf *packFile) parseIdx(b []byte) error {
	if len(b) < 8+1024 || !bytes.Equal(b[:4], []byte{0xff, 0x74, 0x4f, 0x63}) {
		return fmt.Errorf("unsupported pack index")
	}
	if binary.BigEndian.Uint32(b[4:8]) != 2 {
		return fmt.Errorf("unsupported pack index version")
	}
	fanout := b[8 : 8+1024]
	n := int(binary.BigEndian.Uint32(fanout[1020:1024]))
	base := 8 + 1024
	if len(b) < base+n*20+n*4+n*4 {
		return fmt.Errorf("truncated pack index")
	}
	shas := b[base : base+n*20]
	offTable := b[base+n*20+n*4:]
	var large []byte
	if len(b) >= base+n*20+n*4+n*4 {
		large = b[base+n*20+n*4+n*4:]
	}
	for i := 0; i < n; i++ {
		sha := fmt.Sprintf("%x", shas[i*20:i*20+20])
		raw := binary.BigEndian.Uint32(offTable[i*4:])
		var off int64
		if raw&0x80000000 != 0 {
			li := int(raw&0x7fffffff) * 8
			if li+8 > len(large) {
				continue
			}
			off = int64(binary.BigEndian.Uint64(large[li:]))
		} else {
			off = int64(raw)
		}
		pf.offsets[sha] = off
	}
	return nil
}

// objectAt resolves a pack object, following deltas.
func (pf *packFile) objectAt(off int64, depth int) (string, []byte, error) {
	if depth > 64 {
		return "", nil, fmt.Errorf("delta too deep")
	}
	if o, ok := pf.cache[off]; ok {
		return o.typ, o.body, nil
	}
	typ, body, baseOff, err := pf.rawAt(off)
	if err != nil {
		return "", nil, err
	}
	switch typ {
	case "ofs_delta":
		btyp, bbody, err := pf.objectAt(baseOff, depth+1)
		if err != nil {
			return "", nil, err
		}
		out, err := applyDelta(bbody, body)
		if err != nil {
			return "", nil, err
		}
		pf.cache[off] = packObj{typ: btyp, body: out}
		return btyp, out, nil
	case "ref_delta":
		return "ref_delta", body, nil // resolved by the caller when needed
	default:
		pf.cache[off] = packObj{typ: typ, body: body}
		return typ, body, nil
	}
}

// rawAt inflates the entry at off, returning its type and (for deltas) the
// base offset or unresolved delta body.
func (pf *packFile) rawAt(off int64) (string, []byte, int64, error) {
	if off < 0 || off >= int64(len(pf.data)) {
		return "", nil, 0, fmt.Errorf("offset out of range")
	}
	p := int(off)
	b := pf.data
	first := b[p]
	p++
	typCode := (first >> 4) & 7
	size := int64(first & 0x0f)
	shift := uint(4)
	for first&0x80 != 0 {
		first = b[p]
		p++
		size |= int64(first&0x7f) << shift
		shift += 7
	}
	typ := map[byte]string{1: "commit", 2: "tree", 3: "blob", 4: "tag", 6: "ofs_delta", 7: "ref_delta"}[typCode]
	if typ == "" {
		return "", nil, 0, fmt.Errorf("unknown pack type %d", typCode)
	}

	var baseOff int64
	if typ == "ofs_delta" {
		// negative relative offset, little-endian 7-bit groups
		c := b[p]
		p++
		val := int64(c & 0x7f)
		for c&0x80 != 0 {
			c = b[p]
			p++
			val = ((val + 1) << 7) | int64(c&0x7f)
		}
		baseOff = off - val
	}

	zr, err := zlib.NewReader(bytes.NewReader(b[p:]))
	if err != nil {
		return "", nil, 0, err
	}
	defer zr.Close()
	body, err := io.ReadAll(io.LimitReader(zr, size+64))
	if err != nil && len(body) == 0 {
		return "", nil, 0, err
	}
	return typ, body, baseOff, nil
}

// applyDelta reconstructs an object from a base and a git delta.
func applyDelta(base, delta []byte) ([]byte, error) {
	i := 0
	srcSize, n := readVarint(delta[i:])
	i += n
	_ = srcSize
	tgtSize, n := readVarint(delta[i:])
	i += n
	out := make([]byte, 0, tgtSize)
	for i < len(delta) {
		op := delta[i]
		i++
		switch {
		case op&0x80 != 0: // copy from base
			var off, size int
			for bit := 0; bit < 4; bit++ {
				if op&(1<<bit) != 0 {
					off |= int(delta[i]) << (8 * bit)
					i++
				}
			}
			for bit := 0; bit < 3; bit++ {
				if op&(0x10<<bit) != 0 {
					size |= int(delta[i]) << (8 * bit)
					i++
				}
			}
			if size == 0 {
				size = 0x10000
			}
			if off+size > len(base) {
				return nil, fmt.Errorf("delta copy out of range")
			}
			out = append(out, base[off:off+size]...)
		case op == 0:
			if i < len(delta) {
				out = append(out, delta[i])
				i++
			}
		default: // insert op literal bytes
			end := i + int(op)
			if end > len(delta) {
				end = len(delta)
			}
			out = append(out, delta[i:end]...)
			i = end
		}
	}
	return out, nil
}

func readVarint(b []byte) (int, int) {
	var v int
	var shift uint
	for i := 0; i < len(b); i++ {
		v |= int(b[i]&0x7f) << shift
		if b[i]&0x80 == 0 {
			return v, i + 1
		}
		shift += 7
	}
	return v, len(b)
}

// packObject returns an object by sha from the loaded pack.
func (d *dumber) packObject(sha string) (string, []byte, error) {
	if d.pack == nil {
		return "", nil, fmt.Errorf("no pack")
	}
	off, ok := d.pack.offsets[sha]
	if !ok {
		return "", nil, fmt.Errorf("not in pack")
	}
	typ, body, err := d.pack.objectAt(off, 0)
	if err != nil {
		return "", nil, err
	}
	if typ == "ref_delta" {
		// resolve via the base sha encoded in the delta
		if len(body) >= 20 {
			baseSha := fmt.Sprintf("%x", body[:20])
			btyp, bbody, err := d.getObject(baseSha)
			if err != nil {
				return "", nil, err
			}
			out, err := applyDelta(bbody, body[20:])
			if err == nil {
				return btyp, out, nil
			}
		}
		return "", nil, fmt.Errorf("unresolved ref delta")
	}
	return typ, body, nil
}

var _ = sort.Ints
