package aws

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// BucketAccess describes the public accessibility of a bucket.
type BucketAccess struct {
	Name        string   `json:"name"`
	Region      string   `json:"region,omitempty"`
	Exists      bool     `json:"exists"`
	Public      bool     `json:"public"` // anonymous listing allowed
	AnonRead    bool     `json:"anon_read"`
	ObjectCount int      `json:"object_count"`
	Sample      []string `json:"sample,omitempty"`
	Err         string   `json:"error,omitempty"`
}

// isDotted reports whether a bucket name contains dots, in which case the
// virtual-host form does not match the S3 wildcard certificate.
func isDotted(bucket string) bool { return strings.Contains(bucket, ".") }

// bucketBase returns the base URL for a bucket, using path-style addressing for
// dotted names (TLS wildcard + DNS constraints).
func bucketBase(bucket, region string) string {
	if isDotted(bucket) {
		if region == "" || region == "us-east-1" {
			return "https://s3.amazonaws.com/" + bucket
		}
		return fmt.Sprintf("https://s3.%s.amazonaws.com/%s", region, bucket)
	}
	if region == "" || region == "us-east-1" {
		return fmt.Sprintf("https://%s.s3.amazonaws.com", bucket)
	}
	return fmt.Sprintf("https://%s.s3.%s.amazonaws.com", bucket, region)
}

// CheckBucket probes a bucket anonymously: it reports existence, region and
// whether the object listing is public, plus a sample of keys.
func CheckBucket(ctx context.Context, client *http.Client, name string, maxKeys int) BucketAccess {
	res := BucketAccess{Name: name}
	if maxKeys <= 0 {
		maxKeys = 20
	}
	region, err := bucketRegion(ctx, client, name)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	res.Exists = true
	res.Region = region

	url := fmt.Sprintf("%s/?list-type=2&max-keys=%d", bucketBase(name, region), maxKeys)
	status, body, err := anonGet(ctx, client, name, url)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	switch status {
	case 200:
		res.Public = true
		res.AnonRead = true
		keys, count := parseListing(body)
		res.Sample = keys
		res.ObjectCount = count
	case 403:
		res.Exists = true
		res.Err = "403 (exists, listing not public)"
	case 404:
		res.Exists = false
		res.Err = "404 (no such bucket)"
	default:
		res.Err = fmt.Sprintf("status %d", status)
	}
	return res
}

// PublicObjectURL returns the anonymous URL of an object.
func PublicObjectURL(bucket, region, key string) string {
	return bucketBase(bucket, region) + "/" + key
}

// ObjectURL builds a URL for an object (region-aware).
func ObjectURL(bucket, region, key string, pathStyle bool) string {
	if pathStyle || isDotted(bucket) {
		return PublicObjectURL(bucket, region, key)
	}
	return bucketBase(bucket, region) + "/" + key
}

// bucketRegion discovers a bucket's region via a HEAD request (anonymous).
func bucketRegion(ctx context.Context, client *http.Client, name string) (string, error) {
	url := fmt.Sprintf("https://%s.s3.amazonaws.com/", name)
	if isDotted(name) {
		url = "https://s3.amazonaws.com/" + name
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := do(client, req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if r := resp.Header.Get("x-amz-bucket-region"); r != "" {
		return r, nil
	}
	switch resp.StatusCode {
	case 200, 403:
		return "us-east-1", nil
	case 404:
		return "", fmt.Errorf("no such bucket")
	default:
		return "us-east-1", nil
	}
}

func anonGet(ctx context.Context, client *http.Client, bucket, url string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", "git-scanner")
	resp, err := do(client, req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	// follow a region redirect once
	if resp.StatusCode == 301 {
		if r := resp.Header.Get("x-amz-bucket-region"); r != "" {
			req2, _ := http.NewRequestWithContext(ctx, http.MethodGet,
				bucketBase(bucket, r)+"/?list-type=2", nil)
			if req2 != nil {
				if resp2, err := do(client, req2); err == nil {
					defer resp2.Body.Close()
					b2, _ := io.ReadAll(io.LimitReader(resp2.Body, 2<<20))
					return resp2.StatusCode, b2, nil
				}
			}
		}
	}
	return resp.StatusCode, body, nil
}

func firstLabel(url string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(url, "https://"), "http://")
	if i := strings.Index(s, "."); i > 0 {
		return s[:i]
	}
	return s
}

func parseListing(body []byte) ([]string, int) {
	var out struct {
		KeyCount int `xml:"KeyCount"`
		Contents []struct {
			Key string `xml:"Key"`
		} `xml:"Contents"`
	}
	_ = xml.Unmarshal(body, &out)
	var keys []string
	for _, c := range out.Contents {
		keys = append(keys, c.Key)
	}
	count := out.KeyCount
	if count == 0 {
		count = len(keys)
	}
	return keys, count
}

// ScanPublicBuckets checks many buckets concurrently.
func ScanPublicBuckets(ctx context.Context, client *http.Client, names []string, workers int) []BucketAccess {
	if workers <= 0 {
		workers = 20
	}
	out := make([]BucketAccess, len(names))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i, n := range names {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, n string) {
			defer wg.Done()
			defer func() { <-sem }()
			out[i] = CheckBucket(ctx, client, n, 20)
		}(i, n)
	}
	wg.Wait()
	return out
}

// PublicBucketsForCredentials lists the account buckets and checks each.
func PublicBucketsForCredentials(ctx context.Context, client *http.Client, c Credentials, workers int) ([]BucketAccess, error) {
	buckets, err := ListBuckets(ctx, client, c)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(buckets))
	for _, b := range buckets {
		names = append(names, b.Name)
	}
	return ScanPublicBuckets(ctx, client, names, workers), nil
}
