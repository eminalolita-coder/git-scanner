package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/eminalolita-coder/git-scanner/internal/aws"
	"github.com/eminalolita-coder/git-scanner/internal/model"
	"github.com/eminalolita-coder/git-scanner/internal/output"
	"github.com/eminalolita-coder/git-scanner/internal/scanner"
	"github.com/eminalolita-coder/git-scanner/internal/source"
)

func newS3Cmd(opts *Options) *cobra.Command {
	var (
		accessKey    string
		secretKey    string
		sessionToken string
		region       string
		account      bool
		doScan       bool
		maxKeys      int
		concurrency  int
		maxSizeKB    int
	)

	cmd := &cobra.Command{
		Use:   "s3 [bucket...]",
		Short: "Probe S3 buckets for public access and scan their objects",
		Long: `s3 checks whether buckets allow anonymous listing, and can download and
scan their objects for secrets.

Give bucket names directly, or use --account (with credentials) to enumerate
every bucket in an AWS account and triage them.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var creds *aws.Credentials
			if accessKey != "" {
				creds = &aws.Credentials{AccessKey: accessKey, SecretKey: secretKey, SessionToken: sessionToken, Region: region}
			}
			if account && creds == nil {
				return fmt.Errorf("--account requires --access-key and --secret-key")
			}

			client := &http.Client{Timeout: 20 * time.Second}
			ctx := cmd.Context()
			out := cmd.OutOrStdout()

			var buckets []string
			for _, a := range args {
				if fi, err := os.Stat(a); err == nil && !fi.IsDir() {
					ts, err := source.FromListFile(a)
					if err == nil {
						for _, t := range ts {
							buckets = append(buckets, normalizeBucket(t.Value))
						}
						continue
					}
				}
				buckets = append(buckets, normalizeBucket(a))
			}
			if account {
				all, err := aws.ListBuckets(ctx, client, *creds)
				if err != nil {
					return err
				}
				for _, b := range all {
					buckets = append(buckets, b.Name)
				}
			}
			if len(buckets) == 0 {
				return fmt.Errorf("no buckets")
			}
			if concurrency <= 0 {
				concurrency = 20
			}

			var sc *scanner.Scanner
			if doScan {
				cfg, err := loadConfig(opts)
				if err != nil {
					return err
				}
				engine, err := buildEngine(cfg, "")
				if err != nil {
					return err
				}
				sc = scanner.New(scanner.Options{Config: cfg, Engine: engine, Writer: output.NewStream(out)})
			}

			results := aws.ScanPublicBuckets(ctx, client, buckets, concurrency)
			public := 0
			for _, r := range results {
				switch {
				case r.Public:
					public++
					fmt.Fprintf(out, "[PUBLIC] %s  region=%s  objects=%d+  sample=%v\n", r.Name, r.Region, r.ObjectCount, firstN(r.Sample, 3))
				case r.Exists:
					fmt.Fprintf(out, "[private] %s  region=%s  (%s)\n", r.Name, r.Region, r.Err)
				default:
					fmt.Fprintf(out, "[none] %s  (%s)\n", r.Name, r.Err)
				}
			}
			fmt.Fprintf(out, "\n%d public / %d checked\n", public, len(results))

			if doScan {
				scanPublicObjects(ctx, out, client, results, sc, maxKeys, maxSizeKB, concurrency)
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&accessKey, "access-key", "", "AWS access key (for --account)")
	f.StringVar(&secretKey, "secret-key", "", "AWS secret key")
	f.StringVar(&sessionToken, "session-token", "", "AWS session token")
	f.StringVar(&region, "region", "us-east-1", "region")
	f.BoolVar(&account, "account", false, "enumerate all buckets in the account")
	f.BoolVar(&doScan, "scan", false, "download and scan objects of public buckets")
	f.IntVar(&maxKeys, "max-keys", 50, "objects to fetch per bucket when scanning")
	f.IntVar(&maxSizeKB, "max-size", 512, "max object size in KB to download")
	f.IntVarP(&concurrency, "concurrency", "C", 20, "concurrency")
	return cmd
}

func mustExpand(args []string) []model.Target {
	ts, err := source.Expand(args)
	if err != nil {
		return nil
	}
	return ts
}

func normalizeBucket(s string) string {
	s = strings.TrimSpace(s)
	host := s
	if i := strings.Index(s, "://"); i >= 0 {
		host = s[i+3:]
	}
	host = strings.TrimSuffix(host, "/")
	if i := strings.IndexByte(host, '/'); i > 0 {
		host = host[:i]
	}
	// only strip the leading label when the input is an S3 endpoint
	if strings.Contains(host, "amazonaws.com") || strings.Contains(host, ".s3.") || strings.HasSuffix(host, ".s3") {
		if i := strings.IndexByte(host, '.'); i > 0 {
			return host[:i]
		}
	}
	return host
}

func firstN(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func scanPublicObjects(ctx context.Context, out io.Writer, client *http.Client, results []aws.BucketAccess, sc *scanner.Scanner, maxKeys, maxSizeKB, concurrency int) {
	if maxSizeKB <= 0 {
		maxSizeKB = 512
	}
	limit := int64(maxSizeKB) << 10
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	for _, b := range results {
		if !b.Public {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(b aws.BucketAccess) {
			defer wg.Done()
			defer func() { <-sem }()
			keys := b.Sample
			if len(keys) == 0 {
				return
			}
			if len(keys) > maxKeys {
				keys = keys[:maxKeys]
			}
			for _, key := range keys {
				u := aws.PublicObjectURL(b.Name, b.Region, key)
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
				if err != nil {
					continue
				}
				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				body, _ := io.ReadAll(io.LimitReader(resp.Body, limit))
				resp.Body.Close()
				if len(body) == 0 {
					continue
				}
				sc.ScanBytes(model.Target{Kind: model.KindURL, Value: "s3://" + b.Name}, key, body)
			}
			fmt.Fprintf(out, "[scanned] s3://%s (%d objects)\n", b.Name, len(keys))
		}(b)
	}
	wg.Wait()
}
