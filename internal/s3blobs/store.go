// Package s3blobs keeps blob bytes in an S3 bucket (core.BlobStore, §7.8):
// the store for several instances sharing a database, on any backend
// (SQLite, Postgres, DynamoDB), without a shared volume.
//
//	s3://<bucket>/<prefix>?region=…&endpoint=…&path-style=…
//
// Each name the engine stores is an object under the prefix. Objects are
// written once and never rewritten, so S3's read-after-write consistency
// is all the engine needs: a committed row names a complete object (Put
// returns once it is stored), and a listing finds every object stored
// before it began (the orphan sweep). Reads open the whole object and
// stream it; a seek elsewhere (an HTTP range) re-reads from there with a
// ranged GET.
//
// The package depends on the AWS SDK only, not on the engine: it
// satisfies core.BlobStore through standard library types.
package s3blobs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// IsURL reports whether a blob store URL names an S3 bucket.
func IsURL(s string) bool { return strings.HasPrefix(s, "s3://") }

// Store is a bucket, or a prefix of one.
type Store struct {
	Client *s3.Client
	Bucket string
	Prefix string // "" or ending in "/"
	region string
}

// Open connects to the bucket an s3:// URL names:
//
//	s3://patchlog-blobs/prod?region=eu-west-1
//	s3://blobs?region=us-east-1&endpoint=http://localhost:8333   (SeaweedFS)
//
// Credentials come from the default AWS chain (environment, shared config,
// instance profile). endpoint is an S3-compatible service's URL; with one,
// requests address the bucket in the path (path-style=false turns that
// off) and checksums are sent and checked only where S3 requires them,
// which every such service supports.
func Open(ctx context.Context, rawurl string) (*Store, error) {
	u, err := url.Parse(rawurl)
	if err != nil || u.Scheme != "s3" || u.Host == "" {
		return nil, fmt.Errorf("s3blobs: an S3 URL is s3://<bucket>/<prefix>?region=…&endpoint=…, got %q", rawurl)
	}
	q := u.Query()
	for k := range q {
		switch k {
		case "region", "endpoint", "path-style":
		default:
			return nil, fmt.Errorf("s3blobs: %q: unknown parameter %q", rawurl, k)
		}
	}
	endpoint := q.Get("endpoint")
	pathStyle := endpoint != ""
	if v := q.Get("path-style"); v != "" {
		if pathStyle, err = strconv.ParseBool(v); err != nil {
			return nil, fmt.Errorf("s3blobs: %q: path-style: %v", rawurl, err)
		}
	}
	var opts []func(*config.LoadOptions) error
	if r := q.Get("region"); r != "" {
		opts = append(opts, config.WithRegion(r))
	}
	if endpoint != "" {
		opts = append(opts,
			config.WithRequestChecksumCalculation(aws.RequestChecksumCalculationWhenRequired),
			config.WithResponseChecksumValidation(aws.ResponseChecksumValidationWhenRequired))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, err
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if endpoint != "" {
			o.BaseEndpoint = aws.String(endpoint)
		}
		o.UsePathStyle = pathStyle
	})
	prefix := strings.Trim(u.Path, "/")
	if prefix != "" {
		prefix += "/"
	}
	return &Store{Client: client, Bucket: u.Host, Prefix: prefix, region: cfg.Region}, nil
}

// String is the store's URL, without its parameters.
func (s *Store) String() string { return "s3://" + s.Bucket + "/" + s.Prefix }

// Sub is the store of a prefix under s's (tests give each its own).
func (s *Store) Sub(prefix string) *Store {
	c := *s
	c.Prefix += strings.Trim(prefix, "/") + "/"
	return &c
}

func (s *Store) key(name string) *string { return aws.String(s.Prefix + name) }

// Put stores data under name.
func (s *Store) Put(ctx context.Context, name string, data []byte) error {
	_, err := s.Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        &s.Bucket,
		Key:           s.key(name),
		Body:          bytes.NewReader(data),
		ContentLength: aws.Int64(int64(len(data))),
	})
	if err != nil {
		return fmt.Errorf("s3blobs: put %s: %w", name, err)
	}
	return nil
}

// Open opens name, reading from its start; a missing name is
// fs.ErrNotExist.
func (s *Store) Open(ctx context.Context, name string) (io.ReadSeekCloser, error) {
	out, err := s.Client.GetObject(ctx, &s3.GetObjectInput{Bucket: &s.Bucket, Key: s.key(name)})
	if err != nil {
		if notFound(err) {
			return nil, fmt.Errorf("s3blobs: %s: %w", name, fs.ErrNotExist)
		}
		return nil, fmt.Errorf("s3blobs: get %s: %w", name, err)
	}
	return &object{ctx: ctx, s: s, name: name, size: aws.ToInt64(out.ContentLength), etag: out.ETag, body: out.Body}, nil
}

// Remove deletes name; S3 answers a missing one as deleted.
func (s *Store) Remove(ctx context.Context, name string) error {
	_, err := s.Client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &s.Bucket, Key: s.key(name)})
	if err != nil && !notFound(err) {
		return fmt.Errorf("s3blobs: delete %s: %w", name, err)
	}
	return nil
}

// List lists the objects under the prefix.
func (s *Store) List(ctx context.Context, fn func(name string, size int64, modified time.Time) error) error {
	p := s3.NewListObjectsV2Paginator(s.Client, &s3.ListObjectsV2Input{Bucket: &s.Bucket, Prefix: aws.String(s.Prefix)})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("s3blobs: list %s: %w", s, err)
		}
		for _, o := range page.Contents {
			name := strings.TrimPrefix(aws.ToString(o.Key), s.Prefix)
			if name == "" {
				continue
			}
			if err := fn(name, aws.ToInt64(o.Size), aws.ToTime(o.LastModified)); err != nil {
				return err
			}
		}
	}
	return nil
}

// CreateBucket creates the bucket unless it exists: for development and
// tests (deployments create theirs with its policies).
func (s *Store) CreateBucket(ctx context.Context) error {
	if _, err := s.Client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &s.Bucket}); err == nil {
		return nil
	}
	in := &s3.CreateBucketInput{Bucket: &s.Bucket}
	if s.region != "" && s.region != "us-east-1" {
		in.CreateBucketConfiguration = &types.CreateBucketConfiguration{LocationConstraint: types.BucketLocationConstraint(s.region)}
	}
	_, err := s.Client.CreateBucket(ctx, in)
	var owned *types.BucketAlreadyOwnedByYou
	if err != nil && !errors.As(err, &owned) {
		return fmt.Errorf("s3blobs: create bucket %s: %w", s.Bucket, err)
	}
	return nil
}

func notFound(err error) bool {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		switch ae.ErrorCode() {
		case "NoSuchKey", "NotFound":
			return true
		}
	}
	return false
}

// object reads a stored object: the body of the GET that opened it while
// reads follow on, else a ranged GET from where a seek moved to.
type object struct {
	ctx     context.Context
	s       *Store
	name    string
	size    int64
	etag    *string
	off     int64         // where the next Read reads
	body    io.ReadCloser // nil: none open
	bodyOff int64         // where body reads
}

func (o *object) Read(p []byte) (int, error) {
	if o.off >= o.size {
		return 0, io.EOF
	}
	if o.body != nil && o.bodyOff != o.off {
		o.body.Close()
		o.body = nil
	}
	if o.body == nil {
		out, err := o.s.Client.GetObject(o.ctx, &s3.GetObjectInput{
			Bucket:  &o.s.Bucket,
			Key:     o.s.key(o.name),
			Range:   aws.String("bytes=" + strconv.FormatInt(o.off, 10) + "-"),
			IfMatch: o.etag,
		})
		if err != nil {
			if notFound(err) {
				return 0, fmt.Errorf("s3blobs: %s: %w", o.name, fs.ErrNotExist)
			}
			return 0, fmt.Errorf("s3blobs: get %s: %w", o.name, err)
		}
		o.body, o.bodyOff = out.Body, o.off
	}
	n, err := o.body.Read(p)
	o.off += int64(n)
	o.bodyOff += int64(n)
	if err == io.EOF && o.off < o.size {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

func (o *object) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		offset += o.off
	case io.SeekEnd:
		offset += o.size
	default:
		return 0, errors.New("s3blobs: seek: invalid whence")
	}
	if offset < 0 {
		return 0, errors.New("s3blobs: seek: negative position")
	}
	o.off = offset
	return offset, nil
}

func (o *object) Close() error {
	if o.body == nil {
		return nil
	}
	err := o.body.Close()
	o.body = nil
	return err
}
