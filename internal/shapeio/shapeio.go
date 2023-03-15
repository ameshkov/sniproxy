// Package shapeio provides connections throttling functionality.  It is based
// on https://github.com/fujiwara/shapeio.
package shapeio

import (
	"context"
	"io"
	"time"

	"golang.org/x/time/rate"
)

const burstLimit = 1000 * 1000 * 1000

// Reader implements the io.Reader interface and allows limiting reading speed.
type Reader struct {
	r       io.Reader
	limiter *rate.Limiter
}

// Writer implements the io.Reader interface and allows limiting writing speed.
type Writer struct {
	w       io.Writer
	limiter *rate.Limiter
}

// NewReader returns a reader that implements io.Reader with rate limiting.
func NewReader(r io.Reader, limiter *rate.Limiter) *Reader {
	return &Reader{
		r:       r,
		limiter: limiter,
	}
}

// NewWriter returns a writer that implements io.Writer with rate limiting.
func NewWriter(w io.Writer, limiter *rate.Limiter) *Writer {
	return &Writer{
		w:       w,
		limiter: limiter,
	}
}

// SetRateLimit sets rate limit (bytes/sec) to the reader.  It overrides the
// original limiter that was passed in NewReader.
func (s *Reader) SetRateLimit(bytesPerSec float64) {
	s.limiter = rate.NewLimiter(rate.Limit(bytesPerSec), burstLimit)
	// Spend initial burst.
	s.limiter.AllowN(time.Now(), burstLimit)
}

// SetRateLimit sets rate limit (bytes/sec) to the writer.  It overrides the
// original limiter that was passed in NewWriter.
func (s *Writer) SetRateLimit(bytesPerSec float64) {
	s.limiter = rate.NewLimiter(rate.Limit(bytesPerSec), burstLimit)
	// Spend initial burst.
	s.limiter.AllowN(time.Now(), burstLimit)
}

// Read implements the io.Reader interface for *Reader.
func (s *Reader) Read(p []byte) (n int, err error) {
	if s.limiter == nil {
		return s.r.Read(p)
	}
	n, err = s.r.Read(p)
	if err != nil {
		return n, err
	}

	ctx := context.Background()
	if err = s.limiter.WaitN(ctx, n); err != nil {
		return n, err
	}

	return n, nil
}

// Write implements the io.Writer interface for *Writer.
func (s *Writer) Write(p []byte) (n int, err error) {
	if s.limiter == nil {
		return s.w.Write(p)
	}
	n, err = s.w.Write(p)
	if err != nil {
		return n, err
	}

	ctx := context.Background()
	if err = s.limiter.WaitN(ctx, n); err != nil {
		return n, err
	}

	return n, err
}
