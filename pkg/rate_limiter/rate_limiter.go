package rate_limiter

import (
	"errors"
	"net/http"
)

const (
	apiKeyHeader = "API_KEY"
	xRealIp      = "X-Real-Ip"
	xForwarded   = "X-Forwarded-For"

	ipNotFound        = "ip not found"
	rateLimitExceeded = "rate limit exceeded"
)

type RateLimiter struct {
	rateLimiterRepository RateLimiterRepositoryInterface
	DefaultLimit          int
}

func NewRateLimiter(
	rateLimiterRepository RateLimiterRepositoryInterface,
	DefaultLimit int,

) *RateLimiter {
	return &RateLimiter{
		rateLimiterRepository: rateLimiterRepository,
		DefaultLimit:          DefaultLimit,
	}
}

func (r *RateLimiter) Do(req *http.Request) error {
	ip := r.defineIp(req)
	if ip == "" {
		return errors.New(ipNotFound)
	}

	limit := r.defineToken(req)

	err := r.checkRateLimit(ip, limit)
	if err != nil {
		return err
	}

	return nil
}

func (r *RateLimiter) defineIp(req *http.Request) string {
	IPAddress := req.Header.Get(xRealIp)

	if IPAddress == "" {
		IPAddress = req.Header.Get(xForwarded)
	}

	if IPAddress == "" {
		IPAddress = req.RemoteAddr
	}

	return IPAddress
}

func (r *RateLimiter) defineToken(req *http.Request) int {
	token := req.Header.Get(apiKeyHeader)
	if token == "" {
		return r.defineDefaultLimit()
	}

	limit, err := r.rateLimiterRepository.FindLimitByToken(token)
	if err != nil {
		return r.defineDefaultLimit()
	}

	if limit == 0 {
		return r.defineDefaultLimit()
	}

	return limit
}

func (r *RateLimiter) defineDefaultLimit() int {
	return r.DefaultLimit
}

func (r *RateLimiter) checkRateLimit(ip string, limit int) error {
	amount, err := r.rateLimiterRepository.CountByIpInLastSecond(ip)
	if err != nil {
		return err
	}

	if amount >= limit {
		return errors.New(rateLimitExceeded)
	}

	return nil
}
