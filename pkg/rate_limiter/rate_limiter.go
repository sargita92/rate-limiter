package rate_limiter

import (
	"errors"
	"net/http"
	"time"
)

const (
	apiKeyHeader = "API_KEY"
	xRealIp      = "X-Real-Ip"
	xForwarded   = "X-Forwarded-For"

	ipNotFound        = "ip not found"
	rateLimitExceeded = "you have reached the maximum number of requests or actions allowed within a certain time frame"
)

type RateLimiter struct {
	rateLimiterRepository RateLimiterRepositoryInterface
	DefaultLimit          int
	BlockDuration         int
}

func NewRateLimiter(
	rateLimiterRepository RateLimiterRepositoryInterface,
	DefaultLimit int,
	blockDuration int,

) *RateLimiter {
	return &RateLimiter{
		rateLimiterRepository: rateLimiterRepository,
		DefaultLimit:          DefaultLimit,
		BlockDuration:         blockDuration,
	}
}

func (r *RateLimiter) Do(req *http.Request) error {
	ip := r.defineIp(req)
	if ip == "" {
		return errors.New(ipNotFound)
	}

	token := req.Header.Get(apiKeyHeader)
	if err := r.checkIsTokenBlocked(token); err != nil {
		return err
	}

	if err := r.checkIsIpBlocked(ip); err != nil {
		return err
	}

	limit := r.defineTokenLimit(req)
	if err := r.checkRateLimit(ip, token, limit); err != nil {
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

func (r *RateLimiter) checkIsTokenBlocked(token string) error {
	if token == "" {
		return nil
	}

	isBlocked, blockedUntil, err := r.rateLimiterRepository.FindIsTokenBlocked(token)
	if err != nil {
		return err
	}

	if isBlocked {
		return r.shouldUnblock("", token, blockedUntil)
	}

	return nil
}

func (r *RateLimiter) shouldUnblock(ip string, token string, unblockTime *time.Time) error {
	if token != "" {
		ip = ""
	}

	if time.Now().After(*unblockTime) {
		if err := r.rateLimiterRepository.UpdateIsBlocked(ip, token, false); err != nil {
			return err
		}

		return nil
	}

	return errors.New(rateLimitExceeded)
}

func (r *RateLimiter) checkIsIpBlocked(ip string) error {
	isBlocked, _, err := r.rateLimiterRepository.FindIsIpBlocked(ip)
	if err != nil {
		return err
	}

	if isBlocked {
		return errors.New(rateLimitExceeded)
	}

	return nil
}

func (r *RateLimiter) defineTokenLimit(req *http.Request) int {
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

func (r *RateLimiter)

func (r *RateLimiter) checkRateLimit(ip string, token string, limit int) error {
	amount, err := r.defineAmountInLastSecond(ip, token)
	if err != nil {
		return err
	}

	if amount > limit {
		if err := r.rateLimiterRepository.UpdateIsBlocked(ip, token, true); err != nil {
			return err
		}

		return errors.New(rateLimitExceeded)
	}

	return nil
}

func (r *RateLimiter) defineAmountInLastSecond(ip string, token string) (int, error) {
	if token != "" {
		return r.rateLimiterRepository.CountByIpInLastSecond(ip)
	}

	return r.rateLimiterRepository.CountByIpInLastSecond(ip)
}

func calculateBlockTimeDuration(durationInSeconds int) time.Time {
	return time.Now().Add(time.Duration(durationInSeconds) * time.Second)
}
