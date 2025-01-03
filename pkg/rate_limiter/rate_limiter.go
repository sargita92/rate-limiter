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
	tokenNotFound     = "token not found"
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
	token := r.defineToken(req)

	if err := r.checkTokenExists(token); err != nil {
		if err := r.saveTry(ip, token); err != nil {
			return err
		}

		return err
	}

	if err := r.saveTry(ip, token); err != nil {
		return err
	}

	blockTimeWindow := r.defineBlockTimeWindow(token)

	if err := r.checkIsTokenBlocked(token, blockTimeWindow); err != nil {
		return err
	}

	if err := r.checkIsIpBlocked(ip, blockTimeWindow); err != nil {
		return err
	}

	if err := r.blockedTry(ip, token); err != nil {
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

func (r *RateLimiter) defineToken(req *http.Request) string {
	return req.Header.Get(apiKeyHeader)
}

func (r *RateLimiter) checkTokenExists(token string) error {
	if token == "" {
		return nil
	}

	exists, err := r.rateLimiterRepository.TokenExists(token)
	if err != nil {
		return err
	}

	if !exists {
		return errors.New(tokenNotFound)
	}

	return nil
}

func (r *RateLimiter) saveTry(ip string, token string) error {
	return r.rateLimiterRepository.SaveTry(ip, token)
}

func (r *RateLimiter) checkIsTokenBlocked(token string, blockTimeWindow time.Time) error {
	if token == "" {
		return nil
	}

	blocked, err := r.rateLimiterRepository.IsBlockedByToken(token, blockTimeWindow)
	if err != nil {
		return err
	}

	if blocked {
		return errors.New(rateLimitExceeded)
	}

	return nil
}

func (r *RateLimiter) defineBlockTimeWindow(token string) time.Time {
	if token == "" {
		return calculateBlockTimeWindow(r.BlockDuration)
	}

	tokenDuration, err := r.rateLimiterRepository.FindTokenBlockDuration(token)
	if err != nil {
		return calculateBlockTimeWindow(r.BlockDuration)
	}

	if tokenDuration == 0 {
		return calculateBlockTimeWindow(r.BlockDuration)
	}

	return calculateBlockTimeWindow(tokenDuration)
}

func calculateBlockTimeWindow(durationInSeconds int) time.Time {
	return time.Now().Add(-time.Duration(durationInSeconds) * time.Second)
}

func (r *RateLimiter) checkIsIpBlocked(ip string, blockTimeWindow time.Time) error {
	if ip == "" {
		return errors.New(ipNotFound)
	}

	blocked, err := r.rateLimiterRepository.IsBlockedByIp(ip, blockTimeWindow)
	if err != nil {
		return err
	}

	if blocked {
		return errors.New(rateLimitExceeded)
	}

	return nil
}

func (r *RateLimiter) blockedTry(ip string, token string) error {
	tryLimit := r.defineTryLimit(token)

	if err := r.blockedToken(token, tryLimit); err != nil {
		return err
	}

	if err := r.blockedIp(ip, tryLimit); err != nil {
		return err
	}

	return nil
}

func (r *RateLimiter) defineTryLimit(token string) int {
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

func (r *RateLimiter) blockedToken(token string, tryLimit int) error {
	if token == "" {
		return nil
	}

	tries, err := r.rateLimiterRepository.FindTriesByTokenInLastSecond(token)
	if err != nil {
		return err
	}

	if tries >= tryLimit {
		if err := r.rateLimiterRepository.BlockToken(token); err != nil {
			return err
		}

		return errors.New(rateLimitExceeded)
	}

	return nil
}

func (r *RateLimiter) blockedIp(ip string, tryLimit int) error {
	if ip == "" {
		return errors.New(ipNotFound)
	}

	tries, err := r.rateLimiterRepository.FindTriesByIpInLastSecond(ip)
	if err != nil {
		return err
	}

	if tries >= tryLimit {
		if err := r.rateLimiterRepository.BlockIp(ip); err != nil {
			return err
		}

		return errors.New(rateLimitExceeded)
	}

	return nil
}
