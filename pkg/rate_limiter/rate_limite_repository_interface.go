package rate_limiter

import "time"

type RateLimiterRepositoryInterface interface {
	CountByIpInLastSecond(ip string) (int, error)
	FindLimitByToken(token string) (int, error)
	FindIsTokenBlocked(token string) (bool, *time.Time, error)
	FindIsIpBlocked(ip string) (bool, *time.Time, error)
	UpdateIsBlocked(ip string, token string, isBlocked bool) error
}
