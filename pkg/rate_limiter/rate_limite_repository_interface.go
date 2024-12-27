package rate_limiter

type RateLimiterRepositoryInterface interface {
	CountByIpInLastSecond(ip string) (int, error)
	FindLimitByToken(token string) (int, error)
	FindIsBlocked(token string) (bool, error)
	UpdateIsBlocked(ip string, isBlocked bool) error
}
