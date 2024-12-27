package rate_limiter

type RateLimiterRepositoryInterface interface {
	CountByIpInLastSecond(ip string) (int, error)
	FindLimitByToken(token string) (int, error)
}
