package rate_limiter

type RateLimiterRepositoryInterface interface {
	SaveTry(ip string, token string) error
	TokenExists(token string) (bool, error)
	IsBlockedByToken(token string) (bool, error)
	IsBlockedByIp(ip string) (bool, error)
	FindLimitByToken(token string) (int, error)
	FindTriesByTokenInLastSecond(token string) (int, error)
	BlockToken(token string) error
	FindTriesByIpInLastSecond(token string) (int, error)
	BlockIp(token string) error
}
