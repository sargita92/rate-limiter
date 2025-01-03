package rate_limiter

import "time"

type RateLimiterRepositoryInterface interface {
	SaveTry(ip string, token string) error
	TokenExists(token string) (bool, error)
	FindTokenBlockDuration(token string) (int, error)
	IsBlockedByToken(token string, blockTimeWindow time.Time) (bool, error)
	IsBlockedByIp(ip string, blockTimeWindow time.Time) (bool, error)
	FindLimitByToken(token string) (int, error)
	FindTriesByTokenInLastSecond(token string) (int, error)
	BlockToken(token string) error
	FindTriesByIpInLastSecond(token string) (int, error)
	BlockIp(token string) error
}
