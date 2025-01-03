package database

import (
	"context"
	"github.com/sargita92/rate-limiter/pkg/rate_limiter"
	"math"
	"time"

	"github.com/redis/go-redis/v9"
)

var ctx = context.Background()

type RateLimiterRepository struct {
	db         *redis.Client
	expiration int
}

func NewRateLimiterRepository(expiration int) rate_limiter.RateLimiterRepositoryInterface {
	rdb := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       0,  // use default DB
	})

	return &RateLimiterRepository{
		db:         rdb,
		expiration: expiration,
	}
}

func (r *RateLimiterRepository) getDuration() time.Duration {
	d := time.Duration(r.expiration) * time.Second
	if d < 0 || d > time.Duration(math.MaxInt64) {
		return time.Duration(60) * time.Minute
	}

	return d
}

func (r *RateLimiterRepository) SaveTry(ip string, token string) error {
	d := r.getDuration()
	if token != "" {
		return r.db.Set(ctx, token, time.Now(), d).Err()
	}

	return r.db.Set(ctx, ip, time.Now(), d).Err()
}

func (r *RateLimiterRepository) TokenExists(token string) (bool, error) {
	return true, nil
}

func (r *RateLimiterRepository) FindTokenBlockDuration(token string) (int, error) {
	return 1, nil
}

func (r *RateLimiterRepository) IsBlockedByToken(token string, blockTimeWindow time.Time) (bool, error) {
	return false, nil
}

func (r *RateLimiterRepository) IsBlockedByIp(ip string, blockTimeWindow time.Time) (bool, error) {
	return false, nil
}

func (r *RateLimiterRepository) FindLimitByToken(token string) (int, error) {
	return 0, nil
}

func (r *RateLimiterRepository) FindTriesByTokenInLastSecond(token string) (int, error) {
	return 0, nil
}

func (r *RateLimiterRepository) BlockToken(token string) error {
	return nil
}

func (r *RateLimiterRepository) FindTriesByIpInLastSecond(token string) (int, error) {
	return 0, nil
}

func (r *RateLimiterRepository) BlockIp(token string) error {
	return nil
}
