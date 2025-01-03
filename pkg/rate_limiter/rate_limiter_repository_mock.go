package rate_limiter

import (
	"github.com/stretchr/testify/mock"
	"time"
)

type RateLimiterRepositoryMock struct {
	mock.Mock
	countTries  int
	currentTime time.Time
}

func NewRateLimiterRepositoryMock(currentTime time.Time) *RateLimiterRepositoryMock {
	return &RateLimiterRepositoryMock{
		countTries:  0,
		currentTime: currentTime,
	}
}

func (r *RateLimiterRepositoryMock) SaveTry(ip string, token string) error {
	args := r.Called(ip, token)
	if r.countTries == 0 {
		r.countTries = args.Int(0)
	}

	r.countTries++

	return args.Error(1)
}

func (r *RateLimiterRepositoryMock) TokenExists(token string) (bool, error) {
	args := r.Called(token)

	return args.Bool(0), args.Error(1)
}

func (r *RateLimiterRepositoryMock) FindTokenBlockDuration(token string) (int, error) {
	args := r.Called(token)

	return args.Int(0), args.Error(1)
}

func (r *RateLimiterRepositoryMock) IsBlockedByToken(token string, blockTimeWindow time.Time) (bool, error) {
	args := r.Called(token, r.currentTime)

	return args.Bool(0), args.Error(1)
}

func (r *RateLimiterRepositoryMock) IsBlockedByIp(ip string, blockTimeWindow time.Time) (bool, error) {
	args := r.Called(ip, r.currentTime)

	return args.Bool(0), args.Error(1)
}

func (r *RateLimiterRepositoryMock) FindLimitByToken(token string) (int, error) {
	args := r.Called(token)

	return args.Int(0), args.Error(1)
}

func (r *RateLimiterRepositoryMock) FindTriesByTokenInLastSecond(token string) (int, error) {
	args := r.Called(token)

	if r.countTries > 1 {
		return r.countTries - 1, nil
	}

	return args.Int(0), args.Error(1)
}

func (r *RateLimiterRepositoryMock) BlockToken(token string) error {
	args := r.Called(token)

	return args.Error(0)
}

func (r *RateLimiterRepositoryMock) FindTriesByIpInLastSecond(token string) (int, error) {
	args := r.Called(token)

	if r.countTries > 1 {
		return r.countTries - 1, nil
	}

	return args.Int(0), args.Error(1)
}

func (r *RateLimiterRepositoryMock) BlockIp(token string) error {
	args := r.Called(token)

	return args.Error(0)
}
