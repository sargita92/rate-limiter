package rate_limiter

import (
	"github.com/stretchr/testify/mock"
)

type RateLimiterRepositoryMock struct {
	mock.Mock
	countTries int
}

func NewRateLimiterRepositoryMock() *RateLimiterRepositoryMock {
	return &RateLimiterRepositoryMock{
		countTries: 0,
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

func (r *RateLimiterRepositoryMock) IsBlockedByToken(token string) (bool, error) {
	args := r.Called(token)

	return args.Bool(0), args.Error(1)
}

func (r *RateLimiterRepositoryMock) IsBlockedByIp(ip string) (bool, error) {
	args := r.Called(ip)

	return args.Bool(0), args.Error(1)
}

func (r *RateLimiterRepositoryMock) FindLimitByToken(token string) (int, error) {
	args := r.Called(token)

	return args.Int(0), args.Error(1)
}

func (r *RateLimiterRepositoryMock) FindTriesByTokenInLastSecond(token string) (int, error) {
	args := r.Called(token)

	return args.Int(0), args.Error(1)
}

func (r *RateLimiterRepositoryMock) BlockToken(token string) error {
	args := r.Called(token)

	return args.Error(0)
}

func (r *RateLimiterRepositoryMock) FindTriesByIpInLastSecond(token string) (int, error) {
	args := r.Called(token)

	return args.Int(0), args.Error(1)
}

func (r *RateLimiterRepositoryMock) BlockIp(token string) error {
	args := r.Called(token)

	return args.Error(0)
}
