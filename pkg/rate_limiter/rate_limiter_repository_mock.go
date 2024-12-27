package rate_limiter

import (
	"github.com/stretchr/testify/mock"
	_ "github.com/stretchr/testify/mock"
)

type RateLimiterRepositoryMock struct {
	mock.Mock
}

func NewRateLimiterRepositoryMock() *RateLimiterRepositoryMock {
	return &RateLimiterRepositoryMock{}
}

func (m *RateLimiterRepositoryMock) CountByIpInLastSecond(ip string) (int, error) {
	args := m.Called(ip)
	return args.Int(0), args.Error(1)
}

func (m *RateLimiterRepositoryMock) FindLimitByToken(token string) (int, error) {
	args := m.Called(token)
	return args.Int(0), args.Error(1)
}
