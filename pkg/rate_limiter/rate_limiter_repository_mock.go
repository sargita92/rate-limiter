package rate_limiter

import (
	"github.com/stretchr/testify/mock"
	"strconv"
)

type RateLimiterRepositoryMock struct {
	mock.Mock
	countTries int
	IsBlocked  string
}

func NewRateLimiterRepositoryMock() *RateLimiterRepositoryMock {
	return &RateLimiterRepositoryMock{
		countTries: 0,
	}
}

func (m *RateLimiterRepositoryMock) CountByIpInLastSecond(ip string) (int, error) {
	args := m.Called(ip)
	if m.countTries == 0 {
		m.countTries = args.Int(0)
	}

	m.countTries++

	return m.countTries, args.Error(1)
}

func (m *RateLimiterRepositoryMock) FindLimitByToken(token string) (int, error) {
	args := m.Called(token)

	return args.Int(0), args.Error(1)
}

func (m *RateLimiterRepositoryMock) FindIsBlocked(ip string) (bool, error) {
	args := m.Called(ip)

	if m.IsBlocked == "" {
		m.IsBlocked = strconv.FormatBool(args.Bool(0))
	}

	IsBlocked, _ := strconv.ParseBool(m.IsBlocked)

	return IsBlocked, args.Error(1)
}

func (m *RateLimiterRepositoryMock) UpdateIsBlocked(ip string, IsBlocked bool) error {
	args := m.Called(ip, IsBlocked)

	m.IsBlocked = strconv.FormatBool(args.Bool(0))

	return args.Error(1)
}
