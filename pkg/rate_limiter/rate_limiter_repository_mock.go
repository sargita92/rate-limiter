package rate_limiter

import (
	"github.com/stretchr/testify/mock"
	"strconv"
	"time"
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

	return m.countTries, args.Error(1)
}

func (m *RateLimiterRepositoryMock) FindLimitByToken(token string) (int, error) {
	args := m.Called(token)

	return args.Int(0), args.Error(1)
}

func (m *RateLimiterRepositoryMock) FindIsTokenBlocked(token string) (bool, *time.Time, error) {
	args := m.Called(token)

	if m.IsBlocked == "" {
		m.IsBlocked = strconv.FormatBool(args.Bool(0))
	}

	IsBlocked, _ := strconv.ParseBool(m.IsBlocked)

	blockedTime, ok := args.Get(1).(time.Time)
	if !ok {
		return false, nil, args.Error(2)
	}

	return IsBlocked, &blockedTime, args.Error(2)
}

func (m *RateLimiterRepositoryMock) FindIsIpBlocked(ip string) (bool, *time.Time, error) {
	args := m.Called(ip)

	if m.IsBlocked == "" {
		m.IsBlocked = strconv.FormatBool(args.Bool(0))
	}

	IsBlocked, _ := strconv.ParseBool(m.IsBlocked)

	blockedTime, ok := args.Get(1).(time.Time)
	if !ok {
		return false, nil, args.Error(2)
	}

	return IsBlocked, &blockedTime, args.Error(2)
}

func (m *RateLimiterRepositoryMock) UpdateIsBlocked(ip string, token string, isBlocked bool) error {
	args := m.Called(ip, token, isBlocked)

	m.IsBlocked = strconv.FormatBool(isBlocked)

	return args.Error(0)
}
