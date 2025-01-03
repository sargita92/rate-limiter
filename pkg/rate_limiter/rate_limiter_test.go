package rate_limiter

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

const (
	defaultIp = "1.1.1.1"
	secondIp  = "2.2.2.2"

	initialIpQuantity     = 0
	initialTokenLimit     = 1
	defaultLimit          = 3
	defaultTokenLimit     = 5
	defaultTimeDuration   = 1
	defaultToken          = "test"
	defaultRequestMethod  = "GET"
	defaultUrl            = "/"
	FindLimitByToken      = "FindLimitByToken"
	CountByIpInLastSecond = "CountByIpInLastSecond"
	FindIsTokenBlocked    = "FindIsTokenBlocked"
	FindIsIpBlocked       = "FindIsIpBlocked"
	UpdateIsBlocked       = "UpdateIsBlocked"
	DefaultErrorMessage   = "error"
	ExpectedErrorMessage  = "Expected error, got nil"
	ExpectedNillMessage   = "Expected nil, got %v"
)

func TestDefineIp(t *testing.T) {
	req, err := http.NewRequest(defaultRequestMethod, defaultUrl, nil)
	assert.Nil(t, err)

	req.Header.Set(xRealIp, defaultIp)
	assert.Equal(t, defaultIp, (&RateLimiter{}).defineIp(req))

	req.Header.Del(xRealIp)
	req.Header.Set(xForwarded, secondIp)
	assert.Equal(t, secondIp, (&RateLimiter{}).defineIp(req))

	req.Header.Del(xForwarded)
	assert.Equal(t, req.RemoteAddr, (&RateLimiter{}).defineIp(req))
}

func TestEmptyDefineIp(t *testing.T) {
	req, err := http.NewRequest(defaultRequestMethod, defaultUrl, nil)
	assert.Nil(t, err)

	assert.Equal(t, "", (&RateLimiter{}).defineIp(req))
}

func TestCheckTokenNotBlocked(t *testing.T) {
	rateLimiterRepository := NewRateLimiterRepositoryMock()
	rateLimiterRepository.On(FindIsTokenBlocked, defaultToken).Return(false, nil, nil)

	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit, defaultTimeDuration)
	err := rateLimiter.checkIsTokenBlocked(defaultToken)
	assert.Nil(t, err, ExpectedNillMessage, err)
}

func TestCheckIsTokenBlockedError(t *testing.T) {
	rateLimiterRepository := NewRateLimiterRepositoryMock()
	rateLimiterRepository.On(FindIsTokenBlocked, defaultToken).Return(false, nil, errors.New(DefaultErrorMessage))

	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit, defaultTimeDuration)
	err := rateLimiter.checkIsTokenBlocked(defaultToken)
	assert.Error(t, err, ExpectedErrorMessage, err)
}

func TestCheckIsTokenBlocked(t *testing.T) {
	timeDuration := calculateBlockTimeDuration(defaultTimeDuration)
	rateLimiterRepository := NewRateLimiterRepositoryMock()
	rateLimiterRepository.On(FindIsTokenBlocked, defaultToken).Return(true, timeDuration, nil)

	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit, defaultTimeDuration)
	err := rateLimiter.checkIsTokenBlocked(defaultToken)
	assert.Error(t, err, ExpectedErrorMessage, err)
}

func TestCheckIpNotBlocked(t *testing.T) {
	rateLimiterRepository := NewRateLimiterRepositoryMock()
	rateLimiterRepository.On(FindIsIpBlocked, defaultIp).Return(false, nil, nil)

	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit, defaultTimeDuration)
	err := rateLimiter.checkIsIpBlocked(defaultIp)
	assert.Nil(t, rateLimiter.checkIsIpBlocked(defaultIp), ExpectedNillMessage, err)
}

func TestCheckIsIpBlockedError(t *testing.T) {
	rateLimiterRepository := NewRateLimiterRepositoryMock()
	rateLimiterRepository.On(FindIsIpBlocked, defaultIp).Return(false, nil, errors.New(DefaultErrorMessage))

	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit, defaultTimeDuration)
	err := rateLimiter.checkIsIpBlocked(defaultIp)
	assert.Error(t, err, ExpectedErrorMessage, err)
}

func TestCheckIsIpBlocked(t *testing.T) {
	timeDuration := calculateBlockTimeDuration(defaultTimeDuration)
	rateLimiterRepository := NewRateLimiterRepositoryMock()
	rateLimiterRepository.On(FindIsIpBlocked, defaultIp).Return(true, timeDuration, nil)

	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit, defaultTimeDuration)
	err := rateLimiter.checkIsIpBlocked(defaultIp)
	assert.Error(t, err, ExpectedErrorMessage, err)
}

func TestDefineToken(t *testing.T) {
	req, err := http.NewRequest(defaultRequestMethod, defaultUrl, nil)
	assert.Nil(t, err)

	rateLimiterRepository := NewRateLimiterRepositoryMock()
	rateLimiterRepository.On(FindLimitByToken, defaultToken).Return(defaultTokenLimit, nil)
	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit, defaultTimeDuration)

	req.Header.Set(apiKeyHeader, defaultToken)
	assert.Equal(t, defaultTokenLimit, rateLimiter.defineTokenLimit(req))

	req.Header.Del(apiKeyHeader)
	assert.Equal(t, defaultLimit, rateLimiter.defineTokenLimit(req))
}

func TestTokenNotFound(t *testing.T) {
	req, err := http.NewRequest(defaultRequestMethod, defaultUrl, nil)
	assert.Nil(t, err)

	rateLimiterRepository := NewRateLimiterRepositoryMock()
	rateLimiterRepository.On(FindLimitByToken, defaultToken).Return(initialIpQuantity, nil)
	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit, defaultTimeDuration)

	req.Header.Set(apiKeyHeader, defaultToken)
	assert.Equal(t, defaultLimit, rateLimiter.defineTokenLimit(req))
}

func TestDefineTokenError(t *testing.T) {
	req, err := http.NewRequest(defaultRequestMethod, defaultUrl, nil)
	assert.Nil(t, err)

	rateLimiterRepository := NewRateLimiterRepositoryMock()
	err = errors.New(DefaultErrorMessage)
	rateLimiterRepository.On(FindLimitByToken, defaultToken).Return(initialTokenLimit, err)
	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit, defaultTimeDuration)

	req.Header.Set(apiKeyHeader, defaultToken)
	assert.Equal(t, defaultLimit, rateLimiter.defineTokenLimit(req))
}

func TestCheckRateLimiter(t *testing.T) {
	rateLimiterRepository := NewRateLimiterRepositoryMock()
	rateLimiterRepository.On(CountByIpInLastSecond, defaultIp).Return(initialIpQuantity, nil)

	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit, defaultTimeDuration)

	err := rateLimiter.checkRateLimit(defaultIp, defaultToken, 1)
	assert.Nil(t, err, ExpectedNillMessage, err)
}

func TestCheckRateLimiterShouldExceedLimit(t *testing.T) {
	rateLimiterRepository := NewRateLimiterRepositoryMock()
	rateLimiterRepository.On(CountByIpInLastSecond, defaultIp).Return(defaultLimit, nil)
	rateLimiterRepository.On(UpdateIsBlocked, defaultIp, defaultToken, true).Return(nil)

	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit, defaultTimeDuration)

	err := rateLimiter.checkRateLimit(defaultIp, defaultToken, defaultLimit)
	assert.Error(t, err, ExpectedErrorMessage)
}

func TestCheckRateLimiterUpdateIsBlockedError(t *testing.T) {
	rateLimiterRepository := NewRateLimiterRepositoryMock()
	rateLimiterRepository.On(CountByIpInLastSecond, defaultIp).Return(defaultLimit, nil)
	expectedError := errors.New(DefaultErrorMessage)
	rateLimiterRepository.On(UpdateIsBlocked, defaultIp, defaultToken, true).Return(expectedError)

	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit, defaultTimeDuration)

	err := rateLimiter.checkRateLimit(defaultIp, defaultToken, defaultLimit)
	assert.Error(t, err, ExpectedErrorMessage)
}

func TestCheckRateLimiterError(t *testing.T) {
	rateLimiterRepository := NewRateLimiterRepositoryMock()
	expectedError := errors.New(DefaultErrorMessage)
	rateLimiterRepository.On(CountByIpInLastSecond, defaultIp).Return(defaultLimit, expectedError)

	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit, defaultTimeDuration)

	err := rateLimiter.checkRateLimit(defaultIp, defaultToken, defaultLimit)
	assert.Errorf(t, err, expectedError.Error(), ExpectedErrorMessage, err)
}

func TestEmptyIpRateLimiter(t *testing.T) {
	rateLimiterRepository := NewRateLimiterRepositoryMock()
	rateLimiterRepository.On(CountByIpInLastSecond, defaultIp).Return(initialIpQuantity, nil)
	rateLimiterRepository.On(FindLimitByToken, defaultIp).Return(initialTokenLimit, nil)
	rateLimiterRepository.On(FindIsIpBlocked, defaultIp).Return(false, nil, nil)

	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit, defaultTimeDuration)
	req, err := http.NewRequest(defaultRequestMethod, defaultUrl, nil)
	assert.Nil(t, err)

	err = rateLimiter.Do(req)
	assert.Error(t, err, ExpectedErrorMessage)
}

func TestRateLimiter(t *testing.T) {
	rateLimiterRepository := NewRateLimiterRepositoryMock()
	rateLimiterRepository.On(CountByIpInLastSecond, defaultIp).Return(initialIpQuantity, nil)
	rateLimiterRepository.On(FindLimitByToken, defaultToken).Return(initialTokenLimit, nil)
	rateLimiterRepository.On(FindIsTokenBlocked, defaultToken).Return(false, nil, nil)
	rateLimiterRepository.On(FindIsIpBlocked, defaultIp).Return(false, nil, nil)

	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit, defaultTimeDuration)
	req, err := http.NewRequest(defaultRequestMethod, defaultUrl, nil)
	assert.Nil(t, err)

	req.Header.Set(xRealIp, defaultIp)
	req.Header.Set(apiKeyHeader, defaultToken)

	err = rateLimiter.Do(req)
	assert.Nil(t, err, ExpectedNillMessage, err)
}

func TestRateLimiterExceed(t *testing.T) {
	rateLimiterRepository := NewRateLimiterRepositoryMock()
	rateLimiterRepository.On(CountByIpInLastSecond, defaultIp).Return(defaultLimit, nil)
	rateLimiterRepository.On(FindLimitByToken, defaultToken).Return(defaultLimit, nil)
	rateLimiterRepository.On(FindIsTokenBlocked, defaultToken).Return(false, nil, nil)
	rateLimiterRepository.On(FindIsIpBlocked, defaultIp).Return(false, nil, nil)
	rateLimiterRepository.On(UpdateIsBlocked, defaultIp, defaultToken, true).Return(nil)

	rateLimiter := NewRateLimiter(rateLimiterRepository, 0, defaultTimeDuration)
	req, err := http.NewRequest(defaultRequestMethod, defaultUrl, nil)
	assert.Nil(t, err)

	req.Header.Set(xRealIp, defaultIp)
	req.Header.Set(apiKeyHeader, defaultToken)

	err = rateLimiter.Do(req)
	assert.Error(t, err, ExpectedNillMessage, err)
}

func TestRateLimitePersistanceByToken(t *testing.T) {
	rateLimiterRepository := NewRateLimiterRepositoryMock()
	rateLimiterRepository.On(CountByIpInLastSecond, defaultIp).Return(initialIpQuantity, nil)
	rateLimiterRepository.On(FindLimitByToken, defaultToken).Return(defaultTokenLimit, nil)
	rateLimiterRepository.On(FindIsTokenBlocked, defaultToken).Return(false, nil, nil)
	rateLimiterRepository.On(FindIsIpBlocked, defaultIp).Return(false, nil, nil)
	rateLimiterRepository.On(UpdateIsBlocked, defaultIp, defaultToken, true).Return(nil)

	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit, defaultTimeDuration)
	req, err := http.NewRequest(defaultRequestMethod, defaultUrl, nil)
	assert.Nil(t, err)

	req.Header.Set(xRealIp, defaultIp)
	req.Header.Set(apiKeyHeader, defaultToken)

	for range defaultTokenLimit {
		err = rateLimiter.Do(req)
		assert.Nil(t, err, ExpectedNillMessage, err)
	}

	err = rateLimiter.Do(req)
	assert.Error(t, err, ExpectedErrorMessage)
}

func TestRateLimitePersistance(t *testing.T) {
	rateLimiterRepository := NewRateLimiterRepositoryMock()
	rateLimiterRepository.On(CountByIpInLastSecond, defaultIp).Return(initialIpQuantity, nil)
	rateLimiterRepository.On(FindLimitByToken, defaultToken).Return(defaultTokenLimit, nil)
	rateLimiterRepository.On(FindIsTokenBlocked, "").Return(false, nil, nil)
	rateLimiterRepository.On(FindIsIpBlocked, defaultIp).Return(false, nil, nil)
	rateLimiterRepository.On(UpdateIsBlocked, defaultIp, "", true).Return(nil)

	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit, defaultTimeDuration)
	req, err := http.NewRequest(defaultRequestMethod, defaultUrl, nil)
	assert.Nil(t, err)

	req.Header.Set(xRealIp, defaultIp)

	for range defaultLimit {
		err = rateLimiter.Do(req)
		assert.Nil(t, err, ExpectedNillMessage, err)
	}

	err = rateLimiter.Do(req)
	assert.Error(t, err, ExpectedErrorMessage)
}

func TestRateLimiterIsIpBlocked(t *testing.T) {
	timeDuration := calculateBlockTimeDuration(defaultTimeDuration)
	rateLimiterRepository := NewRateLimiterRepositoryMock()
	rateLimiterRepository.On(CountByIpInLastSecond, defaultIp).Return(initialIpQuantity, nil)
	rateLimiterRepository.On(FindLimitByToken, defaultToken).Return(initialTokenLimit, nil)
	rateLimiterRepository.On(FindIsTokenBlocked, "").Return(false, nil, nil)
	rateLimiterRepository.On(FindIsIpBlocked, defaultIp).Return(true, timeDuration, nil)

	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit, defaultTimeDuration)
	req, err := http.NewRequest(defaultRequestMethod, defaultUrl, nil)
	assert.Nil(t, err)

	req.Header.Set(xRealIp, defaultIp)
	req.Header.Set(apiKeyHeader, "")

	err = rateLimiter.Do(req)
	assert.Error(t, err, ExpectedErrorMessage)
}

func TestRateLimiterIsTokenBlocked(t *testing.T) {
	timeDuration := calculateBlockTimeDuration(defaultTimeDuration)

	rateLimiterRepository := NewRateLimiterRepositoryMock()
	rateLimiterRepository.On(CountByIpInLastSecond, defaultIp).Return(initialIpQuantity, nil)
	rateLimiterRepository.On(FindLimitByToken, defaultToken).Return(initialTokenLimit, nil)
	rateLimiterRepository.On(FindIsTokenBlocked, defaultToken).Return(true, timeDuration, nil)
	rateLimiterRepository.On(FindIsIpBlocked, defaultIp).Return(false, nil, nil)

	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit, defaultTimeDuration)
	req, err := http.NewRequest(defaultRequestMethod, defaultUrl, nil)
	assert.Nil(t, err)

	req.Header.Set(xRealIp, defaultIp)
	req.Header.Set(apiKeyHeader, defaultToken)

	err = rateLimiter.Do(req)
	assert.Error(t, err, ExpectedErrorMessage)
}

func TestShouldNotUnblock(t *testing.T) {
	rateLimiterRepository := NewRateLimiterRepositoryMock()
	rateLimiterRepository.On(UpdateIsBlocked, defaultIp, defaultToken, false).Return(nil)

	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit, defaultTimeDuration)

	timeDuration := calculateBlockTimeDuration(defaultTimeDuration)

	err := rateLimiter.shouldUnblock(defaultIp, defaultToken, &timeDuration)
	assert.Error(t, err, ExpectedErrorMessage)
}

func TestShouldUnblock(t *testing.T) {
	rateLimiterRepository := NewRateLimiterRepositoryMock()
	rateLimiterRepository.On(UpdateIsBlocked, "", defaultToken, false).Return(nil)

	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit, defaultTimeDuration)

	timeDuration := calculateBlockTimeDuration(-defaultTimeDuration)

	err := rateLimiter.shouldUnblock(defaultIp, defaultToken, &timeDuration)
	assert.Nil(t, err, ExpectedNillMessage)
}

func TestShouldUnblockError(t *testing.T) {
	rateLimiterRepository := NewRateLimiterRepositoryMock()
	rateLimiterRepository.On(UpdateIsBlocked, "", defaultToken, false).Return(errors.New(DefaultErrorMessage))

	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit, defaultTimeDuration)

	timeDuration := calculateBlockTimeDuration(-defaultTimeDuration)

	err := rateLimiter.shouldUnblock(defaultIp, defaultToken, &timeDuration)
	assert.Error(t, err, ExpectedErrorMessage)
}

func TestDefineAmountInLastSecondByIp(t *testing.T) {
	rateLimiterRepository := NewRateLimiterRepositoryMock()
	rateLimiterRepository.On(CountByIpInLastSecond, defaultIp).Return(initialIpQuantity, nil)

	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit, defaultTimeDuration)

	amount, err := rateLimiter.defineAmountInLastSecond(defaultIp, "")
	assert.Nil(t, err)
	assert.Equal(t, initialIpQuantity, amount)
}
