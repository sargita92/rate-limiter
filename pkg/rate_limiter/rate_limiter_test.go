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
	defaultToken          = "test"
	defaultRequestMethod  = "GET"
	defaultUrl            = "/"
	FindLimitByToken      = "FindLimitByToken"
	CountByIpInLastSecond = "CountByIpInLastSecond"
	FindIsBlocked         = "FindIsBlocked"
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

func TestCheckNotBlocked(t *testing.T) {
	rateLimiterRepository := NewRateLimiterRepositoryMock()
	rateLimiterRepository.On(FindIsBlocked, defaultIp).Return(false, nil)

	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit)
	err := rateLimiter.checkIsBlocked(defaultIp)
	assert.Nil(t, rateLimiter.checkIsBlocked(defaultIp), ExpectedNillMessage, err)
}

func TestCheckIsBlockedError(t *testing.T) {
	rateLimiterRepository := NewRateLimiterRepositoryMock()
	rateLimiterRepository.On(FindIsBlocked, defaultIp).Return(false, errors.New(DefaultErrorMessage))

	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit)
	err := rateLimiter.checkIsBlocked(defaultIp)
	assert.Error(t, err, ExpectedErrorMessage, err)
}

func TestCheckIsBlocked(t *testing.T) {
	rateLimiterRepository := NewRateLimiterRepositoryMock()
	rateLimiterRepository.On(FindIsBlocked, defaultIp).Return(true, nil)

	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit)
	err := rateLimiter.checkIsBlocked(defaultIp)
	assert.Error(t, err, ExpectedErrorMessage, err)
}

func TestDefineToken(t *testing.T) {
	req, err := http.NewRequest(defaultRequestMethod, defaultUrl, nil)
	assert.Nil(t, err)

	rateLimiterRepository := NewRateLimiterRepositoryMock()
	rateLimiterRepository.On(FindLimitByToken, defaultToken).Return(defaultTokenLimit, nil)
	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit)

	req.Header.Set(apiKeyHeader, defaultToken)
	assert.Equal(t, defaultTokenLimit, rateLimiter.defineToken(req))

	req.Header.Del(apiKeyHeader)
	assert.Equal(t, defaultLimit, rateLimiter.defineToken(req))
}

func TestTokenNotFound(t *testing.T) {
	req, err := http.NewRequest(defaultRequestMethod, defaultUrl, nil)
	assert.Nil(t, err)

	rateLimiterRepository := NewRateLimiterRepositoryMock()
	rateLimiterRepository.On(FindLimitByToken, defaultToken).Return(initialIpQuantity, nil)
	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit)

	req.Header.Set(apiKeyHeader, defaultToken)
	assert.Equal(t, defaultLimit, rateLimiter.defineToken(req))
}

func TestDefineTokenError(t *testing.T) {
	req, err := http.NewRequest(defaultRequestMethod, defaultUrl, nil)
	assert.Nil(t, err)

	rateLimiterRepository := NewRateLimiterRepositoryMock()
	err = errors.New(DefaultErrorMessage)
	rateLimiterRepository.On(FindLimitByToken, defaultToken).Return(initialTokenLimit, err)
	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit)

	req.Header.Set(apiKeyHeader, defaultToken)
	assert.Equal(t, defaultLimit, rateLimiter.defineToken(req))
}

func TestCheckRateLimiter(t *testing.T) {
	rateLimiterRepository := NewRateLimiterRepositoryMock()
	rateLimiterRepository.On(CountByIpInLastSecond, defaultIp).Return(initialIpQuantity, nil)

	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit)

	err := rateLimiter.checkRateLimit(defaultIp, 1)
	assert.Nil(t, err, ExpectedNillMessage, err)
}

func TestCheckRateLimiterShouldExceedLimit(t *testing.T) {
	rateLimiterRepository := NewRateLimiterRepositoryMock()
	rateLimiterRepository.On(CountByIpInLastSecond, defaultIp).Return(defaultLimit, nil)
	rateLimiterRepository.On(UpdateIsBlocked, defaultIp, true).Return(true, nil)

	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit)

	err := rateLimiter.checkRateLimit(defaultIp, defaultLimit)
	assert.Error(t, err, ExpectedErrorMessage)
}

func TestCheckRateLimiterUpdateIsBlockedError(t *testing.T) {
	rateLimiterRepository := NewRateLimiterRepositoryMock()
	rateLimiterRepository.On(CountByIpInLastSecond, defaultIp).Return(defaultLimit, nil)
	expectedError := errors.New(DefaultErrorMessage)
	rateLimiterRepository.On(UpdateIsBlocked, defaultIp, true).Return(true, expectedError)

	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit)

	err := rateLimiter.checkRateLimit(defaultIp, defaultLimit)
	assert.Error(t, err, ExpectedErrorMessage)
}

func TestCheckRateLimiterError(t *testing.T) {
	rateLimiterRepository := NewRateLimiterRepositoryMock()
	expectedError := errors.New(DefaultErrorMessage)
	rateLimiterRepository.On(CountByIpInLastSecond, defaultIp).Return(defaultLimit, expectedError)

	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit)

	err := rateLimiter.checkRateLimit(defaultIp, defaultLimit)
	assert.Errorf(t, err, expectedError.Error(), ExpectedErrorMessage, err)
}

func TestEmptyIpRateLimiter(t *testing.T) {
	rateLimiterRepository := NewRateLimiterRepositoryMock()
	rateLimiterRepository.On(CountByIpInLastSecond, defaultIp).Return(initialIpQuantity, nil)
	rateLimiterRepository.On(FindLimitByToken, defaultIp).Return(initialTokenLimit, nil)
	rateLimiterRepository.On(FindIsBlocked, defaultIp).Return(false, nil)

	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit)
	req, err := http.NewRequest(defaultRequestMethod, defaultUrl, nil)
	assert.Nil(t, err)

	err = rateLimiter.Do(req)
	assert.Error(t, err, ExpectedErrorMessage)
}

func TestRateLimiter(t *testing.T) {
	rateLimiterRepository := NewRateLimiterRepositoryMock()
	rateLimiterRepository.On(CountByIpInLastSecond, defaultIp).Return(initialIpQuantity, nil)
	rateLimiterRepository.On(FindLimitByToken, defaultToken).Return(initialTokenLimit, nil)
	rateLimiterRepository.On(FindIsBlocked, defaultIp).Return(false, nil)

	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit)
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
	rateLimiterRepository.On(FindIsBlocked, defaultIp).Return(false, nil)
	rateLimiterRepository.On(UpdateIsBlocked, defaultIp, true).Return(true, nil)

	rateLimiter := NewRateLimiter(rateLimiterRepository, 0)
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
	rateLimiterRepository.On(FindIsBlocked, defaultIp).Return(false, nil)
	rateLimiterRepository.On(UpdateIsBlocked, defaultIp, true).Return(true, nil)

	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit)
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
	rateLimiterRepository.On(FindIsBlocked, defaultIp).Return(false, nil)
	rateLimiterRepository.On(UpdateIsBlocked, defaultIp, true).Return(true, nil)

	rateLimiter := NewRateLimiter(rateLimiterRepository, defaultLimit)
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
