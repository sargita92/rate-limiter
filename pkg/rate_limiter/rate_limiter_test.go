package rate_limiter

import (
	"errors"
	_ "errors"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

const (
	defaultIp = "1.1.1.1"
	secondIp  = "2.2.2.2"

	initialTryCount      = 0
	defaultLimit         = 3
	defaultTokenLimit    = 5
	defaultTimeDuration  = 1
	defaultToken         = "test"
	defaultRequestMethod = "GET"
	defaultUrl           = "/"
	DefaultErrorMessage  = "error"
	ExpectedErrorMessage = "Expected error, got nil"
	ExpectedNillMessage  = "Expected nil, got %v"
)

func startRateLimite() (*RateLimiter, *RateLimiterRepositoryMock) {
	RateLimiterRepository := NewRateLimiterRepositoryMock()

	return NewRateLimiter(
		RateLimiterRepository,
		defaultLimit,
		defaultTimeDuration,
	), RateLimiterRepository
}

func TestRateLimiterDo(t *testing.T) {
	rateLimiter, repository := startRateLimite()

	repository.On("SaveTry", defaultIp, defaultToken).Return(initialTryCount, nil)
	repository.On("TokenExists", defaultToken).Return(true, nil)
	repository.On("IsBlockedByIp", defaultIp).Return(false, nil)
	repository.On("IsBlockedByToken", defaultToken).Return(false, nil)

	repository.On("FindLimitByToken", defaultToken).Return(defaultTokenLimit, nil)
	repository.On("FindTriesByTokenInLastSecond", defaultToken).Return(initialTryCount, nil)
	repository.On("BlockToken", defaultToken).Return(nil)

	repository.On("FindLimitByIp", defaultIp).Return(defaultLimit, nil)
	repository.On("FindTriesByIpInLastSecond", defaultIp).Return(initialTryCount, nil)
	repository.On("BlockIp", defaultIp).Return(nil)

	req, err := http.NewRequest(defaultRequestMethod, defaultUrl, nil)
	assert.Nil(t, err, ExpectedNillMessage, err)

	req.Header.Set(xRealIp, defaultIp)
	req.Header.Set(apiKeyHeader, defaultToken)

	err = rateLimiter.Do(req)
	assert.Nil(t, err, ExpectedNillMessage, err)
}

func TestRateLimiterDoWithoutToken(t *testing.T) {
	rateLimiter, repository := startRateLimite()

	repository.On("SaveTry", defaultIp, "").Return(initialTryCount, nil)
	repository.On("TokenExists", "").Return(true, nil)
	repository.On("IsBlockedByIp", defaultIp).Return(false, nil)
	repository.On("IsBlockedByToken", "").Return(false, nil)

	repository.On("FindLimitByIp", defaultIp).Return(defaultLimit, nil)
	repository.On("FindTriesByIpInLastSecond", defaultIp).Return(initialTryCount, nil)
	repository.On("BlockIp", defaultIp).Return(nil)

	req, err := http.NewRequest(defaultRequestMethod, defaultUrl, nil)
	assert.Nil(t, err, ExpectedNillMessage, err)

	req.Header.Set(xRealIp, defaultIp)
	req.Header.Set(apiKeyHeader, "")

	err = rateLimiter.Do(req)
	assert.Nil(t, err, ExpectedNillMessage, err)
}

func TestRateLimiterTokenErrorSaveTry(t *testing.T) {
	rateLimiter, repository := startRateLimite()

	repository.On("SaveTry", defaultIp, defaultToken).Return(initialTryCount, nil)
	repository.On("TokenExists", defaultToken).Return(false, nil)

	req, err := http.NewRequest(defaultRequestMethod, defaultUrl, nil)
	assert.Nil(t, err, ExpectedNillMessage, err)

	req.Header.Set(xRealIp, defaultIp)
	req.Header.Set(apiKeyHeader, defaultToken)

	err = rateLimiter.Do(req)
	assert.Error(t, err, ExpectedErrorMessage, err)
}

func TestRateLimiterTokenErrorSaveTryError(t *testing.T) {
	rateLimiter, repository := startRateLimite()

	repository.On("SaveTry", defaultIp, defaultToken).Return(initialTryCount, errors.New(DefaultErrorMessage))
	repository.On("TokenExists", defaultToken).Return(false, nil)

	req, err := http.NewRequest(defaultRequestMethod, defaultUrl, nil)
	assert.Nil(t, err, ExpectedNillMessage, err)

	req.Header.Set(xRealIp, defaultIp)
	req.Header.Set(apiKeyHeader, defaultToken)

	err = rateLimiter.Do(req)
	assert.Error(t, err, ExpectedErrorMessage, err)
}

func TestDoSaveTryError(t *testing.T) {
	rateLimiter, repository := startRateLimite()

	err := errors.New(DefaultErrorMessage)

	repository.On("SaveTry", defaultIp, defaultToken).Return(initialTryCount, err)
	repository.On("TokenExists", defaultToken).Return(true, nil)

	req, err := http.NewRequest(defaultRequestMethod, defaultUrl, nil)
	assert.Nil(t, err, ExpectedNillMessage, err)

	req.Header.Set(xRealIp, defaultIp)
	req.Header.Set(apiKeyHeader, defaultToken)

	err = rateLimiter.Do(req)
	assert.Error(t, err, ExpectedErrorMessage, err)
}

func TestDoTokenIsBlocked(t *testing.T) {
	rateLimiter, repository := startRateLimite()

	repository.On("SaveTry", defaultIp, defaultToken).Return(initialTryCount, nil)
	repository.On("TokenExists", defaultToken).Return(true, nil)
	repository.On("IsBlockedByIp", defaultIp).Return(true, nil)
	repository.On("IsBlockedByToken", defaultToken).Return(true, nil)

	req, err := http.NewRequest(defaultRequestMethod, defaultUrl, nil)
	assert.Nil(t, err, ExpectedNillMessage, err)

	req.Header.Set(xRealIp, defaultIp)
	req.Header.Set(apiKeyHeader, defaultToken)

	err = rateLimiter.Do(req)
	assert.Error(t, err, ExpectedErrorMessage, err)
}

func TestDoIpIsBlocked(t *testing.T) {
	rateLimiter, repository := startRateLimite()

	repository.On("SaveTry", defaultIp, defaultToken).Return(initialTryCount, nil)
	repository.On("TokenExists", defaultToken).Return(true, nil)
	repository.On("IsBlockedByIp", defaultIp).Return(true, nil)
	repository.On("IsBlockedByToken", defaultToken).Return(false, nil)

	req, err := http.NewRequest(defaultRequestMethod, defaultUrl, nil)
	assert.Nil(t, err, ExpectedNillMessage, err)

	req.Header.Set(xRealIp, defaultIp)
	req.Header.Set(apiKeyHeader, defaultToken)

	err = rateLimiter.Do(req)
	assert.Error(t, err, ExpectedErrorMessage, err)
}

func TestRateLimiterDoTokenTriesExceeded(t *testing.T) {
	rateLimiter, repository := startRateLimite()

	repository.On("SaveTry", defaultIp, defaultToken).Return(initialTryCount, nil)
	repository.On("TokenExists", defaultToken).Return(true, nil)
	repository.On("IsBlockedByIp", defaultIp).Return(false, nil)
	repository.On("IsBlockedByToken", defaultToken).Return(false, nil)

	repository.On("FindLimitByToken", defaultToken).Return(defaultTokenLimit, nil)
	repository.On("FindTriesByTokenInLastSecond", defaultToken).Return(defaultTokenLimit, nil)
	repository.On("BlockToken", defaultToken).Return(nil)

	repository.On("FindLimitByIp", defaultIp).Return(defaultLimit, nil)
	repository.On("FindTriesByIpInLastSecond", defaultIp).Return(initialTryCount, nil)
	repository.On("BlockIp", defaultIp).Return(nil)

	req, err := http.NewRequest(defaultRequestMethod, defaultUrl, nil)
	assert.Nil(t, err, ExpectedNillMessage, err)

	req.Header.Set(xRealIp, defaultIp)
	req.Header.Set(apiKeyHeader, defaultToken)

	err = rateLimiter.Do(req)
	assert.Error(t, err, ExpectedErrorMessage, err)
}

func TestRateLimiterDoIpTriesExceeded(t *testing.T) {
	rateLimiter, repository := startRateLimite()

	repository.On("SaveTry", defaultIp, "").Return(initialTryCount, nil)
	repository.On("TokenExists", "").Return(true, nil)
	repository.On("IsBlockedByIp", defaultIp).Return(false, nil)
	repository.On("IsBlockedByToken", "").Return(false, nil)

	repository.On("FindLimitByIp", defaultIp).Return(defaultLimit, nil)
	repository.On("FindTriesByIpInLastSecond", defaultIp).Return(defaultLimit, nil)
	repository.On("BlockIp", defaultIp).Return(nil)

	req, err := http.NewRequest(defaultRequestMethod, defaultUrl, nil)
	assert.Nil(t, err, ExpectedNillMessage, err)

	req.Header.Set(xRealIp, defaultIp)

	err = rateLimiter.Do(req)
	assert.Error(t, err, ExpectedErrorMessage, err)
}

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

func TestDefineToken(t *testing.T) {
	req, err := http.NewRequest(defaultRequestMethod, defaultUrl, nil)
	assert.Nil(t, err)

	req.Header.Set(apiKeyHeader, defaultToken)
	assert.Equal(t, defaultToken, (&RateLimiter{}).defineToken(req))
}

func TestEmptyDefineToken(t *testing.T) {
	req, err := http.NewRequest(defaultRequestMethod, defaultUrl, nil)
	assert.Nil(t, err)

	assert.Equal(t, "", (&RateLimiter{}).defineToken(req))
}

func TestCheckToken(t *testing.T) {
	repository := NewRateLimiterRepositoryMock()

	repository.On("TokenExists", defaultToken).Return(true, nil)

	rateLimiter := NewRateLimiter(repository, defaultTokenLimit, defaultTimeDuration)

	assert.Nil(t, rateLimiter.checkTokenExists(defaultToken), ExpectedNillMessage)
}

func TestCheckTokenNotFound(t *testing.T) {
	repository := NewRateLimiterRepositoryMock()

	repository.On("TokenExists", defaultToken).Return(false, nil)

	rateLimiter := NewRateLimiter(repository, defaultTokenLimit, defaultTimeDuration)

	assert.Error(t, rateLimiter.checkTokenExists(defaultToken), ExpectedErrorMessage)
}

func TestCheckTokenError(t *testing.T) {
	repository := NewRateLimiterRepositoryMock()

	repository.On("TokenExists", defaultToken).Return(false, errors.New(DefaultErrorMessage))

	rateLimiter := NewRateLimiter(repository, defaultTokenLimit, defaultTimeDuration)

	assert.Error(t, rateLimiter.checkTokenExists(defaultToken), ExpectedErrorMessage)
}

func TestEmptyCheckToken(t *testing.T) {
	assert.Nil(t, (&RateLimiter{}).checkTokenExists(""))
}

func TestSaveTry(t *testing.T) {
	rateLimiter, repository := startRateLimite()

	repository.On("SaveTry", defaultIp, defaultToken).Return(initialTryCount, nil)

	err := rateLimiter.saveTry(defaultIp, defaultToken)
	assert.Nil(t, err, ExpectedNillMessage, err)
}

func TestCheckTokenIsBlocked(t *testing.T) {
	rateLimiter, repository := startRateLimite()

	repository.On("IsBlockedByToken", defaultToken).Return(false, nil)

	assert.Nil(t, rateLimiter.checkIsTokenBlocked(defaultToken), ExpectedNillMessage)
}

func TestCheckEmptyTokenIsBlocked(t *testing.T) {
	assert.Nil(t, (&RateLimiter{}).checkIsTokenBlocked(""))
}

func TestCheckTokenIsBlockedError(t *testing.T) {
	rateLimiter, repository := startRateLimite()

	repository.On("IsBlockedByToken", defaultToken).Return(false, errors.New(DefaultErrorMessage))

	assert.Error(t, rateLimiter.checkIsTokenBlocked(defaultToken), ExpectedErrorMessage)
}

func TestCheckTokenIsBlockedWhenBlocked(t *testing.T) {
	rateLimiter, repository := startRateLimite()

	repository.On("IsBlockedByToken", defaultToken).Return(true, nil)

	assert.Error(t, rateLimiter.checkIsTokenBlocked(defaultToken), ExpectedErrorMessage)
}

func TestCheckIpIsBlocked(t *testing.T) {
	rateLimiter, repository := startRateLimite()

	repository.On("IsBlockedByIp", defaultToken).Return(false, nil)

	assert.Nil(t, rateLimiter.checkIsIpBlocked(defaultToken), ExpectedNillMessage)
}

func TestCheckEmptyIpIsBlocked(t *testing.T) {
	assert.Error(t, (&RateLimiter{}).checkIsIpBlocked(""), ExpectedErrorMessage)
}

func TestCheckIpIsBlockedError(t *testing.T) {
	rateLimiter, repository := startRateLimite()

	repository.On("IsBlockedByIp", defaultToken).Return(false, errors.New(DefaultErrorMessage))

	assert.Error(t, rateLimiter.checkIsIpBlocked(defaultToken), ExpectedErrorMessage)
}

func TestCheckIpIsBlockedWhenBlocked(t *testing.T) {
	rateLimiter, repository := startRateLimite()

	repository.On("IsBlockedByIp", defaultToken).Return(true, nil)

	assert.Error(t, rateLimiter.checkIsIpBlocked(defaultToken), ExpectedErrorMessage)
}

func TestBlockedTryByToken(t *testing.T) {
	rateLimiter, repository := startRateLimite()

	repository.On("FindLimitByToken", defaultToken).Return(defaultTokenLimit, nil)
	repository.On("FindTriesByTokenInLastSecond", defaultToken).Return(defaultTokenLimit, nil)
	repository.On("BlockToken", defaultToken).Return(nil)

	assert.Error(t, rateLimiter.blockedTry(defaultIp, defaultToken), ExpectedErrorMessage)
}

func TestBlockedTryByIp(t *testing.T) {
	rateLimiter, repository := startRateLimite()

	repository.On("FindLimitByIp", defaultIp).Return(defaultLimit, nil)
	repository.On("FindTriesByIpInLastSecond", defaultIp).Return(defaultLimit, nil)
	repository.On("BlockIp", defaultIp).Return(nil)

	assert.Error(t, rateLimiter.blockedTry(defaultIp, ""), ExpectedErrorMessage)
}

func TestDoesntBlockTryWithToken(t *testing.T) {
	rateLimiter, repository := startRateLimite()

	repository.On("FindLimitByToken", defaultToken).Return(defaultTokenLimit, nil)
	repository.On("FindTriesByTokenInLastSecond", defaultToken).Return(initialTryCount, nil)
	repository.On("BlockToken", defaultToken).Return(nil)

	repository.On("FindLimitByIp", defaultIp).Return(defaultLimit, nil)
	repository.On("FindTriesByIpInLastSecond", defaultIp).Return(initialTryCount, nil)
	repository.On("BlockIp", defaultIp).Return(nil)

	assert.Nil(t, rateLimiter.blockedTry(defaultIp, defaultToken), ExpectedNillMessage)
}

func TestDoesntBlockTryWithEmptyToken(t *testing.T) {
	rateLimiter, repository := startRateLimite()

	repository.On("FindLimitByIp", defaultIp).Return(defaultLimit, nil)
	repository.On("FindTriesByIpInLastSecond", defaultIp).Return(initialTryCount, nil)
	repository.On("BlockIp", defaultIp).Return(nil)

	assert.Nil(t, rateLimiter.blockedTry(defaultIp, ""), ExpectedNillMessage)
}

func TestDefineDefaultLimit(t *testing.T) {
	rateLimiter, repository := startRateLimite()

	repository.On("FindLimitByToken", defaultToken).Return(defaultTokenLimit, nil)

	assert.Equal(t, defaultTokenLimit, rateLimiter.defineTryLimit(defaultToken))
}

func TestDefineTryLimitWhenEmptyToken(t *testing.T) {
	rateLimiter, _ := startRateLimite()

	assert.Equal(t, defaultLimit, rateLimiter.defineTryLimit(""))
}

func TestDefineTryLimitError(t *testing.T) {
	rateLimiter, repository := startRateLimite()

	repository.On("FindLimitByToken", defaultToken).Return(0, errors.New(DefaultErrorMessage))

	assert.Equal(t, defaultLimit, rateLimiter.defineTryLimit(defaultToken))
}

func TestDefineTryLimitNoLimitFound(t *testing.T) {
	rateLimiter, repository := startRateLimite()

	repository.On("FindLimitByToken", defaultToken).Return(0, nil)

	assert.Equal(t, defaultLimit, rateLimiter.defineTryLimit(defaultToken))
}

func TestBlockedTokenWhenTokenIsEmpty(t *testing.T) {
	rateLimiter, _ := startRateLimite()

	assert.Nil(t, rateLimiter.blockedToken("", 0), ExpectedNillMessage)
}

func TestBlockedTokenWhenFindTryError(t *testing.T) {
	rateLimiter, repository := startRateLimite()

	repository.On("FindTriesByTokenInLastSecond", defaultToken).Return(0, errors.New(DefaultErrorMessage))

	assert.Error(t, rateLimiter.blockedToken(defaultToken, 0), ExpectedErrorMessage)
}

func TestBlockedTokenWhenTryLimitExceeded(t *testing.T) {
	rateLimiter, repository := startRateLimite()

	repository.On("FindTriesByTokenInLastSecond", defaultToken).Return(defaultTokenLimit, nil)
	repository.On("BlockToken", defaultToken).Return(nil)

	assert.Error(t, rateLimiter.blockedToken(defaultToken, defaultTokenLimit), rateLimitExceeded)
}

func TestBlockedTokenWhenTryLimitExceededBockedTokenError(t *testing.T) {
	rateLimiter, repository := startRateLimite()

	repository.On("FindTriesByTokenInLastSecond", defaultToken).Return(defaultTokenLimit, nil)
	repository.On("BlockToken", defaultToken).Return(errors.New(DefaultErrorMessage))

	assert.Error(t, rateLimiter.blockedToken(defaultToken, defaultTokenLimit), ExpectedErrorMessage)
}

func TestBlockedTokenWhenTryLimitNotExceeded(t *testing.T) {
	rateLimiter, repository := startRateLimite()

	repository.On("FindTriesByTokenInLastSecond", defaultToken).Return(initialTryCount, nil)

	assert.Nil(t, rateLimiter.blockedToken(defaultToken, defaultTokenLimit), ExpectedNillMessage)
}

func TestBlockedIpWhenIpIsEmpty(t *testing.T) {
	rateLimiter, _ := startRateLimite()

	assert.Error(t, rateLimiter.blockedIp("", 0), ipNotFound)
}

func TestBlockedIpWhenFindTryError(t *testing.T) {
	rateLimiter, repository := startRateLimite()

	repository.On("FindTriesByIpInLastSecond", defaultIp).Return(0, errors.New(DefaultErrorMessage))

	assert.Error(t, rateLimiter.blockedIp(defaultIp, 0), ExpectedErrorMessage)
}

func TestBlockedIpWhenTryLimitExceeded(t *testing.T) {
	rateLimiter, repository := startRateLimite()

	repository.On("FindTriesByIpInLastSecond", defaultIp).Return(defaultLimit, nil)
	repository.On("BlockIp", defaultIp).Return(nil)

	assert.Error(t, rateLimiter.blockedIp(defaultIp, defaultLimit), rateLimitExceeded)
}

func TestBlockedIpWhenTryLimitExceededBockedIpError(t *testing.T) {
	rateLimiter, repository := startRateLimite()

	repository.On("FindTriesByIpInLastSecond", defaultIp).Return(defaultLimit, nil)
	repository.On("BlockIp", defaultIp).Return(errors.New(DefaultErrorMessage))

	assert.Error(t, rateLimiter.blockedIp(defaultIp, defaultLimit), ExpectedErrorMessage)
}

func TestBlockedIpWhenTryLimitNotExceeded(t *testing.T) {
	rateLimiter, repository := startRateLimite()

	repository.On("FindTriesByIpInLastSecond", defaultIp).Return(initialTryCount, nil)

	assert.Nil(t, rateLimiter.blockedIp(defaultIp, defaultLimit), ExpectedNillMessage)
}
