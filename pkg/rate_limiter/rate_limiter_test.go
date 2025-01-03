package rate_limiter

import (
	"errors"
	_ "errors"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
	"time"
)

const (
	defaultIp = "1.1.1.1"
	secondIp  = "2.2.2.2"

	initialTryCount      = 0
	defaultLimit         = 3
	defaultTokenLimit    = 5
	defaultTimeDuration  = 1
	tokenTimeDuration    = 2
	defaultToken         = "test"
	defaultRequestMethod = "GET"
	defaultUrl           = "/"
	DefaultErrorMessage  = "error"
	ExpectedErrorMessage = "Expected error, got nil"
	ExpectedNillMessage  = "Expected nil, got %v"
)

func startRateLimite(currentTime time.Time) (*RateLimiter, *RateLimiterRepositoryMock) {
	RateLimiterRepository := NewRateLimiterRepositoryMock(currentTime)

	return NewRateLimiter(
		RateLimiterRepository,
		defaultLimit,
		defaultTimeDuration,
	), RateLimiterRepository
}

func TestRateLimiterDo(t *testing.T) {
	calculateTime := calculateBlockTimeWindow(tokenTimeDuration)
	rateLimiter, repository := startRateLimite(calculateTime)

	repository.On("SaveTry", defaultIp, defaultToken).Return(initialTryCount, nil)
	repository.On("TokenExists", defaultToken).Return(true, nil)
	repository.On("IsBlockedByIp", defaultIp, calculateTime).Return(false, nil)
	repository.On("IsBlockedByToken", defaultToken, calculateTime).Return(false, nil)
	repository.On("FindTokenBlockDuration", defaultToken).Return(tokenTimeDuration, nil)

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

func TestRateLimiterDoUntilExceededTokenTries(t *testing.T) {
	calculateTime := calculateBlockTimeWindow(tokenTimeDuration)
	rateLimiter, repository := startRateLimite(calculateTime)

	repository.On("SaveTry", defaultIp, defaultToken).Return(initialTryCount, nil)
	repository.On("TokenExists", defaultToken).Return(true, nil)
	repository.On("IsBlockedByIp", defaultIp, calculateTime).Return(false, nil)
	repository.On("IsBlockedByToken", defaultToken, calculateTime).Return(false, nil)
	repository.On("FindTokenBlockDuration", defaultToken).Return(tokenTimeDuration, nil)

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

	for range defaultTokenLimit {
		err = rateLimiter.Do(req)
		assert.Nil(t, err, ExpectedNillMessage, err)
	}

	err = rateLimiter.Do(req)
	assert.Error(t, err, ExpectedErrorMessage, err)
}

func TestRateLimiterDoUntilExceededIpTries(t *testing.T) {
	calculateTime := calculateBlockTimeWindow(tokenTimeDuration)
	rateLimiter, repository := startRateLimite(calculateTime)

	repository.On("SaveTry", defaultIp, "").Return(initialTryCount, nil)
	repository.On("TokenExists", "").Return(true, nil)
	repository.On("IsBlockedByIp", defaultIp, calculateTime).Return(false, nil)
	repository.On("IsBlockedByToken", "", calculateTime).Return(false, nil)
	repository.On("FindTokenBlockDuration", "").Return(tokenTimeDuration, nil)

	repository.On("FindLimitByToken", "").Return(defaultTokenLimit, nil)
	repository.On("FindTriesByTokenInLastSecond", "").Return(initialTryCount, nil)
	repository.On("BlockToken", "").Return(nil)

	repository.On("FindLimitByIp", defaultIp).Return(defaultLimit, nil)
	repository.On("FindTriesByIpInLastSecond", defaultIp).Return(initialTryCount, nil)
	repository.On("BlockIp", defaultIp).Return(nil)

	req, err := http.NewRequest(defaultRequestMethod, defaultUrl, nil)
	assert.Nil(t, err, ExpectedNillMessage, err)

	req.Header.Set(xRealIp, defaultIp)
	req.Header.Set(apiKeyHeader, "")

	for range defaultLimit {
		err = rateLimiter.Do(req)
		assert.Nil(t, err, ExpectedNillMessage, err)
	}

	err = rateLimiter.Do(req)
	assert.Error(t, err, ExpectedErrorMessage, err)
}

func TestRateLimiterDoWithoutToken(t *testing.T) {
	calculateTime := calculateBlockTimeWindow(tokenTimeDuration)
	rateLimiter, repository := startRateLimite(calculateTime)

	repository.On("SaveTry", defaultIp, "").Return(initialTryCount, nil)
	repository.On("TokenExists", "").Return(true, nil)
	repository.On("IsBlockedByIp", defaultIp, calculateTime).Return(false, nil)
	repository.On("IsBlockedByToken", "", calculateTime).Return(false, nil)

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
	rateLimiter, repository := startRateLimite(time.Now())

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
	rateLimiter, repository := startRateLimite(time.Now())

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
	rateLimiter, repository := startRateLimite(time.Now())

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
	calculateTime := calculateBlockTimeWindow(tokenTimeDuration)
	rateLimiter, repository := startRateLimite(calculateTime)

	repository.On("SaveTry", defaultIp, defaultToken).Return(initialTryCount, nil)
	repository.On("TokenExists", defaultToken).Return(true, nil)
	repository.On("IsBlockedByIp", defaultIp).Return(true, nil)
	repository.On("IsBlockedByToken", defaultToken, calculateTime).Return(true, nil)
	repository.On("FindTokenBlockDuration", defaultToken).Return(tokenTimeDuration, nil)

	req, err := http.NewRequest(defaultRequestMethod, defaultUrl, nil)
	assert.Nil(t, err, ExpectedNillMessage, err)

	req.Header.Set(xRealIp, defaultIp)
	req.Header.Set(apiKeyHeader, defaultToken)

	err = rateLimiter.Do(req)
	assert.Error(t, err, ExpectedErrorMessage, err)
}

func TestDoIpIsBlocked(t *testing.T) {
	calculateTime := calculateBlockTimeWindow(tokenTimeDuration)
	rateLimiter, repository := startRateLimite(calculateTime)

	repository.On("SaveTry", defaultIp, defaultToken).Return(initialTryCount, nil)
	repository.On("TokenExists", defaultToken).Return(true, nil)
	repository.On("IsBlockedByIp", defaultIp, calculateTime).Return(true, nil)
	repository.On("IsBlockedByToken", defaultToken, calculateTime).Return(false, nil)
	repository.On("FindTokenBlockDuration", defaultToken).Return(tokenTimeDuration, nil)

	req, err := http.NewRequest(defaultRequestMethod, defaultUrl, nil)
	assert.Nil(t, err, ExpectedNillMessage, err)

	req.Header.Set(xRealIp, defaultIp)
	req.Header.Set(apiKeyHeader, defaultToken)

	err = rateLimiter.Do(req)
	assert.Error(t, err, ExpectedErrorMessage, err)
}

func TestRateLimiterDoTokenTriesExceeded(t *testing.T) {
	calculateTime := calculateBlockTimeWindow(tokenTimeDuration)
	rateLimiter, repository := startRateLimite(calculateTime)

	repository.On("SaveTry", defaultIp, defaultToken).Return(initialTryCount, nil)
	repository.On("TokenExists", defaultToken).Return(true, nil)
	repository.On("IsBlockedByIp", defaultIp, calculateTime).Return(false, nil)
	repository.On("IsBlockedByToken", defaultToken, calculateTime).Return(false, nil)
	repository.On("FindTokenBlockDuration", defaultToken).Return(tokenTimeDuration, nil)

	repository.On("FindLimitByToken", defaultToken).Return(defaultTokenLimit, nil)
	repository.On("FindTriesByTokenInLastSecond", defaultToken).Return(defaultTokenLimit, nil)
	repository.On("BlockToken", defaultToken).Return(nil)
	repository.On("FindTokenBlockDuration", defaultToken).Return(tokenTimeDuration, nil)

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
	calculateTime := calculateBlockTimeWindow(tokenTimeDuration)
	rateLimiter, repository := startRateLimite(calculateTime)

	repository.On("SaveTry", defaultIp, "").Return(initialTryCount, nil)
	repository.On("TokenExists", "").Return(true, nil)
	repository.On("IsBlockedByIp", defaultIp, calculateTime).Return(false, nil)
	repository.On("IsBlockedByToken", "", calculateTime).Return(false, nil)

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
	repository := NewRateLimiterRepositoryMock(time.Now())

	repository.On("TokenExists", defaultToken).Return(true, nil)
	repository.On("FindTokenBlockDuration", defaultToken).Return(defaultTimeDuration, nil)

	rateLimiter := NewRateLimiter(repository, defaultTokenLimit, defaultTimeDuration)

	assert.Nil(t, rateLimiter.checkTokenExists(defaultToken), ExpectedNillMessage)
}

func TestCheckTokenNotFound(t *testing.T) {
	repository := NewRateLimiterRepositoryMock(time.Now())

	repository.On("TokenExists", defaultToken).Return(false, nil)

	rateLimiter := NewRateLimiter(repository, defaultTokenLimit, defaultTimeDuration)

	assert.Error(t, rateLimiter.checkTokenExists(defaultToken), ExpectedErrorMessage)
}

func TestCheckTokenError(t *testing.T) {
	repository := NewRateLimiterRepositoryMock(time.Now())

	repository.On("TokenExists", defaultToken).Return(false, errors.New(DefaultErrorMessage))

	rateLimiter := NewRateLimiter(repository, defaultTokenLimit, defaultTimeDuration)

	assert.Error(t, rateLimiter.checkTokenExists(defaultToken), ExpectedErrorMessage)
}

func TestEmptyCheckToken(t *testing.T) {
	assert.Nil(t, (&RateLimiter{}).checkTokenExists(""))
}

func TestSaveTry(t *testing.T) {
	rateLimiter, repository := startRateLimite(time.Now())

	repository.On("SaveTry", defaultIp, defaultToken).Return(initialTryCount, nil)

	err := rateLimiter.saveTry(defaultIp, defaultToken)
	assert.Nil(t, err, ExpectedNillMessage, err)
}

func TestCheckTokenIsBlocked(t *testing.T) {
	calculateTime := calculateBlockTimeWindow(tokenTimeDuration)
	rateLimiter, repository := startRateLimite(calculateTime)

	repository.On("IsBlockedByToken", defaultToken, calculateTime).Return(false, nil)

	assert.Nil(t, rateLimiter.checkIsTokenBlocked(defaultToken, calculateTime), ExpectedNillMessage)
}

func TestDefineBlockTimeWindowWithEmptyToken(t *testing.T) {
	rateLimiter, _ := startRateLimite(time.Now())

	expectedTime := calculateBlockTimeWindow(defaultTimeDuration).Format(time.RFC3339)
	calculatedTime := rateLimiter.defineBlockTimeWindow("").Format(time.RFC3339)

	assert.Equal(t, expectedTime, calculatedTime)
}

func TestDefineBlockTimeWindowRepositoryError(t *testing.T) {
	rateLimiter, repository := startRateLimite(time.Now())

	repository.On("FindTokenBlockDuration", defaultToken).Return(defaultTimeDuration, errors.New(DefaultErrorMessage))

	expectedTime := calculateBlockTimeWindow(defaultTimeDuration).Format(time.RFC3339)
	calculatedTime := rateLimiter.defineBlockTimeWindow(defaultToken).Format(time.RFC3339)

	assert.Equal(t, expectedTime, calculatedTime)
}

func TestDefineBlockTimeWindowDurationIsZero(t *testing.T) {
	rateLimiter, repository := startRateLimite(time.Now())

	repository.On("FindTokenBlockDuration", defaultToken).Return(0, nil)

	expectedTime := calculateBlockTimeWindow(defaultTimeDuration).Format(time.RFC3339)
	calculatedTime := rateLimiter.defineBlockTimeWindow(defaultToken).Format(time.RFC3339)

	assert.Equal(t, expectedTime, calculatedTime)
}

func TestDefineBlockTimeWindowDefaultBlockDuration(t *testing.T) {
	rateLimiter, repository := startRateLimite(time.Now())

	repository.On("FindTokenBlockDuration", defaultToken).Return(2, nil)

	expectedTime := calculateBlockTimeWindow(2).Format(time.RFC3339)
	calculatedTime := rateLimiter.defineBlockTimeWindow(defaultToken).Format(time.RFC3339)

	assert.Equal(t, expectedTime, calculatedTime)
}

func TestCalculateBlockTimeWindow(t *testing.T) {
	expectedTime := time.Now().Add(-1 * time.Second).Format(time.RFC3339)
	calculateTime := calculateBlockTimeWindow(1).Format(time.RFC3339)

	assert.Equal(t, expectedTime, calculateTime)
}

func TestCheckEmptyTokenIsBlocked(t *testing.T) {
	assert.Nil(t, (&RateLimiter{}).checkIsTokenBlocked("", time.Now()), ExpectedNillMessage)
}

func TestCheckTokenIsBlockedError(t *testing.T) {
	calculateTime := calculateBlockTimeWindow(tokenTimeDuration)
	rateLimiter, repository := startRateLimite(calculateTime)

	repository.On("IsBlockedByToken", defaultToken, calculateTime).Return(false, errors.New(DefaultErrorMessage))
	repository.On("BlockToken", defaultToken).Return(nil)

	assert.Error(t, rateLimiter.checkIsTokenBlocked(defaultToken, calculateTime), ExpectedErrorMessage)
}

func TestCheckTokenIsBlockedWhenBlocked(t *testing.T) {
	calculateTime := calculateBlockTimeWindow(tokenTimeDuration)
	rateLimiter, repository := startRateLimite(calculateTime)

	repository.On("IsBlockedByToken", defaultToken, calculateTime).Return(true, nil)

	assert.Error(t, rateLimiter.checkIsTokenBlocked(defaultToken, calculateTime), ExpectedErrorMessage)
}

func TestCheckIpIsBlocked(t *testing.T) {
	calculateTime := calculateBlockTimeWindow(tokenTimeDuration)
	rateLimiter, repository := startRateLimite(calculateTime)

	repository.On("IsBlockedByIp", defaultToken, calculateTime).Return(false, nil)

	assert.Nil(t, rateLimiter.checkIsIpBlocked(defaultToken, calculateTime), ExpectedNillMessage)
}

func TestCheckEmptyIpIsBlocked(t *testing.T) {
	assert.Error(t, (&RateLimiter{}).checkIsIpBlocked("", time.Now()), ExpectedErrorMessage)
}

func TestCheckIpIsBlockedError(t *testing.T) {
	calculateTime := calculateBlockTimeWindow(tokenTimeDuration)
	rateLimiter, repository := startRateLimite(calculateTime)

	repository.On("IsBlockedByIp", defaultToken, calculateTime).Return(false, errors.New(DefaultErrorMessage))

	assert.Error(t, rateLimiter.checkIsIpBlocked(defaultToken, calculateTime), ExpectedErrorMessage)
}

func TestCheckIpIsBlockedWhenBlocked(t *testing.T) {
	calculateTime := calculateBlockTimeWindow(tokenTimeDuration)
	rateLimiter, repository := startRateLimite(calculateTime)

	repository.On("IsBlockedByIp", defaultToken, calculateTime).Return(true, nil)

	assert.Error(t, rateLimiter.checkIsIpBlocked(defaultToken, calculateTime), ExpectedErrorMessage)
}

func TestBlockedTryByToken(t *testing.T) {
	rateLimiter, repository := startRateLimite(time.Now())

	repository.On("FindLimitByToken", defaultToken).Return(defaultTokenLimit, nil)
	repository.On("FindTriesByTokenInLastSecond", defaultToken).Return(defaultTokenLimit, nil)
	repository.On("BlockToken", defaultToken).Return(nil)

	assert.Error(t, rateLimiter.blockedTry(defaultIp, defaultToken), ExpectedErrorMessage)
}

func TestBlockedTryByIp(t *testing.T) {
	rateLimiter, repository := startRateLimite(time.Now())

	repository.On("FindLimitByIp", defaultIp).Return(defaultLimit, nil)
	repository.On("FindTriesByIpInLastSecond", defaultIp).Return(defaultLimit, nil)
	repository.On("BlockIp", defaultIp).Return(nil)

	assert.Error(t, rateLimiter.blockedTry(defaultIp, ""), ExpectedErrorMessage)
}

func TestDoesntBlockTryWithToken(t *testing.T) {
	rateLimiter, repository := startRateLimite(time.Now())

	repository.On("FindLimitByToken", defaultToken).Return(defaultTokenLimit, nil)
	repository.On("FindTriesByTokenInLastSecond", defaultToken).Return(initialTryCount, nil)
	repository.On("BlockToken", defaultToken).Return(nil)

	repository.On("FindLimitByIp", defaultIp).Return(defaultLimit, nil)
	repository.On("FindTriesByIpInLastSecond", defaultIp).Return(initialTryCount, nil)
	repository.On("BlockIp", defaultIp).Return(nil)

	assert.Nil(t, rateLimiter.blockedTry(defaultIp, defaultToken), ExpectedNillMessage)
}

func TestDoesntBlockTryWithEmptyToken(t *testing.T) {
	rateLimiter, repository := startRateLimite(time.Now())

	repository.On("FindLimitByIp", defaultIp).Return(defaultLimit, nil)
	repository.On("FindTriesByIpInLastSecond", defaultIp).Return(initialTryCount, nil)
	repository.On("BlockIp", defaultIp).Return(nil)

	assert.Nil(t, rateLimiter.blockedTry(defaultIp, ""), ExpectedNillMessage)
}

func TestDefineDefaultLimit(t *testing.T) {
	rateLimiter, repository := startRateLimite(time.Now())

	repository.On("FindLimitByToken", defaultToken).Return(defaultTokenLimit, nil)

	assert.Equal(t, defaultTokenLimit, rateLimiter.defineTryLimit(defaultToken))
}

func TestDefineTryLimitWhenEmptyToken(t *testing.T) {
	rateLimiter, _ := startRateLimite(time.Now())

	assert.Equal(t, defaultLimit, rateLimiter.defineTryLimit(""))
}

func TestDefineTryLimitError(t *testing.T) {
	rateLimiter, repository := startRateLimite(time.Now())

	repository.On("FindLimitByToken", defaultToken).Return(0, errors.New(DefaultErrorMessage))

	assert.Equal(t, defaultLimit, rateLimiter.defineTryLimit(defaultToken))
}

func TestDefineTryLimitNoLimitFound(t *testing.T) {
	rateLimiter, repository := startRateLimite(time.Now())

	repository.On("FindLimitByToken", defaultToken).Return(0, nil)

	assert.Equal(t, defaultLimit, rateLimiter.defineTryLimit(defaultToken))
}

func TestBlockedTokenWhenTokenIsEmpty(t *testing.T) {
	rateLimiter, _ := startRateLimite(time.Now())

	assert.Nil(t, rateLimiter.blockedToken("", 0), ExpectedNillMessage)
}

func TestBlockedTokenWhenFindTryError(t *testing.T) {
	rateLimiter, repository := startRateLimite(time.Now())

	repository.On("FindTriesByTokenInLastSecond", defaultToken).Return(0, errors.New(DefaultErrorMessage))

	assert.Error(t, rateLimiter.blockedToken(defaultToken, 0), ExpectedErrorMessage)
}

func TestBlockedTokenWhenTryLimitExceeded(t *testing.T) {
	rateLimiter, repository := startRateLimite(time.Now())

	repository.On("FindTriesByTokenInLastSecond", defaultToken).Return(defaultTokenLimit, nil)
	repository.On("BlockToken", defaultToken).Return(nil)

	assert.Error(t, rateLimiter.blockedToken(defaultToken, defaultTokenLimit), rateLimitExceeded)
}

func TestBlockedTokenWhenTryLimitExceededBockedTokenError(t *testing.T) {
	rateLimiter, repository := startRateLimite(time.Now())

	repository.On("FindTriesByTokenInLastSecond", defaultToken).Return(defaultTokenLimit, nil)
	repository.On("BlockToken", defaultToken).Return(errors.New(DefaultErrorMessage))

	assert.Error(t, rateLimiter.blockedToken(defaultToken, defaultTokenLimit), ExpectedErrorMessage)
}

func TestBlockedTokenWhenTryLimitNotExceeded(t *testing.T) {
	rateLimiter, repository := startRateLimite(time.Now())

	repository.On("FindTriesByTokenInLastSecond", defaultToken).Return(initialTryCount, nil)

	assert.Nil(t, rateLimiter.blockedToken(defaultToken, defaultTokenLimit), ExpectedNillMessage)
}

func TestBlockedIpWhenIpIsEmpty(t *testing.T) {
	rateLimiter, _ := startRateLimite(time.Now())

	assert.Error(t, rateLimiter.blockedIp("", 0), ipNotFound)
}

func TestBlockedIpWhenFindTryError(t *testing.T) {
	rateLimiter, repository := startRateLimite(time.Now())

	repository.On("FindTriesByIpInLastSecond", defaultIp).Return(0, errors.New(DefaultErrorMessage))

	assert.Error(t, rateLimiter.blockedIp(defaultIp, 0), ExpectedErrorMessage)
}

func TestBlockedIpWhenTryLimitExceeded(t *testing.T) {
	rateLimiter, repository := startRateLimite(time.Now())

	repository.On("FindTriesByIpInLastSecond", defaultIp).Return(defaultLimit, nil)
	repository.On("BlockIp", defaultIp).Return(nil)

	assert.Error(t, rateLimiter.blockedIp(defaultIp, defaultLimit), rateLimitExceeded)
}

func TestBlockedIpWhenTryLimitExceededBockedIpError(t *testing.T) {
	rateLimiter, repository := startRateLimite(time.Now())

	repository.On("FindTriesByIpInLastSecond", defaultIp).Return(defaultLimit, nil)
	repository.On("BlockIp", defaultIp).Return(errors.New(DefaultErrorMessage))

	assert.Error(t, rateLimiter.blockedIp(defaultIp, defaultLimit), ExpectedErrorMessage)
}

func TestBlockedIpWhenTryLimitNotExceeded(t *testing.T) {
	rateLimiter, repository := startRateLimite(time.Now())

	repository.On("FindTriesByIpInLastSecond", defaultIp).Return(initialTryCount, nil)

	assert.Nil(t, rateLimiter.blockedIp(defaultIp, defaultLimit), ExpectedNillMessage)
}
