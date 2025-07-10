// Package spotify provides utilities for interfacing
// with Spotify's Web API.
package spotify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

const (
	// DateLayout can be used with time.Parse to create time.Time values
	// from Spotify date strings.  For example, PrivateUser.Birthdate
	// uses this format.
	DateLayout = "2006-01-02"
	// TimestampLayout can be used with time.Parse to create time.Time
	// values from SpotifyTimestamp strings.  It is an ISO 8601 UTC timestamp
	// with a zero offset.  For example, PlaylistTrack's AddedAt field uses
	// this format.
	TimestampLayout = "2006-01-02T15:04:05Z"

	// defaultRetryDurationS helps us fix an apparent server bug whereby we will
	// be told to retry but not be given a wait-interval.
	defaultRetryDuration = time.Second * 5
)

// TokenRefresher interface for handling token refresh
type TokenRefresher interface {
	RefreshToken(ctx context.Context, token *oauth2.Token) (*oauth2.Token, error)
	Client(ctx context.Context, token *oauth2.Token) *http.Client
}

// TokenUpdateCallback is a function type for token update callbacks
type TokenUpdateCallback func(oldToken, newToken *oauth2.Token)

// Client is a client for working with the Spotify Web API.
// It is best to create this using spotify.New()
type Client struct {
	http    *http.Client
	baseURL string

	autoRetry      bool
	acceptLanguage string

	// Token refresh fields
	authenticator       TokenRefresher
	token               *oauth2.Token
	tokenMutex          sync.RWMutex
	tokenUpdateCallback TokenUpdateCallback
}

type ClientOption func(client *Client)

// WithRetry configures the Spotify API client to automatically retry requests that fail due to rate limiting.
func WithRetry(shouldRetry bool) ClientOption {
	return func(client *Client) {
		client.autoRetry = shouldRetry
	}
}

// WithBaseURL provides an alternative base url to use for requests to the Spotify API. This can be used to connect to a
// staging or other alternative environment.
func WithBaseURL(url string) ClientOption {
	return func(client *Client) {
		client.baseURL = url
	}
}

// WithAcceptLanguage configures the client to provide the accept language header on all requests.
func WithAcceptLanguage(lang string) ClientOption {
	return func(client *Client) {
		client.acceptLanguage = lang
	}
}

// WithTokenRefresher configures the client to automatically refresh tokens when encountering 401 responses.
func WithTokenRefresher(auth TokenRefresher, token *oauth2.Token) ClientOption {
	return func(client *Client) {
		client.authenticator = auth
		client.token = token
	}
}

// WithTokenUpdateCallback configures a callback function that will be called whenever the token is updated.
func WithTokenUpdateCallback(callback TokenUpdateCallback) ClientOption {
	return func(client *Client) {
		client.tokenUpdateCallback = callback
	}
}

// New returns a client for working with the Spotify Web API.
// The provided httpClient must provide Authentication with the requests.
// The auth package may be used to generate a suitable client.
func New(httpClient *http.Client, opts ...ClientOption) *Client {
	c := &Client{
		http:    httpClient,
		baseURL: "https://api.spotify.com/v1/",
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// NewWithTokenRefresh creates a new client with automatic token refresh capability.
// This is a convenience function for creating a client that will automatically refresh
// tokens when encountering 401 responses.
func NewWithTokenRefresh(auth TokenRefresher, token *oauth2.Token, opts ...ClientOption) *Client {
	// Create the initial HTTP client with the token
	httpClient := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(token))

	// Create the client with token refresh capability
	clientOpts := append([]ClientOption{
		WithRetry(true),
		WithTokenRefresher(auth, token),
	}, opts...)

	return New(httpClient, clientOpts...)
}

// NewWithTokenRefreshCallback creates a new client with automatic token refresh capability and a callback.
// This is a convenience function for creating a client that will automatically refresh
// tokens when encountering 401 responses and call the provided callback when tokens are updated.
func NewWithTokenRefreshCallback(auth TokenRefresher, token *oauth2.Token, callback TokenUpdateCallback, opts ...ClientOption) *Client {
	// Create the initial HTTP client with the token
	httpClient := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(token))

	// Create the client with token refresh capability and callback
	clientOpts := append([]ClientOption{
		WithRetry(true),
		WithTokenRefresher(auth, token),
		WithTokenUpdateCallback(callback),
	}, opts...)

	return New(httpClient, clientOpts...)
}

// URI identifies an artist, album, track, or category.  For example,
// spotify:track:6rqhFgbbKwnb9MLmUQDhG6
type URI string

// ID is a base-62 identifier for an artist, track, album, etc.
// It can be found at the end of a spotify.URI.
type ID string

func (id *ID) String() string {
	return string(*id)
}

// Numeric is a convenience type for handling numbers sent as either integers or floats.
type Numeric int

// UnmarshalJSON unmarshals a JSON number (float or int) into the Numeric type.
func (n *Numeric) UnmarshalJSON(data []byte) error {
	var f float64
	if err := json.Unmarshal(data, &f); err != nil {
		return err
	}
	*n = Numeric(int(f))
	return nil
}

// Followers contains information about the number of people following a
// particular artist or playlist.
type Followers struct {
	// The total number of followers.
	Count Numeric `json:"total"`
	// A link to the Web API endpoint providing full details of the followers,
	// or the empty string if this data is not available.
	Endpoint string `json:"href"`
}

// Image identifies an image associated with an item.
type Image struct {
	// The image height, in pixels.
	Height Numeric `json:"height"`
	// The image width, in pixels.
	Width Numeric `json:"width"`
	// The source URL of the image.
	URL string `json:"url"`
}

// Download downloads the image and writes its data to the specified io.Writer.
func (i Image) Download(dst io.Writer) error {
	resp, err := http.Get(i.URL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// TODO: get Content-Type from header?
	if resp.StatusCode != http.StatusOK {
		return errors.New("Couldn't download image - HTTP" + strconv.Itoa(resp.StatusCode))
	}
	_, err = io.Copy(dst, resp.Body)
	return err
}

// Error represents an error returned by the Spotify Web API.
type Error struct {
	// A short description of the error.
	Message string `json:"message"`
	// The HTTP status code.
	Status int `json:"status"`
	// RetryAfter contains the time before which client should not retry a
	// rate-limited request, calculated from the Retry-After header, when present.
	RetryAfter time.Time `json:"-"`
}

func (e Error) Error() string {
	return fmt.Sprintf("spotify: %s [%d]", e.Message, e.Status)
}

// HTTPStatus returns the HTTP status code returned by the server when the error
// occurred.
func (e Error) HTTPStatus() int {
	return e.Status
}

// decodeError decodes an Error from an io.Reader.
func decodeError(resp *http.Response) error {
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if ctHeader := resp.Header.Get("Content-Type"); ctHeader == "" {
		msg := string(responseBody)
		if len(msg) == 0 {
			msg = http.StatusText(resp.StatusCode)
		}

		return Error{
			Message: msg,
			Status:  resp.StatusCode,
		}
	}

	if len(responseBody) == 0 {
		return Error{
			Message: "server response without body",
			Status:  resp.StatusCode,
		}
	}

	buf := bytes.NewBuffer(responseBody)

	var e struct {
		E Error `json:"error"`
	}
	err = json.NewDecoder(buf).Decode(&e)
	if err != nil {
		return Error{
			Message: fmt.Sprintf("failed to decode error response %q", responseBody),
			Status:  resp.StatusCode,
		}
	}

	e.E.Status = resp.StatusCode
	if e.E.Message == "" {
		// Some errors will result in there being a useful status-code but an
		// empty message. An example of this is when we send some of the
		// arguments directly in the HTTP query and the URL ends-up being too
		// long.

		e.E.Message = "server response without error description"
	}
	if retryAfter, _ := strconv.Atoi(resp.Header.Get("Retry-After")); retryAfter != 0 {
		e.E.RetryAfter = time.Now().Add(time.Duration(retryAfter) * time.Second)
	}

	return e.E
}

// refreshTokenIfNeeded refreshes the token if a 401 response is received
func (c *Client) refreshTokenIfNeeded(ctx context.Context, statusCode int) error {
	if statusCode != http.StatusUnauthorized || c.authenticator == nil {
		return nil
	}

	c.tokenMutex.Lock()
	defer c.tokenMutex.Unlock()

	// Get the current token from the oauth2 transport
	currentToken, err := c.Token()
	if err != nil {
		return fmt.Errorf("failed to get current token: %w", err)
	}

	// If we have an authenticator, try to refresh the token
	newToken, err := c.authenticator.RefreshToken(ctx, currentToken)
	if err != nil {
		return fmt.Errorf("failed to refresh token: %w", err)
	}

	// Update the stored token
	c.token = newToken

	// Call the token update callback if set
	if c.tokenUpdateCallback != nil {
		c.tokenUpdateCallback(currentToken, newToken)
	}

	// Create a new HTTP client with the refreshed token
	// Use the authenticator's client method to ensure proper oauth2 setup
	c.http = c.authenticator.Client(ctx, newToken)

	return nil
}

// shouldRetry determines whether the status code indicates that the
// previous operation should be retried at a later time
func shouldRetry(status int) bool {
	return status == http.StatusAccepted || status == http.StatusTooManyRequests || status == http.StatusUnauthorized
}

// isFailure determines whether the code indicates failure
func isFailure(code int, validCodes []int) bool {
	for _, item := range validCodes {
		if item == code {
			return false
		}
	}
	return true
}

// `execute` executes a non-GET request. `needsStatus` describes other HTTP
// status codes that will be treated as success. Note that we allow all 200s
// even if there are additional success codes that represent success.
func (c *Client) execute(req *http.Request, result interface{}, needsStatus ...int) error {
	if c.acceptLanguage != "" {
		req.Header.Set("Accept-Language", c.acceptLanguage)
	}

	// Buffer the request body for potential retries
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return err
		}
		req.Body.Close()
	}

	maxRetries := 2 // Allow one retry after token refresh
	for retryCount := 0; retryCount < maxRetries; retryCount++ {
		// Recreate the request body for each attempt
		if bodyBytes != nil {
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}

		resp, err := c.http.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if c.autoRetry &&
			isFailure(resp.StatusCode, needsStatus) &&
			shouldRetry(resp.StatusCode) {

			// Handle 401 specifically for token refresh
			if resp.StatusCode == http.StatusUnauthorized {
				if err := c.refreshTokenIfNeeded(req.Context(), resp.StatusCode); err != nil {
					return fmt.Errorf("token refresh failed: %w", err)
				}
				// Continue to retry the request with the new token
				continue
			}

			// Handle other retryable errors (rate limiting, etc.)
			select {
			case <-req.Context().Done():
				// If the context is cancelled, return the original error
				return req.Context().Err()
			case <-time.After(retryDuration(resp)):
				continue
			}
		}

		if resp.StatusCode == http.StatusNoContent {
			return nil
		}
		if (resp.StatusCode >= 300 ||
			resp.StatusCode < 200) &&
			isFailure(resp.StatusCode, needsStatus) {
			return decodeError(resp)
		}

		if result != nil {
			if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
				return err
			}
		}
		break
	}
	return nil
}

func retryDuration(resp *http.Response) time.Duration {
	raw := resp.Header.Get("Retry-After")
	if raw == "" {
		return defaultRetryDuration
	}
	seconds, err := strconv.ParseInt(raw, 10, 32)
	if err != nil {
		return defaultRetryDuration
	}
	return time.Duration(seconds) * time.Second
}

func (c *Client) get(ctx context.Context, url string, result interface{}) error {
	maxRetries := 2 // Allow one retry after token refresh
	for retryCount := 0; retryCount < maxRetries; retryCount++ {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if c.acceptLanguage != "" {
			req.Header.Set("Accept-Language", c.acceptLanguage)
		}
		if err != nil {
			return err
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return err
		}

		defer resp.Body.Close()

		if c.autoRetry && (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusUnauthorized) {
			// Handle 401 specifically for token refresh
			if resp.StatusCode == http.StatusUnauthorized {
				if err := c.refreshTokenIfNeeded(ctx, resp.StatusCode); err != nil {
					return fmt.Errorf("token refresh failed: %w", err)
				}
				// Continue to retry the request with the new token
				continue
			}

			// Handle rate limiting
			if resp.StatusCode == http.StatusTooManyRequests {
				select {
				case <-ctx.Done():
					// If the context is cancelled, return the original error
					return ctx.Err()
				case <-time.After(retryDuration(resp)):
					continue
				}
			}
		}

		if resp.StatusCode == http.StatusNoContent {
			return nil
		}
		if resp.StatusCode != http.StatusOK {
			return decodeError(resp)
		}

		return json.NewDecoder(resp.Body).Decode(result)
	}
	return errors.New("max retries exceeded")
}

// NewReleases gets a list of new album releases featured in Spotify.
// Supported options: Country, Limit, Offset
func (c *Client) NewReleases(ctx context.Context, opts ...RequestOption) (albums *SimpleAlbumPage, err error) {
	spotifyURL := c.baseURL + "browse/new-releases"
	if params := processOptions(opts...).urlParams.Encode(); params != "" {
		spotifyURL += "?" + params
	}

	var objmap map[string]*json.RawMessage
	err = c.get(ctx, spotifyURL, &objmap)
	if err != nil {
		return nil, err
	}

	var result SimpleAlbumPage
	err = json.Unmarshal(*objmap["albums"], &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// Token gets the client's current token.
func (c *Client) Token() (*oauth2.Token, error) {
	transport, ok := c.http.Transport.(*oauth2.Transport)
	if !ok {
		return nil, errors.New("spotify: client not backed by oauth2 transport")
	}
	t, err := transport.Source.Token()
	if err != nil {
		return nil, err
	}
	return t, nil
}
