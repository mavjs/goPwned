// Package gopwned implements the REST api of haveibeenpwned.com for easy
// querying. More specifically package gopwned implements the version 3 (V3) of the API.
package gopwned

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

type (
	// Client represents a client interfact to the haveibeenpwned.com API.
	Client struct {
		client    *http.Client
		Token     string
		UserAgent string
		BaseURL   *url.URL
		PwnPwdURL *url.URL
	}

	// Breach holds all breach information returned from the API.
	Breach struct {
		Name         string       `json:"Name,omitempty"`
		Title        string       `json:"Title,omitempty"`
		Domain       string       `json:"Domain,omitempty"`
		BreachDate   string       `json:"BreachDate,omitempty"`
		AddedDate    string       `json:"AddedDate,omitempty"`
		ModifiedDate string       `json:"ModifiedDate,omitempty"`
		PwnCount     int          `json:"PwnCount,omitempty"`
		Description  string       `json:"Description,omitempty"`
		DataClasses  *DataClasses `json:"DataClasses,omitempty"`
		IsVerified   bool         `json:"IsVerified,omitempty"`
		IsFabricated bool         `json:"IsFabricated,omitempty"`
		IsSensitive  bool         `json:"IsSensitive,omitempty"`
		IsRetired    bool         `json:"IsRetired,omitempty"`
		IsSpamList   bool         `json:"IsSpamList,omitempty"`
		LogoPath     string       `json:"LogoPath,omitempty"`
	}

	// Paste holds all paste information returned from the API.
	Paste struct {
		Source     string `json:"Source,omitempty"`
		ID         string `json:"Id,omitempty"`
		Title      string `json:"Title,omitempty"`
		Date       string `json:"Date,omitempty"`
		EmailCount int    `json:"EmailCount,omitempty"`
	}

	// DataClasses holds all data classes exposed from breaches returned
	// from the API.
	DataClasses []string
)

const (
	// version of goPwned, follows Semantic Versioning 2.0.0 (https://semver.org/)
	version = "0.0.2"

	// userAgent of goPwned
	userAgent = "gopwned-api-client-" + version

	// endpoint - the endpoint URL of the haveibeenpwned.com (HIBP) API.
	// Majority of the functions depend on this URL for information.
	endpoint = "https://haveibeenpwned.com/api/v3/"

	// pwnPwdEndpoint - the endpoint URL of the pwnedpasswords API.
	// This is the only endpoint used by `PwnedPasswords` function.
	pwnPwdEndpoint = "https://api.pwnedpasswords.com/range/"
)

var (
	// respCodes - a list of response codes and their expected values as
	// defined by HIBP API: https://haveibeenpwned.com/API/v3#ResponseCodes
	respCodes = map[int]string{
		200: "Ok — everything worked and there's a string array of pwned sites for the account",
		400: "Bad request — the account does not comply with an acceptable format (i.e. it's an empty string)",
		401: "Unauthorised — the API key provided was not valid",
		403: "Forbidden — no user agent has been specified in the request",
		404: "Not found — the account could not be found and has therefore not been pwned",
		429: "Too many requests — the rate limit has been exceeded",
		503: "Service unavailable — usually returned by Cloudflare if the underlying service is not available",
	}
)

// NewClient creates a new haveibeenpwned.com API client. It expects 2 arguments
// 1) a `http.Client`
// 2) an API key
//
// Currently, the 1st argument will default to `http.DefaultClient` if no
// arguments are given. The 2nd argument will default to an empty string, which
// means the client will not be able to call certain endpoints as per the API
// version changes in V3. For more information: https://haveibeenpwned.com/API/v3
func NewClient(httpClient *http.Client, token string) *Client {
	if httpClient == nil {
		httpClient = &http.Client{}
	}

	baseURL, _ := url.Parse(endpoint)
	pwnpwdURL, _ := url.Parse(pwnPwdEndpoint)

	return &Client{client: httpClient, Token: token, UserAgent: userAgent, BaseURL: baseURL, PwnPwdURL: pwnpwdURL}
}

func checkAPI(path string) bool {
	switch {
	default:
		return false
	case strings.Contains(path, "/pasteaccount/") || strings.Contains(path, "/breachedaccount/"):
		return true
	}
}
func (c *Client) newRequest(resource string, opts url.Values) (*http.Response, error) {
	target, err := c.BaseURL.Parse(resource)
	if err != nil {
		return nil, err
	}

	if opts != nil {
		target.RawQuery = opts.Encode()
	}

	req, err := http.NewRequest("GET", target.String(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", c.UserAgent)
	if checkAPI(target.String()) {
		if c.Token != "" {
			req.Header.Set("hibp-api-key", c.Token)
		} else {
			return nil, errors.New("the function you're trying to request requires an API key")
		}
	}
	req.Close = true

	// Note: An error is returned if caused by client policy (such as CheckRedirect), or failure to speak HTTP (such as a network connectivity problem). A non-2xx status code doesn't cause an error.
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, errors.New(respCodes[resp.StatusCode])
	}

	return resp, nil
}

func (c *Client) newPwdRequest(resource string, opts url.Values) (*http.Response, error) {
	target, err := c.PwnPwdURL.Parse(resource)
	if err != nil {
		return nil, err
	}

	if opts != nil {
		target.RawQuery = opts.Encode()
	}
	req, err := http.NewRequest("GET", target.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	if checkAPI(target.String()) {
		if c.Token != "" {
			req.Header.Set("hibp-api-key", c.UserAgent)
		} else {
			return nil, errors.New("the function you're trying to request requires an API key")
		}
	}
	req.Close = true

	// Note: An error is returned if caused by client policy (such as CheckRedirect), or failure to speak HTTP (such as a network connectivity problem). A non-2xx status code doesn't cause an error.
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, errors.New(respCodes[resp.StatusCode])
	}

	return resp, nil
}

func (c *Client) getBreaches(resource string, opts url.Values) ([]*Breach, error) {
	resp, err := c.newRequest(resource, opts)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var breaches []*Breach
	err = json.NewDecoder(resp.Body).Decode(&breaches)
	return breaches, err
}

// GetAllBreaches - returns a list of all breaches of a particular account has
// been involved in. This function checks if an HIBP API key is provided, if not
// it will throw an error.
// The function accepts 4 arguments, with 1 of them being required. They are:
//     - account - The account is not case sensitive and is URL encoded before sending to the endpoint. (required)
//     - domain - Filters the result set to only breaches against the domain specified. (e.g. adobe.com)
//     - untruncate - Instructs the API to return the full breach data instead of, by default, only the name of the breach.
//     - unverified - Instructs the API not to include unverified breaches instead of, by default, returning both verified and unverified.
func (c *Client) GetAllBreaches(account, domain string, truncate, unverified bool) ([]*Breach, error) {

	resource := fmt.Sprintf("breachedaccount/%s", url.QueryEscape(account))

	opts := url.Values{}
	if domain != "" {
		opts.Set("domain", domain)
	}

	if !truncate {
		opts.Set("truncateResponse", "false")
	}

	if unverified {
		opts.Set("includeUnverified", "true")
	}

	return c.getBreaches(resource, opts)
}

// GetAllBreachedSites - returns a list of all details of each breach. A breach:
// an instance of a system having been compromised and data disclosed.
// This function accepts an option argument which can be used to filter on a
// specific breached domain. (e.g. adobe.com)
func (c *Client) GetAllBreachedSites(domain string) ([]*Breach, error) {
	resource := "breaches"

	opts := url.Values{}
	if domain != "" {
		opts.Set("domain", domain)
	}

	return c.getBreaches(resource, opts)
}

// GetBreachedSite - returns all details of a single breach by its breach "name".
// This breach "name" is a stable value in the haveibeenpwned.com data-sets.
// An example of a breach "name" would be "Adobe" instead of "adobe.com".
func (c *Client) GetBreachedSite(site string) ([]*Breach, error) {
	resource := fmt.Sprintf("breach/%s", site)
	return c.getBreaches(resource, nil)
}

// GetDataClasses - returns an alphabetically ordered list of data classes exposed
// during a breach. A "data class" is an attribute of a record compromised in a
// breach. E.g. "Email addresses" and "Passwords"
func (c *Client) GetDataClasses() (*DataClasses, error) {
	resource := "dataclasses"

	resp, err := c.newRequest(resource, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var dataclasses *DataClasses
	err = json.NewDecoder(resp.Body).Decode(&dataclasses)
	return dataclasses, err
}

// GetAllPastes - returns a list of pastes based on the email provided.
// This function checks if an HIBP API key is provided, if not it will throw an
// error.
//
func (c *Client) GetAllPastes(email string) ([]*Paste, error) {

	resource := fmt.Sprintf("pasteaccount/%s", email)

	resp, err := c.newRequest(resource, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var pastes []*Paste
	err = json.NewDecoder(resp.Body).Decode(&pastes)
	return pastes, err
}

// PwnedPasswords - returns a list of suffixes that has a similar prefix hash,
// i.e., the first 5 characters of SHA-1 hash of the password and the count of
// how many times that suffix has been seen in the data set.
// This function requires exactly 1 argument which is the 1st 5 characters of
// the hash of the password as a string.
func (c *Client) PwnedPasswords(chars string) ([]byte, error) {
	resp, err := c.newPwdRequest(chars, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return respBody, nil
}
