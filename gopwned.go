// Package gopwned implements the REST api of haveibeenpwned.com for easy querying
package gopwned

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

type (
	Client struct {
		client    *http.Client
		UserAgent string
		BaseURL   *url.URL
		PwnPwdURL *url.URL
	}

	Breach struct {
		Name         string       `json:"Name,omitempty"`
		Title        string       `json:"Title,omitempty"`
		Domain       string       `json:"Domain,omitempty"`
		BreachDate   string       `json:"BreachDate,omitempty"`
		AddedDate    string       `json:"AddedDate,omitempty"`
		PwnCount     int          `json:"PwnCount,omitempty"`
		Description  string       `json:"Description,omitempty"`
		DataClasses  *DataClasses `json:"DataClasses,omitempty"`
		IsVerified   bool         `json:"IsVerified,omitempty"`
		IsFabricated bool         `json:"IsFabricated,omitempty"`
		IsSensitive  bool         `json:"IsSensitive,omitempty"`
		IsRetired    bool         `json:"IsRetired,omitempty"`
		IsSpamList   bool         `json:"IsSpamList,omitempty"`
		LogoType     string       `json:"LogoType,omitempty"`
	}

	Paste struct {
		Source     string `json:"Source,omitempty"`
		ID         string `json:"Id,omitempty"`
		Title      string `json:"Title,omitempty"`
		Date       string `json:"Date,omitempty"`
		EmailCount int    `json:"EmailCount,omitempty"`
	}

	DataClasses []string
)

const (
	Version        = "0.1"
	UserAgent      = "gopwned-api-client-" + Version
	MediaTypeV2    = "application/vnd.haveibeenpwned.v2+json"
	Endpoint       = "https://haveibeenpwned.com/api/v2/"
	PwnPwdEndpoint = "https://api.pwnedpasswords.com/range/"
)

var (
	respcodes = map[int]string{
		400: "Bad request — the account does not comply with an acceptable format (i.e. it's an empty string)",
		403: "Forbidden — no user agent has been specified in the request",
		404: "Not found — the account could not be found and has therefore not been pwned",
		429: "Too many requests — the rate limit has been exceeded",
	}

	defaultClient = NewClient(nil)
	baseURL, _    = url.Parse(Endpoint)
	pwnpwdURL, _  = url.Parse(PwnPwdEndpoint)
)

func NewClient(client *http.Client) *Client {
	if client == nil {
		client = http.DefaultClient
	}
	return &Client{client: client, UserAgent: UserAgent, BaseURL: baseURL, PwnPwdURL: pwnpwdURL}
}

func (c *Client) newRequest(resource string, opts url.Values) (*http.Response, error) {
	u, err := c.BaseURL.Parse(resource)
	if err != nil {
		return nil, err
	}

	target := u.String()
	if opts != nil {
		target = fmt.Sprintf("%s?%s", target, opts.Encode())
	}

	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", MediaTypeV2)
	req.Header.Set("User-Agent", c.UserAgent)
	req.Close = true

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (c *Client) newPwdRequest(resource string, opts url.Values) (*http.Response, error) {
	target, err := c.PwnPwdURL.Parse(resource)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", target.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	req.Close = true

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
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

func (c *Client) GetAllBreachesForAccount(email, domain, truncateResponse string) ([]*Breach, error) {
	resource := fmt.Sprintf("breachedaccount/%s", email)

	opts := url.Values{}
	if domain != "" {
		opts.Set("domain", domain)
	}

	if truncateResponse != "" {
		opts.Set("truncateResponse", truncateResponse)
	}

	return c.getBreaches(resource, opts)
}

func (c *Client) GetAllBreachedSites(domain string) ([]*Breach, error) {
	resource := "breaches"

	opts := url.Values{}
	if domain != "" {
		opts.Set("domain", domain)
	}

	return c.getBreaches(resource, opts)
}

func (c *Client) GetBreachedSite(site string) ([]*Breach, error) {
	resource := fmt.Sprintf("breach/%s", site)
	return c.getBreaches(resource, nil)
}

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

func (c *Client) GetAllPastesForAccount(account string) ([]*Paste, error) {
	resource := fmt.Sprintf("pasteaccount/%s", account)

	resp, err := c.newRequest(resource, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var pastes []*Paste
	err = json.NewDecoder(resp.Body).Decode(&pastes)
	return pastes, err
}

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

func GetAllBreachesForAccount(email, domain, truncateResponse string) ([]*Breach, error) {
	return defaultClient.GetAllBreachesForAccount(email, domain, truncateResponse)
}

func GetAllBreachedSites(domain string) ([]*Breach, error) {
	return defaultClient.GetAllBreachedSites(domain)
}

func GetBreachedSite(site string) ([]*Breach, error) {
	return defaultClient.GetBreachedSite(site)
}

func GetDataClasses() (*DataClasses, error) {
	return defaultClient.GetDataClasses()
}

func GetAllPastesForAccount(account string) ([]*Paste, error) {
	return defaultClient.GetAllPastesForAccount(account)
}

func PwnedPasswords(chars string) ([]byte, error) {
	return defaultClient.PwnedPasswords(chars)
}
