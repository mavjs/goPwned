// Package gopwned implements the REST api of haveibeenpwned.com for easy querying
package gopwned

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

type (
	Client struct {
		client    *http.Client
		UserAgent string
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
	Version     = "0.1"
	UserAgent   = "gopwned-api-client-" + Version
	MediaTypeV2 = "application/vnd.haveibeenpwned.v2+json"
	Endpoint    = "https://haveibeenpwned.com/api/v2/"
)

var (
	respcodes = map[int]string{
		400: "Bad request — the account does not comply with an acceptable format (i.e. it's an empty string)",
		403: "Forbidden — no user agent has been specified in the request",
		404: "Not found — the account could not be found and has therefore not been pwned",
		429: "Too many requests — the rate limit has been exceeded",
	}

	defaultClient, _ = NewClient(nil)
	baseURL, _       = url.Parse(Endpoint)
)

func NewClient(client *http.Client) (*Client, error) {
	if client == nil {
		client = http.DefaultClient
	}
	return &Client{client: client, UserAgent: UserAgent}, nil
}

func (c *Client) do(resource string, opts url.Values) (*http.Response, error) {
	u, err := baseURL.Parse(resource)
	if err != nil {
		return nil, err
	}

	target := u.String()
	if opts != nil {
		target = fmt.Sprintf("%s?%s", target, opts.Encode())
	}

	req, err := http.NewRequest("GET", target, nil)
	req.Header.Set("Accept", MediaTypeV2)
	req.Header.Set("User-Agent", c.UserAgent)
	req.Close = true

	return c.client.Do(req)
}

func (c *Client) getBreaches(resource string, opts url.Values) ([]*Breach, error) {
	resp, err := c.do(resource, opts)
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

	resp, err := c.do(resource, nil)
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

	resp, err := c.do(resource, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var pastes []*Paste
	err = json.NewDecoder(resp.Body).Decode(&pastes)
	return pastes, err
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
