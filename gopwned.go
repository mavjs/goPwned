// Package gopwned implements the REST api of haveibeenpwned.com for easy querying
package gopwned

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

const (
	libVersion     = "0.1"
	defaultBaseURL = "https://haveibeenpwned.com/api/v2/"
	userAgent      = "gopwned-api-client-" + libVersion
	mediaTypeV2    = "application/vnd.haveibeenpwned.v2+json"
)

type response struct {
	strResp    string
	statuscode string
}

func (r *response) Resp() string {
	if r.statuscode == "" {
		return r.strResp
	}

	return r.statuscode
}

// A Client manages communication with the HaveIBeenPwned API
type Client struct {
	client    *http.Client
	baseURL   *url.URL
	userAgent string
	respCodes map[int]string
}

type BreachModel struct {
	Name         string   `json:"Name,omitempty"`
	Title        string   `json:"Title,omitempty"`
	Domain       string   `json:"Domain,omitempty"`
	BreachDate   string   `json:"BreachDate,omitempty"`
	AddedDate    string   `json:"AddedDate,omitempty"`
	PwnCount     int      `json:"PwnCount,omitempty"`
	Description  string   `json:"Description,omitempty"`
	DataClasses  []string `json:"DataClasses,omitempty"`
	IsVerified   bool     `json:"IsVerified,omitempty"`
	IsFabricated bool     `json:"IsFabricated,omitempty"`
	IsSensitive  bool     `json:"IsSensitive,omitempty"`
	IsRetired    bool     `json:"IsRetired,omitempty"`
	IsSpamList   bool     `json:"IsSpamList,omitempty"`
	LogoType     string   `json:"LogoType,omitempty"`
}

type PasteModel struct {
	Source     string `json:"Source,omitempty"`
	ID         string `json:"Id,omitempty"`
	Title      string `json:"Title,omitempty"`
	Date       string `json:"Date,omitempty"`
	EmailCount int    `json:"EmailCount,omitempty"`
}

type DataClasses []string

// NewClient returns a new HaveIBeenPwned API client.
func NewClient(httpClient *http.Client) (*Client, error) {
	var respCodes = map[int]string{
		400: "Bad request — the account does not comply with an acceptable format (i.e. it's an empty string)",
		403: "Forbidden — no user agent has been specified in the request",
		404: "Not found — the account could not be found and has therefore not been pwned",
		429: "Too many requests — the rate limit has been exceeded",
	}

	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	baseURL, err := url.Parse(defaultBaseURL)
	if err != nil {
		return nil, err
	}

	client := &Client{client: httpClient, baseURL: baseURL, userAgent: userAgent, respCodes: respCodes}
	return client, nil
}

// NewRequest creates an API request.
func (c *Client) reqURL(endpoint, params string, opts url.Values) (*http.Request, error) {

	u, err := c.baseURL.Parse(endpoint + params)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", u.String(), bytes.NewBufferString(opts.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Add("Accept", mediaTypeV2)
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}

	return req, nil
}

func (c *Client) reqDo(req *http.Request) (*http.Response, error) {
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// GetAllBreachesForAccount gets all the breaches associated with an account.
func (c *Client) GetAllBreachesForAccount(email, domain, truncateResponse string) ([]*BreachModel, error) {

	var (
		// url Endpoint for getting all breached sites for an account
		endpoint = "breachedaccount/"
		opts     = url.Values{}
		jsonResp []*BreachModel
	)

	if domain != "" {
		opts.Set("domain", domain)
	}

	if truncateResponse != "" {
		opts.Set("truncateResponse", truncateResponse)
	}

	req, err := c.reqURL(endpoint, email, opts)
	if err != nil {
		return nil, err
	}

	resp, err := c.reqDo(req)
	if err != nil {
		return nil, err
	}

	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, err
	}
	return jsonResp, nil
}

// GetAllBreachedSites gets all the breached sites.
func (c *Client) GetAllBreachedSites(domain string) ([]*BreachModel, error) {
	var (
		endpoint = "breaches"
		opts     = url.Values{}
		jsonResp []*BreachModel
	)

	if domain != "" {
		opts.Set("domain", domain)
	}

	req, err := c.reqURL(endpoint, "", opts)
	if err != nil {
		return nil, err
	}

	resp, err := c.reqDo(req)
	if err != nil {
		return nil, err
	}

	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, err
	}
	return jsonResp, nil
}

// GetBreachedSite gets details about one breached site.
func (c *Client) GetBreachedSite(siteName string) ([]*BreachModel, error) {
	var (
		endpoint = "breach/"
		jsonResp []*BreachModel
	)

	if siteName == "" {
		return nil, fmt.Errorf("this method require a name of the breached site")
	}

	req, err := c.reqURL(endpoint, siteName, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.reqDo(req)
	if err != nil {
		return nil, err
	}

	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, err
	}

	return jsonResp, nil
}

// GetDataClasses get all data classes defined in the API.
func (c *Client) GetDataClasses() (*DataClasses, error) {
	var (
		endpoint = "dataclasses"
		jsonResp *DataClasses
	)

	req, err := c.reqURL(endpoint, "", nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.reqDo(req)
	if err != nil {
		return nil, err
	}

	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, err
	}

	return jsonResp, nil
}

// GetAllPastesForAccount get all paste services associated with an account.
func (c *Client) GetAllPastesForAccount(account string) ([]*PasteModel, error) {
	var (
		endpoint = "pasteaccount/"
		jsonResp []*PasteModel
	)

	req, err := c.reqURL(endpoint, account, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.reqDo(req)
	if err != nil {
		return nil, err
	}

	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, err
	}

	return jsonResp, nil
}
