// Package gopwned implements the REST api of haveibeenpwned.com for easy querying
package gopwned

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"
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

type breachModel struct {
	Name         string
	Title        string
	Domain       string
	BreachDate   string
	AddedDate    string
	PwnCount     int
	Description  string
	DataClasses  []string
	IsVerified   bool
	IsFabricated bool
	IsSensitive  bool
	IsRetired    bool
	IsSpamList   bool
	LogoType     string
}

type pasteModel struct {
	Source     string
	ID         string
	Title      string
	Date       time.Time
	EmailCount int
}

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
func (c *Client) reqURL(endpoint, params string, opts url.Values, jsonresp interface{}) (*response, error) {

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

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return nil, err
	}

	err = json.NewDecoder(resp.Body).Decode(&jsonresp)
	if err != nil {
		return nil, err
	}

	b, err := json.MarshalIndent(jsonresp, "", " ")
	if err != nil {
		return nil, err
	}
	result := &response{
		strResp:    string(b),
		statuscode: c.respCodes[resp.StatusCode],
	}

	return result, nil
}

// Do makes the HTTP Request and returns a HTTP Response.
//func (c *Client) Do(req *http.Request) (*http.Response, error) {
//}

// GetAllBreachesForAccount gets all the breaches associated with an account.
func (c *Client) GetAllBreachesForAccount(email, domain string) string {

	var (
		url string
		// url Endpoint for getting all breached sites for an account
		endpoint = "breachedAccount/"
	)

	var (
		jsonres    []jsonResp
		result     []byte
		statuscode string
	)

	if domain == "" {

		// build url for getting breaches for an account
		url = fmt.Sprintf(baseURL, endpoint+email)

	} else {

		// build url for getting breaches for an account on specific domain
		url = fmt.Sprintf(baseURL, endpoint+email+"?domain="+domain)
	}
	result, statuscode = reqURL(url)

	if statuscode != "" {
		return statuscode
	}

	err := json.Unmarshal(result, &jsonres)
	if err != nil {
		log.Fatal(err)
	}

	result, err = json.Marshal(jsonres)
	if err != nil {
		log.Fatal(err)
	}
	return fmt.Sprintf("%s", result)
}

// AllBreaches gets all breaches associated with a domain.
func AllBreaches(domain string) string {

	var (
		url string
		// url Endpoint for getting details about all breached sites
		endpoint = "breaches/"
	)

	var (
		jsonres    []jsonResp
		result     []byte
		statuscode string
	)

	if domain == "" {
		// build url for getting details about all breached sites
		url = fmt.Sprintf(baseURL, endpoint)
	} else {

		// build url for getting details about a single breached site
		url = fmt.Sprintf(baseURL, endpoint+"?domain="+domain)
	}

	result, statuscode = reqURL(url)

	if statuscode != "" {
		return fmt.Sprintf("%s", statuscode)
	}

	err := json.Unmarshal(result, &jsonres)
	if err != nil {
		log.Fatal(err)
	}

	result, err = json.Marshal(jsonres)
	if err != nil {
		log.Fatal(err)
	}
	return fmt.Sprintf("%s", result)
}

// GetSingleBreachedSite gets breaches associated to a single site.
func GetSingleBreachedSite(name string) string {

	// url Endpoint for getting details for a single breached site
	endpoint := "breach/"

	var (
		url        string
		jsonres    jsonResp
		result     []byte
		statuscode string
	)

	// build url for getting details for a single breached site
	url = fmt.Sprintf(baseURL, endpoint+name)

	result, statuscode = reqURL(url)

	if statuscode != "" {
		return fmt.Sprintf("%s", statuscode)
	}

	err := json.Unmarshal(result, &jsonres)
	if err != nil {
		log.Fatal(err)
	}

	result, err = json.Marshal(jsonres)
	if err != nil {
		log.Fatal(err)
	}
	return fmt.Sprintf("%s", result)
}

// GetAllDataClasses gets all data classes defined by the service.
func GetAllDataClasses() string {

	// url Endpoint for getting breach data classes
	endpoint := "dataclasses/"

	var (
		url        string
		jsonres    interface{}
		result     []byte
		statuscode string
	)

	// build url for getting breach data classes
	url = fmt.Sprintf(baseURL, endpoint)

	result, statuscode = reqURL(url)

	if statuscode != "" {
		return fmt.Sprintf("%s", statuscode)
	}

	err := json.Unmarshal(result, &jsonres)
	if err != nil {
		log.Fatal(err)
	}

	result, err = json.Marshal(jsonres)
	if err != nil {
		log.Fatal(err)
	}
	return fmt.Sprintf("%s", result)
}

// GetAllPastesForAccount gets all pastebins associated with an account.
func GetAllPastesForAccount(email string) string {

	// url Endpoint for getting pastes for an account
	endpoint := "pasteaccount/"

	var (
		url        string
		jsonres    []jsonPasteResp
		result     []byte
		statuscode string
	)

	// build url for getting pastes for an account
	url = fmt.Sprintf(baseURL, endpoint+email)

	result, statuscode = reqURL(url)

	if statuscode != "" {
		return fmt.Sprintf("%s", statuscode)
	}

	err := json.Unmarshal(result, &jsonres)
	if err != nil {
		log.Fatal(err)
	}

	result, err = json.Marshal(jsonres)
	if err != nil {
		log.Fatal(err)
	}
	return fmt.Sprintf("%s", result)
}
