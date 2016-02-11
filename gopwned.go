// Package gopwned implements the REST api of haveibeenpwned.com for easy querying
package gopwned

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

type jsonResp struct {
	Title       string
	Name        string
	Domain      string
	BreachDate  string
	AddedDate   string
	PwnCount    int
	Description string
	DataClasses []string
	IsVerified  bool
	LogoType    string
}

type jsonPasteResp struct {
	Source     string
	ID         string
	Title      string
	Date       string
	EmailCount int
}

const baseURL = "https://haveibeenpwned.com/api/v2/%s"

func reqURL(url string) ([]byte, string) {
	var respcodes = map[int]string{
		400: "Bad request — the account does not comply with an acceptable format (i.e. it's an empty string)",
		403: "Forbidden — no user agent has been specified in the request",
		404: "Not found — the account could not be found and has therefore not been pwned",
	}

	// create http client
	client := new(http.Client)

	// request http api
	req, err := http.NewRequest("Get", url, nil)
	if err != nil {
		log.Fatal(err)
	}

	// set haveibeenpwned content negotiation header
	req.Header.Add("Accept", "application/vnd.haveibeenpwned.v2+json")
	req.Header.Add("User-Agent", "gopwned (HIBP golang API client library) - https://github.com/mavjs/goPwned")
	// make the request
	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	// read body
	body, err := ioutil.ReadAll(res.Body)
	defer res.Body.Close()
	if err != nil {
		log.Fatal(err)
	}

	statuscode := respcodes[res.StatusCode]
	return body, statuscode

}

// GetAllBreachesForAccount gets all the breaches associated with an account.
func GetAllBreachesForAccount(email, domain string) string {

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
