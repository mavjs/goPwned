// Package gopwned implements the REST api of haveibeenpwned.com for easy querying
package gopwned

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
)

// not used for now
// XXX check for possible API change
// type jsonResp struct {
// 	Title       string
// 	Name        string
// 	Domain      string
// 	BreachDate  string
// 	AddedDate   string
// 	PwnCount    int
// 	Description string
// 	DataClasses []string
// 	IsVerified  bool
// 	LogoType    string
// }

// type jsonPasteResp struct {
// 	Source     string
// 	ID         string
// 	Title      string
// 	Date       string
// 	EmailCount int
// }

const baseURL = "https://haveibeenpwned.com/api/v2/%s"

var (
	respcodes = map[int]string{
		400: "Bad request — the account does not comply with an acceptable format (i.e. it's an empty string)",
		403: "Forbidden — no user agent has been specified in the request",
		404: "Not found — the account could not be found and has therefore not been pwned",
		429: "Not found — the account could not be found and has therefore not been pwned",
	}

	client = &http.Client{}
)

func reqURL(target string) (string, error) {
	// request http api
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return "", err
	}

	// set haveibeenpwned content negotiation header
	req.Header.Add("Accept", "application/vnd.haveibeenpwned.v2+json")
	req.Header.Add("User-Agent", "gopwned (HIBP golang API client library) - https://github.com/mavjs/goPwned")
	// make the request
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	statuscode := respcodes[res.StatusCode]
	if statuscode != "" {
		return statuscode, nil
	}

	// Because Mav likes it
	var jsonres interface{}
	err = json.NewDecoder(res.Body).Decode(&jsonres)
	if err != nil {
		return "", err
	}

	// Pretty print for Mav
	b, err := json.MarshalIndent(jsonres, "", "  ")
	return string(b), err

	// For direct response
	// body, err := ioutil.ReadAll(res.Body)
	// return string(body), err
}

func fetch(endpoint string, param url.Values) (string, error) {
	target := fmt.Sprintf(baseURL, endpoint)
	if param != nil {
		target = fmt.Sprintf("%s?%s", target, param.Encode())
	}
	return reqURL(target)
}

// GetAllBreachesForAccount gets all the breaches associated with an account.
func GetAllBreachesForAccount(email, domain string) string {
	endpoint := fmt.Sprintf("breachedAccount/%s", email)

	var params url.Values
	if domain != "" {
		params = url.Values{}
		params.Set("domain", domain)
	}

	// XXX should return (string, error) but it'll break API, temporary fix
	// Should panic when this occurs
	result, err := fetch(endpoint, params)
	if err != nil {
		log.Fatal(err)
	}
	return result
}

// AllBreaches gets all breaches associated with a domain.
func AllBreaches(domain string) string {
	// url Endpoint for getting details about all breached sites
	endpoint := "breaches/"

	var params url.Values
	if domain != "" {
		params = url.Values{}
		params.Set("domain", domain)
	}

	result, err := fetch(endpoint, params)
	if err != nil {
		log.Fatal(err)
	}
	return result
}

// GetSingleBreachedSite gets breaches associated to a single site.
func GetSingleBreachedSite(name string) string {
	// url Endpoint for getting details for a single breached site
	endpoint := fmt.Sprintf("breach/%s", name)
	result, err := fetch(endpoint, nil)
	if err != nil {
		log.Fatal(err)
	}
	return result
}

// GetAllDataClasses gets all data classes defined by the service.
func GetAllDataClasses() string {
	// url Endpoint for getting breach data classes
	endpoint := "dataclasses/"
	result, err := fetch(endpoint, nil)
	if err != nil {
		log.Fatal(err)
	}
	return result
}

// GetAllPastesForAccount gets all pastebins associated with an account.
func GetAllPastesForAccount(email string) string {
	// url Endpoint for getting pastes for an account
	endpoint := fmt.Sprintf("pasteaccount/%s", email)
	result, err := fetch(endpoint, nil)
	if err != nil {
		log.Fatal(err)
	}
	return result
}
