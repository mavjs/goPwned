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
	Id         string
	Title      string
	Date       string
	EmailCount int
}

var BASEAPIURL = "https://haveibeenpwned.com/api/v2/"

func RestReq(url string) ([]byte, string) {
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
	req.Header.Add("User-Agent", "gopwned (HIBP golang API client library)")
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

func GetAllBreachesForAccount(email, domain string) string {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// URL Endpoint for getting all breached sites for an account
	URLENDPOINT := "breachedAccount/"

	var (
		jsonres    []jsonResp
		result     []byte
		statuscode string
	)

	if domain == "" {

		// build URL for getting breaches for an account
		var URL = BASEAPIURL + URLENDPOINT + email

		result, statuscode = RestReq(URL)

		if statuscode != "" {
			return fmt.Sprintf("%s", statuscode)
		}

		err := json.Unmarshal(result, &jsonres)
		if err != nil {
			log.Fatal(err)
		}
	} else {

		// build URL for getting breaches for an account on specific domain
		var URL = BASEAPIURL + URLENDPOINT + email + "?domain=" + domain

		result, statuscode = RestReq(URL)

		if statuscode != "" {
			return fmt.Sprintf("%s", statuscode)
		}

		err := json.Unmarshal(result, &jsonres)
		if err != nil {
			log.Fatal(err)
		}
	}
	return fmt.Sprintf("%+v", jsonres)
}

func AllBreaches(domain string) string {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// URL Endpoint for getting details about all breached sites
	URLENDPOINT := "breaches/"

	var (
		jsonres    []jsonResp
		result     []byte
		statuscode string
	)

	if domain == "" {

		// build URL for getting details about all breached sites
		var URL = BASEAPIURL + URLENDPOINT

		result, statuscode = RestReq(URL)

		if statuscode != "" {
			return fmt.Sprintf("%s", statuscode)
		}

		err := json.Unmarshal(result, &jsonres)
		if err != nil {
			log.Fatal(err)
		}
	} else {

		// build URL for getting details about a single breached site
		var URL = BASEAPIURL + URLENDPOINT + "?domain=" + domain

		result, statuscode = RestReq(URL)

		if statuscode != "" {
			return fmt.Sprintf("%s", statuscode)
		}

		err := json.Unmarshal(result, &jsonres)
		if err != nil {
			log.Fatal(err)
		}
	}
	return fmt.Sprintf("%+v", jsonres)
}

func GetSingleBreachedSite(name string) string {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// URL Endpoint for getting details for a single breached site
	URLENDPOINT := "breach/"

	var (
		jsonres    jsonResp
		result     []byte
		statuscode string
	)

	// build URL for getting details for a single breached site
	var URL = BASEAPIURL + URLENDPOINT + name

	result, statuscode = RestReq(URL)

	if statuscode != "" {
		return fmt.Sprintf("%s", statuscode)
	}

	err := json.Unmarshal(result, &jsonres)
	if err != nil {
		log.Fatal(err)
	}
	return fmt.Sprintf("%+v", jsonres)
}

func GetAllDataClasses() string {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// URL Endpoint for getting breach data classes
	URLENDPOINT := "dataclasses/"

	var (
		jsonres    interface{}
		result     []byte
		statuscode string
	)

	// build URL for getting breach data classes
	var URL = BASEAPIURL + URLENDPOINT

	result, statuscode = RestReq(URL)

	if statuscode != "" {
		return fmt.Sprintf("%s", statuscode)
	}

	err := json.Unmarshal(result, &jsonres)
	if err != nil {
		log.Fatal(err)
	}
	return fmt.Sprintf("%+v", jsonres)
}

func GetAllPastesForAccount(email string) string {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// URL Endpoint for getting pastes for an account
	URLENDPOINT := "pasteaccount/"

	var (
		jsonres    []jsonPasteResp
		result     []byte
		statuscode string
	)

	// build URL for getting pastes for an account
	var URL = BASEAPIURL + URLENDPOINT + email

	result, statuscode = RestReq(URL)

	if statuscode != "" {
		return fmt.Sprintf("%s", statuscode)
	}

	err := json.Unmarshal(result, &jsonres)
	if err != nil {
		log.Fatal(err)
	}
	return fmt.Sprintf("%+v", jsonres)

}
