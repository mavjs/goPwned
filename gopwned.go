package gopwned

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

type jsonRespEmail struct {
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

var BASEAPIURL = "https://haveibeenpwned.com/api/v2/"

var respcodes = map[int]string{
	400: "Bad request — the account does not comply with an acceptable format (i.e. it's an empty string)",
	403: "Forbidden — no user agent has been specified in the request",
	404: "Not found — the account could not be found and has therefore not been pwned",
}

func StatusCodeCheck(statuscode int) string {
	// return status codes and exit
	return respcodes[statuscode]
}

func GetAllBreachesForAccount(email, domain string) string {
	URLENDPOINT := "breachedAccount/"

	// create http client
	client := new(http.Client)
	var result []jsonRespEmail

	if domain == "" {
		var URL = BASEAPIURL + URLENDPOINT + email

		// request http api
		req, err := http.NewRequest("Get", URL, nil)
		if err != nil {
			log.Fatal(err)
		}

		// set haveibeenpwned content negotiation header
		req.Header.Add("Accept", "application/vnd.haveibeenpwned.v2+json")

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

		statuscode := StatusCodeCheck(res.StatusCode)
		if statuscode != "" {
			return fmt.Sprintf("%s", statuscode)
		}

		err = json.Unmarshal(body, &result)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		var URL = BASEAPIURL + URLENDPOINT + email + "?domain=" + domain

		// request http api
		req, err := http.NewRequest("Get", URL, nil)
		if err != nil {
			log.Fatal(err)
		}

		// set haveibeenpwned content negotiation header
		req.Header.Add("Accept", "application/vnd.haveibeenpwned.v2+json")

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

		statuscode := StatusCodeCheck(res.StatusCode)
		if statuscode != "" {
			return fmt.Sprintf("%s", statuscode)
		}

		err = json.Unmarshal(body, &result)
		if err != nil {
			log.Fatal(err)
		}
	}
	return fmt.Sprintf("%+v", result)
}
