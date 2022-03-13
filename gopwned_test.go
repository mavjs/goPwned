package gopwned

import (
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	expectedMethod  = "GET"
	expectedHeaders = map[string]string{
		"Accept": "application/json",
	}

	mockHandler *http.ServeMux
	mockServer  *httptest.Server
)

func init() {
	mockHandler = http.NewServeMux()
	mockServer = httptest.NewServer(mockHandler)
}

func checkHeader(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != expectedMethod {
			t.Fatalf("Expected %s for request method, got %s", expectedMethod, r.Method)
		}

		for k, v := range expectedHeaders {
			header := r.Header.Get(k)
			if header != v {
				t.Fatalf("Expected %s for request header, got %s", v, header)
			}
		}
	}
}

func setupPasswordInput() (string, string) {
	inputPassword := "P@ssw0rd"
	h := sha1.New()
	h.Write([]byte(inputPassword))
	password := fmt.Sprintf("%X", h.Sum(nil)) // hash = "21BD12DC183F740EE76F27B78EB39C8AD972A757"

	frange := password[0:5]
	lrange := password[5:40]

	return frange, lrange
}

func helperPasswordOutput(karray []byte, lrange string) int64 {
	str_karray := string(karray)
	respArray := strings.Split(str_karray, "\r\n")

	result := int64(-1)
	for _, resp := range respArray {
		str_array := strings.Split(resp, ":")
		test := str_array[0]

		result, err := strconv.ParseInt(str_array[1], 0, 32)
		if err != nil {
			fmt.Printf("%#v", str_array[1])
			panic("unable to convert string into integer")
		}
		if test == lrange {
			return result
		}
	}
	return result
}

func TestNewClient(t *testing.T) {
	var token = ""
	c := NewClient(nil, token)

	if got, want := c.Token, token; got != want {
		t.Errorf("[TestNewClient] Token is %v, want %v", got, want)
	}
}

func TestUnAuthReq(t *testing.T) {
	assert := assert.New(t)

	gopwn := NewClient(nil, "")
	_, got_err := gopwn.GetAccountBreaches("multiple-breaches@hibp-integration-tests.com", "", true, false)
	if got_err != nil {
		assert.EqualError(got_err, "the function you're trying to request requires an API key")

	}
}

func TestWrongAPIKey(t *testing.T) {
	assert := assert.New(t)

	want_error := errors.New(respCodes[401])

	gopwn := NewClient(nil, "InvalidAPIKey")
	_, got_err := gopwn.GetAccountBreaches("account-exists@hibp-integration-tests.com", "", true, false)
	if got_err != nil {
		assert.Equal(want_error, got_err, "[TestWrongAPIKey] Expected to return a message based on HTTP Status Code 401.")
	}
}

func TestAccountExists(t *testing.T) {
	HIBP_API_KEY := os.Getenv("HIBP_API_KEY")
	if HIBP_API_KEY == "" {
		t.Skip("[TestAccountExists] Skipped test as API key was not provided.")
	}

	assert := assert.New(t)
	want := []*Breach{
		{
			Name:         "Adobe",
			Title:        "",
			Domain:       "",
			BreachDate:   "",
			AddedDate:    "",
			ModifiedDate: "",
			PwnCount:     0,
			Description:  "",
			DataClasses:  nil,
			IsVerified:   false,
			IsFabricated: false,
			IsSensitive:  false,
			IsRetired:    false,
			IsSpamList:   false,
			LogoPath:     "",
		},
	}

	gopwn := NewClient(nil, HIBP_API_KEY)
	got, err := gopwn.GetAccountBreaches("account-exists@hibp-integration-tests.com", "", true, false)
	if err != nil {
		t.Errorf("[TestWithAPICheckAccountExists] Returned errors: %v", err)
	}
	assert.Equal(want, got, "[TestWithAPICheckAccountExists] Expected a non nil return of a breach.")
}

func TestAccountDomain(t *testing.T) {
	HIBP_API_KEY := os.Getenv("HIBP_API_KEY")
	if HIBP_API_KEY == "" {
		t.Skip("[TestAccountDomain] Skipped test as API key was not provided.")
	}

	assert := assert.New(t)
	want := []*Breach{
		{
			Name:         "Adobe",
			Title:        "",
			Domain:       "",
			BreachDate:   "",
			AddedDate:    "",
			ModifiedDate: "",
			PwnCount:     0,
			Description:  "",
			DataClasses:  nil,
			IsVerified:   false,
			IsFabricated: false,
			IsSensitive:  false,
			IsRetired:    false,
			IsSpamList:   false,
			LogoPath:     "",
		},
	}

	gopwn := NewClient(nil, HIBP_API_KEY)
	got, err := gopwn.GetAccountBreaches("account-exists@hibp-integration-tests.com", "adobe.com", true, false)
	if err != nil {
		t.Errorf("[TestAccountDomain] Returned errors: %v", err)
	}
	assert.Equal(want, got, "[TestAccountDomain] Expected a non nil return of a breach.")
}

func TestNotActiveBreach(t *testing.T) {
	HIBP_API_KEY := os.Getenv("HIBP_API_KEY")
	if HIBP_API_KEY == "" {
		t.Skip("[TestNotActiveBreach] Skipped test as API key was not provided.")
	}

	assert := assert.New(t)

	gopwn := NewClient(nil, HIBP_API_KEY)

	got, err := gopwn.GetAccountBreaches("not-active-breach@hibp-integration-tests.com", "", true, false)
	if err != nil {
		assert.EqualError(err, respCodes[404])
	}

	if got != nil {
		t.Errorf("[TestNotActiveBreach] Expected no breaches to be returned. Got: %v", got)
	}
}

func TestPasteBreach(t *testing.T) {
	HIBP_API_KEY := os.Getenv("HIBP_API_KEY")
	if HIBP_API_KEY == "" {
		t.Skip("[TestPasteBreach] Skipping test as API key was not provided.")
	}

	assert := assert.New(t)

	want := []*Paste{
		{
			Source:     "Pastebin",
			ID:         "uQNGpAxp",
			Title:      "",
			Date:       "2018-06-12T00:51:08Z",
			EmailCount: 1117,
		},
	}
	gopwn := NewClient(nil, HIBP_API_KEY)

	got, err := gopwn.GetAccountPastes("paste-sensitive-breach@hibp-integration-tests.com")
	if err != nil {
		t.Errorf("[TestPasteBreach] Expected no pastes to be returned. Got: %v", got)
	}

	assert.Equal(want, got, "[TestPasteBreach] Expected a paste to be returned.")
}

func TestPasswordBreach(t *testing.T) {
	assert := assert.New(t)

	want := int64(83129)

	gopwned := NewClient(nil, "")

	frange, lrange := setupPasswordInput()

	karray, err := gopwned.GetPwnedPasswords(frange, false)
	if err != nil {
		t.Errorf("[TestPasswordBreach] Expected password to return a count. Got: %v", err)
	}

	got := helperPasswordOutput(karray, lrange)
	if got == int64(-1) {
		t.Errorf("[TestPasswordBreach] Expected a count of >= 0. Got: %v", got)
	}

	assert.Equal(want, got, "[TestPasswordBreach] Expected a return of a password count.")
}

func TestPasswordBreachWithPadding(t *testing.T) {
	assert := assert.New(t)

	want := int64(83129)

	gopwned := NewClient(nil, "")

	frange, lrange := setupPasswordInput()

	karray, err := gopwned.GetPwnedPasswords(frange, true)
	if err != nil {
		t.Errorf("[TestPasswordBreachWithPadding] Expected password to return a count. Got: %v", err)
	}

	got := helperPasswordOutput(karray, lrange)
	if got == int64(-1) {
		t.Errorf("[TestPasswordBreachWithPadding] Expected a count of >= 0. Got: %v", got)
	}

	assert.Equal(want, got, "[TestPasswordBreachWithPadding] Expected a return of a password count.")
}

func TestPasswordBreachWrongChars(t *testing.T) {
	assert := assert.New(t)

	gopwned := NewClient(nil, "")

	karray, err := gopwned.GetPwnedPasswords("1234G", true)
	if err != nil {
		assert.EqualError(err, respCodes[400])
	}

	if karray != nil {
		t.Errorf("[TestPasswordBreachWrongChars] Expected no returns. Got: %v", karray)
	}
}

func TestBreachesStruct(t *testing.T) {
	assert := assert.New(t)

	breach_struct := []*Breach{}

	raw_breaches := `
	[
	{
	"Name":"Adobe",
	"Title":"Adobe",
	"Domain":"adobe.com",
	"BreachDate":"2013-10-04",
	"AddedDate":"2013-12-04T00:00Z",
	"ModifiedDate":"2013-12-04T00:00Z",
	"PwnCount":152445165,
	"Description":"In October 2013, 153 million Adobe accounts were breached with each containing an internal ID, username, email, <em>encrypted</em> password and a password hint in plain text. The password cryptography was poorly done and <a href=\"http://stricture-group.com/files/adobe-top100.txt\" target=\"_blank\" rel=\"noopener\">many were quickly resolved back to plain text</a>. The unencrypted hints also <a href=\"http://www.troyhunt.com/2013/11/adobe-credentials-and-serious.html\" target=\"_blank\" rel=\"noopener\">disclosed much about the passwords</a> adding further to the risk that hundreds of millions of Adobe customers already faced.",
	"DataClasses":["Email addresses","Password hints","Passwords","Usernames"],
	"IsVerified":true,
	"IsFabricated":false,
	"IsSensitive":false,
	"IsRetired":false,
	"IsSpamList":false,
	"LogoPath":"https://haveibeenpwned.com/Content/Images/PwnedLogos/Adobe.png"
	},
	{
	"Name":"BattlefieldHeroes",
	"Title":"Battlefield Heroes",
	"Domain":"battlefieldheroes.com",
	"BreachDate":"2011-06-26",
	"AddedDate":"2014-01-23T13:10Z",
	"ModifiedDate":"2014-01-23T13:10Z",
	"PwnCount":530270,
	"Description":"In June 2011 as part of a final breached data dump, the hacker collective &quot;LulzSec&quot; <a href=\"http://www.rockpapershotgun.com/2011/06/26/lulzsec-over-release-battlefield-heroes-data\" target=\"_blank\" rel=\"noopener\">obtained and released over half a million usernames and passwords from the game Battlefield Heroes</a>. The passwords were stored as MD5 hashes with no salt and many were easily converted back to their plain text versions.",
	"DataClasses":["Passwords","Usernames"],
	"IsVerified":true,
	"IsFabricated":false,
	"IsSensitive":false,
	"IsRetired":false,
	"IsSpamList":false,
	"LogoPath":"https://haveibeenpwned.com/Content/Images/PwnedLogos/BattlefieldHeroes.png"
	}
	]
	`

	err := json.Unmarshal([]byte(raw_breaches), &breach_struct)
	if err != nil {
		t.Fatalf("[TestBreachesStruct] returned error: %v", err)
	}

	want := []*Breach{
		{
			Name:         "Adobe",
			Title:        "Adobe",
			Domain:       "adobe.com",
			BreachDate:   "2013-10-04",
			AddedDate:    "2013-12-04T00:00Z",
			ModifiedDate: "2013-12-04T00:00Z",
			PwnCount:     152445165,
			Description:  "In October 2013, 153 million Adobe accounts were breached with each containing an internal ID, username, email, <em>encrypted</em> password and a password hint in plain text. The password cryptography was poorly done and <a href=\"http://stricture-group.com/files/adobe-top100.txt\" target=\"_blank\" rel=\"noopener\">many were quickly resolved back to plain text</a>. The unencrypted hints also <a href=\"http://www.troyhunt.com/2013/11/adobe-credentials-and-serious.html\" target=\"_blank\" rel=\"noopener\">disclosed much about the passwords</a> adding further to the risk that hundreds of millions of Adobe customers already faced.",
			DataClasses: &DataClasses{
				"Email addresses",
				"Password hints",
				"Passwords",
				"Usernames",
			},
			IsVerified:   true,
			IsFabricated: false,
			IsSensitive:  false,
			IsRetired:    false,
			IsSpamList:   false,
			LogoPath:     "https://haveibeenpwned.com/Content/Images/PwnedLogos/Adobe.png",
		},
		{
			Name:         "BattlefieldHeroes",
			Title:        "Battlefield Heroes",
			Domain:       "battlefieldheroes.com",
			BreachDate:   "2011-06-26",
			AddedDate:    "2014-01-23T13:10Z",
			ModifiedDate: "2014-01-23T13:10Z",
			PwnCount:     530270,
			Description:  "In June 2011 as part of a final breached data dump, the hacker collective &quot;LulzSec&quot; <a href=\"http://www.rockpapershotgun.com/2011/06/26/lulzsec-over-release-battlefield-heroes-data\" target=\"_blank\" rel=\"noopener\">obtained and released over half a million usernames and passwords from the game Battlefield Heroes</a>. The passwords were stored as MD5 hashes with no salt and many were easily converted back to their plain text versions.",
			DataClasses: &DataClasses{
				"Passwords",
				"Usernames",
			},
			IsVerified:   true,
			IsFabricated: false,
			IsSensitive:  false,
			IsRetired:    false,
			IsSpamList:   false,
			LogoPath:     "https://haveibeenpwned.com/Content/Images/PwnedLogos/BattlefieldHeroes.png",
		},
	}

	assert.Equal(want, breach_struct, "Expected equal value for Breaches in TestBreaches.")
}

func TestPastesStruct(t *testing.T) {
	assert := assert.New(t)

	paste_struct := []*Paste{}

	raw_pastes := `
	[
	{
	"Source":"Pastebin",
	"Id":"8Q0BvKD8",
	"Title":"syslog",
	"Date":"2014-03-04T19:14:54Z",
	"EmailCount":139
	},
	{
	"Source":"Pastie",
	"Id":"7152479",
	"Date":"2013-03-28T16:51:10Z",
	"EmailCount":30
	}
	]
	`

	err := json.Unmarshal([]byte(raw_pastes), &paste_struct)
	if err != nil {
		t.Fatalf("[TestPastesStruct] returned error: %v", err)
	}

	want := []*Paste{
		{
			Source:     "Pastebin",
			ID:         "8Q0BvKD8",
			Title:      "syslog",
			Date:       "2014-03-04T19:14:54Z",
			EmailCount: 139,
		},
		{
			Source:     "Pastie",
			ID:         "7152479",
			Date:       "2013-03-28T16:51:10Z",
			EmailCount: 30,
		},
	}

	assert.Equal(want, paste_struct, "Expected equal value for Pastes in TestPastes.")
}

func TestGetDataClasses(t *testing.T) {
	assert := assert.New(t)

	mockHandler.HandleFunc("/dataclasses", func(w http.ResponseWriter, r *http.Request) {
		checkHeader(t)(w, r)
		fmt.Fprint(w, `["Account balances","Age groups"]`)
	})

	gopwned := NewClient(nil, "")
	gopwned.BaseURL, _ = url.Parse(mockServer.URL)
	gopwned.PwnPwdURL, _ = url.Parse(mockServer.URL)

	got, err := gopwned.GetDataClasses()
	if err != nil {
		t.Errorf("[TestGetDataClasses] returned error: %v", err)
	}

	want := &DataClasses{
		"Account balances",
		"Age groups",
	}
	assert.Equal(want, got, "[TestGetDataClasses] Expected equal value for DataClasses.")
}

func TestGetBreachedSite(t *testing.T) {
	assert := assert.New(t)

	mockHandler.HandleFunc("/breach/Adobe", func(w http.ResponseWriter, r *http.Request) {
		checkHeader(t)(w, r)
		fmt.Fprint(w, `{"Name": "Adobe"}`)
	})

	gopwned := NewClient(nil, "")
	gopwned.BaseURL, _ = url.Parse(mockServer.URL)
	gopwned.PwnPwdURL, _ = url.Parse(mockServer.URL)

	got, err := gopwned.GetABreachedSite("Adobe")
	if err != nil {
		t.Fatalf("[TestGetBreachedSite] returned error: %v", err)
	}

	want := &Breach{
		Name: "Adobe",
	}
	assert.Equal(want, got, "[TestGetBreachedSite] Expected equal value for a breached site.")
}

func TestGetBreachedSiteWithoutSite(t *testing.T) {
	assert := assert.New(t)

	mockHandler.HandleFunc("/breach/", func(w http.ResponseWriter, r *http.Request) {
		checkHeader(t)(w, r)
		fmt.Fprint(w, `{"Name": "Adobe"}`)
	})

	gopwned := NewClient(nil, "")
	gopwned.BaseURL, _ = url.Parse(mockServer.URL)
	gopwned.PwnPwdURL, _ = url.Parse(mockServer.URL)

	got, err := gopwned.GetABreachedSite("")
	if err != nil {
		assert.EqualError(err, "a breach name was not provided")
	}
	if got != nil {
		t.Errorf("[TestGetBreachedSiteWithoutSite] Expected no return value. Got: %v", got)
	}
}

func TestGetBreachedSites(t *testing.T) {
	assert := assert.New(t)

	mockHandler.HandleFunc("/breaches", func(w http.ResponseWriter, r *http.Request) {
		checkHeader(t)(w, r)
		fmt.Fprint(w, `[{"Name":"000webhost"},{"Name": "Adobe"}]`)
	})

	want := []*Breach{
		{Name: "000webhost"},
		{Name: "Adobe"},
	}

	gopwned := NewClient(nil, "")
	gopwned.BaseURL, _ = url.Parse(mockServer.URL)
	gopwned.PwnPwdURL, _ = url.Parse(mockServer.URL)

	got, err := gopwned.GetBreachedSites("")
	if err != nil {
		t.Errorf("[TestGetBreachedSites] Expected no errors to return. Got: %v", err)
	}

	assert.Equal(want, got, "[TestGetBreachedSites] Expected equal value for breached sites.")
}

func TestGetBreachedSitesFiltered(t *testing.T) {
	assert := assert.New(t)

	want := []*Breach{
		{
			Name:         "Adobe",
			Title:        "Adobe",
			Domain:       "adobe.com",
			BreachDate:   "2013-10-04",
			AddedDate:    "2013-12-04T00:00:00Z",
			ModifiedDate: "2013-12-04T00:00:00Z",
			PwnCount:     152445165,
			Description:  "In October 2013, 153 million Adobe accounts were breached with each containing an internal ID, username, email, <em>encrypted</em> password and a password hint in plain text. The password cryptography was poorly done and <a href=\"http://stricture-group.com/files/adobe-top100.txt\" target=\"_blank\" rel=\"noopener\">many were quickly resolved back to plain text</a>. The unencrypted hints also <a href=\"http://www.troyhunt.com/2013/11/adobe-credentials-and-serious.html\" target=\"_blank\" rel=\"noopener\">disclosed much about the passwords</a> adding further to the risk that hundreds of millions of Adobe customers already faced.",
			LogoPath:     "https://haveibeenpwned.com/Content/Images/PwnedLogos/Adobe.png",
			DataClasses: &DataClasses{
				"Email addresses",
				"Password hints",
				"Passwords",
				"Usernames"},
			IsVerified:   true,
			IsFabricated: false,
			IsSensitive:  false,
			IsRetired:    false,
			IsSpamList:   false,
			IsMalware:    false,
		},
	}

	gopwned := NewClient(nil, "")

	got, err := gopwned.GetBreachedSites("adobe.com")
	if err != nil {
		t.Errorf("[TestGetBreachedSitesFiltered] Expected no errors to return. Got: %v", err)
	}

	assert.Equal(want, got, "[TestGetBreachedSitesFiltered] Expected equal value for breached sites.")
}
