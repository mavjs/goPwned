package gopwned

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"fmt"

	"github.com/stretchr/testify/assert"
)

var (
	expectedMethod  = "GET"
	expectedHeaders = map[string]string{
		"Accept": MediaTypeV2,
	}

	mockHandler *http.ServeMux
	mockServer  *httptest.Server
)

func init() {
	mockHandler = http.NewServeMux()
	mockServer = httptest.NewServer(mockHandler)

	// overwrite the package's default
	baseURL, _ = url.Parse(mockServer.URL)
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

// XXX Test for *Client

func TestAllBreachesForAccount(t *testing.T) {
	assert := assert.New(t)

	mockHandler.HandleFunc("/breachedaccount/test@example.com", func(w http.ResponseWriter, r *http.Request) {
		checkHeader(t)(w, r)
		fmt.Fprint(w, `[{"Name":"000webhost"},{"Name": "Adobe"}]`)
	})

	account, err := GetAllBreachesForAccount("test@example.com", "", "")
	if err != nil {
		t.Fatalf("[Get All Breaches For Account] returned error: %v", err)
	}

	want := []*Breach{
		{Name: "000webhost"},
		{Name: "Adobe"},
	}
	assert.Equal(want, account, "Expected equal value")
}

func TestAllBreachedSites(t *testing.T) {
	assert := assert.New(t)

	mockHandler.HandleFunc("/breaches", func(w http.ResponseWriter, r *http.Request) {
		checkHeader(t)(w, r)
		fmt.Fprint(w, `[{"Name": "Adobe"}]`)
	})

	account, err := GetAllBreachedSites("adobe.com")
	if err != nil {
		t.Fatalf("[Get All Breached Sites] returned error: %v", err)
	}

	want := []*Breach{
		{Name: "Adobe"},
	}
	assert.Equal(want, account, "they should be the same output.")
}

func TestGetBreachedSite(t *testing.T) {
	assert := assert.New(t)

	mockHandler.HandleFunc("/breach/Adobe", func(w http.ResponseWriter, r *http.Request) {
		checkHeader(t)(w, r)
		fmt.Fprint(w, `[{"Name": "Adobe"}]`)
	})

	account, err := GetBreachedSite("Adobe")
	if err != nil {
		t.Fatalf("[Get Breached Site] returned error: %v", err)
	}

	want := []*Breach{
		{Name: "Adobe"},
	}
	assert.Equal(want, account, "they should be the same output.")
}

func TestGetDataClasses(t *testing.T) {
	assert := assert.New(t)

	mockHandler.HandleFunc("/dataclasses", func(w http.ResponseWriter, r *http.Request) {
		checkHeader(t)(w, r)
		fmt.Fprint(w, `["Account balances","Age groups"]`)
	})

	account, err := GetDataClasses()
	if err != nil {
		t.Fatalf("[Get All Data Classes] returned error: %v", err)
	}

	want := &DataClasses{
		"Account balances",
		"Age groups",
	}
	assert.Equal(want, account, "they should be the same output.")
}

func TestGetAllPastesForAccount(t *testing.T) {
	assert := assert.New(t)

	mockHandler.HandleFunc("/pasteaccount/test@example.com", func(w http.ResponseWriter, r *http.Request) {
		checkHeader(t)(w, r)
		fmt.Fprint(w, `[{"Source":"Pastebin","Id":"Ab2ZYrq4","EmailCount":48},{"Source":"Pastebin","Id":"46g62dvD","EmailCount":1670}]`)
	})

	account, err := GetAllPastesForAccount("test@example.com")
	if err != nil {
		t.Errorf("[Get All Breaches For Account] returned error: %v", err)
	}

	want := []*Paste{
		{
			Source:     "Pastebin",
			ID:         "Ab2ZYrq4",
			EmailCount: 48,
		},
		{
			Source:     "Pastebin",
			ID:         "46g62dvD",
			EmailCount: 1670,
		},
	}
	assert.Equal(want, account, "they should be the same output.")
}
