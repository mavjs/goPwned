package gopwned

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"fmt"

	"github.com/stretchr/testify/assert"
)

func TestAllBreachesForAccount(t *testing.T) {
	assert := assert.New(t)
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)

	httpClient := &http.Client{}
	// gopwned client configured to use test server
	client, err := NewClient(httpClient)
	if err != nil {
		t.Errorf("Can't initiate goPwned client: %v", err)
	}

	url, _ := url.Parse(server.URL)
	client.baseURL = url

	mux.HandleFunc("/breachedaccount/test@example.com", func(w http.ResponseWriter, r *http.Request) {
		wantMethod := "GET"
		wantHeader := "Accept"
		wantHeaderType := mediaTypeV2
		if got := r.Method; got != wantMethod {
			t.Errorf("Request method: %v, want %v", got, wantMethod)
		}
		if got := r.Header.Get(wantHeader); got != wantHeaderType {
			t.Errorf("Header.Get(%q) returned %q, want %q", wantHeader, got, wantHeaderType)
		}
		fmt.Fprint(w, `[{"Name":"000webhost"},{"Name": "Adobe"}]`)
	})

	account, err := client.GetAllBreachesForAccount("test@example.com", "", "")
	if err != nil {
		t.Errorf("[Get All Breaches For Account] returned error: %v", err)
	}

	want := []*BreachModel{
		{
			Name: "000webhost",
		},
		{
			Name: "Adobe",
		},
	}
	assert.Equal(want, account, "they should be the same output.")
}
