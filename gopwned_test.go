package gopwned

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnAuthReq(t *testing.T) {
	assert := assert.New(t)

	want_result := []*Breach([]*Breach(nil))
	want_error := errors.New("the function you're trying to request requires an API key")

	gopwn := NewClient(nil, "")
	got_result, got_err := gopwn.GetAllBreaches("multiple-breaches@hibp-integration-tests.com", "", true, false)
	if got_err != nil {
		assert.Equal(want_error, got_err, "[Error Test] The test expected a failure in authentication due to missing API key.")
	}
	assert.Equal(want_result, got_result, "[Return Test] The test expected a failure in authentication due to missing API key.")
}

func TestUnAuthzAPI(t *testing.T) {
	assert := assert.New(t)

	want_error := errors.New(respCodes[401])

	gopwn := NewClient(nil, "InvalidAPIKey")
	_, got_err := gopwn.GetAllBreaches("account-exists@hibp-integration-tests.com", "", true, false)
	if got_err != nil {
		assert.Equal(want_error, got_err, "The test expected to return a message based on HTTP Status Code 401.")
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
