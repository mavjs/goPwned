package gopwned

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

const (
	NOTFOUND     = "Not found — the account could not be found and has therefore not been pwned"
	FOOBAR       = "[{\"Title\":\"Adobe\",\"Name\":\"Adobe\",\"Domain\":\"adobe.com\",\"BreachDate\":\"2013-10-4\",\"AddedDate\":\"2013-12-04T00:00:00Z\",\"PwnCount\":152445165,\"Description\":\"The big one. In October 2013, 153 million Adobe accounts were breached with each containing an internal ID, username, email, \\u003cem\\u003eencrypted\\u003c/em\\u003e password and a password hint in plain text. The password cryptography was poorly done and \\u003ca href=\\\"http://stricture-group.com/files/adobe-top100.txt\\\" target=\\\"_blank\\\"\\u003emany were quickly resolved back to plain text\\u003c/a\\u003e. The unencrypted hints also \\u003ca href=\\\"http://www.troyhunt.com/2013/11/adobe-credentials-and-serious.html\\\" target=\\\"_blank\\\"\\u003edisclosed much about the passwords\\u003c/a\\u003e adding further to the risk that hundreds of millions of Adobe customers already faced.\",\"DataClasses\":[\"Email addresses\",\"Password hints\",\"Passwords\",\"Usernames\"],\"IsVerified\":true,\"LogoType\":\"svg\"}]"
	BREACHES     = "[{\"Title\":\"Adobe\",\"Name\":\"Adobe\",\"Domain\":\"adobe.com\",\"BreachDate\":\"2013-10-4\",\"AddedDate\":\"2013-12-04T00:00:00Z\",\"PwnCount\":152445165,\"Description\":\"The big one. In October 2013, 153 million Adobe accounts were breached with each containing an internal ID, username, email, \\u003cem\\u003eencrypted\\u003c/em\\u003e password and a password hint in plain text. The password cryptography was poorly done and \\u003ca href=\\\"http://stricture-group.com/files/adobe-top100.txt\\\" target=\\\"_blank\\\"\\u003emany were quickly resolved back to plain text\\u003c/a\\u003e. The unencrypted hints also \\u003ca href=\\\"http://www.troyhunt.com/2013/11/adobe-credentials-and-serious.html\\\" target=\\\"_blank\\\"\\u003edisclosed much about the passwords\\u003c/a\\u003e adding further to the risk that hundreds of millions of Adobe customers already faced.\",\"DataClasses\":[\"Email addresses\",\"Password hints\",\"Passwords\",\"Usernames\"],\"IsVerified\":true,\"LogoType\":\"svg\"}]"
	SINGLEBREACH = "{\"Title\":\"Adobe\",\"Name\":\"Adobe\",\"Domain\":\"adobe.com\",\"BreachDate\":\"2013-10-4\",\"AddedDate\":\"2013-12-04T00:00:00Z\",\"PwnCount\":152445165,\"Description\":\"The big one. In October 2013, 153 million Adobe accounts were breached with each containing an internal ID, username, email, \\u003cem\\u003eencrypted\\u003c/em\\u003e password and a password hint in plain text. The password cryptography was poorly done and \\u003ca href=\\\"http://stricture-group.com/files/adobe-top100.txt\\\" target=\\\"_blank\\\"\\u003emany were quickly resolved back to plain text\\u003c/a\\u003e. The unencrypted hints also \\u003ca href=\\\"http://www.troyhunt.com/2013/11/adobe-credentials-and-serious.html\\\" target=\\\"_blank\\\"\\u003edisclosed much about the passwords\\u003c/a\\u003e adding further to the risk that hundreds of millions of Adobe customers already faced.\",\"DataClasses\":[\"Email addresses\",\"Password hints\",\"Passwords\",\"Usernames\"],\"IsVerified\":true,\"LogoType\":\"svg\"}"
	DATACLASSES  = "[\"Addresses\",\"Age groups\",\"Career levels\",\"Credit cards\",\"Customer interactions\",\"Dates of birth\",\"Device usage tracking data\",\"Education levels\",\"Email addresses\",\"Email messages\",\"Employers\",\"Genders\",\"Geographic location\",\"Government issued IDs\",\"Historical passwords\",\"Instant messenger identities\",\"IP addresses\",\"Job titles\",\"MAC addresses\",\"Names\",\"Nicknames\",\"Passport numbers\",\"Password hints\",\"Passwords\",\"Phone numbers\",\"Private messages\",\"Purchases\",\"Races\",\"Relationship statuses\",\"Reward program balances\",\"Salutations\",\"Sexual preferences\",\"SMS messages\",\"Social connections\",\"Spoken languages\",\"Time zones\",\"User website URLs\",\"Usernames\",\"Website activity\",\"Years of birth\"]"
)

func TestGoPwned(t *testing.T) {
	assert := assert.New(t)

	FBTest := GetAllBreachesForAccount("foo@bar.com", "adobe.com")
	assert.Equal(FBTest, FOOBAR, "they should be equal")

	NFResult := GetAllBreachesForAccount("mavjs01@gmail.com", "")
	assert.Equal(NFResult, NOTFOUND, "they should be equal")

	BRDomain := AllBreaches("adobe.com")
	assert.Equal(BREACHES, BRDomain, "they should be equal")

	BRALL := AllBreaches("")
	assert.NotEmpty(BRALL, "they should not be empty")
	assert.NotEqual(BREACHES, BRALL, "they should not be equal")

	GSBSite := GetSingleBreachedSite("adobe")
	assert.Equal(SINGLEBREACH, GSBSite, "they should be equal")

	CLS := GetAllDataClasses()
	assert.Equal(DATACLASSES, CLS, "they must be equal")

	PAccount := GetAllPastesForAccount("foo@bar.com")
	assert.NotEmpty(PAccount, "they should not be empty")
}
