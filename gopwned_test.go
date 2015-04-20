package gopwned

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var (
	NOTFOUND = "Not found — the account could not be found and has therefore not been pwned"
	FOOBAR   = "[{Title:Adobe Name:Adobe Domain:adobe.com BreachDate:2013-10-4 AddedDate:2013-12-04T00:00:00Z PwnCount:152445165 Description:The big one. In October 2013, 153 million Adobe accounts were breached with each containing an internal ID, username, email, <em>encrypted</em> password and a password hint in plain text. The password cryptography was poorly done and <a href=\"http://stricture-group.com/files/adobe-top100.txt\" target=\"_blank\">many were quickly resolved back to plain text</a>. The unencrypted hints also <a href=\"http://www.troyhunt.com/2013/11/adobe-credentials-and-serious.html\" target=\"_blank\">disclosed much about the passwords</a> adding further to the risk that hundreds of millions of Adobe customers already faced. DataClasses:[Email addresses Password hints Passwords Usernames] IsVerified:true LogoType:svg}]"
)

func TestGoPwned(t *testing.T) {
	assert := assert.New(t)

	FBTest := GetAllBreachesForAccount("foo@bar.com", "adobe.com")
	assert.Equal(FBTest, FOOBAR, "they should be equal")

	NFResult := GetAllBreachesForAccount("mavjs01@gmail.com", "")
	assert.Equal(NFResult, NOTFOUND, "they should be equal")
}
