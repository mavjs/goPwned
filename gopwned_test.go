package gopwned

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var (
	NOTFOUND     = "Not found — the account could not be found and has therefore not been pwned"
	FOOBAR       = "[{Title:Adobe Name:Adobe Domain:adobe.com BreachDate:2013-10-4 AddedDate:2013-12-04T00:00:00Z PwnCount:152445165 Description:The big one. In October 2013, 153 million Adobe accounts were breached with each containing an internal ID, username, email, <em>encrypted</em> password and a password hint in plain text. The password cryptography was poorly done and <a href=\"http://stricture-group.com/files/adobe-top100.txt\" target=\"_blank\">many were quickly resolved back to plain text</a>. The unencrypted hints also <a href=\"http://www.troyhunt.com/2013/11/adobe-credentials-and-serious.html\" target=\"_blank\">disclosed much about the passwords</a> adding further to the risk that hundreds of millions of Adobe customers already faced. DataClasses:[Email addresses Password hints Passwords Usernames] IsVerified:true LogoType:svg}]"
	BREACHES     = "[{Title:Adobe Name:Adobe Domain:adobe.com BreachDate:2013-10-4 AddedDate:2013-12-04T00:00:00Z PwnCount:152445165 Description:The big one. In October 2013, 153 million Adobe accounts were breached with each containing an internal ID, username, email, <em>encrypted</em> password and a password hint in plain text. The password cryptography was poorly done and <a href=\"http://stricture-group.com/files/adobe-top100.txt\" target=\"_blank\">many were quickly resolved back to plain text</a>. The unencrypted hints also <a href=\"http://www.troyhunt.com/2013/11/adobe-credentials-and-serious.html\" target=\"_blank\">disclosed much about the passwords</a> adding further to the risk that hundreds of millions of Adobe customers already faced. DataClasses:[Email addresses Password hints Passwords Usernames] IsVerified:true LogoType:svg}]"
	SINGLEBREACH = "{Title:Adobe Name:Adobe Domain:adobe.com BreachDate:2013-10-4 AddedDate:2013-12-04T00:00:00Z PwnCount:152445165 Description:The big one. In October 2013, 153 million Adobe accounts were breached with each containing an internal ID, username, email, <em>encrypted</em> password and a password hint in plain text. The password cryptography was poorly done and <a href=\"http://stricture-group.com/files/adobe-top100.txt\" target=\"_blank\">many were quickly resolved back to plain text</a>. The unencrypted hints also <a href=\"http://www.troyhunt.com/2013/11/adobe-credentials-and-serious.html\" target=\"_blank\">disclosed much about the passwords</a> adding further to the risk that hundreds of millions of Adobe customers already faced. DataClasses:[Email addresses Password hints Passwords Usernames] IsVerified:true LogoType:svg}"
	DATACLASSES  = "[Addresses Age groups Career levels Credit cards Customer interactions Dates of birth Education levels Email addresses Employers Genders Geographic location Government issued IDs Historical passwords Instant messenger identities IP addresses Job titles Languages MAC addresses Names Nicknames Passport numbers Password hints Passwords Phone numbers Private messages Purchases Reward program balances Salutations SMS messages Social connections Time zones User website URLs Usernames Website activity Years of birth]"
	PASTE        = "[{Source:Pastebin Id:9ZKSRx5i Title:1K Combo [CrackingSeal.net] Date:2015-04-19T13:06:08Z EmailCount:999} {Source:Pastebin Id:L6fZS5VC Title:kwekwekwekwk Date:2015-02-18T15:30:00Z EmailCount:14427} {Source:Pastebin Id:b6taeWri Title: Date:2014-11-17T08:11:00Z EmailCount:972} {Source:Pastebin Id:ba6LmF9Z Title:Hacked by Kashirmi Cheetah Date:2014-09-08T08:09:00Z EmailCount:1799} {Source:Pastebin Id:wXb5W8GV Title:#freenode-log Date:2014-07-06T19:07:00Z EmailCount:187} {Source:Pastebin Id:EE8GM0ed Title: Date:2014-03-26T17:03:00Z EmailCount:80} {Source:Pastebin Id:8Q0BvKD8 Title:syslog Date:2014-03-04T19:03:00Z EmailCount:139} {Source:Pastebin Id:C4GdBDnP Title:#secuinside13 logs Date:2013-05-26T22:05:00Z EmailCount:255}]"
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
	assert.Equal(PASTE, PAccount, "they should be equal")
}
