package gopwned

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

const (
	NOTFOUND     = "Not found — the account could not be found and has therefore not been pwned"
	FOOBAR       = "[{\"Title\":\"Adobe\",\"Name\":\"Adobe\",\"Domain\":\"adobe.com\",\"BreachDate\":\"2013-10-04\",\"AddedDate\":\"2013-12-04T00:00:00Z\",\"PwnCount\":152445165,\"Description\":\"The big one. In October 2013, 153 million Adobe accounts were breached with each containing an internal ID, username, email, \\u003cem\\u003eencrypted\\u003c/em\\u003e password and a password hint in plain text. The password cryptography was poorly done and \\u003ca href=\\\"http://stricture-group.com/files/adobe-top100.txt\\\" target=\\\"_blank\\\"\\u003emany were quickly resolved back to plain text\\u003c/a\\u003e. The unencrypted hints also \\u003ca href=\\\"http://www.troyhunt.com/2013/11/adobe-credentials-and-serious.html\\\" target=\\\"_blank\\\"\\u003edisclosed much about the passwords\\u003c/a\\u003e adding further to the risk that hundreds of millions of Adobe customers already faced.\",\"DataClasses\":[\"Email addresses\",\"Password hints\",\"Passwords\",\"Usernames\"],\"IsVerified\":true,\"LogoType\":\"svg\"}]"
	BREACHES     = "[{\"Title\":\"Adobe\",\"Name\":\"Adobe\",\"Domain\":\"adobe.com\",\"BreachDate\":\"2013-10-04\",\"AddedDate\":\"2013-12-04T00:00:00Z\",\"PwnCount\":152445165,\"Description\":\"The big one. In October 2013, 153 million Adobe accounts were breached with each containing an internal ID, username, email, \\u003cem\\u003eencrypted\\u003c/em\\u003e password and a password hint in plain text. The password cryptography was poorly done and \\u003ca href=\\\"http://stricture-group.com/files/adobe-top100.txt\\\" target=\\\"_blank\\\"\\u003emany were quickly resolved back to plain text\\u003c/a\\u003e. The unencrypted hints also \\u003ca href=\\\"http://www.troyhunt.com/2013/11/adobe-credentials-and-serious.html\\\" target=\\\"_blank\\\"\\u003edisclosed much about the passwords\\u003c/a\\u003e adding further to the risk that hundreds of millions of Adobe customers already faced.\",\"DataClasses\":[\"Email addresses\",\"Password hints\",\"Passwords\",\"Usernames\"],\"IsVerified\":true,\"LogoType\":\"svg\"}]"
	SINGLEBREACH = "{\"Title\":\"Adobe\",\"Name\":\"Adobe\",\"Domain\":\"adobe.com\",\"BreachDate\":\"2013-10-04\",\"AddedDate\":\"2013-12-04T00:00:00Z\",\"PwnCount\":152445165,\"Description\":\"The big one. In October 2013, 153 million Adobe accounts were breached with each containing an internal ID, username, email, \\u003cem\\u003eencrypted\\u003c/em\\u003e password and a password hint in plain text. The password cryptography was poorly done and \\u003ca href=\\\"http://stricture-group.com/files/adobe-top100.txt\\\" target=\\\"_blank\\\"\\u003emany were quickly resolved back to plain text\\u003c/a\\u003e. The unencrypted hints also \\u003ca href=\\\"http://www.troyhunt.com/2013/11/adobe-credentials-and-serious.html\\\" target=\\\"_blank\\\"\\u003edisclosed much about the passwords\\u003c/a\\u003e adding further to the risk that hundreds of millions of Adobe customers already faced.\",\"DataClasses\":[\"Email addresses\",\"Password hints\",\"Passwords\",\"Usernames\"],\"IsVerified\":true,\"LogoType\":\"svg\"}"
	DATACLASSES  = "[\"Account balances\",\"Age groups\",\"Career levels\",\"Credit cards\",\"Customer interactions\",\"Dates of birth\",\"Device usage tracking data\",\"Education levels\",\"Email addresses\",\"Email messages\",\"Employers\",\"Ethnicities\",\"Genders\",\"Geographic location\",\"Government issued IDs\",\"Historical passwords\",\"Home addresses\",\"Homepage URLs\",\"Instant messenger identities\",\"IP addresses\",\"Job titles\",\"MAC addresses\",\"Names\",\"Nicknames\",\"Passport numbers\",\"Password hints\",\"Passwords\",\"Payment histories\",\"Phone numbers\",\"Private messages\",\"Purchases\",\"Races\",\"Relationship statuses\",\"Reward program balances\",\"Salutations\",\"Security questions and answers\",\"Sexual preferences\",\"SMS messages\",\"Social connections\",\"Spoken languages\",\"Time zones\",\"User agent details\",\"User website URLs\",\"Usernames\",\"Website activity\",\"Years of birth\"]"
	PASTE        = "[{\"Source\":\"Pastebin\",\"ID\":\"urh5D0dT\",\"Title\":\"\",\"Date\":\"2016-01-25T16:54:32Z\",\"EmailCount\":22},{\"Source\":\"Pastebin\",\"ID\":\"VXXkSVa6\",\"Title\":\"Twitter\",\"Date\":\"2015-12-12T15:52:27Z\",\"EmailCount\":90},{\"Source\":\"Pastebin\",\"ID\":\"vwXXWCEN\",\"Title\":\"AMEmails.txt\",\"Date\":\"2015-08-19T05:32:23Z\",\"EmailCount\":10437},{\"Source\":\"Pastebin\",\"ID\":\"qAegkpzu\",\"Title\":\"Working Fresh EMails Hacked [Gmail,Hotmail,Yahoo..] By Aluf\",\"Date\":\"2015-06-09T11:16:36Z\",\"EmailCount\":7663},{\"Source\":\"Pastebin\",\"ID\":\"Lg80iL8k\",\"Title\":\"www.captainfarris.com\",\"Date\":\"2015-05-29T20:32:46Z\",\"EmailCount\":1081},{\"Source\":\"Pastebin\",\"ID\":\"uMq1W2mx\",\"Title\":\"npm-debug.log\",\"Date\":\"2015-05-10T23:57:41Z\",\"EmailCount\":40},{\"Source\":\"Pastebin\",\"ID\":\"9ZKSRx5i\",\"Title\":\"1K Combo [CrackingSeal.net]\",\"Date\":\"2015-04-19T13:06:08Z\",\"EmailCount\":999},{\"Source\":\"Pastebin\",\"ID\":\"L6fZS5VC\",\"Title\":\"kwekwekwekwk\",\"Date\":\"2015-02-18T15:30:00Z\",\"EmailCount\":14427},{\"Source\":\"Pastebin\",\"ID\":\"b6taeWri\",\"Title\":\"\",\"Date\":\"2014-11-17T08:11:00Z\",\"EmailCount\":972},{\"Source\":\"Pastebin\",\"ID\":\"ba6LmF9Z\",\"Title\":\"Hacked by Kashirmi Cheetah\",\"Date\":\"2014-09-08T08:09:00Z\",\"EmailCount\":1799},{\"Source\":\"Pastebin\",\"ID\":\"wXb5W8GV\",\"Title\":\"#freenode-log\",\"Date\":\"2014-07-06T19:07:00Z\",\"EmailCount\":187},{\"Source\":\"Pastebin\",\"ID\":\"EE8GM0ed\",\"Title\":\"\",\"Date\":\"2014-03-26T17:03:00Z\",\"EmailCount\":80},{\"Source\":\"Pastebin\",\"ID\":\"8Q0BvKD8\",\"Title\":\"syslog\",\"Date\":\"2014-03-04T19:03:00Z\",\"EmailCount\":139},{\"Source\":\"Pastebin\",\"ID\":\"C4GdBDnP\",\"Title\":\"#secuinside13 logs\",\"Date\":\"2013-05-26T22:05:00Z\",\"EmailCount\":255},{\"Source\":\"AdHocUrl\",\"ID\":\"http://siph0n.in/exploits.php?id=4364\",\"Title\":\"siph0n.in\",\"Date\":\"\",\"EmailCount\":89270},{\"Source\":\"AdHocUrl\",\"ID\":\"http://siph0n.in/exploits.php?id=1154\",\"Title\":\"siph0n.in\",\"Date\":\"\",\"EmailCount\":1595}]"
)

func TestGoPwned(t *testing.T) {
	assert := assert.New(t)

	FBTest := GetAllBreachesForAccount("foo@bar.com", "adobe.com")
	assert.Equal(FOOBAR, FBTest, "they should be equal")

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
