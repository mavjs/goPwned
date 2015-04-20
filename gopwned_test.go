package gopwned

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var (
	NOTFOUND = "Not found — the account could not be found and has therefore not been pwned"
	FOOBAR   = "[{Title:Adobe Name:Adobe Domain:adobe.com BreachDate:2013-10-4 PwnCount:152445165 IsVerified:true} {Title:Flashback Name:Flashback Domain:flashback.se BreachDate:2015-2-11 PwnCount:40256 IsVerified:true} {Title:Gawker Name:Gawker Domain:gawker.com BreachDate:2010-12-11 PwnCount:1247574 IsVerified:true} {Title:Stratfor Name:Stratfor Domain:stratfor.com BreachDate:2011-12-24 PwnCount:859777 IsVerified:true}]"
)

func TestGoPwned(t *testing.T) {
	assert := assert.New(t)

	FBTest := GetAllBreachesForAccount("foo@bar.com", "")
	assert.Equal(FBTest, FOOBAR, "they should be equal")

	NFResult := GetAllBreachesForAccount("mavjs01@gmail.com", "")
	assert.Equal(NFResult, NOTFOUND, "they should be equal")
}
