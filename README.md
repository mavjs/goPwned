goPwned
=======
[![Go Report Card](https://goreportcard.com/badge/github.com/mavjs/goPwned)](https://goreportcard.com/report/github.com/mavjs/goPwned)
[![GoDoc](https://godoc.org/github.com/mavjs/goPwned?status.svg)](https://godoc.org/github.com/mavjs/goPwned)
[![Build Status](https://travis-ci.org/mavjs/goPwned.svg?branch=master)](https://travis-ci.org/mavjs/goPwned)
[![Coverage Status](https://coveralls.io/repos/github/mavjs/goPwned/badge.svg)](https://coveralls.io/github/mavjs/goPwned)

A golang library for HaveIBeenPwned REST API -
[https://haveibeenpwned.com/](https://haveibeenpwned.com/)

Installation
------------

```go get github.com/mavjs/goPwned```

Usage
-----
### Setup client with API token
**Note:** Have I Been Pwned API V3 requires an API Key for retrieveing all breaches and or pastes for an account. Please see here: https://haveibeenpwned.com/API/v3#Authorisation
```go
import (
    gopwned "github.com/mavjs/goPwned"
)

func main() {
    gopwned := gopwned.NewClient(nil, "APIKEY")
}
```
### Breaches

#### Getting all breaches for an account
https://haveibeenpwned.com/API/v3#BreachesForAccount
```go
import (
    gopwned "github.com/mavjs/goPwned"
)

func main() {
	gopwned := gopwned.NewClient(nil, "APIKEY")

	acc_breaches, err := gopwned.GetAccountBreaches("foo@bar.com", "", false, true)
	if err != nil {
		panic(err)
	}
	for _, breach := range acc_breaches {
		fmt.Println(breach)
	}
}
```

##### Get all breaches for an account across a particular domain.
https://haveibeenpwned.com/API/v3#BreachesForAccount
```go
import (
    gopwned "github.com/mavjs/goPwned"
)

func main() {
    gopwned := gopwned.NewClient(nil, "APIKEY")

	acc_breaches, err := gopwned.GetAccountBreaches("foo@bar.com", "adobe.com", false, true)
	if err != nil {
		panic(err)
	}
	for _, breach := range acc_breaches {
		fmt.Println(breach)
	}
}
```

#### Getting all breached sites in the system
https://haveibeenpwned.com/API/v3#AllBreaches
```go
import (
    gopwned "github.com/mavjs/goPwned"
)

func main() {
	gopwned := gopwned.NewClient(nil, "")

	breaches, err := gopwned.GetBreachedSites("")
	if err != nil {
		panic(err)
	}
	for _, breach := range breaches {
		fmt.Println(breach)
	}
}
```

#### Getting a single breached site in the system
https://haveibeenpwned.com/API/v3#SingleBreach

```go
import (
    gopwned "github.com/mavjs/goPwned"
)

func main() {
	gopwned := gopwned.NewClient(nil, "")

	breached_site, err := gopwned.GetABreachedSite("adobe")
	if err != nil {
		panic(err)
	}
	fmt.Println(breached_site)
}
```

#### Getting all data classes in the system
https://haveibeenpwned.com/API/v3#AllDataClasses
```go
import (
    gopwned "github.com/mavjs/goPwned"
)

func main() {
	gopwned := gopwned.NewClient(nil, "")

	data_classes, err := gopwned.GetDataClasses()
	if err != nil {
		panic(err)
	}
	fmt.Println(data_classes)
}
```

### Pastes

#### Getting all pastes for an account
https://haveibeenpwned.com/API/v3#PastesForAccount

```go
import (
    gopwned "github.com/mavjs/goPwned"
)

func main() {
	gopwned := gopwned.NewClient(nil, "APIKEY")

	pastes, err := gopwned.GetAccountPastes("foo@bar.com")
	if err != nil {
		panic(err)
	}
	for _, paste := range pastes {
		fmt.Println(paste)
	}
}
```

### Pwned Passwords

#### Searching by range
https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange

```go
import (
	"crypto/sha1"
	"fmt"
	"strconv"
	"strings"

	gopwned "github.com/mavjs/goPwned"
)

func fakeinput() string {
	inputPassword := "P@ssw0rd"
	h := sha1.New()
	h.Write([]byte(inputPassword))
	password := fmt.Sprintf("%X", h.Sum(nil)) // hash = "21BD12DC183F740EE76F27B78EB39C8AD972A757"

	return password
}

func main() {
	gopwned := gopwned.NewClient(nil, "")

	pwdhash := fakeinput()
	frange := pwdhash[0:5]
	lrange := pwdhash[5:40]

	karray, err := gopwned.GetPwnedPasswords(frange, false)
	if err != nil {
		panic("unable to get pwned passwords")
	}

	str_karray := string(karray)
	respArray := strings.Split(str_karray, "\r\n")

	var result int64
	for _, resp := range respArray {
		str_array := strings.Split(resp, ":")
		test := str_array[0]

		count, err := strconv.ParseInt(str_array[1], 0, 32)
		if err != nil {
			fmt.Printf("%#v", str_array[1])
			panic("unable to convert string into integer")
		}
		if test == lrange {
			result = count
		}
	}

	fmt.Println("This password has been seen:", result)
}
```
Development & Testing
----------
* Get an API key at: https://haveibeenpwned.com/API/Key
* Set `HIBP_API_KEY=<your api key>` in `.env` file
* If using VS Code:
  * Use the `Testing` tab to run tests, it should pick up the API key as environement variable to run tests that require the API key.
* If others:
  * Use `make tests`

License
-------
MIT
