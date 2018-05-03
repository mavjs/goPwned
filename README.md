goPwned
=======
[![Go Report Card](https://goreportcard.com/badge/github.com/mavjs/goPwned)](https://goreportcard.com/report/github.com/mavjs/goPwned)
[![GoDoc](https://godoc.org/github.com/mavjs/goPwned?status.svg)](https://godoc.org/github.com/mavjs/goPwned)
[![Build Status](https://travis-ci.org/mavjs/goPwned.svg?branch=master)](https://travis-ci.org/mavjs/goPwned)
[![Coverage Status](https://coveralls.io/repos/mavjs/goPwned/badge.svg?branch=master&service=github)](https://coveralls.io/github/mavjs/goPwned?branch=master)

A golang library for HaveIBeenPwned REST API - 
[https://haveibeenpwned.com/](https://haveibeenpwned.com/)

Installation
------------

```go get github.com/mavjs/goPwned```

Usage
-----
### Breaches 

#### Getting all breaches for an account

##### Get all breaches for an account across all domains.

```go
import (
    "github.com/mavjs/goPwned"
    )

func main() {
    fmt.Println(gopwned.GetBreachesForAccount("foo@bar.com"))
}
```

##### Get all breaches for an account across a particular domain.

```go
import (
    "github.com/mavjs/goPwned"
    )

func main() {
    fmt.Println(gopwned.GetBreachesForAccount("foo@bar.com", "adobe.com"))
}
```

#### Getting all breached sites in the system

##### Get all the details of each breach in the system

```go
import (
    "github.com/mavjs/goPwned"
    )

func main() {
    fmt.Println(gopwned.AllBreaches())
}
```

##### Get all the details of breached site

```go
import (
    "github.com/mavjs/goPwned"
    )

func main() {
    fmt.Println(gopwned.AllBreaches("adobe.com"))
}
```

#### Getting a single breached site in the system

```go
import (
    "github.com/mavjs/goPwned"
    )

func main() {
    fmt.Println(gopwned.GetSingleBreachedSite("adobe"))
}
```

#### Getting all data classes in the system

```go
import (
    "github.com/mavjs/goPwned"
    )

func main() {
    fmt.Println(gopwned.GetAllDataClasses())
}
```

### Pastes

#### Getting all pastes for an account

```go
import (
    "github.com/mavjs/goPwned"
    )

func main() {
    fmt.Println(gopwned.GetAllPastesForAccount("foo@bar.com"))
}
```

License
-------
MIT
