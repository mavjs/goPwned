goPwned
=======

A golang client for HaveIBeenPwned REST API. 
[https://haveibeenpwned.com/](https://haveibeenpwned.com/)

Installation
------------

```go get https://github.com/mavjs/goPwned```

Usage
-----
### Breaches 

#### Getting all breaches for an account

##### Get all breaches for an account across all domains.

```
import (
    "github.com/mavjs/goPwned"
    )

func main() {
    fmt.Println(gopwned.GetBreachesForAccount("foo@bar.com"))
}
```

##### Get all breaches for an account across a particular domain.

```
import (
    "github.com/mavjs/goPwned"
    )

func main() {
    fmt.Println(gopwned.GetBreachesForAccount("foo@bar.com", "adobe.com"))
}
```

#### Getting all breached sites in the system

##### Get all the details of each breach in the system

```
import (
    "github.com/mavjs/goPwned"
    )

func main() {
    fmt.Println(gopwned.AllBreaches())
}
```

##### Get all the details of breached site

```
import (
    "github.com/mavjs/goPwned"
    )

func main() {
    fmt.Println(gopwned.AllBreaches("adobe.com"))
}
```

#### Getting a single breached site in the system

```
import (
    "github.com/mavjs/goPwned"
    )

func main() {
    fmt.Println(gopwned.GetSingleBreachedSite("adobe"))
}
```

#### Getting all data classes in the system

```
import (
    "github.com/mavjs/goPwned"
    )

func main() {
    fmt.Println(gopwned.GetAllDataClasses())
}
```

### Pastes

#### Getting all pastes for an account

```
import (
    "github.com/mavjs/goPwned"
    )

func main() {
    fmt.Println(gopwned.GetAllPastesForAccount("foo@bar.com"))
}
```
