module gochen-iam

go 1.27.0

require (
	github.com/golang-jwt/jwt/v4 v4.5.2
	github.com/mattn/go-sqlite3 v1.14.22
	github.com/stretchr/testify v1.11.1
	gochen v0.0.0
	gochen-runtime v0.0.0
	golang.org/x/crypto v0.47.0
	gorm.io/driver/sqlite v1.6.0
	gorm.io/gorm v1.30.0
)

replace (
	gochen => ../gochen
	gochen-runtime => ../gochen-runtime
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/text v0.33.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
