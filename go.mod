module gochen-iam

go 1.24.1

require (
	github.com/golang-jwt/jwt/v4 v4.5.2
	gochen v0.0.0
	golang.org/x/crypto v0.47.0
	gorm.io/driver/sqlite v1.6.0
	gorm.io/gorm v1.30.0
)

require (
	github.com/google/uuid v1.6.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/mattn/go-sqlite3 v1.14.22 // indirect
	golang.org/x/text v0.33.0 // indirect
)

replace gochen => github.com/logichill/gochen v0.0.0-20260212152207-227b57c07397
