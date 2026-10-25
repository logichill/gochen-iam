// Package likesafe 构造 LIKE 包含匹配的安全模式。
//
// 值中的通配符（% _）与转义符自身（!）会被转义，必须配合 SQL 中显式
// 的 ESCAPE '!' 子句使用；'!' 作为转义字符在 SQLite/MySQL/Postgres 上
// 均可移植，避免反斜杠在 MySQL 字符串字面量中的差异。
package likesafe

import "strings"

// EscapeClause 供 LIKE 表达式拼接的显式转义子句（转义字符 '!'）。
const EscapeClause = " ESCAPE '!'"

var escaper = strings.NewReplacer("!", "!!", "%", "!%", "_", "!_")

// ContainsPattern 返回包含匹配模式 %value%，并转义 LIKE 通配符。
func ContainsPattern(value string) string {
	return "%" + escaper.Replace(value) + "%"
}
