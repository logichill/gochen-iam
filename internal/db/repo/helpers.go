package repo

import (
	"fmt"
	"strings"

	idb "gochen-iam/internal/db"
)

func (r *Repo[T]) applyAdvancedFilters(q *queryBuilder, advanced map[string]any) *queryBuilder {
	for key, value := range advanced {
		switch key {
		case "or":
			if conditions, ok := value.([]map[string]string); ok {
				expr, args := buildOrCondition(conditions)
				if expr != "" {
					q = q.Where(expr, args...)
				}
			}
		case "date_range":
			if dateRange, ok := value.(map[string]string); ok {
				if startDate, exists := dateRange["start"]; exists && startDate != "" {
					q = q.Where("created_at >= ?", startDate)
				}
				if endDate, exists := dateRange["end"]; exists && endDate != "" {
					q = q.Where("created_at <= ?", endDate)
				}
			}
		case "custom_where":
			if customWhere, ok := value.(map[string]any); ok {
				if query, exists := customWhere["query"]; exists {
					if args, exists := customWhere["args"]; exists {
						q = q.Where(fmt.Sprint(query), args)
					} else {
						q = q.Where(fmt.Sprint(query))
					}
				}
			}
		}
	}
	return q
}

func (r *Repo[T]) applySorting(q *queryBuilder, options *idb.QueryOptions) *queryBuilder {
	if len(options.Sorts) > 0 {
		for field, direction := range options.Sorts {
			if direction.IsValid() {
				q = q.Order(field, strings.EqualFold(string(direction), "desc"))
			}
		}
		return q
	}
	if options.Order != "" {
		q = q.Order(resolveOrderField(options), strings.EqualFold(options.Order, "desc"))
	}
	return q
}

func resolveOrderField(options *idb.QueryOptions) string {
	if len(options.Fields) > 0 && options.Fields[0] != "" {
		return options.Fields[0]
	}
	return "id"
}

func buildOrCondition(conditions []map[string]string) (string, []any) {
	var exprs []string
	var args []any
	for _, condition := range conditions {
		if len(condition) == 0 {
			continue
		}
		var inner []string
		var innerArgs []any
		for key, value := range condition {
			inner = append(inner, fmt.Sprintf("%s = ?", key))
			innerArgs = append(innerArgs, value)
		}
		if len(inner) > 0 {
			exprs = append(exprs, "("+strings.Join(inner, " AND ")+")")
			args = append(args, innerArgs...)
		}
	}
	return strings.Join(exprs, " OR "), args
}

// toStringMap 将 map[string]interface{} 转为 map[string]string（主要用于查询参数来自 URL）
func toStringMap(src map[string]interface{}) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = fmt.Sprint(v)
	}
	return dst
}
