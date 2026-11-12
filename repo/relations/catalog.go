package relations

import (
	"context"
	"slices"

	"gochen-runtime/db/orm/repo"
	"gochen/app/query"
	"gochen/db/orm"
	"gochen/domain"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
)

// Link connects the requested source with a conditionally visible target.
type Link struct{ SourceID, TargetID int64 }
type Catalog[T any] struct {
	Links []Link
	Items []T
}

// Read joins the actual target repository, applies its condition before reading
// associations, and then loads complete targets with the same condition.
// Join and column arguments are assembly constants supplied by the owning repository.
func Read[T domain.IEntity[int64]](ctx context.Context, target *repo.Repo[T, int64], sourceIDs []int64, condition spec.Spec, join orm.Join, sourceColumn, targetColumn string, filters ...orm.Condition) (Catalog[T], error) {
	var result Catalog[T]
	sources := make(map[int64]bool, len(sourceIDs))
	for _, id := range sourceIDs {
		if id <= 0 {
			return result, errors.NewCode(errors.InvalidInput, "association source ID must be positive")
		}
		sources[id] = true
	}
	unique := map[int64]bool{}
	seenLinks := map[Link]bool{}
	for start := 0; start < len(sourceIDs); start += 1000 {
		q, err := target.ScopedQueryWithSpec(ctx, condition)
		if err != nil {
			return result, err
		}
		var links []Link
		for _, filter := range filters {
			q.Where(filter.Expr, filter.Args...)
		}
		err = q.Join(join).Where(sourceColumn+" IN ?", sourceIDs[start:min(start+1000, len(sourceIDs))]).
			SelectExprUnsafe(repo.AllowUnsafeSelectExpr(), sourceColumn+" AS source_id", targetColumn+" AS target_id").Find(&links)
		if err != nil {
			return result, err
		}
		for _, link := range links {
			if !sources[link.SourceID] || link.TargetID <= 0 {
				return result, errors.NewCode(errors.Forbidden, "association result differs from the requested sources")
			}
			if !seenLinks[link] {
				result.Links = append(result.Links, link)
				seenLinks[link] = true
			}
			unique[link.TargetID] = true
		}
	}
	ids := make([]int64, 0, len(unique))
	for id := range unique {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for start := 0; start < len(ids); start += 1000 {
		values := make([]any, 0, 1000)
		for _, id := range ids[start:min(start+1000, len(ids))] {
			values = append(values, id)
		}
		items, err := target.Query(ctx, query.QueryOptions{Limit: 1000, Sorts: []query.Sort{{Field: "id", Direction: query.ASC}}}, spec.And(condition, spec.In(meta.ID(), values...)))
		if err != nil {
			return result, err
		}
		result.Items = append(result.Items, items...)
	}
	return result, nil
}
