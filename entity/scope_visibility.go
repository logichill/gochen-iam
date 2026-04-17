package entity

// ScopeVisibility 预展开记录“viewer scope 可见哪些 target scope”。
type ScopeVisibility struct {
	ViewerScopeID int64 `json:"viewer_scope_id" gorm:"primaryKey;autoIncrement:false"`
	TargetScopeID int64 `json:"target_scope_id" gorm:"primaryKey;autoIncrement:false"`
	Distance      int   `json:"distance" gorm:"not null;default:0;index"`
}

// TableName 指定表名。
func (ScopeVisibility) TableName() string {
	return "scope_visibility_map"
}
