package entity

import "gorm.io/gorm"

// SetupJoinTables 注册带额外字段的关联表模型，确保 AutoMigrate 使用正式表结构。
func SetupJoinTables(db *gorm.DB) error {
	if db == nil {
		return nil
	}
	if err := db.SetupJoinTable(&User{}, "Roles", &UserRoleBinding{}); err != nil {
		return err
	}
	if err := db.SetupJoinTable(&Role{}, "Users", &UserRoleBinding{}); err != nil {
		return err
	}
	return nil
}
