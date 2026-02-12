package event

import "time"

// UserRoleAssigned 用户角色分配事件负载
type UserRoleAssigned struct {
	UserID     int64     `json:"user_id"`
	RoleID     int64     `json:"role_id"`
	RoleCode   string    `json:"role_code"`
	AssignedAt time.Time `json:"assigned_at"`
}

func (e UserRoleAssigned) GetType() string {
	return "UserRoleAssigned"
}

// UserRoleRemoved 用户角色移除事件负载
type UserRoleRemoved struct {
	UserID    int64     `json:"user_id"`
	RoleID    int64     `json:"role_id"`
	RemovedAt time.Time `json:"removed_at"`
}

func (e UserRoleRemoved) GetType() string {
	return "UserRoleRemoved"
}
