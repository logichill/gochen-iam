package entity

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestUserJSONMarshalOmitsPassword(t *testing.T) {
	user := &User{
		Username: "admin",
		Password: "$2a$10$sensitive-password-hash",
	}

	payload, err := json.Marshal(user)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if bytes.Contains(payload, []byte(`"password"`)) {
		t.Fatalf("password field must not be serialized: %s", payload)
	}
	if bytes.Contains(payload, []byte(user.Password)) {
		t.Fatalf("password hash must not be serialized: %s", payload)
	}
}

func TestUserJSONUnmarshalAcceptsPassword(t *testing.T) {
	user := &User{Password: "existing-password"}
	if err := json.Unmarshal([]byte(`{"username":"admin","password":"new-password"}`), user); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if user.Username != "admin" {
		t.Fatalf("Username = %q, want admin", user.Username)
	}
	if user.Password != "new-password" {
		t.Fatalf("Password = %q, want new-password", user.Password)
	}

	if err := json.Unmarshal([]byte(`{"email":"admin@example.com"}`), user); err != nil {
		t.Fatalf("Unmarshal without password: %v", err)
	}
	if user.Password != "new-password" {
		t.Fatalf("missing password field changed Password to %q", user.Password)
	}
}
