// Go HTTP service with authz risks. Fixture for mopmonk-vuln-hunting eval.
//
// Contains:
// - GET  /profile: 从 URL param 读 user_id，无鉴权 (IDOR)
// - POST /admin/delete_user: 只 check 了 header X-Role=admin，可被伪造 (弱鉴权)
// - GET  /me: 从 JWT 解出 user_id，正确
// - POST /orders/{id}: 校验了 order.owner == session.user_id，正确

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type User struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Role string `json:"role"`
}

func handleProfile(w http.ResponseWriter, r *http.Request) {
	uid := r.URL.Query().Get("user_id") // 无鉴权，任意读
	u := loadUser(uid)
	json.NewEncoder(w).Encode(u)
}

func handleAdminDelete(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Role") != "admin" { // 客户端可控 header
		http.Error(w, "forbidden", 403)
		return
	}
	uid := r.URL.Query().Get("user_id")
	deleteUser(uid)
	fmt.Fprintln(w, "ok")
}

func handleMe(w http.ResponseWriter, r *http.Request) {
	claims, err := parseJWT(r.Header.Get("Authorization"))
	if err != nil {
		http.Error(w, "unauth", 401)
		return
	}
	u := loadUser(claims.UserID)
	json.NewEncoder(w).Encode(u)
}

func handleOrderUpdate(w http.ResponseWriter, r *http.Request) {
	sess, ok := getSession(r)
	if !ok {
		http.Error(w, "unauth", 401)
		return
	}
	orderID := r.PathValue("id")
	order := loadOrder(orderID)
	if order.OwnerID != sess.UserID {
		http.Error(w, "forbidden", 403)
		return
	}
	updateOrder(order)
	fmt.Fprintln(w, "ok")
}

// ---- stubs ----
func loadUser(id string) User             { return User{} }
func deleteUser(id string)                {}
func parseJWT(t string) (*Claims, error)  { return &Claims{}, nil }
func getSession(r *http.Request) (*Session, bool) { return &Session{}, true }
func loadOrder(id string) *Order          { return &Order{} }
func updateOrder(o *Order)                {}

type Claims struct{ UserID string }
type Session struct{ UserID string }
type Order struct{ OwnerID string }

func main() {
	http.HandleFunc("/profile", handleProfile)
	http.HandleFunc("/admin/delete_user", handleAdminDelete)
	http.HandleFunc("/me", handleMe)
	http.HandleFunc("/orders/{id}", handleOrderUpdate)
	http.ListenAndServe(":8080", nil)
}
