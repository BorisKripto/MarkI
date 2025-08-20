package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type State string

const (
	StateCreated   State = "created"
	StatePurchased State = "purchased"
	StateClaimed   State = "claimed"
	StateRevoked   State = "revoked"
)

type Metadata struct {
	Name           string   `json:"name"`
	ManufacturedAt string   `json:"manufacturedAt"`
	Serial         string   `json:"serial"`
	Certificates   []string `json:"certificates"`
	Image          string   `json:"image"`
	Version        int      `json:"version"`
}

type Product struct {
	ID         int64    `json:"id"`
	Meta       Metadata `json:"meta"`
	IPFSHash   string   `json:"ipfsHash"`   // mock
	SerialHash string   `json:"serialHash"` // sha256(serial)
	State      State    `json:"state"`
	CreatedAt  int64    `json:"createdAt"`
	QRPayload  any      `json:"qrPayload"`
}

type ClaimTicket struct {
	TicketID string `json:"ticketId"`
	TokenID  int64  `json:"tokenId"`
	Nonce    string `json:"n"`
	Exp      int64  `json:"exp"`
	CT       string `json:"ct"` // email|phone
	V        int    `json:"v"`
	Payload  any    `json:"payload"`
	Used     bool   `json:"used"`
}

type ErrorResp struct {
	Error string `json:"error"`
}

var (
	mu       sync.RWMutex
	products       = make(map[int64]*Product)
	tickets        = make(map[string]*ClaimTicket)
	idSeq    int64 = 100000 // start token ids
)

func main() {
	rand.Seed(time.Now().UnixNano())

	mux := http.NewServeMux()
	// health
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "time": time.Now().UTC()})
	})

	// MANUFACTURER
	mux.HandleFunc("/api/manufacturer/products", withCORS(manufacturerCreateProduct))
	mux.HandleFunc("/api/products", withCORS(productsList))              // GET
	mux.HandleFunc("/api/products/", withCORS(productActions))           // POST /purchase
	mux.HandleFunc("/api/labels/qrcode", withCORS(generateLabelPayload)) // optional
	mux.HandleFunc("/api/claim/issue", withCORS(issueClaimTicket))       // POST
	mux.HandleFunc("/api/claim/redeem", withCORS(redeemClaimTicket))     // POST

	// USER
	mux.HandleFunc("/api/verify/", withCORS(verifyProduct)) // GET /api/verify/{id}

	port := os.Getenv("PORT")
	if port == "" {
    port = "4500" // локально
	}
	addr := ":" + port
	log.Println("MARKI Secure backend running at", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// ---------- Handlers ----------

type createReq struct {
	Serial       string `json:"serial"`
	Name         string `json:"name"`
	Date         string `json:"date"`
	Certificates string `json:"certificates"` // comma separated
	Image        string `json:"image"`
}

func manufacturerCreateProduct(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		returnOK(w)
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, 405, ErrorResp{"Method not allowed"})
		return
	}

	var req createReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, ErrorResp{"invalid json"})
		return
	}
	if strings.TrimSpace(req.Serial) == "" || strings.TrimSpace(req.Name) == "" {
		writeJSON(w, 400, ErrorResp{"serial and name are required"})
		return
	}

	meta := Metadata{
		Name:           req.Name,
		ManufacturedAt: ifEmpty(req.Date, time.Now().Format("2006-01-02")),
		Serial:         req.Serial,
		Certificates:   splitCSV(req.Certificates),
		Image:          req.Image,
		Version:        1,
	}
	ipfsHash := sha256HexJSON(meta)[:46]
	serialHash := sha256Hex(req.Serial)
	tokenID := nextID()

	payload := map[string]any{
		"t":   "prod",
		"std": "1155",
		"id":  tokenID,
		"s":   serialHash,
		"iss": "MID_DEMO",
		"v":   1,
	}
	payload["sig"] = mockSign(payload)

	p := &Product{
		ID:         tokenID,
		Meta:       meta,
		IPFSHash:   ipfsHash,
		SerialHash: serialHash,
		State:      StateCreated,
		CreatedAt:  time.Now().UnixMilli(),
		QRPayload:  payload,
	}
	mu.Lock()
	products[p.ID] = p
	mu.Unlock()

	writeJSON(w, http.StatusCreated, p)
}

func productsList(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		returnOK(w)
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, 405, ErrorResp{"Method not allowed"})
		return
	}

	mu.RLock()
	defer mu.RUnlock()
	out := make([]*Product, 0, len(products))
	for _, p := range products {
		out = append(out, p)
	}
	writeJSON(w, 200, out)
}

// /api/products/{id}/purchase
func productActions(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		returnOK(w)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/products/"), "/")
	if len(parts) == 0 {
		writeJSON(w, 404, ErrorResp{"not found"})
		return
	}
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		writeJSON(w, 400, ErrorResp{"bad id"})
		return
	}

	if len(parts) == 2 && parts[1] == "purchase" && r.Method == http.MethodPost {
		mu.Lock()
		defer mu.Unlock()
		p, ok := products[id]
		if !ok {
			writeJSON(w, 404, ErrorResp{"product not found"})
			return
		}
		p.State = StatePurchased
		writeJSON(w, 200, map[string]any{"ok": true, "state": p.State})
		return
	}
	writeJSON(w, 404, ErrorResp{"not found"})
}

func generateLabelPayload(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		returnOK(w)
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, 405, ErrorResp{"Method not allowed"})
		return
	}

	var body struct {
		TokenID int64 `json:"tokenId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, ErrorResp{"invalid json"})
		return
	}
	mu.RLock()
	p, ok := products[body.TokenID]
	mu.RUnlock()
	if !ok {
		writeJSON(w, 404, ErrorResp{"product not found"})
		return
	}

	payload := map[string]any{
		"t":   "prod",
		"std": "1155",
		"id":  p.ID,
		"s":   p.SerialHash,
		"iss": "MID_DEMO",
		"v":   1,
	}
	payload["sig"] = mockSign(payload)
	writeJSON(w, 200, payload)
}

func issueClaimTicket(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		returnOK(w)
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, 405, ErrorResp{"Method not allowed"})
		return
	}

	var body struct {
		TokenID int64  `json:"tokenId"`
		To      string `json:"to"` // email or phone
		TTL     int64  `json:"ttlSeconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, ErrorResp{"invalid json"})
		return
	}
	if body.TokenID == 0 || strings.TrimSpace(body.To) == "" {
		writeJSON(w, 400, ErrorResp{"tokenId and to are required"})
		return
	}
	mu.RLock()
	p, ok := products[body.TokenID]
	mu.RUnlock()
	if !ok {
		writeJSON(w, 404, ErrorResp{"product not found"})
		return
	}

	if body.TTL <= 0 {
		body.TTL = 24 * 60 * 60
	}
	t := &ClaimTicket{
		TicketID: randID(),
		TokenID:  p.ID,
		Nonce:    randID(),
		Exp:      time.Now().Unix() + body.TTL,
		CT:       body.To,
		V:        1,
		Used:     false,
	}

	payload := map[string]any{
		"t":   "claim",
		"id":  fmt.Sprintf("%d", t.TokenID),
		"n":   t.Nonce,
		"exp": t.Exp,
		"ct":  t.CT,
		"v":   t.V,
	}
	payload["sig"] = mockSign(payload)
	t.Payload = payload

	mu.Lock()
	tickets[t.TicketID] = t
	mu.Unlock()
	writeJSON(w, 201, t)
}

func redeemClaimTicket(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		returnOK(w)
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, 405, ErrorResp{"Method not allowed"})
		return
	}

	var body struct {
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, ErrorResp{"invalid json"})
		return
	}
	var pay map[string]any
	if err := json.Unmarshal(body.Payload, &pay); err != nil {
		writeJSON(w, 400, ErrorResp{"invalid payload"})
		return
	}
	if pay["t"] != "claim" {
		writeJSON(w, 400, ErrorResp{"wrong payload type"})
		return
	}
	idStr, _ := pay["id"].(string)
	tokenID, _ := strconv.ParseInt(idStr, 10, 64)
	expF, _ := pay["exp"].(float64)
	sig, _ := pay["sig"].(string)

	// mock signature check
	if sig == "" {
		writeJSON(w, 400, ErrorResp{"missing signature"})
		return
	}
	if int64(expF) < time.Now().Unix() {
		writeJSON(w, 410, ErrorResp{"ticket expired"})
		return
	}

	mu.Lock()
	defer mu.Unlock()
	p, ok := products[tokenID]
	if !ok {
		writeJSON(w, 404, ErrorResp{"product not found"})
		return
	}
	if p.State == StateClaimed {
		writeJSON(w, 409, ErrorResp{"already claimed"})
		return
	}
	p.State = StateClaimed
	writeJSON(w, 200, map[string]any{"ok": true, "state": p.State})
}

func verifyProduct(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		returnOK(w)
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, 405, ErrorResp{"Method not allowed"})
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/api/verify/")
	tokenID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, 400, ErrorResp{"bad id"})
		return
	}

	mu.RLock()
	p, ok := products[tokenID]
	mu.RUnlock()
	if !ok {
		writeJSON(w, 404, ErrorResp{"product not found"})
		return
	}

	resp := map[string]any{
		"state":      p.State,
		"tokenId":    p.ID,
		"metadata":   p.Meta,
		"ipfsHash":   p.IPFSHash,
		"serialHash": p.SerialHash,
	}
	writeJSON(w, 200, resp)
}

// ---------- helpers ----------

func withCORS(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			returnOK(w)
			return
		}
		h.ServeHTTP(w, r)
	}
}

func returnOK(w http.ResponseWriter) {
	w.WriteHeader(http.StatusOK)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func ifEmpty(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func sha256HexJSON(v any) string {
	b, _ := json.Marshal(v)
	return sha256Hex(string(b))
}

func mockSign(payload any) string {
	h := sha256.Sum256(mustJSON(payload))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func nextID() int64 {
	mu.Lock()
	defer mu.Unlock()
	idSeq++
	return idSeq
}

func randID() string {
	return fmt.Sprintf("%x%x", rand.Uint64(), time.Now().UnixNano())
}
