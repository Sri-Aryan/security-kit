package main
import "net/http"
func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /orders/{id}", getOrder)
	mux.Handle("/admin", authMiddleware(http.HandlerFunc(admin)))
	http.HandleFunc("/health", health)
}
