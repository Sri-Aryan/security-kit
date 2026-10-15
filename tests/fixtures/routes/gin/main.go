package main
import "github.com/gin-gonic/gin"
func main() {
	r := gin.Default()
	r.GET("/ping", ping)
	api := r.Group("/api", AuthRequired())
	api.GET("/orders/:id", getOrder)
	admin := api.Group("/admin")
	admin.DELETE("/users/:id", deleteUser)
	r.POST("/login", login)
}
