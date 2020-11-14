package jwt

import (
	"time"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
)

var identityKey = "user_id"
var projectIdentityKey = "project_id"

type ProjectUserId struct {
	UserId    string
	ProjectId string
}

type ProjectTokenSolver struct {
	Token string
}

func NewProjectTokenSolver(token string) *ProjectTokenSolver {
	return &ProjectTokenSolver{token}
}

func (pts *ProjectTokenSolver) CreateMiddleware() (jwt.GinJWTMiddleware, error) {
	authMiddleware, err := jwt.New(&jwt.GinJWTMiddleware{
		Realm:       "test zone",
		Key:         []byte(pts.Token),
		Timeout:     time.Hour,
		MaxRefresh:  time.Hour,
		IdentityKey: identityKey,
		PayloadFunc: func(data interface{}) jwt.MapClaims {
			if v, ok := data.(*ProjectUserId); ok {
				return jwt.MapClaims{
					identityKey: v.UserId,
				}
			}
			return jwt.MapClaims{}
		},
		IdentityHandler: pts.GetIdentity,
		Authenticator: func(c *gin.Context) (interface{}, error) {
			return ProjectUserId{}, nil
		},
		Authorizator: func(data interface{}, c *gin.Context) bool {
			return true
		},
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.JSON(code, gin.H{
				"code":    code,
				"message": message,
			})
		},

		TokenLookup:   "header: Authorization, query: token, cookie: jwt",
		TokenHeadName: "Bearer",
		TimeFunc:      time.Now,
	})
	return *authMiddleware, err
}

func (pts *ProjectTokenSolver) GetIdentity(c *gin.Context) interface{} {
	claims := jwt.ExtractClaims(c)
	return &ProjectUserId{
		UserId:    claims[identityKey].(string),
		ProjectId: claims[projectIdentityKey].(string),
	}
}

func (pts *ProjectTokenSolver) ValidateAccess(c *gin.Context) bool {
	identity := pts.GetIdentity(c).(*ProjectUserId)
	resourceOwner := pts.getResourceProject(c)

	if resourceOwner != identity.ProjectId {
		return false
	}
	return true
}

func (pts *ProjectTokenSolver) getResourceProject(c *gin.Context) string {
	return c.Param("project")
}

func (pts *ProjectTokenSolver) ValidateIdentity(Id string, c *gin.Context) bool {
	identity := pts.GetIdentity(c).(*ProjectUserId)
	if Id != identity.UserId {
		return false
	}
	return true
}
