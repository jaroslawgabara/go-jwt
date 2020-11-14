package jwt

import (
	"time"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
)

type UserId struct {
	UserId string
}

type UserTokenSolver struct {
	Token string
}

func NewUserTokenSolver(token string) *UserTokenSolver {
	return &UserTokenSolver{token}
}

func (pts *UserTokenSolver) CreateMiddleware() (jwt.GinJWTMiddleware, error) {
	authMiddleware, err := jwt.New(&jwt.GinJWTMiddleware{
		Realm:       "test zone",
		Key:         []byte(pts.Token),
		Timeout:     time.Hour,
		MaxRefresh:  time.Hour,
		IdentityKey: identityKey,
		PayloadFunc: func(data interface{}) jwt.MapClaims {
			if v, ok := data.(*UserId); ok {
				return jwt.MapClaims{
					identityKey: v.UserId,
				}
			}
			return jwt.MapClaims{}
		},
		IdentityHandler: pts.GetIdentity,
		Authenticator: func(c *gin.Context) (interface{}, error) {
			return UserId{}, nil
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

func (pts *UserTokenSolver) GetIdentity(c *gin.Context) interface{} {
	claims := jwt.ExtractClaims(c)
	return &UserId{
		UserId: claims[identityKey].(string),
	}
}

func (pts *UserTokenSolver) ValidateAccess(c *gin.Context) bool {
	identity := pts.GetIdentity(c).(*UserId)
	resourceOwner := pts.getUserFromRequest(c)

	if resourceOwner != identity.UserId {
		return false
	}
	return true
}

func (pts *UserTokenSolver) getUserFromRequest(c *gin.Context) string {
	return c.Param("userId")
}

func (pts *UserTokenSolver) ValidateIdentity(Id string, c *gin.Context) bool {
	identity := pts.GetIdentity(c).(*UserId)
	if Id != identity.UserId {
		return false
	}
	return true
}
