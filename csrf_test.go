package csrf

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func newServer(options Options) *gin.Engine {
	g := gin.New()
	store := sessions.NewCookieStore([]byte("secret123"))

	g.Use(sessions.Sessions("my_session", store))
	g.Use(Middleware(options))

	return g
}

type requestOptions struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    io.Reader
}

func request(server *gin.Engine, options requestOptions) *httptest.ResponseRecorder {
	if options.Method == "" {
		options.Method = "GET"
	}

	w := httptest.NewRecorder()
	req, err := http.NewRequest(options.Method, options.URL, options.Body)

	if options.Headers != nil {
		for key, value := range options.Headers {
			req.Header.Set(key, value)
		}
	}

	server.ServeHTTP(w, req)

	if err != nil {
		panic(err)
	}

	return w
}

func TestForm(t *testing.T) {
	var token string
	g := newServer(Options{
		Secret: "secret123",
	})

	g.GET("/login", func(c *gin.Context) {
		token = GetToken(c)
	})

	g.POST("/login", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	r1 := request(g, requestOptions{URL: "/login"})
	r2 := request(g, requestOptions{
		Method: "POST",
		URL:    "/login",
		Headers: map[string]string{
			"Cookie":       r1.Header().Get("Set-Cookie"),
			"Content-Type": "application/x-www-form-urlencoded",
		},
		Body: strings.NewReader("_csrf=" + token),
	})

	if body := r2.Body.String(); body != "OK" {
		t.Error("Response is not OK: ", body)
	}
}

func TestQueryString(t *testing.T) {
	var token string
	g := newServer(Options{
		Secret: "secret123",
	})

	g.GET("/login", func(c *gin.Context) {
		token = GetToken(c)
	})

	g.POST("/login", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	r1 := request(g, requestOptions{URL: "/login"})
	r2 := request(g, requestOptions{
		Method: "POST",
		URL:    "/login?_csrf=" + token,
		Headers: map[string]string{
			"Cookie": r1.Header().Get("Set-Cookie"),
		},
	})

	if body := r2.Body.String(); body != "OK" {
		t.Error("Response is not OK: ", body)
	}
}

func TestQueryHeader1(t *testing.T) {
	var token string
	g := newServer(Options{
		Secret: "secret123",
	})

	g.GET("/login", func(c *gin.Context) {
		token = GetToken(c)
	})

	g.POST("/login", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	r1 := request(g, requestOptions{URL: "/login"})
	r2 := request(g, requestOptions{
		Method: "POST",
		URL:    "/login",
		Headers: map[string]string{
			"Cookie":       r1.Header().Get("Set-Cookie"),
			"X-CSRF-Token": token,
		},
	})

	if body := r2.Body.String(); body != "OK" {
		t.Error("Response is not OK: ", body)
	}
}

func TestQueryHeader2(t *testing.T) {
	var token string
	g := newServer(Options{
		Secret: "secret123",
	})

	g.GET("/login", func(c *gin.Context) {
		token = GetToken(c)
	})

	g.POST("/login", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	r1 := request(g, requestOptions{URL: "/login"})
	r2 := request(g, requestOptions{
		Method: "POST",
		URL:    "/login",
		Headers: map[string]string{
			"Cookie":       r1.Header().Get("Set-Cookie"),
			"X-XSRF-Token": token,
		},
	})

	if body := r2.Body.String(); body != "OK" {
		t.Error("Response is not OK: ", body)
	}
}

func TestErrorFunc(t *testing.T) {
	result := ""
	g := newServer(Options{
		Secret: "secret123",
		ErrorFunc: func(c *gin.Context) {
			result = "something wrong"
		},
	})

	g.GET("/login", func(c *gin.Context) {
		GetToken(c)
	})

	g.POST("/login", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	r1 := request(g, requestOptions{URL: "/login"})
	request(g, requestOptions{
		Method: "POST",
		URL:    "/login",
		Headers: map[string]string{
			"Cookie": r1.Header().Get("Set-Cookie"),
		},
	})

	if result != "something wrong" {
		t.Error("Error function was not called")
	}
}

func TestIgnoreMethods(t *testing.T) {
	g := newServer(Options{
		Secret:        "secret123",
		IgnoreMethods: []string{"GET", "POST"},
	})

	g.GET("/login", func(c *gin.Context) {
		GetToken(c)
	})

	g.POST("/login", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	r1 := request(g, requestOptions{URL: "/login"})
	r2 := request(g, requestOptions{
		Method: "POST",
		URL:    "/login",
		Headers: map[string]string{
			"Cookie": r1.Header().Get("Set-Cookie"),
		},
	})

	if body := r2.Body.String(); body != "OK" {
		t.Error("Response is not OK: ", body)
	}
}

// In this scenario we want to check CSRF token for all the POST requests,
// except, for example, "/paypal/notify" (which is endpoint that PayPal calls during
// a payment validation) and "/hpkp/report" (which URL where Public-Key-Pins validation failures are reported)
func TestIgnorePaths(t *testing.T) {

	var token string

	g := newServer(Options{
		Secret:      "secret123",
		IgnorePaths: []string{"/paypal/notify", "/hpkp/report"},
		ErrorFunc: func(c *gin.Context) {
			c.String(400, "CSRF token mismatch")
			c.Abort()
		},
	})

	g.GET("/login", func(c *gin.Context) {
		token = GetToken(c)
	})

	g.POST("/form", func(c *gin.Context) {
		c.String(http.StatusOK, "OK") // post some usual form
	})

	g.POST("/paypal/notify", func(c *gin.Context) {
		c.String(http.StatusOK, "OK PP")
	})

	g.POST("/hpkp/report", func(c *gin.Context) {
		c.String(http.StatusOK, "OK HPKP")
	})

	// start session, generate token
	r1 := request(g, requestOptions{URL: "/login"})
	sessionCookies := r1.Header().Get("Set-Cookie")

	// Experiment 1:
	// call the /form two times and verify that it returns OK only if we send CSRF token, otherwise it fails
	r2Ok := request(g, requestOptions{
		Method: "POST",
		URL:    "/form",
		Headers: map[string]string{
			"Cookie":       sessionCookies,
			"X-XSRF-Token": token,
		},
	})

	if body := r2Ok.Body.String(); body != "OK" {
		t.Error("Response is not OK: ", body)
	}

	r2Failure := request(g, requestOptions{
		Method: "POST",
		URL:    "/form",
		Headers: map[string]string{
			"Cookie": sessionCookies,
			// omitted CSRF token
		},
	})

	if 400 != r2Failure.Code {
		// we expect second request returns 400 because we omitted CSRF token
		t.Error("Response is not 400: ", r2Failure.Code)
	}

	// Experiment 2:
	// Even if we omitted the CSRF token for the POST request, it will be ignored
	r3 := request(g, requestOptions{
		Method: "POST",
		URL:    "/paypal/notify",
		Headers: map[string]string{
			"Cookie": sessionCookies,
			// omitted CSRF token
		},
	})

	if body := r3.Body.String(); body != "OK PP" {
		t.Error("Response is not OK: ", body)
	}

	// Experiment 3:
	// The same as above, but with another path
	r4 := request(g, requestOptions{
		Method: "POST",
		URL:    "/hpkp/report",
		Headers: map[string]string{
			"Cookie": sessionCookies,
			// omitted CSRF token
		},
	})

	if body := r4.Body.String(); body != "OK HPKP" {
		t.Error("Response is not OK: ", body)
	}
}

func TestTokenGetter(t *testing.T) {
	var token string
	g := newServer(Options{
		Secret: "secret123",
		TokenGetter: func(c *gin.Context) string {
			return c.Request.FormValue("wtf")
		},
	})

	g.GET("/login", func(c *gin.Context) {
		token = GetToken(c)
	})

	g.POST("/login", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	r1 := request(g, requestOptions{URL: "/login"})
	r2 := request(g, requestOptions{
		Method: "POST",
		URL:    "/login",
		Headers: map[string]string{
			"Cookie":       r1.Header().Get("Set-Cookie"),
			"Content-Type": "application/x-www-form-urlencoded",
		},
		Body: strings.NewReader("wtf=" + token),
	})

	if body := r2.Body.String(); body != "OK" {
		t.Error("Response is not OK: ", body)
	}
}
