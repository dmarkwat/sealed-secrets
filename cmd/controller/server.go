package main

import (
	"fmt"
	"github.com/throttled/throttled"
	"github.com/throttled/throttled/store/memstore"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

type verifier func([]byte) (bool, error)
type rotator func([]byte) ([]byte, error)

type ApiServer struct {
	mux         *http.ServeMux
	rateLimiter throttled.HTTPRateLimiter
	verFn       verifier
	rotFn       rotator
}

func NewApiServer(verFn verifier, rotFn rotator) *ApiServer {
	mux := http.NewServeMux()
	rateLimiter := rateLimter()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "ok\n")
	})

	mux.Handle("/v1/verify", rateLimiter.RateLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		content, err := ioutil.ReadAll(r.Body)

		if err != nil {
			log.Printf("Error handling /v1/verify request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		valid, err := verFn(content)

		if err != nil {
			log.Printf("Error validating secret: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if valid {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusConflict)
		}
	})))

	mux.HandleFunc("/v1/rotate", func(w http.ResponseWriter, r *http.Request) {
		content, err := ioutil.ReadAll(r.Body)

		if err != nil {
			log.Printf("Error handling /v1/rotate request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		newSecret, err := rotFn(content)

		if err != nil {
			log.Printf("Error rotating secret: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		w.Write(newSecret)
	})

	return &ApiServer{
		mux:         mux,
		rateLimiter: rateLimter(),
		verFn:       verFn,
		rotFn:       rotFn,
	}
}

func (a *ApiServer) V1(pattern string, handler http.HandlerFunc) {
	a.mux.HandleFunc(fmt.Sprintf("/v1/%s", pattern), handler)
}

func (a *ApiServer) V2(registry KeyRegistry, pattern string, handler http.HandlerFunc) {
	a.mux.HandleFunc(fmt.Sprintf("/v2/%s/%s", registry.Name(), pattern), handler)
}

func (a *ApiServer) Listen(listenAddr string, readTimeout time.Duration, writeTimeout time.Duration) {
	server := http.Server{
		Addr:         listenAddr,
		Handler:      a.mux,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
	}

	log.Printf("HTTP server serving on %s", server.Addr)
	err := server.ListenAndServe()
	log.Printf("HTTP server exiting: %v", err)
}

func rateLimter() throttled.HTTPRateLimiter {
	store, err := memstore.New(65536)
	if err != nil {
		log.Fatal(err)
	}

	quota := throttled.RateQuota{MaxRate: throttled.PerSec(2), MaxBurst: 2}
	rateLimiter, err := throttled.NewGCRARateLimiter(store, quota)
	if err != nil {
		log.Fatal(err)
	}
	return throttled.HTTPRateLimiter{
		RateLimiter: rateLimiter,
		VaryBy:      &throttled.VaryBy{Path: true, Headers: []string{"X-Forwarded-For"}},
	}
}
