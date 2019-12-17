package main

import (
	"net/http"
)

type HTTPServer struct {
	miningService *MiningService
	srv           *http.Server
}

func NewHTTPServer(miningService *MiningService) *HTTPServer {
	mux := http.NewServeMux()

	// todo list of unconfirmed txs and current blockchain state and current node list
	mux.HandleFunc("/debug", nil)
	mux.HandleFunc("/mining/start", nil)
	mux.HandleFunc("/mining/stop", nil)

	srv := &http.Server{
		Handler: mux,
		Addr:    "127.0.0.1:8080",
	}

	return &HTTPServer{
		miningService: miningService,
		srv:           srv,
	}
}

func (s *HTTPServer) Start() error {
	err := s.srv.ListenAndServe()
	return err
}
