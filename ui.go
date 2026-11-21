package main

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"
)

//go:embed all:webui
var webFiles embed.FS

func registerUI(mux *http.ServeMux) error {
	if _, err := fs.Stat(webFiles, "webui/dist/index.html"); err != nil {
		return fmt.Errorf("Svelte build missing: run npm --prefix frontend ci and npm --prefix frontend run build before go build")
	}
	dist, err := fs.Sub(webFiles, "webui/dist")
	if err != nil {
		return err
	}
	files := http.FileServerFS(dist)
	mux.Handle("GET /{$}", files)
	mux.Handle("GET /assets/", files)
	return nil
}
