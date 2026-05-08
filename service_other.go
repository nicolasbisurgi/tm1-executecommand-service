//go:build !windows

package main

import "fmt"

// startService runs the HTTP server in the foreground. The Windows service
// plumbing (SCM detection, event log, executeCommandService struct) lives in
// service_windows.go and is only compiled on Windows. This stub exists so the
// main package builds and tests on macOS / Linux during development.
func startService(app *App) {
	fmt.Printf("Starting ExecuteCommand service on port %d...\n", app.cfg.Server.HTTPPort)
	app.runServer()
}
