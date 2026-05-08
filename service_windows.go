//go:build windows

package main

import (
	"fmt"
	"log"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
)

// elog is the Windows event log — kept package-level since it's only set at startup.
var elog debug.Log

type executeCommandService struct {
	app *App
}

func (m *executeCommandService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}
	go m.app.runServer()
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

loop:
	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			break loop
		default:
			elog.Error(1, fmt.Sprintf("Unexpected service control request #%d", c.Cmd))
		}
	}
	changes <- svc.Status{State: svc.StopPending}
	return
}

func runWindowsService(name string, app *App) {
	run := svc.Run
	elog.Info(1, fmt.Sprintf("starting %s service on port %d", name, app.cfg.Server.HTTPPort))
	err := run(name, &executeCommandService{app: app})
	if err != nil {
		elog.Error(1, fmt.Sprintf("service %s failed: %v", name, err))
		return
	}
	elog.Info(1, fmt.Sprintf("service %s stopped", name))
}

// startService is the platform entrypoint. On Windows, it detects whether
// we're running under the Service Control Manager and dispatches accordingly;
// otherwise it runs as a foreground HTTP server.
func startService(app *App) {
	isWindowsService, err := svc.IsWindowsService()
	if err != nil {
		log.Fatalf("Failed to determine if we are running in a windows service: %v", err)
	}

	if isWindowsService {
		elog, err = eventlog.Open("ExecuteCommandService")
		if err != nil {
			return
		}
		defer elog.Close()
		runWindowsService("ExecuteCommandService", app)
	} else {
		fmt.Printf("Starting ExecuteCommand service on port %d...\n", app.cfg.Server.HTTPPort)
		elog = debug.New("ExecuteCommandService")
		app.runServer()
	}
}
