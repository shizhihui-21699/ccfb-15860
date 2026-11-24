// Command cabinetd runs a cabinet controller's HTTP API: the local operator
// console plus the device side of HQ sync. It is deliberately small — all
// policy lives in internal/.
//
// Because this is a simulator build, it wires the in-memory hardware stack. A
// production build would substitute drivers implementing access.Actuator,
// session.Scale and the fob reader; nothing in this file would change except
// the construction of those drivers.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"hazmatcontrol/internal/model"
	"hazmatcontrol/internal/server"
	"hazmatcontrol/internal/session"
	"hazmatcontrol/internal/sim"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	dataDir := flag.String("data", "./cabinet-data", "durable data directory (ledger, seal, outbox)")
	flag.Parse()

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		log.Fatalf("data dir: %v", err)
	}
	st, err := sim.New(*dataDir, time.Now().UTC())
	if err != nil {
		log.Fatalf("boot controller: %v", err)
	}
	if st.Edge.Degraded {
		log.Printf("WARNING: controller is DEGRADED (log behind seal); cabinets must stay locked until audited")
	}

	factory := func(id string, p model.Product, authGrams float64, a, b model.OperatorID) (*session.Session, error) {
		return st.NewSession(id, p, authGrams, a, b)
	}

	srv := server.New(st.Edge, factory)
	log.Printf("cabinetd listening on %s (data %s)", *addr, *dataDir)
	if err := http.ListenAndServe(*addr, srv.Handler()); err != nil {
		log.Fatal(err)
	}
}
