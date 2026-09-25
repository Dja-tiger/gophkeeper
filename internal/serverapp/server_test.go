package serverapp

import (
	"context"
	"io"
	"testing"
)

func TestInvalidConfiguration(t *testing.T) {
	for _, args := range [][]string{{}, {"--unknown"}, {"--listen", "bad"}, {"--dev-http", "--listen", "0.0.0.0:8443"}, {"--dev-http"}, {"--tls-cert", "missing", "--tls-key", "missing"}, {"extra"}} {
		if e := Run(context.Background(), args, func(string) string { return "" }, io.Discard); e == nil {
			t.Fatal("accepted", args)
		}
	}
}
