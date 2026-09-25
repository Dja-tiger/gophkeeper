// Command client runs the GophKeeper command-line client.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/Dja-tiger/gophkeeper/internal/cli"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if err := cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
