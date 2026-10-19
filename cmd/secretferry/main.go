// Command secretferry moves a secret from where it is kept to where it is used.
package main

import (
	"os"

	"github.com/maddiecs84/secretferry/internal/app"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

func main() {
	os.Exit(app.Run(os.Args[1:], app.DefaultEnv(version)))
}
