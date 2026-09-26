// Package buildinfo exposes release information injected by the build pipeline.
package buildinfo

// Version is the release tag, or dev for an unversioned build.
var Version = "dev"

// Date is the UTC build timestamp, or unknown for go run.
var Date = "unknown"

// Commit identifies the source revision used to build the executable.
var Commit = "unknown"
