// Package web embeds the built single-page app so the portal ships as one
// binary. Run the frontend build (see web/README) to populate dist before
// compiling for release; the checked-in placeholder lets the backend build
// without a frontend toolchain.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var embedded embed.FS

func Dist() (fs.FS, error) {
	return fs.Sub(embedded, "dist")
}
