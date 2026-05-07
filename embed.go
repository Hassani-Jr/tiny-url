package main

import (
	"embed"
	"io/fs"
)

// embeddedStatic captures the static/ directory at build time so the binary
// is self-contained — no working-directory or COPY step required at deploy
// time. The go:embed directive must live in the main package (its path is
// resolved relative to the file containing the directive) so we expose the
// rooted sub-FS to the handlers package via dependency injection.
//
//go:embed static
var embeddedStatic embed.FS

// staticDirFS returns embeddedStatic rooted at "static", so handlers can
// look up "index.html" instead of "static/index.html".
func staticDirFS() fs.FS {
	sub, err := fs.Sub(embeddedStatic, "static")
	if err != nil {
		// embed paths are validated at compile time; unreachable.
		panic(err)
	}
	return sub
}
