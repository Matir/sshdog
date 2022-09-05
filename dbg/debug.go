package dbg

import (
	"fmt"
	"os"
)

type Debugger bool

func Debug(format string, args ...interface{}) {
	if dbg {
		msg := fmt.Sprintf(format, args...)
		fmt.Fprintf(os.Stderr, "[DEBUG] %s\n", msg)
	}
}

var dbg Debugger = true

func Set(enable Debugger) {
	dbg = enable
}
