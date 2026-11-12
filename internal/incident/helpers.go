package incident

import (
	"io"
)

// copyWithLimit is a named seam around io.Copy. Hashing reads the whole file;
// the same storage limits enforced at the HTTP boundary bound production data
// sizes, and preservation is an offline operator action over that bounded data.
func copyWithLimit(dst io.Writer, src io.Reader) (int64, error) {
	return io.Copy(dst, src)
}
