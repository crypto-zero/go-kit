package snowflake

import (
	"time"

	"github.com/bwmarrin/snowflake"
)

func init() {
	// Use a 2024-01-01 epoch with 42 time bits, covering roughly 139 years.
	snowflake.Epoch = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli()
	// Use 9 node bits, supporting roughly 512 nodes.
	snowflake.NodeBits = 9
}

// Node is a snowflake node.
type Node = snowflake.Node

// NewNode returns a new snowflake node.
func NewNode(node int) *snowflake.Node {
	n, err := snowflake.NewNode(int64(node))
	if err != nil {
		panic(err)
	}
	return n
}
