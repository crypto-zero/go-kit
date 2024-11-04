package snowflake

import (
	"time"

	"github.com/bwmarrin/snowflake"
)

func init() {
	// change epoch from 2024-01-01 and 42 time bits
	// approximately 139 years 5 months 18 days
	snowflake.Epoch = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli()
	// node used 9 bits approximately 512 nodes
	snowflake.NodeBits = 9
}

// Node is a snowflake Node
type Node = snowflake.Node

// NewNode returns a new snowflake Node
func NewNode(node int) *snowflake.Node {
	n, err := snowflake.NewNode(int64(node))
	if err != nil {
		panic(err)
	}
	return n
}
