package go_kit

import (
	"github.com/google/wire"
	"github.com/crypto-zero/go-kit/maxmind"
	"github.com/crypto-zero/go-kit/otel"
	"github.com/crypto-zero/go-kit/pprof"
)

var ProviderSet = wire.NewSet(
	pprof.NewPProfImpl,
	otel.NewTraceProvider,
	maxmind.ContainerPath,
	maxmind.NewDatabaseImpl,
)
