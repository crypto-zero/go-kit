package zap

import (
	"context"
	"os"

	"go.uber.org/zap/zapcore"
)

func testValuer(ctx context.Context) any {
	return "test-valuer"
}

var counter = 0

func testCounter(ctx context.Context) any {
	counter++
	return counter
}

func ExampleZap() {
	z := &Zap{writer: os.Stdout}

	cfg := z.NewEncoderConfig()
	cfg.TimeKey = ""

	core := z.NewCore(cfg, zapcore.DebugLevel)

	logger := z.SlogWithCore(core)
	logger = logger.With(LoggerNamed, "test")
	logger.Info("hello from slog")

	zapLogger := z.LoggerWithCore(core)
	zapLogger.Info("hello from zap")

	type x func(context.Context) any
	var counter x = testCounter
	logger = logger.With(LoggerNamed, "zap").With("counter", Valuer(counter))
	logger.Info("counting")
	logger.Info("counting")

	logger.With("x", "x").Info("x")

	logger = z.SlogWithCore(z.NewMixedConsoleCore(cfg, zapcore.DebugLevel, zapcore.WarnLevel))
	logger.Warn("a warning")

	// Output:
	// {"level":"INFO","logger":"test","msg":"hello from slog"}
	// {"level":"INFO","msg":"hello from zap"}
	// {"level":"INFO","logger":"test.zap","msg":"counting","counter":1}
	// {"level":"INFO","logger":"test.zap","msg":"counting","counter":2}
	// {"level":"INFO","logger":"test.zap","msg":"x","x":"x","counter":3}
	// {"level":"WARN","msg":"a warning"}
	// {"level":"WARN","msg":"a warning"}
}
