package zap

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"

	"go.uber.org/zap"
	"go.uber.org/zap/exp/zapslog"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	// LoggerNamed is the key for logger name in slog attributes.
	LoggerNamed = "__LOGGER.NAMED__"
	// DefaultRotateSizeInMB is the default rotate size in MB.
	DefaultRotateSizeInMB = 1024
	// DefaultRotateAgeInDays is the default rotate age in days.
	DefaultRotateAgeInDays = 15
)

// Adapter is an adapter logger interface.
type Adapter[T ~int8] interface {
	Log(level T, keyVals ...any) error
}

type zapAdapter[T ~int8] struct {
	sugared *zap.SugaredLogger
}

func (z *zapAdapter[T]) Log(level T, keyVals ...any) error {
	switch zapcore.Level(level) {
	case zapcore.DebugLevel:
		z.sugared.Debugw("", keyVals...)
	case zapcore.InfoLevel:
		z.sugared.Infow("", keyVals...)
	case zapcore.WarnLevel:
		z.sugared.Warnw("", keyVals...)
	case zapcore.ErrorLevel:
		z.sugared.Errorw("", keyVals...)
	case zapcore.DPanicLevel:
		z.sugared.DPanicw("", keyVals...)
	default:
		z.sugared.Infow("", keyVals...)
	}
	return nil
}

// ToAdapter returns a zap adapter.
func ToAdapter[T ~int8](z *Zap) Adapter[T] {
	config := z.NewEncoderConfig()
	// ignore message key cause kratos has its own message key
	config.MessageKey = ""
	core := z.NewCore(config, zapcore.DebugLevel)
	return &zapAdapter[T]{z.LoggerWithCore(core).With(z.zapFields()...).Sugar()}
}

// Valuer is a function that returns a value.
type Valuer func(ctx context.Context) any

// FunctionField represents a key-value pair.
type FunctionField struct {
	Key string
	F   Valuer
}

func (f FunctionField) MarshalLogObject(encoder zapcore.ObjectEncoder) error {
	value := f.F(context.Background())
	zap.Any(f.Key, value).AddTo(encoder)
	return nil
}

var _ zapcore.ObjectMarshaler = FunctionField{}

// WrapHandler wraps a slog handler.
type WrapHandler struct {
	name         string
	core         zapcore.Core
	handler      slog.Handler
	dynamicAttrs []slog.Attr
}

func (h *WrapHandler) clone(newHandler slog.Handler) *WrapHandler {
	return &WrapHandler{
		name:         h.name,
		core:         h.core,
		handler:      newHandler,
		dynamicAttrs: slices.Clone(h.dynamicAttrs),
	}
}

func (h *WrapHandler) resolveAttrs(ctx context.Context, attrs []slog.Attr) (
	out []slog.Attr,
) {
	out = make([]slog.Attr, 0, len(attrs))
	for _, attr := range attrs {
		if attr.Value.Kind() != slog.KindAny {
			out = append(out, attr)
			continue
		}
		switch attrValue := attr.Value.Any().(type) {
		case FunctionField:
			value := attrValue.F(ctx)
			attr = slog.Any(attr.Key, value)
		}
		out = append(out, attr)
	}
	return
}

func (h *WrapHandler) resolveNameFromAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) != 1 {
		return nil
	}
	attr := attrs[0]
	if attr.Key != LoggerNamed || attr.Value.Kind() != slog.KindString {
		return nil
	}
	name := attr.Value.String()
	if name == "" {
		return nil
	}
	if h.name != "" {
		name = fmt.Sprintf("%s.%s", h.name, name)
	}
	handler := zapslog.NewHandler(h.core, zapslog.WithName(name))
	wrap := h.clone(handler)
	wrap.name = name
	return wrap
}

func (h *WrapHandler) filterDynamicAttrs(attrs []slog.Attr) (out []slog.Attr) {
	out = make([]slog.Attr, 0, len(attrs))
	for _, attr := range attrs {
		if attr.Value.Kind() != slog.KindAny {
			out = append(out, attr)
			continue
		}
		value := attr.Value.Any()
		f, ok := value.(Valuer)
		if ok {
			attr = slog.Any(attr.Key, FunctionField{Key: attr.Key, F: f})
			h.dynamicAttrs = append(h.dynamicAttrs, attr)
		}
	}
	return
}

func (h *WrapHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.handler.Enabled(ctx, level)
}

func (h *WrapHandler) Handle(ctx context.Context, record slog.Record) error {
	if record.NumAttrs() == 0 && len(h.dynamicAttrs) == 0 {
		return h.handler.Handle(ctx, record)
	}
	newAttrs := make([]slog.Attr, 0, record.NumAttrs()+len(h.dynamicAttrs))
	for _, dynamicAttr := range h.dynamicAttrs {
		newAttrs = append(newAttrs, dynamicAttr)
	}
	record.Attrs(func(attr slog.Attr) bool {
		newAttrs = append(newAttrs, attr)
		return true
	})
	newAttrs = h.resolveAttrs(ctx, newAttrs)
	newRecord := slog.NewRecord(record.Time, record.Level, record.Message, record.PC)
	newRecord.AddAttrs(newAttrs...)
	return h.handler.Handle(ctx, newRecord)
}

func (h *WrapHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if newHandler := h.resolveNameFromAttrs(attrs); newHandler != nil {
		return newHandler
	}
	if newAttrs := h.filterDynamicAttrs(attrs); len(newAttrs) > 0 {
		return h.clone(h.handler.WithAttrs(newAttrs))
	}
	return h
}

func (h *WrapHandler) WithGroup(name string) slog.Handler {
	return h.clone(h.handler.WithGroup(name))
}

// WithFields adds fields to the zap logger.
func WithFields[T comparable](z *Zap, fields map[string]T) {
	for k, v := range fields {
		z.kvs = append(z.kvs, k, v)
	}
}

var _ slog.Handler = (*WrapHandler)(nil)

// Zap is a logger.
type Zap struct {
	kvs    []any
	writer zapcore.WriteSyncer
}

func (z *Zap) zapFields() (out []zap.Field) {
	out = make([]zap.Field, 0, len(z.kvs)/2)
	for i := 0; i < len(z.kvs); i += 2 {
		key := z.kvs[i].(string)
		val := z.kvs[i+1]
		var field zap.Field
		switch newVal := val.(type) {
		case Valuer:
			field = zap.Inline(FunctionField{Key: key, F: newVal})
		default:
			field = zap.Any(key, val)
		}
		out = append(out, field)
	}
	return
}

// NewEncoderConfig returns a zap encoder config.
func (z *Zap) NewEncoderConfig() zapcore.EncoderConfig {
	ec := zap.NewProductionEncoderConfig()
	ec.MessageKey, ec.LevelKey, ec.NameKey = "msg", "level", "logger"
	ec.EncodeLevel, ec.EncodeTime = zapcore.CapitalLevelEncoder, zapcore.ISO8601TimeEncoder
	return ec
}

// NewCore returns a zap core.
func (z *Zap) NewCore(config zapcore.EncoderConfig, level zapcore.Level) zapcore.Core {
	return zapcore.NewCore(
		zapcore.NewJSONEncoder(config),
		z.writer,
		level,
	)
}

// NewConsoleCore returns a zap console core.
func (z *Zap) NewConsoleCore(config zapcore.EncoderConfig, level zapcore.Level) zapcore.Core {
	return zapcore.NewCore(
		zapcore.NewJSONEncoder(config),
		os.Stdout,
		level,
	)
}

// NewMixedConsoleCore returns a zap mixed console core.
func (z *Zap) NewMixedConsoleCore(config zapcore.EncoderConfig, fileLevel,
	consoleLevel zapcore.Level,
) zapcore.Core {
	return zapcore.NewTee(
		z.NewCore(config, fileLevel),
		z.NewConsoleCore(config, consoleLevel),
	)
}

// LoggerWithCore returns a zap logger with core.
func (z *Zap) LoggerWithCore(core zapcore.Core) *zap.Logger {
	return zap.New(core).With(z.zapFields()...)
}

// Logger returns a zap logger.
func (z *Zap) Logger() *zap.Logger {
	core := z.NewCore(z.NewEncoderConfig(), zapcore.DebugLevel)
	return z.LoggerWithCore(core)
}

// SlogWithCore returns a slog logger with core.
func (z *Zap) SlogWithCore(core zapcore.Core) *slog.Logger {
	handler := zapslog.NewHandler(core)
	wrap := &WrapHandler{
		name:    "",
		core:    core,
		handler: handler,
	}
	return slog.New(wrap).With(z.kvs...)
}

// Slog returns a slog logger.
func (z *Zap) Slog() *slog.Logger {
	core := z.NewMixedConsoleCore(z.NewEncoderConfig(), zapcore.DebugLevel, zapcore.WarnLevel)
	return z.SlogWithCore(core)
}

// DefaultLogFilePath returns the default log file path.
func DefaultLogFilePath() (string, error) {
	name := fmt.Sprintf("%s.log", filepath.Base(os.Args[0]))
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get working directory: %w", err)
	}
	return filepath.Join(wd, "logs", name), nil
}

// NewZap returns a zap logger.
// zapslog stabilization tracking issue: https://github.com/uber-go/zap/issues/1333
func NewZap() (*Zap, func(), error) {
	path, err := DefaultLogFilePath()
	if err != nil {
		return nil, nil, err
	}

	writer, cleanup, err := zap.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open log file: %w", err)
	}
	return &Zap{writer: writer}, cleanup, nil
}

// NewZapWithRotation returns a zap logger with rotation.
func NewZapWithRotation() (*Zap, func(), error) {
	path, err := DefaultLogFilePath()
	if err != nil {
		return nil, nil, err
	}

	logger := &lumberjack.Logger{
		Filename: path,
		MaxSize:  DefaultRotateSizeInMB,
		MaxAge:   DefaultRotateAgeInDays,
	}
	w := zapcore.AddSync(newDailyRotateWriter(logger))
	return &Zap{writer: w}, func() { _ = logger.Close() }, nil
}
