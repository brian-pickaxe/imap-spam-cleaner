package logx

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
)

// ANSI color codes for terminal output (only used when stdout is a TTY).
const (
	ansiReset  = "\033[0m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiRed    = "\033[31m"
)

// ColorScore returns "score/100" with the number colored by severity: green (low), yellow (mid), red (high).
// When stdout is not a TTY, returns plain "score/100" with no escape codes.
func ColorScore(score int) string {
	if !isTerminal() {
		return fmt.Sprintf("%d/100", score)
	}
	var c string
	switch {
	case score < 40:
		c = ansiGreen
	case score < 70:
		c = ansiYellow
	default:
		c = ansiRed
	}
	return c + fmt.Sprintf("%d", score) + ansiReset + "/100"
}

func isTerminal() bool {
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

var logger *logrus.Logger

func init() {
	logger = logrus.New()
	logger.SetOutput(os.Stdout)
	logger.SetLevel(logrus.InfoLevel)
	logger.SetFormatter(&logrus.TextFormatter{
		ForceColors:   true,
		FullTimestamp: true,
		PadLevelText:  true,
	})
}

func SetLevel(level string) {
	lvl, err := logrus.ParseLevel(level)
	if err != nil {
		logger.Errorf("Invalid log level: %s", level)
		return
	}
	logger.SetLevel(lvl)
}

func Info(v ...interface{}) {
	logger.Info(v...)
}

func Infof(format string, v ...interface{}) {
	logger.Infof(format, v...)
}

func Debug(v ...interface{}) {
	logger.Debug(v...)
}

func Debugf(format string, v ...interface{}) {
	logger.Debugf(format, v...)
}

func Warn(v ...interface{}) {
	logger.Warn(v...)
}

func Warnf(format string, v ...interface{}) {
	logger.Warnf(format, v...)
}

func Error(v ...interface{}) {
	logger.Error(v...)
}

func Errorf(format string, v ...interface{}) {
	logger.Errorf(format, v...)
}

func Panic(v ...interface{}) {
	logger.Panic(v...)
}

func Panicf(format string, v ...interface{}) {
	logger.Panicf(format, v...)
}
