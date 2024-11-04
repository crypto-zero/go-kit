package kubernetes

import (
	"io"
	"os"
	"strings"
)

// GetCurrentNamespace returns the current namespace in the kubernetes cluster.
func GetCurrentNamespace() (namespace string) {
	namespaceFile, err := os.Open("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		return ""
	}
	d, err := io.ReadAll(namespaceFile)
	if err != nil {
		return ""
	}
	namespace = strings.TrimSpace(string(d))
	return
}
