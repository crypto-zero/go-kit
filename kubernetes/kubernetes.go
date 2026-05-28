package kubernetes

import (
	"os"
	"strings"
)

const namespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

// GetCurrentNamespace returns the current namespace in the kubernetes cluster.
func GetCurrentNamespace() (namespace string) {
	d, err := os.ReadFile(namespacePath)
	if err != nil {
		return ""
	}
	namespace = strings.TrimSpace(string(d))
	return
}
