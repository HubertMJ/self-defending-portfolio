package runner

import (
	"context"
	"io"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

// KubeExecer runs commands through the API server's pods/exec subresource, the same path as
// `kubectl exec`: WebSocket first, SPDY as the fallback for an API server or proxy that refuses the
// upgrade. RBAC: `create` on pods/exec in `sandbox` only (cluster/infra/portfolio-api/
// rbac-sandbox.yaml); since Kubernetes 1.31 a WebSocket exec is authorised as `create` too.
//
// A TTY matters for detection, not for the output: Falco's "Terminal shell in container" rule only
// fires for a shell whose process has a controlling terminal (proc.tty != 0), which is what a
// visitor's "someone got a shell" story is about. With a TTY the API server requires stdin to be
// attached, so an empty stdin is sent; the command is non-interactive (`sh -c ...`) by contract.
//
// Output is discarded: nothing a scenario prints is shown to visitors, and keeping it would only be
// an unbounded buffer fed by whatever runs in the sandbox.
type KubeExecer struct {
	Config *rest.Config
	Client kubernetes.Interface
}

// Exec runs command in namespace/pod/container until it exits or ctx ends.
func (e *KubeExecer) Exec(ctx context.Context, namespace, pod, container string, command []string, tty bool) error {
	req := e.Client.CoreV1().RESTClient().Post().
		Resource("pods").Namespace(namespace).Name(pod).SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: container,
			Command:   command,
			Stdin:     tty,
			Stdout:    true,
			Stderr:    !tty, // with a TTY, stderr is merged into stdout by the runtime
			TTY:       tty,
		}, scheme.ParameterCodec)

	ws, err := remotecommand.NewWebSocketExecutor(e.Config, "GET", req.URL().String())
	if err != nil {
		return err
	}
	spdy, err := remotecommand.NewSPDYExecutor(e.Config, "POST", req.URL())
	if err != nil {
		return err
	}
	exec, err := remotecommand.NewFallbackExecutor(ws, spdy, func(err error) bool {
		return httpstream.IsUpgradeFailure(err) || httpstream.IsHTTPSProxyError(err)
	})
	if err != nil {
		return err
	}
	opts := remotecommand.StreamOptions{Stdout: io.Discard, Tty: tty}
	if tty {
		opts.Stdin = strings.NewReader("")
	} else {
		opts.Stderr = io.Discard
	}
	return exec.StreamWithContext(ctx, opts)
}
