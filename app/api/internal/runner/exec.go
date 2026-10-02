package runner

import (
	"context"
	"errors"
	"io"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	utilexec "k8s.io/client-go/util/exec"
)

// KubeExecer runs commands through the API server's pods/exec subresource, the same path as
// `kubectl exec`: WebSocket first, SPDY as the fallback for an API server or proxy that refuses the
// upgrade. RBAC: `create` on pods/exec in `sandbox` and the unguarded twin `sandbox-unguarded`
// (cluster/infra/portfolio-api/); since Kubernetes 1.31 a WebSocket exec is authorised as `create`.
//
// A TTY matters for detection, not for the output: Falco's "Terminal shell in container" rule only
// fires for a shell whose process has a controlling terminal (proc.tty != 0), which is what a
// visitor's "someone got a shell" story is about. With a TTY the API server requires stdin to be
// attached, so an empty stdin is sent.
//
// Exec discards output: a scripted scenario shows nothing it prints. ExecStream is the terminal
// path (ADR 0029): it streams the command's stdout and stderr back and reports the exit code, so
// the visitor reads what their command printed (scrubbed and capped by the runner's sink).
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

// ExecStream is the terminal path (ADR 0029): the same pods/exec call, but the command's stdout and
// stderr are copied to the given writers as they stream, and the exit code is returned. A non-zero
// exit is reported through exitCode, not err; err is a transport failure or the pod going away.
func (e *KubeExecer) ExecStream(ctx context.Context, namespace, pod, container string, command []string, tty bool, stdout, stderr io.Writer) (int, error) {
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
		return -1, err
	}
	spdy, err := remotecommand.NewSPDYExecutor(e.Config, "POST", req.URL())
	if err != nil {
		return -1, err
	}
	exec, err := remotecommand.NewFallbackExecutor(ws, spdy, func(err error) bool {
		return httpstream.IsUpgradeFailure(err) || httpstream.IsHTTPSProxyError(err)
	})
	if err != nil {
		return -1, err
	}
	opts := remotecommand.StreamOptions{Stdout: stdout, Tty: tty}
	if tty {
		opts.Stdin = strings.NewReader("")
	} else {
		opts.Stderr = stderr
	}
	err = exec.StreamWithContext(ctx, opts)
	var codeErr utilexec.CodeExitError
	if errors.As(err, &codeErr) {
		return codeErr.Code, nil // a non-zero exit is the command's result, not a transport error
	}
	if err != nil {
		return -1, err
	}
	return 0, nil
}
