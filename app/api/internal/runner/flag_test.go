package runner

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/flagmac"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/scenarios"
)

type flagSink struct {
	mu    sync.Mutex
	reg   []string // runID|podRef
	macs  [][]byte
	ended []string
}

func (f *flagSink) RegisterFlag(runID, podRef string, mac []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reg = append(f.reg, runID+"|"+podRef)
	f.macs = append(f.macs, mac)
}

func (f *flagSink) EndFlag(runID string, _ time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ended = append(f.ended, runID)
}

// A terminal run hands the MAC of its own flag's label, with its pod ref, to the flag sink at start,
// and its end when it is over; the flag itself is never handed on (ADR 0036).
func TestTerminalRunRegistersFlagMAC(t *testing.T) {
	c := fake.NewClientset()
	readyOnCreate(c)
	rec := newRecorder()
	key := flagmac.New()
	sink := &flagSink{}
	r := New(c, &fakeExec{code: 0}, rec, nil, Config{PollInterval: 10 * time.Millisecond, QuarantineLinger: -1,
		CommandTimeout: 500 * time.Millisecond, DeleteWait: 200 * time.Millisecond, Flags: sink, FlagMAC: key.Sum})
	release, done := released()
	id, token := r.StartTerminal(terminalScenario(), release)
	rec.waitFor(t, StatePodReady)

	pods, err := c.CoreV1().Pods("sandbox").List(context.Background(), metav1.ListOptions{})
	if err != nil || len(pods.Items) != 1 {
		t.Fatalf("pods: %v %d", err, len(pods.Items))
	}
	pod := pods.Items[0]
	var flag string
	for _, e := range pod.Spec.Containers[0].Env {
		if e.Name == "SDP_FLAG" {
			flag = e.Value
		}
	}
	hexPart := strings.TrimSuffix(strings.TrimPrefix(flag, "SDP{"), "}")
	if len(hexPart) != 16 {
		t.Fatalf("flag = %q", flag)
	}
	sink.mu.Lock()
	if len(sink.reg) != 1 || sink.reg[0] != id+"|sandbox_"+pod.Name {
		t.Fatalf("registered %v, want %s|sandbox_%s", sink.reg, id, pod.Name)
	}
	if !bytes.Equal(sink.macs[0], key.Sum("sdp-"+hexPart)) {
		t.Fatal("the registered MAC is not HMAC(key, sdp-<flag hex>)")
	}
	if bytes.Contains(sink.macs[0], []byte(hexPart)) {
		t.Fatal("the flag reached the sink")
	}
	sink.mu.Unlock()

	if err := r.Leave(id, token); err != nil {
		t.Fatal(err)
	}
	<-done
	deadline := time.Now().Add(2 * time.Second)
	for {
		sink.mu.Lock()
		n := len(sink.ended)
		sink.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the run's end never reached the flag sink")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if sink.ended[0] != id {
		t.Fatalf("ended %v", sink.ended)
	}
}

// A scripted run has no flag and registers nothing.
func TestScriptedRunRegistersNoFlag(t *testing.T) {
	c := fake.NewClientset()
	readyOnCreate(c)
	rec := newRecorder()
	sink := &flagSink{}
	r := New(c, &fakeExec{code: 0}, rec, nil, Config{PollInterval: 10 * time.Millisecond, QuarantineLinger: -1,
		DeleteWait: 200 * time.Millisecond, Flags: sink, FlagMAC: flagmac.New().Sum})
	release, done := released()
	sc := scenarios.Scenario{ID: "shell-in-container", TimeoutSeconds: 1}
	sc.Template.Spec.Containers = terminalScenario().Template.Spec.Containers
	if _, err := r.Start(sc, release); err != nil {
		t.Fatal(err)
	}
	<-done
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.reg) != 0 || len(sink.ended) != 0 {
		t.Fatalf("scripted run touched the flag sink: %v %v", sink.reg, sink.ended)
	}
}
