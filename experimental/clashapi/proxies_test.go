package clashapi

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

type testStubOutbound struct {
	outbound.Adapter
}

func newTestStubOutbound(tag string) *testStubOutbound {
	return &testStubOutbound{
		Adapter: outbound.NewAdapter("direct", tag, []string{N.NetworkTCP, N.NetworkUDP}, nil),
	}
}

func (o *testStubOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (o *testStubOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

type testOutboundManager struct {
	outbounds map[string]adapter.Outbound
	order     []adapter.Outbound
}

func newTestOutboundManager(items ...adapter.Outbound) *testOutboundManager {
	m := &testOutboundManager{
		outbounds: make(map[string]adapter.Outbound, len(items)),
		order:     append([]adapter.Outbound(nil), items...),
	}
	for _, it := range items {
		m.outbounds[it.Tag()] = it
	}
	return m
}

func (m *testOutboundManager) Start(stage adapter.StartStage, scope *adapter.Scope) error { return nil }
func (m *testOutboundManager) Close() error                                              { return nil }
func (m *testOutboundManager) Outbounds() []adapter.Outbound        { return m.order }
func (m *testOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	it, ok := m.outbounds[tag]
	return it, ok
}
func (m *testOutboundManager) Default() adapter.Outbound { return m.order[0] }
func (m *testOutboundManager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, outboundType string, options any) error {
	return nil
}

type testEndpointManager struct {
	adapter.EndpointManager
}

func (e *testEndpointManager) Endpoints() []adapter.Endpoint { return nil }

func TestClashAPIFallbackPinUnpinAndProxyInfo(t *testing.T) {
	history := urltest.NewHistoryStorage()
	defer history.Close()

	node1 := newTestStubOutbound("node-1")
	node2 := newTestStubOutbound("node-2")

	baseMgr := newTestOutboundManager(node1, node2)
	ctx := context.Background()
	ctx = service.ContextWithPtr(ctx, history)
	ctx = service.ContextWith[adapter.OutboundManager](ctx, baseMgr)

	logger := log.NewNOPFactory().Logger()

	fbOut, err := group.NewFallback(ctx, nil, logger, "FallbackGroup", option.FallbackOutboundOptions{
		Outbounds: []string{"node-1", "node-2"},
	})
	if err != nil {
		t.Fatalf("NewFallback failed: %v", err)
	}
	fb := fbOut.(*group.Fallback)
	if err := fb.Start(adapter.StartStateStart, nil); err != nil {
		t.Fatalf("Fallback.Start failed: %v", err)
	}

	selOut, err := group.NewSelector(ctx, nil, logger, "SelectorGroup", option.SelectorOutboundOptions{
		Outbounds: []string{"node-1", "node-2"},
	})
	if err != nil {
		t.Fatalf("NewSelector failed: %v", err)
	}
	sel := selOut.(*group.Selector)
	if err := sel.Start(adapter.StartStateStart, nil); err != nil {
		t.Fatalf("Selector.Start failed: %v", err)
	}

	fullMgr := newTestOutboundManager(fb, sel, node1, node2)
	srv := &Server{
		outbound:       fullMgr,
		endpoint:       &testEndpointManager{},
		urlTestHistory: history,
		logger:         logger,
	}
	router := proxyRouter(srv, nil)

	// 1. GET / -> verify FallbackGroup metadata without "fixed"
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / status=%d body=%s", rec.Code, rec.Body.String())
	}
	var allResp struct {
		Proxies map[string]map[string]any `json:"proxies"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &allResp); err != nil {
		t.Fatalf("unmarshal GET /: %v", err)
	}
	fbInfo := allResp.Proxies["FallbackGroup"]
	if fbInfo == nil {
		t.Fatalf("FallbackGroup missing from GET /")
	}
	if fbInfo["type"] != "Fallback" {
		t.Fatalf("expected type=Fallback, got %v", fbInfo["type"])
	}
	if fbInfo["now"] != "node-1" {
		t.Fatalf("expected now=node-1, got %v", fbInfo["now"])
	}
	if _, hasFixed := fbInfo["fixed"]; hasFixed {
		t.Fatalf("did not expect fixed key when unpinned, got %v", fbInfo["fixed"])
	}

	// 2. PUT /FallbackGroup -> pin to node-2
	req = httptest.NewRequest(http.MethodPut, "/FallbackGroup", bytes.NewBufferString(`{"name":"node-2"}`))
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("PUT pin status=%d body=%s", rec.Code, rec.Body.String())
	}

	// 3. GET /FallbackGroup -> verify now=node-2 and fixed=node-2
	req = httptest.NewRequest(http.MethodGet, "/FallbackGroup", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /FallbackGroup status=%d", rec.Code)
	}
	var singleResp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &singleResp); err != nil {
		t.Fatalf("unmarshal GET /FallbackGroup: %v", err)
	}
	if singleResp["now"] != "node-2" || singleResp["fixed"] != "node-2" {
		t.Fatalf("expected now=node-2 and fixed=node-2, got %v", singleResp)
	}

	// 4. DELETE /FallbackGroup -> unpin (Mihomo standard 204 No Content)
	req = httptest.NewRequest(http.MethodDelete, "/FallbackGroup", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE unpin status=%d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/FallbackGroup", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	singleResp = nil
	if err := json.Unmarshal(rec.Body.Bytes(), &singleResp); err != nil {
		t.Fatalf("unmarshal after DELETE: %v", err)
	}
	if singleResp["now"] != "node-1" {
		t.Fatalf("expected now=node-1 after DELETE, got %v", singleResp["now"])
	}
	if _, hasFixed := singleResp["fixed"]; hasFixed {
		t.Fatalf("expected no fixed field after DELETE, got %v", singleResp["fixed"])
	}

	// 5. PUT pin then PUT {"name":""} to unpin
	req = httptest.NewRequest(http.MethodPut, "/FallbackGroup", bytes.NewBufferString(`{"name":"node-2"}`))
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("PUT re-pin status=%d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodPut, "/FallbackGroup", bytes.NewBufferString(`{"name":""}`))
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("PUT empty-name unpin status=%d body=%s", rec.Code, rec.Body.String())
	}
	if fb.IsPinned() || fb.Selected(N.NetworkTCP).Tag() != "node-1" {
		t.Fatalf("expected unpinned and back to node-1 after PUT empty name")
	}

	// 6. Error handling
	req = httptest.NewRequest(http.MethodPut, "/FallbackGroup", bytes.NewBufferString(`{"name":"missing"}`))
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown member, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodDelete, "/SelectorGroup", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for DELETE on Selector, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodDelete, "/NoSuchGroup", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for DELETE on unknown group, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPut, "/node-1", bytes.NewBufferString(`{"name":"node-2"}`))
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for PUT on leaf outbound, got %d", rec.Code)
	}
}

type probeControlledOutbound struct {
	outbound.Adapter
	probeAddr string
	allowDial bool
	dialCalls int
}

func newProbeControlledOutbound(tag string, probeAddr string, allowDial bool) *probeControlledOutbound {
	return &probeControlledOutbound{
		Adapter:   outbound.NewAdapter("direct", tag, []string{N.NetworkTCP, N.NetworkUDP}, nil),
		probeAddr: probeAddr,
		allowDial: allowDial,
	}
}

func (o *probeControlledOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	o.dialCalls++
	if !o.allowDial {
		return nil, net.ErrClosed
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", o.probeAddr)
}

func (o *probeControlledOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

type testCertificateStore struct {
	pool *x509.CertPool
}

func (s *testCertificateStore) Name() string                                               { return "test-cert" }
func (s *testCertificateStore) Start(stage adapter.StartStage, scope *adapter.Scope) error { return nil }
func (s *testCertificateStore) Pool() *x509.CertPool                                       { return s.pool }
func (s *testCertificateStore) ExclusiveAnchors() bool                                     { return true }

func TestClashAPIGetProxyDelayUnwrapsFallbackWithoutRescueOrBypassingRecoverTimes(t *testing.T) {
	probeSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer probeSrv.Close()
	probeAddr := probeSrv.Listener.Addr().String()
	certPool := x509.NewCertPool()
	certPool.AddCert(probeSrv.Certificate())

	history := urltest.NewHistoryStorage()
	defer history.Close()

	node1 := newProbeControlledOutbound("node-1", probeAddr, false)
	node2 := newProbeControlledOutbound("node-2", probeAddr, true)

	baseMgr := newTestOutboundManager(node1, node2)
	ctx := context.Background()
	ctx = service.ContextWith[adapter.CertificateStore](ctx, &testCertificateStore{pool: certPool})
	ctx = service.ContextWithPtr(ctx, history)
	ctx = service.ContextWith[adapter.OutboundManager](ctx, baseMgr)
	logger := log.NewNOPFactory().Logger()

	fbOut, err := group.NewFallback(ctx, nil, logger, "FallbackGroup", option.FallbackOutboundOptions{
		Outbounds:    []string{"node-1", "node-2"},
		URL:          probeSrv.URL,
		FailTimes:    2,
		RecoverTimes: 2,
	})
	if err != nil {
		t.Fatalf("NewFallback failed: %v", err)
	}
	fb := fbOut.(*group.Fallback)
	if err := fb.Start(adapter.StartStateStart, nil); err != nil {
		t.Fatalf("Fallback.Start failed: %v", err)
	}

	fullMgr := newTestOutboundManager(fb, node1, node2)
	srv := &Server{
		ctx:            ctx,
		outbound:       fullMgr,
		endpoint:       &testEndpointManager{},
		urlTestHistory: history,
		logger:         logger,
	}
	router := proxyRouter(srv, nil)

	// node-1 is currently selected (optimistic startup), but node-1 is down while node-2 is up.
	// GET /FallbackGroup/delay must probe node-1 directly (returning 503) WITHOUT rescuing onto node-2
	// and WITHOUT writing node-2's latency under node-1's history!
	req := httptest.NewRequest(http.MethodGet, "/FallbackGroup/delay?timeout=1500&url="+probeSrv.URL, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when active primary node-1 fails delay test, got %d body=%s", rec.Code, rec.Body.String())
	}
	if node2.dialCalls != 0 {
		t.Fatalf("expected GET /FallbackGroup/delay not to trigger passive rescue onto node-2, got %d dials", node2.dialCalls)
	}
	if h1 := history.LoadURLTestHistory("node-1"); h1 != nil {
		t.Fatalf("did not expect polluted history on failing node-1, got %+v", h1)
	}

	// Demote node-1 via URLTest so Fallback selects node-2.
	if _, err := fb.URLTest(context.Background()); err != nil {
		t.Fatalf("fb.URLTest failed: %v", err)
	}
	if got := fb.Selected(N.NetworkTCP).Tag(); got != "node-2" {
		t.Fatalf("expected fallback selected node-2, got %s", got)
	}

	// Bring node-1 back up and probe /node-1/delay ONCE.
	// PerformUpdateCheck must respect recover_times=2 and hold on node-2 until the 2nd probe!
	node1.allowDial = true
	req = httptest.NewRequest(http.MethodGet, "/node-1/delay?timeout=1500&url="+probeSrv.URL, nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on 1st recovered /node-1/delay, got %d body=%s", rec.Code, rec.Body.String())
	}
	if got := fb.Selected(N.NetworkTCP).Tag(); got != "node-2" {
		t.Fatalf("expected PerformUpdateCheck to respect recover_times=2 after 1st probe, got %s", got)
	}
}
