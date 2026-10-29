package snowflake

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/messages"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/namematcher"
)

const (
	proxyPollWait = 10 * time.Second
	clientWait    = 30 * time.Second
	maxBody       = 1 << 20
	maxQueued     = 256
)

// Broker is the in-process rendezvous service of the Snowflake protocol
// (client/proxy v1.x, proxy v1.3). Clients post an SDP offer to /client, a
// volunteer proxy long-polls /proxy to receive one, and posts its SDP answer to
// /answer, which is handed back to the waiting client. Every match points the
// proxy at the single relay this broker was built for, so volunteers only ever
// forward to our node.
type Broker struct {
	relay    string
	relayDom string

	offers chan *offer

	mu      sync.Mutex
	pending map[string]*offer // by proxy session id
}

type offer struct {
	sdp    string
	nat    string
	answer chan string
	gone   <-chan struct{}
}

// NewBroker returns a Broker whose matches use relayURL (wss://host/...).
func NewBroker(relayURL string) (*Broker, error) {
	u, err := url.Parse(relayURL)
	if err != nil {
		return nil, err
	}
	return &Broker{
		relay:    relayURL,
		relayDom: u.Hostname(),
		offers:   make(chan *offer, maxQueued),
		pending:  map[string]*offer{},
	}, nil
}

// Handler serves /client, /proxy and /answer relative to where it is mounted.
func (b *Broker) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /client", b.client)
	mux.HandleFunc("POST /proxy", b.proxy)
	mux.HandleFunc("POST /answer", b.answer)
	return mux
}

func (b *Broker) client(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	req, err := messages.DecodeClientPollRequest(body)
	if err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	o := &offer{sdp: req.Offer, nat: req.NAT, answer: make(chan string, 1), gone: r.Context().Done()}
	select {
	case b.offers <- o:
	default:
		writeClient(w, messages.ClientPollResponse{Error: "no snowflake proxies available"})
		return
	}
	select {
	case a := <-o.answer:
		writeClient(w, messages.ClientPollResponse{Answer: a})
	case <-time.After(clientWait):
		writeClient(w, messages.ClientPollResponse{Error: "no snowflake proxies available"})
	case <-r.Context().Done():
	}
}

func writeClient(w http.ResponseWriter, resp messages.ClientPollResponse) {
	out, err := resp.EncodePollResponse()
	if err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(out)
}

func (b *Broker) proxy(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	sid, _, _, _, pattern, aware, err := messages.DecodeProxyPollRequestWithRelayPrefix(body)
	if err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	// A proxy restricted to other relays must not receive our clients.
	if aware && pattern != "" {
		m := namematcher.NewNameMatcher(pattern)
		if !m.IsMember(b.relayDom) {
			writePoll(w, messages.ProxyPollResponse{Status: messages.ProxyClientNoMatch})
			return
		}
	}
	timeout := time.After(proxyPollWait)
	for {
		select {
		case o := <-b.offers:
			select {
			case <-o.gone:
				continue // client gave up while queued
			default:
			}
			b.mu.Lock()
			b.pending[sid] = o
			b.mu.Unlock()
			// Forget the match if the proxy never answers.
			time.AfterFunc(clientWait, func() {
				b.mu.Lock()
				delete(b.pending, sid)
				b.mu.Unlock()
			})
			writePoll(w, messages.ProxyPollResponse{
				Status: messages.ProxyClientMatch, Offer: o.sdp, NAT: o.nat, RelayURL: b.relay,
			})
			return
		case <-timeout:
			writePoll(w, messages.ProxyPollResponse{Status: messages.ProxyClientNoMatch})
			return
		case <-r.Context().Done():
			return
		}
	}
}

func writePoll(w http.ResponseWriter, resp messages.ProxyPollResponse) {
	out, err := resp.Encode()
	if err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(out)
}

func (b *Broker) answer(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	req, err := messages.DecodeProxyAnswerRequest(body)
	if err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	b.mu.Lock()
	o := b.pending[req.Sid]
	delete(b.pending, req.Sid)
	b.mu.Unlock()
	status := "client gone"
	if o != nil {
		select {
		case <-o.gone:
		default:
			o.answer <- req.Answer
			status = "success"
		}
	}
	_ = json.NewEncoder(w).Encode(messages.ProxyAnswerResponse{Status: status})
}
