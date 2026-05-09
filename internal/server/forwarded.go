package server

import (
	"net/http"
	"net/netip"
	"strings"
)

type forwardedForInfo struct {
	clientIP     string
	forwardedFor []string
}

func (g *Gateway) clientIP(r *http.Request) string {
	info := g.forwardedForInfo(r)
	return info.clientIP
}

func (g *Gateway) trustedForwardedFor(r *http.Request) []string {
	info := g.forwardedForInfo(r)
	return info.forwardedFor
}

func (g *Gateway) forwardedForInfo(r *http.Request) forwardedForInfo {
	if r == nil {
		return forwardedForInfo{}
	}

	remotePeer, ok := requestRemoteIP(r)
	if !ok {
		return forwardedForInfo{
			clientIP: strings.TrimSpace(r.RemoteAddr),
		}
	}

	remotePeerString := remotePeer.String()
	trustedProxies := g.trustedProxies()
	if !isTrustedProxy(remotePeer, trustedProxies) {
		return forwardedForInfo{
			clientIP: remotePeerString,
		}
	}

	forwardedFor := sanitizeForwardedFor(r.Header, trustedProxies)
	if len(forwardedFor) == 0 {
		return forwardedForInfo{
			clientIP: remotePeerString,
		}
	}

	return forwardedForInfo{
		clientIP:     forwardedFor[0],
		forwardedFor: forwardedFor,
	}
}

func (g *Gateway) trustedProxies() []netip.Prefix {
	if g == nil || g.Client == nil {
		return nil
	}
	return g.Client.Config.TrustedProxies
}

func requestRemoteIP(r *http.Request) (netip.Addr, bool) {
	remoteAddr := strings.TrimSpace(r.RemoteAddr)
	if remoteAddr == "" {
		return netip.Addr{}, false
	}
	if addrPort, err := netip.ParseAddrPort(remoteAddr); err == nil {
		return addrPort.Addr(), true
	}
	if addr, err := netip.ParseAddr(remoteAddr); err == nil {
		return addr, true
	}
	return netip.Addr{}, false
}

func sanitizeForwardedFor(header http.Header, trustedProxies []netip.Prefix) []string {
	addrs := forwardedForAddrs(header)
	if len(addrs) == 0 {
		return nil
	}

	clientIndex := 0
	for i := len(addrs) - 1; i >= 0; i-- {
		if !isTrustedProxy(addrs[i], trustedProxies) {
			clientIndex = i
			break
		}
	}

	return addrStrings(addrs[clientIndex:])
}

func forwardedForAddrs(header http.Header) []netip.Addr {
	values := header.Values("X-Forwarded-For")
	addrs := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		for forwarded := range strings.SplitSeq(value, ",") {
			forwarded = strings.TrimSpace(forwarded)
			if forwarded == "" {
				continue
			}
			addr, err := netip.ParseAddr(forwarded)
			if err != nil {
				continue
			}
			addrs = append(addrs, addr)
		}
	}
	return addrs
}

func addrStrings(addrs []netip.Addr) []string {
	values := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		values = append(values, addr.String())
	}
	return values
}

func isTrustedProxy(addr netip.Addr, trustedProxies []netip.Prefix) bool {
	for _, prefix := range trustedProxies {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
