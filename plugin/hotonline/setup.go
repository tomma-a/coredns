package hotonline

import (
	"context"
	//"fmt"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
	"net"
	"net/http"
	"strings"
)

type HotOnline struct {
	Next  plugin.Handler
	Pairs map[string]string
}

func init() { plugin.Register("hotonline", setup) }
func setup(c *caddy.Controller) error {

	c.Next()
	args := c.RemainingArgs()
	if len(args) != 1 {
		return c.ArgErr()
	}
	port := args[0]
	h := HotOnline{Pairs: make(map[string]string)}
	go func() {
		gin.SetMode(gin.ReleaseMode)
		r := gin.Default()
		r.GET("/", h.getAll)
		r.GET("/add", h.add)
		r.GET("/del", h.del)
		r.Run(":" + port)
	}()
	// Add the Plugin to CoreDNS, so Servers can use it in their plugin chain.
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		h.Next = next
		return h
	})

	return nil
}

func (hot HotOnline) add(c *gin.Context) {
	domain := c.Query("d")
	ip := c.Query("ip")
	if domain != "" && ip != "" {
		hot.Pairs[domain] = ip
	}
}
func (hot HotOnline) del(c *gin.Context) {
	domain := c.Query("d")
	if domain != "" {
		delete(hot.Pairs, domain)
	}
}
func (hot HotOnline) getAll(c *gin.Context) {
	c.IndentedJSON(http.StatusOK, hot.Pairs)
}
func (hot HotOnline) lookup(domain string) net.IP {
	d_without_dot := strings.TrimRight(domain, ".")
	if val, ok := hot.Pairs[d_without_dot]; ok {
		return net.ParseIP(val)
	}
	return nil

}
func (hot HotOnline) Name() string { return "hotonline" }
func (hot HotOnline) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	qname := state.Name()
	if state.QType() == dns.TypeA {
		ip := hot.lookup(qname)
		if ip != nil {
			a := dns.A{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				A: ip.To4(),
			}
			m := new(dns.Msg)
			m.SetReply(r)
			m.Authoritative = true
			m.Answer = append(m.Answer, &a)

			w.WriteMsg(m)
			return dns.RcodeSuccess, nil
		}
	}

	return plugin.NextOrFailure(hot.Name(), hot.Next, ctx, w, r)
}
