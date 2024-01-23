package hotonline

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
	"github.com/tidwall/gjson"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var log = clog.NewWithPlugin("hotonline")

var Default_github_ips = [...]string{"192.30.252.0/22",
	"185.199.108.0/22",
	"140.82.112.0/20",
	"143.55.64.0/20",
	"2a0a:a440::/29",
	"20.201.28.151/32",
	"20.205.243.166/32",
	"20.87.245.0/32",
	"20.248.137.48/32",
	"20.207.73.82/32",
	"20.27.177.113/32",
	"20.200.245.247/32",
	"20.175.192.147/32",
	"20.233.83.145/32",
	"20.29.134.23/32"}
var disable_githubassets = false
var github_ip_list []string
var githubassets_ip_list []string
var github_websites = [...]string{"github.com",
	"github.dev",
	"github.io",
	"githubassets.com",
	"githubusercontent.com"}
var github_ips []string
var ip_upper int = 50
var github_assets_ip_prefix string = "185.199"

const git_meta string = "https://api.github.com/meta"

type HotOnline struct {
	Next   plugin.Handler
	Pairs  map[string]string
	Reload time.Duration
	TTL    uint32
}

func update_github_ips() {
	github_ips = nil
	resp, err := http.Get("https://api.github.com/meta")
	if err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		webs := gjson.Get(string(body), "web")
		for _, i := range webs.Array() {
			github_ips = append(github_ips, i.String())
		}
	}
}

func get_ips(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	if strings.HasPrefix(cidr, github_assets_ip_prefix) {
		githubassets_ip_list = append(githubassets_ip_list, ips...)

	}
	// remove network address and broadcast address
	if len(ips) > ip_upper {
		ips = ips[0:ip_upper] //narrow down the ip range
	}
	return ips, nil
}
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func update_github_ip_list() {
	github_ip_list = nil
	if github_ips == nil || len(github_ips) < 2 {
		github_ips = Default_github_ips[:]
	}
	for _, item := range github_ips {
		if strings.Index(item, ":") >= 0 {
			continue // skip ipv6
		}
		ips, err := get_ips(item)
		if err != nil {
			continue
		}
		github_ip_list = append(github_ip_list, ips...)
	}

}
func test_github_connection(ip string, domain string) bool {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: domain,
		VerifyConnection: func(cs tls.ConnectionState) error {
			// adapted from the tls.Config.VerifyConnection example
			// behaves just like the default verification,
			// except for the overriden DNSName below
			opts := x509.VerifyOptions{
				// override the requested hostname with the server hostname
				DNSName:       domain,
				Intermediates: x509.NewCertPool(),
			}
			for _, cert := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(cert)
			}
			_, err := cs.PeerCertificates[0].Verify(opts)
			return err
		},
	}}
	client := &http.Client{Transport: tr, Timeout: time.Second * 6}
	//Declare and initialize slice1
	req, _ := http.NewRequest("GET", "https://"+ip, nil)
	req.Header.Set("Host", domain)
	req.Header.Set("user-agent", "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36")
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		return true
	}
	/*if strings.Index(err.Error(),"wsarecv")>0 {
		return true   // tls sni problem
	  }*/
	fmt.Println(err)

	return false
}
func get_workable_github_ip(domain string) (string, error) {
	ips_num := len(github_ip_list)
	done := make(map[string]bool, 50)
	for i := 0; i < 100; {
		ip := github_ip_list[rand.Int31n(int32(ips_num))]
		if domain == "github.githubassets.com" {
			ip = githubassets_ip_list[rand.Int31n(int32(len(githubassets_ip_list)))]
		}
		if _, ok := done[ip]; ok {
			continue
		}
		done[ip] = true
		fmt.Printf("Trying ... %v\n", ip)
		i++

		ret := test_github_connection(ip, domain)
		if ret {
			return ip, nil
		}

	}
	return "", errors.New("Not workable ip")
}
func init() { plugin.Register("hotonline", setup) }
func setup(c *caddy.Controller) error {

	c.Next()
	args := c.RemainingArgs()
	if len(args) != 1 {
		return c.ArgErr()
	}
	port := args[0]
	h := HotOnline{Pairs: make(map[string]string), Reload: time.Minute * 5, TTL: 120}
	for c.NextBlock() {
		switch c.Val() {
		case "reload":
			remaining := c.RemainingArgs()
			if len(remaining) != 1 {
				return c.Errf("reload need a duration")
			}
			i, err := time.ParseDuration(remaining[0])
			if err != nil {
				return c.Errf("%v", err)
			}
			h.Reload = i
		case "ttl":
			remaining := c.RemainingArgs()
			if len(remaining) != 1 {
				return c.Errf("ttl need a int")
			}
			i, err := strconv.Atoi(remaining[0])
			if err != nil {
				return c.Errf("%v", err)
			}
			h.TTL = uint32(i)
		case "ipupper":
			remaining := c.RemainingArgs()
			if len(remaining) != 1 {
				return c.Errf("ipupper need a int")
			}
			i, err := strconv.Atoi(remaining[0])
			if err != nil {
				return c.Errf("%v", err)
			}
			ip_upper = i
		case "prefix":
			remaining := c.RemainingArgs()
			if len(remaining) != 1 {
				return c.Errf("ipupper need a prefix")
			}
			github_assets_ip_prefix = remaining[0]
		case "disable_githubassets":
			disable_githubassets = true
		default:
			return c.Errf("unknow property %s", c.Val())
		}
	}

	cc := periodicHostsUpdate(&h)
	c.OnStartup(func() error {
		go func() {
			gin.SetMode(gin.ReleaseMode)
			h.sync(true)
			//fmt.Println(github_ip_list)
			r := gin.Default()
			r.GET("/", h.getAll)
			r.GET("/add", h.add)
			r.GET("/del", h.del)
			r.Run(":" + port)
		}()
		return nil
	})
	c.OnShutdown(func() error {
		close(cc)
		return nil
	})
	// Add the Plugin to CoreDNS, so Servers can use it in their plugin chain.
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		h.Next = next
		return h
	})

	return nil
}
func periodicHostsUpdate(h *HotOnline) chan bool {
	parseChan := make(chan bool)

	go func() {
		ticker := time.NewTicker(h.Reload)
		defer ticker.Stop()
		for {
			select {
			case <-parseChan:
				return
			case <-ticker.C:
				h.sync(false)
			}
		}
	}()
	return parseChan
}

func (hot HotOnline) sync(flag bool) {
	fmt.Println("new sync")
	if val, ok := hot.Pairs["github.com"]; ok {
		ok = test_github_connection(val, "github.com")
		if ok {
			return
		}
	}
	if flag {
		update_github_ips()
		update_github_ip_list()
	}
	wip, err := get_workable_github_ip("github.com")
	if err == nil {
		hot.Pairs["github.com"] = wip
		fmt.Printf("Get workable ip %v  for github.com\n", wip)

	}
	if !disable_githubassets {
		wip, err = get_workable_github_ip("github.githubassets.com")
		if err == nil {
			hot.Pairs["github.githubassets.com"] = wip
			fmt.Printf("Get workable ip %v  for github.githubassets.com\n", wip)

		}
	}
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
			fmt.Printf("Found %v  %v\n", qname, ip)
			a := dns.A{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    hot.TTL,
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
