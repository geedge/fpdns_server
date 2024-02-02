package main

import (
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"sync"

	"fpdns_server/datastruct"

	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
)

var CONFIG_SLD string
var UniqueCounter uint32 = 0xfffffffa
var mutex_lock sync.Mutex

func InttoIPv4(n uint32) net.IP {
	b0 := (n >> 24) & 0xff
	b1 := (n >> 16) & 0xff
	b2 := (n >> 8) & 0xff
	b3 := n & 0xff
	return net.IPv4(byte(b0), byte(b1), byte(b2), byte(b3))
}

func TtlParser(domain string) uint32 {
	subdomain := strings.ToLower(strings.Split(domain, ".")[0])
	ttl, _ := strconv.Atoi(strings.Split(subdomain, "-")[0])
	return uint32(ttl)
}

func retrieve_token(label string) (int, error) {
	fields := strings.Split(label, "-")
	token, err := strconv.Atoi(fields[len(fields)-1])
	if err != nil {
		return 0, err
	}
	return token, nil
}

func task_parser(name string, qtype uint16) int8 {
	labels := strings.Split(name, ".")
	subdomain := strings.ToLower(labels[0])
	if qtype == dns.TypeA {
		if len(labels) == 4 && (subdomain == "ns1" || subdomain == "ns2") {
			return 0
		} else if strings.Contains(subdomain, "start") {
			return 1
		} else if strings.Contains(subdomain, "init") {
			return 2
		} else if strings.Contains(subdomain, "end") {
			return 3
		} else if strings.Contains(subdomain, "echo") {
			return 4 // basic echodns
		} else if strings.Contains(subdomain, "ttl") {
			return 5 // ttl test
		} else if strings.Contains(subdomain, "merge") {
			return 6
		} else if strings.Contains(subdomain, "fetch") {
			return 7
		} else if strings.Contains(subdomain, "bailiwick") {
			return 8 // bailiwick verification
		} else if strings.Contains(subdomain, "cname-chain") {
			return 9 // unlimited ns chain
		} else if strings.Contains(subdomain, "ns-chain") {
			return 10 // unlimited cname chain
		} else if strings.Contains(subdomain, "retry") {
			return 11
		} else if strings.Contains(subdomain, "timeout") {
			return 12
		}
	}
	return -1
}

func query_handler(w dns.ResponseWriter, r *dns.Msg) {
	var ip net.IP
	respond_flag := true
	if addr, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		ip = addr.IP
	}
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = true
	m.Authoritative = true
	name := m.Question[0].Name
	subdomain := strings.Split(name, ".")[0]
	qtype := m.Question[0].Qtype
	mutex_lock.Lock()
	switch task_parser(name, qtype) {
	case 1:
		var random_token int
		// may cause dead loop -> attention!
		for {
			random_token = rand.Intn(1 << 32)
			_, init_existed := datastruct.Init_set[random_token]
			_, task_existed := datastruct.Task_map[random_token]
			if !init_existed && !task_existed {
				datastruct.Init_set[random_token] = struct{}{}
				//fmt.Printf("test initialized (token = %v)\n", random_token)
				break
			}
		}
		a := &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   InttoIPv4(uint32(random_token)),
		}
		m.Answer = append(m.Answer, a)
	case 2:
		var reply_code string
		var ok bool
		token, err := retrieve_token(subdomain)
		if err != nil {
			m.MsgHdr.Rcode = dns.RcodeServerFailure
			break
		}
		//mutex_lock.Lock()
		if _, ok = datastruct.Init_set[token]; ok {
			delete(datastruct.Init_set, token)
		}
		//mutex_lock.Unlock()
		if ok {
			delete(datastruct.Init_set, token)
			datastruct.Task_map[token] = &datastruct.ResolverFp{}
			//fmt.Printf("Task Created (token = %v)\n", token)
			if r.IsEdns0() != nil {
				datastruct.Task_map[token].Dnssec = r.IsEdns0().Do()
			}
			if name != strings.ToLower(name) {
				datastruct.Task_map[token].QnameEncode = true
			} else {
				datastruct.Task_map[token].QnameEncode = false
			}
			reply_code = "200.200.200.200"
		} else {
			m.MsgHdr.Rcode = dns.RcodeServerFailure
			break
		}
		a := &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP(reply_code),
		}
		m.Answer = append(m.Answer, a)
	case 3:
		var reply_code string
		token, err := retrieve_token(subdomain)
		if err != nil {
			m.MsgHdr.Rcode = dns.RcodeServerFailure
			break
		}
		if result, ok := datastruct.Task_map[token]; ok {
			delete(datastruct.Task_map, token)
			datastruct.Result_map[token] = *result
			reply_code = "200.200.200.200"
			//fmt.Printf("Task terminated (token = %v)\n", token)
		} else {
			m.MsgHdr.Rcode = dns.RcodeServerFailure
			break
		}
		a := &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP(reply_code),
		}
		m.Answer = append(m.Answer, a)
	case 4:
		a := &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   ip,
		}
		m.Answer = append(m.Answer, a)
	case 5:
		query_ttl := TtlParser(name)
		//fmt.Println(query_ttl)
		a := &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: query_ttl},
			A:   ip,
		}
		m.Answer = append(m.Answer, a)
	case 6:
		respond_flag = false
		token, err := retrieve_token(subdomain)
		if err != nil {
			break
		}
		if fp, ok := datastruct.Task_map[token]; ok {
			fp.QueryMerge += 1
			//fmt.Printf("MergeTest (token = %v) current_status: %v\n", token, fp.QueryMerge)
		}
	case 7:
		respond_flag = false
		token, err := retrieve_token(subdomain)
		if err != nil {
			break
		}
		if fp, ok := datastruct.Task_map[token]; ok {
			fp.FetchLimit += 1
			//fmt.Printf("FetchTest (token = %v) current_status: %v\n", token, fp.FetchLimit)
		}
	case 8:
		wrong_ns := &dns.NS{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
			Ns:  dns.Fqdn("dns.baidu.com"),
		}
		wrong_ns_ip := &dns.A{
			Hdr: dns.RR_Header{Name: "dns.baidu.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("159.75.200.247"),
		}
		m.Ns = append(m.Ns, wrong_ns)
		m.Extra = append(m.Extra, wrong_ns_ip)
	case 9:
		var cname_target string
		token, err := retrieve_token(subdomain)
		labels := strings.Split(subdomain, "-")
		if labels[0] == "cname" {
			cname_target = "1-" + subdomain
		} else {
			iter_cnt, _ := strconv.Atoi(labels[0])
			if err == nil {
				if fp, ok := datastruct.Task_map[token]; ok {
					if iter_cnt > fp.MaxCnameDepth {
						fp.MaxCnameDepth = iter_cnt
						//fmt.Printf("CnameChainTest (token = %v) status_update: %v\n", token, fp.MaxCnameDepth)
					}
				}
			}
			iter_cnt += 1
			cname_target = strconv.Itoa(iter_cnt) + "-" + strings.Join(labels[1:], "-")
			//cname_target = strings.Join([]string{labels[0], labels[1], strconv.Itoa(iter_cnt)}, "-")
		}
		cname_target = dns.Fqdn(cname_target + "." + CONFIG_SLD)
		cname_redir := &dns.CNAME{
			Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
			Target: cname_target,
		}
		m.Answer = append(m.Answer, cname_redir)
	case 10:
		var ns_target string
		token, err := retrieve_token(subdomain)
		labels := strings.Split(subdomain, "-")
		if labels[0] == "ns" {
			ns_target = "1-" + subdomain
		} else {
			iter_cnt, _ := strconv.Atoi(labels[0])
			if err == nil {
				if fp, ok := datastruct.Task_map[token]; ok {
					if iter_cnt > fp.MaxNsDepth {
						fp.MaxNsDepth = iter_cnt
						//fmt.Printf("NsChainTest (token = %v) status_update: %v\n", token, fp.MaxNsDepth)
					}
				}
			}
			iter_cnt += 1
			ns_target = strconv.Itoa(iter_cnt) + "-" + strings.Join(labels[1:], "-")
			//ns_target = strings.Join([]string{labels[0], labels[1], strconv.Itoa(iter_cnt)}, "-")
		}
		ns_target = dns.Fqdn(ns_target + "." + CONFIG_SLD)
		ns_delegation := &dns.NS{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
			Ns:  ns_target,
		}
		m.Ns = append(m.Ns, ns_delegation)
	case 11:
		respond_flag = false
		token, err := retrieve_token(subdomain)
		if err != nil {
			break
		}
		if fp, ok := datastruct.Task_map[token]; ok {
			fp.RetryLimit += 1
			//fmt.Printf("RetryTest (token = %v) current_status: %v\n", token, fp.RetryLimit)
		}
	case 12:
		respond_flag = false
		token, err := retrieve_token(subdomain)
		if err != nil {
			break
		}
		if fp, ok := datastruct.Task_map[token]; ok {
			if fp.TimeoutStart == 0 {
				fp.TimeoutStart = time.Now().UnixMilli()
				//fmt.Printf("TimeoutTest (token = %v) start_timestamp: %v\n", token, fp.TimeoutStart)
			} else {
				fp.TimeoutEnd = time.Now().UnixMilli()
				//fmt.Printf("TimeoutTest (token = %v) timestamp_update: %v\n", token, fp.TimeoutEnd)
			}
		}
	case 0:
		a := &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
			A:   net.ParseIP("159.75.200.247"),
		}
		m.Answer = append(m.Answer, a)
	case -1:
		m.MsgHdr.Rcode = dns.RcodeNameError
	}
	mutex_lock.Unlock()
	if respond_flag {
		w.WriteMsg(m)
	}
}

/*
func strategyMaker(name string, qtype uint16) int8 {
	var subdomain string
	labels := strings.Split(name, ".")
	if len(labels) >= 4 {
		subdomain = strings.ToLower(labels[len(labels)-4])
	}

	if qtype == dns.TypeA {
		if len(labels) == 4 && (subdomain == "ns1" || subdomain == "ns2") {
			return 0
		} else if strings.Contains(subdomain, "fwd") {
			return 1 // return rdns ip in cname
		} else if strings.Contains(subdomain, "rdns") {
			return 2 // return honey cname record
		} else if strings.Contains(subdomain, "honey") {
			return 3 // return timestamp in a record
		} else if strings.Contains(subdomain, "echo") {
			return 4 // basic echodns
		} else if strings.Contains(subdomain, "ttl") {
			return 5 // ttl test
		} else if strings.Contains(subdomain, "wrong-id") {
			return 6 // return response with wrong txid
		} else if strings.Contains(subdomain, "wrong-rec") {
			return 7 // return response with wrong records
		} else if strings.Contains(subdomain, "bailiwick") {
			return 8 // bailiwick verification
		} else if strings.Contains(subdomain, "cname-chain") {
			return 9 // unlimited ns chain
		} else if strings.Contains(subdomain, "ns-chain") {
			return 10 // unlimited cname chain
		} else if strings.Contains(subdomain, "attack") {
			return 11
		}
	}
	return -1
}


func handleReflect(w dns.ResponseWriter, r *dns.Msg) {
	var (
		ip    net.IP
		name  string
		qtype uint16
	)
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = true
	m.Authoritative = true
	if addr, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		ip = addr.IP
	}
	name = m.Question[0].Name
	subdomain := strings.ToLower(strings.Split(name, ".")[0])
	qtype = m.Question[0].Qtype
	switch strategyMaker(name, qtype) {
	case 1:
		cname_subdomain := "rdns-" + strings.Replace(ip.String(), ".", "-", -1)
		cname_fqdn := dns.Fqdn(cname_subdomain + "." + CONFIG_SLD)
		cname := &dns.CNAME{
			Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 14400},
			Target: cname_fqdn,
		}
		//fmt.Println(name+" "+cname_fqdn)
		m.Answer = append(m.Answer, cname)
	case 2:
		cname_fqdn := dns.Fqdn("honey." + CONFIG_SLD)
		cname := &dns.CNAME{
			Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 14400},
			Target: cname_fqdn,
		}
		//fmt.Println(cname_fqdn)
		m.Answer = append(m.Answer, cname)
	case 3:
		//time_str := strconv.FormatInt(time.Now().UnixMicro(), 10)
		//time_int, _ := strconv.Atoi(time_str[5 : len(time_str)-2])
		//time_int += rand.Intn(10000)
		UniqueCounter += 1
		timestamp := InttoIPv4(uint32(UniqueCounter))
		a := &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 14400},
			A:   timestamp,
		}
		m.Answer = append(m.Answer, a)
	case 4:
		a := &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   ip,
		}
		m.Answer = append(m.Answer, a)
	case 5:
		query_ttl := TtlParser(name)
		//fmt.Println(query_ttl)
		a := &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: query_ttl},
			A:   ip,
		}
		m.Answer = append(m.Answer, a)
	case 6:
		m.MsgHdr.Id += 1
		a := &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   ip,
		}
		m.Answer = append(m.Answer, a)
	case 7:
		wrong_answer := &dns.AAAA{
			Hdr:  dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
			AAAA: net.ParseIP("fe80::7526:a2ae:a0b8:946d"),
		}
		m.Answer = append(m.Answer, wrong_answer)
	case 8:
		wrong_ns := &dns.NS{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
			Ns:  dns.Fqdn("dns.baidu.com"),
		}
		wrong_ns_ip := &dns.A{
			Hdr: dns.RR_Header{Name: "dns.baidu.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("159.75.200.247"),
		}
		m.Ns = append(m.Ns, wrong_ns)
		m.Extra = append(m.Extra, wrong_ns_ip)
	case 9:
		cname_target := ""
		labels := strings.Split(subdomain, "-")
		if labels[len(labels)-1] == "chain" {
			cname_target = subdomain + "-0"
		} else {
			iter_cnt, _ := strconv.Atoi(labels[len(labels)-1])
			iter_cnt += 1
			labels = append(labels[:len(labels)-1], strconv.Itoa(iter_cnt))
			cname_target = strings.Join(labels, "-")
			//cname_target = strings.Join([]string{labels[0], labels[1], strconv.Itoa(iter_cnt)}, "-")
		}
		cname_target = dns.Fqdn(cname_target + "." + CONFIG_SLD)
		cname_redir := &dns.CNAME{
			Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
			Target: cname_target,
		}
		m.Answer = append(m.Answer, cname_redir)
	case 10:
		ns_target := ""
		labels := strings.Split(subdomain, "-")
		if labels[len(labels)-1] == "chain" {
			ns_target = subdomain + "-0"
		} else {
			iter_cnt, _ := strconv.Atoi(labels[len(labels)-1])
			iter_cnt += 1
			labels = append(labels[:len(labels)-1], strconv.Itoa(iter_cnt))
			ns_target = strings.Join(labels, "-")
			//ns_target = strings.Join([]string{labels[0], labels[1], strconv.Itoa(iter_cnt)}, "-")
		}
		ns_target = dns.Fqdn(ns_target + "." + CONFIG_SLD)
		ns_delegation := &dns.NS{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
			Ns:  ns_target,
		}
		m.Ns = append(m.Ns, ns_delegation)
	case 11:
		ns_record := &dns.NS{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
			Ns:  "shiyan7.jthmfgz.icu.",
		}
		m.Ns = append(m.Ns, ns_record)
	case 0:
		a := &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
			A:   net.ParseIP("159.75.200.247"),
		}
		m.Answer = append(m.Answer, a)
	case -1:
		m.MsgHdr.Rcode = dns.RcodeNameError
	}
	w.WriteMsg(m)
}
*/

func getResults(c *gin.Context) {
	token, err := strconv.Atoi(c.Param("token"))
	if err != nil {
		c.IndentedJSON(http.StatusNotFound, gin.H{"message": "wrong token"})
		return
	}
	if data, ok := datastruct.Result_map[token]; ok {
		c.IndentedJSON(http.StatusOK, data)
		delete(datastruct.Result_map, token)
		return
	}
	c.IndentedJSON(http.StatusNotFound, gin.H{"message": "result not found"})
}

func main() {
	flag.StringVar(&CONFIG_SLD, "sld", "", "configure sld for echo dns server")
	flag.Parse()
	if CONFIG_SLD == "" {
		panic("Please configure the SLD for the echo dns server!\n")
	}

	router := gin.Default()
	router.GET("/results/:token", getResults)

	go router.Run(":8888")

	dns.HandleFunc(dns.Fqdn(CONFIG_SLD), query_handler)
	server := &dns.Server{Addr: ":53", Net: "udp"}
	if err := server.ListenAndServe(); err != nil {
		fmt.Println("Failed to set up dns server!")
		panic(err)
	}
}
