// Command devicebench measures how many devices a deployment can hold, each
// long-polling its own resource (§7.7) for a result, as a device that started
// a workflow run waits for it. It connects devices in steps, and in each step
// completes random connected devices' resources at a fixed rate while a
// background writer loads the same namespace. Per step it reports the devices
// held, how long a completion took to reach its device, the requests the
// devices made, errors, and its own CPU and memory, as JSON lines that
// deploy/devices-summary.py merges across processes.
//
//	patchlog serve -dev -max-rate-per-namespace 1e9,1e9 -max-rate-per-resource 1e9,1e9 -max-rate-per-principal 1e9,1e9 &
//	go run ./cmd/devicebench -setup -devices 20000
//	go run ./cmd/devicebench -devices 20000 -step 5000 -out steps.jsonl
//
// Several processes share one run by holding different ranges (-first) and
// the same -start-at, which aligns their steps. deploy/ec2-devices.sh runs it
// on EC2 instances of their own, apart from the servers.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	arg "github.com/alexflint/go-arg"
)

type args struct {
	URL         string        `arg:"--url" default:"http://localhost:8080" help:"servers the devices long-poll, comma-separated: device i uses the (i mod n)th"`
	WriteURL    string        `arg:"--write-url" help:"server the writers and -setup use (default: the first of --url)"`
	NS          string        `arg:"--ns" default:"devices" help:"namespace"`
	Setup       bool          `arg:"--setup" help:"create the namespace and resources dev-0 … dev-(devices-1), then exit"`
	First       int           `arg:"--first" help:"first device this process holds"`
	Devices     int           `arg:"--devices" default:"1000" help:"devices this process holds by its last step (with --setup: devices to create)"`
	Step        int           `arg:"--step" default:"1000" help:"devices added each step"`
	StepTime    time.Duration `arg:"--step-time" default:"60s" help:"how long each step is measured"`
	Settle      time.Duration `arg:"--settle" default:"15s" help:"time each step has to connect its devices before it is measured"`
	Ramp        int           `arg:"--ramp" default:"2000" help:"devices connected a second"`
	StartAt     int64         `arg:"--start-at" help:"Unix time the first step starts, the same for every process of a run (default: now)"`
	Completions float64       `arg:"--completions" default:"50" help:"writes a second to random connected devices' resources"`
	BG          float64       `arg:"--bg" default:"0" help:"background writes a second to other resources of the namespace"`
	Out         string        `arg:"--out" help:"append one JSON line per step here"`
	Label       string        `arg:"--label" help:"label carried in the output"`
	LocalIPs    int           `arg:"--local-ips" help:"rotate source addresses 127.0.0.2 … over this many, for more than one ephemeral port range of connections to a server on loopback"`
}

var a args

func main() {
	arg.MustParse(&a)
	if a.WriteURL == "" {
		a.WriteURL = strings.Split(a.URL, ",")[0]
	}
	if a.Setup {
		setup()
		return
	}
	run()
}

// plain is the writers' and -setup's: a pool big enough for the writers
// to keep their connections.
var plain = &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: 64, IdleConnTimeout: 2 * time.Minute}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func do(c *http.Client, method, url string, hdr map[string]string, body any) (int, http.Header, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		return 0, nil, nil, err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, resp.Header, b, err
}

func fail(f string, v ...any) {
	fmt.Fprintf(os.Stderr, "devicebench: "+f+"\n", v...)
	os.Exit(1)
}

func setup() {
	big := map[string]any{"rate": 1e9, "burst": 1e9}
	code, _, b, err := do(plain, "PATCH", a.WriteURL+"/ns/"+a.NS,
		map[string]string{"X-Author": "devicebench", "If-None-Match": "*", "Content-Type": "application/json-patch+json"},
		[]any{map[string]any{"op": "add", "path": "", "value": map[string]any{"read": "public",
			"limits": map[string]any{"ratePerResource": big, "ratePerPrincipal": big, "ratePerNamespace": big}}}})
	switch {
	case err != nil:
		fail("namespace: %v", err)
	case code == 412:
		fmt.Println("namespace", a.NS, "exists")
	case code != 201:
		fail("namespace: %d %s (is the server run with -dev and -max-rate-per-namespace raised?)", code, b)
	}
	made := 0
	for i := 0; i < a.Devices; i += 1000 {
		var items []any
		for j := i; j < min(i+1000, a.Devices); j++ {
			items = append(items, map[string]any{"resource": "dev-" + strconv.Itoa(j), "ifNoneMatch": "*",
				"steps": []any{[]any{map[string]any{"op": "add", "path": "", "value": map[string]any{"status": "running"}}}}})
		}
		code, _, b, err := do(plain, "POST", a.WriteURL+"/ns/"+a.NS+"/batch",
			map[string]string{"X-Author": "devicebench", "Content-Type": "application/json"}, map[string]any{"items": items})
		switch {
		case err != nil:
			fail("batch at %d: %v", i, err)
		case code == 201:
			made += len(items)
		case code == 200, code == 412 && bytes.Contains(b, []byte(`"stale"`)):
			// Made by an earlier setup: the same batch again (§7.2), or written to since.
		default:
			fail("batch at %d: %d %s", i, code, b)
		}
	}
	fmt.Printf("devices: %d made, %d in all\n", made, a.Devices)
}

// hist counts latencies in buckets 8% wide from 0.1 ms, so processes' counts merge.
type hist struct {
	mu sync.Mutex
	m  map[int]int64
}

func (h *hist) add(d time.Duration) {
	ms := float64(d.Microseconds()) / 1000
	i := 0
	if ms > 0.1 {
		i = int(math.Log(ms/0.1) / math.Log(1.08))
	}
	h.mu.Lock()
	h.m[i]++
	h.mu.Unlock()
}

func (h *hist) take() map[string]int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := map[string]int64{}
	for k, v := range h.m {
		out[strconv.Itoa(k)] = v
	}
	h.m = map[int]int64{}
	return out
}

// pct reads a percentile off counts: the bucket's upper bound, in ms.
func pct(m map[string]int64, p float64) float64 {
	var keys []int
	var n int64
	for k, v := range m {
		i, _ := strconv.Atoi(k)
		keys = append(keys, i)
		n += v
	}
	if n == 0 {
		return 0
	}
	sort.Ints(keys)
	want := int64(math.Ceil(p * float64(n)))
	var seen int64
	for _, k := range keys {
		seen += m[strconv.Itoa(k)]
		if seen >= want {
			return math.Round(0.1*math.Pow(1.08, float64(k+1))*10) / 10
		}
	}
	return 0
}

var (
	connected, waiting                       atomic.Int64
	polls, wakes, timeouts                   atomic.Int64
	connErrs, statusErrs                     atomic.Int64
	completions, writeErrs, bgWrites, bgErrs atomic.Int64
	delivery                                 = &hist{m: map[int]int64{}}
	writeLat                                 = &hist{m: map[int]int64{}}
	sentAt                                   sync.Map // device name -> time its completion was sent
	liveMu                                   sync.RWMutex
	live                                     []int // connected devices
	ipSeq                                    atomic.Int64
)

// transport is one per server: a device holds one of its connections at a
// time, so the pool needs as many idle connections as devices.
func transport() *http.Transport {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	t := &http.Transport{MaxIdleConns: 0, MaxIdleConnsPerHost: 1 << 20, IdleConnTimeout: 5 * time.Minute,
		DialContext: d.DialContext}
	if a.LocalIPs > 0 {
		t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			dd := *d
			dd.LocalAddr = &net.TCPAddr{IP: net.ParseIP(fmt.Sprintf("127.0.0.%d", 2+ipSeq.Add(1)%int64(a.LocalIPs)))}
			return dd.DialContext(ctx, network, addr)
		}
	}
	return t
}

func device(c *http.Client, base string, i int) {
	name := "dev-" + strconv.Itoa(i)
	since, cursor, first := "", "", true
	for {
		u := base + "/r/" + a.NS + "/" + name + "/log?live=long-poll&since=" + since
		if cursor != "" {
			u += "&cursor=" + cursor
		}
		waiting.Add(1)
		code, h, _, err := do(c, "GET", u, nil, nil)
		waiting.Add(-1)
		polls.Add(1)
		if err != nil {
			connErrs.Add(1)
			time.Sleep(time.Second + rand.N(time.Second))
			continue
		}
		cursor = h.Get("X-Cursor")
		switch code {
		case 200:
			since = h.Get("X-Revision")
			if first {
				first = false
				connected.Add(1)
				liveMu.Lock()
				live = append(live, i)
				liveMu.Unlock()
				continue
			}
			wakes.Add(1)
			if t, ok := sentAt.LoadAndDelete(name); ok {
				delivery.add(time.Since(t.(time.Time)))
			}
		case 204:
			timeouts.Add(1)
		default:
			statusErrs.Add(1)
			time.Sleep(time.Second + rand.N(time.Second))
		}
	}
}

// completer writes to the connected devices of its share (index mod of n == k).
func completer(rate float64, k, of int) {
	heads := map[string]string{}
	tick := time.NewTicker(time.Duration(float64(time.Second) / rate))
	for range tick.C {
		liveMu.RLock()
		n := len(live)
		var i int
		found := false
		for try := 0; try < 8 && n > 0; try++ {
			i = live[rand.IntN(n)]
			if i%of == k {
				found = true
				break
			}
		}
		liveMu.RUnlock()
		if !found {
			continue
		}
		name := "dev-" + strconv.Itoa(i)
		head, ok := heads[name]
		if !ok {
			code, h, _, err := do(plain, "GET", a.WriteURL+"/r/"+a.NS+"/"+name, nil, nil)
			if err != nil || code != 302 {
				writeErrs.Add(1)
				continue
			}
			head = strings.Trim(h.Get("Etag"), `"`)
		}
		t := time.Now()
		sentAt.Store(name, t)
		code, h, b, err := do(plain, "PATCH", a.WriteURL+"/r/"+a.NS+"/"+name,
			map[string]string{"X-Author": "devicebench", "Content-Type": "application/json-patch+json", "If-Match": `"` + head + `"`},
			[]any{map[string]any{"op": "replace", "path": "/status", "value": "done " + strconv.FormatInt(t.UnixMilli(), 10)}})
		switch {
		case err == nil && (code == 201 || code == 200):
			writeLat.add(time.Since(t))
			heads[name] = strings.Trim(h.Get("Etag"), `"`)
			completions.Add(1)
		case err == nil && code == 412:
			sentAt.Delete(name)
			var e struct{ Head string }
			json.Unmarshal(b, &e)
			heads[name] = e.Head
			writeErrs.Add(1)
		default:
			sentAt.Delete(name)
			delete(heads, name)
			writeErrs.Add(1)
		}
	}
}

// background creates and then appends to 250 resources of its own.
func background(rate float64, k int) {
	host, _ := os.Hostname()
	heads := map[string]string{}
	n := 0
	tick := time.NewTicker(time.Duration(float64(time.Second) / rate))
	for range tick.C {
		name := fmt.Sprintf("bg-%s-%d-%d", host, k, n%250)
		n++
		hdr := map[string]string{"X-Author": "devicebench", "Content-Type": "application/json-patch+json"}
		ops := []any{map[string]any{"op": "replace", "path": "/n", "value": n}}
		if head, ok := heads[name]; ok {
			hdr["If-Match"] = `"` + head + `"`
		} else {
			hdr["If-None-Match"] = "*"
			ops = []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"n": n}}}
		}
		code, h, b, err := do(plain, "PATCH", a.WriteURL+"/r/"+a.NS+"/"+name, hdr, ops)
		switch {
		case err == nil && (code == 201 || code == 200):
			heads[name] = strings.Trim(h.Get("Etag"), `"`)
			bgWrites.Add(1)
		case err == nil && code == 412:
			var e struct{ Head string }
			json.Unmarshal(b, &e)
			if e.Head != "" {
				heads[name] = e.Head
			}
			bgErrs.Add(1)
		default:
			bgErrs.Add(1)
		}
	}
}

func selfStat() (cpu, rssMB float64) {
	b, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0, 0
	}
	s := string(b)
	f := strings.Fields(s[strings.LastIndex(s, ")")+2:])
	u, _ := strconv.ParseFloat(f[11], 64)
	st, _ := strconv.ParseFloat(f[12], 64)
	rss, _ := strconv.ParseFloat(f[21], 64)
	return (u + st) / 100, rss * float64(os.Getpagesize()) / 1e6
}

func round(f float64) float64 { return math.Round(f*10) / 10 }

func run() {
	urls := strings.Split(a.URL, ",")
	clients := make([]*http.Client, len(urls))
	for i := range urls {
		clients[i] = &http.Client{Transport: transport(), Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	start := time.Now()
	if a.StartAt > 0 {
		start = time.Unix(a.StartAt, 0)
		if late := time.Since(start); late > 5*time.Second {
			fmt.Fprintf(os.Stderr, "devicebench: started %s after --start-at: its steps are out of line with other processes'\n", late.Round(time.Second))
		}
		time.Sleep(time.Until(start))
	}
	if a.Completions > 0 {
		of := max(1, int(math.Ceil(a.Completions/40)))
		for k := 0; k < of; k++ {
			go completer(a.Completions/float64(of), k, of)
		}
	}
	if a.BG > 0 {
		of := max(1, int(math.Ceil(a.BG/40)))
		for k := 0; k < of; k++ {
			go background(a.BG/float64(of), k)
		}
	}
	var out *os.File
	if a.Out != "" {
		var err error
		if out, err = os.OpenFile(a.Out, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err != nil {
			fail("%v", err)
		}
		defer out.Close()
	}
	period := a.Settle + a.StepTime
	next, end := a.First, a.First+a.Devices
	for step := 0; next < end; step++ {
		begin := start.Add(time.Duration(step) * period)
		time.Sleep(time.Until(begin))
		target := min(next+a.Step, end)
		for next < target {
			n := min(target-next, max(1, a.Ramp/10))
			for i := next; i < next+n; i++ {
				go device(clients[i%len(urls)], urls[i%len(urls)], i)
			}
			next += n
			time.Sleep(100 * time.Millisecond)
		}
		time.Sleep(time.Until(begin.Add(a.Settle)))
		delivery.take()
		writeLat.take()
		p0, w0, t0, ce0, se0 := polls.Load(), wakes.Load(), timeouts.Load(), connErrs.Load(), statusErrs.Load()
		c0, we0, b0, be0 := completions.Load(), writeErrs.Load(), bgWrites.Load(), bgErrs.Load()
		cpu0, _ := selfStat()
		m0 := time.Now()
		late := m0.Sub(begin.Add(a.Settle))
		time.Sleep(time.Until(begin.Add(period)))
		el := time.Since(m0).Seconds()
		cpu1, rss := selfStat()
		d, w := delivery.take(), writeLat.take()
		var delivered int64
		for _, v := range d {
			delivered += v
		}
		res := map[string]any{
			"label": a.Label, "step": step, "start": m0.Unix(), "end": time.Now().Unix(), "seconds": round(el), "late_s": round(late.Seconds()),
			"devices_target": target - a.First, "devices": connected.Load(), "waiting": waiting.Load(),
			"polls": polls.Load() - p0, "wakes": wakes.Load() - w0, "timeouts_204": timeouts.Load() - t0,
			"conn_errors": connErrs.Load() - ce0, "status_errors": statusErrs.Load() - se0,
			"completions": completions.Load() - c0, "write_errors": writeErrs.Load() - we0,
			"bg_writes": bgWrites.Load() - b0, "bg_errors": bgErrs.Load() - be0,
			"delivered": delivered, "delivery_hist": d, "write_hist": w,
			"self_cores": round((cpu1 - cpu0) / el), "self_rss_mb": round(rss),
		}
		b, _ := json.Marshal(res)
		if out != nil {
			out.Write(append(b, '\n'))
		}
		fmt.Printf("step %d: %d devices (%d waiting), %.1f completions/s, delivery p50 %.1f p99 %.1f ms, %d delivered, errors conn %d status %d write %d, self %.1f cores %.0f MB\n",
			step, connected.Load(), waiting.Load(), float64(completions.Load()-c0)/el, pct(d, .5), pct(d, .99), delivered,
			connErrs.Load()-ce0, statusErrs.Load()-se0, writeErrs.Load()-we0, round((cpu1-cpu0)/el), rss)
	}
}
