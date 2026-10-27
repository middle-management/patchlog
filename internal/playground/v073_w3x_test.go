package playground

import (
	"encoding/json"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// W3X (P28 RH-35 x the playground; §7.3): a namespace's event stream ends
// after its purge-ns entry, and the server ends every reconnect at once,
// so the live namespace stream closes its EventSource on that event
// instead of reconnecting every few seconds while the page is open. Other
// events, and a resource stream's purge, leave the stream open.
func TestW3XPlaygroundStreamEndsOnPurgeNS(t *testing.T) {
	t.Parallel()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	js, err := assets.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	var src strings.Builder
	src.WriteString(`
const els = {};
const $ = (id) => (els[id] = els[id] || { id, checked: true, hidden: false, textContent: '', className: '',
  firstChild: null, children: { length: 0 }, prepend() {}, replaceChildren() {} });
const h = () => ({});
const kindBadge = () => null, idEl = () => null, jsonPre = () => null;
const renderEntry = () => {};
let refreshTimer;
const refreshNS = async () => {}, refreshRes = async () => {};
const S = { ns: 'n', nsHead: '', res: 'r', resState: null };
const streams = { ns: null, res: null };
const open = (kind) => {
  const es = { closed: false, close() { this.closed = true; } };
  return (streams[kind] = { es, entry: { resBody: '' }, seen: new Set() });
};
`)
	for _, f := range []string{"liveUrl", "updateLiveUrls", "setStreamState", "onStreamEvent"} {
		src.WriteString(jsFunction(t, js, f) + "\n")
	}
	// The helpers onStreamEvent calls, those app.js has.
	for _, f := range []string{"endStream", "stopStream"} {
		if regexp.MustCompile(`(?m)^function ` + f + `\(`).Match(js) {
			src.WriteString(jsFunction(t, js, f) + "\n")
		}
	}
	src.WriteString(`
const ev = (id, data) => ({ lastEventId: id, data: JSON.stringify(data) });
const ns = open('ns'), res = open('res');
onStreamEvent('ns', ns, 'head', ev('1a', { resource: 'r' }));
onStreamEvent('res', res, 'purge', ev('', { ns: 'n', name: 'r' }));
const before = { ns: !!streams.ns && !ns.es.closed, res: !!streams.res && !res.es.closed };
onStreamEvent('ns', ns, 'purge-ns', ev('1b', {}));
process.stdout.write(JSON.stringify({ before, closed: ns.es.closed, stream: streams.ns === null, checked: $('liveNs').checked,
  badge: $('liveNsSt').textContent, resOpen: !!streams.res && !res.es.closed, body: ns.entry.resBody.includes('namespace purged') }));
`)
	out, err := exec.Command(node, "-e", src.String()).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	var got struct {
		Before  struct{ NS, Res bool }
		Closed  bool
		Stream  bool
		Checked bool
		Badge   string
		ResOpen bool
		Body    bool
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if !got.Before.NS || !got.Before.Res {
		t.Errorf("a head event or a resource purge closed a stream: %s", out)
	}
	if !got.Closed || !got.Stream || got.Checked || !strings.Contains(got.Badge, "purged") || !got.Body {
		t.Errorf("after purge-ns, the namespace stream: %s, want its EventSource closed, the stream off and unchecked, and the badge saying why", out)
	}
	if !got.ResOpen {
		t.Errorf("the resource stream was closed with it: %s", out)
	}
}
