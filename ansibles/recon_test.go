package main

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// The survey once reported the page cache of a Debian 7 host as its available
// memory, so its awk program is run here against both kernel generations.
func TestReconMemoryRow(t *testing.T) {
	src, err := os.ReadFile("scripts/recon.sh")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`awk '([^']+)' /proc/meminfo`).FindSubmatch(src)
	if m == nil {
		t.Fatal("recon.sh no longer reads /proc/meminfo with awk")
	}
	for _, c := range []struct{ name, meminfo, want string }{
		{
			"kernel before 3.14: free + buffers + cache, without shared memory",
			"MemTotal: 1025756 kB\nMemFree: 164576 kB\nBuffers: 146748 kB\nCached: 272616 kB\n" +
				"SwapCached: 1832 kB\nShmem: 102400 kB\n",
			"1001 MB total, 470 MB available",
		},
		{
			"kernel with MemAvailable: its own estimate wins",
			"MemTotal: 2048000 kB\nMemFree: 102400 kB\nMemAvailable: 1024000 kB\nBuffers: 51200 kB\n" +
				"Cached: 921600 kB\nShmem: 512000 kB\n",
			"2000 MB total, 1000 MB available",
		},
	} {
		cmd := exec.Command("awk", string(m[1]))
		cmd.Stdin = strings.NewReader(c.meminfo)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", c.name, err, out)
		}
		if string(out) != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, out, c.want)
		}
	}
}
