package client

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func writeFake(t *testing.T, path, tag string) {
	t.Helper()
	body := "#!/bin/sh\necho \"" + tag + " $*\"\n"
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

// シムが「detach-sign だけ rga、それ以外は本物の gpg」に振り分けることを確認する。
func TestGpgShimRouting(t *testing.T) {
	dir := t.TempDir()
	writeFake(t, filepath.Join(dir, "rga"), "RGA")
	writeFake(t, filepath.Join(dir, "realgpg"), "GPG")

	run := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("sh", "../../scripts/gpg-shim")
		cmd.Args = append(cmd.Args, args...)
		cmd.Env = append(os.Environ(),
			"PATH="+dir+":"+os.Getenv("PATH"),
			"REAL_GPG="+filepath.Join(dir, "realgpg"),
		)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("shim %v: %v", args, err)
		}
		return strings.TrimSpace(string(out))
	}

	if got := run("--detach-sign", "--use-agent", "pkg.tar.zst"); !strings.HasPrefix(got, "RGA") {
		t.Fatalf("--detach-sign must go to rga: %q", got)
	}
	if got := run("-bsau", "AAAA"); !strings.HasPrefix(got, "RGA") {
		t.Fatalf("-bsau must go to rga: %q", got)
	}
	if got := run("-bsa"); !strings.HasPrefix(got, "RGA") {
		t.Fatalf("-bsa must go to rga: %q", got)
	}
	if got := run("--verify", "a.sig", "a"); !strings.HasPrefix(got, "GPG") {
		t.Fatalf("--verify must go to the real gpg: %q", got)
	}
	if got := run("--list-keys"); !strings.HasPrefix(got, "GPG") {
		t.Fatalf("--list-keys must go to the real gpg: %q", got)
	}
}
