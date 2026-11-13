package client

import "testing"

func TestClassifyPurpose(t *testing.T) {
	cases := []struct {
		name string
		inv  GpgInvocation
		env  string
		want string
	}{
		{name: "git (stdin)", inv: GpgInvocation{Detach: true}, want: PurposeGitCommit},
		{name: "makepkg zst", inv: GpgInvocation{File: "foo-1.0-1-x86_64.pkg.tar.zst"}, want: PurposeMakepkg},
		{name: "makepkg xz", inv: GpgInvocation{File: "/tmp/build/foo-1.0-1-x86_64.pkg.tar.xz"}, want: PurposeMakepkg},
		{name: "repo db", inv: GpgInvocation{File: "custom.db.tar.gz"}, want: PurposeRepoDB},
		{name: "repo files db", inv: GpgInvocation{File: "custom.files.tar.zst"}, want: PurposeRepoDB},
		{name: "repo symlink", inv: GpgInvocation{File: "custom.db"}, want: PurposeRepoDB},
		{name: "plain file", inv: GpgInvocation{File: "release.tar.gz"}, want: PurposeFile},
		{name: "override", inv: GpgInvocation{File: "foo.pkg.tar.zst"}, env: "custom-type", want: "custom-type"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ClassifyPurpose(c.inv, c.env); got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestDescriptionFor(t *testing.T) {
	if got := DescriptionFor(GpgInvocation{File: "/tmp/foo-1.0.pkg.tar.zst"}, "/home/u/src", ""); got != "foo-1.0.pkg.tar.zst" {
		t.Fatalf("file description: %q", got)
	}
	if got := DescriptionFor(GpgInvocation{}, "/home/u/src", ""); got != "/home/u/src" {
		t.Fatalf("stdin description: %q", got)
	}
	if got := DescriptionFor(GpgInvocation{File: "x"}, "/home/u/src", "my label"); got != "my label" {
		t.Fatalf("override description: %q", got)
	}
}
