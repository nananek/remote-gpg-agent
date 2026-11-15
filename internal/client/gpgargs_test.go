package client

import (
	"testing"
)

func TestParseGpgArgs(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want GpgInvocation
	}{
		{
			name: "git",
			args: []string{"--status-fd=2", "-bsau", "ABCD1234"},
			want: GpgInvocation{Detach: true, Armor: true, StatusFD: 2, StatusSet: true, LocalUser: "ABCD1234"},
		},
		{
			name: "combined short opts",
			args: []string{"-bsauABCD1234"},
			want: GpgInvocation{Detach: true, Armor: true, LocalUser: "ABCD1234"},
		},
		{
			name: "makepkg",
			args: []string{"--detach-sign", "--use-agent", "--local-user", "ABCD", "pkg.tar.zst"},
			want: GpgInvocation{Detach: true, LocalUser: "ABCD", File: "pkg.tar.zst"},
		},
		{
			name: "verify is not detach-sign",
			args: []string{"--verify", "a.sig", "a"},
			want: GpgInvocation{File: "a"},
		},
		{
			name: "pinentry-mode consumes its argument",
			args: []string{"--pinentry-mode", "loopback", "--status-fd", "1", "-bsa"},
			want: GpgInvocation{Detach: true, Armor: true, StatusFD: 1, StatusSet: true},
		},
		{
			name: "local-user with equals",
			args: []string{"--detach-sign", "--local-user=DEADBEEF", "out.sig"},
			want: GpgInvocation{Detach: true, LocalUser: "DEADBEEF", File: "out.sig"},
		},
		{
			name: "--output takes the signature path and must not swallow the input file",
			args: []string{"--detach-sign", "--output", "pkg.sig", "pkg.tar.zst"},
			want: GpgInvocation{Detach: true, OutFile: "pkg.sig", File: "pkg.tar.zst"},
		},
		{
			name: "-o short form",
			args: []string{"-b", "-o", "pkg.sig", "pkg.tar.zst"},
			want: GpgInvocation{Detach: true, OutFile: "pkg.sig", File: "pkg.tar.zst"},
		},
		{
			name: "--output= with equals",
			args: []string{"--detach-sign", "--output=pkg.sig", "pkg.tar.zst"},
			want: GpgInvocation{Detach: true, OutFile: "pkg.sig", File: "pkg.tar.zst"},
		},
		{
			name: "--no-armor is kept for package signatures",
			args: []string{"--batch", "--detach-sign", "--no-armor", "--local-user", "ABCD", "pkg.tar.zst"},
			want: GpgInvocation{Detach: true, NoArmor: true, LocalUser: "ABCD", File: "pkg.tar.zst"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ParseGpgArgs(c.args)
			if got != c.want {
				t.Fatalf("got %+v want %+v", got, c.want)
			}
		})
	}
}

// git は `-bsau` の出力をそのまま gpgsig に入れる。binary を返すと git が
// 署名中の NUL で切り詰め、GitHub で unknown_signature_type (unverified) に
// なるため、stdout 向けは --no-armor でも armor のままにする。
func TestArmorOutput(t *testing.T) {
	cases := []struct {
		name string
		inv  GpgInvocation
		want bool
	}{
		{"git commit (stdin -> stdout)", GpgInvocation{Detach: true, Armor: true, StatusSet: true}, true},
		{"stdout stays armored even with --no-armor", GpgInvocation{Detach: true, NoArmor: true}, true},
		{"package .sig without --no-armor", GpgInvocation{Detach: true, File: "pkg.tar.zst"}, true},
		{"package .sig with --no-armor", GpgInvocation{Detach: true, NoArmor: true, File: "pkg.tar.zst"}, false},
		{"--output with --no-armor", GpgInvocation{Detach: true, NoArmor: true, OutFile: "pkg.sig"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.inv.ArmorOutput(); got != c.want {
				t.Fatalf("ArmorOutput() = %v, want %v", got, c.want)
			}
		})
	}
}
