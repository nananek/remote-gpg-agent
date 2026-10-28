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
