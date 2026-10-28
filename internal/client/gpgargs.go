package client

import "strings"

type GpgInvocation struct {
	Detach    bool
	Armor     bool
	StatusFD  int
	StatusSet bool
	LocalUser string
	File      string
}

// ParseGpgArgs は gpg 互換の引数列から、署名に必要な情報だけを取り出す。
// git は `--status-fd=2 -bsau <key>`、makepkg は
// `--detach-sign --use-agent --local-user <key> <file>` を渡してくる。
func ParseGpgArgs(argv []string) GpgInvocation {
	out := GpgInvocation{}
	var positionals []string

	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "--detach-sign":
			out.Detach = true
		case a == "--armor":
			out.Armor = true
		case a == "--local-user" || a == "-u":
			if i+1 < len(argv) {
				i++
				out.LocalUser = argv[i]
			}
		case strings.HasPrefix(a, "--local-user="):
			out.LocalUser = strings.TrimPrefix(a, "--local-user=")
		case a == "--status-fd":
			if i+1 < len(argv) {
				i++
				out.StatusFD = atoi(argv[i])
				out.StatusSet = true
			}
		case strings.HasPrefix(a, "--status-fd="):
			out.StatusFD = atoi(strings.TrimPrefix(a, "--status-fd="))
			out.StatusSet = true
		case a == "--pinentry-mode":
			i++
		case strings.HasPrefix(a, "--"):
			// --use-agent / --batch / --yes / --quiet などは無視
		case strings.HasPrefix(a, "-") && len(a) > 1:
			for j := 1; j < len(a); j++ {
				switch a[j] {
				case 'b':
					out.Detach = true
				case 'a':
					out.Armor = true
				case 'u':
					if rest := a[j+1:]; rest != "" {
						out.LocalUser = rest
					} else if i+1 < len(argv) {
						i++
						out.LocalUser = argv[i]
					}
					j = len(a)
				}
			}
		default:
			positionals = append(positionals, a)
		}
	}
	if len(positionals) > 0 {
		out.File = positionals[len(positionals)-1]
	}
	return out
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int(c-'0')
	}
	return n
}
