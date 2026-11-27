package scanner

import (
	"bytes"
	"strings"
	"testing"

	"github.com/eminalolita-coder/git-scanner/internal/patterns"
)

// Deux paires SES dans le meme fichier, separees de plus de 100 lignes : la
// recherche en fenetre doit rendre le secret VOISIN, pas celui de l'autre paire.
func TestPairingUsesWindowNotWholeFile(t *testing.T) {
	const key1, pass1 = "AKIAIOSFODNN7EXAMPLE", "Bf3xK9mQ2rT7vL1nW8sY4pZ6cH0jD5gA2eR9uI3oX7kA"
	const key2, pass2 = "AKIAIOSFODNN8EXAMPLE", "Zq7wR2tY9uP4aS6dF8gH1jK3lM5nB7vC9xZ2qW4eR6tY"

	var b bytes.Buffer
	b.WriteString("SMTP_USERNAME=" + key1 + "\nSMTP_PASSWORD=" + pass1 + "\n")
	for i := 0; i < 200; i++ {
		b.WriteString("# filler line to push the second pair far away\n")
	}
	b.WriteString("SMTP_USERNAME=" + key2 + "\nSMTP_PASSWORD=" + pass2 + "\n")
	content := b.Bytes()

	idx := bytes.Index(content, []byte(key2))
	if idx < 0 {
		t.Fatal("cle 2 introuvable")
	}

	// fenetre: doit trouver pass2
	win := lineWindow(content, idx, 100)
	if got := patterns.BestSESPassword(win, key2, patterns.DefaultSecretEntropy); got != pass2 {
		t.Errorf("dans la fenetre: got %q, want %q", got, pass2)
	}
	// tout le fichier: trouverait pass1 (premier token 40 car. du fichier)
	if got := patterns.BestSESPassword(content, key2, patterns.DefaultSecretEntropy); got != pass1 {
		t.Logf("note: fichier entier -> %q (attendu pass1 pour montrer la difference)", got)
	}
}

func TestLineWindowBounds(t *testing.T) {
	content := []byte("a\nb\nc\nd\ne\nf\ng\n")
	// offset sur 'd' (index 6)
	win := lineWindow(content, 6, 2)
	s := string(win)
	if !strings.Contains(s, "d") {
		t.Fatalf("la fenetre doit contenir la ligne cible, got %q", s)
	}
	if strings.Contains(s, "g") {
		t.Errorf("la fenetre (±2 lignes) ne doit pas atteindre g: %q", s)
	}
	if got := lineWindow(content, 0, 100); len(got) != len(content) {
		t.Errorf("offset 0 + grande fenetre doit couvrir tout le contenu")
	}
}
