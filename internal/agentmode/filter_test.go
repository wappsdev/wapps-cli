package agentmode

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFilterScrubbable_NoteFiresForSubFloorSecret (P3-b): floor'un ALTINDA kalan
// gerçek-görünümlü bir gizli değer scrubber'a verilemez (transcript'i bozmamak için)
// ama bu bir SIZINTI riskidir → operatöre TEK bir stderr notu yazılmalı. Floor
// üstündeki uzun sır normal biçimde scrub setinde kalır.
func TestFilterScrubbable_NoteFiresForSubFloorSecret(t *testing.T) {
	var note bytes.Buffer
	got := FilterScrubbable([]string{"ab", "sk_live_longsecret"}, &note)

	require.Equal(t, []string{"sk_live_longsecret"}, got, "floor-üstü sır scrub setinde kalmalı")
	assert.Contains(t, note.String(), "NOT redacted", "sub-floor sır için sızıntı notu fire etmeli")
	assert.NotContains(t, note.String(), "ab", "not ASLA değer içermemeli")
}

// TestFilterScrubbable_OneConsolidatedNote, birden çok sub-floor sır için TEK bir
// not satırı yazıldığını (spam değil) kanıtlar ("one-time" note).
func TestFilterScrubbable_OneConsolidatedNote(t *testing.T) {
	var note bytes.Buffer
	got := FilterScrubbable([]string{"ab", "cd", "ef"}, &note)
	require.Empty(t, got)
	assert.Equal(t, 1, strings.Count(note.String(), "\n"), "birden çok sub-floor sır → tek not satırı")
}

// TestFilterScrubbable_NoNoteForLiteralsAndShortDigits, yaygın literaller (true/null)
// ve SUB-FLOOR saf-basamak değerler (kısa sayaç/index) için not FIRE ETMEDİĞİNİ
// kanıtlar — bunlar sır değildir, atlanmaları sızıntı sayılmaz. (Floor-üstü değerler
// güvenlik-önce yaklaşımıyla scrub edilir; sızıntı notu YALNIZCA sub-floor gerçek-
// görünümlü değerler içindir.)
func TestFilterScrubbable_NoNoteForLiteralsAndShortDigits(t *testing.T) {
	var note bytes.Buffer
	got := FilterScrubbable([]string{"true", "null", "12"}, &note)
	assert.Empty(t, got, "literaller + sub-floor saf-basamak scrub edilmez")
	assert.Empty(t, note.String(), "literal/kısa-basamak değerler sızıntı notu TETİKLEMEZ")
}

// TestFilterScrubbable_LoweredFloorScrubsShortSecret, tabanın DÜŞÜRÜLDÜĞÜNÜ (eski 5
// yerine 4) kanıtlar: 4 karakterlik gerçek bir sır artık scrub setinde.
func TestFilterScrubbable_LoweredFloorScrubsShortSecret(t *testing.T) {
	var note bytes.Buffer
	got := FilterScrubbable([]string{"a1b2"}, &note) // len 4 == ScrubFloor
	require.Equal(t, []string{"a1b2"}, got, "floor'a (4) eşit uzunlukta sır scrub edilmeli")
	assert.Empty(t, note.String())
}
