package unicodepolicy

import (
	"errors"
	"sort"
	"unicode/utf8"
)

const (
	UnicodeVersion = "17.0.0"
	TableSHA256    = "3d7664f62e9abe69851726e858e1214a860dbe2ab0a2adbd6b3c79cbb4ff2649"
)

type scalarRange struct {
	category string
	start    rune
	end      rune
	step     rune
}

var unsafeScalarRanges = [...]scalarRange{
	{category: "Cc", start: 0x000000, end: 0x00001f, step: 1},
	{category: "Cc", start: 0x00007f, end: 0x00009f, step: 1},
	{category: "Cf", start: 0x0000ad, end: 0x000600, step: 1363},
	{category: "Cf", start: 0x000601, end: 0x000605, step: 1},
	{category: "Cf", start: 0x00061c, end: 0x0006dd, step: 193},
	{category: "Cf", start: 0x00070f, end: 0x000890, step: 385},
	{category: "Cf", start: 0x000891, end: 0x0008e2, step: 81},
	{category: "Cf", start: 0x00180e, end: 0x00200b, step: 2045},
	{category: "Cf", start: 0x00200c, end: 0x00200f, step: 1},
	{category: "Zl", start: 0x002028, end: 0x002028, step: 1},
	{category: "Zp", start: 0x002029, end: 0x002029, step: 1},
	{category: "Cf", start: 0x00202a, end: 0x00202e, step: 1},
	{category: "Cf", start: 0x002060, end: 0x002064, step: 1},
	{category: "Cf", start: 0x002066, end: 0x00206f, step: 1},
	{category: "Cf", start: 0x00feff, end: 0x00fff9, step: 250},
	{category: "Cf", start: 0x00fffa, end: 0x00fffb, step: 1},
	{category: "Cf", start: 0x0110bd, end: 0x0110cd, step: 16},
	{category: "Cf", start: 0x013430, end: 0x01343f, step: 1},
	{category: "Cf", start: 0x01bca0, end: 0x01bca3, step: 1},
	{category: "Cf", start: 0x01d173, end: 0x01d17a, step: 1},
	{category: "Cf", start: 0x0e0001, end: 0x0e0020, step: 31},
	{category: "Cf", start: 0x0e0021, end: 0x0e007f, step: 1},
}

var ErrInvalidUTF8 = errors.New("value is not valid UTF-8")

func DecodeUTF8(value []byte) (string, error) {
	if !utf8.Valid(value) {
		return "", ErrInvalidUTF8
	}
	return string(value), nil
}

func ValidScalarString(value string) bool {
	return utf8.ValidString(value)
}

func IsUnsafeScalar(value rune) bool {
	index := sort.Search(len(unsafeScalarRanges), func(index int) bool {
		return unsafeScalarRanges[index].end >= value
	})
	if index == len(unsafeScalarRanges) {
		return false
	}
	candidate := unsafeScalarRanges[index]
	return value >= candidate.start && (value-candidate.start)%candidate.step == 0
}

func ContainsUnsafeScalar(value string) bool {
	if !ValidScalarString(value) {
		return true
	}
	for _, character := range value {
		if IsUnsafeScalar(character) {
			return true
		}
	}
	return false
}
