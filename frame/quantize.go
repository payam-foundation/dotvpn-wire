// SPDX-License-Identifier: AGPL-3.0-only OR PolyForm-Noncommercial-1.0.0

package frame

import "sort"

// overhead is every on-wire byte of a record that is not data or padding:
// mask(2) + type(1) + n(2) + AEAD tag.
const overhead = 2 + 3 + tagLen

// buckets are the on-wire record sizes Quantize rounds up to. The top bucket
// holds a full MaxData record.
var buckets = [...]int{128, 512, 1400, 4096, 8192, 16384}

// Quantize is an Opts.Pad that makes every record one of a few fixed sizes, so
// a passive observer sees a size histogram of six values rather than the real
// packet length distribution. Padding is invisible to the receiver, so a
// shaped end interoperates with an unshaped one.
func Quantize(n int) int {
	size := overhead + n
	i := sort.SearchInts(buckets[:], size)
	if i == len(buckets) {
		return 0
	}
	return buckets[i] - size
}
