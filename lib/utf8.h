#pragma once
#include <stddef.h>
#include <stdint.h>

namespace fortis::codec::utf8 {
// Unicode scalar values only: no overlongs, UTF-16 surrogate code points,
// truncated sequences, or values above U+10FFFF.
inline bool Valid(const uint8_t* text, size_t length) {
  if (!text && length) return false;
  for (size_t i = 0; i < length;) {
    const unsigned c = text[i++];
    if (c < 0x80) continue;
    unsigned count = 0, value = 0, minimum = 0;
    if (c >= 0xc2 && c <= 0xdf) { count = 1; value = c & 31; minimum = 0x80; }
    else if (c >= 0xe0 && c <= 0xef) { count = 2; value = c & 15; minimum = 0x800; }
    else if (c >= 0xf0 && c <= 0xf4) { count = 3; value = c & 7; minimum = 0x10000; }
    else return false;
    if (count > length - i) return false;
    while (count--) {
      const unsigned next = text[i++];
      if ((next & 0xc0) != 0x80) return false;
      value = (value << 6) | (next & 63);
    }
    if (value < minimum || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff)) return false;
  }
  return true;
}
// Decode one scalar with Unicode maximal-subpart replacement. An invalid
// continuation is left for the next call; a valid prefix is consumed once.
inline uint32_t Next(const uint8_t* text, size_t length, size_t* position) {
  if (*position >= length) return 0xfffd;
  const unsigned c = text[(*position)++];
  if (c < 0x80) return c;
  unsigned need = 0, value = 0, low = 0x80, high = 0xbf;
  if (c >= 0xc2 && c <= 0xdf) { need = 1; value = c & 31; }
  else if (c >= 0xe0 && c <= 0xef) {
    need = 2; value = c & 15;
    if (c == 0xe0) low = 0xa0;
    if (c == 0xed) high = 0x9f;
  } else if (c >= 0xf0 && c <= 0xf4) {
    need = 3; value = c & 7;
    if (c == 0xf0) low = 0x90;
    if (c == 0xf4) high = 0x8f;
  } else return 0xfffd;
  while (need--) {
    if (*position >= length) return 0xfffd;
    const unsigned next = text[*position];
    if (next < low || next > high) return 0xfffd;
    ++*position;
    value = (value << 6) | (next & 63);
    low = 0x80; high = 0xbf;
  }
  return value;
}
// Returns the complete normalized byte length. No terminator is written;
// a short buffer receives a prefix, and nullptr/0 measures without writing.
inline size_t Normalize(const uint8_t* text, size_t length, char* output, size_t capacity) {
  size_t size = 0;
  auto put = [&](unsigned byte) {
    if (size < capacity) output[size] = static_cast<char>(byte);
    ++size;
  };
  for (size_t i = 0; i < length;) {
    const uint32_t cp = Next(text, length, &i);
    if (cp < 0x80) put(cp);
    else if (cp < 0x800) { put(0xc0 | (cp >> 6)); put(0x80 | (cp & 63)); }
    else if (cp < 0x10000) { put(0xe0 | (cp >> 12)); put(0x80 | ((cp >> 6) & 63)); put(0x80 | (cp & 63)); }
    else { put(0xf0 | (cp >> 18)); put(0x80 | ((cp >> 12) & 63)); put(0x80 | ((cp >> 6) & 63)); put(0x80 | (cp & 63)); }
  }
  return size;
}
}  // namespace fortis::codec::utf8
