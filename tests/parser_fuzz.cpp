// Fuzz target for the parsers that read text nobody has verified yet: the
// release index, key=value files, JSON and sandbox requests. Each must either
// accept the bytes or refuse them with an exception, and nothing else:
// no crash, no out-of-bounds read, no undefined behaviour, no hang.
//
// Built only by `make fuzz`, with Clang's libFuzzer and the sanitizers.
#include <cstddef>
#include <cstdint>
#include <exception>
#include <string>
#include <string_view>
#include <vector>
#include "bounded_json.h"
#include "native_control_support.h"
#include "release_fetch.h"
#include "sandbox_spec.h"

namespace {
template <typename Parser>
void Try(Parser parse) {
  try {
    parse();
  } catch (const std::exception&) {  // NOLINT(bugprone-empty-catch): refusing the input is a correct answer
  }
}
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const std::string_view text(reinterpret_cast<const char*>(data), size);
  Try([&] { (void)fortis::host::updates::ParseReleaseIndex(text); });
  Try([&] { (void)fortis::host::updates::KeyValues(text); });
  Try([&] { (void)fortis::host::sandbox::ParseSpec(text); });
  Try([&] { (void)fortis::host::sandbox::ParsePolicy(text); });
  std::vector<fortis::codec::BoundedJsonToken> tokens(256);
  fortis::codec::BoundedJsonDocument document;
  fortis::codec::BoundedJsonError error{};
  if (document.Parse(data, size, tokens.data(), tokens.size(), &error)) {
    for (uint32_t index = 0; index < document.token_count(); ++index) {
      std::string decoded(size + 1, '\0');
      size_t length = 0;
      double number = 0;
      (void)document.DecodeString(index, decoded.data(), decoded.size(), &length);
      (void)document.Number(index, &number);
      (void)document.FindObjectValue(index, "version");
    }
  }
  return 0;
}
