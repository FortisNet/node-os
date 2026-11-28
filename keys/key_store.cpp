#include "key_store.h"

#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <mbedtls/sha512.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <stdexcept>
#include <string>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace fortis::keys {
namespace {
namespace fs = std::filesystem;
namespace p = primitives;

constexpr size_t kFileMax = 64 * 1024;
constexpr std::string_view kIdentityMagic = "FKI1";
constexpr std::string_view kMachineMagic = "FKM1";
constexpr std::string_view kIdentityFile = "identity.key";
constexpr std::string_view kMachineFile = "machine.key";
constexpr std::string_view kPublicFile = "identity.public";

[[noreturn]] void Fail(const std::string& what) { throw std::runtime_error("key store: " + what); }
void Require(bool condition, const char* what) {
  if (!condition) Fail(what);
}

// A byte buffer that wipes itself: serialized files hold secret keys. Its
// room is reserved once, for the largest key file, so it never reallocates:
// a reallocation would free a copy of the secrets without wiping it.
struct Buffer {
  Bytes bytes;
  Buffer() { bytes.reserve(kFileMax); }
  ~Buffer() { Wipe(bytes); }
  Buffer(const Buffer&) = delete;
  Buffer& operator=(const Buffer&) = delete;
  void Room(size_t n) const { Require(n <= bytes.capacity() - bytes.size(), "a key file outgrew its buffer"); }
  void Text(std::string_view text) {
    Room(text.size());
    bytes.insert(bytes.end(), text.begin(), text.end());
  }
  void Byte(uint8_t v) {
    Room(1);
    bytes.push_back(v);
  }
  void U32(uint32_t v) {
    for (int shift = 24; shift >= 0; shift -= 8) Byte(static_cast<uint8_t>(v >> shift));
  }
  void U64(uint64_t v) {
    for (int shift = 56; shift >= 0; shift -= 8) Byte(static_cast<uint8_t>(v >> shift));
  }
  void Field(View v) {
    U32(static_cast<uint32_t>(v.size()));
    Room(v.size());
    bytes.insert(bytes.end(), v.begin(), v.end());
  }
};

struct Reader {
  View data;
  size_t at = 0;
  View Take(size_t n) {
    Require(n <= data.size() - at, "file is cut short");
    auto out = data.subspan(at, n);
    at += n;
    return out;
  }
  uint64_t Number(int bytes) {
    uint64_t v = 0;
    for (const auto b : Take(static_cast<size_t>(bytes))) v = v << 8 | b;
    return v;
  }
  View Field(size_t max) {
    const auto n = Number(4);
    Require(n <= max, "field too long");
    return Take(static_cast<size_t>(n));
  }
};

std::array<uint8_t, 64> Sha512(View data) {
  std::array<uint8_t, 64> out{};
  Require(mbedtls_sha512(data.data(), data.size(), out.data(), 0) == 0, "SHA-512 failed");
  return out;
}

SecretBytes Copy(View secret) {
  SecretBytes out(secret.size());
  std::memcpy(out.Bytes().data(), secret.data(), secret.size());
  return out;
}

KeyPair Generate(Algorithm algorithm) {
  const auto sizes = SizesOf(algorithm);
  KeyPair pair{algorithm, Bytes(sizes.public_key), SecretBytes(sizes.secret_key)};
  bool ok = false;
  switch (algorithm) {
    case Algorithm::MlDsa87:
      ok = p::MlDsa87KeyPair(std::span<uint8_t, 2592>(pair.public_key),
                             std::span<uint8_t, 4896>(pair.secret_key.Bytes().data(), 4896));
      break;
    case Algorithm::SqiSignV:
      ok = p::SqiSignVKeyPair(std::span<uint8_t, 169>(pair.public_key),
                              std::span<uint8_t, 549>(pair.secret_key.Bytes().data(), 549));
      break;
    case Algorithm::Secp256k1:
      ok = p::Secp256k1KeyPair(std::span<uint8_t, 65>(pair.public_key),
                               std::span<uint8_t, 32>(pair.secret_key.Bytes().data(), 32));
      break;
  }
  Require(ok, "key generation failed");
  return pair;
}

// The ML-DSA-87 root, from the master: the seed is HKDF(master, "pq2:did-update:ML-DSA-87").
}  // namespace

KeyPair DeriveUpdateRoot(View master) {
  SecretBytes seed(32);
  Derive(master, "pq2:did-update:ML-DSA-87", std::span<uint8_t, 32>(seed.Bytes().data(), 32));
  std::array<uint8_t, 32> s{};
  std::memcpy(s.data(), seed.Bytes().data(), 32);
  KeyPair pair{Algorithm::MlDsa87, Bytes(kMlDsa87Sizes.public_key), SecretBytes(kMlDsa87Sizes.secret_key)};
  const bool ok = p::MlDsa87KeyPair(std::span<uint8_t, 2592>(pair.public_key),
                                    std::span<uint8_t, 4896>(pair.secret_key.Bytes().data(), 4896), &s);
  Wipe(s);
  Require(ok, "ML-DSA-87 root derivation failed");
  return pair;
}

// The account key, from the master: the first HKDF(master, "evm:secp256k1:i") that is a valid scalar.
KeyPair DeriveAccount(View master) {
  KeyPair pair{Algorithm::Secp256k1, Bytes(65), SecretBytes(32)};
  for (int i = 0; i < 1024; ++i) {
    auto scalar = std::span<uint8_t, 32>(pair.secret_key.Bytes().data(), 32);
    Derive(master, "evm:secp256k1:" + std::to_string(i), scalar);
    if (p::Secp256k1PublicKey(std::span<uint8_t, 65>(pair.public_key), scalar)) return pair;
  }
  Fail("secp256k1 derivation exhausted");
}

namespace {

// Each private key must make signatures its public key accepts.
void Check(const KeyPair& pair) {
  static constexpr uint8_t kProbe[] = {'F', 'O', 'R', 'T', 'I', 'S', '-', 'K', 'E', 'Y', '-', 'C', 'H', 'E', 'C', 'K'};
  const View message(kProbe);
  const Stamp stamp{};  // a check signature is never given out, so it needs no real stamp
  const auto sig = p::SignLabelled(pair.algorithm, pair.secret_key.Bytes(), "key-check", stamp, message);
  if (sig.empty() || !Verify(pair.algorithm, pair.public_key, "key-check", message, stamp, sig))
    Fail(std::string(Name(pair.algorithm)) + " private key does not match its public key");
}

void SetId(Machine& machine) {
  const auto digest = Sha512(machine.key.public_key);
  std::copy(digest.begin(), digest.begin() + 16, machine.id_bytes.begin());
  machine.id = Hex(machine.id_bytes);
}

void Put(Buffer& out, const KeyPair& pair) {
  out.Byte(static_cast<uint8_t>(pair.algorithm));
  out.Field(pair.public_key);
  out.Field(pair.secret_key.Bytes());
}

KeyPair Get(Reader& in, Algorithm expected) {
  const auto algorithm = AlgorithmFrom(static_cast<uint8_t>(in.Number(1)));
  Require(algorithm == expected, "unexpected algorithm");
  const auto sizes = SizesOf(expected);
  const auto pub = in.Field(sizes.public_key);
  const auto secret = in.Field(sizes.secret_key);
  Require(pub.size() == sizes.public_key && secret.size() == sizes.secret_key, "key of the wrong size");
  return KeyPair{expected, Bytes(pub.begin(), pub.end()), Copy(secret)};
}

void Seal(Buffer& out) {
  const auto checksum = Sha512(out.bytes);
  out.Room(checksum.size());
  out.bytes.insert(out.bytes.end(), checksum.begin(), checksum.end());
}

// The body of a file, after its magic and before its checksum, once both are right.
View Unseal(View data, std::string_view magic) {
  Require(data.size() > magic.size() + 64, "file too short");
  Require(std::memcmp(data.data(), magic.data(), magic.size()) == 0, "not a key file of this version");
  const auto body = data.first(data.size() - 64);
  const auto checksum = Sha512(body);
  Require(std::memcmp(checksum.data(), data.data() + body.size(), 64) == 0, "checksum does not match");
  return body.subspan(magic.size());
}

void SyncFolder(const fs::path& folder) {
  const int fd = ::open(folder.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  Require(fd >= 0, "cannot open the store folder");
  const bool ok = ::fsync(fd) == 0;
  (void)::close(fd);
  Require(ok, "cannot flush the store folder");
}

// Written whole to a new name, flushed, then renamed: a power cut leaves the
// old file or the new one, never half of either.
void WriteFile(const fs::path& folder, std::string_view name, View data) {
  const auto target = folder / name;
  const auto staged = folder / (std::string(name) + ".new");
  (void)::unlink(staged.c_str());
  const int fd = ::open(staged.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  Require(fd >= 0, "cannot create a key file");
  size_t done = 0;
  bool ok = true;
  while (ok && done < data.size()) {
    const ssize_t n = ::write(fd, data.data() + done, data.size() - done);
    if (n < 0 && errno == EINTR) continue;
    ok = n > 0;
    if (ok) done += static_cast<size_t>(n);
  }
  ok = ok && ::fsync(fd) == 0;
  ok = ::close(fd) == 0 && ok;
  if (!ok || ::rename(staged.c_str(), target.c_str()) != 0) {
    (void)::unlink(staged.c_str());
    Fail("cannot write a key file");
  }
  SyncFolder(folder);
}

// The one file in the store others may read: replaced whole, mode 0644.
void WritePublic(const fs::path& folder, std::string_view name, View data) {
  WriteFile(folder, name, data);
  Require(::chmod((folder / name).c_str(), 0644) == 0, "cannot publish identity.public");
}

// A key file must be a regular file of this user, readable by nobody else.
// Returns empty when the file does not exist.
SecretBytes ReadFile(const fs::path& folder, std::string_view name) {
  const auto path = folder / name;
  const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0 && errno == ENOENT) return {};
  Require(fd >= 0, "cannot open a key file");
  struct stat st {};
  const bool safe = ::fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == ::geteuid() &&
                    (st.st_mode & 077) == 0 && st.st_nlink == 1 && st.st_size > 0 &&
                    static_cast<size_t>(st.st_size) <= kFileMax;
  if (!safe) {
    (void)::close(fd);
    Fail(std::string(name) + " is not a private file of this user");
  }
  SecretBytes out(static_cast<size_t>(st.st_size));
  size_t done = 0;
  while (done < out.size()) {
    const ssize_t n = ::read(fd, out.Bytes().data() + done, out.size() - done);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) break;
    done += static_cast<size_t>(n);
  }
  (void)::close(fd);
  Require(done == out.size(), "cannot read a key file");
  return out;
}

// One key service per store: a second one (a restart while the old one is
// still stopping) would write over the first one's files.
base::FileDescriptor LockFolder(const fs::path& folder) {
  base::FileDescriptor fd(::open(folder.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  Require(fd.get() >= 0, "cannot open the store folder");
  Require(::flock(fd.get(), LOCK_EX | LOCK_NB) == 0, "another key service is using this store");
  return fd;
}

void PrepareFolder(const fs::path& folder) {
  if (::mkdir(folder.c_str(), 0700) != 0 && errno != EEXIST) Fail("cannot create the store folder");
  struct stat st {};
  Require(::lstat(folder.c_str(), &st) == 0 && S_ISDIR(st.st_mode), "the store is not a folder");
  Require(st.st_uid == ::geteuid() && (st.st_mode & 077) == 0, "the store folder must be this user's, mode 0700");
}

Machine NewMachine() {
  Machine machine{Generate(Algorithm::MlDsa87), {}};
  SetId(machine);
  return machine;
}

void SaveMachine(const fs::path& folder, const Machine& machine) {
  Buffer out;
  out.Text(kMachineMagic);
  Put(out, machine.key);
  Seal(out);
  WriteFile(folder, kMachineFile, out.bytes);
}

Machine LoadMachine(const SecretBytes& file) {
  Reader in{Unseal(file.Bytes(), kMachineMagic)};
  Machine machine{Get(in, Algorithm::MlDsa87), {}};
  Require(in.at == in.data.size(), "trailing bytes in machine.key");
  SetId(machine);
  return machine;
}

void Finish(Identity& identity) {
  identity.manifest =
      Manifest(identity.account.public_key, identity.network_root.public_key, identity.update_root.public_key);
  identity.did = DidOf(identity.manifest);
}

Identity NewIdentity() {
  Identity identity;
  identity.master = SecretBytes(32);
  p::FillRandom(identity.master.Bytes());
  identity.update_root = DeriveUpdateRoot(identity.master.Bytes());
  identity.account = DeriveAccount(identity.master.Bytes());
  identity.network_root = Generate(Algorithm::SqiSignV);
  identity.runtime_mldsa = Generate(Algorithm::MlDsa87);
  identity.runtime_sqisign = Generate(Algorithm::SqiSignV);
  identity.runtime_issued =
      std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
  Finish(identity);
  return identity;
}

void SaveIdentity(const fs::path& folder, const Identity& identity) {
  Buffer out;
  out.Text(kIdentityMagic);
  out.Field(identity.master.Bytes());
  for (const auto* pair : {&identity.update_root, &identity.network_root, &identity.account, &identity.runtime_mldsa,
                           &identity.runtime_sqisign})
    Put(out, *pair);
  out.U64(static_cast<uint64_t>(identity.runtime_issued));
  Seal(out);
  WriteFile(folder, kIdentityFile, out.bytes);
}

Identity LoadIdentity(const SecretBytes& file) {
  Reader in{Unseal(file.Bytes(), kIdentityMagic)};
  Identity identity;
  const auto master = in.Field(32);
  Require(master.size() == 32, "master of the wrong size");
  identity.master = Copy(master);
  identity.update_root = Get(in, Algorithm::MlDsa87);
  identity.network_root = Get(in, Algorithm::SqiSignV);
  identity.account = Get(in, Algorithm::Secp256k1);
  identity.runtime_mldsa = Get(in, Algorithm::MlDsa87);
  identity.runtime_sqisign = Get(in, Algorithm::SqiSignV);
  identity.runtime_issued = static_cast<int64_t>(in.Number(8));
  Require(in.at == in.data.size(), "trailing bytes in identity.key");
  // The derived keys must be the ones the master derives.
  Require(DeriveUpdateRoot(identity.master.Bytes()).public_key == identity.update_root.public_key,
          "the ML-DSA-87 root is not the one the master derives");
  Require(DeriveAccount(identity.master.Bytes()).public_key == identity.account.public_key,
          "the account key is not the one the master derives");
  Finish(identity);
  return identity;
}

void CheckAll(const Identity& identity, const Machine& machine) {
  for (const auto* pair : {&identity.update_root, &identity.network_root, &identity.account, &identity.runtime_mldsa,
                           &identity.runtime_sqisign, &machine.key})
    Check(*pair);
}
}  // namespace

const KeyPair& Identity::ForNode(Algorithm algorithm) const noexcept {
  switch (algorithm) {
    case Algorithm::MlDsa87: return runtime_mldsa;
    case Algorithm::SqiSignV: return runtime_sqisign;
    case Algorithm::Secp256k1: return account;
  }
  return account;
}

void Derive(std::span<const uint8_t> master, std::string_view label, std::span<uint8_t, 32> out) {
  static constexpr std::string_view kSalt = "FORTIS-DID-EXPERIMENT-v1";
  const auto* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
  Require(md && mbedtls_hkdf(md, reinterpret_cast<const unsigned char*>(kSalt.data()), kSalt.size(), master.data(),
                             master.size(), reinterpret_cast<const unsigned char*>(label.data()), label.size(),
                             out.data(), out.size()) == 0,
          "HKDF failed");
}

// The pq2 genesis manifest (identity prototype, docs/THREE-ROLE-PQ2.md):
// "FDM2" then field(role) field(algorithm) field(public key) for each role, in this order.
Bytes Manifest(View account, View network_root, View update_root) {
  Buffer out;
  out.Text("FDM2");
  auto role = [&out](std::string_view name, std::string_view algorithm, View key) {
    out.Field(View(reinterpret_cast<const uint8_t*>(name.data()), name.size()));
    out.Field(View(reinterpret_cast<const uint8_t*>(algorithm.data()), algorithm.size()));
    out.Field(key);
  };
  role("evm-account", Name(Algorithm::Secp256k1), account);
  role("fortisnet-network", Name(Algorithm::SqiSignV), network_root);
  role("did-update", Name(Algorithm::MlDsa87), update_root);
  return out.bytes;
}

std::string Hex(View bytes) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (const auto b : bytes) {
    out.push_back(kDigits[b >> 4]);
    out.push_back(kDigits[b & 15]);
  }
  return out;
}

KeyStore KeyStore::Open(const fs::path& folder) {
  PrepareFolder(folder);
  KeyStore store;
  store.lock_ = LockFolder(folder);
  auto machine_file = ReadFile(folder, kMachineFile);
  auto identity_file = ReadFile(folder, kIdentityFile);
  // An identity is made only for a store that has never held anything. A
  // machine key without its identity means the identity was lost or the
  // wrong disk is mounted: making a new one would silently change the DID.
  if (machine_file.size() && !identity_file.size())
    Fail("identity.key is missing although machine.key exists; restore it, or remove machine.key to start anew");
  if (machine_file.size()) {
    store.machine_ = LoadMachine(machine_file);
  } else {
    // A new installation, or an identity copied into a fresh store.
    store.machine_ = NewMachine();
    Check(store.machine_.key);
    SaveMachine(folder, store.machine_);
    store.new_machine_ = true;
  }
  if (identity_file.size()) {
    store.identity_ = LoadIdentity(identity_file);
  } else {
    store.identity_ = NewIdentity();
    SaveIdentity(folder, store.identity_);
    store.created_ = true;
  }
  CheckAll(store.identity_, store.machine_);
  // The public part, for the orchestrator's pages: it reads this file, and
  // never the key files. Both values are public.
  const std::string published = "did=" + store.identity_.did + "\nmachine=" + store.machine_.id + "\n";
  WritePublic(folder, kPublicFile, View(reinterpret_cast<const uint8_t*>(published.data()), published.size()));
  return store;
}
}  // namespace fortis::keys
