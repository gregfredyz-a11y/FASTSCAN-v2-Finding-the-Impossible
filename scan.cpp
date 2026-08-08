// ==========================
// FASTSCAN v2 – BTC (1, 3, bc1) 
// 1(U) NIEZALEŻNY, 1(C)+bc1 POŁĄCZONE, 3 NIEZALEŻNY!
// Z 24-BITOWYM INDEKSEM (128 MB) - SZYBSZY!
// ==========================

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <iomanip>
#include <chrono>
#include <cstring>
#include <cerrno>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/bn.h>
#include <secp256k1.h>

// ===============================
// PARAMETRY
// ===============================
static const uint64_t BLOCK_SIZE = 1'579'000ULL;
static const int THREAD_COUNT = 30;

std::mutex log_mutex;

// ===============================
// MAPOWANIE PLIKÓW 20B
// ===============================
class MMapFile {
public:
    MMapFile(const char* path) {
        fd = ::open(path, O_RDONLY);
        if (fd < 0) throw std::runtime_error(std::string("open: ") + strerror(errno));

        struct stat st{};
        if (fstat(fd, &st) != 0)
            throw std::runtime_error(std::string("fstat: ") + strerror(errno));

        size = st.st_size;
        if (size == 0 || size % 20 != 0)
            throw std::runtime_error("invalid bin file");

        data = (const unsigned char*) mmap(nullptr, size, PROT_READ, MAP_SHARED, fd, 0);
        if (data == MAP_FAILED)
            throw std::runtime_error(std::string("mmap: ") + strerror(errno));
    }

    ~MMapFile() {
        if (data) munmap((void*)data, size);
        if (fd >= 0) close(fd);
    }

    const unsigned char* ptr() const { return data; }
    size_t length() const { return size; }

private:
    int fd;
    const unsigned char* data;
    size_t size;
};

// ===============================
// 24-BITOWY INDEKS PREFIKSOWY (128 MB)
// ===============================
class PrefixIndex24 {
private:
    const MMapFile& mm;
    std::vector<uint64_t> index;
    bool ready;

    static inline uint32_t get_prefix24(const unsigned char* p) {
        return (uint32_t(p[0]) << 16) | (uint32_t(p[1]) << 8) | uint32_t(p[2]);
    }

public:
    PrefixIndex24(const MMapFile& m) : mm(m), ready(false) {
        index.resize(16777217);
        build();
    }

    void build() {
        const unsigned char* base = mm.ptr();
        uint64_t count = mm.length() / 20;
        
        std::cout << "📦 Budowanie 24-bitowego indeksu dla " << count << " adresów...\n";
        std::cout << "📊 Rozmiar indeksu: ~" << (index.size() * sizeof(uint64_t)) / (1024*1024) << " MB\n";
        
        auto start_time = std::chrono::steady_clock::now();

        uint64_t pos = 0;
        uint64_t buckets_found = 0;

        while (pos < count) {
            const unsigned char* rec = base + pos * 20;
            uint32_t p = get_prefix24(rec);
            
            index[p] = pos;
            
            uint64_t lo = pos;
            uint64_t hi = count;
            
            while (lo + 1 < hi) {
                uint64_t mid = (lo + hi) / 2;
                const unsigned char* mid_rec = base + mid * 20;
                uint32_t mp = get_prefix24(mid_rec);
                
                if (mp <= p)
                    lo = mid;
                else
                    hi = mid;
            }
            
            index[p + 1] = lo + 1;
            
            pos = lo + 1;
            buckets_found++;
            
            if (buckets_found % 1000 == 0) {
                std::cout << "\r   Przetworzono: " << pos << "/" << count 
                          << " rekordów | Znaleziono: " << buckets_found 
                          << " prefiksów" << std::flush;
            }
        }
        
        uint64_t last_start = 0;
        uint64_t last_end = count;
        
        for (int i = 16777215; i >= 0; i--) {
            if (index[i] != 0 || i == 0) {
                last_start = index[i];
                last_end = index[i + 1];
            } else {
                index[i] = last_start;
                index[i + 1] = last_end;
            }
        }

        auto end_time = std::chrono::steady_clock::now();
        double seconds = std::chrono::duration<double>(end_time - start_time).count();
        
        std::cout << "\n✅ Indeks zbudowany: " << buckets_found << "/16777216 prefiksów używanych\n";
        std::cout << "⏱️  Czas budowy: " << std::fixed << std::setprecision(1) << seconds << " s\n";
        std::cout << "📊 Pamięć indeksu: ~" << (index.size() * sizeof(uint64_t)) / (1024*1024) << " MB\n";
        
        ready = true;
    }

    // ==========================================
    // contains() z 24-bitowym indeksem - SZYBSZY!
    // ==========================================
    bool contains(const unsigned char addr20[20]) const {
        uint32_t p = get_prefix24(addr20);
        
        uint64_t lo = index[p];
        uint64_t hi = index[p + 1];
        
        if (lo >= hi) {
            return false;
        }
        
        const unsigned char* base = mm.ptr();
        
        while (lo < hi) {
            uint64_t mid = (lo + hi) / 2;
            const unsigned char* midp = base + mid * 20;

            int cmp = memcmp(midp, addr20, 20);
            if (cmp == 0) return true;
            if (cmp < 0) lo = mid + 1;
            else hi = mid;
        }
        return false;
    }
};

// ===============================
// HASH TOOLS
// ===============================
inline void sha256_once(const unsigned char* d, size_t n, unsigned char out[32]) {
    SHA256_CTX c;
    SHA256_Init(&c);
    SHA256_Update(&c, d, n);
    SHA256_Final(out, &c);
}

inline void ripemd160_once(const unsigned char* d, size_t n, unsigned char out[20]) {
    RIPEMD160_CTX r;
    RIPEMD160_Init(&r);
    RIPEMD160_Update(&r, d, n);
    RIPEMD160_Final(out, &r);
}

inline void pubkey_hash160(const unsigned char* pub, size_t len, unsigned char out[20]) {
    unsigned char sh[32];
    sha256_once(pub, len, sh);
    ripemd160_once(sh, 32, out);
}

// ===============================
// FAST PUBKEY CONTEXT
// ===============================
struct FastPubCtx {
    secp256k1_context* ctx;
    secp256k1_pubkey pub;
    bool initialized = false;
};

inline void fast_priv_add_one(FastPubCtx& pc) {
    static const unsigned char ONE32[32] = {
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1
    };
    secp256k1_ec_pubkey_tweak_add(pc.ctx, &pc.pub, ONE32);
}

inline void fast_load_priv(FastPubCtx& pc, const unsigned char priv[32]) {
    secp256k1_ec_pubkey_create(pc.ctx, &pc.pub, priv);
    pc.initialized = true;
}

// ============================================================
// SZYBKIE HASHE - BTC + P2SH
// ============================================================
inline void fast_get_btc_hashes(const FastPubCtx& pc, 
                                 unsigned char hu[20],
                                 unsigned char hc[20],
                                 unsigned char p2sh_hash[20]) {
    unsigned char pub[65]; 
    size_t pub_len = 65;
    secp256k1_ec_pubkey_serialize(pc.ctx, pub, &pub_len, &pc.pub, 
                                  SECP256K1_EC_UNCOMPRESSED);
    
    // ==========================================
    // 1. BTC uncompressed (1...) - NIEZALEŻNY!
    // ==========================================
    pubkey_hash160(pub, 65, hu);
    
    // ==========================================
    // 2. BTC compressed (1...) + SegWit (bc1...)
    // ==========================================
    unsigned char compressed[33];
    compressed[0] = (pub[64] & 1) ? 0x03 : 0x02;
    memcpy(compressed + 1, pub + 1, 32);
    pubkey_hash160(compressed, 33, hc);
    
    // ==========================================
    // 3. BTC P2SH (3...) - NIEZALEŻNY!
    // ==========================================
    unsigned char redeem_script[22];
    redeem_script[0] = 0x00;
    redeem_script[1] = 0x14;
    memcpy(redeem_script + 2, hc, 20);
    pubkey_hash160(redeem_script, 22, p2sh_hash);
}

// ===============================
// BASE58
// ===============================
static const char* BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

std::string base58_encode(const std::vector<unsigned char>& in) {
    BIGNUM* bn = BN_new();
    BN_bin2bn(in.data(), in.size(), bn);

    BIGNUM *dv = BN_new(), *rem = BN_new(), *b58 = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    BN_set_word(b58, 58);

    std::string out;
    while (!BN_is_zero(bn)) {
        BN_div(dv, rem, bn, b58, ctx);
        out.insert(out.begin(), BASE58[BN_get_word(rem)]);
        BN_copy(bn, dv);
    }

    for (unsigned char c : in)
        if (c == 0x00) out.insert(out.begin(), '1');
        else break;

    BN_free(bn); BN_free(dv); BN_free(rem); BN_free(b58); BN_CTX_free(ctx);
    return out;
}

std::string addr_p2pkh(const unsigned char ripe[20]) {
    std::vector<unsigned char> ext;
    ext.push_back(0x00);
    ext.insert(ext.end(), ripe, ripe+20);

    unsigned char c1[32], c2[32];
    sha256_once(ext.data(), ext.size(), c1);
    sha256_once(c1, 32, c2);

    ext.insert(ext.end(), c2, c2+4);
    return base58_encode(ext);
}

std::string addr_p2sh(const unsigned char ripe[20]) {
    std::vector<unsigned char> ext;
    ext.push_back(0x05);
    ext.insert(ext.end(), ripe, ripe+20);

    unsigned char c1[32], c2[32];
    sha256_once(ext.data(), ext.size(), c1);
    sha256_once(c1, 32, c2);

    ext.insert(ext.end(), c2, c2+4);
    return base58_encode(ext);
}

// ===============================
// BECH32 - SEGWIT (bc1...)
// ===============================
std::string bech32_encode(const std::string& hrp, const std::vector<uint8_t>& data) {
    const std::string CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    
    auto polymod = [](const std::vector<uint8_t>& values) -> uint32_t {
        const uint32_t GEN[] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
        uint32_t chk = 1;
        for (uint8_t v : values) {
            uint32_t top = chk >> 25;
            chk = ((chk & 0x1ffffff) << 5) ^ v;
            for (size_t i = 0; i < 5; ++i) {
                if ((top >> i) & 1) chk ^= GEN[i];
            }
        }
        return chk;
    };
    
    auto hrp_expand = [](const std::string& h) -> std::vector<uint8_t> {
        std::vector<uint8_t> ret;
        for (char c : h) ret.push_back((uint8_t)(c >> 5));
        ret.push_back(0);
        for (char c : h) ret.push_back((uint8_t)(c & 0x1f));
        return ret;
    };
    
    std::string result = hrp + "1";
    for (uint8_t v : data) {
        if (v >= 32) return "";
        result += CHARSET[v];
    }
    
    std::vector<uint8_t> values = hrp_expand(hrp);
    values.insert(values.end(), data.begin(), data.end());
    values.insert(values.end(), {0,0,0,0,0,0});
    uint32_t mod = polymod(values) ^ 1;
    
    for (int i = 0; i < 6; ++i) {
        result += CHARSET[(mod >> (5 * (5 - i))) & 31];
    }
    
    return result;
}

std::string addr_segwit(const unsigned char h160[20]) {
    std::vector<uint8_t> data;
    data.push_back(0);
    
    uint64_t acc = 0;
    size_t bits = 0;
    std::vector<uint8_t> converted;
    for (size_t i = 0; i < 20; i++) {
        acc = (acc << 8) | h160[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            converted.push_back((acc >> bits) & 0x1F);
        }
    }
    if (bits > 0) {
        converted.push_back((acc << (5 - bits)) & 0x1F);
    }
    data.insert(data.end(), converted.begin(), converted.end());
    
    return bech32_encode("bc", data);
}

// ===============================
// SAVE FOUND
// ===============================
void save_found(const std::string& addr, const unsigned char priv[32], const std::string& type) {
    std::lock_guard<std::mutex> lk(log_mutex);

    std::ofstream f("found.txt", std::ios::app);
    f << type << ": " << addr << "\nPRIV: ";
    for (int i = 0; i < 32; i++)
        f << std::hex << std::setw(2) << std::setfill('0') << (int)priv[i];
    f << std::dec << "\n---\n";

    std::cout << "\n🎯 ZNALEZIONO " << type << ": " << addr << "\n";
}

// ===============================
// PROGRESS
// ===============================
void save_state(uint64_t r, uint64_t c) {
    std::ofstream f("progress.txt", std::ios::trunc);
    f << r << "\n" << c << "\n";
}

bool load_state(uint64_t& r, uint64_t& c) {
    std::ifstream f("progress.txt");
    if (!f.is_open()) return false;
    f >> r >> c;
    return true;
}

// ===============================
// SKANOWANIE - 1(U) NIEZALEŻNY, 1(C)+bc1 POŁĄCZONE, 3 NIEZALEŻNY!
// Z 24-BITOWYM INDEKSEM
// ===============================
inline void scan_key_fast(FastPubCtx& fctx, const unsigned char priv[32], const PrefixIndex24& idx) {
    // ==========================================
    // HASHE - wszystkie 3 typy
    // ==========================================
    unsigned char hU[20], hC[20], p2sh_h[20];
    fast_get_btc_hashes(fctx, hU, hC, p2sh_h);
    
    // ==========================================
    // 1. BTC P2PKH (U) - NIEZALEŻNY!
    // ==========================================
    if (idx.contains(hU)) {
        std::string addr = addr_p2pkh(hU);
        save_found(addr, priv, "BTC P2PKH (U)");
    }
    
    // ==========================================
    // 2. BTC P2PKH (C) + SegWit (bc1...) - POŁĄCZONE!
    // ==========================================
    if (idx.contains(hC)) {
        std::string addr = addr_p2pkh(hC);
        save_found(addr, priv, "BTC P2PKH (C)");
        
        std::string segwit = addr_segwit(hC);
        if (!segwit.empty()) {
            save_found(segwit, priv, "BTC SegWit");
        }
    }
    
    // ==========================================
    // 3. BTC P2SH (3...) - NIEZALEŻNY!
    // ==========================================
    if (idx.contains(p2sh_h)) {
        std::string addr = addr_p2sh(p2sh_h);
        save_found(addr, priv, "BTC P2SH");
    }
}

// ===============================
// MAIN
// ===============================
int main(int argc, char* argv[]) {

    if (argc < 4) {
        std::cout << "Użycie: ./scan adresy.bin start_bit end_bit [--resume]\n";
        return 1;
    }

    std::cout << "📂 Ładowanie pliku: " << argv[1] << "\n";
    MMapFile mm(argv[1]);
    
    int start_bit = std::stoi(argv[2]);
    int end_bit   = std::stoi(argv[3]);
    bool resume = (argc >= 5 && std::string(argv[4]) == "--resume");

    uint64_t total_bytes = mm.length();
    uint64_t total_mb = total_bytes / (1024*1024);
    uint64_t total_gb = total_bytes / (1024*1024*1024);
    uint64_t addr_count = total_bytes / 20;
    
    std::cout << "📏 Rozmiar: " << total_gb << " GB (" << total_mb << " MB)\n";
    std::cout << "🔢 Adresów: " << addr_count << "\n";
    std::cout << "🔥 Skanuję: 1(U) NIEZALEŻNY, 1(C)+bc1 POŁĄCZONE, 3 NIEZALEŻNY!\n";
    std::cout << "⚡ Używam 24-bitowego indeksu (128 MB) - SZYBSZY!\n";

    // ==========================================
    // 24-BITOWY INDEKS (128 MB)
    // ==========================================
    PrefixIndex24 prefix_idx(mm);

    secp256k1_context* ctx_master =
        secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    BN_CTX* bnctx = BN_CTX_new();
    BIGNUM *R0 = BN_new(), *R1 = BN_new(), *two = BN_new();
    BN_set_word(two, 2);

    BIGNUM *bs = BN_new(), *be = BN_new();
    BN_set_word(bs, start_bit);
    BN_set_word(be, end_bit);

    BN_exp(R0, two, bs, bnctx);
    BN_exp(R1, two, be, bnctx);

    BIGNUM* RLEN = BN_new();
    BN_sub(RLEN, R1, R0);

    uint64_t round_idx = 1;
    uint64_t chunk_idx = 0;

    if (resume) load_state(round_idx, chunk_idx);

    while (true) {

        uint64_t CHUNKS = round_idx * 34563ULL;
        if (CHUNKS > 100000) CHUNKS = 100000;

        std::cout << "\n🔁 Runda " << round_idx
                  << " | chunks=" << CHUNKS
                  << " | BLOCK=" << BLOCK_SIZE << "\n";

        BIGNUM* bn_chunks = BN_new();
        BN_set_word(bn_chunks, CHUNKS);

        BIGNUM* stride = BN_new();
        BN_div(stride, nullptr, RLEN, bn_chunks, bnctx);
        
        if (BN_is_zero(stride)) {
            while (BN_is_zero(stride) && CHUNKS > 1) {
                BN_free(bn_chunks);
                BN_free(stride);
                CHUNKS = CHUNKS / 2;
                if (CHUNKS < 1) CHUNKS = 1;
                bn_chunks = BN_new();
                BN_set_word(bn_chunks, CHUNKS);
                stride = BN_new();
                BN_div(stride, nullptr, RLEN, bn_chunks, bnctx);
            }
        }

        std::atomic<uint64_t> next(chunk_idx);
        std::atomic<uint64_t> keys_done(0), chunks_done(0);
        std::atomic<bool> stop(false);

        // Speed monitor
        std::thread monitor([&]() {
            uint64_t last = 0;
            while (!stop.load()) {
                std::this_thread::sleep_for(std::chrono::seconds(2));
                uint64_t now = keys_done.load();
                double m = (now - last) / 2'000'000.0;
                last = now;

                std::cout << "\r⚙️ "
                          << std::fixed << std::setprecision(2)
                          << m << " Mkeys/s"
                          << " | chunk " << chunks_done
                          << "/" << CHUNKS
                          << std::flush;
            }
        });

        std::vector<std::thread> pool;

        for (int t = 0; t < THREAD_COUNT; t++) {
            pool.emplace_back([&, t]() {

                BN_CTX* lc = BN_CTX_new();
                BIGNUM *bn_i = BN_new(), *bn_off = BN_new(), *privBN = BN_new();

                FastPubCtx fctx;
                fctx.ctx = secp256k1_context_clone(ctx_master);

                while (true) {

                    uint64_t i = next.fetch_add(1);
                    if (i >= CHUNKS) break;

                    BN_set_word(bn_i, i);
                    BN_mul(bn_off, bn_i, stride, lc);
                    BN_add(privBN, R0, bn_off);

                    unsigned char priv[32];

                    fctx.initialized = false;

                    for (uint64_t k = 0; k < BLOCK_SIZE; k++) {

                        BN_bn2binpad(privBN, priv, 32);

                        if (!fctx.initialized) fast_load_priv(fctx, priv);
                        else fast_priv_add_one(fctx);

                        scan_key_fast(fctx, priv, prefix_idx);

                        BN_add_word(privBN, 1);
                        keys_done++;
                    }

                    save_state(round_idx, i);
                    chunks_done++;
                }

                BN_free(bn_i);
                BN_free(bn_off);
                BN_free(privBN);
                BN_CTX_free(lc);
                secp256k1_context_destroy(fctx.ctx);
            });
        }

        for (auto& th : pool) th.join();
        stop = true;
        monitor.join();

        std::cout << "\n➡️ Runda " << round_idx << " zakończona.\n";

        round_idx++;
        chunk_idx = 0;

        BN_free(bn_chunks);
        BN_free(stride);
    }

    return 0;
}
