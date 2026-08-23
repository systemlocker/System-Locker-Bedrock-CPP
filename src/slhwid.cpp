// Pure cryptographic core of the secret-sharing HWID module plus the
// prepare/commit lifecycle: GF(2^61-1) arithmetic on uint64 (portable
// split-limb multiplication, no __int128), four-limb secret sharing,
// x-derivation, helper-blob serialization, recovery and refresh.

#include "slhwid_internal.hpp"

#include "crypto.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <stdexcept>

namespace syslocker::bedrock::slhwid::detail
{
    namespace
    {
        std::vector<unsigned char> sha256(const unsigned char *data, std::size_t length)
        {
            std::vector<unsigned char> digest(32);
            unsigned int outLength = 0;
            if (EVP_Digest(data, length, digest.data(), &outLength, EVP_sha256(), nullptr) != 1 || outLength != 32)
                throw std::runtime_error("slhwid: SHA-256 failed");
            return digest;
        }

        std::vector<unsigned char> sha256Parts(std::initializer_list<std::pair<const unsigned char *, std::size_t>> parts)
        {
            std::vector<unsigned char> input;
            for (const auto &part : parts)
                input.insert(input.end(), part.first, part.first + part.second);
            return sha256(input.data(), input.size());
        }

        std::uint64_t readLE64(const unsigned char *bytes)
        {
            std::uint64_t value = 0;
            for (int i = 7; i >= 0; --i)
                value = (value << 8) | bytes[i];
            return value;
        }

        void writeLE64(unsigned char *bytes, std::uint64_t value)
        {
            for (int i = 0; i < 8; ++i)
                bytes[i] = static_cast<unsigned char>((value >> (8 * i)) & 0xFF);
        }

        std::vector<unsigned char> domainInput(std::uint8_t prefix, const char *label, const Key &k)
        {
            std::vector<unsigned char> input;
            input.push_back(prefix);
            const std::size_t labelLength = std::strlen(label);
            input.reserve(1 + labelLength + 32);
            input.insert(input.end(), label, label + labelLength);
            const auto kb = keyBytes(k);
            input.insert(input.end(), kb.begin(), kb.end());
            return input;
        }

        const char *const kCorruptPrefix = "slhwid: stored helper data is corrupt";

        class ScopedUnlock
        {
        public:
            explicit ScopedUnlock(std::function<void()> release) : release_(std::move(release)) {}
            ~ScopedUnlock()
            {
                if (release_)
                    release_();
            }

        private:
            std::function<void()> release_;
        };
    } // namespace

    void secureWipe(void *data, std::size_t length)
    {
        volatile unsigned char *bytes = static_cast<volatile unsigned char *>(data);
        while (length-- > 0)
            *bytes++ = 0;
    }

    std::string toLowerHex(const std::vector<unsigned char> &data)
    {
        static const char *digits = "0123456789abcdef";
        std::string out;
        out.reserve(data.size() * 2);
        for (const unsigned char byte : data)
        {
            out.push_back(digits[byte >> 4]);
            out.push_back(digits[byte & 0x0F]);
        }
        return out;
    }

    // ── field arithmetic ───────────────────────────────────────────────

    std::uint64_t addmod(std::uint64_t a, std::uint64_t b)
    {
        const std::uint64_t s = a + b; // a, b < p < 2^61 → s < 2^62, no overflow
        return s >= kPrime ? s - kPrime : s;
    }

    std::uint64_t submod(std::uint64_t a, std::uint64_t b)
    {
        return a >= b ? a - b : a + kPrime - b;
    }

    namespace
    {
        // Reduces any x < 2^64 into [0, p): 2^61 ≡ 1 (mod p).
        std::uint64_t red64(std::uint64_t x)
        {
            std::uint64_t r = (x & kPrime) + (x >> 61); // < 2^61 + 8
            return r >= kPrime ? r - kPrime : r;
        }
    }

    std::uint64_t mulmod(std::uint64_t a, std::uint64_t b)
    {
        constexpr std::uint64_t lo31 = 0x7FFFFFFFULL;
        const std::uint64_t alo = a & lo31;
        const std::uint64_t ahi = a >> 31; // alo < 2^31, ahi < 2^30
        const std::uint64_t blo = b & lo31;
        const std::uint64_t bhi = b >> 31;
        const std::uint64_t ll = alo * blo;            // < 2^62
        const std::uint64_t t = alo * bhi + ahi * blo; // < 2^62
        const std::uint64_t hh = ahi * bhi;            // < 2^60
        // full product = ll + t·2^31 + hh·2^62, and 2^62 ≡ 2 (mod p)
        const std::uint64_t th = t >> 31;
        const std::uint64_t tl = t & lo31;
        std::uint64_t r = red64(ll);
        r = addmod(r, red64(tl << 31));
        r = addmod(r, red64(th << 1));
        r = addmod(r, red64(hh << 1));
        return r;
    }

    std::uint64_t invmod(std::uint64_t a)
    {
        std::int64_t lm = 1;
        std::int64_t hm = 0;
        std::int64_t low = static_cast<std::int64_t>(a);
        std::int64_t high = static_cast<std::int64_t>(kPrime);
        while (low > 1)
        {
            const std::int64_t r = high / low;
            const std::int64_t newLm = hm - lm * r;
            const std::int64_t newLow = high - low * r;
            hm = lm;
            lm = newLm;
            high = low;
            low = newLow;
        }
        if (lm < 0)
            lm += static_cast<std::int64_t>(kPrime);
        return static_cast<std::uint64_t>(lm);
    }

    // ── derivation ─────────────────────────────────────────────────────

    std::uint64_t deriveX(const std::string &slot, const std::string &value, std::uint8_t salt)
    {
        std::vector<unsigned char> input;
        input.reserve(12 + slot.size() + value.size());
        const char label[] = "SL-SS-X1";
        input.insert(input.end(), label, label + sizeof(label) - 1);
        input.push_back(0);
        input.push_back(salt);
        input.push_back(0);
        input.insert(input.end(), slot.begin(), slot.end());
        input.push_back(0);
        input.insert(input.end(), value.begin(), value.end());
        const auto digest = sha256(input.data(), input.size());
        const std::uint64_t v = readLE64(digest.data()) & kPrime;
        return 1 + v % (kPrime - 1);
    }

    std::vector<unsigned char> keyBytes(const Key &k)
    {
        std::vector<unsigned char> out(32);
        for (int i = 0; i < 4; ++i)
            writeLE64(out.data() + i * 8, k[i]);
        return out;
    }

    std::vector<unsigned char> checkWord(const Key &k)
    {
        const auto input = domainInput(0x01, "SL-SS-CW1", k);
        return sha256(input.data(), input.size());
    }

    std::string hwidOf(const Key &k)
    {
        const auto input = domainInput(0x02, "SL-SS-ID1", k);
        const auto digest = sha256(input.data(), input.size());
        return bedrock::detail::base64UrlEncode(digest.data(), digest.size());
    }

    bool ctEqual(const std::vector<unsigned char> &a, const std::vector<unsigned char> &b)
    {
        if (a.size() != b.size())
            return false;
        volatile unsigned char diff = 0;
        for (std::size_t i = 0; i < a.size(); ++i)
            diff |= static_cast<unsigned char>(a[i] ^ b[i]);
        return diff == 0;
    }

    // ── threshold ──────────────────────────────────────────────────────

    int threshold(int n, int m)
    {
        if (n < 5 || m >= n)
            return 0;
        const int num = n > 10 ? 4 : 7; // 80% above ten factors, else 70%
        const int den = n > 10 ? 5 : 10;
        int t = (num * n + den - 1) / den;
        if (t < m + 1)
            t = m + 1;
        if (t > n)
            t = n;
        return t;
    }

    // ── normalization ──────────────────────────────────────────────────

    namespace
    {
        std::string trimNulAndSpace(const std::string &raw)
        {
            std::size_t begin = 0;
            std::size_t end = raw.size();
            const auto blank = [](unsigned char c)
            { return c == 0 || std::isspace(c) != 0; };
            while (begin < end && blank(static_cast<unsigned char>(raw[begin])))
                ++begin;
            while (end > begin && blank(static_cast<unsigned char>(raw[end - 1])))
                --end;
            return raw.substr(begin, end - begin);
        }

        const std::set<std::string> &placeholders()
        {
            static const std::set<std::string> values = {
                "", "none", "unknown", "default string",
                "to be filled by o.e.m.", "not specified", "system serial number"};
            return values;
        }
    }

    std::string normalize(const std::string &name, const std::string &raw)
    {
        std::string value = trimNulAndSpace(raw);
        std::transform(value.begin(), value.end(), value.begin(),
                       [](unsigned char c)
                       { return static_cast<char>(std::tolower(c)); });
        if (name == "mac")
            value.erase(std::remove_if(value.begin(), value.end(),
                                       [](char c)
                                       { return c == ':' || c == '-'; }),
                        value.end());
        return value;
    }

    bool isMissing(const std::string &value)
    {
        return placeholders().count(trimNulAndSpace(value)) > 0;
    }

    std::map<std::string, std::string> normalizeFactors(const std::map<std::string, std::string> &raw)
    {
        std::map<std::string, std::string> out;
        for (const auto &[name, value] : raw)
        {
            const std::string normalized = normalize(name, value);
            if (!normalized.empty() && !isMissing(normalized))
                out[name] = normalized;
        }
        return out;
    }

    std::vector<SlotData> slotList(const std::map<std::string, std::string> &factors, const std::set<std::string> &mandatory)
    {
        std::vector<SlotData> slots;
        slots.reserve(factors.size());
        for (const auto &[name, value] : factors)
            slots.push_back({name, value, mandatory.count(name) > 0});
        return slots; // std::map iterates in sorted order
    }

    // ── randomness ─────────────────────────────────────────────────────

    std::uint64_t Draw::elem()
    {
        unsigned char chunk[8];
        if (!source_ || !source_(chunk, sizeof(chunk)))
            throw std::runtime_error("slhwid: randomness exhausted");
        return readLE64(chunk) % kPrime;
    }

    // ── sharing ────────────────────────────────────────────────────────

    ShareResult buildShares(const Key &k, const std::vector<SlotData> &slots, int t, Draw &draw)
    {
        std::uint8_t salt = 0;
        std::vector<std::uint64_t> xs(slots.size());
        while (true)
        {
            for (std::size_t i = 0; i < slots.size(); ++i)
                xs[i] = deriveX(slots[i].name, slots[i].value, salt);
            bool collision = false;
            for (std::size_t i = 0; i < xs.size() && !collision; ++i)
                for (std::size_t j = 0; j < i; ++j)
                    if (xs[i] == xs[j])
                    {
                        collision = true;
                        break;
                    }
            if (!collision)
                break;
            if (++salt == 255)
                throw std::runtime_error("slhwid: x-coordinate collision loop");
        }
        std::vector<std::vector<std::uint64_t>> coeffs(4, std::vector<std::uint64_t>(t, 0));
        for (int limb = 0; limb < 4; ++limb)
            for (int j = 1; j < t; ++j)
                coeffs[limb][j] = draw.elem();
        ShareResult result;
        for (std::size_t i = 0; i < slots.size(); ++i)
        {
            Share share{};
            for (int limb = 0; limb < 4; ++limb)
            {
                std::uint64_t acc = 0;
                for (int j = t - 1; j >= 1; --j) // Horner
                    acc = addmod(mulmod(acc, xs[i]), coeffs[limb][j]);
                share[limb] = addmod(mulmod(acc, xs[i]), k[limb]);
            }
            result.shares[slots[i].name] = share;
        }
        for (auto &row : coeffs)
            secureWipe(row.data(), row.size() * sizeof(std::uint64_t));
        result.salt = salt;
        return result;
    }

    // ── helper blob ────────────────────────────────────────────────────

    std::vector<unsigned char> serializeHelper(const std::map<std::string, Share> &shares,
                                               const std::set<std::string> &mandatory,
                                               int t, std::uint8_t salt,
                                               const std::vector<unsigned char> &cw)
    {
        std::vector<unsigned char> payload;
        payload.push_back(1); // version
        payload.push_back(1); // norm_version
        payload.push_back(salt);
        payload.push_back(static_cast<unsigned char>(shares.size()));
        int m = 0;
        for (const auto &[name, share] : shares)
            if (mandatory.count(name) > 0)
                ++m;
        payload.push_back(static_cast<unsigned char>(m));
        payload.push_back(static_cast<unsigned char>(t));
        payload.push_back(0); // reserved
        payload.push_back(0);
        for (const auto &[name, share] : shares) // std::map iterates sorted
        {
            payload.push_back(static_cast<unsigned char>(name.size()));
            payload.insert(payload.end(), name.begin(), name.end());
            payload.push_back(mandatory.count(name) > 0 ? 1 : 0);
            unsigned char limb[8];
            for (const std::uint64_t value : share)
            {
                writeLE64(limb, value);
                payload.insert(payload.end(), limb, limb + 8);
            }
        }

        std::vector<unsigned char> out;
        const char magic[] = "SLSSHWID";
        out.insert(out.end(), magic, magic + 8);
        unsigned char length[4];
        for (int i = 0; i < 4; ++i)
            length[i] = static_cast<unsigned char>((payload.size() >> (8 * i)) & 0xFF);
        out.insert(out.end(), length, length + 4);
        out.insert(out.end(), payload.begin(), payload.end());
        out.insert(out.end(), cw.begin(), cw.end());
        const auto integrity = sha256(out.data(), out.size());
        out.insert(out.end(), integrity.begin(), integrity.end());
        return out;
    }

    namespace
    {
        [[noreturn]] void corrupt(const std::string &why)
        {
            throw std::runtime_error(std::string(kCorruptPrefix) + ": " + why);
        }
    }

    bool isCorruptError(const std::exception &error)
    {
        return std::strncmp(error.what(), kCorruptPrefix, std::strlen(kCorruptPrefix)) == 0;
    }

    Helper parseHelper(const std::vector<unsigned char> &blob)
    {
        if (blob.size() < 8 + 4 + 8 + 32 + 32)
            corrupt("truncated");
        if (std::memcmp(blob.data(), "SLSSHWID", 8) != 0)
            corrupt("magic mismatch");
        const auto integrity = sha256(blob.data(), blob.size() - 32);
        if (!ctEqual(integrity, std::vector<unsigned char>(blob.end() - 32, blob.end())))
            corrupt("integrity mismatch");
        const std::uint32_t payloadLen = readLE64(blob.data() + 8) & 0xFFFFFFFFULL;
        if (static_cast<std::size_t>(12) + payloadLen + 64 != blob.size())
            corrupt("length mismatch");
        const unsigned char *body = blob.data() + 12;
        const int n = body[3];
        Helper helper;
        helper.salt = body[2];
        helper.threshold = body[5];
        helper.checkWord.assign(blob.data() + 12 + payloadLen, blob.data() + 12 + payloadLen + 32);
        if (body[0] != 1)
            corrupt("unsupported version");
        std::size_t offset = 8;
        std::set<std::string> seen;
        for (int i = 0; i < n; ++i)
        {
            if (offset + 1 > payloadLen)
                corrupt("slot truncated");
            const std::size_t nameLen = body[offset];
            if (nameLen == 0 || offset + 1 + nameLen + 1 + 32 > payloadLen)
                corrupt("slot truncated");
            HelperSlot slot;
            slot.name.assign(reinterpret_cast<const char *>(body + offset + 1), nameLen);
            if (!seen.insert(slot.name).second)
                corrupt("duplicate slot");
            slot.mandatory = (body[offset + 1 + nameLen] & 1) == 1;
            for (int limb = 0; limb < 4; ++limb)
            {
                slot.share[limb] = readLE64(body + offset + 2 + nameLen + limb * 8);
                if (slot.share[limb] >= kPrime)
                    corrupt("share limb out of range");
            }
            helper.slots.push_back(std::move(slot));
            offset += 2 + nameLen + 32;
        }
        if (offset != payloadLen)
            corrupt("trailing bytes");
        return helper;
    }

    // ── recovery ───────────────────────────────────────────────────────

    namespace
    {
        struct Point
        {
            std::string name;
            std::uint64_t x = 0;
            const Share *share = nullptr;
        };

        std::uint64_t lagrangeAtZero(const std::vector<Point> &points, int limb)
        {
            std::uint64_t total = 0;
            for (std::size_t j = 0; j < points.size(); ++j)
            {
                std::uint64_t num = 1;
                std::uint64_t den = 1;
                for (std::size_t k = 0; k < points.size(); ++k)
                {
                    if (k == j)
                        continue;
                    num = mulmod(num, points[k].x);
                    den = mulmod(den, submod(points[k].x, points[j].x));
                }
                total = addmod(total, mulmod((*points[j].share)[limb], mulmod(num, invmod(den))));
            }
            return total;
        }

        std::uint64_t evaluateAt(const std::vector<Point> &points, int limb, std::uint64_t xq)
        {
            std::uint64_t total = 0;
            for (std::size_t j = 0; j < points.size(); ++j)
            {
                std::uint64_t num = 1;
                std::uint64_t den = 1;
                for (std::size_t k = 0; k < points.size(); ++k)
                {
                    if (k == j)
                        continue;
                    num = mulmod(num, submod(xq, points[k].x));
                    den = mulmod(den, submod(points[j].x, points[k].x));
                }
                total = addmod(total, mulmod((*points[j].share)[limb], mulmod(num, invmod(den))));
            }
            return total;
        }

        Key keyFromPoints(const std::vector<Point> &points)
        {
            Key k{};
            for (int limb = 0; limb < 4; ++limb)
                k[limb] = lagrangeAtZero(points, limb);
            return k;
        }

        // Searches size-t subsets containing every mandatory candidate, in
        // lexicographic order; mandatory slots are in every subset: a wrong
        // mandatory factor cannot be routed around (hard lock). The sweep is
        // exhaustive: neither intermediate failures nor a match truncate it,
        // so the amount of work done does not signal which factors survived
        // (side-channel resistance).
        bool findRecoveringSubset(const std::vector<Point> &mandatory,
                                  const std::vector<Point> &optional,
                                  int t,
                                  const std::vector<unsigned char> &cw,
                                  std::vector<Point> &found)
        {
            const int need = std::max(0, t - static_cast<int>(mandatory.size()));
            if (need > static_cast<int>(optional.size()))
                return false;
            std::vector<Point> points = mandatory;
            points.resize(mandatory.size() + need);
            std::function<void(int, int)> search = [&](int start, int depth)
            {
                if (depth == need)
                {
                    if (found.empty())
                    {
                        const Key k = keyFromPoints(points);
                        if (ctEqual(checkWord(k), cw))
                            found = points;
                    }
                    return;
                }
                for (int i = start; i <= static_cast<int>(optional.size()) - (need - depth); ++i)
                {
                    points[mandatory.size() + depth] = optional[i];
                    search(i + 1, depth + 1);
                }
            };
            search(0, 0);
            return !found.empty();
        }

        bool isMandatorySlot(const Helper &helper, const std::string &name)
        {
            for (const auto &slot : helper.slots)
                if (slot.name == name)
                    return slot.mandatory;
            return false;
        }
    }

    RecoverResult recoverCore(const std::vector<unsigned char> &blob, const std::map<std::string, std::string> &factors)
    {
        RecoverResult result;
        Helper helper;
        try
        {
            helper = parseHelper(blob);
        }
        catch (const std::exception &error)
        {
            if (isCorruptError(error))
            {
                result.reason = "corrupt";
                return result;
            }
            throw;
        }
        const int t = helper.threshold;

        std::vector<Point> mandatory;
        std::vector<Point> optional;
        int present = 0;
        for (const auto &slot : helper.slots) // slots are stored sorted by name
        {
            const auto it = factors.find(slot.name);
            if (it == factors.end() || it->second.empty())
            {
                if (slot.mandatory)
                    result.missing.push_back(slot.name);
                continue;
            }
            ++present;
            Point point{slot.name, deriveX(slot.name, it->second, helper.salt), &slot.share};
            if (slot.mandatory)
                mandatory.push_back(point);
            else
                optional.push_back(point);
        }
        // The sweep runs to completion regardless of absences or failures
        // (constant-work shape); the hard-locked mandatory verdict is applied
        // afterwards and any accidental match is discarded.
        std::vector<Point> found;
        const bool swept = findRecoveringSubset(mandatory, optional, t, helper.checkWord, found);
        if (!result.missing.empty())
        {
            result.reason = "mandatory";
            result.present = present;
            result.needed = t;
            return result;
        }
        if (!swept)
        {
            // Diagnostic: if dropping one mandatory slot lets the rest of
            // the machine recover, that mandatory factor was changed
            // (intentional tampering) rather than the machine having drifted.
            std::string culprit;
            for (const auto &ms : helper.slots)
            {
                if (!ms.mandatory)
                    continue;
                std::vector<Point> merged = mandatory;
                merged.insert(merged.end(), optional.begin(), optional.end());
                std::vector<Point> mand2;
                std::vector<Point> opt2;
                for (const auto &point : merged)
                {
                    if (point.name == ms.name)
                        continue;
                    (isMandatorySlot(helper, point.name) ? mand2 : opt2).push_back(point);
                }
                std::vector<Point> ignored;
                if (culprit.empty() && findRecoveringSubset(mand2, opt2, t, helper.checkWord, ignored))
                    culprit = ms.name;
            }
            if (!culprit.empty())
            {
                result.reason = "mandatory";
                result.present = present;
                result.needed = t;
                result.missing = {culprit};
                return result;
            }
            result.reason = "drift";
            result.present = present;
            result.needed = t;
            return result;
        }

        result.key = keyFromPoints(found);
        result.hwid = hwidOf(result.key);
        std::set<std::string> inSubset;
        for (const auto &point : found)
            inSubset.insert(point.name);
        for (const auto &slot : helper.slots)
        {
            if (inSubset.count(slot.name) > 0)
            {
                result.live.push_back(slot.name);
                continue;
            }
            const auto it = factors.find(slot.name);
            if (it == factors.end() || it->second.empty())
            {
                result.dead.push_back(slot.name);
                continue;
            }
            const std::uint64_t xq = deriveX(slot.name, it->second, helper.salt);
            bool onCurve = true;
            for (int limb = 0; limb < 4 && onCurve; ++limb)
                onCurve = evaluateAt(found, limb, xq) == slot.share[limb];
            (onCurve ? result.live : result.dead).push_back(slot.name);
        }
        std::sort(result.live.begin(), result.live.end());
        std::sort(result.dead.begin(), result.dead.end());
        result.ok = true;
        result.pending = !result.dead.empty();
        return result;
    }

    RefreshResult refreshCore(const Key &k,
                              const std::map<std::string, std::string> &factors,
                              const std::set<std::string> &mandatory,
                              Draw &draw)
    {
        RefreshResult result;
        const auto slots = slotList(factors, mandatory);
        int m = 0;
        for (const auto &slot : slots)
            if (slot.mandatory)
                ++m;
        const int t = threshold(static_cast<int>(slots.size()), m);
        if (t == 0)
            return result;
        const auto shared = buildShares(k, slots, t, draw);
        result.blob = serializeHelper(shared.shares, mandatory, t, shared.salt, checkWord(k));
        result.written = true;
        return result;
    }

    // ── lifecycle ──────────────────────────────────────────────────────

    namespace
    {
        bool randomSource(unsigned char *out, std::size_t n)
        {
            return RAND_bytes(out, static_cast<int>(n)) == 1;
        }

        std::string driftMessage(const RecoverResult &result)
        {
            if (result.reason == "mandatory")
            {
                std::string joined;
                for (const auto &name : result.missing)
                {
                    if (!joined.empty())
                        joined += ", ";
                    joined += name;
                }
                return "slhwid: mandatory factor(s) " + joined + " changed or absent; re-activation required";
            }
            return "slhwid: hardware drifted past the recovery threshold (" +
                   std::to_string(result.present) + " factors present, " +
                   std::to_string(result.needed) + " needed); re-activation required";
        }

        constexpr std::size_t kSlstorePrefixLength = 7; // "SLSTOR1"

        std::optional<std::vector<unsigned char>> unwrapSlstore(const std::vector<unsigned char> &data)
        {
            if (data.size() != kSlstorePrefixLength + 32)
                throw std::runtime_error(std::string(kCorruptPrefix) + ": store secret has the wrong size");
            static const unsigned char prefix[kSlstorePrefixLength] = {'S', 'L', 'S', 'T', 'O', 'R', '1'};
            if (std::memcmp(data.data(), prefix, kSlstorePrefixLength) != 0)
                throw std::runtime_error(std::string(kCorruptPrefix) + ": store secret prefix mismatch");
            return std::vector<unsigned char>(data.begin() + kSlstorePrefixLength, data.end());
        }
    }

    using RandomSource = bool (*)(unsigned char *, std::size_t);

    RandomSource randomSourceAlias();

    Result<Session> prepareWith(const Options &options,
                                const std::function<std::map<std::string, std::string>()> &collect,
                                const Source &source,
                                const std::shared_ptr<Store> &store)
    {
        std::set<std::string> mandatory{"slstore"};
        for (const auto &name : options.extraMandatory)
        {
            bool valid = name.size() >= 1 && name.size() <= 32 &&
                         (std::isalpha(static_cast<unsigned char>(name[0])) != 0) &&
                         std::all_of(name.begin(), name.end(), [](unsigned char c)
                                     { return std::isalnum(c) != 0 || c == '_'; });
            if (!valid)
                return Result<Session>::fail(ErrorKind::LocalFailure,
                                              "slhwid: invalid extra mandatory slot name '" + name + "'");
            mandatory.insert(name);
        }

        std::map<std::string, std::string> factors;
        try
        {
            factors = normalizeFactors(collect());
        }
        catch (const std::exception &error)
        {
            return Result<Session>::fail(ErrorKind::LocalFailure,
                                         std::string("slhwid: factor collection failed: ") + error.what());
        }

        std::shared_ptr<Store> theStore = store;
        if (!theStore)
        {
            std::string storeError;
            theStore = defaultStore(options.storePath, storeError);
            if (!theStore)
                return Result<Session>::fail(ErrorKind::LocalFailure, storeError);
        }
        std::function<void()> release;
        std::string lockError;
        if (!acquireStorageLock(theStore->lockDirectory(), release, lockError))
            return Result<Session>::fail(ErrorKind::LocalFailure, lockError);
        ScopedUnlock storageLock(std::move(release));
        const auto existing = theStore->read("HWID-device");
        if (!existing.error.empty())
            return Result<Session>::fail(ErrorKind::LocalFailure,
                                         "slhwid: helper storage read failed: " + existing.error);

        // The slstore factor is ours, not collectable hardware: recovery
        // injects the persisted value (read-only). An absent value with an
        // existing helper is intentional tampering and recoverCore reports
        // it as a hard-locked mandatory failure below.
        if (existing.data && !options.forceReenroll && factors.find("slstore") == factors.end())
        {
            const auto stored = theStore->read("slstore");
            if (!stored.error.empty())
                return Result<Session>::fail(ErrorKind::LocalFailure,
                                             "slhwid: store secret read failed: " + stored.error);
            if (stored.data)
            {
                auto value = unwrapSlstore(*stored.data);
                factors["slstore"] = toLowerHex(*value);
            }
        }

        auto state = std::make_shared<SessionState>();
        state->factors = factors;
        state->mandatory = mandatory;
        state->store = theStore;
        state->source = source;

        if (!existing.data || options.forceReenroll)
        {
            if (factors.find("slstore") == factors.end())
            {
                const auto stored = theStore->read("slstore");
                if (!stored.error.empty())
                    return Result<Session>::fail(ErrorKind::LocalFailure,
                                                 "slhwid: store secret read failed: " + stored.error);
                std::vector<unsigned char> value;
                if (stored.data)
                {
                    auto existingValue = unwrapSlstore(*stored.data);
                    value = *existingValue;
                }
                else
                {
                    value.resize(32);
                    if (!source || !source(value.data(), value.size()))
                        return Result<Session>::fail(ErrorKind::LocalFailure, "slhwid: randomness failed");
                    std::vector<unsigned char> wrapped(kSlstorePrefixLength + 32);
                    static const unsigned char prefix[kSlstorePrefixLength] = {'S', 'L', 'S', 'T', 'O', 'R', '1'};
                    std::memcpy(wrapped.data(), prefix, kSlstorePrefixLength);
                    std::memcpy(wrapped.data() + kSlstorePrefixLength, value.data(), 32);
                    std::string writeError;
                    if (!theStore->write("slstore", wrapped, writeError))
                    {
                        secureWipe(value.data(), value.size());
                        return Result<Session>::fail(ErrorKind::LocalFailure,
                                                     "slhwid: store secret write failed: " + writeError);
                    }
                }
                factors["slstore"] = toLowerHex(value);
                state->factors = factors;
                secureWipe(value.data(), value.size());
            }
            for (const auto &name : mandatory)
                if (factors.find(name) == factors.end())
                    return Result<Session>::fail(ErrorKind::LocalFailure,
                                                 "slhwid: mandatory factor '" + name +
                                                     "' is not available on this machine");
            const int t = threshold(static_cast<int>(factors.size()), static_cast<int>(mandatory.size()));
            if (t == 0)
                return Result<Session>::fail(ErrorKind::LocalFailure,
                                             "slhwid: need at least 5 enrolled factors, have " +
                                                 std::to_string(factors.size()));
            try
            {
                Draw draw(source);
                Key k{};
                for (int limb = 0; limb < 4; ++limb)
                    k[limb] = draw.elem();
                const auto shared = buildShares(k, slotList(factors, mandatory), t, draw);
                const auto cw = checkWord(k);
                auto blob = serializeHelper(shared.shares, mandatory, t, shared.salt, cw);
                std::string writeError;
                if (!theStore->write("HWID-device", blob, writeError))
                    return Result<Session>::fail(ErrorKind::LocalFailure,
                                                 "slhwid: helper storage write failed: " + writeError);
                state->key = k;
                state->hasKey = true;
                state->expectedHelper = blob;
                secureWipe(blob.data(), blob.size());
                return Session(hwidOf(k), true, {}, false, state);
            }
            catch (const std::exception &error)
            {
                return Result<Session>::fail(ErrorKind::LocalFailure, error.what());
            }
        }

        RecoverResult recovered;
        try
        {
            recovered = recoverCore(*existing.data, factors);
        }
        catch (const std::exception &error)
        {
            return Result<Session>::fail(ErrorKind::LocalFailure, error.what());
        }
        if (!recovered.ok)
        {
            if (recovered.reason == "corrupt")
                return Result<Session>::fail(ErrorKind::LocalFailure,
                                             std::string(kCorruptPrefix) + "; re-enroll to recover");
            return Result<Session>::fail(ErrorKind::LocalFailure, driftMessage(recovered));
        }
        state->key = recovered.key;
        state->hasKey = true;
        state->expectedHelper = *existing.data;
        // A second application must not weaken a hard lock selected by the
        // application that enrolled the shared device helper.
        const auto helper = parseHelper(*existing.data);
        state->mandatory.clear();
        for (const auto &slot : helper.slots)
            if (slot.mandatory)
                state->mandatory.insert(slot.name);
        return Session(recovered.hwid, false, recovered.dead, recovered.pending, state);
    }

} // namespace syslocker::bedrock::slhwid::detail

// ── Session (namespace slhwid) ─────────────────────────────────────
namespace syslocker::bedrock::slhwid
{
    // ── Session ────────────────────────────────────────────────────────

    Session::Session(std::string hwid,
                     bool freshlyEnrolled,
                     std::vector<std::string> driftedSlots,
                     bool pendingRefresh,
                     std::shared_ptr<void> state)
        : hwid_(std::move(hwid)),
          freshlyEnrolled_(freshlyEnrolled),
          driftedSlots_(std::move(driftedSlots)),
          pendingRefresh_(pendingRefresh),
          state_(std::move(state))
    {
    }

    Session::~Session()
    {
        auto *state = static_cast<detail::SessionState *>(state_.get());
        if (state)
            detail::secureWipe(&state->key, sizeof(state->key));
    }

    const std::string &Session::hwid() const noexcept { return hwid_; }
    bool Session::freshlyEnrolled() const noexcept { return freshlyEnrolled_; }
    const std::vector<std::string> &Session::driftedSlots() const noexcept { return driftedSlots_; }
    bool Session::pendingRefresh() const noexcept { return pendingRefresh_; }

    void Session::commit() noexcept
    {
        auto *state = static_cast<detail::SessionState *>(state_.get());
        if (state == nullptr || state->committed || !state->hasKey)
            return;
        state->committed = true;
        try
        {
            std::function<void()> release;
            std::string lockError;
            if (!detail::acquireStorageLock(state->store->lockDirectory(), release, lockError))
                throw std::runtime_error(lockError);
            detail::ScopedUnlock storageLock(std::move(release));
            const auto current = state->store->read("HWID-device");
            if (!current.error.empty() || !current.data ||
                !detail::ctEqual(*current.data, state->expectedHelper))
            {
                // Another module user refreshed or re-enrolled after this
                // session prepared. Never restore a stale snapshot.
                detail::secureWipe(&state->key, sizeof(state->key));
                state->hasKey = false;
                return;
            }
            detail::Draw draw(state->source);
            auto refreshed = detail::refreshCore(state->key, state->factors, state->mandatory, draw);
            if (refreshed.written)
            {
                std::string writeError;
                if (state->store->write("HWID-device", refreshed.blob, writeError))
                {
                    pendingRefresh_ = false;
                    driftedSlots_.clear();
                }
                detail::secureWipe(refreshed.blob.data(), refreshed.blob.size());
            }
        }
        catch (...)
        {
            // the next launch re-derives
            volatile int sink = 0;
            (void)sink;
        }
        detail::secureWipe(&state->key, sizeof(state->key));
        state->hasKey = false;
    }

}

namespace syslocker::bedrock::slhwid
{
    Result<Session> prepare(const Options &options)
    {
        return detail::prepareWith(
            options,
            []() -> std::map<std::string, std::string>
            {
                std::string error;
                auto factors = detail::collectFactors(error);
                if (!error.empty())
                    throw std::runtime_error(error);
                return factors;
            },
            detail::randomSourceAlias(),
            nullptr);
    }
}

namespace syslocker::bedrock::slhwid::detail
{
    RandomSource randomSourceAlias() { return randomSource; }
}
