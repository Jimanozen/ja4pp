#include <sstream>
#include <iomanip>
#include <openssl/sha.h>

#include "ja4.h"

namespace ja4 {
    std::string uint16_to_hexstring(uint16_t hex) {
        std::stringstream ss;
        ss << std::hex << std::setw(4) << std::setfill('0') << hex;

        return ss.str();
    }

    std::string digest_to_truncated_hash(const unsigned char *digest, size_t size) {
        std::stringstream ss;

        for (size_t i = 0; i < size; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(digest[i]);
        }

        return ss.str();
    }

    bool is_grease(const uint16_t value) {
        bool ret = false;

        if (((value & 0x0f0f) == 0x0a0a) && ((value & 0xff) == (value >> 8)))
            ret = true;

        return ret;
    }

    void degrease(std::vector<uint16_t> &vec) {
        for (auto it = vec.begin(); it != vec.end(); ++it) {
                if (is_grease(*it))
                    vec.erase(it);
        }
    }

    std::string &join_vector(std::string &str, const std::vector<uint16_t> &vec) {
        for (auto it = vec.begin(); it != vec.end(); it++) {
            if (is_grease(*it))
                continue;

            str.append(uint16_to_hexstring(*it));

            if (it != std::prev(vec.end())) {
                str.push_back(',');
            }
        }

        return str;
    }

    const char *alpn_cstr(const std::string &alpn) {
        if (alpn.empty())
            return "00";

        if (alpn == "http/1.1")
            return "h1";

        return alpn.c_str();
    }

    const char *tls_version_cstr(enum TLS_VERSION tls_version) {
        switch (tls_version) {
            case TLS_VERSION::SSL1_0:
                return "s1";

            case TLS_VERSION::SSL2_0:
                return "s2";

            case TLS_VERSION::SSL3_0:
                return "s3";

            case TLS_VERSION::TLS1_0:
                return "10";

            case TLS_VERSION::TLS1_1:
                return "11";

            case TLS_VERSION::TLS1_2:
                return "12";

            case TLS_VERSION::TLS1_3:
                return "13";

            default:
                return "00";
        }
    }

    const char *sni_cstr(enum SNI sni) {
        switch (sni) {
            case SNI::SNI_DOMAIN:
                return "d";
            case SNI::SNI_IP:
                return "i";
            default:
                return nullptr;
        }
    }

    const char *transport_protocol_cstr(enum TRANSPORT_PROTOCOL protocol) {
        switch (protocol) {
            case TRANSPORT_PROTOCOL::PROTO_QUIC:
                return "q";
            case TRANSPORT_PROTOCOL::PROTO_TCP:
                return "t";
            default:
                return nullptr;
        }
    }

    void Ja4::extension_filter(std::vector<uint16_t> &vec) {
        for (auto it = vec.begin(); it != vec.end(); ++it) {
            if (*it == 0x0000 || *it == 0x0010)
                vec.erase(it);
        }
    }

    Ja4 Ja4::getSorted() {
        std::vector<uint16_t> sorted_cipher_suites(this->cipher_suites);
        std::vector<uint16_t> sorted_extensions(this->extensions);

        /* removing ALPN and SNI extension */
        ja4::Ja4::extension_filter(sorted_extensions);

        std::sort(sorted_cipher_suites.begin(), sorted_cipher_suites.end());
        std::sort(sorted_extensions.begin(), sorted_extensions.end());

        return Ja4{this->e_protocol,
                   this->e_tls_version,
                   this->e_sni,
                   this->alpn,
                   sorted_cipher_suites,
                   sorted_extensions,
                   this->signature_algorithms};
    }

    Ja4::Ja4(enum TRANSPORT_PROTOCOL protocol, enum TLS_VERSION tls_version, enum SNI sni, std::string &alpn, std::vector<uint16_t> &cipher_suites, std::vector<uint16_t> &extensions, std::vector<uint16_t> &signature_algorithms) {
        this->e_sni = sni;
        this->e_tls_version = tls_version;
        this->e_protocol = protocol;
        this->cipher_suites = cipher_suites;
        this->extensions = extensions;
        this->signature_algorithms = signature_algorithms;

        this->alpn = alpn_cstr(alpn);

        this->protocol = transport_protocol_cstr(e_protocol);
        if (this->protocol.c_str() == nullptr)
            throw std::invalid_argument("Invalid argument for ja4::TRANSPORT_PROTOCOL");

        this->sni = sni_cstr(e_sni);
        if (this->sni.c_str() == nullptr)
            throw std::invalid_argument("Invalid argument for ja4::SNI");

        this->tls_version = tls_version_cstr(e_tls_version);
        if (this->tls_version.c_str() == nullptr)
            throw std::invalid_argument("Invalid argument for ja4::TLS_VERSION");

        degrease(this->extensions);
        degrease(this->cipher_suites);
        degrease(this->signature_algorithms);

        this->nb_cipher_suites = (this->cipher_suites.size() > 99) ? 99 : this->cipher_suites.size();
        this->nb_extensions = (this->extensions.size() > 99) ? 99 : this->extensions.size();

        this->getPart_a().append(this->protocol)
                .append(this->tls_version)
                .append(this->sni)
                .append(std::to_string(this->nb_cipher_suites))
                .append(std::to_string(this->nb_extensions))
                .append(this->alpn);

        (void)join_vector(this->getPart_b(), this->cipher_suites);

        (void)join_vector(this->getPart_c(), this->extensions);

        if (!this->signature_algorithms.empty()) {
            this->getPart_c().push_back('_');
            (void) join_vector(this->getPart_c(), this->signature_algorithms);
        }
    }

    std::string Ja4::getFingerprint() {
        Ja4 sorted = this->getSorted();
        unsigned char digest[SHA256_DIGEST_LENGTH];
        std::string hash_part_b;
        std::string hash_part_c;

        SHA256(reinterpret_cast<const unsigned char *>(sorted.getPart_b().c_str()),
               sorted.getPart_b().size(),
               digest);

        hash_part_b = digest_to_truncated_hash(digest, 6);

        SHA256(reinterpret_cast<const unsigned char *>(sorted.getPart_c().c_str()),
               sorted.getPart_c().size(),
               digest);

        hash_part_c = digest_to_truncated_hash(digest, 6);

        return this->getPart_a() + "_" + hash_part_b + "_" + hash_part_c;
    }

    std::string Ja4::getRawOriginalOrder() {
        return this->getPart_a() + "_" + this->getPart_b() + "_" + this->getPart_c();
    }

    std::string Ja4::getRaw() {
        return this->getSorted().getRawOriginalOrder();
    }

    std::string Ja4::getFingerprintOriginalOrder() {
        unsigned char digest[SHA256_DIGEST_LENGTH];
        std::string hash_part_b;
        std::string hash_part_c;

        SHA256(reinterpret_cast<const unsigned char *>(this->getPart_b().c_str()),
               this->getPart_b().size(),
               digest);

        hash_part_b = digest_to_truncated_hash(digest, 6);

        SHA256(reinterpret_cast<const unsigned char *>(this->getPart_c().c_str()),
               this->getPart_c().size(),
               digest);

        hash_part_c = digest_to_truncated_hash(digest, 6);

        return this->getPart_a() + "_" + hash_part_b + "_" + hash_part_c;
    }
}