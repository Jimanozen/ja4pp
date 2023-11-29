#ifndef JA4_JA4_H
#define JA4_JA4_H

#include <string>
#include <openssl/sha.h>

#include "ja4interface.h"

namespace ja4 {
    enum class TRANSPORT_PROTOCOL : char {
        PROTO_TCP  =  't',
        PROTO_QUIC =  'q'
    };

    enum class SNI : char {
        SNI_DOMAIN  = 'd',
        SNI_IP      = 'i'
    };

    enum class TLS_VERSION : uint16_t {
        TLS1_3  = 0x0304,
        TLS1_2  = 0x0303,
        TLS1_1  = 0x0302,
        TLS1_0  = 0x0301,
        SSL3_0  = 0x0300,
        SSL2_0  = 0x0200,
        SSL1_0  = 0x0100,
    };

    std::string uint16_to_hexstring(uint16_t hex);
    std::string digest_to_truncated_hash(const unsigned char *digest, size_t size);
    bool is_grease(uint16_t value);
    void degrease(std::vector<uint16_t> &vec);
    const char *tls_version_cstr(enum TLS_VERSION tls_version);
    const char *transport_protocol_cstr(enum TRANSPORT_PROTOCOL protocol);
    const char *sni_cstr(enum SNI sni);

    class Ja4 : private Ja4Interface {
        std::string raw;
        std::string fingerprint;
        std::string tls_version;
        std::string protocol;
        std::string sni;
        std::string alpn;
        std::vector<uint16_t> cipher_suites;
        std::vector<uint16_t> extensions;
        std::vector<uint16_t> signature_algorithms;
        enum TRANSPORT_PROTOCOL e_protocol;
        enum SNI e_sni;
        enum TLS_VERSION e_tls_version;
        uint32_t nb_extensions;
        uint16_t nb_cipher_suites;

        static void extension_filter(std::vector<uint16_t> &vec);
        Ja4 getSorted();

    public:
        Ja4(enum TRANSPORT_PROTOCOL protocol, enum TLS_VERSION tls_version, enum SNI sni, std::string &alpn, std::vector<uint16_t> &cipher_suites, std::vector<uint16_t> &extensions, std::vector<uint16_t> &signature_algorithms);
        std::string getRawOriginalOrder();
        std::string getFingerprintOriginalOrder();
        std::string getRaw() override;
        std::string getFingerprint() override;
    };
}

#endif //JA4_JA4_H
