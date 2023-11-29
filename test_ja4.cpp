#include <iostream>

#include "ja4.h"

int main() {

    /*
     * https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
     */
    auto proto = ja4::TRANSPORT_PROTOCOL::PROTO_TCP;
    auto version = ja4::TLS_VERSION::TLS1_3;
    auto sni = ja4::SNI::SNI_DOMAIN;
    std::string alpn = "h2";
    std::vector<uint16_t> ciphers = {0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035};
    std::vector<uint16_t> extensions = {0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015};
    std::vector<uint16_t> sign_algo = {0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601};

    ja4::Ja4 j(proto, version, sni, alpn, ciphers, extensions, sign_algo);

    std::cout << "ja4_ro : " << j.getRawOriginalOrder() << std::endl;
    std::cout << "ja4_o  : " << j.getFingerprintOriginalOrder() << std::endl;
    std::cout << "ja4_r  : " << j.getRaw() << std::endl;
    std::cout << "ja4    : " << j.getFingerprint() << std::endl;

    return 0;
}
