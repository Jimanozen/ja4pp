#ifndef JA4_JA4INTERFACE_H
#define JA4_JA4INTERFACE_H

namespace ja4 {
    class Ja4Interface {
        std::string _a;
        std::string _b;
        std::string _c;
        std::string _d;

    public:
        std::string & getPart_a() { return this->_a; };
        std::string & getPart_b() { return this->_b; };
        std::string & getPart_c() { return this->_c; };
        std::string & getPart_d() { return this->_d; };
        virtual std::string getRaw() = 0;
        virtual std::string getFingerprint() = 0;
    };
}

#endif //JA4_JA4INTERFACE_H
