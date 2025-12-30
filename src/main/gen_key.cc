#include <iostream>
#include "security/ecdsa/private_key.h"
#include "security/ecdsa/public_key.h"
#include "security/ecdsa/curve.h"
#include <common/encode.h>

int main(int argc, char** argv) {
    seth::security::Curve curve;
    seth::security::PublicKey pubkey(curve);
    seth::security::PrivateKey prikey(argv[0]);

    pubkey.FromPrivateKey(curve, prikey);
    std::cout << seth::common::Encode::HexEncode(pubkey.str_pubkey()) << std::endl;
    std::cout << seth::common::Encode::HexEncode(pubkey.str_pubkey_uncompressed()) << std::endl;
    
    return 0;
}
