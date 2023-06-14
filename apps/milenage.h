#ifndef _MILENAGE_H
#define _MILENAGE_H

/*
 * Using spec at https://www.etsi.org/deliver/etsi_ts/135200_135299/135206/14.00.00_60/ts_135206v140000p.pdf
 */

/*** Includes ***/
#include <cstdint>
#include <array>
#include <string.h>
#include "rijndael.h"

/*** Global Variables ***/

/*** Functions ***/

/*** Classes ***/
namespace the303tel {
    namespace crypto {
        class Milenage {
            public:
                Milenage();
                void setKandOp(std::array<uint8_t, 16> k, std::array<uint8_t, 16> op);
                void setKandOpc(std::array<uint8_t, 16> k, std::array<uint8_t, 16> op_c);
                void setRAND(std::array<uint8_t, 16> value);
                void setSQN(std::array<uint8_t, 6> value);
                void setAMF(std::array<uint8_t, 2> value);

                void runF1();
                void runF2345();

                std::array<uint8_t, 8> getMACA();
                std::array<uint8_t, 8> getMACS();
                std::array<uint8_t, 8> getRES();
                std::array<uint8_t, 16> getCK();
                std::array<uint8_t, 16> getIK();
                std::array<uint8_t, 6> getAK();
                std::array<uint8_t, 6> getAKR();

                std::array<uint8_t, 8> getGsmKc();
                std::array<uint8_t, 4> getGsmSRES();

                // Crutch functions:
                uint8_t hextoint(char x);
                std::array<uint8_t, 16> convertSTR16ARR(std::string value);
                std::array<uint8_t, 4> convertSTR4ARR(std::string value);

            private:
                std::array<uint8_t, 16> opc;
                std::array<uint8_t, 16> rand;
                std::array<uint8_t, 6> sqn;
                std::array<uint8_t, 2> amf;

                std::array<uint8_t, 8> mac_a;
                std::array<uint8_t, 8> mac_s;
                std::array<uint8_t, 8> res;
                std::array<uint8_t, 16> ck;
                std::array<uint8_t, 16> ik;
                std::array<uint8_t, 6> ak;
                std::array<uint8_t, 6> akr;

                the303tel::crypto::Rijndael encryptor;
        };
    }
}

#endif // _MILENAGE_H

