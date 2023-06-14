#ifndef _RIJNDAEL_H
#define _RIJNDAEL_H

/*
 * Using spec at https://www.etsi.org/deliver/etsi_ts/135200_135299/135206/14.00.00_60/ts_135206v140000p.pdf
 */

/*** Includes ***/
#include <cstdint>
#include <array>

/*** Global Variables ***/

/*** Functions ***/

/*** Classes ***/
namespace the303tel {
    namespace crypto {
        class Rijndael {
            public:
                Rijndael();
                void setKey(std::array<uint8_t, 16> value);
                std::array<uint8_t, 16> encrypt(std::array<uint8_t, 16> value);

            private:
                std::array<uint8_t, 176> roundKeys; // 11*4*4, (x*16)+(y*4)+(z)
                std::array<uint8_t, 16> state;
                void KeyAdd(uint8_t round);
                void ByteSub();
                void ShiftRow();
                void MixColumn();
        };
    }
}

#endif // _RIJNDAEL_H
