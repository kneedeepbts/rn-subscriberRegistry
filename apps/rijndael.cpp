/*
 * Using spec at https://www.etsi.org/deliver/etsi_ts/135200_135299/135206/14.00.00_60/ts_135206v140000p.pdf
 */

/*** Includes ***/
#include "rijndael.h"
#include "rijndaelstatics.h"

/*** Defines ***/

/*** Function Definitions ***/

/*** Class Method Definitions ***/
the303tel::crypto::Rijndael::Rijndael() {}

void the303tel::crypto::Rijndael::setKey(std::array<uint8_t, 16> value) {
    uint8_t roundConst;

    /* first round key equals key */
    for (uint8_t i = 0; i < 16; i++) {
        //roundKeys[0][i & 0x03][i>>2] = key[i];
        // roundKeys is [11][4][4], which works to [(x*16) + (y*4) + z]
        roundKeys[(0*16) + ((i & 0x03)*4) + (i>>2)] = value[i];
    }
    roundConst = 1;

    /* now calculate round keys */
    for (uint8_t i =1 ; i < 11; i++) {
        roundKeys[(i*16)+(0*4)+(0)] = S[roundKeys[((i-1)*16) + (1*4) + (3)]] ^ roundKeys[((i-1)*16) + (0*4) + (0)] ^ roundConst;
        roundKeys[(i*16)+(1*4)+(0)] = S[roundKeys[((i-1)*16) + (2*4) + (3)]] ^ roundKeys[((i-1)*16) + (1*4) + (0)];
        roundKeys[(i*16)+(2*4)+(0)] = S[roundKeys[((i-1)*16) + (3*4) + (3)]] ^ roundKeys[((i-1)*16) + (2*4) + (0)];
        roundKeys[(i*16)+(3*4)+(0)] = S[roundKeys[((i-1)*16) + (0*4) + (3)]] ^ roundKeys[((i-1)*16) + (3*4) + (0)];
        for (uint8_t j = 0; j < 4; j++)
        {
            roundKeys[(i*16) + (j*4) + (1)] = roundKeys[((i-1)*16) + (j*4) + (1)] ^ roundKeys[(i*16) + (j*4) + (0)];
            roundKeys[(i*16) + (j*4) + (2)] = roundKeys[((i-1)*16) + (j*4) + (2)] ^ roundKeys[(i*16) + (j*4) + (1)];
            roundKeys[(i*16) + (j*4) + (3)] = roundKeys[((i-1)*16) + (j*4) + (3)] ^ roundKeys[(i*16) + (j*4) + (2)];
        }
        /* update round constant */
        roundConst = Xtime[roundConst];
    }
    return;
}

std::array<uint8_t, 16> the303tel::crypto::Rijndael::encrypt(std::array<uint8_t, 16> value) {
    std::array<uint8_t, 16> output;

    /* initialize state array from input byte string */
    for (uint8_t i = 0; i < 16; i++) {
        state[((i & 0x3) * 4) + (i>>2)] = value[i];
    }

    /* add first round_key */
    KeyAdd(0);

    /* do lots of full rounds */
    for (uint8_t r = 1; r <= 9; r++) {
        ByteSub();
        ShiftRow();
        MixColumn();
        KeyAdd(r);
    }

    /* final round */
    ByteSub();
    ShiftRow();
    KeyAdd(10);

    /* produce output byte string from state array */
    for (uint8_t i = 0; i < 16; i++) {
        output[i] = state[((i & 0x3) * 4) + (i>>2)];
    }
    return output;
}

void the303tel::crypto::Rijndael::KeyAdd(uint8_t round)
{
    for (uint8_t i = 0; i < 4; i++) {
        for (uint8_t j = 0; j < 4; j++) {
            state[(i*4) + j] ^= roundKeys[(round*16)+(i*4) + (j)];
        }
    }
    return;
}

void the303tel::crypto::Rijndael::ByteSub()
{
    for (uint8_t i = 0; i < 4; i++) {
        for (uint8_t j = 0; j < 4; j++) {
            state[(i*4) + j] = S[state[(i*4) + j]];
        }
    }
    return;
}

void the303tel::crypto::Rijndael::ShiftRow()
{
    uint8_t temp;
    /* left rotate row 1 by 1 */
    temp = state[4]; // temp = state[1][0]; // 1*4 + 0
    state[4] = state[5]; // state[1][0] = state[1][1];
    state[5] = state[6]; // state[1][1] = state[1][2];
    state[6] = state[7]; // state[1][2] = state[1][3];
    state[7] = temp; // state[1][3] = temp;

    /* left rotate row 2 by 2 */
    temp = state[8]; // temp = state[2][0];
    state[8] = state[10]; // state[2][0] = state[2][2];
    state[10] = temp; // state[2][2] = temp;

    temp = state[9]; // temp = state[2][1];
    state[9] = state[11]; // state[2][1] = state[2][3];
    state[11] = temp; // state[2][3] = temp;

    /* left rotate row 3 by 3 */
    temp = state[12]; // temp = state[3][0];
    state[12] = state[15]; // state[3][0] = state[3][3];
    state[15] = state[14]; // state[3][3] = state[3][2];
    state[14] = state[13]; // state[3][2] = state[3][1];
    state[13] = temp; // state[3][1] = temp;
    return;
}

void the303tel::crypto::Rijndael::MixColumn()
{
    uint8_t temp, tmp, tmp0;

    /* do one column at a time */
    for (uint8_t i = 0; i < 4; i++) {
        temp = state[0 + i] ^ state[4 + i] ^ state[8 + i] ^ state[12 + i]; // temp = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i];
        tmp0 = state[0 + i];
        /* Xtime array does multiply by x in GF2^8 */
        tmp = Xtime[state[0 + i] ^ state[4 + i]];
        state[0 + i] ^= temp ^ tmp;
        tmp = Xtime[state[4 + i] ^ state[8 + i]];
        state[4 + i] ^= temp ^ tmp;
        tmp = Xtime[state[8 + i] ^ state[12 + i]];
        state[8 + i] ^= temp ^ tmp;
        tmp = Xtime[state[12 + i] ^ tmp0];
        state[12 + i] ^= temp ^ tmp;
    }
    return;
}
