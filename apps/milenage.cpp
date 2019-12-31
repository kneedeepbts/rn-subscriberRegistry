/*
 * Using spec at https://www.etsi.org/deliver/etsi_ts/135200_135299/135206/14.00.00_60/ts_135206v140000p.pdf
 */

/*** Includes ***/
#include "milenage.h"

/*** Defines ***/

/*** Function Definitions ***/

/*** Class Method Definitions ***/
the303tel::crypto::Milenage::Milenage() {}

void the303tel::crypto::Milenage::setKandOp(std::array<uint8_t, 16> k, std::array<uint8_t, 16> op) {
    std::array<uint8_t, 16> tmpOut;
    encryptor.setKey(k);

    tmpOut = encryptor.encrypt(op);

    for (uint8_t i = 0; i < 16; i++) {
        opc[i] = tmpOut[i] ^ op[i];
    }
    return;
}

void the303tel::crypto::Milenage::setKandOpc(std::array<uint8_t, 16> k, std::array<uint8_t, 16> op_c) {
    encryptor.setKey(k);
    opc = op_c;
    return;
}

void the303tel::crypto::Milenage::setRAND(std::array<uint8_t, 16> value) {
    rand = value;
    return;
}

void the303tel::crypto::Milenage::setSQN(std::array<uint8_t, 6> value) {
    sqn = value;
    return;
}

void the303tel::crypto::Milenage::setAMF(std::array<uint8_t, 2> value) {
    amf = value;
    return;
}

void the303tel::crypto::Milenage::runF1() {
    std::array<uint8_t, 16> rijndaelInput;
    std::array<uint8_t, 16> in1;
    std::array<uint8_t, 16> temp;
    std::array<uint8_t, 16> out;

    for (uint8_t i = 0; i < 16; i++) {
        rijndaelInput[i] = rand[i] ^ opc[i];
    }

    temp = encryptor.encrypt(rijndaelInput);

    for (uint8_t i = 0; i < 6; i++) {
        in1[i] = sqn[i];
        in1[i+8] = sqn[i];
    }

    for (uint8_t i = 0; i < 2; i++) {
        in1[i+6] = amf[i];
        in1[i+14] = amf[i];
    }

    /* XOR op_c and in1, rotate by r1=64, and XOR *
    * on the constant c1 (which is all zeroes) */
    for (uint8_t i = 0; i < 16; i++) {
        rijndaelInput[(i+8) % 16] = in1[i] ^ opc[i];
    }

    /* XOR on the value temp computed before */
    for (uint8_t i = 0; i < 16; i++) {
        rijndaelInput[i] ^= temp[i];
    }

    out = encryptor.encrypt(rijndaelInput);

    for (uint8_t i = 0; i < 16; i++) {
        out[i] ^= opc[i];
    }

    for (uint8_t i = 0; i < 8; i++) {
        mac_a[i] = out[i];
        mac_s[i] = out[i+8];
    }
    return;
}

void the303tel::crypto::Milenage::runF2345() {
    std::array<uint8_t, 16> rijndaelInput;
    std::array<uint8_t, 16> temp;
    std::array<uint8_t, 16> out;

    for (uint8_t i = 0; i < 16; i++) {
        rijndaelInput[i] = rand[i] ^ opc[i];
    }

    temp = encryptor.encrypt(rijndaelInput);

    /* To obtain output block OUT2: XOR OPc and TEMP,    *
     * rotate by r2=0, and XOR on the constant c2 (which *
     * is all zeroes except that the last bit is 1).     */
    for (uint8_t i = 0; i < 16; i++) {
        rijndaelInput[i] = temp[i] ^ opc[i];
    }

    rijndaelInput[15] ^= 1;

    out = encryptor.encrypt(rijndaelInput);

    for (uint8_t i = 0; i < 16; i++) {
        out[i] ^= opc[i];
    }

    for (uint8_t i = 0; i < 8; i++) {
        res[i] = out[i+8];
    }

    for (uint8_t i = 0; i < 6; i++) {
        ak[i] = out[i];
    }

    /* To obtain output block OUT3: XOR OPc and TEMP, *
    * rotate by r3=32, and XOR on the constant c3 (which *
    * is all zeroes except that the next to last bit is 1). */
    for (uint8_t i = 0; i < 16; i++) {
        rijndaelInput[(i+12) % 16] = temp[i] ^ opc[i];
    }

    rijndaelInput[15] ^= 2;

    out = encryptor.encrypt(rijndaelInput);

    for (uint8_t i = 0; i < 16; i++) {
        out[i] ^= opc[i];
    }

    for (uint8_t i = 0; i < 16; i++) {
        ck[i] = out[i];
    }

    /* To obtain output block OUT4: XOR OPc and TEMP, *
    * rotate by r4=64, and XOR on the constant c4 (which *
    * is all zeroes except that the 2nd from last bit is 1). */
    for (uint8_t i = 0; i < 16; i++) {
        rijndaelInput[(i+8) % 16] = temp[i] ^ opc[i];
    }

    rijndaelInput[15] ^= 4;

    out = encryptor.encrypt(rijndaelInput);

    for (uint8_t i = 0; i < 16; i++) {
        out[i] ^= opc[i];
    }

    for (uint8_t i = 0; i < 16; i++) {
        ik[i] = out[i];
    }

    /* To obtain output block OUT5: XOR OPc and TEMP, *
    * rotate by r5=96, and XOR on the constant c5 (which *
    * is all zeroes except that the 3rd from last bit is 1). */
    for (uint8_t i = 0; i < 16; i++) {
        rijndaelInput[(i+4) % 16] = temp[i] ^ opc[i];
    }

    rijndaelInput[15] ^= 8;

    out = encryptor.encrypt(rijndaelInput);

    for (uint8_t i=0; i < 16; i++) {
        out[i] ^= opc[i];
    }

    for (uint8_t i = 0; i < 6; i++) {
        akr[i] = out[i];
    }

    return;
}

std::array<uint8_t, 8> the303tel::crypto::Milenage::getMACA() {
    return mac_a;
}

std::array<uint8_t, 8> the303tel::crypto::Milenage::getMACS() {
    return mac_s;
}

std::array<uint8_t, 8> the303tel::crypto::Milenage::getRES() {
    return res;
}

std::array<uint8_t, 16> the303tel::crypto::Milenage::getCK() {
    return ck;
}

std::array<uint8_t, 16> the303tel::crypto::Milenage::getIK() {
    return ik;
}

std::array<uint8_t, 6> the303tel::crypto::Milenage::getAK() {
    return ak;
}

std::array<uint8_t, 6> the303tel::crypto::Milenage::getAKR() {
    return akr;
}

std::array<uint8_t, 8> the303tel::crypto::Milenage::getGsmKc() {
    std::array<uint8_t, 8> out;
    for (uint8_t i = 0; i < 8; i++) {
        out[i] = ck[i] ^ ck[i+8] ^ ik[i] ^ ik[i+8];
    }
    return out;
}

std::array<uint8_t, 4> the303tel::crypto::Milenage::getGsmSRES() {
    std::array<uint8_t, 4> out;
    for (uint8_t i = 0; i < 4; i++) {
        out[i] = res[i] ^ res[i+4];
    }
    return out;
}

uint8_t the303tel::crypto::Milenage::hextoint(char x) {
    x = toupper(x);
    if (x >= 'A' && x <= 'F')
        return x-'A'+10;
    else if (x >= '0' && x <= '9')
        return x-'0';
}

std::array<uint8_t, 16> the303tel::crypto::Milenage::convertSTR16ARR(std::string value) {
    std::array<uint8_t, 16> out;

    if(value.length() == 32) { // 32 hex digits sans the '0x' -> 16 bytes
        for (uint8_t i = 0; i < 16; i++) {
            out[i] = hextoint(value[2*i])<<4 | hextoint(value[(2*i)+1]);
        }
    }
    return out;
}

std::array<uint8_t, 4> the303tel::crypto::Milenage::convertSTR4ARR(std::string value) {
    std::array<uint8_t, 4> out;

    if(value.length() == 8) { // 32 hex digits sans the '0x' -> 16 bytes
        for (uint8_t i = 0; i < 4; i++) {
            out[i] = hextoint(value[2*i])<<4 | hextoint(value[(2*i)+1]);
        }
    }
    return out;
}
