//
//  WKAuthorizer.c
//
//
//  Created by Christina Peterson on 6/13/22.
//

#include <stdio.h>
#include <stdbool.h>
#include <string>
#include <vector>
#include <iostream>

#include <bitcoin/src/script/script.h>
#include <bitcoin/src/primitives/transaction.h>
#include <bitcoin/src/key_io.h>
#include <bitcoin/src/base58.h>
#include <bitcoin/src/core_io.h>

#include <bitcoin/src/crypto/hmac_sha512.h>
#include <bitcoin/src/wallet/crypter.h>

#include <sqlite3.h>
#include <regex>

#define MAINNET 0

#define BIP_44_ADDRESS_GAP_LIMIT 20
#define TRANSACTION_FEE_PER_BYTE 0.6
#define TRANSACTION_MAX_INPUTS 100000 // TODO: Increase past 100,000 inputs?
#define TRANSACTION_DUST_AMOUNT 135

#define SIZE_SIGNED_INPUT_BYTES 150
#define SIZE_EMPTY_TX_BYTES 10

#if MAINNET
    const char *pubKeyHash = "00";
#else
    const char *pubKeyHash = "6f";
#endif

using Record = std::vector<std::string>;
using Records = std::vector<Record>;

static secp256k1_context* secp256k1_context_sign = nullptr;

extern "C++" {
    //#include <bitcoin/src/script/script.h>
}

//extern "C++" {
extern "C" {

class TokenInput;
class TokenTransaction;
class TxBuilder;
//class ArgsManager;

static int select_callback(void *p_data, int num_fields, char **p_fields, char **p_col_names)
{
  Records* records = static_cast<Records*>(p_data);
  try {
    records->emplace_back(p_fields, p_fields + num_fields);
  }
  catch (...) {
    // abort select on failure, don't let exception propogate thru sqlite3 call-stack
    return 1;
  }
  return 0;
}

static int callback(void *NotUsed, int argc, char **argv, char **azColName) {
   int i;
   for(i = 0; i<argc; i++) {
      printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
   }
   printf("\n");
   return 0;
}

typedef struct UTxOutData {
    //uint32_t vout;
    CTxOut txOut;
} UTxOutData;

typedef struct OutputData {
    std::string asset;
    std::string alias;
    std::string domain;
    std::string version;
    std::string authorizer;
    std::string address;
    int amount;
    std::string notes;
    std::string issuer;
    COutPoint linkPrevOutpoint;
    std::string state;
} OutputData;

typedef struct SigOpStruct {
    int nScriptChunk;
    std::string type;
    std::string addressStr;
    unsigned long nHashType;
}SigOpStruct;

typedef struct TokenDataStruct {
  std::string asset;
    int amount;
    std::string address;
    std::string authorizer;
    std::string notes;
    std::string issuer;
    std::string state;
} TokenDataStruct;

typedef struct Chunks {
    std::string buf;
    size_t len;
    opcodetype opCodeNum;
} Chunks;

typedef struct AssetStruct {
    int id;
    std::string alias;
    std::string issuerAddress;
} AssetStruct;

typedef struct PaymentOutput {
    std::string type;
    int amount;
    AssetStruct asset;
} PaymentOutput;

typedef struct Utxo {
    int64_t id;
    std::string utxo_id;
    int64_t wallet_id;
    int64_t from_wallet_id;
    int64_t satoshis;
    std::string address;
    int address_index;
    std::string txid;
    int vout;
    std::string script;
    std::string spent_txid;
    int64_t amount;
    int64_t asset_id;

    Utxo() {
        id = 0;
        utxo_id = std::string("");
        wallet_id = 0;
        from_wallet_id = 0;
        satoshis = 0;
        address = std::string("");
        address_index = 0;
        txid = std::string("");
        vout = 0;
        script = std::string("");
        spent_txid = std::string("");
        amount = 0;
        asset_id = 0;
    }
} Utxo;

class BaseConverter
{
public:
    std::string GetSourceBaseSet() const { return sourceBaseSet_; }
    std::string GetTargetBaseSet() const { return targetBaseSet_; }
    unsigned int GetSourceBase() const { return (unsigned int)sourceBaseSet_.length(); }
    unsigned int GetTargetBase() const { return (unsigned int)targetBaseSet_.length(); }

    /// <summary>
    /// Constructor
    /// </summary>
    /// <param name="sourceBaseSet">Characters used for source base</param>
    /// <param name="targetBaseSet">Characters used for target base</param>
    BaseConverter(const std::string& sourceBaseSet, const std::string& targetBaseSet);

    /// <summary>
    /// Get a base converter for decimal to binary numbers
    /// </summary>
    static const BaseConverter& DecimalToBinaryConverter();

    /// <summary>
    /// Get a base converter for binary to decimal numbers
    /// </summary>
    static const BaseConverter& BinaryToDecimalConverter();

    /// <summary>
    /// Get a base converter for decimal to binary numbers
    /// </summary>
    static const BaseConverter& DecimalToHexConverter();

    /// <summary>
    /// Get a base converter for binary to decimal numbers
    /// </summary>
    static const BaseConverter& HexToDecimalConverter();

    /// <summary>
    /// Convert a value in the source number base to the target number base.
    /// </summary>
    /// <param name="value">Value in source number base.</param>
    /// <returns>Value in target number base.</returns>
    std::string  Convert(std::string value) const;


    /// <summary>
    /// Convert a value in the source number base to the target number base.
    /// </summary>
    /// <param name="value">Value in source number base.</param>
    /// <param name="minDigits">Minimum number of digits for returned value.</param>
    /// <returns>Value in target number base.</returns>
    std::string Convert(const std::string& value, size_t minDigits) const;

    /// <summary>
    /// Convert a decimal value to the target base.
    /// </summary>
    /// <param name="value">Decimal value.</param>
    /// <returns>Result in target base.</returns>
    std::string FromDecimal(unsigned int value) const;

    /// <summary>
    /// Convert a decimal value to the target base.
    /// </summary>
    /// <param name="value">Decimal value.</param>
    /// <param name="minDigits">Minimum number of digits for returned value.</param>
    /// <returns>Result in target base.</returns>
    std::string FromDecimal(unsigned int value, size_t minDigits) const;

    /// <summary>
    /// Convert value in source base to decimal.
    /// </summary>
    /// <param name="value">Value in source base.</param>
    /// <returns>Decimal value.</returns>
    unsigned int ToDecimal(std::string value) const;

private:
    /// <summary>
    /// Divides x by y, and returns the quotient and remainder.
    /// </summary>
    /// <param name="baseDigits">Base digits for x and quotient.</param>
    /// <param name="x">Numerator expressed in base digits; contains quotient, expressed in base digits, upon return.</param>
    /// <param name="y">Denominator</param>
    /// <returns>Remainder of x / y.</returns>
    static unsigned int divide(const std::string& baseDigits,
                               std::string& x,
                               unsigned int y);

    static unsigned int base2dec(const std::string& baseDigits,
                                 const std::string& value);

    static std::string dec2base(const std::string& baseDigits, unsigned int value);

private:
    static const char*  binarySet_;
    static const char*  decimalSet_;
    static const char*  hexSet_;
    std::string         sourceBaseSet_;
    std::string         targetBaseSet_;
};

// Arbitrary precision base conversion by Daniel Gehriger <gehriger@linkcad.com>

#include <stdexcept>
#include <algorithm>


const char* BaseConverter::binarySet_ = "01";
const char* BaseConverter::decimalSet_ = "0123456789";
//const char* BaseConverter::hexSet_ = "0123456789ABCDEF";
const char* BaseConverter::hexSet_ = "0123456789abcdef";

BaseConverter::BaseConverter(const std::string& sourceBaseSet, const std::string& targetBaseSet)
    : sourceBaseSet_(sourceBaseSet)
    , targetBaseSet_(targetBaseSet)
{
    if (sourceBaseSet.empty() || targetBaseSet.empty())
        throw std::invalid_argument("Invalid base character set");
}

const BaseConverter& BaseConverter::DecimalToBinaryConverter()
{
    static const BaseConverter dec2bin(decimalSet_, binarySet_);
    return dec2bin;
}

const BaseConverter& BaseConverter::BinaryToDecimalConverter()
{
    static const BaseConverter bin2dec(binarySet_, decimalSet_);
    return bin2dec;
}

const BaseConverter& BaseConverter::DecimalToHexConverter()
{
    static const BaseConverter dec2hex(decimalSet_, hexSet_);
    return dec2hex;
}

const BaseConverter& BaseConverter::HexToDecimalConverter()
{
    static const BaseConverter hex2dec(hexSet_, decimalSet_);
    return hex2dec;
}

std::string BaseConverter::Convert(std::string value) const
{
    unsigned int numberBase = GetTargetBase();
    std::string result;

    do
    {
        unsigned int remainder = divide(sourceBaseSet_, value, numberBase);
        result.push_back(targetBaseSet_[remainder]);
    }
    while (!value.empty() && !(value.length() == 1 && value[0] == sourceBaseSet_[0]));

    std::reverse(result.begin(), result.end());
    return result;
}

std::string BaseConverter::Convert(const std::string& value, size_t minDigits) const
{
    std::string result = Convert(value);
    if (result.length() < minDigits)
        return std::string(minDigits - result.length(), targetBaseSet_[0]) + result;
    else
        return result;
}

std::string BaseConverter::FromDecimal(unsigned int value) const
{
    return dec2base(targetBaseSet_, value);
}

std::string BaseConverter::FromDecimal(unsigned int value, size_t minDigits) const
{
    std::string result = FromDecimal(value);
    if (result.length() < minDigits)
        return std::string(minDigits - result.length(), targetBaseSet_[0]) + result;
    else
        return result;
}

unsigned int BaseConverter::ToDecimal(std::string value) const
{
    return base2dec(sourceBaseSet_, value);
}

unsigned int BaseConverter::divide(const std::string& baseDigits, std::string& x, unsigned int y)
{
    std::string quotient;

    size_t lenght = x.length();
    for (size_t i = 0; i < lenght; ++i)
    {
        size_t j = i + 1 + x.length() - lenght;
        if (x.length() < j)
            break;

        unsigned int value = base2dec(baseDigits, x.substr(0, j));

        quotient.push_back(baseDigits[value / y]);
        x = dec2base(baseDigits, value % y) + x.substr(j);
    }

    // calculate remainder
    unsigned int remainder = base2dec(baseDigits, x);

    // remove leading "zeros" from quotient and store in 'x'
    size_t n = quotient.find_first_not_of(baseDigits[0]);
    if (n != std::string::npos)
    {
        x = quotient.substr(n);
    }
    else
    {
        x.clear();
    }

    return remainder;
}

std::string BaseConverter::dec2base(const std::string& baseDigits, unsigned int value)
{
    unsigned int numberBase = (unsigned int)baseDigits.length();
    std::string result;
    do
    {
        result.push_back(baseDigits[value % numberBase]);
        value /= numberBase;
    }
    while (value > 0);

    std::reverse(result.begin(), result.end());
    return result;
}

unsigned int BaseConverter::base2dec(const std::string& baseDigits, const std::string& value)
{
    unsigned int numberBase = (unsigned int)baseDigits.length();
    unsigned int result = 0;
    for (size_t i = 0; i < value.length(); ++i)
    {
        result *= numberBase;
        int c = baseDigits.find(value[i]);
        if (c == std::string::npos)
            throw std::runtime_error("Invalid character");

        result += (unsigned int)c;
    }

    return result;
}

// C++ program to multiply two numbers represented
// as strings.
//#include<bits/stdc++.h>

// Multiplies str1 and str2, and prints result.
static std::string multiply(std::string num1, std::string num2)
{
    int len1 = num1.size();
    int len2 = num2.size();
    if (len1 == 0 || len2 == 0)
    return "0";

    // will keep the result number in vector
    // in reverse order
    std::vector<int> result(len1 + len2, 0);

    // Below two indexes are used to find positions
    // in result.
    int i_n1 = 0;
    int i_n2 = 0;

    // Go from right to left in num1
    for (int i=len1-1; i>=0; i--)
    {
        int carry = 0;
        int n1 = num1[i] - '0';

        // To shift position to left after every
        // multiplication of a digit in num2
        i_n2 = 0;

        // Go from right to left in num2
        for (int j=len2-1; j>=0; j--)
        {
            // Take current digit of second number
            int n2 = num2[j] - '0';

            // Multiply with current digit of first number
            // and add result to previously stored result
            // at current position.
            int sum = n1*n2 + result[i_n1 + i_n2] + carry;

            // Carry for next iteration
            carry = sum/10;

            // Store result
            result[i_n1 + i_n2] = sum % 10;

            i_n2++;
        }

        // store carry in next cell
        if (carry > 0)
            result[i_n1 + i_n2] += carry;

        // To shift position to left after every
        // multiplication of a digit in num1.
        i_n1++;
    }

    // ignore '0's from the right
    int i = result.size() - 1;
    while (i>=0 && result[i] == 0)
    i--;

    // If all were '0's - means either both or
    // one of num1 or num2 were '0'
    if (i == -1)
    return "0";

    // generate the result string
    std::string s = "";

    while (i >= 0)
        s += std::to_string(result[i--]);

    return s;
}

// C++ program to find sum of two large numbers.
//#include<bits/stdc++.h>
//using namespace std;

// Function for finding sum of larger numbers
static std::string add(std::string str1, std::string str2)
{
    // Before proceeding further, make sure length
    // of str2 is larger.
    if (str1.length() > str2.length())
        swap(str1, str2);

    // Take an empty string for storing result
    std::string str = "";

    // Calculate length of both string
    int n1 = str1.length(), n2 = str2.length();

    // Reverse both of strings
    reverse(str1.begin(), str1.end());
    reverse(str2.begin(), str2.end());

    int carry = 0;
    for (int i=0; i<n1; i++)
    {
        // Do school mathematics, compute sum of
        // current digits and carry
        int sum = ((str1[i]-'0')+(str2[i]-'0')+carry);
        str.push_back(sum%10 + '0');

        // Calculate carry for next step
        carry = sum/10;
    }

    // Add remaining digits of larger number
    for (int i=n1; i<n2; i++)
    {
        int sum = ((str2[i]-'0')+carry);
        str.push_back(sum%10 + '0');
        carry = sum/10;
    }

    // Add remaining carry
    if (carry)
        str.push_back(carry+'0');

    // reverse resultant string
    reverse(str.begin(), str.end());

    return str;
}

// C++ program to find difference of two large numbers.
//#include <bits/stdc++.h>
//using namespace std;

// Returns true if str1 is smaller than str2.
static bool isSmaller(std::string str1, std::string str2)
{
    // Calculate lengths of both string
    int n1 = str1.length(), n2 = str2.length();

    if (n1 < n2)
        return true;
    if (n2 < n1)
        return false;

    for (int i = 0; i < n1; i++)
        if (str1[i] < str2[i])
            return true;
        else if (str1[i] > str2[i])
            return false;

    return false;
}

// Function for find difference of larger numbers
static std::string findDiff(std::string str1, std::string str2)
{
    // Before proceeding further, make sure str1
    // is not smaller
    if (isSmaller(str1, str2))
        swap(str1, str2);

    // Take an empty string for storing result
    std::string str = "";

    // Calculate length of both string
    int n1 = str1.length(), n2 = str2.length();

    // Reverse both of strings
    reverse(str1.begin(), str1.end());
    reverse(str2.begin(), str2.end());

    int carry = 0;

    // Run loop till small string length
    // and subtract digit of str1 to str2
    for (int i = 0; i < n2; i++) {
        // Do school mathematics, compute difference of
        // current digits

        int sub
            = ((str1[i] - '0') - (str2[i] - '0') - carry);

        // If subtraction is less then zero
        // we add then we add 10 into sub and
        // take carry as 1 for calculating next step
        if (sub < 0) {
            sub = sub + 10;
            carry = 1;
        }
        else
            carry = 0;

        str.push_back(sub + '0');
    }

    // subtract remaining digits of larger number
    for (int i = n2; i < n1; i++) {
        int sub = ((str1[i] - '0') - carry);

        // if the sub value is -ve, then make it positive
        if (sub < 0) {
            sub = sub + 10;
            carry = 1;
        }
        else
            carry = 0;

        str.push_back(sub + '0');
    }

    // reverse resultant string
    reverse(str.begin(), str.end());

    return str;
}

static std::string mod(std::string str1, std::string str2) {
/*    if (str1 == str2) {
        return std::to_string(0);
    }
    else if (isSmaller(str1, str2)) {
        return str1;
    }
    else {
        std::string diff = findDiff(str1, str2);
        return mod(diff, str2);
    }*/

    /*while(!isSmaller(str1, str2)) {
        str1 = findDiff(str1, str2);
        printf("str1: %s\n", str1.c_str());
    }
    return str1;*/

    while(!isSmaller(str1, str2)) {

        int size1 = str1.size();
        int size2 = str2.size();

        //printf("size1 = %d\n", size1);
        //printf("size2 = %d\n", size2);

        int size_diff = size1 - size2;

        std::string str3 = str2;
        std::string str5("0");
        std::string str_prev;
        for(int i = 0; i < size_diff; i++) {
            str_prev = str3;
            str3 = str3 + str5;
        }
        if(isSmaller(str1, str3)) str3 = str_prev;
        //printf("str3: %s\n", str3.c_str());

        str1 = findDiff(str1, str3);
        str1.erase(0, str1.find_first_not_of('0'));

        //printf("str1: %s\n", str1.c_str());
    }
    return str1;
}

static std::vector<unsigned char> sliceBufferUch(std::vector<unsigned char> buf, unsigned int start, unsigned int end) {
    std::vector<unsigned char> result;

    if(start > buf.size()) return result;

    if(end > buf.size()) end = buf.size();

    for(unsigned int i = start; i < end; i++) {
        result.push_back(buf[i]);
    }

    return result;
}

static std::vector<std::string> sliceBuffer(std::vector<std::string> buf, unsigned int start, unsigned int end) {
    std::vector<std::string> result;

    if(start > buf.size()) return result;

    if(end > buf.size()) end = buf.size();

    for(unsigned int i = start; i < end; i++) {
        result.push_back(buf[i]);
    }

    return result;
}

static std::vector<std::string> sliceBuffer(std::vector<std::string> buf, unsigned int start) {
    std::vector<std::string> result;

    if((start > buf.size())) return result;

    for(unsigned int i = start; i < buf.size(); i++) {
        result.push_back(buf[i]);
    }

    return result;
}

static int64_t bufferToNumber(std::vector<std::string> buf) {
    if(buf.size() == 0) return 0;

    std::string str;

    for(int i = 0; i < buf.size(); i++) {
        str = str + buf[i];
    }

    return std::stoi(str, 0, 16);
}

static std::string stringToHex(std::string str) {
    if(str.size() == 0) return std::string("");
    size_t n = str.size();
    char hex[n*2];

    for (int i = 0, j = 0; i < n; ++i, j += 2) {
        //printf("%02x", str.c_str()[i] & 0xff);
        sprintf(hex + j, "%02x", str.c_str()[i] & 0xff);
    }
    //printf("\n");
    std::string ret(hex);
    return ret;
}

std::string hexToString(std::string hex_str) {
    if(hex_str.size() == 0) return std::string("");
    size_t n = hex_str.size();

    char string[n];

  for (int i = 0, j = 0; j < n; ++i, j += 2) {
      int val[1];
      sscanf(hex_str.c_str() + j, "%2x", val);
      string[i] = val[0];
      string[i + 1] = '\0';
  }

    std::string ret(string);
    return ret;
}

static std::vector<Chunks> getChunks(CScript script) {
    CScript::const_iterator pc = script.begin();
    CScript::const_iterator end = script.end();
    opcodetype opcodeRet;
    std::vector<unsigned char> vchRet;

    std::vector<Chunks> chunks;
    while (script.GetOp(pc, opcodeRet, vchRet)) {
        //printf("OPCODE: %02x\n", opcodeRet);
        Chunks chunk;
        std::string s(vchRet.begin(), vchRet.end());
        chunk.buf = stringToHex(s);
        //printf("vchRet: %s\n", chunk.buf.c_str());
        chunk.len = chunk.buf.size()/2;
        //printf("len: %lu\n", chunk.len);
        chunk.opCodeNum = opcodeRet;
        //printf("OPNAME: %s\n", GetOpName(opcodeRet).c_str());

        chunks.push_back(chunk);
    }
    return chunks;
}

static std::vector<unsigned char> hexToUchBuffer(std::string buf) {
    std::vector<unsigned char> result;
    //if(buf.size() == 0) return result;
    for(int i = 0; i < (int) (buf.size() - 1); i+=2) {

        std::string st(1, buf[i]);
        std::string st1(1, buf[i+1]);
        std::string str = st + st1;

        unsigned int uch = (unsigned int) std::stoi(str, 0, 16);
        //printf("str: %d\n", uch);

        result.push_back(uch);

    }
    return result;
}

static std::vector<unsigned char> scriptToBuffer(CScript script) {
    std::string s(script.begin(), script.end());
    return hexToUchBuffer(stringToHex(s));
}

static void setChunk(CScript& script, int nChunk, std::vector<unsigned char> sig) {
    CScript::iterator pc = script.begin();
    CScript::iterator end = script.end();
    opcodetype opcodeRet;
    std::vector<unsigned char> vchRet;

    int cnt = 0;
    while(cnt <= nChunk)
    {
        opcodeRet = OP_INVALIDOPCODE;
        //if (pvchRet)
        //        pvchRet->clear();
        if (vchRet.size() != 0)
                vchRet.clear();
        if (pc >= end)
                return;

        // Read instruction
        if (end - pc < 1)
                return;

        if(cnt++ == nChunk) {
            /*CScript::iterator pc2 = pc;
            pc2 = pc2 + 1 + *pc2;
            CScript scriptSuffix(pc2, end);
            std::vector<unsigned char> buf = scriptToBuffer(scriptSuffix);*/

            unsigned int oldSize = *pc;

            char ch[3];
            sprintf(ch, "%02lx", sig.size());
            unsigned int uch = (unsigned int) std::stoi(ch, 0, 16);
            *pc = uch;
            pc++;
            //printf("before pc = %02x\n", *pc);
            //printf("before pc + 1 = %02x\n", *(pc + 1));

            //pc = script.erase(pc);

            for(unsigned int i = 0; i < oldSize; i++) {
                pc = script.erase(pc);
            }

            //printf("after pc = %02x\n", *pc);

            /*for(size_t i = 0; i < buf.size(); i++) {
                printf("%02x ", buf[i]);
                sig.push_back(buf[i]);
            }
            printf("\n");*/

            script.insert(pc, sig.begin(), sig.end());

            return;
        }

        unsigned int opcode = *pc++;
        //printf("opcode = %02x\n", opcode);

        // Immediate operand
        if (opcode <= OP_PUSHDATA4)
        {
                unsigned int nSize = 0;
                if (opcode < OP_PUSHDATA1)
                {
                        nSize = opcode;
                }
                else if (opcode == OP_PUSHDATA1)
                {
                        if (end - pc < 1)
                                return;
                        nSize = *pc++;
                }
                else if (opcode == OP_PUSHDATA2)
                {
                        if (end - pc < 2)
                                return;
                        nSize = ReadLE16(&pc[0]);
                        pc += 2;
                }
                else if (opcode == OP_PUSHDATA4)
                {
                        if (end - pc < 4)
                                return;
                        nSize = ReadLE32(&pc[0]);
                        pc += 4;
                }
                if (end - pc < 0 || (unsigned int)(end - pc) < nSize)
                        return;
                //if (pvchRet)
                //        pvchRet->assign(pc, pc + nSize);
                vchRet.assign(pc, pc + nSize);
                pc += nSize;
        }

        opcodeRet = static_cast<opcodetype>(opcode);
    }

}

static std::string bufferToString(std::vector<std::string> buf) {
    std::string str;

    for(int i = 0; i < buf.size(); i++) {
        str = str + buf[i];
    }
    return str;
}

static std::vector<unsigned char> bufferAlloc(unsigned int n) {

    std::vector<unsigned char> result;
    for(unsigned int i = 0; i < n; i++) {
        unsigned int uch = (unsigned int) 0;
        result.push_back(uch);
    }
    return result;
}

static std::vector<unsigned char> bufferToUchBuffer(std::vector<std::string> buf) {

    std::vector<unsigned char> result;
    for(unsigned int i = 0; i < buf.size(); i++) {

        unsigned int uch = (unsigned int) std::stoi(buf[i], 0, 16);
        //printf("str: %d\n", uch);

        result.push_back(uch);

    }
    return result;
}

static std::string uchbufToString(std::vector<unsigned char> buf) {
    std::string str;
    for(int i = 0; i < buf.size(); i++) {
        char ch[3];
        sprintf(ch, "%02x", buf[i]);
        str = str + std::string(ch);
    }
    return str;
}

static std::vector<unsigned char> toLittleEndianUch(std::vector<unsigned char> buf) {

    std::vector<unsigned char> result;
    for(int i = buf.size() - 1; i >= 0; i--) {
        result.push_back(buf[i]);
    }
    return result;
}

static std::vector<std::string> stringToBuffer(std::string buf) {
    std::vector<std::string> result;

    for(unsigned int i = 0; i < (buf.size() - 1); i+=2) {

        std::string st(1, buf[i]);
        std::string st1(1, buf[i+1]);
        std::string str = st + st1;

        result.push_back(str);

    }
    return result;

}

static std::vector<unsigned char> getLittleEndian(CKey privKey, std::vector<unsigned char> sig, std::vector<unsigned char> hashBuf) {

    std::string wif = EncodeSecret(privKey);
    //printf("wif: %s\n", wif.c_str());
    std::vector<unsigned char> vchRet;
    int max_ret_len = 100;
    bool res = DecodeBase58Check(wif, vchRet, max_ret_len);
    /*for(size_t i = 0; i < vchRet.size(); i++) {
        printf("%02x", vchRet[i]);
    }
    printf("\n");*/
    std::vector<unsigned char> bnBuf = sliceBufferUch(vchRet, 1, 1 + 32);
    std::string bnStr = uchbufToString(bnBuf);
    //printf("bnStr: %s\n", bnStr.c_str());

    std::vector<unsigned char> rBuf = sliceBufferUch(sig, 4, 4 + 32);
    std::string rStr = uchbufToString(rBuf);
    //printf("rStr: %s\n", rStr.c_str());

    std::string hashBufStr = uchbufToString(hashBuf);
    //printf("hashBufStr: %s\n", hashBufStr.c_str());

    const BaseConverter& hex2dec = BaseConverter::HexToDecimalConverter();

    std::string d = hex2dec.Convert(bnStr.c_str()); //"5264b9cc16e3205b2114bb36bc3c660dc24fc16f99bb79b1a95136aff3f08596"

    std::string r = hex2dec.Convert(rStr.c_str()); //"1c9b0e71d32fcedb7c5a644c6dcf30a52691c67abc18de3508689b2748bc2edf"

    std::string e = hex2dec.Convert(hashBufStr.c_str()); //"502d9839d55f6c5acd0daf920186e93f8a606c42d92e698be81b6d275eb1e23a"

    std::string kinvmN = hex2dec.Convert("73f7579deedd822d7cb84fd5f85aa3f135eb6f35c67dc6dc5fad77b6696e0718");

    std::string N = hex2dec.Convert("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

    printf("N: %s\n", N.c_str());

    std::string result = multiply(d, r);
    printf("result = %s\n", result.c_str());

    const BaseConverter& dec2hex = BaseConverter::DecimalToHexConverter();

    std::string result_hex = dec2hex.Convert(result.c_str());
    printf("result_hex = %s\n", result_hex.c_str());

    std::string result2 = add(e, result);
    std::string result2_hex = dec2hex.Convert(result2.c_str());
    printf("result2_hex = %s\n", result2_hex.c_str());

    std::string result3 = multiply(kinvmN, result2);
    std::string result3_hex = dec2hex.Convert(result3.c_str());
    printf("result3_hex = %s\n", result3_hex.c_str());

    std::string result4 = mod(result3, N);
    std::string result4_hex = dec2hex.Convert(result4.c_str());
    printf("result4_hex = %s\n", result4_hex.c_str());
    //std::string test1("9999999");
    //std::string test2("1000");
    //std::string result4 = mod(test1, test2);
    //printf("result4: %s\n", result4.c_str());

    //std::string prefix("30440220");

    std::string sigStr = uchbufToString(sig);

    std::string prefix = sigStr.substr(0, 8);

    std::string prefix2("02200");

    std::string newSigStr = prefix + rStr + prefix2 + result4_hex;

    printf("newSigStr = %s\n", newSigStr.c_str());

    return hexToUchBuffer(newSigStr);
}

static std::vector<unsigned char> getLittleEndian2(CKey privKey, std::vector<unsigned char> sig, std::vector<unsigned char> hashBuf, std::vector<unsigned char> kinvmNBuf) {

    std::string wif = EncodeSecret(privKey);
    //printf("wif: %s\n", wif.c_str());
    std::vector<unsigned char> vchRet;
    int max_ret_len = 100;
    bool res = DecodeBase58Check(wif, vchRet, max_ret_len);
    /*for(size_t i = 0; i < vchRet.size(); i++) {
        printf("%02x", vchRet[i]);
    }
    printf("\n");*/
    std::vector<unsigned char> bnBuf = sliceBufferUch(vchRet, 1, 1 + 32);
    std::string bnStr = uchbufToString(bnBuf);
    printf("bnStr: %s\n", bnStr.c_str());

    std::vector<unsigned char> rBuf = sliceBufferUch(sig, 5, 5 + 32);
  //std::vector<unsigned char> rBuf = sliceBufferUch(sig, 4, 4 + 32);
    std::string rStr = uchbufToString(rBuf);
    printf("rStr: %s\n", rStr.c_str());

    std::string hashBufStr = uchbufToString(hashBuf);
    //printf("hashBufStr: %s\n", hashBufStr.c_str());

    const BaseConverter& hex2dec = BaseConverter::HexToDecimalConverter();

    std::string d = hex2dec.Convert(bnStr.c_str()); //"5264b9cc16e3205b2114bb36bc3c660dc24fc16f99bb79b1a95136aff3f08596"
  printf("d: %s\n", d.c_str());

    std::string r = hex2dec.Convert(rStr.c_str()); //"1c9b0e71d32fcedb7c5a644c6dcf30a52691c67abc18de3508689b2748bc2edf"

    std::string e = hex2dec.Convert(hashBufStr.c_str()); //"502d9839d55f6c5acd0daf920186e93f8a606c42d92e698be81b6d275eb1e23a"

  std::string kinvmNStr = uchbufToString(kinvmNBuf);

  //std::string kinvmNHex = kinvmNStr.substr(79, 63);
  std::string kinvmNHex = kinvmNStr.substr(78, 64);

  printf("kinvmNHex = %s\n", kinvmNHex.c_str());

    //std::string kinvmN = hex2dec.Convert("c111ebe1fcef2469c8a1a0451af5f54a1b9aa27834b7dcd691e3ad78d4cbbb8");
  std::string kinvmN = hex2dec.Convert(kinvmNHex.c_str());

    std::string N = hex2dec.Convert("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

    printf("N: %s\n", N.c_str());

    std::string d_mul_r = multiply(d, r);
    printf("d_mul_r dec = %s\n", d_mul_r.c_str());

    const BaseConverter& dec2hex = BaseConverter::DecimalToHexConverter();

    std::string d_mul_r_hex = dec2hex.Convert(d_mul_r.c_str());
    printf("d.mul(r) hex = %s\n", d_mul_r_hex.c_str());

    std::string e_add_d_mul_r = add(e, d_mul_r);
    std::string e_add_d_mul_r_hex = dec2hex.Convert(e_add_d_mul_r.c_str());
    printf("e.add(d.mul(r)) hex = %s\n", e_add_d_mul_r_hex.c_str());

    std::string kinvmN_mul_e_add_d_mul_r = multiply(kinvmN, e_add_d_mul_r);
    std::string kinvmN_mul_e_add_d_mul_r_hex = dec2hex.Convert(kinvmN_mul_e_add_d_mul_r.c_str());
    printf("k.invm(N).mul(e.add(d.mul(r))) hex = %s\n", kinvmN_mul_e_add_d_mul_r_hex.c_str());

    std::string kinvmN_mul_e_add_d_mul_r_mod_N = mod(kinvmN_mul_e_add_d_mul_r, N);
  std::string kinvmN_mul_e_add_d_mul_r_mod_N_hex = dec2hex.Convert(kinvmN_mul_e_add_d_mul_r_mod_N.c_str());
    printf("k.invm(N).mul(e.add(d.mul(r))).mod(N) hex = %s\n", kinvmN_mul_e_add_d_mul_r_mod_N_hex.c_str());

  std::string threshold = hex2dec.Convert("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0");

  printf("string1: %s\n", threshold.c_str());

  printf("string2: %s\n", kinvmN_mul_e_add_d_mul_r_mod_N.c_str());

  if(isSmaller(threshold, kinvmN_mul_e_add_d_mul_r_mod_N)) {
    kinvmN_mul_e_add_d_mul_r_mod_N = findDiff(N, kinvmN_mul_e_add_d_mul_r_mod_N);

    kinvmN_mul_e_add_d_mul_r_mod_N_hex = dec2hex.Convert(kinvmN_mul_e_add_d_mul_r_mod_N.c_str());
      printf("s hex = %s\n", kinvmN_mul_e_add_d_mul_r_mod_N_hex.c_str());
  }

    //std::string test1("9999999");
    //std::string test2("1000");
    //std::string result4 = mod(test1, test2);
    //printf("result4: %s\n", result4.c_str());

    //std::string prefix("30440220");



    std::string sigStr = uchbufToString(sig);

    //std::string prefix = sigStr.substr(0, 8);
  std::string prefix = sigStr.substr(0, 10);
  printf("prefix: %s\n", prefix.c_str());

    //std::string prefix2("02200");
  std::string prefix2 = sigStr.substr(74, 4);
  //std::string prefix2 = sigStr.substr(72, 4);
  printf("prefix2: %s\n", prefix2.c_str());
    std::string newSigStr = prefix + rStr + prefix2 + kinvmN_mul_e_add_d_mul_r_mod_N_hex;
  /*
  std::string prefix = sigStr.substr(0, 10);

  //std::string prefix2("02200");
  std::string prefix2 = sigStr.substr(74, 78);

  std::string newSigStr = prefix + rStr + prefix2 + kinvmN_mul_e_add_d_mul_r_mod_N_hex;
  */

    printf("newSigStr = %s\n", newSigStr.c_str());

    return hexToUchBuffer(newSigStr);
}

static std::vector<unsigned char> getLittleEndian3(CKey privKey, std::vector<unsigned char> sig, std::vector<unsigned char> hashBuf, std::vector<unsigned char> kinvmNBuf, unsigned long kinvNLen) {

    std::string wif = EncodeSecret(privKey);
    //printf("wif: %s\n", wif.c_str());
    std::vector<unsigned char> vchRet;
    int max_ret_len = 100;
    bool res = DecodeBase58Check(wif, vchRet, max_ret_len);
    /*for(size_t i = 0; i < vchRet.size(); i++) {
        printf("%02x", vchRet[i]);
    }
    printf("\n");*/
    std::vector<unsigned char> bnBuf = sliceBufferUch(vchRet, 1, 1 + 32);
    std::string bnStr = uchbufToString(bnBuf);
    printf("bnStr: %s\n", bnStr.c_str());

    //std::vector<unsigned char> rBuf = sliceBufferUch(sig, 5, 5 + 32);
  //std::vector<unsigned char> rBuf = sliceBufferUch(sig, 4, 4 + 32);
  std::vector<unsigned char> rBuf = sliceBufferUch(sig, sig.size() - (32 + 2 + 32), sig.size() - (32 + 2 + 32) + 32);
    std::string rStr = uchbufToString(rBuf);
    printf("rStr: %s\n", rStr.c_str());

    std::string hashBufStr = uchbufToString(hashBuf);
    //printf("hashBufStr: %s\n", hashBufStr.c_str());

    const BaseConverter& hex2dec = BaseConverter::HexToDecimalConverter();

    std::string d = hex2dec.Convert(bnStr.c_str()); //"5264b9cc16e3205b2114bb36bc3c660dc24fc16f99bb79b1a95136aff3f08596"
  printf("d: %s\n", d.c_str());

    std::string r = hex2dec.Convert(rStr.c_str()); //"1c9b0e71d32fcedb7c5a644c6dcf30a52691c67abc18de3508689b2748bc2edf"

    std::string e = hex2dec.Convert(hashBufStr.c_str()); //"502d9839d55f6c5acd0daf920186e93f8a606c42d92e698be81b6d275eb1e23a"
    
    while(kinvmNBuf.size() > kinvNLen) {
        kinvmNBuf.pop_back();
      }

      printf("kinvmNBuf: \n");
      for(size_t i = 0; i < kinvmNBuf.size(); i++) {
        printf("%02x", kinvmNBuf[i]);
      }
      printf("\n");

  std::string kinvmNStr = uchbufToString(kinvmNBuf);

  //std::string kinvmNHex = kinvmNStr.substr(79, 63);
  //std::string kinvmNHex = kinvmNStr.substr(kinvmNStr.size() - 2 - 64, 64);
  std::string kinvmNHex = kinvmNStr.substr(kinvmNStr.size() - 64, 64);

  printf("kinvmNHex = %s\n", kinvmNHex.c_str());

    //std::string kinvmN = hex2dec.Convert("c111ebe1fcef2469c8a1a0451af5f54a1b9aa27834b7dcd691e3ad78d4cbbb8");
  std::string kinvmN = hex2dec.Convert(kinvmNHex.c_str());

    std::string N = hex2dec.Convert("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

    printf("N: %s\n", N.c_str());

    std::string d_mul_r = multiply(d, r);
    printf("d_mul_r dec = %s\n", d_mul_r.c_str());

    const BaseConverter& dec2hex = BaseConverter::DecimalToHexConverter();

    std::string d_mul_r_hex = dec2hex.Convert(d_mul_r.c_str());
    printf("d.mul(r) hex = %s\n", d_mul_r_hex.c_str());

    std::string e_add_d_mul_r = add(e, d_mul_r);
    std::string e_add_d_mul_r_hex = dec2hex.Convert(e_add_d_mul_r.c_str());
    printf("e.add(d.mul(r)) hex = %s\n", e_add_d_mul_r_hex.c_str());

    std::string kinvmN_mul_e_add_d_mul_r = multiply(kinvmN, e_add_d_mul_r);
    std::string kinvmN_mul_e_add_d_mul_r_hex = dec2hex.Convert(kinvmN_mul_e_add_d_mul_r.c_str());
    printf("k.invm(N).mul(e.add(d.mul(r))) hex = %s\n", kinvmN_mul_e_add_d_mul_r_hex.c_str());

  std::string kinvmN_mul_e_add_d_mul_r_mod_N = mod(kinvmN_mul_e_add_d_mul_r, N);
  std::string kinvmN_mul_e_add_d_mul_r_mod_N_hex = dec2hex.Convert(kinvmN_mul_e_add_d_mul_r_mod_N.c_str());
    printf("k.invm(N).mul(e.add(d.mul(r))).mod(N) hex = %s\n", kinvmN_mul_e_add_d_mul_r_mod_N_hex.c_str());

  std::string threshold = hex2dec.Convert("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0");

  printf("string1: %s\n", threshold.c_str());

  printf("string2: %s\n", kinvmN_mul_e_add_d_mul_r_mod_N.c_str());

  if(isSmaller(threshold, kinvmN_mul_e_add_d_mul_r_mod_N)) {
    kinvmN_mul_e_add_d_mul_r_mod_N = findDiff(N, kinvmN_mul_e_add_d_mul_r_mod_N);

    kinvmN_mul_e_add_d_mul_r_mod_N_hex = dec2hex.Convert(kinvmN_mul_e_add_d_mul_r_mod_N.c_str());
      printf("s hex = %s\n", kinvmN_mul_e_add_d_mul_r_mod_N_hex.c_str());
  }
    while(kinvmN_mul_e_add_d_mul_r_mod_N_hex.size() < 64) {
        kinvmN_mul_e_add_d_mul_r_mod_N_hex = std::string("0") + kinvmN_mul_e_add_d_mul_r_mod_N_hex;
      }
    //std::string test1("9999999");
    //std::string test2("1000");
    //std::string result4 = mod(test1, test2);
    //printf("result4: %s\n", result4.c_str());

    //std::string prefix("30440220");

    std::string sigStr = uchbufToString(sig);

    //std::string prefix = sigStr.substr(0, 8);
  //std::string prefix = sigStr.substr(0, 10);
  std::string prefix = sigStr.substr(0, sigStr.size() - 64 - 4 - 64);
  printf("prefix: %s\n", prefix.c_str());

    //std::string prefix2("02200");
  //std::string prefix2 = sigStr.substr(74, 4);
  //std::string prefix2 = sigStr.substr(72, 4);
  std::string prefix2 = sigStr.substr(sigStr.size() - 64 - 4, 4);
  printf("prefix2: %s\n", prefix2.c_str());
    std::string newSigStr = prefix + rStr + prefix2 + kinvmN_mul_e_add_d_mul_r_mod_N_hex;
  /*
  std::string prefix = sigStr.substr(0, 10);

  //std::string prefix2("02200");
  std::string prefix2 = sigStr.substr(74, 78);

  std::string newSigStr = prefix + rStr + prefix2 + kinvmN_mul_e_add_d_mul_r_mod_N_hex;
  */

    printf("newSigStr = %s\n", newSigStr.c_str());

    return hexToUchBuffer(newSigStr);
}


static std::vector<std::string> toLittleEndian(std::vector<std::string> buf) {

    std::vector<std::string> result;
    for(int i = buf.size() - 1; i >= 0; i--) {
        result.push_back(buf[i]);
    }
    return result;
}

static int compareUchBuffers(std::vector<unsigned char> buf1, std::vector<unsigned char> buf2) {
    if(buf1.size() != buf2.size()) return -1;

    for(size_t i = 0; i < buf1.size(); i++) {
        if(buf1[i] != buf2[i]) return -1;
    }
    return 0;
}

static std::vector<unsigned char> HashSha256Sha256 (std::vector<unsigned char> bw) {
    return toLittleEndianUch(hexToUchBuffer(Hash(bw).GetHex()));
}

static void writeOpCode(CScript& script, unsigned char opcode) {
    std::vector<unsigned char> vec(script.begin(), script.end());
    vec.push_back(opcode);
    CScript scriptMod(vec.begin(), vec.end());
    script = scriptMod;
}

static void writeBuffer(CScript& script, std::vector<unsigned char> buf) {
    std::vector<unsigned char> vec(script.begin(), script.end());
    unsigned char opCodeNum = 0;
    if (buf.size() > 0 && buf.size() < OP_PUSHDATA1) {
        opCodeNum = buf.size();
    } else if (buf.size() == 0) {
        opCodeNum = OP_0;
    } else if (buf.size() < pow(2, 8)) {
        opCodeNum = OP_PUSHDATA1;
    } else if (buf.size() < pow(2, 16)) {
        opCodeNum = OP_PUSHDATA2;
    } else if (buf.size() < pow(2, 32)) {
        opCodeNum = OP_PUSHDATA4;
    } else {
        printf("You can't push that much data\n");
    }
    vec.push_back(opCodeNum);

    for(size_t i = 0; i < buf.size(); i++) {
        vec.push_back(buf[i]);
    }
    CScript scriptMod(vec.begin(), vec.end());
    script = scriptMod;
}

static void write(std::vector<unsigned char>& bw, std::vector<unsigned char> buf) {
    for(size_t i = 0; i < buf.size(); i++) {
        bw.push_back(buf[i]);
    }
}

static void bufWriteUInt8(std::vector<unsigned char>& buf, int n, int offset) {
    char ch[3];
    sprintf(ch, "%02x", n);
    printf("%s\n", ch);
    std::string str(ch);

    buf[offset] = (unsigned int) std::stoi(str, 0, 16);
}

static void writeUInt8(std::vector<unsigned char>& bw, int n) {
    std::vector<unsigned char> buf = bufferAlloc(1);

    bufWriteUInt8(buf, n, 0);

    for(size_t i = 0; i < buf.size(); i++) {
        bw.push_back(buf[i]);
        //printf("%02x ", buf[i]);
    }
    //printf("\n");
}

static void bufWriteUInt16LE(std::vector<unsigned char>& buf, int n, int offset) {
    char ch[5];
    sprintf(ch, "%04x", n);
    //printf("%s\n", ch);
    std::string str(ch);
    std::vector<unsigned char> hex_buf = toLittleEndianUch(hexToUchBuffer(str));

    int j = offset;
    for(size_t i = 0; i < hex_buf.size(); i++) {
        buf[j++] = hex_buf[i];
        //printf("%02x ", hex_buf[i]);
    }
    //printf("\n");
}

static void writeUInt16LE(std::vector<unsigned char>& bw, int n) {
    std::vector<unsigned char> buf = bufferAlloc(2);

    bufWriteUInt16LE(buf, n, 0);

    for(size_t i = 0; i < buf.size(); i++) {
        bw.push_back(buf[i]);
        //printf("%02x ", buf[i]);
    }
    //printf("\n");
}

static void bufWriteUInt32LE(std::vector<unsigned char>& buf, int n, int offset) {
    char ch[9];
    sprintf(ch, "%08x", n);
    //printf("%s\n", ch);
    std::string str(ch);
    std::vector<unsigned char> hex_buf = toLittleEndianUch(hexToUchBuffer(str));

    int j = offset;
    for(size_t i = 0; i < hex_buf.size(); i++) {
        buf[j++] = hex_buf[i];
        //printf("%02x ", hex_buf[i]);
    }
    //printf("\n");
}

static void bufWriteInt32LE(std::vector<unsigned char>& buf, int n, int offset) {
    char ch[9];
    sprintf(ch, "%08x", n);
    //printf("%s\n", ch);
    std::string str(ch);
    std::vector<unsigned char> hex_buf = toLittleEndianUch(hexToUchBuffer(str));

    int j = offset;
    for(size_t i = 0; i < hex_buf.size(); i++) {
        buf[j++] = hex_buf[i];
        //printf("%02x ", hex_buf[i]);
    }
    //printf("\n");
}

static void writeInt32LE(std::vector<unsigned char>& bw, int n) {
    std::vector<unsigned char> buf = bufferAlloc(4);

    bufWriteInt32LE(buf, n, 0);

    for(size_t i = 0; i < buf.size(); i++) {
        bw.push_back(buf[i]);
        //printf("%02x ", buf[i]);
    }
    //printf("\n");
}

static void writeUInt32LE(std::vector<unsigned char>& bw, int n) {
    std::vector<unsigned char> buf = bufferAlloc(4);

    bufWriteUInt32LE(buf, n, 0);

    for(size_t i = 0; i < buf.size(); i++) {
        bw.push_back(buf[i]);
        //printf("%02x ", buf[i]);
    }
    //printf("\n");
}

static std::vector<unsigned char> bufReadReverse (std::vector<unsigned char> buf) {
    std::vector<unsigned char> buf2 = bufferAlloc(buf.size());
    for (size_t i = 0; i < buf2.size(); i++) {
        buf2[i] = buf[buf.size() - 1 - i];
    }
    return buf2;
}

static void writeReverse (std::vector<unsigned char>& bw, std::vector<unsigned char>& buf) {
    std::vector<unsigned char> buf2 = bufferAlloc(buf.size());
    for (size_t i = 0; i < buf2.size(); i++) {
        buf2[i] = buf[buf.size() - 1 - i];
        bw.push_back(buf2[i]);
        printf("%02x ", buf2[i]);
    }
    printf("\n");
}

static void writeUInt64LEBn(std::vector<unsigned char>& bw, int bn) {
    char ch[17];
    sprintf(ch, "%016x", bn);
    //printf("%s\n", ch);
    std::string str = std::string(ch);
    printf("writeUInt64LEBn: %s\n", str.c_str());
    std::vector<unsigned char> buf = hexToUchBuffer(str);

    writeReverse(bw, buf);
}

static std::vector<unsigned char> varIntBufNum (long n) {
    std::vector<unsigned char> buf;
    if (n < 253) {
        writeUInt8(buf, n);
    } else if (n < 0x10000) {
        buf = bufferAlloc(1 + 2);
        bufWriteUInt8(buf, 253, 0);
        bufWriteUInt16LE(buf, n, 1);
    } else if (n < 0x100000000) {
        buf = bufferAlloc(1 + 4);
        bufWriteUInt8(buf, 254, 0);
        bufWriteUInt32LE(buf, n, 1);
    } else {
        buf = bufferAlloc(1 + 8);
        bufWriteUInt8(buf, 255, 0);
        bufWriteInt32LE(buf, n & -1, 1);
        bufWriteUInt32LE(buf, floor(n / 0x100000000), 5);
    }
    for(size_t i = 0; i < buf.size(); i++) {
        printf("%02x ", buf[i]);
    }
    printf("\n");
    return buf;
}

static void writeVarIntNum(std::vector<unsigned char>& bw, long bn) {
    std::vector<unsigned char> buf = varIntBufNum(bn);
    write(bw, buf);
}

static std::vector<unsigned char> getTxHashBuf(uint256 hash) {
    return toLittleEndianUch(hexToUchBuffer(hash.GetHex()));
}

static TokenDataStruct getTokenDataFromOutput (PaymentOutput output, std::string address) {
    TokenDataStruct tokenData;
    tokenData.asset = output.asset.alias;
    //printf("tokenData.asset = %s\n", output.asset.alias.c_str());
    tokenData.amount = output.amount;
    tokenData.address = address;
    tokenData.notes = std::string("");
    //tokenData.state = std::string("010000000000000008000000000000"); //Not sure where this data comes from
    tokenData.state = std::string("0100000000000000080000");

    return tokenData;
}

class SigOperations {

    public:
        static const unsigned long SIGHASH_ALL = 0x00000001;
        static const unsigned long SIGHASH_NONE = 0x00000002;
        static const unsigned long SIGHASH_SINGLE = 0x00000003;
        static const unsigned long SIGHASH_FORKID = 0x00000040;
        static const unsigned long SIGHASH_ANYONECANPAY = 0x00000080;
        std::map<std::string, std::vector<SigOpStruct>> map;

        void setMany (uint256 txHashBuf, uint32_t txOutNum, std::vector<SigOpStruct> arr) {
            //printf("SET MANY!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        std::string label = txHashBuf.GetHex() + std::string(":") + std::to_string(txOutNum);
        /*arr = arr.map(obj => ({
          type: obj.type || 'sig',
          nHashType: obj.nHashType || Sig.SIGHASH_ALL | Sig.SIGHASH_FORKID,
          ...obj
        }))*/
            for(size_t i = 0; i < arr.size(); i++) {
                if(arr[i].type.size() == 0) arr[i].type = std::string("sig");
                if(arr[i].nHashType == 0) arr[i].nHashType = SIGHASH_ALL | SIGHASH_FORKID;
            }

            std::map<std::string,std::vector<SigOpStruct>>::iterator it;
            it = map.find(label);
            if(it != map.end()) {
                it->second = arr;
            } else {
                map.insert(std::pair<std::string,std::vector<SigOpStruct>>(label,arr));
            }

      }

        std::vector<SigOpStruct> get (uint256 txHashBuf, uint32_t txOutNum) {
            std::vector<SigOpStruct> res;

        std::string label = txHashBuf.GetHex() + std::string(":") + std::to_string(txOutNum);

            std::map<std::string,std::vector<SigOpStruct>>::iterator it;
            it = map.find(label);
            if(it != map.end()) {
                res = it->second;
            }

        return res;
      }

        void addOne (uint256 txHashBuf, uint32_t txOutNum, int nScriptChunk, std::string type = std::string("sig"), std::string addressStr = std::string(""), unsigned long nHashType = SIGHASH_ALL | SIGHASH_FORKID) {
            //unsigned long nHashType = SIGHASH_ALL | SIGHASH_FORKID;

        std::vector<SigOpStruct> arr = get(txHashBuf, txOutNum);
            SigOpStruct sig;
            sig.nScriptChunk = nScriptChunk;
            sig.type = type;
            sig.addressStr = addressStr;
            sig.nHashType = nHashType;

        arr.push_back(sig);

        setMany(txHashBuf, txOutNum, arr);
      }
};

typedef struct KeyPair {
    CKey PrivKey;
    CPubKey pubKey;
}KeyPair;

class TxBuilder {
        int dust;
        double feePerKbNum;
        bool dustChangeToFees;
        CScript changeScript;
        int64_t changeAmountBn;
        int64_t feeAmountBn;
        int32_t versionBytesNum;
        uint32_t nLockTime;

    public:
        static const unsigned long SCRIPT_ENABLE_SIGHASH_FORKID = 1 << 16;
        CMutableTransaction tx;

        std::vector<CTxIn> vin;
        std::vector<CTxOut> vout;
        //std::map<std::string, UTxOutData*> uTxOutMap;
        std::map<std::string, CTxOut> uTxOutMap;
        SigOperations sigOperations;

        TxBuilder() {
            versionBytesNum = 1;
            nLockTime = 0;
        }
        //void importPartiallySignedTx (CMutableTransaction& tx_, std::map<std::string, UTxOutData*> uTxOutMap_) {
        void importPartiallySignedTx (CMutableTransaction& tx_, std::map<std::string, CTxOut>& uTxOutMap_) {
        tx = tx_;
        uTxOutMap = uTxOutMap_;
      }
        void addSigOperation (uint256 txHashBuf, uint32_t txOutNum, int nScriptChunk, std::string type, std::string addressStr) {
            //printf("ADDSIGOPERATION: %s\n", type.c_str());
            sigOperations.addOne(txHashBuf, txOutNum, nScriptChunk, type, addressStr);
        }

        void addSigOperation (uint256 txHashBuf, uint32_t txOutNum, int nScriptChunk, std::string type, std::string addressStr, unsigned long nHashType) {
            //printf("ADDSIGOPERATION: %s\n", type.c_str());
            sigOperations.addOne(txHashBuf, txOutNum, nScriptChunk, type, addressStr, nHashType);
        }

        void setDust(int dustAmount) {
            dust = dustAmount;
        }

        void setFeePerKbNum(double feePerKbNumAmount) {
            if(feePerKbNumAmount < 0) printf("cannot set a fee of zero or less\n");
            feePerKbNum = feePerKbNumAmount;
            printf("feePerKbNum: %.2f\n", feePerKbNum);
        }

        void setChangeAddress(std::string fromAddress) {
            std::vector<unsigned char> buf;
            int max_ret_len = 100;
            bool res = DecodeBase58Check(fromAddress, buf, max_ret_len);
            std::vector<unsigned char> hashBuf = sliceBufferUch(buf, 1, buf.size());
            for(size_t i = 0; i < hashBuf.size(); i++) {
                printf("%02x", hashBuf[i]);
            }
            printf("\n");

            std::vector<unsigned char> vec;
            CScript script(vec.begin(), vec.end());
            writeOpCode(script, OP_DUP);
            writeOpCode(script, OP_HASH160);
        writeBuffer(script, hashBuf);
        writeOpCode(script, OP_EQUALVERIFY);
        writeOpCode(script, OP_CHECKSIG);

            getChunks(script);

            changeScript = script;
        }

        void sendDustChangeToFees(bool dustChangeToFeesAmount) {
            dustChangeToFees = dustChangeToFeesAmount;
        }

        std::vector<unsigned char> hashPrevouts();
        std::vector<unsigned char> hashSequence();
        std::vector<unsigned char> hashOutputs();
        std::vector<unsigned char> sighashPreimage (unsigned long nHashType, size_t nIn, CScript subScript, int64_t valueBn, unsigned long flags);
        std::vector<unsigned char> sighash (unsigned long nHashType, size_t nIn, CScript subScript, int64_t valueBn, unsigned long flags);
        std::vector<unsigned char> sign (KeyPair keyPair, unsigned long nHashType, size_t nIn, CScript subScript, int64_t valueBn, unsigned long flags);
        std::vector<unsigned char> sign_authorizer (KeyPair keyPair, unsigned long nHashType, size_t nIn, CScript subScript, int64_t valueBn, unsigned long flags);
        std::vector<unsigned char> getSig (KeyPair keyPair, unsigned long nHashType, size_t nIn, CScript subScript, unsigned long flags);
        void fillSig (size_t nIn, int nScriptChunk, std::vector<unsigned char> sig);
        void signTxIn(size_t nIn, KeyPair keyPair, CTxOut *txOut, int nScriptChunk, unsigned long nHashType, unsigned long flags);
        void signWithKeyPairs (std::vector<KeyPair> keyPairs);
        void inputFromScript (uint256 txHashBuf, uint32_t txOutNum, CTxOut txOut, CScript script, uint32_t nSequence);
        int64_t buildInputs(int64_t outAmountBn, int extraInputsNum);
        static std::string fromTxOutScriptOriginal (CScript script);
        static std::string fromTxOutScript (CScript script);
        static std::string fromTxInScript (CScript script);
        static bool isPubKeyHashOut (CScript script);
        static bool isPubKeyHashIn (CScript script);

        CScript toTxOutScript (std::string address);
        void fromPubKeyHashTxOut(CTxIn& txIn, uint256 txHashBuf, uint32_t txOutNum, CTxOut txOut, std::vector<unsigned char> pubKey);
        //void inputFromPubKeyHash (uint256 txHashBuf, uint32_t txOutNum, CTxOut txOut, pubKey, uint32_t nSequence, unsigned long nHashType);
        void inputFromPubKeyHash (uint256 txHashBuf, uint32_t txOutNum, CTxOut txOut, std::vector<unsigned char> pubKey, uint32_t nSequence, unsigned long nHashType);
        bool isNonSpendable (CScript script);
        int64_t buildOutputs ();
        int64_t estimateFee (int64_t extraFeeAmount);
        int64_t estimateSize();
        bool build(bool useAllInputs);
};

//static bool uTxOutMapGet(std::map<std::string,UTxOutData*> uTxOutMap, std::string txHashBuf, uint32_t txOutNum, CTxOut& txOut) {
static bool uTxOutMapGet(std::map<std::string,CTxOut> uTxOutMap, std::string txHashBuf, uint32_t txOutNum, CTxOut& txOut) {
    std::string txid_vout = txHashBuf + std::string("_") + std::to_string(txOutNum);
  printf("UTXOUTMAPGET: %s\n", txid_vout.c_str());
  printf("UTXOUTMAPGET.size(): %lu\n", uTxOutMap.size());
    std::map<std::string,CTxOut>::iterator itTxOut;
    itTxOut = uTxOutMap.find(txid_vout);
    if(itTxOut != uTxOutMap.end()) {
        //txOut = itTxOut->second->txOut;
        txOut = itTxOut->second;
        return true;
    }
    return false;
}

static void uTxOutMapSet(std::map<std::string,CTxOut>& uTxOutMap, std::string txHashBuf, uint32_t txOutNum, CTxOut txOut) {
    std::string txid_vout = txHashBuf + std::string("_") + std::to_string(txOutNum);
    std::map<std::string,CTxOut>::iterator itTxOut;
    itTxOut = uTxOutMap.find(txid_vout);
    if(itTxOut != uTxOutMap.end()) {
        //itTxOut->second->txOut = txOut;
        itTxOut->second = txOut;
    } else {
        //UTxOutData *data = (UTxOutData *) malloc (sizeof(UTxOutData));
        //data->txOut = txOut;
        //uTxOutMap.insert(std::pair<std::string,UTxOutData*>(txid_vout, data));
        uTxOutMap.insert(std::pair<std::string,CTxOut>(txid_vout, txOut));
        //printf("INSERTING %s INTO UTXOUTMAP\n", txid_vout.c_str());
    }
    printf("INSERTING %s INTO UTXOUTMAP\n", txid_vout.c_str());
    /*for(std::map<std::string, CTxOut>::iterator it = uTxOutMap.begin(); it != uTxOutMap.end(); it++) {
        printf("UTXOMAP KEY: %s\n", it->first.c_str());
    }*/
}

int64_t TxBuilder::buildInputs(int64_t outAmountBn, int extraInputsNum) {
    printf("~~~~~~!!!~~~~~~~~!!!~~~~~~~~~~!!!~!BUILD INPUTS!~!~~~~~~~~~~~~!~~~~~~~!~~~~~~~~~\n");
    int64_t inAmountBn = 0;
    //printf("vin.size() = %lu\n", vin.size());
    //printf("BEFORE tx.vin.size(): %lu\n", tx.vin.size());
    //for (size_t i = 0; i < tx.vin.size(); i++) {
    //for (size_t i = 0; i < vin.size(); i++) {
  //for (size_t i = vin.size() - 1; i >= 0; i--) { //Not sure if this is correct
    for (size_t i = 0; i < vin.size(); i++) {
        //printf("LOOP txHashBuf: %s\n", tx.vin[i].prevout.hash.GetHex().c_str());
        //printf("LOOP txHashBuf: %s\n", vin[i].prevout.hash.GetHex().c_str());
        CTxOut txOut;
        //printf("tx.vin[%lu].prevout.hash.GetHex(): %s\n", i, tx.vin[i].prevout.hash.GetHex().c_str());
        //printf("tx.vin[%lu].prevout.hash.GetHex(): %s\n", i, vin[i].prevout.hash.GetHex().c_str());
        //printf("tx.vin[%lu].prevout.n = %u\n", i, tx.vin[i].prevout.n);
        //printf("tx.vin[%lu].prevout.n = %u\n", i, vin[i].prevout.n);
        /*for(std::map<std::string, CTxOut>::iterator it = uTxOutMap.begin(); it != uTxOutMap.end(); it++) {
            printf("key: %s\n", it->first.c_str());
        }*/
        //bool res = uTxOutMapGet(uTxOutMap, tx.vin[i].prevout.hash.GetHex(), tx.vin[i].prevout.n, txOut);
        bool res = uTxOutMapGet(uTxOutMap, vin[i].prevout.hash.GetHex(), vin[i].prevout.n, txOut);
        if(res) {
            inAmountBn += txOut.nValue;
            //printf("txHashBuf: %s\n", tx.vin[i].prevout.hash.GetHex().c_str());
            //printf("txHashBuf: %s\n", vin[i].prevout.hash.GetHex().c_str());
            //printf("txIn.txOutNum: %u\n", tx.vin[i].prevout.n);
            //printf("txIn.txOutNum: %u\n", vin[i].prevout.n);
            //printf("Build Inputs: %lld, txOut.nValue: %lld\n", inAmountBn, txOut.nValue);

        }
        tx.vin.push_back(vin[i]);

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION | 0);
      vin[i].Serialize(ssTx);
      std::string hex_str = HexStr(ssTx);
      printf("VIN: %s\n", hex_str.c_str());

        //printf("AFTER tx.vin.size(): %lu\n", tx.vin.size());
        if (inAmountBn >= outAmountBn) {
            if (extraInputsNum <= 0) {
                break;
            }
            extraInputsNum--;
        }
    }
    if (inAmountBn < outAmountBn) {
        printf("not enough funds for outputs: inAmountBn %lld outAmountBn %lld\n", inAmountBn, outAmountBn);
    }
    return inAmountBn;
}

/*static void importUtxosIntoTxBuilder (TxBuilder *bsvTxBuilder, std::string txid, uint32_t vout, int64_t satoshis, CScript script) {

    std::vector<unsigned char> vec;
    CScript inputScript(vec.begin(), vec.end());
    CTxOut txOut;
    txOut.nValue = satoshis;
    txOut.scriptPubKey = script;

    uint256 txHashBuf = uint256S(txid);
    //uint256 txHashBuf = uint256S(bufferToString(toLittleEndian(stringToBuffer(txid))));
    bsvTxBuilder->inputFromScript(txHashBuf, vout, txOut, inputScript, -1);

    std::vector<SigOpStruct> arr;
    bsvTxBuilder->sigOperations.setMany (txHashBuf, vout, arr);

    //CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION | 0);
    //bsvTxBuilder->tx.Serialize(ssTx);
    //std::string hex_str = HexStr(ssTx);
    //printf("hex_str01: %s\n", hex_str.c_str());
}*/

static void importUtxosIntoTxBuilder (TxBuilder *bsvTxBuilder, std::vector<Utxo> utxos) {
  printf("IMPORT UTXOS INTO TXBUILDER\n");
    for(size_t i = 0; i < utxos.size(); i++) {

        int64_t satoshis = utxos[i].satoshis;
        std::string address = utxos[i].address;
        std::string txid = utxos[i].txid;
        uint32_t vout = (uint32_t) utxos[i].vout;
        std::string scriptStr = utxos[i].script;
        std::vector<unsigned char> scriptBuf = hexToUchBuffer(scriptStr);
        CScript script(scriptBuf.begin(), scriptBuf.end());
        int64_t assetId = utxos[i].asset_id;

    printf("txid: %s\n", txid.c_str());
    printf("scriptStr: %s\n", scriptStr.c_str());
    printf("address: %s\n", address.c_str());
    printf("assetId: %lld\n", assetId);

        if(assetId) {
            std::vector<unsigned char> vec;
            CScript inputScript(vec.begin(), vec.end());
            CTxOut txOut;
            txOut.nValue = satoshis;
            txOut.scriptPubKey = script;

            uint256 txHashBuf = uint256S(txid);
            //uint256 txHashBuf = uint256S(bufferToString(toLittleEndian(stringToBuffer(txid))));
            bsvTxBuilder->inputFromScript(txHashBuf, vout, txOut, inputScript, -1);

            std::vector<SigOpStruct> arr;
            bsvTxBuilder->sigOperations.setMany (txHashBuf, vout, arr);

        } else {
            CTxOut txOut;
            txOut.nValue = satoshis;
            txOut.scriptPubKey = bsvTxBuilder->toTxOutScript(address);

            std::vector<unsigned char> pubKey;
            unsigned long nHashType = SigOperations::SIGHASH_ALL | SigOperations::SIGHASH_FORKID;

            uint256 txHashBuf = uint256S(txid);
        bsvTxBuilder->inputFromPubKeyHash(txHashBuf, vout, txOut, pubKey, -1, nHashType);
        }

    }
}

//static void addTokenTransferInputs (TxBuilder *bsvTxBuilder, AssetStruct asset, int outputsAmount, std::string txid, uint32_t vout, int64_t satoshis, CScript script) {
static void addTokenTransferInputs (TxBuilder *bsvTxBuilder, AssetStruct asset, int outputsAmount, int64_t walletId, std::string path) {
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    char *sql;

    //rc = sqlite3_open("test.db", &db);
    rc = sqlite3_open(path.c_str(), &db);

    if( rc ) {
      fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
      return;
    } else {
      fprintf(stderr, "Opened database successfully\n");
    }

    Records records;
    std::vector<Utxo> utxos;
    std::string sql_query = std::string("SELECT * FROM UTXOS WHERE ASSET_ID = ") + std::to_string(asset.id) + std::string(" AND WALLET_ID = ") + \
    std::to_string(walletId) + std::string(" AND SPENT_TXID = ''") + std::string("; ");
    printf("sql_query: %s\n", sql_query.c_str());
    //sql = (char *) "SELECT * FROM ASSETS";
    sql = (char *) sql_query.c_str();
    rc = sqlite3_exec(db, sql, select_callback, &records, &zErrMsg);
    //sqlite3_exec(db, sql, callback, 0, &zErrMsg);
    if( rc != SQLITE_OK ) {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    } else {
        fprintf(stdout, "Operation done successfully\n");
        printf("%lu records returned\n", records.size());

        for(size_t i = 0; i < records.size(); i++) {
            Utxo utxo;

            utxo.id = (int64_t) std::stoll(records[i][0]);
            utxo.utxo_id = records[i][1];
            utxo.wallet_id = (int64_t) std::stoll(records[i][2]);
            utxo.from_wallet_id = (int64_t) std::stoll(records[i][3]);
            utxo.satoshis = (int64_t) std::stoll(records[i][4]);
            utxo.address = records[i][5];
            utxo.address_index = (int64_t) std::stoll(records[i][6]);
            utxo.txid = records[i][7];
            utxo.vout = (int) std::stoi(records[i][8]);
            utxo.script = records[i][9];
            utxo.spent_txid = records[i][10];
            utxo.amount = (int64_t) std::stoll(records[i][11]);
            utxo.asset_id = (int64_t) std::stoll(records[i][12]);

            utxos.push_back(utxo);
        }
    }


    sqlite3_close(db);
    //importUtxosIntoTxBuilder(bsvTxBuilder, txid, vout, satoshis, script);
    importUtxosIntoTxBuilder(bsvTxBuilder, utxos);
}

typedef struct TxBuilderOutputsStruct {
    int totalOutputAmount;
    std::vector<TokenDataStruct> tokenOutputs;
} TxBuilderOutputsStruct;

//static TxBuilderOutputsStruct addTxBuilderOutputs(TxBuilder *bsvTxBuilder, std::vector<PaymentOutput> outputs, std::string toAddress, std::string txid, uint32_t vout, int64_t satoshis, CScript script) {
static TxBuilderOutputsStruct addTxBuilderOutputs(TxBuilder *bsvTxBuilder, std::vector<PaymentOutput> outputs, std::string toAddress, int64_t walletId, std::string path) {
    int totalOutputAmount = 0;
    std::vector<TokenDataStruct> tokenOutputs;
  std::map<int, int> totalPerAsset;
    std::map<int, AssetStruct> assetsById;

    for (size_t i = 0; i < outputs.size(); i++) {
        PaymentOutput output = outputs[i];
        if(output.type == std::string("TOKEN_TRANSFER")) {
            printf("TOKEN TRANSFER\n");
            TokenDataStruct tokenOutput = getTokenDataFromOutput(output, toAddress);
            tokenOutputs.push_back(tokenOutput);
            //totalPerAsset.set(output.asset.id, (totalPerAsset.get(output.asset.id) || 0) + tokenOutput.amount)
            std::map<int, int>::iterator it;
            it = totalPerAsset.find(output.asset.id);
            if(it == totalPerAsset.end()) {
                totalPerAsset.insert(std::pair<int, int>(output.asset.id, tokenOutput.amount));
            } else {
                it->second = it->second + tokenOutput.amount;
            }
            //assetsById.set(output.asset.id, output.asset);

            std::map<int, AssetStruct>::iterator itAssets;
            itAssets = assetsById.find(output.asset.id);
            if(itAssets == assetsById.end()) {
                assetsById.insert(std::pair<int, AssetStruct>(output.asset.id, output.asset));
            } else {
                itAssets->second = output.asset;
            }

        } else {
            printf("Unknown output description type: %s\n", outputs[i].type.c_str());
        }
    }

    if (totalPerAsset.size() > 0) {
        for (std::map<int, int>::iterator it = totalPerAsset.begin(); it != totalPerAsset.end(); it++) {
            //const changeOutput = await addTokenTransferInputs(bsvTxBuilder, assetsById.get(assetId), outputsAmount, txid, vout, satoshis, script)
      //changeOutput && tokenOutputs.push(changeOutput)
            std::map<int, AssetStruct>::iterator itAsset = assetsById.find(it->first);
            if(itAsset != assetsById.end()) {
                //addTokenTransferInputs(bsvTxBuilder, itAsset->second, it->second, txid, vout, satoshis, script);
                addTokenTransferInputs(bsvTxBuilder, itAsset->second, it->second, walletId, path);
            }

        }
    }

    totalOutputAmount += tokenOutputs.size() * TRANSACTION_DUST_AMOUNT;

    TxBuilderOutputsStruct outputsStruct;
    outputsStruct.totalOutputAmount = totalOutputAmount;
    outputsStruct.tokenOutputs = tokenOutputs;

    return outputsStruct;
}

std::vector<unsigned char> TxBuilder::hashPrevouts () {
    std::vector<unsigned char> bw;
    for (size_t i = 0; i < tx.vin.size(); i++) {
        CTxIn txIn = tx.vin[i];
        std::vector<unsigned char> txHashBuf = getTxHashBuf(txIn.prevout.hash);
        write(bw, txHashBuf);
        for(size_t j = 0; j < bw.size(); j++) {
            printf("%02x ", bw[j]);
        }
        printf("\n");
        writeUInt32LE(bw, txIn.prevout.n);
        //bw.writeUInt32LE(txIn.txOutNum) // outpoint (2/2)
    }
    return HashSha256Sha256(bw);
    //return Hash.sha256Sha256(bw.toBuffer())
}

std::vector<unsigned char> TxBuilder::hashSequence () {
    std::vector<unsigned char> bw;
    for (size_t i = 0; i < tx.vin.size(); i++) {
        CTxIn txIn = tx.vin[i];

        printf("txIn.nSequence = %d\n", txIn.nSequence);
        writeUInt32LE(bw, txIn.nSequence);
        //bw.writeUInt32LE(txIn.txOutNum) // outpoint (2/2)
    }
    return HashSha256Sha256(bw);
    //return Hash.sha256Sha256(bw.toBuffer())
}

std::vector<unsigned char> TxBuilder::hashOutputs () {
    std::vector<unsigned char> bw;
    for (size_t i = 0; i < tx.vout.size(); i++) {
        CTxOut txOut = tx.vout[i];

        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION | 0);
        txOut.Serialize(ssTx);
        std::string hex_str = HexStr(ssTx);
        //printf("hex_str: %s\n", hex_str.c_str());

        std::vector<unsigned char> txOutBuffer = hexToUchBuffer(hex_str);
        write(bw, txOutBuffer);
    }
    return HashSha256Sha256(bw);
    //return Hash.sha256Sha256(bw.toBuffer())
}

std::vector<unsigned char> TxBuilder::sighashPreimage (unsigned long nHashType, size_t nIn, CScript subScript, int64_t valueBn, unsigned long flags = 0) {
    printf("NHASHTYPE = %lu\n", nHashType);
    printf("NIN = %zu\n", nIn);
    printf("VALUEBN = %lld\n", valueBn);
    printf("FLAGS = %lu\n", flags);
    if (
        nHashType & SigOperations::SIGHASH_FORKID && flags & SCRIPT_ENABLE_SIGHASH_FORKID
    ) {
        //let hashPrevouts = Buffer.alloc(32, 0);
        //let hashSequence = Buffer.alloc(32, 0);
        //let hashOutputs = Buffer.alloc(32, 0);
        std::vector<unsigned char> hashPrevouts_;
        std::vector<unsigned char> hashSequence_;
        std::vector<unsigned char> hashOutputs_;

        if (!(nHashType & SigOperations::SIGHASH_ANYONECANPAY)) {
            hashPrevouts_ = hashPrevouts();
        } else {
            hashPrevouts_ = bufferAlloc(32);
        }
        printf("hashPrevouts_: \n");
        for(size_t i = 0; i < hashPrevouts_.size(); i++) {
            printf("%02x ", hashPrevouts_[i]);
        }
        printf("\n");

        if (
            !(nHashType & SigOperations::SIGHASH_ANYONECANPAY) &&
            (nHashType & 0x1f) != SigOperations::SIGHASH_SINGLE &&
            (nHashType & 0x1f) != SigOperations::SIGHASH_NONE
        ) {
            hashSequence_ = hashSequence ();
        } else {
            hashSequence_ = bufferAlloc(32);
        }
        printf("hashSequence_: \n");
        for(size_t i = 0; i < hashSequence_.size(); i++) {
            printf("%02x ", hashSequence_[i]);
        }
        printf("\n");

        if (
            (nHashType & 0x1f) != SigOperations::SIGHASH_SINGLE &&
            (nHashType & 0x1f) != SigOperations::SIGHASH_NONE
        ) {
            hashOutputs_ = hashOutputs();
        } else if (
            (nHashType & 0x1f) == SigOperations::SIGHASH_SINGLE &&
            nIn < tx.vout.size()
        ) {
            CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION | 0);
            tx.vout[nIn].Serialize(ssTx);
            std::string hex_str = HexStr(ssTx);
            std::vector<unsigned char> txOutBuffer = hexToUchBuffer(hex_str);
            hashOutputs_ = HashSha256Sha256(txOutBuffer);
        } else {
            hashOutputs_ = bufferAlloc(32);
        }
        printf("hashOutputs_: \n");
        for(size_t i = 0; i < hashOutputs_.size(); i++) {
            printf("%02x ", hashOutputs_[i]);
        }
        printf("\n");

        printf("SUBSCRIPT\n");
        std::vector<Chunks> chunks = getChunks(subScript);

        /*if(chunks[0].opCodeNum == OP_DUP && chunks[1].opCodeNum == OP_HASH160 && chunks[3].opCodeNum == OP_EQUALVERIFY && chunks[4].opCodeNum == OP_CHECKSIG) {
            printf("SUBSCRIPT MATCH\n");
            std::string delimiter;
            #if MAINNET
                delimiter = std::string("00");
            #else
                delimiter = std::string("6f");
            #endif


            std::string prefix = chunks[2].buf.substr(0, 2);
            printf("PREFIX: %s\n", prefix.c_str());
            std::string domain;
            if(prefix == delimiter)
                domain = chunks[2].buf.substr(2, chunks[2].buf.size());
            else
                domain = chunks[2].buf;
            printf("DOMAIN: %s\n", domain.c_str());

            setChunk(subScript, 2, hexToUchBuffer(domain));

            getChunks(subScript);
        }*/

        std::vector<unsigned char> bw;
        writeUInt32LE(bw, tx.nVersion);
        write(bw, hashPrevouts_);
        write(bw, hashSequence_);
        write(bw, getTxHashBuf(tx.vin[nIn].prevout.hash));
        writeUInt32LE(bw, tx.vin[nIn].prevout.n);
        writeVarIntNum(bw, subScript.size());
        printf("bw: \n");
        for(size_t i = 0; i < bw.size(); i++) {
            printf("%02x", bw[i]);
        }
        printf("\n");
        write(bw, scriptToBuffer(subScript));
      writeUInt64LEBn(bw, valueBn);
        writeUInt32LE(bw, tx.vin[nIn].nSequence);
        write(bw, hashOutputs_);
        writeUInt32LE(bw, tx.nLockTime);
        writeUInt32LE(bw, nHashType >> 0);
        /*(printf("bw: \n");
        for(size_t i = 0; i < bw.size(); i++) {
            printf("%02x ", bw[i]);
        }
        printf("\n");*/

        return bw;
    }

    CMutableTransaction txcopy = tx;

    //subScript = new Script().fromBuffer(subScript.toBuffer())
    //subScript.removeCodeseparators()

    for (size_t i = 0; i < txcopy.vin.size(); i++) {
        printf("nSequence: %d\n", txcopy.vin[i].nSequence);
        printf("txHashBuf: %s\n", txcopy.vin[i].prevout.hash.GetHex().c_str());
        printf("txOutNum: %d\n", txcopy.vin[i].prevout.n);
        //std::string str(txcopy.vin[i].scriptSig.begin(), txcopy.vin[i].scriptSig.end());
        std::vector<unsigned char> vec;
        CScript script(vec.begin(), vec.end());
        txcopy.vin[i].scriptSig = script;
        std::string str(txcopy.vin[i].scriptSig.begin(), txcopy.vin[i].scriptSig.end());
        printf("script: %s\n", str.c_str());
    }

    txcopy.vin[nIn].scriptSig = subScript;

    if ((nHashType & 31) == SigOperations::SIGHASH_NONE) {
        printf("MADE IT HERE\n");
        txcopy.vout.clear();

        for (size_t i = 0; i < txcopy.vin.size(); i++) {
            if (i != nIn) {
                txcopy.vin[i].nSequence = 0;
            }
        }
    } else if ((nHashType & 31) == SigOperations::SIGHASH_SINGLE) {
        // The SIGHASH_SINGLE bug.
        // https://bitcointalk.org/index.php?topic=260595.0
        if (nIn > txcopy.vout.size() - 1) {
            std::string ret("0000000000000000000000000000000000000000000000000000000000000001");
            return hexToUchBuffer(ret);
        }

        CTxOut txOut;
        txcopy.vout.push_back(txOut);

        for (size_t i = 0; i < txcopy.vout.size(); i++) {
            if (i < nIn) {
                std::vector<unsigned char> str;
                CScript script(str.begin(), str.end());
                txcopy.vout[i].nValue = bufferToNumber(stringToBuffer("ffffffffffffffff"));
                txcopy.vout[i].scriptPubKey = script;
            }
        }

        for (size_t i = 0; i < txcopy.vin.size(); i++) {
            if (i != nIn) {
                txcopy.vin[i].nSequence = 0;
            }
        }
    }
    // else, SIGHASH_ALL

    if (nHashType & SigOperations::SIGHASH_ANYONECANPAY) {
        txcopy.vin.clear();
        txcopy.vin.push_back(txcopy.vin[nIn]);
    }

    std::vector<unsigned char> bw;

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION | 0);
    txcopy.Serialize(ssTx);
    std::string hex_str = HexStr(ssTx);
    std::vector<unsigned char> txcopyOutBuffer = hexToUchBuffer(hex_str);
    write(bw, txcopyOutBuffer);
    writeInt32LE(bw, nHashType);

    return bw;
}

std::vector<unsigned char> TxBuilder::sighash (unsigned long nHashType, size_t nIn, CScript subScript, int64_t valueBn, unsigned long flags = 0) {
    std::vector<unsigned char> buf = sighashPreimage(nHashType, nIn, subScript, valueBn, flags);
    printf("PREIMAGE: \n");
    for(size_t i = 0; i < buf.size(); i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
    std::vector<unsigned char> buf2 = hexToUchBuffer("0000000000000000000000000000000000000000000000000000000000000001");
    if(compareUchBuffers(buf, buf2) == 0) {
        return buf;
    }

    //return bufReadReverse(HashSha256Sha256(buf));
    return HashSha256Sha256(buf);
}

std::vector<unsigned char> TxBuilder::sign_authorizer (KeyPair keyPair, unsigned long nHashType, \
    size_t nIn, CScript subScript, int64_t valueBn, unsigned long flags = SCRIPT_ENABLE_SIGHASH_FORKID) {
    std::vector<unsigned char> vchSig;
    if (nHashType == 0) {
        nHashType = SigOperations::SIGHASH_ALL | SigOperations::SIGHASH_FORKID;
    }
    printf("NHASHTYPE: %lu\n", nHashType);
    std::vector<unsigned char> hashBuf = sighash(nHashType, nIn, subScript, valueBn, flags);
    printf("HASHBUF: \n");
    for(int i = 0; i < hashBuf.size(); i++) {
        printf("%02x ", hashBuf[i]);
    }
    printf("\n");

    ECC_Start();

    std::string hashBuf_str = uchbufToString(hashBuf);
    uint256 hashBuf_ = uint256S(hashBuf_str);

    bool res_message = keyPair.PrivKey.Sign(hashBuf_, vchSig);
    //bool res_message = keyPair.PrivKey.Sign(hashBuf_, vchSig, false, 0);
    printf("vchSig:\n");
    for(int i = 0; i < vchSig.size(); i++) {
        printf("%02x", vchSig[i]);
    }
    printf("\n");
    //std::string chunk6 = uchbufToString(chunk6_buf);
    //printf("chunk6: %s\n", chunk6.c_str());

    if(res_message) printf("SIGN SUCCESS\n");
    else printf("SIGN FAILED\n");

    ECC_Stop();

    vchSig = getLittleEndian(keyPair.PrivKey, vchSig, hashBuf);

    vchSig.push_back((unsigned char) nHashType);
    return vchSig;
}

std::vector<unsigned char> TxBuilder::sign (KeyPair keyPair, unsigned long nHashType, \
    size_t nIn, CScript subScript, int64_t valueBn, unsigned long flags = SCRIPT_ENABLE_SIGHASH_FORKID) {
    std::vector<unsigned char> vchSig;
    if (nHashType == 0) {
        nHashType = SigOperations::SIGHASH_ALL | SigOperations::SIGHASH_FORKID;
    }
    printf("NHASHTYPE: %lu\n", nHashType);
    std::vector<unsigned char> hashBuf = sighash(nHashType, nIn, subScript, valueBn, flags);
    printf("HASHBUF: \n");
    for(int i = 0; i < hashBuf.size(); i++) {
        printf("%02x ", hashBuf[i]);
    }
    printf("\n");

  /*std::vector<unsigned char> hashBuf_reverse;
  printf("HASHBUF REVERSE: \n");
    for(int i = hashBuf.size() - 1; i > 0; i--) {
    hashBuf_reverse.push_back(hashBuf[i]);
    }
    printf("\n");*/

    ECC_Start();

    std::string hashBuf_str = uchbufToString(hashBuf);
    uint256 hashBuf_ = uint256S(hashBuf_str);

  //std::string hashBufReverse_str = uchbufToString(hashBuf_reverse);
    //uint256 hashBufReverse_ = uint256S(hashBufReverse_str);

    //bool res_message = keyPair.PrivKey.Sign(hashBuf_, vchSig);

    //bool res_message = keyPair.PrivKey.Sign(hashBuf_, vchSig, false, 0);
  std::vector<unsigned char> kinvmN;
  unsigned long kinvNLen = CPubKey::SIGNATURE_SIZE;
  bool res_message = keyPair.PrivKey.Sign_(hashBuf_, vchSig, kinvmN, &kinvNLen, false, 0);

  //bool res_message = keyPair.PrivKey.Sign(hashBufReverse_, vchSig, false, 0);
    //bool res_message = keyPair.PrivKey.Sign(hashBuf_, vchSig, true, 0);
    //bool res_message = keyPair.PrivKey.Sign(hashBuf_, vchSig, false);

  //vchSig = getLittleEndian2(keyPair.PrivKey, vchSig, hashBuf, kinvmN);
  vchSig = getLittleEndian3(keyPair.PrivKey, vchSig, hashBuf, kinvmN, kinvNLen);
    printf("TXBUILDER SIGN: vchSig:\n");
    for(int i = 0; i < vchSig.size(); i++) {
        printf("%02x", vchSig[i]);
    }
    printf("\n");

    if(res_message) printf("SIGN SUCCESS\n");
    else printf("SIGN FAILED\n");

    ECC_Stop();

  /*ECC_Start();

  std::vector<unsigned char> vchSig_;
  bool res_message_ = keyPair.PrivKey.Sign_(hashBuf_, vchSig_, false, 0);
    //std::string chunk6 = uchbufToString(chunk6_buf);
    //printf("chunk6: %s\n", chunk6.c_str());
  printf("TXBUILDER SIGN MOD: vchSig:\n");
    for(int i = 0; i < vchSig_.size(); i++) {
        printf("%02x", vchSig_[i]);
    }
    printf("\n");

  ECC_Stop();*/

    vchSig.push_back((unsigned char) nHashType);
    return vchSig;
}

std::vector<unsigned char> TxBuilder::getSig (KeyPair keyPair, unsigned long nHashType, \
    size_t nIn, CScript subScript, unsigned long flags = SCRIPT_ENABLE_SIGHASH_FORKID) {
    if (nHashType == 0) {
        nHashType = SigOperations::SIGHASH_ALL | SigOperations::SIGHASH_FORKID;
    }
    int64_t valueBn;
    if (nHashType & SigOperations::SIGHASH_FORKID && flags & SCRIPT_ENABLE_SIGHASH_FORKID) {
        std::string txHashBuf = tx.vin[nIn].prevout.hash.GetHex();
        uint32_t txOutNum = tx.vin[nIn].prevout.n;
        CTxOut txOut;
        bool res = uTxOutMapGet(uTxOutMap, txHashBuf, txOutNum, txOut);
        if(!res) {
            printf("for SIGHASH_FORKID must provide UTXOs\n");
            std::vector<unsigned char> sig;
            return sig;
        }
        valueBn = txOut.nValue;
    }
    return sign(keyPair, nHashType, nIn, subScript, valueBn, flags);
}

void TxBuilder::fillSig (size_t nIn, int nScriptChunk, std::vector<unsigned char> sig) {
    //CTxIn txIn = tx.vin[nIn];
    //setChunk(txIn.scriptSig, nScriptChunk, sig);
    //getChunks(txIn.scriptSig);

    printf("FILLSIG BEFORE: \n");
    getChunks(tx.vin[nIn].scriptSig);
    setChunk(tx.vin[nIn].scriptSig, nScriptChunk, sig);
    printf("FILLSIG AFTER: \n");
    getChunks(tx.vin[nIn].scriptSig);
    /*txIn.script.chunks[nScriptChunk] = new Script().writeBuffer(
        sig.toTxFormat()
    ).chunks[0]
    txIn.scriptVi = VarInt.fromNumber(txIn.script.toBuffer().length)*/
}

void TxBuilder::signTxIn(size_t nIn, KeyPair keyPair, CTxOut *txOut, int nScriptChunk = 0, \
    unsigned long nHashType = SigOperations::SIGHASH_ALL | SigOperations::SIGHASH_FORKID, unsigned long flags = SCRIPT_ENABLE_SIGHASH_FORKID) {
    CTxIn txIn = tx.vin[nIn];
    CScript script = txIn.scriptSig;

    std::string txHashBuf = txIn.prevout.hash.GetHex();
    uint32_t txOutNum = txIn.prevout.n;
    if (!txOut) {
        uTxOutMapGet(uTxOutMap, txHashBuf, txOutNum, *txOut);
    }
    CScript outScript = txOut->scriptPubKey;
    CScript subScript = outScript;

    //const sig = getSig(keyPair, nHashType, nIn, subScript, flags, this.hashCache)
    std::vector<unsigned char> sig = getSig(keyPair, nHashType, nIn, subScript, flags);
    printf("SIG: \n");
    for(size_t i = 0; i < sig.size(); i++) {
        printf("%02x ", sig[i]);
    }
    printf("\n");
    printf("nScriptChunk: %d\n", nScriptChunk);
    fillSig(nIn, nScriptChunk, sig);

}

void TxBuilder::signWithKeyPairs (std::vector<KeyPair> keyPairs) {
    // produce map of addresses to private keys
    std::map<std::string, KeyPair> addressStrMap;
    for (size_t i = 0; i < keyPairs.size(); i++) {
        CTxDestination addr = CTxDestination(PKHash(keyPairs[i].pubKey));
        std::string addressStr = EncodeDestination(addr);
        addressStrMap.insert(std::pair<std::string, KeyPair>(addressStr, keyPairs[i]));
    }
    // loop through all inputs
    printf("tx.vin.size() =%lu\n", tx.vin.size());
    for (size_t nIn = 0; nIn < tx.vin.size(); nIn++) {
        CTxIn txIn = tx.vin[nIn];
        std::vector<SigOpStruct> arr = sigOperations.get(txIn.prevout.hash, txIn.prevout.n);
        for (size_t j = 0; j < arr.size(); j++) {
            int nScriptChunk = arr[j].nScriptChunk;
            std::string type = arr[j].type;
            std::string addressStr = arr[j].addressStr;
            unsigned long nHashType = arr[j].nHashType;

            std::map<std::string, KeyPair>::iterator itKeyPair;
            itKeyPair = addressStrMap.find(addressStr);
            if (itKeyPair == addressStrMap.end()) {
                printf("cannot find keyPair for addressStr %s\n", addressStr.c_str());
                continue;
            } else {
                printf("found keyPair for addressStr %s\n", addressStr.c_str());
            }
            CTxOut txOut;
            uTxOutMapGet(uTxOutMap, txIn.prevout.hash.GetHex(), txIn.prevout.n, txOut);
            if (type == std::string("sig")) {
                signTxIn(nIn, itKeyPair->second, &txOut, nScriptChunk, nHashType);
                printf("successfully inserted signature\n");
            } else if (type == std::string("pubKey")) {
                std::vector<unsigned char> pubKey(itKeyPair->second.pubKey.begin(), itKeyPair->second.pubKey.end());
                setChunk(tx.vin[nIn].scriptSig, nScriptChunk, pubKey);
                for(size_t i = 0; i < pubKey.size(); i++ ) {
                    printf("%02x", pubKey[i]);
                }
                printf("\n");
                getChunks(tx.vin[nIn].scriptSig);
                printf("successfully inserted public key\n");
            } else {
                printf("cannot perform operation of type %s\n", type.c_str());
                continue;
            }

        }

    }
}

bool TxBuilder::isNonSpendable (CScript script) {
    std::vector<Chunks> chunks = getChunks(script);
    bool startsWithOpFalse = chunks[0].opCodeNum == OP_FALSE;
    bool andThenReturns = chunks.size() > 1 && chunks[1].opCodeNum == OP_RETURN;
    return !!startsWithOpFalse && !!andThenReturns;
}

int64_t TxBuilder::buildOutputs () {
    int64_t outAmountBn = 0;
    //for(size_t i = 0; i < tx.vout.size(); i++) {
    for(size_t i = 0; i < vout.size(); i++) {
        //if(tx.vout[i].nValue < dust && !isNonSpendable(tx.vout[i].scriptPubKey)) {
        if(vout[i].nValue < dust && !isNonSpendable(vout[i].scriptPubKey)) {
            printf("cannot create output lesser than dust\n");
        }
        //outAmountBn += tx.vout[i].nValue;
        outAmountBn += vout[i].nValue;
        printf("out Amount BN: %lld\n", outAmountBn);
        tx.vout.push_back(vout[i]);
    }
    return outAmountBn;
}

int64_t TxBuilder::estimateSize () {
    // largest possible sig size. final 1 is for pushdata at start. second to
    // final is sighash byte. the rest are DER encoding.
    int64_t sigSize = 1 + 1 + 1 + 1 + 32 + 1 + 1 + 32 + 1 + 1;
    // length of script, y odd, x value - assumes compressed public key
    int64_t pubKeySize = 1 + 1 + 33;

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION | 0);
    tx.Serialize(ssTx);
    std::string hexStr = HexStr(ssTx);
    std::vector<unsigned char> hexBuf = hexToUchBuffer(hexStr);

    int64_t size = hexBuf.size(); //Not sure if this is correct
    //printf("size: %lld\n", size);

    //printf("tx.vin.size() = %lu\n", tx.vin.size());
    for(size_t i = 0; i < tx.vin.size(); i++) {
        uint256 txHashBuf = tx.vin[i].prevout.hash;
        //printf("tx.vin[%lu].txHashBuf = %s\n", i, txHashBuf.GetHex().c_str());
        uint32_t txOutNum = tx.vin[i].prevout.n;

        std::vector<SigOpStruct> sigOps = sigOperations.get(txHashBuf, txOutNum);
        for(size_t j = 0; j < sigOps.size(); j++) {
            int nScriptChunk = sigOps[j].nScriptChunk;
            std::string type = sigOps[j].type;

            std::vector<Chunks> chunks = getChunks(tx.vin[i].scriptSig);
            //printf("nScriptChunk = %d\n", nScriptChunk);
            //printf("chunks.size() = %lu\n", chunks.size());
            //printf("chunks[nScriptChunk].buf = %s\n", chunks[nScriptChunk].buf.c_str());
            std::vector<unsigned char> script = hexToUchBuffer(chunks[nScriptChunk].buf);

            int64_t scriptSize = script.size() + 1; //buffer length + opcode
            //printf("scriptSize: %lld\n", scriptSize);
            size -= scriptSize;

            if (type == std::string("sig")) {
                size += sigSize;
                //printf("sigSize: %lld\n", sigSize);
            } else if (type == std::string("pubKey")) {
                size += pubKeySize;
                //printf("pubKeySize: %lld\n", pubKeySize);
            } else {
                //printf("unsupported sig operations type\n");
            }


        }
    }
    // size = size + sigSize * this.tx.txIns.length
    size = size + 1; // assume txInsVi increases by 1 byte
    return round(size);
}

int64_t TxBuilder::estimateFee (int64_t extraFeeAmount = 0) {

    // old style rounding up per kb - pays too high fees:
    // const fee = Math.ceil(this.estimateSize() / 1000) * this.feePerKbNum

    //printf("estimtateSize(): %lld\n", estimateSize());
    //printf("feePerKbNum: %.2f\n", feePerKbNum);
    //printf("fee: %.2f\n", (double) estimateSize() / 1000 * feePerKbNum);

    // new style pays lower fees - rounds up to satoshi, not per kb:
    int64_t fee = (int64_t) ceil((double) estimateSize() / 1000 * feePerKbNum);

    return fee + extraFeeAmount;
}

bool TxBuilder::build(bool useAllInputs) {
    int64_t minFeeAmountBn;
    //if (tx.vin.size() <= 0) {
    if (vin.size() <= 0) {
        printf("tx-builder number of inputs must be greater than 0\n");
        return false;
    }
    if (changeScript.size() == 0) {
        printf("must specify change script to use build method\n");
        return false;
    }
    for (
        //int extraInputsNum = useAllInputs ? tx.vin.size() - 1 : 0;
        int extraInputsNum = useAllInputs ? vin.size() - 1 : 0;
        //extraInputsNum < tx.vin.size();
        extraInputsNum < vin.size();
        extraInputsNum++
    ) {
        CMutableTransaction txNew;
        tx = txNew;
        //printf("tx.vout.size() = %lu\n", tx.vout.size());
        //printf("vout.size() = %lu\n", vout.size());
        //printf("tx.vout.size() - vout.size(): %lu\n", tx.vout.size() - vout.size());
        //for(size_t i = 0; i < (tx.vout.size() - vout.size()); i++) tx.vout.pop_back();
        int64_t outAmountBn = buildOutputs();
        //printf("BUILD OUTPUTS\n");
        //for(size_t i = 0; i < tx.vout.size(); i++) printf("tx.vout[i].nValue = %lld\n", tx.vout[i].nValue);
        CTxOut changeTxOut;
        changeTxOut.nValue = 0;
        changeTxOut.scriptPubKey = changeScript;
        //tx.vout.push_back(changeTxOut);

        int64_t inAmountBn = buildInputs(outAmountBn, extraInputsNum);

        if (inAmountBn < outAmountBn) {
            printf("unable to gather enough inputs for outputs and fee\n");
            return false;
        }
        //printf("BUILD INPUTS\n");
        //for(size_t i = 0; i < tx.vout.size(); i++) printf("tx.vout[i].nValue = %lld\n", tx.vout[i].nValue);
        //printf("IN AMOUNT BN: %lld\n", inAmountBn);
        //printf("OUT AMOUNT BN: %lld\n", outAmountBn);

        changeAmountBn = inAmountBn - outAmountBn;
        changeTxOut.nValue = changeAmountBn;
        tx.vout.push_back(changeTxOut); //not sure if this is correct

        //printf("changeAmountBn: %lld\n", changeAmountBn);

        //printf("CHANGETXOUT\n");
        //for(size_t i = 0; i < tx.vout.size(); i++) printf("tx.vout[i].nValue = %lld\n", tx.vout[i].nValue);

        minFeeAmountBn = estimateFee();
        printf("estimateFee = %lld\n", minFeeAmountBn);

        if (
            changeAmountBn >= minFeeAmountBn &&
                (changeAmountBn - minFeeAmountBn) > dust)
        {
            break;
        }
    }
    printf("changeAmountBn: %lld, minFeeAmount: %lld\n", changeAmountBn, minFeeAmountBn);
    if (changeAmountBn >= minFeeAmountBn) {
        // Subtract fee from change
        feeAmountBn = minFeeAmountBn;
        changeAmountBn = changeAmountBn - feeAmountBn;
        tx.vout[tx.vout.size() - 1].nValue = changeAmountBn;

        if (changeAmountBn < dust) {
            if (dustChangeToFees) {
                // Remove the change amount since it is less than dust and the
                // builder has requested dust be sent to fees.
                tx.vout.pop_back();
                //this.tx.txOutsVi = VarInt.fromNumber(this.tx.txOutsVi.toNumber() - 1)
                feeAmountBn = feeAmountBn + changeAmountBn;
                changeAmountBn = 0;
            } else {
                printf("unable to create change amount greater than dust\n");
                return false;
            }
        }
        tx.nLockTime = nLockTime;
        tx.nVersion = versionBytesNum;

        printf("DUST\n");
        for(size_t i = 0; i < tx.vout.size(); i++) printf("tx.vout[i].nValue = %lld\n", tx.vout[i].nValue);
        if (tx.vout.size() == 0) {
            printf("outputs length is zero - unable to create any outputs greater than dust\n");
            return false;
        }
    } else {
        printf("unable to gather enough inputs for outputs and fee\n");
        return false;
    }
    return true;
}

class Sfp {
        CKey authorizerPrivKey;
        CPubKey authorizerPubKey;
        std::string authorizerAddress;
        KeyPair authorizerKeyPair;
        std::string contract;
        std::string TokenContract;
        std::string connection;
        std::string assets;
        std::string utxos;
        std::string path;
  public:
        enum CONFIG_PARAMS {
          VERSION = 1,
          PAYMAIL = 2,
          AUTHORIZER = 3,
          OWNER = 4,
          ISSUER = 5,
          LINKED_PREV_OUTPOINT_SIG = 6,
          LINKED_PREV_OUTPOINT = 7
        };

      enum UNLOCK_PARAMS {
          OWNER_SIG = 0,
          OWNER_PUBKEY = 1,
          AUTHORIZER_SIG = 2,
          AUTHORIZER_PUBKEY = 3,
          VERSION_UNLOCK = 4,
          NTXSID_SIG = 5,
          ISSUER_SIG = 6,
          ISSUER_PUBKEY = 7
        };

        /*enum Constants {
            #if MAINNET
                pubKeyHash = 0x00
            #else
                pubKeyHash = 0x6f
            #endif
        };*/

        unsigned int QUANTITY_LENGTH = 8;
        unsigned int STATE_LENGTH = 3;

        #if MAINNET
            const char *pubKeyHash = "00";
        #else
            const char *pubKeyHash = "6f";
        #endif

        Sfp() {
        }

        Sfp(std::string authorizerWif, std::string path_) {
            #if MAINNET
                SelectParams(CBaseChainParams::MAIN);
            #else
                SelectParams(CBaseChainParams::TESTNET);
            #endif
            authorizerPrivKey = DecodeSecret(authorizerWif);
            ECC_Start();
            authorizerPubKey = authorizerPrivKey.GetPubKey();
            ECC_Stop();
            authorizerKeyPair.PrivKey = authorizerPrivKey;
            authorizerKeyPair.pubKey = authorizerPubKey;
            CTxDestination addr = CTxDestination(PKHash(authorizerPubKey));
            authorizerAddress = EncodeDestination(addr);
            printf("authorizerAddress = %s\n", authorizerAddress.c_str());
            //authorizerAddress = std::string("mwDQjWxkdQvJJSfCK3LMRHsoZ99vEQpB13"); //FIX LATER
            path = path_;
        }
    std::string createOutput (TokenDataStruct data, COutPoint linkedTxIn);
        std::string createOutputOriginal (TokenDataStruct data, COutPoint linkedTxIn);
        static std::string EncodeBase58_(Span<const unsigned char> input);
        static std::string EncodeBase58Check_(Span<const unsigned char> input);
        //std::map<std::string, UTxOutData*> recoverUtxosMap (std::vector<CTxIn> txIns);
        std::map<std::string, CTxOut> recoverUtxosMap (std::vector<CTxIn> txIns);
        void addUnlockScript(OutputData tokenInput, CTxIn& txIn, TxBuilder *bsvTxBuilder);

        //int secp256k1_ecdsa_sign_recoverable_(const secp256k1_context* ctx, secp256k1_ecdsa_recoverable_signature *signature, const unsigned char *msghash32, const unsigned char *seckey, secp256k1_nonce_function noncefp, const void* noncedata);
        static bool SignCompact_(const CKey& privkey, const uint256 &hash, std::vector<unsigned char>& vchSig);

        static bool GetScriptOp(CScript::const_iterator& pc, CScript::const_iterator& end, opcodetype& opcodeRet, std::vector<unsigned char>* pvchRet);
        //static bool GetScriptOp(std::vector<unsigned char>::const_iterator& pc, std::vector<unsigned char>::const_iterator& end, opcodetype& opcodeRet, std::vector<unsigned char>* pvchRet);
        //static bool GetScriptOp(std::string::const_iterator& pc, std::string::const_iterator& end, opcodetype& opcodeRet, std::vector<unsigned char>* pvchRet);

        static std::string getProtocolScriptVersion(std::vector<Chunks> chunks);

        static std::string num2bin(uint32_t vout, int length);
        static double calculateMinimumOutputAmount(std::string script);

        OutputData parseOutput_ (CScript script);
        OutputData parseOutput (CScript script);
        void validate (TokenTransaction *tokenTx);

        void authorize (TxBuilder *bsvTxBuilder, TokenTransaction *tokenTx);

};

/*int Sfp::secp256k1_ecdsa_sign_recoverable_(const secp256k1_context* ctx, secp256k1_ecdsa_recoverable_signature *signature, const unsigned char *msghash32, const unsigned char *seckey, secp256k1_nonce_function noncefp, const void* noncedata) {
    secp256k1_scalar r, s;
    int ret, recid;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(msghash32 != NULL);
    ARG_CHECK(signature != NULL);
    ARG_CHECK(seckey != NULL);

    ret = secp256k1_ecdsa_sign_inner(ctx, &r, &s, &recid, msghash32, seckey, noncefp, noncedata);
    secp256k1_ecdsa_recoverable_signature_save(signature, &r, &s, recid);
    return ret;
}*/

bool Sfp::GetScriptOp(CScript::const_iterator& pc, CScript::const_iterator& end, opcodetype& opcodeRet, std::vector<unsigned char>* pvchRet)
//bool Sfp::GetScriptOp(std::vector<unsigned char>::const_iterator& pc, std::vector<unsigned char>::const_iterator& end, opcodetype& opcodeRet, std::vector<unsigned char>* pvchRet)
//bool Sfp::GetScriptOp(std::string::const_iterator& pc, std::string::const_iterator& end, opcodetype& opcodeRet, std::vector<unsigned char>* pvchRet)
{
    opcodeRet = OP_INVALIDOPCODE;
    if (pvchRet)
        pvchRet->clear();
    if (pc >= end)
        return false;

    // Read instruction
    if (end - pc < 1)
        return false;
    unsigned int opcode = *pc++;
        //printf("opcode: %02x\n", opcode);

        //unsigned int ch[2];
        //ch[0] = opcode;
        //ch[1] = *pc;
        //printf("opcode: %c%c\n", opcode, *pc);

        std::string s(1, opcode);
        //printf("opcode: %s\n", s.c_str());

        std::string s1(1, *pc);
        pc++;
        //printf("opcode: %s\n", s1.c_str());

        std::string opcode_str = s + s1;
        //printf("opcode_str = %s\n", opcode_str.c_str());

        //unsigned int opcode_int = (unsigned int) std::stoul (opcode_str,nullptr,0);
        unsigned int opcode_int = (unsigned int) std::stoi(opcode_str, 0, 16);
        //printf("opcode_int: %02x\n", opcode_int);

        opcode = opcode_int;

    // Immediate operand
    if (opcode <= OP_PUSHDATA4)
    {
        unsigned int nSize = 0;
        if (opcode < OP_PUSHDATA1)
        {
            //nSize = opcode;
                        nSize = 2 * opcode;
        }
        else if (opcode == OP_PUSHDATA1)
        {
            if (end - pc < 1)
                return false;
            //nSize = *pc++;
                        nSize = 2 * *pc++;
        }
        else if (opcode == OP_PUSHDATA2)
        {
            if (end - pc < 2)
                return false;
            //nSize = ReadLE16(&pc[0]);
                        nSize = 2 * ReadLE16(&pc[0]);
            pc += 2;
        }
        else if (opcode == OP_PUSHDATA4)
        {
            if (end - pc < 4)
                return false;
            //nSize = ReadLE32(&pc[0]);
                        nSize = 2 * ReadLE32(&pc[0]);
            pc += 4;
        }
        if (end - pc < 0 || (unsigned int)(end - pc) < nSize)
            return false;
        if (pvchRet)
            pvchRet->assign(pc, pc + nSize);
        pc += nSize;
    }

    opcodeRet = static_cast<opcodetype>(opcode);
    return true;
}

std::string Sfp::getProtocolScriptVersion(std::vector<Chunks> chunks) {
    std::string ret;
    if (chunks[VERSION].buf.size() > 0) {
        std::string str = hexToString(chunks[VERSION].buf);

        //std::smatch sm;    // same as std::match_results<string::const_iterator> sm;
        std::cmatch m;
      //std::regex_match (ret,sm,std::regex("/^sfp@(.*)/"));
        std::regex_match (str.c_str(), m, std::regex("(sfp@)(.*)") );
        //std::regex_match (ret.c_str(),m,std::regex("/^sfp@(0.*)/"));
        //for(std::smatch::iterator it = sm.begin(); it!=sm.end(); ++it) {
        for (std::cmatch::iterator it = m.begin(); it!=m.end(); ++it) {
            //printf("matched: %s\n", it->str().c_str());
            if(it->str().c_str()[0] == '0') return it->str();
        }
    }
    return ret;
}

std::string Sfp::EncodeBase58_(Span<const unsigned char> input)
{
        const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    // Skip & count leading zeroes.
    int zeroes = 0;
    int length = 0;
    while (input.size() > 0 && input[0] == 0) {
        input = input.subspan(1);
        zeroes++;
    }
        printf("ZEROES: %d\n", zeroes);

    // Allocate enough space in big-endian base58 representation.
    int size = input.size() * 138 / 100 + 1; // log(256) / log(58), rounded up.
    std::vector<unsigned char> b58(size);
        printf("size: %d\n", size);
    // Process the bytes.
    while (input.size() > 0) {
        int carry = input[0];
        int i = 0;
                std::string s(1, input[0]);
                printf("%s", s.c_str());
                //printf("%d", input[0]);
        // Apply "b58 = b58 * 256 + ch".
        for (std::vector<unsigned char>::reverse_iterator it = b58.rbegin(); (carry != 0 || i < length) && (it != b58.rend()); it++, i++) {
            carry += 256 * (*it);
            *it = carry % 58;
            carry /= 58;
        }

        assert(carry == 0);
        length = i;
        input = input.subspan(1);
    }
        printf("\n");
    // Skip leading zeroes in base58 result.
    std::vector<unsigned char>::iterator it = b58.begin() + (size - length);
    while (it != b58.end() && *it == 0)
        it++;
    // Translate the result into a string.
    std::string str;
    str.reserve(zeroes + (b58.end() - it));
    str.assign(zeroes, '1');
    while (it != b58.end())
        str += pszBase58[*(it++)];
    return str;
}

std::string Sfp::EncodeBase58Check_(Span<const unsigned char> input) //For Testing, remove later
{
    // add 4-byte hash check to the end
    std::vector<unsigned char> vch(input.begin(), input.end());
    uint256 hash = Hash(vch);
    vch.insert(vch.end(), (unsigned char*)&hash, (unsigned char*)&hash + 4);
        /*for(unsigned int i = 0; i < vch.size(); i++) {
            printf("%c", vch[i]);
        }
        printf("\n");*/
        std::string test("6fac30986d081592ff27a65da9bcf1b31813dc19a93b750592");
        //std::vector<unsigned char> test2(test.begin(), test.end());

        std::vector<unsigned char> test2 = hexToUchBuffer(test);

    //return EncodeBase58(vch);
        return EncodeBase58(test2);
}

std::string Sfp::num2bin(uint32_t vout, int length) {
    char ch[length];

    sprintf(ch, "%02x", vout);

    for(int i = 0; i < (length - 1); i++) {
        strcat(ch, "00");
    }

    return bufferToString(toLittleEndian(stringToBuffer(std::string(ch))));
}

double Sfp::calculateMinimumOutputAmount(std::string script) {
    const int BSV_DUST_RELAY_FEE = 250;
  const int BSV_DUST_LIMIT_FACTOR = 4;
  const int INPUT_BYTES = 148;
  const int AMOUNT_BYTES = 9;

  int bytes = (script.size()/2) + AMOUNT_BYTES + INPUT_BYTES;
    //printf("BYTES: %d\n", bytes);
  double fee = (double) bytes * BSV_DUST_RELAY_FEE / 1000;
    //printf("FEE: %.2f\n", fee);
  double dustThreshold = ceil(BSV_DUST_LIMIT_FACTOR * fee);
    //printf("DUSTTHRESHOLD: %.2f\n", dustThreshold);
  return dustThreshold;
}

std::string Sfp::createOutput (TokenDataStruct data, COutPoint linkedTxIn) {
    //std::string linkedTxOutpoint = linkedTxIn.txHashBuf.toString('hex') + num2bin(linkedTxIn.txOutNum, 4)
    //std::string linkedTxOutpoint = linkedTxIn.hash.GetHex() + num2bin(linkedTxIn.n, 4);
    std::string linkedTxOutpoint = bufferToString(toLittleEndian(stringToBuffer(linkedTxIn.hash.GetHex()))) + num2bin(linkedTxIn.n, 4);
    printf("linkedTxOutpoint %s\n", linkedTxOutpoint.c_str());
    uint256 hash = Hash(hexToUchBuffer(std::string(linkedTxOutpoint)));
    //std::vector<std::string> linkedTxOutpointHash = toLittleEndian(stringToBuffer(hash.GetHex()));
    std::vector<std::string> linkedTxOutpointHash = stringToBuffer(hash.GetHex());
    /*printf("linkedTxOutpointHash: \n");
    for(int i = 0; i < linkedTxOutpointHash.size(); i++) {
        printf("%s", linkedTxOutpointHash[i].c_str());
    }
    printf("\n");*/

    std::string linkedTxOutpointHash_str = bufferToString(linkedTxOutpointHash);
    printf("linkedTxOutpointHash: %s\n", linkedTxOutpointHash_str.c_str());

    uint256 linkedTxOutpointHash_ = uint256S(linkedTxOutpointHash_str);

    std::vector<std::string> chunk1_buf = stringToBuffer(stringToHex("sfp@0.3"));
    /*printf("chunk1:\n");
    for(int i = 0; i < chunk1_buf.size(); i++) {
        printf("%s", chunk1_buf[i].c_str());
    }
    printf("\n");*/
    std::string chunk1 = bufferToString(chunk1_buf);
    printf("chunk1: %s\n", chunk1.c_str());

    std::vector<std::string> chunk2_buf = stringToBuffer(stringToHex(data.asset));
    /*printf("chunk2:\n");
    for(int i = 0; i < chunk2_buf.size(); i++) {
        printf("%s", chunk2_buf[i].c_str());
    }
    printf("\n");*/
    std::string chunk2 = bufferToString(chunk2_buf);
    printf("chunk2: %s\n", chunk2.c_str());

    std::vector<unsigned char> vchRet;
    int max_ret_len = 100;

    bool res = DecodeBase58Check(authorizerAddress, vchRet, max_ret_len);
    std::vector<unsigned char> chunk3_buf = vchRet;
    /*printf("chunk3:\n");
    for(int i = 0; i < chunk3_buf.size(); i++) {
        printf("%02x", chunk3_buf[i]);
    }
    printf("\n");*/
    std::string chunk3 = uchbufToString(chunk3_buf);
    chunk3 = chunk3.substr (2,chunk3.size());
    printf("chunk3: %s\n", chunk3.c_str());

    std::vector<unsigned char> vchRet2;
    res = DecodeBase58Check(data.address, vchRet2, max_ret_len);
    std::vector<unsigned char> chunk4_buf = vchRet2;
    /*printf("chunk4:\n");
    for(int i = 0; i < chunk4_buf.size(); i++) {
        printf("%02x", chunk4_buf[i]);
    }
    printf("\n");*/
    std::string chunk4 = uchbufToString(chunk4_buf);
    chunk4 = chunk4.substr (2,chunk4.size());
    printf("chunk4: %s\n", chunk4.c_str());

    std::vector<unsigned char> vchRet3;
    res = DecodeBase58Check(data.issuer, vchRet3, max_ret_len);
    std::vector<unsigned char> chunk5_buf = vchRet3;
    /*printf("chunk5:\n");
    for(int i = 0; i < chunk5_buf.size(); i++) {
        printf("%02x", chunk5_buf[i]);
    }
    printf("\n");*/
    std::string chunk5 = uchbufToString(chunk5_buf);
    chunk5 = chunk5.substr (2,chunk5.size());
    printf("chunk5: %s\n", chunk5.c_str());

    //ArgsManager argsman;
    //std::unique_ptr<const CChainParams> test = CreateChainParams(argsman, CBaseChainParams::TESTNET);

    ECC_Start();


    //std::string signature;
    //bool res_message = MessageSign(key, linkedTxOutpointHash_str, signature);
    //printf("signature: %s\n", signature.c_str());
    //printf("signature hex: %s\n", stringToHex(signature).c_str());
    /*std::vector<unsigned char> vchSig;
    bool res_message = key.SignCompact(linkedTxOutpointHash_, vchSig);
    //bool res_message = SignCompact_(key, linkedTxOutpointHash_, vchSig);
    std::vector<unsigned char> chunk6 = vchSig;
    printf("chunk6:\n");
    for(int i = 0; i < chunk6.size(); i++) {
        printf("%02x", chunk6[i]);
    }
    printf("\n");*/

    std::vector<unsigned char> vchSig;
    //bool res_message = key.Sign(linkedTxOutpointHash_, vchSig, false, 7);
    //bool res_message = authorizerPrivKey.Sign(linkedTxOutpointHash_, vchSig);
    //bool res_message = authorizerPrivKey.Sign(linkedTxOutpointHash_, vchSig);
    
    bool res_message = authorizerPrivKey.Sign(linkedTxOutpointHash_, vchSig, false, 0);

  /*std::vector<unsigned char> kinvmN;
  unsigned long kinvNLen = CPubKey::SIGNATURE_SIZE;
  bool res_message = authorizerPrivKey.Sign_(linkedTxOutpointHash_, vchSig, kinvmN, &kinvNLen, false, 0);
  vchSig = getLittleEndian3(authorizerPrivKey, vchSig, hexToUchBuffer(linkedTxOutpoint), kinvmN, kinvNLen);
    printf("TXBUILDER SIGN: vchSig:\n");
    for(int i = 0; i < vchSig.size(); i++) {
        printf("%02x", vchSig[i]);
    }
    printf("\n");*/
    
    std::vector<unsigned char> chunk6_buf = vchSig;
    /*printf("chunk6:\n");
    for(int i = 0; i < chunk6_buf.size(); i++) {
        printf("%02x", chunk6_buf[i]);
    }
    printf("\n");*/
    std::string chunk6 = uchbufToString(chunk6_buf);
    printf("chunk6: %s\n", chunk6.c_str());

    if(res_message) printf("SIGN SUCCESS\n");
    else printf("SIGN FAILED\n");

    ECC_Stop();

    std::string chunk7 = linkedTxOutpoint;
    printf("chunk7: %s\n", chunk7.c_str());

    //"610773667040302e33246164336362313833316165622e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a914f1f354fceb000dbacb1d665dbf285d355d771f9a142ca3d8061b9c7171c5ae7c4c0bc10781916139a746304402202653e382fe17b7c95f81fd36edee5f4fd1cb1a84777a5d83cb76e521359b4af50220622d1e452615cc7b0eb32af9d1a3d7b40915645cdd76290330927b74171e4afe24405a644b436819e24c2770231c4498fba7eba40b051f073655daddf58155939100000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0b0100000000000000080000"

    std::string op_nop("61");

    std::string ops("000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac77777777777777777777777777777777777777777777");

    std::string op_return("6a");

    char ch1[3];
    sprintf(ch1, "%02lx", chunk1.size()/2);
    std::string chunk1_size(ch1);
    printf("chunk1 size = %s\n", chunk1_size.c_str());

    char ch2[3];
    sprintf(ch2, "%02lx", chunk2.size()/2);
    std::string chunk2_size(ch2);
    printf("chunk2 size = %s\n", chunk2_size.c_str());

    char ch3[3];
    sprintf(ch3, "%02lx", chunk3.size()/2);
    std::string chunk3_size(ch3);
    printf("chunk3 size = %s\n", chunk3_size.c_str());

    char ch4[3];
    sprintf(ch4, "%02lx", chunk4.size()/2);
    std::string chunk4_size(ch4);
    printf("chunk4 size = %s\n", chunk4_size.c_str());

    char ch5[3];
    sprintf(ch5, "%02lx", chunk5.size()/2);
    std::string chunk5_size(ch5);
    printf("chunk5 size = %s\n", chunk5_size.c_str());

    char ch6[3];
    sprintf(ch6, "%02lx", chunk6.size()/2);
    std::string chunk6_size(ch6);
    printf("chunk6 size = %s\n", chunk6_size.c_str());

    char ch7[3];
    sprintf(ch7, "%02lx", chunk7.size()/2);
    std::string chunk7_size(ch7);
    printf("chunk7 size = %s\n", chunk7_size.c_str());

    std::string state = data.state;
    printf("state = %s\n", state.c_str());
    char ch8[3];
    sprintf(ch8, "%02lx", state.size()/2);
    std::string state_size(ch8);
    printf("state size = %s\n", state_size.c_str());

    std::string locking_script = op_nop + chunk1_size + chunk1 + chunk2_size + chunk2 + chunk3_size + chunk3 + chunk4_size + chunk4 + \
    chunk5_size + chunk5 + chunk6_size + chunk6 + chunk7_size + chunk7 + ops + op_return + state_size + state;

    printf("locking_script = %s\n", locking_script.c_str());
    printf("locking_script.length = %lu\n", locking_script.size());

    return locking_script;

    /*std::vector<unsigned char> vchRet2;
    //SFP_AUTHORIZER_WIF="cQLs3wbw3fUCZRe6KyWmu1DE4UmcG2R21NB4TX2fSM6k7uBTFMJA"
    //SFP_AUTHORIZER_PUBKEY="025f44adfa89cc33c42def4165be539a523c3d3fd7e537bc1e9bd44b32fa341cfd"
    std::string authorizerWif_("cQLs3wbw3fUCZRe6KyWmu1DE4UmcG2R21NB4TX2fSM6k7uBTFMJA");

    res = DecodeBase58Check(authorizerWif_, vchRet2, max_ret_len);
    printf("vchRet2:\n");
    for(int i = 0; i < vchRet2.size(); i++) {
        printf("%02x", vchRet2[i]);
    }
    printf("\n");*/

    //std::string linkedTxOutpointHash = EncodeBase58Check(hexToUchBuffer(std::string(linkedTxOutpoint)));
    //printf("linkedTxOutpointHash %s\n", linkedTxOutpointHash.c_str());

}

std::string Sfp::createOutputOriginal (TokenDataStruct data, COutPoint linkedTxIn) {
    //std::string linkedTxOutpoint = linkedTxIn.txHashBuf.toString('hex') + num2bin(linkedTxIn.txOutNum, 4)
    std::string linkedTxOutpoint = linkedTxIn.hash.GetHex() + num2bin(linkedTxIn.n, 4);
    //std::string linkedTxOutpoint = bufferToString(toLittleEndian(stringToBuffer(linkedTxIn.hash.GetHex()))) + num2bin(linkedTxIn.n, 4);
    //printf("linkedTxOutpoint %s\n", linkedTxOutpoint.c_str());
    uint256 hash = Hash(hexToUchBuffer(std::string(linkedTxOutpoint)));
    //std::vector<std::string> linkedTxOutpointHash = toLittleEndian(stringToBuffer(hash.GetHex()));
    std::vector<std::string> linkedTxOutpointHash = stringToBuffer(hash.GetHex());
    /*printf("linkedTxOutpointHash: \n");
    for(int i = 0; i < linkedTxOutpointHash.size(); i++) {
        printf("%s", linkedTxOutpointHash[i].c_str());
    }
    printf("\n");*/

    std::string linkedTxOutpointHash_str = bufferToString(linkedTxOutpointHash);
    printf("linkedTxOutpointHash: %s\n", linkedTxOutpointHash_str.c_str());

    uint256 linkedTxOutpointHash_ = uint256S(linkedTxOutpointHash_str);

    std::vector<std::string> chunk1_buf = stringToBuffer(stringToHex("sfp@0.3"));
    /*printf("chunk1:\n");
    for(int i = 0; i < chunk1_buf.size(); i++) {
        printf("%s", chunk1_buf[i].c_str());
    }
    printf("\n");*/
    std::string chunk1 = bufferToString(chunk1_buf);
    printf("chunk1: %s\n", chunk1.c_str());

    std::vector<std::string> chunk2_buf = stringToBuffer(stringToHex(data.asset));
    /*printf("chunk2:\n");
    for(int i = 0; i < chunk2_buf.size(); i++) {
        printf("%s", chunk2_buf[i].c_str());
    }
    printf("\n");*/
    std::string chunk2 = bufferToString(chunk2_buf);
    printf("chunk2: %s\n", chunk2.c_str());

    std::vector<unsigned char> vchRet;
    int max_ret_len = 100;

    bool res = DecodeBase58Check(authorizerAddress, vchRet, max_ret_len);
    std::vector<unsigned char> chunk3_buf = vchRet;
    /*printf("chunk3:\n");
    for(int i = 0; i < chunk3_buf.size(); i++) {
        printf("%02x", chunk3_buf[i]);
    }
    printf("\n");*/
    std::string chunk3 = uchbufToString(chunk3_buf);
    chunk3 = chunk3.substr (2,chunk3.size());
    printf("chunk3: %s\n", chunk3.c_str());

    std::vector<unsigned char> vchRet2;
    res = DecodeBase58Check(data.address, vchRet2, max_ret_len);
    std::vector<unsigned char> chunk4_buf = vchRet2;
    /*printf("chunk4:\n");
    for(int i = 0; i < chunk4_buf.size(); i++) {
        printf("%02x", chunk4_buf[i]);
    }
    printf("\n");*/
    std::string chunk4 = uchbufToString(chunk4_buf);
    chunk4 = chunk4.substr (2,chunk4.size());
    printf("chunk4: %s\n", chunk4.c_str());

    std::vector<unsigned char> vchRet3;
    res = DecodeBase58Check(data.issuer, vchRet3, max_ret_len);
    std::vector<unsigned char> chunk5_buf = vchRet3;
    /*printf("chunk5:\n");
    for(int i = 0; i < chunk5_buf.size(); i++) {
        printf("%02x", chunk5_buf[i]);
    }
    printf("\n");*/
    std::string chunk5 = uchbufToString(chunk5_buf);
    chunk5 = chunk5.substr (2,chunk5.size());
    printf("chunk5: %s\n", chunk5.c_str());

    //ArgsManager argsman;
    //std::unique_ptr<const CChainParams> test = CreateChainParams(argsman, CBaseChainParams::TESTNET);

    ECC_Start();


    //std::string signature;
    //bool res_message = MessageSign(key, linkedTxOutpointHash_str, signature);
    //printf("signature: %s\n", signature.c_str());
    //printf("signature hex: %s\n", stringToHex(signature).c_str());
    /*std::vector<unsigned char> vchSig;
    bool res_message = key.SignCompact(linkedTxOutpointHash_, vchSig);
    //bool res_message = SignCompact_(key, linkedTxOutpointHash_, vchSig);
    std::vector<unsigned char> chunk6 = vchSig;
    printf("chunk6:\n");
    for(int i = 0; i < chunk6.size(); i++) {
        printf("%02x", chunk6[i]);
    }
    printf("\n");*/

    std::vector<unsigned char> vchSig;
    //bool res_message = key.Sign(linkedTxOutpointHash_, vchSig, false, 7);
    bool res_message = authorizerPrivKey.Sign(linkedTxOutpointHash_, vchSig);
    //bool res_message = SignCompact_(key, linkedTxOutpointHash_, vchSig);
    std::vector<unsigned char> chunk6_buf = vchSig;
    /*printf("chunk6:\n");
    for(int i = 0; i < chunk6_buf.size(); i++) {
        printf("%02x", chunk6_buf[i]);
    }
    printf("\n");*/
    std::string chunk6 = uchbufToString(chunk6_buf);
    printf("chunk6: %s\n", chunk6.c_str());

    if(res_message) printf("SIGN SUCCESS\n");
    else printf("SIGN FAILED\n");

    ECC_Stop();

    std::string chunk7 = linkedTxOutpoint;
    printf("chunk7: %s\n", chunk7.c_str());

    //"610773667040302e33246164336362313833316165622e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a914f1f354fceb000dbacb1d665dbf285d355d771f9a142ca3d8061b9c7171c5ae7c4c0bc10781916139a746304402202653e382fe17b7c95f81fd36edee5f4fd1cb1a84777a5d83cb76e521359b4af50220622d1e452615cc7b0eb32af9d1a3d7b40915645cdd76290330927b74171e4afe24405a644b436819e24c2770231c4498fba7eba40b051f073655daddf58155939100000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0b0100000000000000080000"

    std::string op_nop("61");

    std::string ops("000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac77777777777777777777777777777777777777777777");

    std::string op_return("6a");

    char ch1[3];
    sprintf(ch1, "%02lx", chunk1.size()/2);
    std::string chunk1_size(ch1);
    printf("chunk1 size = %s\n", chunk1_size.c_str());

    char ch2[3];
    sprintf(ch2, "%02lx", chunk2.size()/2);
    std::string chunk2_size(ch2);
    printf("chunk2 size = %s\n", chunk2_size.c_str());

    char ch3[3];
    sprintf(ch3, "%02lx", chunk3.size()/2);
    std::string chunk3_size(ch3);
    printf("chunk3 size = %s\n", chunk3_size.c_str());

    char ch4[3];
    sprintf(ch4, "%02lx", chunk4.size()/2);
    std::string chunk4_size(ch4);
    printf("chunk4 size = %s\n", chunk4_size.c_str());

    char ch5[3];
    sprintf(ch5, "%02lx", chunk5.size()/2);
    std::string chunk5_size(ch5);
    printf("chunk5 size = %s\n", chunk5_size.c_str());

    char ch6[3];
    sprintf(ch6, "%02lx", chunk6.size()/2);
    std::string chunk6_size(ch6);
    printf("chunk6 size = %s\n", chunk6_size.c_str());

    char ch7[3];
    sprintf(ch7, "%02lx", chunk7.size()/2);
    std::string chunk7_size(ch7);
    printf("chunk7 size = %s\n", chunk7_size.c_str());

    std::string state = data.state;
    printf("state = %s\n", state.c_str());
    char ch8[3];
    sprintf(ch8, "%02lx", state.size()/2);
    std::string state_size(ch8);
    printf("state size = %s\n", state_size.c_str());

    std::string locking_script = op_nop + chunk1_size + chunk1 + chunk2_size + chunk2 + chunk3_size + chunk3 + chunk4_size + chunk4 + \
    chunk5_size + chunk5 + chunk6_size + chunk6 + chunk7_size + chunk7 + ops + op_return + state_size + state;

    printf("locking_script = %s\n", locking_script.c_str());
    printf("locking_script.length = %lu\n", locking_script.size());

    return locking_script;

    /*std::vector<unsigned char> vchRet2;
    //SFP_AUTHORIZER_WIF="cQLs3wbw3fUCZRe6KyWmu1DE4UmcG2R21NB4TX2fSM6k7uBTFMJA"
    //SFP_AUTHORIZER_PUBKEY="025f44adfa89cc33c42def4165be539a523c3d3fd7e537bc1e9bd44b32fa341cfd"
    std::string authorizerWif_("cQLs3wbw3fUCZRe6KyWmu1DE4UmcG2R21NB4TX2fSM6k7uBTFMJA");

    res = DecodeBase58Check(authorizerWif_, vchRet2, max_ret_len);
    printf("vchRet2:\n");
    for(int i = 0; i < vchRet2.size(); i++) {
        printf("%02x", vchRet2[i]);
    }
    printf("\n");*/

    //std::string linkedTxOutpointHash = EncodeBase58Check(hexToUchBuffer(std::string(linkedTxOutpoint)));
    //printf("linkedTxOutpointHash %s\n", linkedTxOutpointHash.c_str());

}

OutputData Sfp::parseOutput_ (CScript script) {
    OutputData output;
    CScript::const_iterator pc = script.begin();
    CScript::const_iterator end = script.end();
    opcodetype opcodeRet;
    std::vector<unsigned char> vchRet;

    /*script.GetOp(pc, opcodeRet, vchRet);

    printf("OPCODE: %d\n", opcodeRet);

    std::string s(vchRet.begin(), vchRet.end());
    printf("vchRet: %s\n", s.c_str());

    script.GetOp(pc, opcodeRet, vchRet);

    printf("OPCODE: %d\n", opcodeRet);

    printf("OP_1: %d\n", OP_1);*/

    std::vector<Chunks> chunks;

    while (script.GetOp(pc, opcodeRet, vchRet)) {
    //while (GetScriptOp(pc, end, opcodeRet, &vchRet)) {
        Chunks chunk;
        std::string s(vchRet.begin(), vchRet.end());
        //chunk.buf = s;
        chunk.buf = stringToHex(s);
        printf("vchRet: %s\n", chunk.buf.c_str());
        chunk.len = chunk.buf.size()/2;
        //printf("len: %lu\n", s.size()/2);
        chunk.opCodeNum = opcodeRet;
        //printf("OPCODE: %02x\n", opcodeRet);
        //printf("OPNAME: %s\n", GetOpName(opcodeRet).c_str());

        chunks.push_back(chunk);
    }

    std::string version = getProtocolScriptVersion(chunks);

    printf("version: %s\n", version.c_str());

    if(version.size() > 0) {
        std::string state = chunks[chunks.size() - 1].buf;
        output.state = state;
        output.version = version;
        output.asset = hexToString(chunks[PAYMAIL].buf);
        printf("asset = %s\n", output.asset.c_str());
        //unsigned int val = (unsigned int) pubKeyHash;
        //output.authorizer = std::to_string(val) + chunks[AUTHORIZER].buf;
        //std::vector<unsigned char> input(output.authorizer.begin(), output.authorizer.end());
        //std::string test = EncodeBase58Check_(input);
        output.authorizer = EncodeBase58Check(hexToUchBuffer(std::string(pubKeyHash) + chunks[AUTHORIZER].buf));
        printf("authorizer = %s\n", output.authorizer.c_str());
        output.address = EncodeBase58Check(hexToUchBuffer(std::string(pubKeyHash) + chunks[OWNER].buf));
        printf("output.address = %s\n", output.address.c_str());
        printf("state: %s\n", state.c_str());

        std::vector<std::string> buffer = stringToBuffer(state);

        /*for(int i = 0; i < buffer.size(); i++) {
            printf("%s ", buffer[i].c_str());
        }
        printf("\n");*/

        std::vector<std::string> sliced_buffer = sliceBuffer(buffer, 0, QUANTITY_LENGTH);

        /*for(int i = 0; i < sliced_buffer.size(); i++) {
            printf("%s ", sliced_buffer[i].c_str());
        }
        printf("\n");*/

        std::vector<std::string> reverse_buffer = toLittleEndian(sliced_buffer);

        /*for(int i = 0; i < reverse_buffer.size(); i++) {
            printf("%s ", reverse_buffer[i].c_str());
        }
        printf("\n");*/

        output.amount = bufferToNumber(reverse_buffer);
        printf("output.amount = %d\n", output.amount);

        std::vector<std::string> sliced_state = sliceBuffer(buffer, QUANTITY_LENGTH, buffer.size() - STATE_LENGTH);

        /*for(int i = 0; i < sliced_state.size(); i++) {
            printf("%s ", sliced_state[i].c_str());
        }
        printf("\n");*/

        //std::string tst("68656c6c6f");
        //std::vector<std::string> tst_buffer = stringToBuffer(tst);

        output.notes = hexToString(bufferToString(sliced_state));
        //output.notes = hexToString(bufferToString(tst_buffer));
        printf("output.notes = %s\n", output.notes.c_str());

        output.issuer = std::string("00");

        if(std::stof(output.version) >= 0.2) {
            output.issuer = EncodeBase58Check(hexToUchBuffer(std::string(pubKeyHash) + chunks[ISSUER].buf));
        }
        printf("output.issuer = %s\n", output.issuer.c_str());

        if(std::stof(output.version) >= 0.3) {
            std::string linkedPrevOutpoint = chunks[LINKED_PREV_OUTPOINT].buf;

            printf("linkedPrevOutpoint = %s\n", linkedPrevOutpoint.c_str());

            std::vector<std::string> hash_buffer = sliceBuffer(stringToBuffer(linkedPrevOutpoint), 0, 32);

            for(int i = 0; i < hash_buffer.size(); i++) {
                printf("%s ", hash_buffer[i].c_str());
            }
            printf("\n");

            std::string hash = bufferToString(hash_buffer);
            output.linkPrevOutpoint.hash = uint256S(hash);
            //printf("hex: %s\n", output.linkPrevOutpoint.hash.GetHex().c_str());

            std::vector<std::string> vout_buffer = sliceBuffer(stringToBuffer(linkedPrevOutpoint), 32);

            for(int i = 0; i < vout_buffer.size(); i++) {
                printf("%s ", vout_buffer[i].c_str());
            }
            printf("\n");
            output.linkPrevOutpoint.n = bufferToNumber(toLittleEndian(vout_buffer));
            printf("output.linkPrevOutpoint.n = %d\n", output.linkPrevOutpoint.n);

        }

    }

    return output;
}


OutputData Sfp::parseOutput (CScript script) {
    OutputData output;

    std::vector<Chunks> chunks = getChunks(script);

    std::string version = getProtocolScriptVersion(chunks);

    printf("version: %s\n", version.c_str());

    if(version.size() > 0) {
        std::string state = chunks[chunks.size() - 1].buf;
        output.state = state;
        output.version = version;
        output.asset = hexToString(chunks[PAYMAIL].buf);
        printf("asset = %s\n", output.asset.c_str());
        //unsigned int val = (unsigned int) pubKeyHash;
        //output.authorizer = std::to_string(val) + chunks[AUTHORIZER].buf;
        //std::vector<unsigned char> input(output.authorizer.begin(), output.authorizer.end());
        //std::string test = EncodeBase58Check_(input);
        output.authorizer = EncodeBase58Check(hexToUchBuffer(std::string(pubKeyHash) + chunks[AUTHORIZER].buf));
        printf("authorizer = %s\n", output.authorizer.c_str());
        output.address = EncodeBase58Check(hexToUchBuffer(std::string(pubKeyHash) + chunks[OWNER].buf));
        printf("address = %s\n", output.address.c_str());
        printf("state: %s\n", state.c_str());

        std::vector<std::string> buffer = stringToBuffer(state);

        /*for(int i = 0; i < buffer.size(); i++) {
            printf("%s ", buffer[i].c_str());
        }
        printf("\n");*/

        std::vector<std::string> sliced_buffer = sliceBuffer(buffer, 0, QUANTITY_LENGTH);

        /*for(int i = 0; i < sliced_buffer.size(); i++) {
            printf("%s ", sliced_buffer[i].c_str());
        }
        printf("\n");*/

        std::vector<std::string> reverse_buffer = toLittleEndian(sliced_buffer);

        /*for(int i = 0; i < reverse_buffer.size(); i++) {
            printf("%s ", reverse_buffer[i].c_str());
        }
        printf("\n");*/

        output.amount = bufferToNumber(reverse_buffer);
        printf("amount = %d\n", output.amount);

        std::vector<std::string> sliced_state = sliceBuffer(buffer, QUANTITY_LENGTH, buffer.size() - STATE_LENGTH);

        /*for(int i = 0; i < sliced_state.size(); i++) {
            printf("%s ", sliced_state[i].c_str());
        }
        printf("\n");*/

        //std::string tst("68656c6c6f");
        //std::vector<std::string> tst_buffer = stringToBuffer(tst);

        output.notes = hexToString(bufferToString(sliced_state));
        //output.notes = hexToString(bufferToString(tst_buffer));
        printf("output.notes = %s\n", output.notes.c_str());

        output.issuer = std::string("00");

        if(std::stof(output.version) >= 0.2) {
            output.issuer = EncodeBase58Check(hexToUchBuffer(std::string(pubKeyHash) + chunks[ISSUER].buf));
        }
        printf("output.issuer = %s\n", output.issuer.c_str());

        if(std::stof(output.version) >= 0.3) {
            std::string linkedPrevOutpoint = chunks[LINKED_PREV_OUTPOINT].buf;

            printf("linkedPrevOutpoint = %s\n", linkedPrevOutpoint.c_str());

            std::vector<std::string> hash_buffer = sliceBuffer(stringToBuffer(linkedPrevOutpoint), 0, 32);

            /*for(int i = 0; i < hash_buffer.size(); i++) {
                printf("%s ", hash_buffer[i].c_str());
            }
            printf("\n");*/

            std::string hash = bufferToString(hash_buffer);
            output.linkPrevOutpoint.hash = uint256S(hash);
            //printf("hex: %s\n", output.linkPrevOutpoint.hash.GetHex().c_str());

            //std::vector<std::string> test_buffer = stringToBuffer(linkedPrevOutpoint);
            //std::vector<std::string> vout_buffer = sliceBuffer(test_buffer, 32);
            std::vector<std::string> vout_buffer = sliceBuffer(stringToBuffer(linkedPrevOutpoint), 32);

            /*for(int i = 0; i < vout_buffer.size(); i++) {
                printf("%s ", vout_buffer[i].c_str());
            }
            printf("\n");*/
            output.linkPrevOutpoint.n = bufferToNumber(toLittleEndian(vout_buffer));
            printf("output.linkPrevOutpoint.n = %d\n", output.linkPrevOutpoint.n);

        }

    }

    return output;
}

//std::map<std::string, UTxOutData*> Sfp::recoverUtxosMap (std::vector<CTxIn> txIns) {
std::map<std::string, CTxOut> Sfp::recoverUtxosMap (std::vector<CTxIn> txIns) {
  printf("RECOVER UTXOS MAP\n");
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    char *sql;

    //std::map<std::string, UTxOutData*> map;
    std::map<std::string, CTxOut> map;

    /* Open database */
    //rc = sqlite3_open("test.db", &db);
    rc = sqlite3_open(path.c_str(), &db);

    if( rc ) {
      fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return map;
    } else {
      fprintf(stderr, "Opened database successfully\n");
    }

    for (size_t i = 0; i < txIns.size(); i++) {
        Records records;
        CTxIn txIn = txIns[i];
        std::string txid = txIn.prevout.hash.GetHex();
        printf("txid: %s\n", txid.c_str());

        std::string sql_query = std::string("SELECT * FROM SFP_UTXOS WHERE TXID = '") + txid + std::string("' AND VOUT = ") + std::to_string(txIn.prevout.n) + std::string(" LIMIT 1");

        /* Create SQL statement */
        sql = (char *) sql_query.c_str();

    printf("sql_query: %s\n", sql_query.c_str());

        /* Execute SQL statement */
        rc = sqlite3_exec(db, sql, select_callback, &records, &zErrMsg);

        if( rc != SQLITE_OK ) {
            fprintf(stderr, "SQL error: %s\n", zErrMsg);
            sqlite3_free(zErrMsg);
        } else {
            fprintf(stdout, "Operation done successfully\n");
            printf("%lu records returned\n", records.size());

            if(records.size() > 0) {
                //UTxOutData *data = (UTxOutData *) malloc (sizeof(UTxOutData));
                CTxOut txOut;
                //data->vout = txIn.prevout.n;
                //data->txOut.nValue = (int64_t) std::stoll(records[0][5]);
                txOut.nValue = (int64_t) std::stoll(records[0][5]);
                printf("txOut.nValue = %lld\n", txOut.nValue);

                //printf("records[0][4]: %s\n", records[0][4].c_str());

                //std::vector<unsigned char> utxo_script(records[0][4].begin(), records[0][4].end());
                std::vector<unsigned char> utxo_script = hexToUchBuffer(records[0][4]);
                CScript script(utxo_script.begin(), utxo_script.end());
                //CScript script(records[0][4].c_str(), sizeof(records[0][4].c_str()));
                //data->txOut.scriptPubKey = script;
                txOut.scriptPubKey = script;

                /*std::vector<char> script_(records[0][4].begin(), records[0][4].end());
                std::string::const_iterator it_ = script_.begin();
                while(it_ != script_.end()) printf("%02x", *it_++);
                printf("\n");*/

                std::string txid_vout = txid + std::string("_") + std::to_string(txIn.prevout.n);

                //std::map<std::string,UTxOutData*>::iterator it;
                std::map<std::string,CTxOut>::iterator it;
                //it = map.find(txid);
                it = map.find(txid_vout);

                if (it == map.end()) {
                //map.insert(std::pair<std::string,UTxOutData*>(txid_vout,data));
                    map.insert(std::pair<std::string,CTxOut>(txid_vout,txOut));
                }
            }
        }


    }
    sqlite3_close(db);
    return map;
}

void Sfp::addUnlockScript (OutputData tokenInput, CTxIn& txIn, TxBuilder *bsvTxBuilder) {
    printf("ADD UNLOCK SCRIPT\n");
    std::string placeholders[8];

    //placeholders[VERSION_UNLOCK] = Buffer.from('sfp@' + tokenInput.version).toString('hex')
    std::string buffer = std::string("sfp@") + tokenInput.version;
    placeholders[VERSION_UNLOCK] = stringToHex(buffer);

    placeholders[AUTHORIZER_PUBKEY] = std::string("00");
    placeholders[AUTHORIZER_SIG] = std::string("00");
    placeholders[OWNER_PUBKEY] = std::string("00");
    placeholders[OWNER_SIG] = std::string("00");
    placeholders[NTXSID_SIG] = std::string("00");

    bsvTxBuilder->addSigOperation(txIn.prevout.hash, txIn.prevout.n, AUTHORIZER_SIG, std::string("sig"), tokenInput.authorizer);
    bsvTxBuilder->addSigOperation(txIn.prevout.hash, txIn.prevout.n, AUTHORIZER_PUBKEY, std::string("pubKey"), tokenInput.authorizer);
    bsvTxBuilder->addSigOperation(txIn.prevout.hash, txIn.prevout.n, OWNER_SIG, std::string("sig"), tokenInput.address);
    bsvTxBuilder->addSigOperation(txIn.prevout.hash, txIn.prevout.n, OWNER_PUBKEY, std::string("pubKey"), tokenInput.address);

    if(std::stof(tokenInput.version) >= 0.2) {
        placeholders[ISSUER_PUBKEY] = std::string("00");
        placeholders[ISSUER_SIG] = std::string("00");
        bsvTxBuilder->addSigOperation(txIn.prevout.hash, txIn.prevout.n, ISSUER_SIG, std::string("sig"), tokenInput.issuer);
        bsvTxBuilder->addSigOperation(txIn.prevout.hash, txIn.prevout.n, ISSUER_PUBKEY, std::string("pubKey"), tokenInput.issuer);
    }
    /*std::map<std::string, std::vector<SigOpStruct>>::iterator it;
    for (it = bsvTxBuilder->sigOperations.map.begin(); it != bsvTxBuilder->sigOperations.map.end(); it++)
    {
         printf("Key: %s\n", it->first.c_str());
         for(size_t i = 0; i < it->second.size(); i++) {
             printf("Value: \n");
             printf("type: %s\n", it->second[i].type.c_str());
             printf("nHashType: %lu\n", it->second[i].nHashType);
             printf("nScriptChunk: %d\n", it->second[i].nScriptChunk);
             printf("addressStr: %s\n", it->second[i].addressStr.c_str());
         }
    }*/

    printf("Add Unlock Script size = %u\n", txIn.scriptSig.size());
    //if(!txIn.scriptSig.HasValidOps()) {
    if(txIn.scriptSig.size() == 0) {
        CScript asm_script;
        for(int i = 0; i < 8; i++) {
            writeBuffer(asm_script, hexToUchBuffer(placeholders[i]));
        }
        txIn.scriptSig = asm_script;
    }

}

typedef struct BuildActionStruct {
    std::string hex;
    SigOperations sigOperations;
} BuildActionStruct;

typedef struct BuildTokenStruct {
    TxBuilder *bsvTxBuilder;
    TokenTransaction *tokenTx;
} BuildTokenStruct;


class TokenData {
    public:
        int index;
        std::string asset;
        int amount;
        std::string address;
        std::string authorizer;
        std::string notes;
        std::string issuer;

        TokenData(int index_, TokenDataStruct data) {
            index = index_;
        asset = data.asset;
        amount = data.amount;
        address = data.address;
        authorizer = data.authorizer;
        notes = data.notes;
        issuer = data.issuer;
        }
};

class TokenInput: public TokenData {
    std::string txid;
    CTxIn txIn;
public:
      TokenInput(int index, TokenDataStruct data, CTxIn txIn_) : TokenData(index, data) {
            txid = txIn.prevout.hash.GetHex();
        txIn = txIn_;
      }

      bool hasParam (int position) {
            std::vector<Chunks> chunks = getChunks(txIn.scriptSig);
            printf("chunks[%d].buf = %s\n", position, chunks[position].buf.c_str());
        return (chunks.size() >= position) && (chunks[position].buf != std::string("00"));
      }
};

class TokenOutput: public TokenData {
    public:
        CScript script;
        int64_t satoshis;
      TokenOutput(int index, TokenDataStruct data, CTxOut txOut) : TokenData(index, data) {
        //this.script = txOut.script.toBuffer().toString('hex')
            script = txOut.scriptPubKey;
        //this.satoshis = txOut.valueBn.toNumber()
            satoshis = (int64_t) txOut.nValue;
      }

  /*toJSON () {
    const { script, ...props } = this

    return props
  }*/
};

class AssetsAggregator {
  public:
        std::map<std::string,int> assets;
        AssetsAggregator() {}
        void add (std::string asset, int amount) {
            std::map<std::string,int>::iterator it;
            it = assets.find(asset);

            if (it == assets.end()) {
            assets.insert(std::pair<std::string,int>(asset,amount));
            } else {
                it->second += amount;
            }
      }

        int sum (std::string asset) {
            std::map<std::string,int>::iterator it;
            it = assets.find(asset);
            if (it == assets.end()) {
                return 0;
            } else {
            return it->second;
            }
      }

        size_t length () {
        return assets.size();
      }

        std::vector<std::string> aliases () {

            std::vector<std::string> keys;
            for (std::map<std::string,int>::iterator it=assets.begin(); it!=assets.end(); ++it) {
                keys.push_back(it->first);
            }
        return keys;
      }

        bool has (std::string alias) {
            std::map<std::string,int>::iterator it;
            it = assets.find(alias);

            if(it != assets.end()) return true;
            else return false;
      }
};

class TokenTransaction {
    Sfp sfp;
    int inputsSignedByOwner;
    std::map<std::string, std::string> issuers;
  public:
        AssetsAggregator *assetsInputs;
        AssetsAggregator *assetsOutputs;
        std::vector<TokenInput*> inputs;
        std::vector<TokenOutput*> outputs;
        TokenTransaction(Sfp sfp_) {
            sfp = sfp_;
            assetsInputs = new AssetsAggregator;
            assetsOutputs = new AssetsAggregator;
        }
        void importInputs (TxBuilder *bsvTxBuilder);
        void importOutputs (TxBuilder *bsvTxBuilder);
        bool inputsAmountEqualOutputsAmount ();
        bool allInputsHaveParam (int position);
        bool hasMultipleOutputsPerAsset ();
        void addInput (TokenInput *tokenData);
        void addOutput (TokenOutput *tokenData);
        void setScript(CTxOut& txOut, std::string script_str);
        void createOutputs (TxBuilder *bsvTxBuilder, std::vector<TokenDataStruct> outputs);

};

BuildTokenStruct buildTokenTx(Sfp sfp, std::string hex, std::vector<TokenDataStruct> outputs) {
    TxBuilder *bsvTxBuilder = new TxBuilder();
    TokenTransaction *tokenTx = new TokenTransaction(sfp);
    CMutableTransaction tx;
    bool res = DecodeHexTx(tx, hex, true);

    printf("BUILD TOKEN TX: tx.vin.size() = %lu\n", tx.vin.size());

    /*for(size_t i = 0; i < tx.vin.size(); i++) {
        printf("CHECKPOINT 1: \n");
        getChunks(tx.vin[i].scriptSig);
        printf("CHECKPOINT 1 STOP: \n");

        //std::vector<unsigned char> scriptBuf = hexToUchBuffer("0000");
        //CScript script(scriptBuf.begin(), scriptBuf.end());
        //tx.vin[i].scriptSig = script;
    }*/

    /*for (size_t i = 0; i < tx.vin.size(); i++) {
        printf("nSequence: %d\n", tx.vin[i].nSequence);
        printf("txHashBuf: %s\n", tx.vin[i].prevout.hash.GetHex().c_str());
        printf("txOutNum: %d\n", tx.vin[i].prevout.n);
        std::string str(tx.vin[i].scriptSig.begin(), tx.vin[i].scriptSig.end());
        printf("script: %s\n", str.c_str());
    }*/

    /*CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION | 0);
    ssTx << ctx;
    std::string hex_str = HexStr(ssTx);*/
    //CTransaction ctx(tx);
    //std::string hex_str = EncodeHexTx_(ctx, 0);
    //printf("hex_str: %s\n", hex_str.c_str());

    //printf("EncodeTx = %s\n", EncodeHexTx(ctx).c_str());

    //printf("tx.vin[0].prevout.hash.GetHex(): %s\n", tx.vin[0].prevout.hash.GetHex().c_str());

    if(res) printf("DecodeHexTx = true\n");
    else printf("DecodeHexTx = false\n");

    //std::map<std::string, UTxOutData*> uTxOutMap = sfp.recoverUtxosMap(tx.vin);
    std::map<std::string, CTxOut> uTxOutMap = sfp.recoverUtxosMap(tx.vin);
    bsvTxBuilder->importPartiallySignedTx(tx, uTxOutMap);
    tokenTx->importInputs(bsvTxBuilder);
    tokenTx->importOutputs(bsvTxBuilder);
    /*for(int i = 0; i < bsvTxBuilder->tx.vout.size(); i++) {
        OutputData data = sfp.parseOutput(bsvTxBuilder->tx.vout[i].scriptPubKey);
    }*/
    tokenTx->createOutputs(bsvTxBuilder, outputs);
    CDataStream ssTx0(SER_NETWORK, PROTOCOL_VERSION | 0);
    bsvTxBuilder->tx.Serialize(ssTx0);
    std::string hex_str0 = HexStr(ssTx0);
    //printf("CREATE OUTPUTS: %s\n", hex_str0.c_str());

    BuildTokenStruct tokenData;
    tokenData.bsvTxBuilder = bsvTxBuilder;
    tokenData.tokenTx = tokenTx;
    return tokenData;
}

static BuildActionStruct sendSfpBuildAction(std::string hex, std::vector<TokenDataStruct> outputs, std::string path) {
    BuildActionStruct buildAction;

    //printf("SENDSFPBUILDACTIONHEX: %s\n", hex.c_str());

    Sfp sfp("cQLs3wbw3fUCZRe6KyWmu1DE4UmcG2R21NB4TX2fSM6k7uBTFMJA", path);

    BuildTokenStruct tokenData = buildTokenTx(sfp, hex, outputs);

    /*CDataStream ssTx0(SER_NETWORK, PROTOCOL_VERSION | 0);
    tokenData.bsvTxBuilder->tx.Serialize(ssTx0);
    std::string hex_str0 = HexStr(ssTx0);
    printf("bsvTxBuilder.tx.toHex(): %s\n", hex_str0.c_str());*/

    sfp.validate(tokenData.tokenTx);

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION | 0);
    tokenData.bsvTxBuilder->tx.Serialize(ssTx);
    std::string hex_str = HexStr(ssTx);
    //printf("hex_str: %s\n", hex_str.c_str());

    buildAction.hex = hex_str;
    buildAction.sigOperations = tokenData.bsvTxBuilder->sigOperations;

    return buildAction;
}

static void build(TxBuilder *bsvTxBuilder, std::vector<TokenDataStruct> outputs, std::string path) {
    std::map<std::string, std::vector<TokenDataStruct>> outputsByAuthorizer;
  //const failedRequests = []

    /*CDataStream ssTx0(SER_NETWORK, PROTOCOL_VERSION | 0);
    bsvTxBuilder->tx.Serialize(ssTx0);
    std::string hex_str0 = HexStr(ssTx0);
    printf("hex_str0: %s\n", hex_str0.c_str());*/

  for (size_t i = 0; i < outputs.size(); i++) {
        TokenDataStruct output = outputs[i];
        printf("asset = %s\n", output.asset.c_str());

        std::string delimiter = "@";
        std::string domain = output.asset.substr(output.asset.find(delimiter)+1, output.asset.size());
        printf("DOMAIN: %s\n", domain.c_str());

    /*const [, domain] = output.asset.split('@')
    if (!outputsByAuthorizer[domain]) outputsByAuthorizer[domain] = []
    outputsByAuthorizer[domain].push(output)*/
        std::map<std::string, std::vector<TokenDataStruct>>::iterator it = outputsByAuthorizer.find(domain);
        if(it != outputsByAuthorizer.end()) {
            it->second.push_back(output);
        } else {
            std::vector<TokenDataStruct> vec;
            vec.push_back(output);
            outputsByAuthorizer.insert(std::pair<std::string, std::vector<TokenDataStruct>>(domain, vec));
        }
  }

  if (bsvTxBuilder->tx.vin.size() <= 0) {
    //if (bsvTxBuilder->vin.size() <= 0) {
    printf("At least one input needs to be specified\n");
  }

    for(std::map<std::string, std::vector<TokenDataStruct>>::iterator it = outputsByAuthorizer.begin(); it != outputsByAuthorizer.end(); it++) {
        for(size_t i = 0; i < it->second.size(); i++) {
            printf("asset = %s\n", it->second[i].asset.c_str());
            printf("amount = %d\n", it->second[i].amount);
            printf("address = %s\n", it->second[i].address.c_str());
            printf("notes = %s\n", it->second[i].notes.c_str());
        }
    }

    bsvTxBuilder->buildInputs(0, bsvTxBuilder->tx.vin.size() - 1);
    //bsvTxBuilder->buildInputs(0, bsvTxBuilder->vin.size() - 1);

    /*CDataStream ssTx1(SER_NETWORK, PROTOCOL_VERSION | 0);
    bsvTxBuilder->tx.Serialize(ssTx1);
    std::string hex_str1 = HexStr(ssTx1);
    printf("hex_str1: %s\n", hex_str1.c_str());*/

    for(std::map<std::string, std::vector<TokenDataStruct>>::iterator it = outputsByAuthorizer.begin(); it != outputsByAuthorizer.end(); it++) {
        std::string authorizer = it->first;
        std::vector<TokenDataStruct> outputs_ = it->second;

        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION | 0);
        bsvTxBuilder->tx.Serialize(ssTx);
        std::string hex_str = HexStr(ssTx);
        //printf("hex_str: %s\n", hex_str.c_str());

        BuildActionStruct response = sendSfpBuildAction(hex_str, outputs_, path);

        printf("BUILD ACTION HEX: %s\n", response.hex.c_str());

        CMutableTransaction tx;
        bool res = DecodeHexTx(tx, response.hex, true);

        bsvTxBuilder->sigOperations = response.sigOperations;
        bsvTxBuilder->importPartiallySignedTx(tx, bsvTxBuilder->uTxOutMap);

        bsvTxBuilder->vin = bsvTxBuilder->tx.vin;
        bsvTxBuilder->vout = bsvTxBuilder->tx.vout;

        /*CDataStream ssTx1(SER_NETWORK, PROTOCOL_VERSION | 0);
        bsvTxBuilder->tx.Serialize(ssTx1);
        std::string hex_str1 = HexStr(ssTx1);
        printf("hex_str1: %s\n", hex_str1.c_str());*/

        /*for(size_t i = 0; i < bsvTxBuilder->tx.vin.size(); i++) {
            CDataStream ssTx_(SER_NETWORK, PROTOCOL_VERSION | 0);
            bsvTxBuilder->tx.vin[i].Serialize(ssTx_);
            std::string hex_ = HexStr(ssTx_);
            printf("hex_ = %s\n", hex_.c_str());
        }

        for(size_t i = 0; i < bsvTxBuilder->tx.vout.size(); i++) {
            CDataStream ssTx_(SER_NETWORK, PROTOCOL_VERSION | 0);
            bsvTxBuilder->tx.vout[i].Serialize(ssTx_);
            std::string hex_ = HexStr(ssTx_);
            printf("hex_ = %s\n", hex_.c_str());
        }*/

    }

}

void addTokenScripts (TxBuilder *bsvTxBuilder, std::vector<TokenDataStruct> tokenOutputs, std::string path) {
  build(bsvTxBuilder, tokenOutputs, path);
}

void TxBuilder::inputFromScript (uint256 txHashBuf, uint32_t txOutNum, CTxOut txOut, CScript script, uint32_t nSequence) {
  printf("INPUT FROM SCRIPT\n");
  CTxIn txIn;
    txIn.prevout.hash = txHashBuf;
    txIn.prevout.n = txOutNum;
    txIn.scriptSig = script;
    txIn.nSequence = nSequence;
    
    //printf("INPUT FROM SCRIPT PUSHBACK VIN\n");
    //tx.vin.push_back(txIn);
        
    //Input from script needs to go first
    if(vin.size() == 0) {
        vin.push_back(txIn);
    } else {
        CTxIn tmp = vin[vin.size() - 1]; //Should be vin[0]
        vin[vin.size() - 1] = txIn;
        vin.push_back(tmp);
    }
    //std::vector<Chunks> chunks0 = getChunks(tx.vin[tx.vin.size() - 1].scriptSig);
    //printf("CHUNKS tx.vin[] = %lu\n", chunks0.size());
    //std::vector<Chunks> chunks1 = getChunks(vin[vin.size() - 1].scriptSig);
    //printf("CHUNKS vin[] = %lu\n", chunks1.size());




    uTxOutMapSet(uTxOutMap, txHashBuf.GetHex(), txOutNum, txOut);
}

bool TokenTransaction::inputsAmountEqualOutputsAmount () {
    std::map<std::string, int>::iterator it;
    for (it = assetsInputs->assets.begin(); it != assetsInputs->assets.end(); it++) {
        std::string asset = it->first;
        int amount = it->second;
        if (amount != assetsOutputs->sum(asset)) {
            return false;
        }
    }
    return true;
}

bool TokenTransaction::allInputsHaveParam (int position) {
    for (int i = 0; i < inputs.size(); i++) {
        TokenInput *tokenInput = inputs[i];

        if (!tokenInput->hasParam(position)) {
            return false;
        }
    }
    return true;
}

void Sfp::authorize (TxBuilder *bsvTxBuilder, TokenTransaction *tokenTx) {

    if (!tokenTx->allInputsHaveParam(OWNER_SIG)) {
        printf("Inputs need to be signed before authorizing a tx\n");
    }

    if(!tokenTx->inputsAmountEqualOutputsAmount () && !tokenTx->allInputsHaveParam(ISSUER_SIG)) {
        printf("Assets inputs amounts are not equal to assets outputs amount (if you are trying to mint/burn, issuer signature is missing)\n");
    }

    std::vector<KeyPair> keyPairs;
    keyPairs.push_back(authorizerKeyPair);
    bsvTxBuilder->signWithKeyPairs (keyPairs);
    std::vector<unsigned char> script;
    CScript bsvScript(script.begin(), script.end());
    std::vector<unsigned char> ntxid = bsvTxBuilder->sighash(SigOperations::SIGHASH_ALL, 0, bsvScript, 0);
    for(size_t i = 0; i < ntxid.size(); i++) {
        printf("%02x ", ntxid[i]);
    }
    printf("\n");


    std::vector<unsigned char> ntxidSig;

    ECC_Start();

    //std::string ntxid_str = uchbufToString(toLittleEndianUch(ntxid));
    std::string ntxid_str = uchbufToString(ntxid);
    printf("ntxid_str = %s\n", ntxid_str.c_str());
    uint256 ntxid_hash = uint256S(ntxid_str);

    //bool res_message = authorizerKeyPair.PrivKey.Sign(ntxid_hash, ntxidSig);
    bool res_message = authorizerKeyPair.PrivKey.Sign(ntxid_hash, ntxidSig, false, 0);
    printf("ntxidSig:\n");
    for(int i = 0; i < ntxidSig.size(); i++) {
        printf("%02x", ntxidSig[i]);
    }
    printf("\n");

  /*std::vector<unsigned char> ntxidSig2;
  bool res_message2 = authorizerKeyPair.PrivKey.Sign_(ntxid_hash, ntxidSig2, false, 0);
  printf("ntxidSig2:\n");
    for(int i = 0; i < ntxidSig2.size(); i++) {
        printf("%02x", ntxidSig2[i]);
    }
    printf("\n");*/

    if(res_message) printf("SIGN SUCCESS\n");
    else printf("SIGN FAILED\n");

    ECC_Stop();

    ntxidSig.push_back(0);


    for (size_t i = 0; i < tokenTx->inputs.size(); i++) {
        bsvTxBuilder->fillSig(tokenTx->inputs[i]->index, NTXSID_SIG, ntxidSig);
    }

    /*for(size_t i = 0; i < bsvTxBuilder->tx.vin.size(); i++) {
        CDataStream ssTx_(SER_NETWORK, PROTOCOL_VERSION | 0);
        bsvTxBuilder->tx.vin[i].Serialize(ssTx_);
        std::string hex_ = HexStr(ssTx_);
        printf("hex_ = %s\n", hex_.c_str());
    }

    for(size_t i = 0; i < bsvTxBuilder->tx.vout.size(); i++) {
        CDataStream ssTx_(SER_NETWORK, PROTOCOL_VERSION | 0);
        bsvTxBuilder->tx.vout[i].Serialize(ssTx_);
        std::string hex_ = HexStr(ssTx_);
        printf("hex_ = %s\n", hex_.c_str());
    }*/

    /*CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION | 0);
    bsvTxBuilder->tx.Serialize(ssTx);
    std::string hex_str = HexStr(ssTx);
    printf("hex_str = %s\n", hex_str.c_str());

    std::vector<unsigned char> txid_buf = toLittleEndianUch(HashSha256Sha256(hexToUchBuffer(hex_str)));
    for(size_t i = 0; i < txid_buf.size(); i++) {
        printf("%02x ", txid_buf[i]);
    }
    printf("\n");
    */


    /*std::vector<unsigned char> scriptBuf = hexToUchBuffer("0000");
    CScript script_(scriptBuf.begin(), scriptBuf.end());
    bsvTxBuilder->tx.vin[1].scriptSig = script_;*/


    std::string txid = bsvTxBuilder->tx.GetHash().GetHex();
    printf("txid = %s\n", txid.c_str());

    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    char *sql;

    //rc = sqlite3_open("test.db", &db);
    rc = sqlite3_open(path.c_str(), &db);

    if( rc ) {
      fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
    } else {
      fprintf(stderr, "Opened database successfully\n");
    }

    sql = (char *) "BEGIN TRANSACTION;";
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
    if( rc != SQLITE_OK ) {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    } else {
        fprintf(stdout, "Transaction started successfully\n");
    }

    std::map<std::string, AssetStruct> existingAssets;
    std::vector<std::string> aliases = tokenTx->assetsOutputs->aliases();
    for(size_t i = 0; i < aliases.size(); i++) {
        //printf("aliases[%lu] = %s\n", i, aliases[i].c_str());

        Records records;

        std::string sql_query = std::string("SELECT * FROM SFP_ASSETS WHERE ALIAS = '") + aliases[i] + std::string("'");
        //std::string sql_query = std::string("SELECT * FROM ASSETS");
        //printf("sql_query = %s\n", sql_query.c_str());

        sql = (char *) sql_query.c_str();

        rc = sqlite3_exec(db, sql, select_callback, &records, &zErrMsg);
        //rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

        if( rc != SQLITE_OK ) {
            fprintf(stderr, "SQL error: %s\n", zErrMsg);
            sqlite3_free(zErrMsg);
        } else {
            fprintf(stdout, "Operation done successfully\n");
            printf("%lu records returned\n", records.size());
            for(size_t j = 0; j < records.size(); j++) {
                AssetStruct asset_rec;
                asset_rec.id = stoi(records[0][0]);
                //printf("id = %d\n", asset_rec.id);

                asset_rec.alias = records[0][1];
                //printf("alias = %s\n", asset_rec.alias.c_str());

                asset_rec.issuerAddress = records[0][2];
                //printf("issuerAddress = %s\n", asset_rec.issuerAddress.c_str());

                existingAssets.insert(std::pair<std::string, AssetStruct>(asset_rec.alias, asset_rec));

            }
        }
    }

    /*std::map<std::string, AssetStruct>::iterator it;
    for(it = existingAssets.begin(); it != existingAssets.end(); it++) {
        printf("alias: %s\n", it->first.c_str());
        printf("id: %d\n", it->second.id);
        printf("issuerAddresss: %s\n", it->second.issuerAddress.c_str());
    }*/

    for (size_t i = 0; i < tokenTx->outputs.size(); i++) {
        TokenOutput *output = tokenTx->outputs[i];
        if (!tokenTx->assetsInputs->has(output->asset)) {
            /*existingAssets.push(await entityManager.save(assets.create({
                alias: output.asset,
                issuerAddress: output.address
            })))*/
            Records records0;
            size_t id = 1;
            sql = (char *) "SELECT * FROM SFP_ASSETS";
            rc = sqlite3_exec(db, sql, select_callback, &records0, &zErrMsg);
            if( rc != SQLITE_OK ) {
                fprintf(stderr, "SQL error: %s\n", zErrMsg);
                sqlite3_free(zErrMsg);
            } else {
                fprintf(stdout, "Operation done successfully\n");
                printf("%lu records returned\n", records0.size());
                id = id + records0.size();
            }

            //Records records;

            std::string sql_query = std::string("INSERT INTO SFP_ASSETS (ID,ALIAS,ISSUER_ADDRESS) VALUES (") + std::to_string(id) + std::string(", '") \
            + output->asset + std::string("', '") + output->address + std::string("'); ");

             printf("sql_query = %s\n", sql_query.c_str());

             sql = (char *) sql_query.c_str();
            rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
             //rc = sqlite3_exec(db, sql, select_callback, &records, &zErrMsg);

            if( rc != SQLITE_OK ) {
                fprintf(stderr, "SQL error: %s\n", zErrMsg);
                sqlite3_free(zErrMsg);
            } else {
                fprintf(stdout, "Operation done successfully\n");

                AssetStruct asset_rec;
                asset_rec.id = id;
                printf("id = %zu\n", id);

                asset_rec.alias = output->asset;
                printf("alias = %s\n", output->asset.c_str());

                asset_rec.issuerAddress = output->address;
                printf("issuerAddress = %s\n", output->address.c_str());

                existingAssets.insert(std::pair<std::string, AssetStruct>(asset_rec.alias, asset_rec));

            }
        }
    }

    for (size_t i = 0; i < tokenTx->outputs.size(); i++) {
        TokenOutput *output = tokenTx->outputs[i];

        std::map<std::string, AssetStruct>::iterator itAsset = existingAssets.find(output->asset);

        if(itAsset != existingAssets.end()) {
            AssetStruct asset = itAsset->second;

            Records records0;
            size_t id = 1;
            sql = (char *) "SELECT * FROM SFP_UTXOS";
            rc = sqlite3_exec(db, sql, select_callback, &records0, &zErrMsg);
            if( rc != SQLITE_OK ) {
                fprintf(stderr, "SQL error: %s\n", zErrMsg);
                sqlite3_free(zErrMsg);
            } else {
                fprintf(stdout, "Operation done successfully\n");
                printf("%lu records returned\n", records0.size());
                id = id + records0.size();
            }

            std::string script_(output->script.begin(), output->script.end());
            std::string script = stringToHex(script_);

            std::string sql_query = std::string("INSERT INTO SFP_UTXOS (ID,ASSET_ID,TXID,VOUT,SCRIPT,SATOSHIS,AMOUNT) VALUES (") + \
            std::to_string(id) + std::string(", ") + \
            std::to_string(asset.id) + std::string(", '") + \
            txid + std::string("', ") + \
            std::to_string(output->index) + std::string(", '") + \
            script + std::string("', '") + \
            std::to_string(output->satoshis) + std::string("', '") + \
            std::to_string(output->amount) + std::string("'); ");

            printf("sql_query = %s\n", sql_query.c_str());

            sql = (char *) sql_query.c_str();
            rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
             //rc = sqlite3_exec(db, sql, select_callback, &records, &zErrMsg);

            if( rc != SQLITE_OK ) {
                fprintf(stderr, "SQL error: %s\n", zErrMsg);
                sqlite3_free(zErrMsg);
            } else {
                fprintf(stdout, "Insert into SFP_UTXOS done successfully\n");
            }
        }

    }



    sql = (char *) "COMMIT;";
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
    if( rc != SQLITE_OK ) {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    } else {
        fprintf(stdout, "Transaction committed successfully\n");
    }

    sqlite3_close(db);

}

bool TokenTransaction::hasMultipleOutputsPerAsset () {
    return outputs.size() != assetsOutputs->assets.size();
}

void TokenTransaction::addInput (TokenInput *tokenData) {
    inputs.push_back(tokenData);
    assetsInputs->add(tokenData->asset, tokenData->amount);
    std::map<std::string,std::string>::iterator it;
    it = issuers.find(tokenData->asset);
    if(it == issuers.end()) {
        issuers.insert(std::pair<std::string,std::string>(tokenData->asset,tokenData->issuer));
    } else {
        it->second = tokenData->issuer;
    }
}

void TokenTransaction::addOutput (TokenOutput *tokenData) {
    //printf("ADD OUTPUT: \n");
    //printf("SATOSHIS: %lld\n", tokenData->satoshis);
    std::string script_(tokenData->script.begin(), tokenData->script.end());
    std::string script = stringToHex(script_);
    //printf("SCRIPT: %s\n", script.c_str());
    outputs.push_back(tokenData);
    assetsOutputs->add(tokenData->asset, tokenData->amount);
}

void TokenTransaction::importInputs (TxBuilder *bsvTxBuilder) {
  printf("IMPORT INPUTS\n");
    inputs.clear();
    assetsInputs = new AssetsAggregator;
    if (bsvTxBuilder->tx.vin.size() == 0) {
        printf("At least one input needs to be specified\n");
    }

    for (size_t index = 0; index < bsvTxBuilder->tx.vin.size(); index++) {
        CTxIn txIn = bsvTxBuilder->tx.vin[index];

        CTxOut txOut;
        bool res = uTxOutMapGet(bsvTxBuilder->uTxOutMap, txIn.prevout.hash.GetHex(), txIn.prevout.n, txOut);

        if (res) {
            //const tokenInput = this.sfp.parseOutput(uTxOut.script)
            printf("Found uTxOut\n");

            OutputData tokenInput = sfp.parseOutput (txOut.scriptPubKey);

            TokenDataStruct tokenInputData;
            tokenInputData.asset = tokenInput.asset;
            tokenInputData.amount = tokenInput.amount;
            tokenInputData.address = tokenInput.address;
            tokenInputData.authorizer = tokenInput.authorizer;
            tokenInputData.notes = tokenInput.notes;
            tokenInputData.issuer = tokenInput.issuer;
            tokenInputData.state = tokenInput.state;

            addInput(new TokenInput(index, tokenInputData, txIn));

            //std::vector<Chunks> chunks = getChunks(bsvTxBuilder->tx.vin[index].scriptSig);
            //printf("BEFORE CHUNKS = %lu\n", chunks.size());

            sfp.addUnlockScript (tokenInput, bsvTxBuilder->tx.vin[index], bsvTxBuilder);

            //std::vector<Chunks> chunks1 = getChunks(bsvTxBuilder->tx.vin[index].scriptSig);
            //printf("AFTER CHUNKS = %lu\n", chunks1.size());

            std::string script(bsvTxBuilder->tx.vin[index].scriptSig.begin(), bsvTxBuilder->tx.vin[index].scriptSig.end());
            printf("UNLOCKSCRIPT: %s\n", stringToHex(script).c_str());

        }

    }
}

void TokenTransaction::importOutputs (TxBuilder *bsvTxBuilder) {

    for (size_t index = 0; index < bsvTxBuilder->tx.vout.size(); index++) {
        CTxOut txOut = bsvTxBuilder->tx.vout[index];

        /*CScript::const_iterator pc = txOut.scriptPubKey.begin();
        while(pc != txOut.scriptPubKey.end()) {
            unsigned int opcode = *pc++;
            printf("%u", opcode);
        }
        printf("\n");
        */
        /*std::vector<unsigned char> pvchRet;
        pvchRet.assign(txOut.scriptPubKey.begin(), txOut.scriptPubKey.end());
        std::string s(pvchRet.begin(), pvchRet.end());
        printf("pvchRet: %s\n", stringToHex(s).c_str());*/
        OutputData data = sfp.parseOutput(txOut.scriptPubKey);

        //printf("data.linkPrevOutpoint.txid = %s\n", data.linkPrevOutpoint.hash.GetHex().c_str());
        //printf("data.linkPrevOutpoint.vout = %d\n", data.linkPrevOutpoint.n);

        if(data.linkPrevOutpoint.hash.GetHex() != std::string("0000000000000000000000000000000000000000000000000000000000000000")) {

            COutPoint linkedTxIn;

            for(size_t i = 0; i < bsvTxBuilder->tx.vin.size(); i++) {
                CTxIn txIn = bsvTxBuilder->tx.vin[i];
                printf("txid: %s\n", txIn.prevout.hash.GetHex().c_str());

                std::string txid_reverse = bufferToString(toLittleEndian(stringToBuffer(txIn.prevout.hash.GetHex())));

                if((txid_reverse == data.linkPrevOutpoint.hash.GetHex()) && (txIn.prevout.n == data.linkPrevOutpoint.n)) {
                    printf("txid reverse: %s\n", txid_reverse.c_str());
                    printf("vout: %d\n", txIn.prevout.n);
                    //linkedTxIn.hash = data.linkPrevOutpoint.hash;
                    linkedTxIn.hash = txIn.prevout.hash;
                    linkedTxIn.n = data.linkPrevOutpoint.n;
                    break;
                }
            }
            TokenDataStruct tokenOutputData;
            tokenOutputData.asset = data.asset;
            tokenOutputData.amount = data.amount;
            tokenOutputData.address = data.address;
            tokenOutputData.authorizer = data.authorizer;
            tokenOutputData.notes = data.notes;
            tokenOutputData.issuer = data.issuer;
            tokenOutputData.state = data.state;

            printf("IMPORT OUTPUTS: \n");
            addOutput(new TokenOutput(index, tokenOutputData, txOut));
            setScript(txOut, sfp.createOutput(tokenOutputData, linkedTxIn));

        }

    }
}

void Sfp::validate (TokenTransaction *tokenTx) {
    printf("SFP VALIDATE\n");
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    char *sql;

    /* Open database */
    //rc = sqlite3_open("test.db", &db);
    rc = sqlite3_open(path.c_str(), &db);

    if( rc ) {
      fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
    } else {
      fprintf(stderr, "Opened database successfully\n");
    }

    std::map<std::string, AssetStruct> existingAssets;
    for(size_t i = 0; i < tokenTx->outputs.size(); i++) {
        printf("aliases[%lu] = %s\n", i, tokenTx->outputs[i]->asset.c_str());

        Records records;

        std::string sql_query = std::string("SELECT * FROM SFP_ASSETS WHERE ALIAS = '") + tokenTx->outputs[i]->asset + std::string("'");
        //std::string sql_query = std::string("SELECT * FROM ASSETS");
        printf("sql_query = %s\n", sql_query.c_str());

        sql = (char *) sql_query.c_str();

        rc = sqlite3_exec(db, sql, select_callback, &records, &zErrMsg);
        //rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

        if( rc != SQLITE_OK ) {
            fprintf(stderr, "SQL error: %s\n", zErrMsg);
            sqlite3_free(zErrMsg);
        } else {
            fprintf(stdout, "Operation done successfully\n");
            printf("%lu records returned\n", records.size());
            for(size_t i = 0; i < records.size(); i++) {
                AssetStruct asset_rec;
                asset_rec.id = stoi(records[0][0]);
                printf("id = %d\n", asset_rec.id);

                asset_rec.alias = records[0][1];
                printf("alias = %s\n", asset_rec.alias.c_str());

                asset_rec.issuerAddress = records[0][2];
                printf("issuerAddress = %s\n", asset_rec.issuerAddress.c_str());

                existingAssets.insert(std::pair<std::string, AssetStruct>(asset_rec.alias, asset_rec));

            }
        }
    }

    std::map<std::string,int>::iterator alias;
    for (alias = tokenTx->assetsOutputs->assets.begin(); alias != tokenTx->assetsOutputs->assets.end(); alias++)
    {
        if(!tokenTx->assetsInputs->has(alias->first)) {
            printf("AssetInputs does not have asset %s\n", alias->first.c_str());
            if (tokenTx->hasMultipleOutputsPerAsset()) {
                printf("Minting transaction cannot have duplicated outputs for an asset\n");
            }
            std::map<std::string, AssetStruct>::iterator asset;

            asset = existingAssets.find(alias->first);
            if(asset != existingAssets.end()) {
                printf("Alias already in use: %s\n", alias->first.c_str());
            }
        }
    }


    sqlite3_close(db);
}

static std::string EncodeHexTx_(const CTransaction& tx, const int serializeFlags)
{
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION | serializeFlags);
    ssTx << tx;
    return HexStr(ssTx);
}

void TokenTransaction::setScript(CTxOut& txOut, std::string script_str) {
    std::vector<unsigned char> script_buf = hexToUchBuffer(script_str);
    CScript script(script_buf.begin(), script_buf.end());
    //CScript script(records[0][4].c_str(), sizeof(records[0][4].c_str()));
    txOut.scriptPubKey = script;
}

void TokenTransaction::createOutputs (TxBuilder *bsvTxBuilder, std::vector<TokenDataStruct> outputs) {
    printf("CREATE OUTPUTS\n");
    for (size_t i = 0; i < outputs.size(); i++) {
        TokenDataStruct output = outputs[i];
        std::string issuer;
        if(assetsInputs->has(output.asset)) {
            std::map<std::string, std::string>::iterator it;
            it = issuers.find(output.asset);
            if(it != issuers.end()) {
                issuer = it->second;
            } else {
                issuer = output.address;
            }
        } else {
            issuer = output.address;
        }
        output.issuer = issuer;
    if(bsvTxBuilder->tx.vin.size() > 0) {
          std::string script = sfp.createOutput(output, bsvTxBuilder->tx.vin[0].prevout);
          CTxOut txOut;
          txOut.nValue = (int64_t) sfp.calculateMinimumOutputAmount(script);
          printf("sfp.calculateMinimumOutputAmount = %lld\n", txOut.nValue);
          setScript(txOut, script);

          addOutput(new TokenOutput(bsvTxBuilder->tx.vout.size(), output, txOut));
          bsvTxBuilder->tx.vout.push_back(txOut);
    }
    }
}

bool TxBuilder::isPubKeyHashOut (CScript script) {
    std::vector<Chunks> chunks = getChunks(script);

    if (
            chunks.size() > 4 &&
            chunks[0].opCodeNum == OP_DUP &&
            chunks[1].opCodeNum == OP_HASH160 &&
            chunks[2].buf.size() > 0 &&
            chunks[3].opCodeNum == OP_EQUALVERIFY &&
            chunks[4].opCodeNum == OP_CHECKSIG
    ) {
        return true;
    } else {
        return false;
    }
}

void TxBuilder::fromPubKeyHashTxOut(CTxIn& txIn, uint256 txHashBuf, uint32_t txOutNum, CTxOut txOut, std::vector<unsigned char> pubKey) {
    CScript script;
    if (isPubKeyHashOut(txOut.scriptPubKey)) {
        writeOpCode(script, OP_0);
        if (pubKey.size() > 0) {
            writeBuffer(script, pubKey);
        } else {
            writeOpCode(script, OP_0);
        }
    }
    txIn.prevout.hash = txHashBuf;
  printf("txIn.prevout.hash = %s\n", txIn.prevout.hash.GetHex().c_str());
    txIn.prevout.n = txOutNum;
  //printf("txIn.prevout.n = %u\n", txIn.prevout.n);
    txIn.scriptSig = script;
  std::string str(txIn.scriptSig.begin(), txIn.scriptSig.end());
  printf("txIn.scriptSig = %s\n", str.c_str());
}

std::string TxBuilder::fromTxOutScriptOriginal (CScript script) {
    std::vector<Chunks> chunks = getChunks(script);

    std::string address = EncodeBase58Check(hexToUchBuffer(chunks[2].buf));

    return address;
}

std::string TxBuilder::fromTxOutScript (CScript script) {
    std::vector<Chunks> chunks = getChunks(script);

    #if MAINNET
        std::string pubKeyHash("00");
    #else
        std::string pubKeyHash("6f");
    #endif

    std::string str = pubKeyHash + chunks[2].buf;


    std::string address = EncodeBase58Check(hexToUchBuffer(str));

    return address;
}

CScript TxBuilder::toTxOutScript (std::string address) {
    std::vector<unsigned char> vchRet;
    int max_ret_len = 100;
    bool res = DecodeBase58Check(address, vchRet, max_ret_len);

    std::vector<unsigned char> vchRet2;
    for(size_t i = 1; i < vchRet.size(); i++) {
        vchRet2.push_back(vchRet[i]);
    }

    CScript script;
    writeOpCode(script, OP_DUP);
    writeOpCode(script, OP_HASH160);
    //writeBuffer(script, vchRet);
    writeBuffer(script, vchRet2);
    writeOpCode(script, OP_EQUALVERIFY);
    writeOpCode(script, OP_CHECKSIG);

    return script;
}

void TxBuilder::inputFromPubKeyHash (uint256 txHashBuf, uint32_t txOutNum, CTxOut txOut, std::vector<unsigned char> pubKey, uint32_t nSequence, unsigned long nHashType) {
  printf("INPUT FROM PUBKEYHASH\n");
  CTxIn txIn;
    txIn.nSequence = nSequence;
    fromPubKeyHashTxOut(txIn, txHashBuf, txOutNum, txOut, pubKey);
    //printf("INPUT FROM PUB KEY HASH PUSHBACK VIN\n");
    vin.push_back(txIn);
    //tx.vin.push_back(txIn);
    //std::vector<Chunks> chunks0 = getChunks(tx.vin[tx.vin.size() - 1].scriptSig);
    //printf("CHUNKS tx.vin[] = %lu\n", chunks0.size());
    //std::vector<Chunks> chunks1 = getChunks(vin[vin.size() - 1].scriptSig);
    //printf("CHUNKS vin[] = %lu\n", chunks1.size());

    uTxOutMapSet(uTxOutMap, txHashBuf.GetHex(), txOutNum, txOut);
    //std::string address = fromTxOutScript(txOut.scriptPubKey);
    std::string address = fromTxOutScript(txOut.scriptPubKey);
    addSigOperation(txHashBuf, txOutNum, 0, std::string("sig"), address, nHashType);
    addSigOperation(txHashBuf, txOutNum, 1, std::string("pubKey"), address);
}

static void importUtxosIntoTxBuilder2 (TxBuilder *bsvTxBuilder, std::string txid, uint32_t vout, int64_t satoshis, CScript script, std::string address) {

    //const { txid, vout, script, satoshis, address, asset_id: assetId } = utxo

    //if (assetId) {
      /*bsvTxBuilder.inputFromScript(
        Buffer.from(txid, 'hex').reverse(),
        vout,
        bsv.TxOut.fromProperties(
          bsv.Bn().fromNumber(Number(satoshis)),
          bsv.Script.fromHex(script)
        ),
        bsv.Script.fromString('')
      )
      bsvTxBuilder.sigOperations.setMany(
        Buffer.from(txid, 'hex').reverse(),
        vout,
        []
      )*/
    // else {
        CTxOut txOut;
        txOut.nValue = satoshis;
        txOut.scriptPubKey = bsvTxBuilder->toTxOutScript(address);

        std::vector<unsigned char> pubKey;
        unsigned long nHashType = SigOperations::SIGHASH_ALL | SigOperations::SIGHASH_FORKID;

        uint256 txHashBuf = uint256S(txid);
    bsvTxBuilder->inputFromPubKeyHash(txHashBuf, vout, txOut, pubKey, -1, nHashType);
    //}
}

static bool hasEnoughInputs (TxBuilder *bsvTxBuilder) {
  bool res = bsvTxBuilder->build(true);
  return res;
}

static bool isTxIn (CTxIn txIn, Utxo utxo) {
    printf("txIn = %s\n", txIn.prevout.hash.GetHex().c_str());
    printf("utxo.txid = %s\n", utxo.txid.c_str());

    return txIn.prevout.hash.GetHex() == utxo.txid && \
    txIn.prevout.n == (uint32_t) utxo.vout;
  //Buffer.from(txIn.txHashBuf).reverse().toString('hex') === utxo.txid &&
  //txIn.txOutNum === utxo.vout
}

/*static void addTxBuilderInputs (TxBuilder *bsvTxBuilder, std::string txid, uint32_t vout, int64_t satoshis, CScript script, std::string address) {

  importUtxosIntoTxBuilder2(bsvTxBuilder, txid, vout, satoshis, script, address);

    bsvTxBuilder->build(true);

}*/

static void addTxBuilderInputs (TxBuilder *bsvTxBuilder, int64_t walletId, std::string path) {
    std::vector<Utxo> unspentOutputs;

    for (int count = 0; count < TRANSACTION_MAX_INPUTS; ++count) {
    //for (int count = 0; count < 2; ++count) {
        if (bsvTxBuilder->vin.size() && hasEnoughInputs(bsvTxBuilder)) {
      break;
    }

        sqlite3 *db;
        char *zErrMsg = 0;
        int rc;
        char *sql;

        //rc = sqlite3_open("test.db", &db);
        rc = sqlite3_open(path.c_str(), &db);

        if( rc ) {
          fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
          return;
        } else {
          fprintf(stderr, "Opened database successfully\n");
        }

        Records records;
        std::string sql_query = std::string("SELECT * FROM UTXOS WHERE WALLET_ID = ") + std::to_string(walletId) + \
        std::string(" AND ASSET_ID = 0 AND SPENT_TXID = '' ORDER BY ID; ");
        printf("sql_query: %s\n", sql_query.c_str());
        //sql = (char *) "SELECT * FROM ASSETS";
        sql = (char *) sql_query.c_str();
        rc = sqlite3_exec(db, sql, select_callback, &records, &zErrMsg);
        //sqlite3_exec(db, sql, callback, 0, &zErrMsg);
        if( rc != SQLITE_OK ) {
            fprintf(stderr, "SQL error: %s\n", zErrMsg);
            sqlite3_free(zErrMsg);
        } else {
            fprintf(stdout, "Operation done successfully\n");
            printf("%lu records returned\n", records.size());

            for(size_t i = 0; i < records.size(); i++) {
                Utxo utxo;

                utxo.id = (int64_t) std::stoll(records[i][0]);
                utxo.utxo_id = records[i][1];
                utxo.wallet_id = (int64_t) std::stoll(records[i][2]);
                utxo.from_wallet_id = (int64_t) std::stoll(records[i][3]);
                utxo.satoshis = (int64_t) std::stoll(records[i][4]);
                utxo.address = records[i][5];
                utxo.address_index = (int64_t) std::stoll(records[i][6]);
                utxo.txid = records[i][7];
                utxo.vout = (int) std::stoi(records[i][8]);
                utxo.script = records[i][9];
                utxo.spent_txid = records[i][10];
                utxo.amount = (int64_t) std::stoll(records[i][11]);
                utxo.asset_id = (int64_t) std::stoll(records[i][12]);

                unspentOutputs.push_back(utxo);
            }

            if (unspentOutputs.size() == 0) {
        printf("Insufficient balance\n");
        return;
      }

            Utxo utxo = unspentOutputs[0];
            unspentOutputs.erase(unspentOutputs.begin());

            for(size_t i = 0; i < bsvTxBuilder->vin.size(); i++) {
                if(isTxIn(bsvTxBuilder->vin[i], utxo)) {
                    continue;
                }
            }
            std::vector<Utxo> utxos;
            utxos.push_back(utxo);

            importUtxosIntoTxBuilder (bsvTxBuilder, utxos);

        }

        sqlite3_close(db);
    }

}

static void initializeAddresses(std::string path) {
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    char *sql;

    //rc = sqlite3_open("test.db", &db);
    rc = sqlite3_open(path.c_str(), &db);

    if( rc ) {
      fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
      return;
    } else {
      fprintf(stderr, "Opened database successfully\n");
    }

    sql = (char *) "DROP TABLE ADDRESSES;";
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

    sql = (char *) "CREATE TABLE ADDRESSES("  \
      "ID INT PRIMARY KEY     NOT NULL," \
        "WALLET_ID       BIGINT," \
        "ADDRESS       CHAR(255)," \
        "ADDRESS_INDEX  INT );";

    /* Execute SQL statement */
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

    if( rc != SQLITE_OK ){
      fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
    } else {
      fprintf(stdout, "ADDRESSES Table created successfully\n");
    }

    sql = (char *) "INSERT INTO ADDRESSES (ID,WALLET_ID,ADDRESS,ADDRESS_INDEX) "  \
         "VALUES (1, 2, 'mhWYLCXz1Xv7aARrPbZprDTjTb5Q9RvTdm', 0); ";
  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

  sql = (char *) "INSERT INTO ADDRESSES (ID,WALLET_ID,ADDRESS,ADDRESS_INDEX) "  \
         "VALUES (2, 2, 'mr2b9Z1vTGWKLBZ3ipm9i6bwNppqp8bZck', 1); ";
  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

  sql = (char *) "INSERT INTO ADDRESSES (ID,WALLET_ID,ADDRESS,ADDRESS_INDEX) "  \
         "VALUES (3, 2, 'muYaCpRTMvUeqtkTtPM8z3KX3jLK42DaCR', 2); ";
  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

  sql = (char *) "INSERT INTO ADDRESSES (ID,WALLET_ID,ADDRESS,ADDRESS_INDEX) "  \
         "VALUES (4, 2, 'mjvSKk48pYshBy6hchT4Ay9ZCvNKxEo73c', 3); ";
  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

  sql = (char *) "INSERT INTO ADDRESSES (ID,WALLET_ID,ADDRESS,ADDRESS_INDEX) "  \
         "VALUES (5, 2, 'mkGQ4dDS7HYkEaEkfDic5qC1CMi3GCRsys', 4); ";
  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

  sql = (char *) "INSERT INTO ADDRESSES (ID,WALLET_ID,ADDRESS,ADDRESS_INDEX) "  \
         "VALUES (6, 2, 'mtGgN5HMweLa3ypzVuFVEd9JEgCAKGEpgW', 5); ";
  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

  sql = (char *) "INSERT INTO ADDRESSES (ID,WALLET_ID,ADDRESS,ADDRESS_INDEX) "  \
         "VALUES (7, 3, 'n2wtGEFnzxzGN273a8fZ18UngBhD72KJU3', 0); ";
  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

  sql = (char *) "INSERT INTO ADDRESSES (ID,WALLET_ID,ADDRESS,ADDRESS_INDEX) "  \
         "VALUES (8, 3, 'n1ADqDXZdKqrrs7jnKg5eqjTa9KeVmEgyQ', 1); ";
  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

  sql = (char *) "INSERT INTO ADDRESSES (ID,WALLET_ID,ADDRESS,ADDRESS_INDEX) "  \
         "VALUES (9, 2, 'mxMFoqgirJuT5iP1ZrmeVaAQc281Uwc46r', 6); ";
  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

  sql = (char *) "INSERT INTO ADDRESSES (ID,WALLET_ID,ADDRESS,ADDRESS_INDEX) "  \
         "VALUES (10, 2, 'mkk9en83NYBCa53f8rRbvAwno1S81xpQTw', 7); ";
  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

  sql = (char *) "INSERT INTO ADDRESSES (ID,WALLET_ID,ADDRESS,ADDRESS_INDEX) "  \
         "VALUES (11, 2, 'mmugasXg65VVv54t4UUejVqA4JB6d86S2q', 8); ";
  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

  sql = (char *) "INSERT INTO ADDRESSES (ID,WALLET_ID,ADDRESS,ADDRESS_INDEX) "  \
         "VALUES (12, 2, 'n4HawVttbCdh1HsSKTWtto9Dg2kAfydApU', 9); ";
  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

  sql = (char *) "INSERT INTO ADDRESSES (ID,WALLET_ID,ADDRESS,ADDRESS_INDEX) "  \
         "VALUES (13, 2, 'mrYBqezyanhQi8Te3HF5rNUdeLHjCWH9iC', 10); ";
  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

  sql = (char *) "INSERT INTO ADDRESSES (ID,WALLET_ID,ADDRESS,ADDRESS_INDEX) "  \
         "VALUES (14, 3, 'moyZRWuEXttPgJ84NaUesjHQTR4fC2Q4gQ', 2); ";
  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

  sql = (char *) "INSERT INTO ADDRESSES (ID,WALLET_ID,ADDRESS,ADDRESS_INDEX) "  \
         "VALUES (15, 2, 'mmDRTJXgSCRmapL4pLtH3Y2b7QfoZFdRAL', 11); ";
  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

  sql = (char *) "INSERT INTO ADDRESSES (ID,WALLET_ID,ADDRESS,ADDRESS_INDEX) "  \
         "VALUES (16, 2, 'mhKqa18LtKu2xtZjQrAMhGtV8dhcePW7J4', 12); ";
  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

  if( rc != SQLITE_OK ){
     fprintf(stderr, "SQL error: %s\n", zErrMsg);
     sqlite3_free(zErrMsg);
  } else {
     fprintf(stdout, "Address created successfully\n");
  }

    sqlite3_close(db);

}



/*static bool Derive_(CExtKey& in, CExtKey &out, unsigned int _nChild) {
    out.nDepth = in.nDepth + 1;
    CKeyID id = in.key.GetPubKey().GetID();
    memcpy(out.vchFingerprint, &id, 4);
    out.nChild = _nChild;
    return in.key.Derive(out.key, out.chaincode, _nChild, in.chaincode);
}*/

/*int BytesToKeySHA512AES_(const std::vector<unsigned char>& chSalt, const SecureString& strKeyData, int count, unsigned char *key,unsigned char *iv)
{
    // This mimics the behavior of openssl's EVP_BytesToKey with an aes256cbc
    // cipher and sha512 message digest. Because sha512's output size (64b) is
    // greater than the aes256 block size (16b) + aes256 key size (32b),
    // there's no need to process more than once (D_0).

        if(!count) printf("COUNT IS 0\n");
        if(!key) printf("KEY IS 0\n");
        if(!iv) printf("IV IS 0\n");

    if(!count || !key || !iv)
        return 0;

        printf("KEY: %s\n", strKeyData.data());

        std::vector<unsigned char> chSalt_ = (std::vector<unsigned char>) chSalt;

        char ch[9];
        sprintf(ch, "%08x", 1);
        //printf("%s\n", ch);
        std::string str(ch);

        std::vector<unsigned char> strBuf = hexToUchBuffer(str);

        for(size_t i = 0; i < strBuf.size(); i++) {
            chSalt_.push_back(strBuf[i]);
        }

        printf("SALT: \n");
        for(size_t i = 0; i < chSalt_.size(); i++) {
            printf("%02x", chSalt_[i]);
        }
        printf("\n");

        const SecureString salt = "6d6e656d6f6e696300000001";

        std::string mnemonic("turkey bird toddler amused nephew nominee review useless hover music outdoor sweet");

        std::vector<unsigned char> mnemonicBuf = hexToUchBuffer(stringToHex(mnemonic));
        printf("Mneumonic Buf: \n");
        for(size_t i = 0; i < mnemonicBuf.size(); i++) {
            printf("%02x", mnemonicBuf[i]);
        }
        printf("\n");*/

        /*std::string salt2("c719ab5b5bc80605b491cf9753b33b187b6f3a62f0746569f1a82d01f49aad58190ca0e0f0c26457233057056b0bd931b87c8f71847b7614b15222e436334a08");
        std::vector<unsigned char> salt2Buf = hexToUchBuffer(salt2);
        printf("SALT2: \n");
        for(size_t i = 0; i < salt2Buf.size(); i++) {
            printf("%02x", salt2Buf[i]);
        }
        printf("\n");*/

    /*unsigned char buf[CSHA512::OUTPUT_SIZE];
    CSHA512 di;

        //const SecureString str1 = "4243445d534f16545f445216425952525a534416575b43455352165853465e53411658595b5f585353164453405f5341164345535a534545165e59405344165b43455f55165943425259594416454153534236363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636";
        std::string str1("4243445d534f16545f445216425952525a534416575b43455352165853465e53411658595b5f585353164453405f5341164345535a534545165e59405344165b43455f55165943425259594416454153534236363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636");
        std::vector<unsigned char> str1Buf = hexToUchBuffer(str1);

        //di.Write((const unsigned char*)str1.data(), str1.size());
        di.Write(str1Buf.data(), str1Buf.size());
    di.Finalize(buf);
        di.Reset();

        //const SecureString str2 = "28292e3739257c3e352e387c2833383830392e7c3d31292f39387c32392c34392b7c323331353239397c2e392a35392b7c292f3930392f2f7c34332a392e7c31292f353f7c3329283833332e7c2f2b3939285c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c";
        //const SecureString str3 = "c719ab5b5bc80605b491cf9753b33b187b6f3a62f0746569f1a82d01f49aad58190ca0e0f0c26457233057056b0bd931b87c8f71847b7614b15222e436334a08";
        std::string str2("28292e3739257c3e352e387c2833383830392e7c3d31292f39387c32392c34392b7c323331353239397c2e392a35392b7c292f3930392f2f7c34332a392e7c31292f353f7c3329283833332e7c2f2b3939285c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c");
        std::vector<unsigned char> str2Buf = hexToUchBuffer(str2);

        std::string str3("c719ab5b5bc80605b491cf9753b33b187b6f3a62f0746569f1a82d01f49aad58190ca0e0f0c26457233057056b0bd931b87c8f71847b7614b15222e436334a08");
        std::vector<unsigned char> str3Buf = hexToUchBuffer(str3);

        //di.Write((const unsigned char*)str2.data(), str2.size());
        //di.Write((const unsigned char*)str3.data(), str3.size());
        di.Write(str2Buf.data(), str2Buf.size());
        di.Write(str3Buf.data(), str3Buf.size());
        di.Finalize(buf);
        di.Reset();

    //di.Write((const unsigned char*)strKeyData.data(), strKeyData.size());
        //di.Write((const unsigned char*)salt.data(), salt.size());
        //di.Write(mnemonicBuf.data(), mnemonicBuf.size());
    //di.Write(chSalt.data(), chSalt.size());
        //di.Write(chSalt_.data(), chSalt_.size());
        //di.Write(salt2Buf.data(), salt2Buf.size());
    di.Finalize(buf);

        printf("BUF: \n");
        for(size_t i = 0; i < CSHA512::OUTPUT_SIZE; i++) {
            printf("%02x", buf[i]);
        }
        printf("\n");

    for(int i = 0; i != count - 1; i++)
        di.Reset().Write(buf, sizeof(buf)).Finalize(buf);

        //std::string bufStr(buf);
        //printf("BUF = %s\n", stringToHex(bufStr).c_str());

        printf("BUF: \n");
        for(size_t i = 0; i < CSHA512::OUTPUT_SIZE; i++) {
            printf("%02x", buf[i]);
        }
        printf("\n");

        printf("CSHA512::OUTPUT_SIZE = %zu\n", CSHA512::OUTPUT_SIZE);
        printf("wallet::WALLET_CRYPTO_KEY_SIZE = %u\n", wallet::WALLET_CRYPTO_KEY_SIZE);
        printf("wallet::WALLET_CRYPTO_IV_SIZE = %u\n", wallet::WALLET_CRYPTO_IV_SIZE);

    memcpy(key, buf, wallet::WALLET_CRYPTO_KEY_SIZE);
    //memcpy(iv, buf + wallet::WALLET_CRYPTO_KEY_SIZE, wallet::WALLET_CRYPTO_IV_SIZE);
    memory_cleanse(buf, sizeof(buf));
    return wallet::WALLET_CRYPTO_KEY_SIZE;
}*/

//int BytesToKeySHA512AES_(const std::vector<unsigned char>& chSalt, const SecureString& strKeyData, int count, unsigned char *key,unsigned char *iv)
int BytesToKeySHA512AES_(const std::vector<unsigned char>& strKeyData, const std::vector<unsigned char>& chSalt, int count, unsigned char *key)
{
    // This mimics the behavior of openssl's EVP_BytesToKey with an aes256cbc
    // cipher and sha512 message digest. Because sha512's output size (64b) is
    // greater than the aes256 block size (16b) + aes256 key size (32b),
    // there's no need to process more than once (D_0).

        if(!count) printf("COUNT IS 0\n");
        if(!key) printf("KEY IS 0\n");

    if(!count || !key)
        return 0;

        //printf("KEY: %s\n", strKeyData.data());

        /*std::string mnemonic("turkey bird toddler amused nephew nominee review useless hover music outdoor sweet");

        std::vector<unsigned char> mnemonicBuf = hexToUchBuffer(stringToHex(mnemonic));
        printf("Mneumonic Buf: \n");
        for(size_t i = 0; i < mnemonicBuf.size(); i++) {
            printf("%02x", mnemonicBuf[i]);
        }
        printf("\n");*/

        std::vector<unsigned char> chSalt_ = (std::vector<unsigned char>) chSalt;

        char ch[9];
        sprintf(ch, "%08x", 1);
        //printf("%s\n", ch);
        std::string str(ch);

        std::vector<unsigned char> strBuf = hexToUchBuffer(str);

        for(size_t i = 0; i < strBuf.size(); i++) {
            chSalt_.push_back(strBuf[i]);
        }

        printf("SALT: \n");
        for(size_t i = 0; i < chSalt_.size(); i++) {
            printf("%02x", chSalt_[i]);
        }
        printf("\n");


    unsigned char buf[CSHA512::OUTPUT_SIZE];
    //CHMAC_SHA512 di((const unsigned char*)strKeyData.data(), strKeyData.size());
        CHMAC_SHA512 di(strKeyData.data(), strKeyData.size());

        //const SecureString init = "";
        //CHMAC_SHA512 di((const unsigned char*)init.data(), init.size());

    //di.Write((const unsigned char*)strKeyData.data(), strKeyData.size());
        //di.Write(mnemonicBuf.data(), mnemonicBuf.size());
    //di.Write(chSalt.data(), chSalt.size());
        //di.Write(chSalt_.data(), chSalt_.size());
    //di.Finalize(buf);

        di.Write(chSalt_.data(), chSalt_.size());
        di.Finalize(buf);

        printf("BUF: \n");
        for(size_t i = 0; i < CSHA512::OUTPUT_SIZE; i++) {
            printf("%02x", buf[i]);
        }
        printf("\n");

        unsigned char buf_[CSHA512::OUTPUT_SIZE];
        for(size_t i = 0; i < sizeof(buf); i++)
            buf_[i] = buf[i];

    for(int i = 0; i != count - 1; i++) {
            CHMAC_SHA512 di_(strKeyData.data(), strKeyData.size());
            di_.Write(buf_, sizeof(buf_)).Finalize(buf_);
            //di_.Finalize(buf_);

            /*printf("BUF_: \n");
            for(size_t i = 0; i < CSHA512::OUTPUT_SIZE; i++) {
                printf("%02x", buf_[i]);
            }
            printf("\n");*/

            for (size_t k = 0; k < CSHA512::OUTPUT_SIZE; k++) buf[k] ^= buf_[k];
        }

        //std::string bufStr(buf);
        //printf("BUF = %s\n", stringToHex(bufStr).c_str());

        printf("BUF: \n");
        for(size_t i = 0; i < CSHA512::OUTPUT_SIZE; i++) {
            printf("%02x", buf[i]);
        }
        printf("\n");

        printf("CSHA512::OUTPUT_SIZE = %zu\n", CSHA512::OUTPUT_SIZE);
        printf("wallet::WALLET_CRYPTO_KEY_SIZE = %u\n", wallet::WALLET_CRYPTO_KEY_SIZE);
        printf("wallet::WALLET_CRYPTO_IV_SIZE = %u\n", wallet::WALLET_CRYPTO_IV_SIZE);

    memcpy(key, buf, CSHA512::OUTPUT_SIZE);
    //memcpy(iv, buf + wallet::WALLET_CRYPTO_KEY_SIZE, wallet::WALLET_CRYPTO_IV_SIZE);
    memory_cleanse(buf, sizeof(buf));
    return wallet::WALLET_CRYPTO_KEY_SIZE;
}

typedef struct AddressData {
    int64_t walletId;
    int addressIndex;
} AddressData;

static bool getUtxoAddressIfPresent (AddressData& data, std::string address, std::string path) {

    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    char *sql;

    /* Open database */
    //rc = sqlite3_open("test.db", &db);
    rc = sqlite3_open(path.c_str(), &db);

    if( rc ) {
      fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return false;
    } else {
      fprintf(stderr, "Opened database successfully\n");
    }

    Records records;

    std::string sql_query = std::string("SELECT * FROM ADDRESSES WHERE ADDRESS = '") + address + std::string("' LIMIT 1");

    /* Create SQL statement */
    sql = (char *) sql_query.c_str();

    /* Execute SQL statement */
    rc = sqlite3_exec(db, sql, select_callback, &records, &zErrMsg);

    sqlite3_close(db);

    if( rc != SQLITE_OK ) {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    } else {
        fprintf(stdout, "Operation done successfully\n");
    if(records.size() == 0) printf("sql_query = %s\n", sql_query.c_str());
    if(records.size() == 0) printf("address = %s\n", address.c_str());
        printf("%lu records returned\n", records.size());

        if(records.size() > 0) {
            data.walletId = (int64_t) std::stoll(records[0][1]);
            data.addressIndex = (int) std::stoi(records[0][3]);
            return true;
        }
    }
    return false;
}

bool TxBuilder::isPubKeyHashIn (CScript script) {
    std::vector<Chunks> chunks = getChunks(script);

    if (
        chunks.size() == 2 &&
            (chunks[0].buf.size() > 0 || chunks[0].opCodeNum == OP_0) &&
            (chunks[1].buf.size() > 0 || chunks[0].opCodeNum == OP_0)
    ) {
        return true;
    } else {
        return false;
    }
}

std::string TxBuilder::fromTxInScript (CScript script) {

    std::vector<Chunks> chunks = getChunks(script);
    //const pubKeyHashBuf = Hash.sha256Ripemd160(script.chunks[1].buf || Buffer.from('00'.repeat(32), 'hex'))
    //return this.fromPubKeyHashBuf(pubKeyHashBuf)

    //printf("Script.chunks[1].buf = %s\n", chunks[1].buf.c_str());

    std::vector<unsigned char> chunks1Buf = hexToUchBuffer(chunks[1].buf);
    for(size_t i = chunks1Buf.size(); i < 32; i++) {
        chunks1Buf.push_back(0);
    }

    /*for(size_t i = 0; i < chunks1Buf.size(); i++) {
        printf("%02x", chunks1Buf[i]);
    }
    printf("\n");*/

    //std::vector<unsigned char> chunks1Sha256 = hexToUchBuffer(Hash(chunks1Buf).GetHex());

    std::vector<unsigned char> chunks1Sha256;

    unsigned char buf[CSHA256::OUTPUT_SIZE];

    CSHA256 di_;

    di_.Write(chunks1Buf.data(), chunks1Buf.size());
    di_.Finalize(buf);

    //printf("chunks1Sha256: \n");
    for(size_t i = 0; i < CSHA256::OUTPUT_SIZE; i++) {
        //printf("%02x", buf[i]);
        chunks1Sha256.push_back(buf[i]);
    }
    //printf("\n");

    unsigned char pubKeyHashBuf[CRIPEMD160::OUTPUT_SIZE];

    CRIPEMD160 di;

    di.Write(chunks1Sha256.data(), chunks1Sha256.size());
    di.Finalize(pubKeyHashBuf);

    std::vector<unsigned char> pubKeyHashBufVec;

    #if MAINNET
        std::string pubKeyHash("00");
    #else
        std::string pubKeyHash("6f");
    #endif

    std::vector<unsigned char> pubKeyHashPrefix = hexToUchBuffer(pubKeyHash);
    pubKeyHashBufVec.push_back(pubKeyHashPrefix[0]);

    //printf("pubKeyHashBuf: \n");
    for(size_t i = 0; i < CRIPEMD160::OUTPUT_SIZE; i++) {
        //printf("%02x", pubKeyHashBuf[i]);
        pubKeyHashBufVec.push_back(pubKeyHashBuf[i]);
    }
    //printf("\n");

    std::string address = EncodeBase58Check(pubKeyHashBufVec);

    return address;

    //return uchbufToString(pubKeyHashBufVec);
}

static bool isValidUnlockScript (CScript script) {
  int MIN_PARAMS = 6;
    std::vector<Chunks> chunks = getChunks(script);
    
    if(chunks.size() < 5) return false;

    std::string str = hexToString(chunks[4].buf);

    std::string delimiter = "@";
    std::string protocol = str.substr(0, str.find(delimiter));

    //printf("protocol: %s\n", protocol.c_str());

  return chunks.size() >= MIN_PARAMS
    && chunks[4].buf.size() > 0
    && protocol == std::string("sfp");
}

static bool isValidScript (CScript script) {
    std::vector<Chunks> chunks = getChunks(script);

    std::string str = hexToString(chunks[1].buf);

    std::string delimiter = "@";
    std::string protocol = str.substr(0, str.find(delimiter));

    //printf("protocol: %s\n", protocol.c_str());

  return chunks.size() > 5
    && chunks[1].buf.size() > 0
    && protocol == std::string("sfp");
}

static void extractUtxoFromBsvjsTx(std::map<std::string,Utxo>& utxos, std::string transactionHex, std::string path) {
    CMutableTransaction tx;
    bool res = DecodeHexTx(tx, transactionHex, true);
    int64_t fromWalletId = 0;
    std::string txid = tx.GetHash().GetHex();

    //printf("txid: %s\n", txid.c_str());

    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    char *sql;

    //rc = sqlite3_open("test.db", &db);
    rc = sqlite3_open(path.c_str(), &db);

    if( rc ) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return;
    } else {
        fprintf(stderr, "Opened database successfully\n");
    }

    for (size_t i = 0; i < tx.vin.size(); i++) {
        AddressData found;
        std::string address;

        if (TxBuilder::isPubKeyHashIn(tx.vin[i].scriptSig)) {
            address = TxBuilder::fromTxInScript(tx.vin[i].scriptSig);
        } else {
            if(isValidUnlockScript(tx.vin[i].scriptSig)) {
                //address = protocol.getAddressFromUnlockScript(txIn.script)
                address = TxBuilder::fromTxInScript(tx.vin[i].scriptSig);
            }
        }

        //printf("address = %s\n", address.c_str());

        bool foundRes = false;
        if (address.size() > 0) {
            foundRes = getUtxoAddressIfPresent(found, address, path);
        }

        if(foundRes) {
            std::string prevTxHashBuf = tx.vin[i].prevout.hash.GetHex();
            fromWalletId = found.walletId;
            //const utxoId = `${txIn.txOutNum}-${prevTxHashBuf.reverse().toString('hex')}`
            std::string utxoId = std::to_string(tx.vin[i].prevout.n) + std::string("-") + prevTxHashBuf;

            std::map<std::string,Utxo>::iterator it = utxos.find(utxoId);
            if(it != utxos.end()) {
                it->second.utxo_id = utxoId;
                it->second.spent_txid = txid;
            } else {
                Utxo utxo;
                utxo.utxo_id = utxoId;
                utxo.spent_txid = txid;
                utxos[utxoId] = utxo;
            }
        }
    }

    uint32_t vout = 0;
    for (size_t i = 0; i < tx.vout.size(); i++) {
        AddressData found;
        std::string address;
        OutputData token;
        token.amount = 0;

        int64_t id = 1;

        if(TxBuilder::isPubKeyHashOut (tx.vout[i].scriptPubKey)) {
            address = TxBuilder::fromTxOutScript(tx.vout[i].scriptPubKey);
        } else {
            if(isValidScript (tx.vout[i].scriptPubKey)) {
                Sfp sfp;
                token = sfp.parseOutput (tx.vout[i].scriptPubKey);

                std::string delimiter = "@";
                std::string alias = token.asset.substr(0,token.asset.find(delimiter));

                printf("token alias = %s\n", alias.c_str());

                Records records;


                std::string sql_query = std::string("SELECT * FROM ASSETS WHERE PAYMAIL_ALIAS = '") + alias + std::string("' AND MINTING_SCRIPT = '") \
        + uchbufToString(scriptToBuffer(tx.vout[i].scriptPubKey)) + std::string("'; ");
                printf("sql_query: %s\n", sql_query.c_str());
                //sql = (char *) "SELECT * FROM ASSETS";
                sql = (char *) sql_query.c_str();
                rc = sqlite3_exec(db, sql, select_callback, &records, &zErrMsg);
                //sqlite3_exec(db, sql, callback, 0, &zErrMsg);
                if( rc != SQLITE_OK ) {
                    fprintf(stderr, "SQL error: %s\n", zErrMsg);
                    sqlite3_free(zErrMsg);
                } else {
                    fprintf(stdout, "Operation done successfully\n");
                    printf("%lu records returned\n", records.size());

                    if(records.size() == 0) {
                        printf("ASSET NOT FOUND, INSERTING INTO ASSETS\n");
                        Records records0;
                        sql = (char *) "SELECT * FROM ASSETS";
                        rc = sqlite3_exec(db, sql, select_callback, &records0, &zErrMsg);
                        //sqlite3_exec(db, sql, callback, 0, &zErrMsg);
                        if( rc != SQLITE_OK ) {
                            fprintf(stderr, "SQL error: %s\n", zErrMsg);
                            sqlite3_free(zErrMsg);
                        } else {
                            fprintf(stdout, "Operation done successfully\n");
                            printf("%lu records returned\n", records0.size());
                            id = id + (int64_t) records0.size();

                            std::string script(tx.vout[i].scriptPubKey.begin(), tx.vout[i].scriptPubKey.end());

                            std::string sql_query0 = std::string("INSERT INTO ASSETS (ID,INITIAL_SUPPLY,PAYMAIL_ALIAS,MINTING_SCRIPT) VALUES (") + std::to_string(id) + \
              std::string(", ") + std::to_string(token.amount) + std::string(", '") + alias + std::string("', '") + stringToHex(script) + std::string("'); ");

                            sql = (char *) sql_query0.c_str();
              printf("sql_query0 = %s\n", sql_query0.c_str());

                            rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
                            if( rc != SQLITE_OK ) {
                                fprintf(stderr, "SQL error: %s\n", zErrMsg);
                                sqlite3_free(zErrMsg);
                            } else {
                                fprintf(stdout, "Operation done successfully\n");
                            }
                        }
                    } else {
            id = (int64_t) std::stoll(records[0][0]);
          }
                }

                address = token.address;

            }
        }

        //printf("address = %s\n", address.c_str());

        bool foundRes = false;
        if (address.size() > 0) {
            foundRes = getUtxoAddressIfPresent(found, address, path);
        }

        if(foundRes) {
            //const utxoId = `${vout}-${txid}`
            std::string utxoId = std::to_string(vout) + std::string("-") + txid;
            //std::string utxoId = std::to_string(vout) + std::string("-") + bufferToString(toLittleEndian(stringToBuffer(txid)));

            std::map<std::string,Utxo>::iterator it = utxos.find(utxoId);
            if(it != utxos.end()) {
                it->second.utxo_id = utxoId;
                it->second.wallet_id = found.walletId;
                it->second.from_wallet_id = fromWalletId;
                it->second.satoshis = (int64_t) tx.vout[i].nValue;
                it->second.address = address;
                it->second.address_index = found.addressIndex;
                it->second.txid = txid;
                it->second.script = stringToHex(std::string(tx.vout[i].scriptPubKey.begin(), tx.vout[i].scriptPubKey.end()));
                it->second.vout = vout;

                if(token.amount > 0) {
                    it->second.amount = token.amount;
                    it->second.asset_id = id;
                }
            } else {
                Utxo utxo;
                utxo.utxo_id = utxoId;
                utxo.wallet_id = found.walletId;
                utxo.from_wallet_id = fromWalletId;
                utxo.satoshis = (int64_t) tx.vout[i].nValue;
                utxo.address = address;
                utxo.address_index = found.addressIndex;
                utxo.txid = txid;
                utxo.script = stringToHex(std::string(tx.vout[i].scriptPubKey.begin(), tx.vout[i].scriptPubKey.end()));
                utxo.vout = vout;

                if(token.amount > 0) {
                    utxo.amount = token.amount;
                    utxo.asset_id = id;
                }
                utxos[utxoId] = utxo;
            }

        }
        vout++;
    }

    sqlite3_close(db);

}

static std::vector<int> findIndexesByAddresses(int64_t walletId, std::vector<std::string> addressesArray, std::string path) {
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    char *sql;

    std::vector<int> ret;

    //rc = sqlite3_open("test.db", &db);
    rc = sqlite3_open(path.c_str(), &db);

    if( rc ) {
      fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
      return ret;
    } else {
      fprintf(stderr, "Opened database successfully\n");
    }

    Records records;

    std::string sql_query = std::string("SELECT * FROM ADDRESSES WHERE WALLET_ID = ") + std::to_string(walletId);

    if(addressesArray.size() > 0) sql_query = sql_query + std::string(" AND");
    for(size_t i = 0; i < addressesArray.size(); i++) {
        sql_query = sql_query + std::string(" ADDRESS = '") + addressesArray[i] + std::string("' OR");
    }
    if(addressesArray.size() > 0) sql_query = sql_query.substr(0,sql_query.size() - 3);
    sql_query = sql_query + std::string(";");

    printf("sql_query = %s\n", sql_query.c_str());

    sql = (char *) sql_query.c_str();

    rc = sqlite3_exec(db, sql, select_callback, &records, &zErrMsg);
    //sqlite3_exec(db, sql, callback, 0, &zErrMsg);
    if( rc != SQLITE_OK ) {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    } else {
        fprintf(stdout, "Operation done successfully\n");
        printf("%lu records returned\n", records.size());

        for(size_t i = 0; i < records.size(); i++) {
            ret.push_back(std::stoi(records[i][3]));
        }
    }

    sqlite3_close(db);

    return ret;
}

static void initializeUtxos(std::string path) {
  printf("INITIALIZING UTXOS\n");
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    char *sql;
    //const char* data = "Callback function called";

    //rc = sqlite3_open("test.db", &db);
    rc = sqlite3_open(path.c_str(), &db);

    if( rc ) {
      fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
      return;
    } else {
      fprintf(stderr, "Opened database successfully\n");
    }

    sql = (char *) "DROP TABLE UTXOS;";
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

    /* Create SQL statement */
    sql = (char *) "CREATE TABLE UTXOS("  \
      "ID INT PRIMARY KEY     NOT NULL," \
      "UTXO_ID       CHAR(255)    NOT NULL," \
        "WALLET_ID       BIGINT," \
        "FROM_WALLET_ID  BIGINT," \
        "SATOSHIS       BIGINT," \
        "ADDRESS       CHAR(255)," \
        "ADDRESS_INDEX  INT," \
        "TXID           CHAR(64)," \
      "VOUT                INT," \
      "SCRIPT         TEXT," \
        "SPENT_TXID     CHAR(64)," \
        "AMOUNT         BIGINT," \
        "ASSET_ID         BIGINT );";

    /* Execute SQL statement */
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

    if( rc != SQLITE_OK ){
      fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
    } else {
      fprintf(stdout, "UTXOS Table created successfully\n");
    }

    sqlite3_close(db);
}

extern void authorizerAddUtxo(const char *hex_, const char* path_) {
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    char *sql;
    
    std::string path = std::string(path_) + std::string("/sfp.db");
    printf("path: %s\n", path.c_str());
    
    std::string hex(hex_);
    
  std::map<std::string,Utxo> utxos;
    
    extractUtxoFromBsvjsTx(utxos, hex, path);

    if(utxos.size() > 0) {
        //rc = sqlite3_open("test.db", &db);
        rc = sqlite3_open(path.c_str(), &db);

        if( rc ) {
          fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
          return;
        } else {
          fprintf(stderr, "Opened database successfully\n");
        }

        for (std::map<std::string,Utxo>::iterator it=utxos.begin(); it!=utxos.end(); ++it) {
            Utxo utxo = it->second;

            Records records;

            std::string sql_query = std::string("SELECT * FROM UTXOS WHERE UTXO_ID = '") + utxo.utxo_id + std::string("';");

            sql = (char *) sql_query.c_str();

            rc = sqlite3_exec(db, sql, select_callback, &records, &zErrMsg);
            //sqlite3_exec(db, sql, callback, 0, &zErrMsg);
            if( rc != SQLITE_OK ) {
                fprintf(stderr, "SQL error: %s\n", zErrMsg);
                sqlite3_free(zErrMsg);
            } else {
                fprintf(stdout, "Operation done successfully\n");
                printf("%lu records returned\n", records.size());

                if(records.size() == 0) {

                    size_t id = 1;

                    Records records0;

                    sql = (char *) "SELECT * FROM UTXOS";

                    sqlite3_exec(db, sql, select_callback, &records0, &zErrMsg);
                    if( rc != SQLITE_OK ) {
                        fprintf(stderr, "SQL error: %s\n", zErrMsg);
                        sqlite3_free(zErrMsg);
                    } else {
                        fprintf(stdout, "Select * From Utxos done successfully\n");
                        printf("%lu records returned\n", records0.size());

                        id = 1 + records0.size();
                        utxo.id = id;
                    }

                    std::string sql_query0 = std::string("INSERT INTO UTXOS (ID,UTXO_ID,WALLET_ID,FROM_WALLET_ID,SATOSHIS,\
                        ADDRESS,ADDRESS_INDEX,TXID,VOUT,SCRIPT,SPENT_TXID,AMOUNT,ASSET_ID) VALUES (") + \
                        std::to_string(utxo.id) + std::string(", '") + \
                         utxo.utxo_id + std::string("', ") + \
                        std::to_string(utxo.wallet_id) + std::string(", ") + \
                        std::to_string(utxo.from_wallet_id) + std::string(", ") + \
                        std::to_string(utxo.satoshis) + std::string(", '") + \
                        utxo.address + std::string("', ") + \
                        std::to_string(utxo.address_index) + std::string(", '") + \
                        utxo.txid + std::string("', ") + \
                        std::to_string(utxo.vout) + std::string(", '") + \
                        utxo.script + std::string("', '") + \
                        utxo.spent_txid + std::string("', ") + \
                        std::to_string(utxo.amount) + std::string(", ") + \
                        std::to_string(utxo.asset_id) + std::string("); ");

                  //printf("sql_query0 = %s\n", sql_query0.c_str());

                    sql = (char *) sql_query0.c_str();

                    sqlite3_exec(db, sql, callback, 0, &zErrMsg);
                    if( rc != SQLITE_OK ) {
                        fprintf(stderr, "SQL error: %s\n", zErrMsg);
                        sqlite3_free(zErrMsg);
                    } else {
                        fprintf(stdout, "Insert into Utxos done successfully\n");
                    }
                } else {
                    std::string sql_query0 = std::string("UPDATE UTXOS SET");
                    if(utxo.wallet_id != 0) {
                        sql_query0 = sql_query0 + std::string(" WALLET_ID = ") + std::to_string(utxo.wallet_id) + std::string(",");
                    }
                    if(utxo.from_wallet_id != 0) {
                        sql_query0 = sql_query0 + std::string(" FROM_WALLET_ID = ") + std::to_string(utxo.from_wallet_id) + std::string(",");
                    }
                    if(utxo.satoshis != 0) {
                        sql_query0 = sql_query0 + std::string(" SATOSHIS = ") + std::to_string(utxo.satoshis) + std::string(",");
                    }
                    if(utxo.address != std::string("")) {
                        sql_query0 = sql_query0 + std::string(" ADDRESS = '") + utxo.address + std::string("',");
                    }
                    if(utxo.address_index != 0) {
                        sql_query0 = sql_query0 + std::string(" ADDRESS_INDEX = ") + std::to_string(utxo.address_index) + std::string(",");
                    }
                    if(utxo.txid != std::string("")) {
                        sql_query0 = sql_query0 + std::string(" TXID = '") + utxo.txid + std::string("',");
                    }
                    if(utxo.vout != 0) {
                        sql_query0 = sql_query0 + std::string(" VOUT = ") + std::to_string(utxo.vout) + std::string(",");
                    }
                    if(utxo.script != std::string("")) {
                        sql_query0 = sql_query0 + std::string(" SCRIPT = '") + utxo.script + std::string("',");
                    }
                    if(utxo.spent_txid != std::string("")) {
                        sql_query0 = sql_query0 + std::string(" SPENT_TXID = '") + utxo.spent_txid + std::string("',");
                    }
                    if(utxo.amount != 0) {
                        sql_query0 = sql_query0 + std::string(" AMOUNT = ") + std::to_string(utxo.amount) + std::string(",");
                    }
                    if(utxo.asset_id != 0) {
                        sql_query0 = sql_query0 + std::string(" ASSET_ID = ") + std::to_string(utxo.asset_id) + std::string(",");
                    }

                    sql_query0 = sql_query0.substr(0, sql_query0.size()-1) + std::string(" WHERE UTXO_ID = '") + utxo.utxo_id + std::string("';");;

                    printf("sql_query0 = %s\n", sql_query0.c_str());

                    sql = (char *) sql_query0.c_str();

                    sqlite3_exec(db, sql, callback, 0, &zErrMsg);
                    if( rc != SQLITE_OK ) {
                        fprintf(stderr, "SQL error: %s\n", zErrMsg);
                        sqlite3_free(zErrMsg);
                    } else {
                        fprintf(stdout, "Update Utxos done successfully\n");
                    }
                }
            }
        }

    printf("PRINTING UTXOS TABLE\n");
        sql = (char *) "SELECT * FROM UTXOS";

        sqlite3_exec(db, sql, callback, 0, &zErrMsg);
        if( rc != SQLITE_OK ) {
            fprintf(stderr, "SQL error: %s\n", zErrMsg);
            sqlite3_free(zErrMsg);
        } else {
            fprintf(stdout, "Operation done successfully\n");
        }
        sqlite3_close(db);

    }
}

static void initializeUtxos_old(std::string path) {
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    char *sql;
    //const char* data = "Callback function called";

    //rc = sqlite3_open("test.db", &db);
    rc = sqlite3_open(path.c_str(), &db);

    if( rc ) {
      fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
      return;
    } else {
      fprintf(stderr, "Opened database successfully\n");
    }

    sql = (char *) "DROP TABLE UTXOS;";
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

    /* Create SQL statement */
    sql = (char *) "CREATE TABLE UTXOS("  \
      "ID INT PRIMARY KEY     NOT NULL," \
      "UTXO_ID       CHAR(255)    NOT NULL," \
        "WALLET_ID       BIGINT," \
        "FROM_WALLET_ID  BIGINT," \
        "SATOSHIS       BIGINT," \
        "ADDRESS       CHAR(255)," \
        "ADDRESS_INDEX  INT," \
        "TXID           CHAR(64)," \
      "VOUT                INT," \
      "SCRIPT         TEXT," \
        "SPENT_TXID     CHAR(64)," \
        "AMOUNT         BIGINT," \
        "ASSET_ID         BIGINT );";

    /* Execute SQL statement */
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

    if( rc != SQLITE_OK ){
      fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
    } else {
      fprintf(stdout, "UTXOS Table created successfully\n");
    }

    sqlite3_close(db);

  std::map<std::string,Utxo> utxos;

    std::string hex1("02000000015e989a1536ae316bafb404ecf7b01c81168a3e8b56fe195c9345946d66601d9900000000484730440220388b7c9d87efef914f844aab490de418b107290685efa901b93e0927ecf6cc4f02205c18b01d02af0c559cc42bca0a57f790ed1e440e28fc1f0e46e851b956d2617a41feffffff0240101024010000001976a9141a9cd2673ad1892f348aa6c32eda891c5087658e88ac00e1f505000000001976a914694730a49c6f08f66869b11464be6c5b8847110288ac65000000");

  extractUtxoFromBsvjsTx(utxos, hex1, path);

  std::string hex2("01000000016de1f73ca6ea14874933713e8478824f7fc0416a0b6c53d3d4412be1d7df2d94010000006a47304402200cbbbf14aaf81ed26bd49ddd41a79ce402b3e29fb94ed0606412921f2669a8e502205904739248e6d6cf0cafe7e903df5a33607aedc68b3ec8c9f1520928b39d2ea2412103a498ad531005c837faccce4c910a9d2e73acc4d2680375b8dffac5648226f1a6ffffffff023602000000000000fd9901610773667040302e33243866353539383237353266372e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a91412f88c3fa18325a8e42100b1d5ffa16384fa50cf1412f88c3fa18325a8e42100b1d5ffa16384fa50cf4630440220794afb9e88984dda9c298c9857fbbfa5927318aa3eb97bd4b64b3d09b2ea54d60220264ffc692c47004b84cdf3dc6d569172c1e6cb71ccbcad179a78826f37374ac2246de1f73ca6ea14874933713e8478824f7fc0416a0b6c53d3d4412be1d7df2d9401000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0d01000000000000007b7d0a00005addf505000000001976a914c09bd705a55189ec51c8f3441610d69daef4984b88ac00000000");

    extractUtxoFromBsvjsTx(utxos, hex2, path);

  std::string hex3("01000000027d4866deb25f67bd33554854e9b03ca0fa745ac1cc71c289c02becaf1c1df5fa00000000fd90014730440220248225cdb08702faf35f74b77711b1d53f4c2c184c514d9becd020b575cc87f602207979cc4516692bb408dcfc75c7039cc7e6f3c26c60542b3ec087f71c1d614f1d4121035d4c359afb744402dddef5de4aa764ccfabc7917b3b9268e537f169569a99d0c483045022100817a60fe9878d1cee7a469d1c4371ee4d375bcc116ea8c38aa6bdc8c30bb7ffb022042a8f074863ff1861904bbe148cd03d5fb5f285dd223dbed40256a7d0bde41ec4121025f44adfa89cc33c42def4165be539a523c3d3fd7e537bc1e9bd44b32fa341cfd0773667040302e33483045022100c166bdbc3e284d0e41b977aa2917cd080b7fc24b9fd8b7af4edbb7c4bd99b238022001e8aa9a4d4708b231e94884f68bff2d4ae1a485ed14bab6d7f105251a3d657a004730440220248225cdb08702faf35f74b77711b1d53f4c2c184c514d9becd020b575cc87f602207979cc4516692bb408dcfc75c7039cc7e6f3c26c60542b3ec087f71c1d614f1d4121035d4c359afb744402dddef5de4aa764ccfabc7917b3b9268e537f169569a99d0cffffffff7d4866deb25f67bd33554854e9b03ca0fa745ac1cc71c289c02becaf1c1df5fa010000006a47304402203216b2656fc4f6fbdbe0fa8643f036df12ec7cea4b4bd45eadc018ce1773b44f0220293f45b932c2728ac44c8639a2d140563eefffbdbbe35c2982447dee8b4d4fb0412102540a4fd394938e44dff4c22dcbe57af460b2bbfaaaa74eaa62e01ab54e183771ffffffff023402000000000000fd9701610773667040302e33243866353539383237353266372e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a9141d783a74ab3d71e0e3ba79c94e398cafba9effc41412f88c3fa18325a8e42100b1d5ffa16384fa50cf4630440220305fee934d96fa861d52e85801aa794ac2a4f0138da619069f533732a16b25660220181328571869d47b4741497a894a03505f8c4edd763f31caccd56696eb1984d6247d4866deb25f67bd33554854e9b03ca0fa745ac1cc71c289c02becaf1c1df5fa00000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0b01000000000000000800000edbf505000000001976a914e9034a89b7f9813f1df42059515ea9c2ef05ceef88ac00000000");

    extractUtxoFromBsvjsTx(utxos, hex3, path);

  std::string hex4("02000000016de1f73ca6ea14874933713e8478824f7fc0416a0b6c53d3d4412be1d7df2d94000000006a47304402206a53254209541139c5d12438732cee5a50e03461c5b7c7f50beeca5b04d7b17902204d9dadfebb91d6ad290c06ccc60d133d47c340b2c9c11874d0970008129f4f6041210358f14eaf81c250db1821484e5b62d47a87e87739e9af0d6da0ee06ef8a2f1008feffffff0200e1f505000000001976a9145fae85d7e7d715823f4a851252489c56872743c788ac5e2e1a1e010000001976a914ef476dfc521a7599b0690c02444d002dac2c15dc88ac65000000");

  extractUtxoFromBsvjsTx(utxos, hex4, path);

  std::string hex5("0100000002d7ed7477c68a48b09ab3960064691ff984b6f3777fe847eab361bead48e1341700000000fd2a01483045022100bbe35218854080c756b7c747a7d9a51e8044e3b73873fbcb74c87e63809804ac02206b87ec477d5fee4f5f3441875b81826571d0ec67b3d784635a5196e725f749a2412103201d220702a62e450fef381ca64e91f0b6226ae3228414b4978740acbac2ff2447304402201e197820d7e4898b9fb37c7d386773d973aa02005d6c5ee17cd99e395c8d80b4022062a9640097b8346f7efb1fdcb15a737256231fe829bc24e69a62835944acb1d34121025f44adfa89cc33c42def4165be539a523c3d3fd7e537bc1e9bd44b32fa341cfd0773667040302e33483045022100e3e72d56d534b402a61e9943c757bda6358ce3d536e68e7d7d34dda91aa95db302204e8b7bad37d320f084afe0e34bd2ea9ca4f34f91d47b904716ef6322472d6eea0001000100ffffffff1165a33b23f00109a66ea874a6b8f3c145cbdc702273c9c168fd7c7f93ea26a3000000006b483045022100f487060477ee61fc138ba22a65414c3dfa506f832100556eaf6e915c97cad68b0220020e6be996e7b3675a231d20fd0e83cdc4e6969ac2dd1ea19a2b2853e376c044412102b4b5a1815f25abaaa6651b8d65c7644d87cd89d8e2ca9b1b09efd43ed47f7c3affffffff023402000000000000fd9701610773667040302e33243866353539383237353266372e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a914024570df2d9092b044eed230f5aac1448919075a1412f88c3fa18325a8e42100b1d5ffa16384fa50cf46304402202f4faabde0430c3f3741be82c3437eedf5a4b9081e06a2729470d13582522c7f02202c778650ccb6c9d71ffeec89275a3025406f9a6fdf096e3c0a827d777a3a4ea924d7ed7477c68a48b09ab3960064691ff984b6f3777fe847eab361bead48e1341700000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0b0100000000000000080000b2def505000000001976a914022e6701605ae5e85fd36c387b4d4b813531e46488ac00000000");

  extractUtxoFromBsvjsTx(utxos, hex5, path);

  std::string hex6("0100000002d7ed7477c68a48b09ab3960064691ff984b6f3777fe847eab361bead48e13417010000006a47304402204d3ebc644a4714ac985101bb3c979e8cd2c7015739d1837a44e42e4fb3c5ad8f0220319ace1146bc4afc5b57bb6c472cec0d63ddda5c07d529f6f41c79ff06ddd2604121031addecc146d9dbf87bad9627d8738265e635bd92971e1d9cdc327dc7b15d15d3ffffffffcb65719ef2be12fe330fcb33b7fe836995d75f40647f0448764d1434a7177edc00000000fd900147304402206ff1f5fba5ca7903c2d84458cd72786d8c790d00e3b5afd1b710a57a28f6c3cb0220795077ade79fd9b1998a7de6f597475a83e7d25374a071a78ca8ed24f69bba60412103f797bfa43accdc6c293b6aac3b25f1fa9668ea7ecea591ad336cd5aa5dce6d8f483045022100e437f076bf5a4f7bd35d6ede97c6eb1f8177cc25f8c3d31c71e7d12f23d4a64302202965cc21f9e234fb5e272da89fea5ab8056397e87a23e1f07b903faa9a5d63594121025f44adfa89cc33c42def4165be539a523c3d3fd7e537bc1e9bd44b32fa341cfd0773667040302e33483045022100b575a58fda0bbcc6be39fca11094bcff72959c779d0afbd89dc46ad4a95d54610220089f020ae969e51eb6a6d15e12359aba390fe00332a7435421f639e59df3f4cd0047304402203a4004ade8ede14fb6358133751589599df3de87e31d9ae127aeff8f617228f702207e099d249904f42b41f58e6a366dcb9b78f9bf9e4813d2b083acde67f625f0f84121035d4c359afb744402dddef5de4aa764ccfabc7917b3b9268e537f169569a99d0cffffffff023502000000000000fd9801610773667040302e33243866353539383237353266372e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a914432a14496b68288ec26f3877403ff8782bba0aec1412f88c3fa18325a8e42100b1d5ffa16384fa50cf473045022100e9e58abb4637de284561516b87c29a8e00c019b6f435e9aa6984cdfcde3011ef02202729a27042e13b64690c8a1f4e367264d14689c7c780ef36b8990ed0fdc2117b24cb65719ef2be12fe330fcb33b7fe836995d75f40647f0448764d1434a7177edc00000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0b0100000000000000080000bed8f505000000001976a91457bb2a7ba4cd181f58cdcb57d9cec22794fc783b88ac00000000");

  extractUtxoFromBsvjsTx(utxos, hex6, path);

  std::string hex7("0100000002d31f6910b1371f70ee6244ea913d170a389962466ae0c9d4e85a7a0c2802941000000000fd28014730440220777ecab2514647db29c67b351156be754b500c780388618aa877e85671cdb4d6022033e46fed79743d3891e2d21cd7e4f54adfdda378e13912890c105c44de930c314121033f1385fd2ab05b90a883d0314f7f44133202b584920f33b4afbb55ff9b4b473547304402204fe032ca1ebc912ff5851cac846f6449f8a1348d8c967a10e3e03ede9da8820f02206c69577ef9e6dc1d3f2962afdbf25b626c420fba13808ab1d1545d66338884954121025f44adfa89cc33c42def4165be539a523c3d3fd7e537bc1e9bd44b32fa341cfd0773667040302e33473044022044dd9e3d7123b00dc429987dc4d1d0f8afa08187ed9a3fb03020891d0d88073602207e0b6e765c2931556166d31f47298a5759f6f1f9776762e5d4651dace690515c0001000100ffffffffcb65719ef2be12fe330fcb33b7fe836995d75f40647f0448764d1434a7177edc010000006a473044022040c6058b804ea7cd0340b3a28e979dcbbfd2113b3395141509fd09155d59838a022063ef1bee50acff03e07ced8fa743f9ef7b52208b00fef05c1b98f9607a4b52e34121021fb87df3ea38c9b677e218dbb2e29b9d7b02f921d288aaa14d98c32fd884466dffffffff023502000000000000fd9801610773667040302e33243866353539383237353266372e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a914b582f14ebc63fa84aff302ff371d276ceb7f96081412f88c3fa18325a8e42100b1d5ffa16384fa50cf473045022100e48d1445a443e9f5b807deef3413b83077ace44e7bfcb92b3df8be2dd7767a5402206ac96181a11141ffd4e61b05bf11897f3b68746d1094401a439b998bdf6811ce24d31f6910b1371f70ee6244ea913d170a389962466ae0c9d4e85a7a0c2802941000000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0b010000000000000008000063dcf505000000001976a91460114aeb449f76fb5422aa19bc98be1a1835e1bc88ac00000000");

  extractUtxoFromBsvjsTx(utxos, hex7, path);

  std::string hex8("01000000020b2d06d37d3f207760ba2448254f2238e7ef6424c0039bba4e05cf322c058e0f00000000fd8f0147304402205d8a17d9fd42876762c6c0c4d27e96403c1cb18017e1e404158d4e33307ee8f0022057b40098c51afd6f858440cfb01df24a6512016392021b2a0231562cb32b0af54121037c71bf35b892922de7099f6b9d5007828592f2a7e7d5028ceae8782ae8be70f44830450221008758ccd1222f4c93097b83d9762316234880e947c3e73858f2d447c4df76519e02202038cb13f9a0d38d614fa4ebbc9375a193106d909b8b80072c7e9ae61974391e4121025f44adfa89cc33c42def4165be539a523c3d3fd7e537bc1e9bd44b32fa341cfd0773667040302e334730440220414d6557e56d41cf75371cb9be031567240e08d0e7dd81f06922495f1db1d1f402206195e2b7687035c95081463f90c90e74b7e635ac3a3b2f8f0d6ab2c4c67b9a40004730440220535ce4d6a6d318395eae8f67ca8d6ad3fb7c9d6ed1414ff639b5bd59ba6c49600220293e640ee68ce6796c3310c939b1d357cfb0a87d50b19590161386fa49ebc29e4121035d4c359afb744402dddef5de4aa764ccfabc7917b3b9268e537f169569a99d0cffffffffd31f6910b1371f70ee6244ea913d170a389962466ae0c9d4e85a7a0c28029410010000006b48304502210088c14953018966ee8580119151ffc5448eacc443d65da34d7691ee10ad12ef2902201be514271c974343782226c1a18cd47e61e8694364c6f7eb74d6441e292cb629412103f88256859a835aaf1b79e84de1d2d51480703ef711ce3ce2ce7445566ab4ed22ffffffff023402000000000000fd9701610773667040302e33243866353539383237353266372e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a9141d72965e1b5d764b07229af4839e0aa63fb561861412f88c3fa18325a8e42100b1d5ffa16384fa50cf46304402202cd6aff9189019a9784347c97d8bfe9cf4b3eb4940e452eddf0e422654d58c2302201c411d3c92d19d56cfa020498751dd70c3e8565cf1c612c1e624a4ad241ef9e0240b2d06d37d3f207760ba2448254f2238e7ef6424c0039bba4e05cf322c058e0f00000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0b010000000000000008000071d6f505000000001976a914694730a49c6f08f66869b11464be6c5b8847110288ac00000000");

  extractUtxoFromBsvjsTx(utxos, hex8, path);

    /*std::map<std::string,Utxo> utxos;

    std::string hex1("0200000001c59643ed2c08ce441e6e509f3bcdced144864c5e540a3e4e189fae8718b052c90000000049483045022100e2bfcccd873313ff1e0a55ae5195844e9ae9a2f5702801efdc11205e327b8ef202206fde1be151d1ded5e365611a5b83bc90ebb6e14d414825cbc6575f3fbc63ff2141feffffff0200e1f505000000001976a9143c7a37d150d625b7b2cfd4dbee58564a2fc759fb88ac40101024010000001976a914001577d2dacb84666f5ef5f4a613e1bafb69956b88ac65000000");

    extractUtxoFromBsvjsTx(utxos, hex1);

    std::string hex2("0200000001ae3ea23a10a7af2e8fca307ec7393f8c039f632fe6c11f1e84cfd6f9b0b99b8f010000006b483045022100ef6919336d356c31c2f33f15b1b03db1c937dfa2f24e9f5c783f868caa1a1e1a02203ba3696b6277fb92a1428714500037b0f3dffa5dedc9d78523a8979571da5fc4412103952232170c346843e0296807721b4021b2d82da3bfae77b81ee3d63d707a16a1feffffff0200e1f505000000001976a9145fae85d7e7d715823f4a851252489c56872743c788ac5e2e1a1e010000001976a9148640e64d8cc6ac2eb3090ab03c72d3458946844388ac26000000");

    extractUtxoFromBsvjsTx(utxos, hex2);

    std::string hex3("0100000001ae3ea23a10a7af2e8fca307ec7393f8c039f632fe6c11f1e84cfd6f9b0b99b8f000000006a473044022015329ab1342f6605ef054fda1694ca1cd1dc7978364b5972c19e0f6e62fac07b022017c45dee4680f681fd61b431b820925ed7c5c7a99ae4d888e14e5e23ccde0827412103ece4e7b8bb8a770c4c252173e014cba09c20fdb50f6f5da113ca5aaa3c4632b9ffffffff023602000000000000fd9901610773667040302e33246164336362313833316165622e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a9142ca3d8061b9c7171c5ae7c4c0bc10781916139a7142ca3d8061b9c7171c5ae7c4c0bc10781916139a7463044022029556bfe4aadb8a50fd326ac4f51e8cf4ddebe81823b1c0888ffb8d6bdbd7a29022053d8b1ad41978ee1ba56fee8fd40b71abae2cab8ddbf6cf20bc72820affa2f9b24ae3ea23a10a7af2e8fca307ec7393f8c039f632fe6c11f1e84cfd6f9b0b99b8f00000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0d01000000000000007b7d0a00005addf505000000001976a91437361ee32d0445c1acdd28142e401791f6f5213788ac00000000");

    extractUtxoFromBsvjsTx(utxos, hex3);

    std::string hex4("010000000241884cdf70aef573faa3378aabca9c54a81c5606df91cf95dfe685948da966c900000000fd9001483045022100cfc50fe0d7ee1e5bfca23ed0594504cc520d327f4d5844d00c2bf8ee5b1001e902200b666d3949334f47bdc4d93ad7032e3e5940d12b8fd74e4c6b17e9d790cbb580412103f35a29c3f513cda81a6e65f2d879516e03742803955faa3cf9282519e295a82e473044022014655621dd5b0e1f380578e0a04f6d3b75b49874eeb1b550bedc6f8ccfadda58022061d842229cf05e0bb77ced04a65250ff2d21519273c2df318822c90344529b014121025f44adfa89cc33c42def4165be539a523c3d3fd7e537bc1e9bd44b32fa341cfd0773667040302e3347304402205eb25d591cc45093e8d307904955db66ba71812264e2bed5989ea1ad2711606402207fadc85b96398636c5c30b0f587a3e396a93b8474b399d6d4ecafc29d72b5b4f00483045022100cfc50fe0d7ee1e5bfca23ed0594504cc520d327f4d5844d00c2bf8ee5b1001e902200b666d3949334f47bdc4d93ad7032e3e5940d12b8fd74e4c6b17e9d790cbb580412103f35a29c3f513cda81a6e65f2d879516e03742803955faa3cf9282519e295a82effffffff41884cdf70aef573faa3378aabca9c54a81c5606df91cf95dfe685948da966c9010000006a47304402207690b7537f10a27b1fdf7dfdf74331f58584f66b780a2a0f02d9226608f44142022033e2319540cd313759bc6e45be8c6efe67cc4d0b44f121558e349098514aeb874121031a319c249b004a2c26628c59c8e2dd178417d7bad281aa68bf67a9e1f0a5d9daffffffff023502000000000000fd9801610773667040302e33246164336362313833316165622e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a9140ee50e5b49cf683f0213d8858f765a8fe97a5747142ca3d8061b9c7171c5ae7c4c0bc10781916139a7473045022100b65b5f07210e19c96623a093745a9471a1c759ebb84d78e710ddd03a71ebf441022071839ec99607e7623c223e1f157c7ef7980b3166090c3fb160606c72e7d84e072441884cdf70aef573faa3378aabca9c54a81c5606df91cf95dfe685948da966c900000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0b01000000000000000800000cdbf505000000001976a9148bd02fc583319029398efc2e679fb2728ce7752c88ac00000000");

    extractUtxoFromBsvjsTx(utxos, hex4);

    std::string hex5("010000000250cabaedce82a547f46adcc9b27be4fe4e8921361e392e5828be7ccadb6cfd3f000000006b483045022100a989edb8a926070fba5e15a82a0a9e2389dfc33bd673af7634693744a92bba4202205a51fc975e51fde747969a61a0c8c7996f7d5d25798214c9e0d65e3bae4c145d412102b4b5a1815f25abaaa6651b8d65c7644d87cd89d8e2ca9b1b09efd43ed47f7c3affffffff9ff0e30cb6c35df50d5501cc8e4e1a7718265b2d4930706750cdbf8b19e1426700000000fd29014730440220495cfed51213295d74167f7717573a1a5fa508b61598af961e842be24f87966a022057b276cfc3a2dc5f01ee869d72bcc67789eef0f139d55a3d662bdc4512dcaf494121022fd081a335b081518537bed3ddd0c8fe8d5edfbdd300d1ea45ab05f94bcace49483045022100af85129454db5fee521c7a637210c221194c87f85beb17d6a36f64ba17d559df02204a414d25ad32c6eff00b634599102c810d82ba52eed96fdaff42781b7ac228194121025f44adfa89cc33c42def4165be539a523c3d3fd7e537bc1e9bd44b32fa341cfd0773667040302e3347304402206c15701933d253a7341d611ee12350bc46d375ef757b5c23771425ab42b4c49e022041da05562537189855861288bed4e96021e20b913e8ee43c5537d595b06da0680001000100ffffffff023502000000000000fd9801610773667040302e33246164336362313833316165622e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a91485ffb91009e7a85e93a30ef5d394637c7479e9ac142ca3d8061b9c7171c5ae7c4c0bc10781916139a7473045022100a0bedca2f81402c24efe08e780847d0872020284a66eb4e4d7f21f1d0aa9b6c1022023b412f7e9dd32ccea88ab7820b658a010407215055b55300b1e0d9b7ae13137249ff0e30cb6c35df50d5501cc8e4e1a7718265b2d4930706750cdbf8b19e1426700000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0b0100000000000000080000b1def505000000001976a914f507b6a3d41789c4d3eba3d1490118eefd8dbb5f88ac00000000");

    extractUtxoFromBsvjsTx(utxos, hex5);

    std::string hex6("0100000002df5f0f72aa7f60170295ca521d2425b7792125b61f2360e6aae0285e5729853000000000fd9201483045022100ce7351ad7675053c6d35675aa8a87b90ece0daa97fcba47e0a5fe6cf232f48a302206c74ccd2407c37174d5622ae2407be402b20be0178877c38a63cd824d26636b4412103a2b6e61d7e3c6d1b48345673f89ede0beb4abe9daeeb3797bb97ac68ce0d3f1d483045022100eeb62656116b3b1a43d42cd1254fc3ee43ba048afb843bb6bda97f1274f489a402207371d2b10dc45551a1c3f1b4656d08d4f393bda05754d0a2e2c992a3c29583b74121025f44adfa89cc33c42def4165be539a523c3d3fd7e537bc1e9bd44b32fa341cfd0773667040302e334830450221009745aff2ef887ff278aaafa8601ba3990363e024c85b03e04fe2dab844c251c102205dcc6aec8c68c07bce53d544f476ce8ea77fcf9ea79d283fc05b4d6b9a838ce700483045022100fef4c809a103a4a04b088fd2315c76d1f79a1c611c65bc19c88021ab09add3f30220463712f6f5b4e4feafe42a413ee267c5db3902375f823914134aa27040fc7eca412103f35a29c3f513cda81a6e65f2d879516e03742803955faa3cf9282519e295a82effffffff9ff0e30cb6c35df50d5501cc8e4e1a7718265b2d4930706750cdbf8b19e14267010000006a47304402201797800ad81c768c0a774c67834b7d7d5ddfe5bf4f08b5cd98e54d7b6b85ebc002204fd674f6f5719698deb57f03f23b0b012023e834d9fa38bbcd3bb419df75e153412102fb076877a219bb22d74911e13a23643a169249b9d7625c9a45967653bae2174bffffffff023402000000000000fd9701610773667040302e33246164336362313833316165622e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a91460114aeb449f76fb5422aa19bc98be1a1835e1bc142ca3d8061b9c7171c5ae7c4c0bc10781916139a7463044022100a40496429c198ff47242565e7edfd9e5b60501c04856f32f2f244a7448ddbb10021f26b2d5d8fbd665cc441817c66aec722cd9ab3b9129b3dfbf7df4299972dac324df5f0f72aa7f60170295ca521d2425b7792125b61f2360e6aae0285e5729853000000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0b0100000000000000080000bfd8f505000000001976a9142e4b32720135a6ad20f7032311ba9ff2f6b2769288ac00000000");

    extractUtxoFromBsvjsTx(utxos, hex6);

    std::string hex7("0100000002df5f0f72aa7f60170295ca521d2425b7792125b61f2360e6aae0285e57298530010000006a47304402203327b64bb210fab90d6850bbd8bb1d913bab4edc02d24ab7dd36a431f82027d202201ac6ae1c3e427baa15afd4a60920bbc82c8f5676143bca208980cdd7bbdbaa67412102a622c93398c68d37f60dc7c3a2ac022106a2e71be4280c7d03cd8265f9c0784fffffffff7bf2bffc2c4f7aa5e7e1df48678dfad59d79bbf633ee16862cec057b991a359200000000fd2901483045022100e35d9d7b5672dbf2ebecdbdf3eb43b0d94fe0685647c8f8c5b6cb4804bd36168022046338308bc872a2b5ed23914af805f6883e6f2da9ad3115288a24ee8b14e925f412102fe66f220e02f0e68b8a05a7db5bd1f9895c7721789078962df166feb4edfdd63473044022042a323b6793891ae6530b271d4229eeb99f0deb420940bc9d76ae4822ba1cad402201467344be5f0eb3c51ce094e04f8f897581fde71b8e77691727ddd8077dca47d4121025f44adfa89cc33c42def4165be539a523c3d3fd7e537bc1e9bd44b32fa341cfd0773667040302e3347304402205e704bda8d6c77df70a38ae4d31a6027831ca67d4fa0bb625e7f762463eb96c90220145ee8d8bf724d07ca8524f99a7224251a83e171e84f1f8e066af7a89bd311880001000100ffffffff023402000000000000fd9701610773667040302e33246164336362313833316165622e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a914810b4d7cd220fb1dff092a1eccc7974ad2e1662b142ca3d8061b9c7171c5ae7c4c0bc10781916139a746304402206ec1fec46cd9bf4fa97bc91d87119bc87d1935d1373e5639ba69f0cc364653dc02205425210f1c7d3e530dd58cf902aa5300a2d308a7a3d8f7b4d935e1a591b0768d247bf2bffc2c4f7aa5e7e1df48678dfad59d79bbf633ee16862cec057b991a359200000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0b010000000000000008000063dcf505000000001976a9141d72965e1b5d764b07229af4839e0aa63fb5618688ac00000000");

    extractUtxoFromBsvjsTx(utxos, hex7);

    std::string hex8("0100000002b7f183816d6277e9a89e15a6e1b5908b0e62e953b4c20fe8bb27d9ddd2a4213b00000000fd90014730440220056260e655ded43355a2178e0cdc1777f703e14f9c2df02e8ea4c8fe8e8009e30220103c8b4b8d51d154b0097cd16841b86ea49c4a421d08e2de358d128d9414cc5d412102c67a0f45ec309a8b79ddbfd835cdd530755590a9a248802ae396eab4c9f697d84830450221009092a48a6bfc448c44e0431f0e1f5e3d80ae05b4f464b26e80193d787a8f184b022028287c6dce252b16bbe40d5a427008fc52905f76e792dc3b18a3f48897adeaaf4121025f44adfa89cc33c42def4165be539a523c3d3fd7e537bc1e9bd44b32fa341cfd0773667040302e3348304502210097655e505597461a1db599dad58ff98ecef53480634708f4c3e6cdcab54855a5022069c71a250adf2dbd11ef1301e12a091f28bcd7d187173d9ced383f10f4cff88d0047304402202198d5942b282bdc0840d1cbbc5406686924f425657a07b63830a5c43711591a022064433769ca9768e3bda8566ec51a739fc80f1666d961764a3f18c4048feaebf1412103f35a29c3f513cda81a6e65f2d879516e03742803955faa3cf9282519e295a82effffffff7bf2bffc2c4f7aa5e7e1df48678dfad59d79bbf633ee16862cec057b991a3592010000006a47304402202b1aa4d936c1006f4077d916ef033ba6010a2a9d403e5a07f9205aa0de290acd022072f34973809d3407a93a137b807cf1bd8fabab24867741963a8e1e14947ed86f41210328323dd4b960d7b4a88acb7c96148a1be6c30a3fa02fc418a90afffd31d587b2ffffffff023402000000000000fd9701610773667040302e33246164336362313833316165622e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a9146d861709c1cdb8fef249f13568efcf778fefef0d142ca3d8061b9c7171c5ae7c4c0bc10781916139a7463044022044e433312a186a17372c7f4709f2fe19dd608ae9c59547e6c86a28b5de5e213002202a4f6c72988bdccbdcffe299ed0c60eaa56ef41d8cb9accb584c93712df0227224b7f183816d6277e9a89e15a6e1b5908b0e62e953b4c20fe8bb27d9ddd2a4213b00000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0b010000000000000008000071d6f505000000001976a9147b655bc26b209d3e0a4cad607f0721f19c354f4788ac00000000");

    extractUtxoFromBsvjsTx(utxos, hex8);

    std::string hex9("0100000002d447903e385942989b040394b4c6a4cac231553ffa0c1359360d80e635631a0f00000000fd9201483045022100acf8aa094d669bdf01458bb243697c9c3a5301ae5d1cd63f89571cbdc6fc97c4022014f410dd8ac002cbfc49eed8e7b24c98082971b78e23448ff4ab89b5f77872fc412103bef7f3ba2209cd3d0ebfa19618e30ab01ba5b80da49c1faa19e71cb355fbaf87483045022100abc0b968446aac5698ed493db2b0e64a607fdf93c229c99dfdf5d0eeb377628f02205b7f7235d8f760a1bc041914bca0333f2cbc0243a9555bf5e78012449bfc36854121025f44adfa89cc33c42def4165be539a523c3d3fd7e537bc1e9bd44b32fa341cfd0773667040302e33483045022100a3e4dcdc5e021ef026466ff1d52a2f1bde6658b7f012033535557fd805ccb071022054c0cf76717acbc5767b0bb731efe765ee41dc859f9b73d785ecc7cf1f72397a00483045022100d85d0e32404b55c9335a59a2464503f41837384e57b70eb4edde3265bb571428022068a3de549b436e3f90a13c9636fb4d89a29c9cd350d01178da33c85482b78c39412103f35a29c3f513cda81a6e65f2d879516e03742803955faa3cf9282519e295a82effffffffd447903e385942989b040394b4c6a4cac231553ffa0c1359360d80e635631a0f010000006b483045022100aea90f8e243c89623b2b8cf77fb5d706678dff5a571f5a122eea535b536ea0a2022051e091665aef32a6920984189eff90cb9105b91ea098aff00b6383a7bb7131794121029fc962569b74723cf5a544531cbdcafa45b8ea71f4f13152469897bc48bf721dffffffff023502000000000000fd9801610773667040302e33246164336362313833316165622e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a914679c1d8f104ecc603e1771f32d6ae395075cc63a142ca3d8061b9c7171c5ae7c4c0bc10781916139a747304502210084fe776922f3911e30cd26f90e5df33e0b83b265362e2294af5f2104bfd0d12f0220569bbdb7fbb52bf540992de25743b62baa0b56683716476bf6476a357950198324d447903e385942989b040394b4c6a4cac231553ffa0c1359360d80e635631a0f00000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0b010000000000000008000021d4f505000000001976a914e4b89a82107c2afbdd9ca20ae9c54520a00cbf0688ac00000000");

    extractUtxoFromBsvjsTx(utxos, hex9);

    std::string hex10("0100000002e819cd4b59568aac8563719eaec34d0724572964f7977ef299ea030da80bfa1d00000000fd2b01483045022100926d2af9a2ced6e489ea410a96146a19ad346e8bf3b055f3ea973b94324af40b02206b25c71a3c35b50a298219e0686efcf29d7492a2d600257c2ef6b218430018b941210257f583904c339dc7c3a0ec72043ab86be83cfc04c47aef4e750b495642b2a41e483045022100d103fe8a2615db1ed8f0fe6b5fcf811bf80a9b9cf2c292e1876dba52c75e5f2002207f6b3040414a76cd6c374b7972f895bb2c84d1db94b11d9e8c9cc2b2e584cf9e4121025f44adfa89cc33c42def4165be539a523c3d3fd7e537bc1e9bd44b32fa341cfd0773667040302e33483045022100d84d5f139931e9093f388e43b1be07b778013c3a06884508bb9755489d8e93ee02201a2c6202d5ae7701710ac4b496ee88d3628a114cba83c2b3838db17844dc01010001000100ffffffffb7f183816d6277e9a89e15a6e1b5908b0e62e953b4c20fe8bb27d9ddd2a4213b010000006a473044022043382101a1f04b833ec616dd70fe1fc1eba7892f8e9f6d6d5c8ea86f7b3054b6022068803990ce7e4455d514dfa0cf155af22f4780261019a39fba3a9e84becb08ce4121033c18eed5b78a804040e2efe1a7414dca53a9b52d7957ef0a3d4624075fc806b3ffffffff023402000000000000fd9701610773667040302e33246164336362313833316165622e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a9142013224c192388f4c7abbb9806544dba578e431d142ca3d8061b9c7171c5ae7c4c0bc10781916139a746304402205ede62329eff3785153b8fe0b0b2692bf0851dd1858874da2b53aa7afe8be49a022004a60c663924508443fd6da79fdf811a81d1e4e6df5a02d6cd45c05b5aa1dc8824e819cd4b59568aac8563719eaec34d0724572964f7977ef299ea030da80bfa1d00000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0b010000000000000008000016daf505000000001976a914523b097fd37c6860f75e3e0186771f57a60d53a788ac00000000");

    extractUtxoFromBsvjsTx(utxos, hex10);

    std::string hex11("0100000002e819cd4b59568aac8563719eaec34d0724572964f7977ef299ea030da80bfa1d010000006a4730440220086266a90ee714c01df344c5c140efbee6df46e6f3f451629edb2923eb9b76f702202cc9d831dffec941e82b1bb0bd97f487855f78c7145bc12018e144382dc37a19412102732a9afde8ebf04ea21e9e2bbe277cbdb696eadb5534f2436a9727c7ae9d8269ffffffff7fd02d9c7167a4e62df0c0f2866d7d7b2e8c93a78f1cd116f94193b47f4122de00000000fd9001483045022100c8afaa88f5b36c2982c08f1b1eef82c95ccea58536596df50b00afccae68ab1202201ba2b3cb0cf51e2b89c85ce9177bd52de9a2b875ac664ddef678b9fce481a4db4121021eef04f5e1eb4f76e36b6d18625dc4c5f562152ba91105b52df013c6e552d01a47304402200d59dbe0ecff185426422e2f60b19fde788265e1e215da7eddedef49e26818a5022035e84318b7f1fc04a0483ea24d115e13683b78455b3d360e80dba75c869f190c4121025f44adfa89cc33c42def4165be539a523c3d3fd7e537bc1e9bd44b32fa341cfd0773667040302e33473044022059ab6f4cd9dfcec136ea7f44d97c54dc03b6a2dab2f812c5f54d3b3b029137f702200dfbe1f2aea6f543aa56e661b16895048c8044d85fd679b0fce9f7ae1962b53b004830450221009a876fd616c85fcae61a53bdc9a0cf6bb805b4e2038281f47e2daa0a1eee4116022004de7bb2ddf58766d1814e1a50dcff3823d371169b3472bb7b02c6b4f049bcf8412103f35a29c3f513cda81a6e65f2d879516e03742803955faa3cf9282519e295a82effffffff023402000000000000fd9701610773667040302e33246164336362313833316165622e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a9149769cfb09c16409fe8a27e4306260263fa0e7416142ca3d8061b9c7171c5ae7c4c0bc10781916139a7463044022011a0a102abdb6707d77ce7a71648668da5cbaa492c6baa6a2eff5af1c4dcc6c6022070cc699ab842444a8af244e492029d65cdf10821a47fc73f0e63a63d517bff0c247fd02d9c7167a4e62df0c0f2866d7d7b2e8c93a78f1cd116f94193b47f4122de00000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0b0100000000000000080000d3d1f505000000001976a9145c507c080e0c25511be2acedeb10789c38ba0abe88ac00000000");

    extractUtxoFromBsvjsTx(utxos, hex11);

    std::string hex12("0100000002424dac797909f022f3d4d3b4c4126aa6e1fa6930b74e78c88fed6976bcd33dd200000000fd2a01483045022100e114a7a688ab7ed9b3a40144760268c1fd60902cd4521722f76fea5b476bb2a60220079be140822560f4cdf0148e6a8a0c9d4f0d87b16d36d1625e10c54fc10bd66b412103c81ce134418ab56226936cbaae6fcb5430cdd905671198130ad9b4f393a8552f483045022100f5ef219dd1b1efad40e603729567aa97f2b04aab3dcb7e79a06aa585aef844a202201c699764a539667bafeb43a8e2211d831585c598d7d9da60fe4bee8bdfab2fca4121025f44adfa89cc33c42def4165be539a523c3d3fd7e537bc1e9bd44b32fa341cfd0773667040302e3347304402203f3ce75fd2936f51b73c7c30c288bf31ccd6e23a92486a4ab4bb8dd937bc2b3a022053d08cd7d6180497ec7607aa631fa8e70af674d15270a0e814d5edd9953000ab0001000100ffffffff7fd02d9c7167a4e62df0c0f2866d7d7b2e8c93a78f1cd116f94193b47f4122de010000006a47304402203a5c32b0d2c7f55d8fe51b1b02e56f74e1bc09d2e8467461f4217f6968daceb9022006eb9b816b0d9ffa4fccf4d5c2bc6a340433a6f71c93c8efff2a99344647039f4121035189ee0f293ce9019a6305a8a91fcf02f96e973c2c99d94c0b930fb473943e02ffffffff023402000000000000fd9701610773667040302e33246164336362313833316165622e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a9143068ae6fcc2f78352de78c53a0e1d73203142853142ca3d8061b9c7171c5ae7c4c0bc10781916139a746304402200c853afd844de213e8f27ad1f32aeabcd0e8ad7a6756e1084b4d1d60a24442a202203879aea43d189defd31e57cfb811f822d6fc2ef4d5b28ce6f3756022fa800a5924424dac797909f022f3d4d3b4c4126aa6e1fa6930b74e78c88fed6976bcd33dd200000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0b0100000000000000080000c8d7f505000000001976a9140b4b9b1a8b70bb95aeea3a74a87dc7cc36b7762888ac00000000");

    extractUtxoFromBsvjsTx(utxos, hex12);

    std::string hex13("0100000002424dac797909f022f3d4d3b4c4126aa6e1fa6930b74e78c88fed6976bcd33dd2010000006a47304402200cea592854e6bbac5be9c237dc5f57a6fb0f2daa5472377e264de05a665778d1022062dcd29a357c87ead7cdb2b0381eb7764a696ead4d83e4f41f278dc1f4b41aeb4121029d7cc37a2af1496ce1fa3ab7c81ed7dbe609e2b5ecf0ee405a6110f90b7337beffffffff64fcc089acd509315e882637b7c340180fad7c021f4d4ca8f8df6cc0acbb9ef000000000fd8f01483045022100e9443c64bc117832305f6c7d4041e2ddb450aed0da4034de26f0ecf834729be80220195d4832d889854546c5dd4ab87606dc903abfd0f734f0ad1b2abddde9335d894121020518d17c36206611916cacdf14ed7471b7f199820250c30dc73aa8257f013a27473044022054973580405b4e3ccb5b0598001dbd3ae66c43bc0079bac6847d5a7cd17c77780220409227c3e2a2b6d73496b539115df669693c568c689ff599012cf1fb519907b44121025f44adfa89cc33c42def4165be539a523c3d3fd7e537bc1e9bd44b32fa341cfd0773667040302e3347304402205e79d19b7398b96145fc4736f8d59791f915d23086530a25dacee12120985da702204a5d0a78f8acf31a75c0266117b5017c023bd9a681dd73c510680be1a8b50abf0047304402201f10fe05e1c741e499957b2db2a0215ea9693fe6e1f1cbf99cf049983baedce702201a05637b0cade50316cce3d1036822a9d5a05dfe6457c9d6b1d0480a7210fca9412103f35a29c3f513cda81a6e65f2d879516e03742803955faa3cf9282519e295a82effffffff023502000000000000fd9801610773667040302e33246164336362313833316165622e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a91486fc86aace85cb8a6f7c25616598834e284f4b09142ca3d8061b9c7171c5ae7c4c0bc10781916139a74730450221008306c7fe1bb6e80f098a3cc4fc77641cde2aaca3d5b54152bd2ca7475fe6e683022023a782e0bbd51d823a8aa1665530cbfd2e4ebb0593851042317131df0363e0162464fcc089acd509315e882637b7c340180fad7c021f4d4ca8f8df6cc0acbb9ef000000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0b010000000000000008000083cff505000000001976a9141d7af5cf4ade36ccdf3ec70062cacf2755a3388788ac00000000");

    extractUtxoFromBsvjsTx(utxos, hex13);

    std::string hex14("010000000216ede2a6c06e7af7b990298593aa35909fa1e6944dd64a41c8e8d40c8db7b74800000000fd2a01473044022069e3d42be88b604b0e1e510da5d929b3e5fcbbfaaf7ff12ecde301a7b10643fe0220601e5d6e16bff4ffa00a4217916acec370cbfef84fd3803106461341cc0f7c1e412102583e634216e1cc42063e2b886cbe5f301f3f7834f0766b0da209f5384c89e53b4830450221008d819385b146e9b0c36193c14de00c6ead5b039a0ce267afcef3b55f02682d6c02207c45ffafdb5b1ec41a425438776882fb6a5e9557856a40f96707b47446e992d34121025f44adfa89cc33c42def4165be539a523c3d3fd7e537bc1e9bd44b32fa341cfd0773667040302e33483045022100923e967be7d2bed834f48bbcd303e202ef07b3f405e4b632794defbf4142c10d02205cffc1a026492a1c16a520d55685eb836879a512850428d13b3d10506686c93b0001000100ffffffff64fcc089acd509315e882637b7c340180fad7c021f4d4ca8f8df6cc0acbb9ef0010000006a4730440220420811d76dd9ad2d78a630b71a62109a07d11e148414528c4a3c800157f0744a02201526e3a76bcc2503ae531119c128b4f12df75dcc9bf2381d191c3f3a39b928c4412102d1a850c88992167f6c5b121731df4398524973a3276a6cf0e003b93b6e71430affffffff023402000000000000fd9701610773667040302e33246164336362313833316165622e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a914e25fc8bf2c7730def4c5a217bf9cfe766574de1e142ca3d8061b9c7171c5ae7c4c0bc10781916139a7463044022067d460557b8ac51c85e1b992568f187cc73dd7e8b5d1d355262f0f02acb2908c022029c93d0dcce711218361f5da50a114a406d2157511269dd9606fefe56b8a51ed2416ede2a6c06e7af7b990298593aa35909fa1e6944dd64a41c8e8d40c8db7b74800000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0b01000000000000000800007bd5f505000000001976a914348c5a7e40f561084fc0eb80b82997f799e4564c88ac00000000");

    extractUtxoFromBsvjsTx(utxos, hex14);

    std::string hex15("010000000216ede2a6c06e7af7b990298593aa35909fa1e6944dd64a41c8e8d40c8db7b748010000006a47304402204fb1ef790830bf40e56e6784c0420aa1101cb59c69434327ed77a2cefb937cc202200f2a5c469f617f762fc16f8d5491dcf93cb8898aed2c40329ab980efea8c93e1412103618b5b1366100160da6cb87d1395e38ad4bf3db2492d73c5fb2020473524cb24ffffffff2b3019b9bbdd9ea4af25e0c879a153f5b5c979ca4391835301338160c3c3deae00000000fd9101483045022100bf72c3523b7c0b236139a822b29cc6fce3ebd120f934655cbe0305651eb1510b02206e4ec946a19e78a02776b844b71cd61ddc51947aa8e27e64d2281564a5bfb358412103f8cd67ea78fca80af5de757d18d2e3802b1ec7d3791c8bbe57308574b898d034483045022100a6cae1d29245dfca38b4968779664dcd2a98375f26b5002ec9fe3e7d6913131702207af0629ee5457326d39f7cfd73d787a725e4722bd8dfd1096dffb4d78d449a044121025f44adfa89cc33c42def4165be539a523c3d3fd7e537bc1e9bd44b32fa341cfd0773667040302e33483045022100ed4bdadda0e41fe95abd50b601a2de571e8412aeaa141d6b148bfd0ee615f6f7022047043c3ba7fecc940acb80fe77f06a8298ec049a4caff499cbfa3ee9371817330047304402206b26d2232a3104517426c8edac7f009418bdff8c0ee6fe6cc15ed8572c66456a022020ae4d47c651467ac53d0157516a23bfc06d06fa27b508c7fabf70f9f79aead2412103f35a29c3f513cda81a6e65f2d879516e03742803955faa3cf9282519e295a82effffffff023402000000000000fd9701610773667040302e33246164336362313833316165622e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a9149e9e1f959811652b6b6741dfd3758fc2dac4389e142ca3d8061b9c7171c5ae7c4c0bc10781916139a746304402202ab94d63050c7acf3bad3b9fc038f195db57c22ff9045e510cf903fe7631b17d0220594056c20489e61521d11a7057d53ae422a25409d2fca155bf382bb6eb39d719242b3019b9bbdd9ea4af25e0c879a153f5b5c979ca4391835301338160c3c3deae00000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0b010000000000000008000035cdf505000000001976a914b6c07dbea779bb69baea5fee240752352725515988ac00000000");

    extractUtxoFromBsvjsTx(utxos, hex15);

    std::string hex16("0100000002405a644b436819e24c2770231c4498fba7eba40b051f073655daddf58155939100000000fd2a01483045022100b68d8bceb0a0ea72361035a90ede28b5e70b7f6c336bfbfb8346e4f93a91a7180220257a2f2ef7c40f91a18f5f520f3754f68b0244b54739efe7e3901ce6479037514121031653e35e1f63a889192d97b6c689f540d6bf688f54925d3458f31bac186e238747304402201c9b0e71d32fcedb7c5a644c6dcf30a52691c67abc18de3508689b2748bc2edf022005ce3e115aa86bd4d11c95a2a7ce3ab09c29ff766711a206905034e2b01675904121025f44adfa89cc33c42def4165be539a523c3d3fd7e537bc1e9bd44b32fa341cfd0773667040302e33483045022100bd6df31216551d4f3ed6bddc6f1ee9aa08ec5ec83b5647fdc1658e8a0c7bb6f7022000b4ec78e0b06d61a52959af75fcd94711816c9e7c8c99d9a99cd919b3981d5c0001000100ffffffff2b3019b9bbdd9ea4af25e0c879a153f5b5c979ca4391835301338160c3c3deae010000006b483045022100f77c417dbb9952dc8c03f7b309f3c8532a26b6b5b5bfce16d8878326ae148b3002206615333a7fd2b08414307e1f0a081d0f84071332f6942cf06c0bb9a284794555412102a717d8ac10318dcf42bd397eb1c31f85219ebb1497198783b688d8401063b01dffffffff023402000000000000fd9701610773667040302e33246164336362313833316165622e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a914f1f354fceb000dbacb1d665dbf285d355d771f9a142ca3d8061b9c7171c5ae7c4c0bc10781916139a746304402202653e382fe17b7c95f81fd36edee5f4fd1cb1a84777a5d83cb76e521359b4af50220622d1e452615cc7b0eb32af9d1a3d7b40915645cdd76290330927b74171e4afe24405a644b436819e24c2770231c4498fba7eba40b051f073655daddf58155939100000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0b01000000000000000800002dd3f505000000001976a91412c162bc4a7cff519390d17cafbf30a7f384cb5988ac00000000");
  */

    /*extractUtxoFromBsvjsTx(utxos, hex16);

    std::string hex17("0100000002405a644b436819e24c2770231c4498fba7eba40b051f073655daddf581559391010000006a47304402207750e378c263c4c28f994560d9b10baf628147c2e0fe8066378879834c29d210022059ff0b991b0151a838bbcdfa9bfffceceb1c8e6e7150d89144a3765714b7fb484121024d199b03906d648921fe2e48c2960cb8b5b3decff45a94137cfcd9e5906d56a6ffffffff713a2d315f05de1663a328089891d1e124cf1d08807db9b5aa703c2f813440a000000000fd8f01473044022055420c69922b215f33ce73a9efeb50b784090c31106434966f4f99e695253545022066e89a52704a97e2baf1a6e21989b3f3c19d4cb5ed58e9ac14efcacb49c86031412103705b2ec25a60dfe80449e20069dc33fd22a57df2bf5e131f1c1641fc6e47487e483045022100ac90b015a1801f90fd4c3d34d896439f15b95c9036bee44f40d6955dd256caeb022016be02088d549b9043fd94d742f77a82920794da72e2d1dc2381c318286c36554121025f44adfa89cc33c42def4165be539a523c3d3fd7e537bc1e9bd44b32fa341cfd0773667040302e3347304402207321bc9ab1033699c067187824710ca9525b189a0c5fc9f433a5f9ffcce43f670220412f621033f79d1f5ccd0a0ada75b2b162364a6759ac2a1d349ed94c5af41cd3004730440220084e10e41c09c504f421c3693a53d866cc326db7112858550c579e93c943d3e7022035e582335a3cf1ce975c40b680a896298a78f4da95a3280206e2418a25835383412103f35a29c3f513cda81a6e65f2d879516e03742803955faa3cf9282519e295a82effffffff023402000000000000fd9701610773667040302e33246164336362313833316165622e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a9141d7cc42e550489a8642a3164408f6de9bd4f5ab6142ca3d8061b9c7171c5ae7c4c0bc10781916139a7463044022076f15a12035efc9aa0e22096b0c112ddbf676a62fc88b73ac61f18f32bb3fe2b022021efa026be10a430db0aff92259b1402992f8d12540bddc5dd95ba08a171700a24713a2d315f05de1663a328089891d1e124cf1d08807db9b5aa703c2f813440a000000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0b0100000000000000080000e7caf505000000001976a914d461f41f4843205e289b569720c3be9a367624d988ac00000000");

    extractUtxoFromBsvjsTx(utxos, hex17);

    std::string hex18("010000000248607113dbd2ba196e6775b73c72f30be49812f81453482c7b3d85a9f78fe58000000000fd2a0147304402203958f87dfcddc87736a2293dd0f96f6dbfafa22293174df6504d02d6a071aa1a0220664aa1768b37c95d088aa5b015f23967fbd65fd5d5dc9aacd97409a174fb1bc0412102fed69e18668b77306687eba57fcf31b3a556035e631508cf39cc7795b4a0ce764830450221009688a3ddd8f9eb0f819ca40bb87ad0722ef751a73b8d83869caf46bed92c6e4a0220641a07683a80e79c6dc8b8b4a4de625670cd3b96942f722aacfd8368b33db5dc4121025f44adfa89cc33c42def4165be539a523c3d3fd7e537bc1e9bd44b32fa341cfd0773667040302e33483045022100ab1f5b82890d3b15cce4f339ca828b723cf61b8a3481f421c81c431cd136ac5a02205e9290b86e817d3841060de69482d96823473924f78b152d342f6b284cbc13540001000100ffffffff713a2d315f05de1663a328089891d1e124cf1d08807db9b5aa703c2f813440a0010000006b483045022100b264964591681a64e85f6e1b44f539d3c34e96ab0c2e9926201670b0e7e73ba2022038eac1af53500c59617a9b43cf5f836fb060a410b1408b51f544fcf79bf0a56d412102fcba6a8aa57f4c499d45f7bd4a95534d77445c715061e32d15b38ccaead031a8ffffffff023502000000000000fd9801610773667040302e33246164336362313833316165622e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a91450858063dd4b422815b61edf2d998425a03dd13f142ca3d8061b9c7171c5ae7c4c0bc10781916139a7473045022100ff2e39193d20ca0c6e81a64fec1951a0c3372ff6ee3427bea5d4558387ba88cd02202f2675c27720a3ecb3b4d158cf7f974bc21dc24741ccb3a803a404e4fa8e63632448607113dbd2ba196e6775b73c72f30be49812f81453482c7b3d85a9f78fe58000000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0b0100000000000000080000ddd0f505000000001976a914331c8f9805a478023989773cdaa34588d9846cc588ac00000000");

    extractUtxoFromBsvjsTx(utxos, hex18);*/

    if(utxos.size() > 0) {
        //rc = sqlite3_open("test.db", &db);
        rc = sqlite3_open(path.c_str(), &db);

        if( rc ) {
          fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
          return;
        } else {
          fprintf(stderr, "Opened database successfully\n");
        }

        for (std::map<std::string,Utxo>::iterator it=utxos.begin(); it!=utxos.end(); ++it) {
            Utxo utxo = it->second;

            Records records;

            std::string sql_query = std::string("SELECT * FROM UTXOS WHERE UTXO_ID = '") + utxo.utxo_id + std::string("';");

            sql = (char *) sql_query.c_str();

            rc = sqlite3_exec(db, sql, select_callback, &records, &zErrMsg);
            //sqlite3_exec(db, sql, callback, 0, &zErrMsg);
            if( rc != SQLITE_OK ) {
                fprintf(stderr, "SQL error: %s\n", zErrMsg);
                sqlite3_free(zErrMsg);
            } else {
                fprintf(stdout, "Operation done successfully\n");
                printf("%lu records returned\n", records.size());

                if(records.size() == 0) {

                    size_t id = 1;

                    Records records0;

                    sql = (char *) "SELECT * FROM UTXOS";

                    sqlite3_exec(db, sql, select_callback, &records0, &zErrMsg);
                    if( rc != SQLITE_OK ) {
                        fprintf(stderr, "SQL error: %s\n", zErrMsg);
                        sqlite3_free(zErrMsg);
                    } else {
                        fprintf(stdout, "Select * From Utxos done successfully\n");
                        printf("%lu records returned\n", records0.size());

                        id = 1 + records0.size();
                        utxo.id = id;
                    }

                    std::string sql_query0 = std::string("INSERT INTO UTXOS (ID,UTXO_ID,WALLET_ID,FROM_WALLET_ID,SATOSHIS,\
                        ADDRESS,ADDRESS_INDEX,TXID,VOUT,SCRIPT,SPENT_TXID,AMOUNT,ASSET_ID) VALUES (") + \
                        std::to_string(utxo.id) + std::string(", '") + \
                         utxo.utxo_id + std::string("', ") + \
                        std::to_string(utxo.wallet_id) + std::string(", ") + \
                        std::to_string(utxo.from_wallet_id) + std::string(", ") + \
                        std::to_string(utxo.satoshis) + std::string(", '") + \
                        utxo.address + std::string("', ") + \
                        std::to_string(utxo.address_index) + std::string(", '") + \
                        utxo.txid + std::string("', ") + \
                        std::to_string(utxo.vout) + std::string(", '") + \
                        utxo.script + std::string("', '") + \
                        utxo.spent_txid + std::string("', ") + \
                        std::to_string(utxo.amount) + std::string(", ") + \
                        std::to_string(utxo.asset_id) + std::string("); ");

                  //printf("sql_query0 = %s\n", sql_query0.c_str());

                    sql = (char *) sql_query0.c_str();

                    sqlite3_exec(db, sql, callback, 0, &zErrMsg);
                    if( rc != SQLITE_OK ) {
                        fprintf(stderr, "SQL error: %s\n", zErrMsg);
                        sqlite3_free(zErrMsg);
                    } else {
                        fprintf(stdout, "Insert into Utxos done successfully\n");
                    }
                } else {
                    std::string sql_query0 = std::string("UPDATE UTXOS SET");
                    if(utxo.wallet_id != 0) {
                        sql_query0 = sql_query0 + std::string(" WALLET_ID = ") + std::to_string(utxo.wallet_id) + std::string(",");
                    }
                    if(utxo.from_wallet_id != 0) {
                        sql_query0 = sql_query0 + std::string(" FROM_WALLET_ID = ") + std::to_string(utxo.from_wallet_id) + std::string(",");
                    }
                    if(utxo.satoshis != 0) {
                        sql_query0 = sql_query0 + std::string(" SATOSHIS = ") + std::to_string(utxo.satoshis) + std::string(",");
                    }
                    if(utxo.address != std::string("")) {
                        sql_query0 = sql_query0 + std::string(" ADDRESS = '") + utxo.address + std::string("',");
                    }
                    if(utxo.address_index != 0) {
                        sql_query0 = sql_query0 + std::string(" ADDRESS_INDEX = ") + std::to_string(utxo.address_index) + std::string(",");
                    }
                    if(utxo.txid != std::string("")) {
                        sql_query0 = sql_query0 + std::string(" TXID = '") + utxo.txid + std::string("',");
                    }
                    if(utxo.vout != 0) {
                        sql_query0 = sql_query0 + std::string(" VOUT = ") + std::to_string(utxo.vout) + std::string(",");
                    }
                    if(utxo.script != std::string("")) {
                        sql_query0 = sql_query0 + std::string(" SCRIPT = '") + utxo.script + std::string("',");
                    }
                    if(utxo.spent_txid != std::string("")) {
                        sql_query0 = sql_query0 + std::string(" SPENT_TXID = '") + utxo.spent_txid + std::string("',");
                    }
                    if(utxo.amount != 0) {
                        sql_query0 = sql_query0 + std::string(" AMOUNT = ") + std::to_string(utxo.amount) + std::string(",");
                    }
                    if(utxo.asset_id != 0) {
                        sql_query0 = sql_query0 + std::string(" ASSET_ID = ") + std::to_string(utxo.asset_id) + std::string(",");
                    }

                    sql_query0 = sql_query0.substr(0, sql_query0.size()-1) + std::string(" WHERE UTXO_ID = '") + utxo.utxo_id + std::string("';");;

                    //printf("sql_query0 = %s\n", sql_query0.c_str());

                    sql = (char *) sql_query0.c_str();

                    sqlite3_exec(db, sql, callback, 0, &zErrMsg);
                    if( rc != SQLITE_OK ) {
                        fprintf(stderr, "SQL error: %s\n", zErrMsg);
                        sqlite3_free(zErrMsg);
                    } else {
                        fprintf(stdout, "Update Utxos done successfully\n");
                    }
                }
            }
        }

    printf("PRINTING UTXOS TABLE\n");
        sql = (char *) "SELECT * FROM UTXOS";

        sqlite3_exec(db, sql, callback, 0, &zErrMsg);
        if( rc != SQLITE_OK ) {
            fprintf(stderr, "SQL error: %s\n", zErrMsg);
            sqlite3_free(zErrMsg);
        } else {
            fprintf(stdout, "Operation done successfully\n");
        }
        sqlite3_close(db);

    }

    //sqlite3 *db;
    //char *zErrMsg = 0;
    //int rc;
    //char *sql;

    /*rc = sqlite3_open("test.db", &db);

    Records records0;
    size_t id = 1;
    sql = (char *) "SELECT * FROM ASSETS where PAYMAIL_ALIAS = 'ad3cb1831aeb.asset'";
    rc = sqlite3_exec(db, sql, select_callback, &records0, &zErrMsg);
    if( rc != SQLITE_OK ) {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    } else {
        fprintf(stdout, "Operation done successfully\n");
        printf("%lu records returned\n", records0.size());
        id = id + records0.size();
    }

    sqlite3_close(db);*/

}

static void initializeWallet (std::string path) {
  sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    char *sql;
    //const char* data = "Callback function called";

    //rc = sqlite3_open("test.db", &db);
    rc = sqlite3_open(path.c_str(), &db);

    if( rc ) {
      fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
      return;
    } else {
      fprintf(stderr, "Opened database successfully\n");
    }

    sql = (char *) "DROP TABLE WALLETS;"; //NEED TO DROP FOR SOME REASON
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

    /* Create SQL statement */
    sql = (char *) "CREATE TABLE WALLETS("  \
      "ID INT PRIMARY KEY     NOT NULL," \
      "USER_ID         BIGINT," \
        "MNEMONIC       CHAR(2000)," \
        "XPUB           CHAR(255)," \
        "LAST_USED_ADDRESS_INDEX       INT," \
        "NEXT_ADDRESS_INDEX       INT);";

    /* Execute SQL statement */
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

    if( rc != SQLITE_OK ){
      fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
    } else {
      fprintf(stdout, "WALLETS Table created successfully\n");
    }

  sql = (char *) "INSERT INTO WALLETS (ID,USER_ID,MNEMONIC,XPUB,LAST_USED_ADDRESS_INDEX,NEXT_ADDRESS_INDEX) "  \
        "VALUES (2, 5, 'sense tent make blue industry fantasy brush army make gather quote discover'," \
               "'tpubDEVpyDo8xspSmcmQX7GVRitdfis6S9QsWxA5oMB1ScFAc5yYxjS9775gaPvr1Egq7bhAbYHaEwfGsuCnpKqd3rsU1DnCYH1ar3Zt54j7N7j'," \
               "-1, 10); ";

 /* Execute SQL statement */
  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

  if( rc != SQLITE_OK ){
     fprintf(stderr, "SQL error: %s\n", zErrMsg);
     sqlite3_free(zErrMsg);
  } else {
     fprintf(stdout, "WALLETS Record created successfully\n");
  }

  sql = (char *) "INSERT INTO WALLETS (ID,USER_ID,MNEMONIC,XPUB,LAST_USED_ADDRESS_INDEX,NEXT_ADDRESS_INDEX) "  \
        "VALUES (3, 6, 'start area few frequent ocean blouse across game account sport prosper soda'," \
               "'tpubDFUpCAWz7aHga4p1uwPpuJiVFcixAhaSAgJsTQAK59mWhyhhiVnRdMSNje15HLXDVjkGxAmuSFqzocsGUXcNhC9vnjpgB5CjvT31geutCfg'," \
               "-1, 2); ";

 /* Execute SQL statement */
  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

  if( rc != SQLITE_OK ){
     fprintf(stderr, "SQL error: %s\n", zErrMsg);
     sqlite3_free(zErrMsg);
  } else {
     fprintf(stdout, "WALLETS Record created successfully\n");
  }

    sqlite3_close(db);
}

static int getLastUsedAddressIndex (int64_t id, std::string path) {
  sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    char *sql;
    //const char* data = "Callback function called";

  int ret = -1;

    //rc = sqlite3_open("test.db", &db);
    rc = sqlite3_open(path.c_str(), &db);

    if( rc ) {
      fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
      return ret;
    } else {
      fprintf(stderr, "Opened database successfully\n");
    }

  std::vector<std::string> addresses;
  std::vector<std::string> usedAddresses;

  Records records;
    std::string sql_query = std::string("SELECT ADDRESS_INDEX, ADDRESS FROM ADDRESSES WHERE WALLET_ID = ") + std::to_string(id) + \
  std::string(" ORDER BY ADDRESS_INDEX DESC LIMIT ") + std::to_string(BIP_44_ADDRESS_GAP_LIMIT + 1) + std::string("; ");
  //std::string sql_query = std::string("SELECT * FROM ADDRESSES WHERE WALLET_ID = ") + std::to_string(id) + \
  std::string(" ORDER BY ADDRESSES.INDEX DESC LIMIT ") + std::to_string(BIP_44_ADDRESS_GAP_LIMIT + 1) + std::string("; ");
    printf("sql_query: %s\n", sql_query.c_str());
    //sql = (char *) "SELECT * FROM ASSETS";
    sql = (char *) sql_query.c_str();
    rc = sqlite3_exec(db, sql, select_callback, &records, &zErrMsg);
    //sqlite3_exec(db, sql, callback, 0, &zErrMsg);
    if( rc != SQLITE_OK ) {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    } else {
        fprintf(stdout, "Operation done successfully\n");
        printf("%lu records returned\n", records.size());

    for(size_t i = 0; i < records.size(); i++) {
      addresses.push_back(records[i][1]);
      Records records0;
        std::string sql_query0 = std::string("SELECT ADDRESS FROM UTXOS WHERE ADDRESS = '") + addresses[i] + std::string("'; ");

      //printf("sql_query0: %s\n", sql_query0.c_str());
        //sql = (char *) "SELECT * FROM ASSETS";
        sql = (char *) sql_query0.c_str();
        rc = sqlite3_exec(db, sql, select_callback, &records0, &zErrMsg);
        //sqlite3_exec(db, sql, callback, 0, &zErrMsg);
        if( rc != SQLITE_OK ) {
            fprintf(stderr, "SQL error: %s\n", zErrMsg);
            sqlite3_free(zErrMsg);
        } else {
            fprintf(stdout, "Operation done successfully\n");
        if(records0.size() == 0) printf("sql_query0: %s\n", sql_query0.c_str());
            printf("%lu records returned\n", records0.size());

        for(size_t j = 0; j < records0.size(); j++) {
          usedAddresses.push_back(records0[j][0]);
        }

      }

    }

    for(size_t i = 0; i < addresses.size(); i++) {
      for(size_t j = 0; j < usedAddresses.size(); j++) {
        if(addresses[i] == usedAddresses[j]) {
          ret = std::stoi(records[i][0]);
          printf("Index = %d\n", ret);
          sqlite3_close(db);
          return ret;
        }
      }
    }


  }

  sqlite3_close(db);
  return ret;
}

static int calculateNextAddressIndex (int lastUsedAddressIndex, int nextAddressIndex) {
  printf("lastUsedAddressIndex = %d\n", lastUsedAddressIndex);
  printf("nextAddressIndex = %d\n", nextAddressIndex);
  printf("BIP_44_ADDRESS_GAP_LIMIT = %d\n", BIP_44_ADDRESS_GAP_LIMIT);
  if (nextAddressIndex >= lastUsedAddressIndex + BIP_44_ADDRESS_GAP_LIMIT) {
    return lastUsedAddressIndex + 1;
  }
  return nextAddressIndex + 1;
}

static std::string getNewReceiveAddressById(int64_t id, std::string path) {
  sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    char *sql;
    //const char* data = "Callback function called";

    //rc = sqlite3_open("test.db", &db);
    rc = sqlite3_open(path.c_str(), &db);

    if( rc ) {
      fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
      return std::string("");
    } else {
      fprintf(stderr, "Opened database successfully\n");
    }

  Records records;
    std::string sql_query = std::string("SELECT * FROM WALLETS WHERE ID = ") + std::to_string(id) + std::string("; ");
    printf("sql_query: %s\n", sql_query.c_str());
    //sql = (char *) "SELECT * FROM ASSETS";
    sql = (char *) sql_query.c_str();
    rc = sqlite3_exec(db, sql, select_callback, &records, &zErrMsg);
    //sqlite3_exec(db, sql, callback, 0, &zErrMsg);
    if( rc != SQLITE_OK ) {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    } else {
        fprintf(stdout, "Operation done successfully\n");
        printf("%lu records returned\n", records.size());

    if(records.size() > 0) {
      std::string mnemonic = records[0][2];
      std::string xpub = records[0][3];
      printf("XPUB = %s\n", xpub.c_str());
      int nextAddressIndex = std::stoi(records[0][5]);
      printf("nextAddressIndex = %d\n", nextAddressIndex);

      sqlite3_close(db);

      int lastUsedAddressIndex = getLastUsedAddressIndex(id, path);

      int updatedNextAddressIndex = calculateNextAddressIndex(lastUsedAddressIndex, nextAddressIndex);

      //rc = sqlite3_open("test.db", &db);
        rc = sqlite3_open(path.c_str(), &db);

        if( rc ) {
          fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
          return std::string("");
        } else {
          fprintf(stderr, "Opened database successfully\n");
        }

      std::string sql_query0 = std::string("UPDATE WALLETS SET NEXT_ADDRESS_INDEX = ") + std::to_string(updatedNextAddressIndex) + \
      std::string(" WHERE ID = ") + std::to_string(id) + std::string("; ");
        printf("sql_query: %s\n", sql_query0.c_str());
        //sql = (char *) "SELECT * FROM ASSETS";
        sql = (char *) sql_query0.c_str();
        rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

      if( rc != SQLITE_OK ) {
            fprintf(stderr, "SQL error: %s\n", zErrMsg);
            sqlite3_free(zErrMsg);
        } else {
            fprintf(stdout, "Operation done successfully\n");
      }

      #if MAINNET
                SelectParams(CBaseChainParams::MAIN);
            #else
                SelectParams(CBaseChainParams::TESTNET);
            #endif
            ECC_Start();

      //unsigned char code[BIP32_EXTKEY_SIZE + 4];
      /*unsigned char code[BIP32_EXTKEY_SIZE];
      std::vector<unsigned char> vchRet;
        int max_ret_len = 100;
        bool res = DecodeBase58Check(xpub, vchRet, max_ret_len);
        //for(size_t i = 0; i < BIP32_EXTKEY_SIZE + 4; i++) {
      for(size_t i = 4; i < BIP32_EXTKEY_SIZE + 4; i++) {
            printf("%02x", vchRet[i]);
        code[i - 4] = vchRet[i];
        }
        printf("\n");

      printf("BIP32_EXTKEY_SIZE = %d\n", BIP32_EXTKEY_SIZE);
      printf("vchRet.size() = %lu\n", vchRet.size());

      CExtKey basePrivKey;
      basePrivKey.Decode(code);

      printf("basePrivKey.nDepth = %hhu\n", basePrivKey.nDepth);
      printf("basePrivKey.nChild = %u\n", basePrivKey.nChild);

      printf("basePrivKey.vchFingerprint:\n");
      for(size_t i = 0; i < 4; i++) {
            printf("%02x", basePrivKey.vchFingerprint[i]);
        }
        printf("\n");

      CExtKey bip32 = basePrivKey;
      //CExtKey bip32;
      bool res_ = bip32.Derive(bip32, updatedNextAddressIndex);
      //bool res_ = basePrivKey.Derive(bip32, updatedNextAddressIndex);

      std::string Wif = EncodeSecret(bip32.key);
      printf("Wif = %s\n", Wif.c_str());

      CKey privKey = DecodeSecret(Wif);

            CPubKey pubKey = privKey.GetPubKey();
            CTxDestination addr = CTxDestination(PKHash(pubKey));
      std::string address = EncodeDestination(addr);
      printf("Address = %s\n", address.c_str());*/

      //std::string mnemonic("humble satisfy matrix magic february exit can now fluid panther demand design");

        std::vector<unsigned char> mbuf = hexToUchBuffer(stringToHex(mnemonic));
        printf("Mneumonic Buf: \n");
        for(size_t i = 0; i < mbuf.size(); i++) {
            printf("%02x", mbuf[i]);
        }
        printf("\n");

        //std::string pbuf("6d6e656d6f6e6963");

        std::string passphrase("");

        std::string pstr = std::string("mnemonic") + passphrase;

        std::vector<unsigned char> pbuf = hexToUchBuffer(stringToHex(pstr));

        uint32_t rounds = 2048;


        std::vector<unsigned char, secure_allocator<unsigned char>> vchKey;
        //vchKey.resize(wallet::WALLET_CRYPTO_KEY_SIZE);
        vchKey.resize(CSHA512::OUTPUT_SIZE);
        //BytesToKeySHA512AES_(mbuf, hexToUchBuffer(pbuf), rounds, vchKey.data(), vchIV.data());
        BytesToKeySHA512AES_(mbuf, pbuf, rounds, vchKey.data());
        //printf("vchKey.data() = %s\n", vchKey.data());

        printf("SEED: \n");
        for(size_t i = 0; i < vchKey.size(); i++) {
            printf("%02x", vchKey[i]);
        }
        printf("\n");

        //std::string seedStr_(vchKey.data());
        //printf("SEED STR = %s\n", stringToHex(seedStr_).c_str());

        char hex_[CSHA512::OUTPUT_SIZE*2];

        for (int i = 0, j = 0; i < CSHA512::OUTPUT_SIZE; ++i, j += 2) {
            //printf("%02x", str.c_str()[i] & 0xff);
            sprintf(hex_ + j, "%02x", vchKey[i] & 0xff);
        }
        //printf("\n");
        std::string seedStr(hex_);

        printf("RET: %s\n", seedStr.c_str());

        std::vector<unsigned char> seed = hexToUchBuffer(seedStr);

        CExtKey basePrivKey;
      basePrivKey.SetSeed(seed);

      std::string Wif = EncodeSecret(basePrivKey.key);
      printf("Wif = %s\n", Wif.c_str());

      std::vector<unsigned int> childIndexes;
      childIndexes.push_back(2147483692);
      childIndexes.push_back(2147483648);
      childIndexes.push_back(2147483648);
      childIndexes.push_back(0);

      //CExtKey bip32 = basePrivKey;
      for(size_t i = 0; i < childIndexes.size(); i++) {
          bool res_ = basePrivKey.Derive(basePrivKey, childIndexes[i]);
      }

      //CExtKey bip32_ = bip32;

      std::string Wif2 = EncodeSecret(basePrivKey.key);
      printf("Wif2 = %s\n", Wif2.c_str());

      CExtKey bip32 = basePrivKey;

      //bool res = basePrivKey.Derive(bip32, 41); //"muyeUy6h8KGXPYjmBDaGbp21FKNPc5pHLm"
      bool res = bip32.Derive(bip32, nextAddressIndex);

      std::string Wif3 = EncodeSecret(bip32.key);
      printf("Wif3 = %s\n", Wif3.c_str());

      CKey privKey = DecodeSecret(Wif3);

            CPubKey pubKey = privKey.GetPubKey();
            CTxDestination addr = CTxDestination(PKHash(pubKey));
      std::string receiveAddress = EncodeDestination(addr);
      printf("Address = %s\n", receiveAddress.c_str());

      ECC_Stop();

      Records records1;

      std::string sql_query1 = std::string("SELECT * FROM ADDRESSES WHERE ADDRESS = '") + receiveAddress + std::string("'; ");
        printf("sql_query: %s\n", sql_query1.c_str());
        //sql = (char *) "SELECT * FROM ASSETS";
        sql = (char *) sql_query1.c_str();
        rc = sqlite3_exec(db, sql, select_callback, &records1, &zErrMsg);

      if( rc != SQLITE_OK ) {
            fprintf(stderr, "SQL error: %s\n", zErrMsg);
            sqlite3_free(zErrMsg);
        } else {
            fprintf(stdout, "Operation done successfully\n");
        printf("%lu records returned\n", records1.size());

        if(records1.size() == 0) {
          int64_t index = -1;

          Records records2;
          //sql = (char *) "INSERT INTO ADDRESSES (ID,WALLET_ID,ADDRESS,ADDRESS_INDEX) "  \
                 "VALUES (84, 2, 'miCqC3Ln22MC5tV2QTnVcmXsUJvLHsamR6', 51); ";
          std::string sql_query2 = std::string("SELECT * FROM ADDRESSES ORDER BY ID DESC;");
          printf("sql_query: %s\n", sql_query2.c_str());
          //sql = (char *) "SELECT * FROM ASSETS";
          sql = (char *) sql_query2.c_str();
          rc = sqlite3_exec(db, sql, select_callback, &records2, &zErrMsg);

          if( rc != SQLITE_OK ) {
              fprintf(stderr, "SQL error: %s\n", zErrMsg);
              sqlite3_free(zErrMsg);
          } else {
              fprintf(stdout, "Operation done successfully\n");
            printf("%lu records returned\n", records2.size());

            if(records2.size() > 0) {
              index = std::stoll(records2[0][0]) + 1;
              printf("Index = %lld\n", index);
            }
          }
          std::string sql_query3 = std::string("INSERT INTO ADDRESSES (ID,WALLET_ID,ADDRESS,ADDRESS_INDEX) VALUES(") + \
          std::to_string(index) + std::string(", ") + std::to_string(id) + std::string(", '") + receiveAddress + \
          std::string("', ") + std::to_string(nextAddressIndex) + std::string("); ");
            printf("sql_query: %s\n", sql_query3.c_str());
            //sql = (char *) "SELECT * FROM ASSETS";
            sql = (char *) sql_query3.c_str();
            rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

          if( rc != SQLITE_OK ) {
                fprintf(stderr, "SQL error: %s\n", zErrMsg);
                sqlite3_free(zErrMsg);
            } else {
                fprintf(stdout, "Operation done successfully\n");
          }
        }
      }

      sqlite3_close(db);

      return receiveAddress;
    }
  }

  sqlite3_close(db);
  return std::string("");
}

extern void authorizerGetAddress(char *str, long size, const char *script) {
    
    std::string txOut(script);
    std::vector<unsigned char> txOutBuf = hexToUchBuffer(txOut);
    CScript txOutScript(txOutBuf.begin(), txOutBuf.end());
    std::vector<Chunks> chunks = getChunks(txOutScript);
    std::string addr = EncodeBase58Check(hexToUchBuffer(std::string(pubKeyHash) + chunks[Sfp::OWNER].buf));
    
    snprintf(str, size, "%s", addr.c_str());
}
    
extern bool authorizerCheckAddress(const char *address, const char *script) {
    
    //std::string txOut("610773667040302e33246164336362313833316165622e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a914f1f354fceb000dbacb1d665dbf285d355d771f9a142ca3d8061b9c7171c5ae7c4c0bc10781916139a746304402202653e382fe17b7c95f81fd36edee5f4fd1cb1a84777a5d83cb76e521359b4af50220622d1e452615cc7b0eb32af9d1a3d7b40915645cdd76290330927b74171e4afe24405a644b436819e24c2770231c4498fba7eba40b051f073655daddf58155939100000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0b0100000000000000080000");
    
    std::string txOut(script);
    std::vector<unsigned char> txOutBuf = hexToUchBuffer(txOut);
    CScript txOutScript(txOutBuf.begin(), txOutBuf.end());
    std::vector<Chunks> chunks = getChunks(txOutScript);
    std::string addr = EncodeBase58Check(hexToUchBuffer(std::string(pubKeyHash) + chunks[Sfp::OWNER].buf));
    
    printf("addr = %s\n", addr.c_str());
    
    if(strcmp(address, addr.c_str()) == 0) {
        return true;
    }
    
    return false;
}

extern bool authorizerCheckSFP(const char *script) {
    std::string txOut(script);
    std::vector<unsigned char> txOutBuf = hexToUchBuffer(txOut);
    CScript txOutScript(txOutBuf.begin(), txOutBuf.end());
    std::vector<Chunks> chunks = getChunks(txOutScript);
    
    std::string version = hexToString(chunks[Sfp::VERSION].buf);

    std::string delimiter = "@";
    std::string type = version.substr(0, version.find(delimiter));

    printf("TYPE: %s\n", type.c_str());
    if(strcmp(type.c_str(), "sfp") == 0) {
        return true;
    }
    return false;
}

void initializeDB(std::string path) {
  sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    char *sql;
    //const char* data = "Callback function called";

    //rc = sqlite3_open("test.db", &db);
    rc = sqlite3_open(path.c_str(), &db);

    if( rc ) {
      fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
    return;
    } else {
      fprintf(stderr, "Opened database successfully\n");
    }

    sql = (char *) "DROP TABLE SFP_UTXOS;";
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

    /* Create SQL statement */
    sql = (char *) "CREATE TABLE SFP_UTXOS("  \
      "ID INT PRIMARY KEY     NOT NULL," \
      "ASSET_ID       INT    NOT NULL," \
      "TXID           CHAR(64) NOT NULL," \
      "VOUT                INT," \
      "SCRIPT         TEXT," \
        "SATOSHIS       BIGINT," \
        "AMOUNT         BIGINT );";

    /* Execute SQL statement */
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

    if( rc != SQLITE_OK ){
      fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
    } else {
      fprintf(stdout, "SFP_UTXOS Table created successfully\n");
    }

  /*sql = (char *) "INSERT INTO SFP_UTXOS (ID,ASSET_ID,TXID,VOUT,SCRIPT,SATOSHIS,AMOUNT) "  \
        "VALUES (1, 1, '3d5eb86b889942127b469425327f7753fb7ff3900f2db3e63d9ee8e0d9023239', 0," \
               "'610773667040302e33243136363264386235323832322e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a9143417e66193cde6c4c2b4c3ca39ba8675dbb0e66b143417e66193cde6c4c2b4c3ca39ba8675dbb0e66b4630440220378f23b86600e8b42d0b095aea95530ab03865d9f190532ec7107b38c19a748302205ddd5ef721cbb5eb9bd28d976a01561c959e7dd488530a3aa042a44043d37c32246cbd06039e6be101be3bafc50fdd3ddf4459a7ad505cd04b3a1186d73a04ee8f00000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0d01000000000000007b7d0a0000'," \
               "'566', '1'); ";

  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

  if( rc != SQLITE_OK ){
     fprintf(stderr, "SQL error: %s\n", zErrMsg);
     sqlite3_free(zErrMsg);
  } else {
     fprintf(stdout, "SFP_UTXOS Record created successfully\n");
  }*/

    sql = (char *) "DROP TABLE SFP_ASSETS;";
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

    /* Create SQL statement */
    sql = (char *) "CREATE TABLE SFP_ASSETS("  \
      "ID INT PRIMARY KEY     NOT NULL," \
      "ALIAS           CHAR(100) NOT NULL," \
      "ISSUER_ADDRESS         CHAR(100));";

    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

    if( rc != SQLITE_OK ){
      fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
    } else {
      fprintf(stdout, "SFP_ASSETS Table created successfully\n");
    }

  /*sql = (char *) "INSERT INTO SFP_ASSETS (ID,ALIAS,ISSUER_ADDRESS) "  \
         "VALUES (1, 'ad3cb1831aeb.asset@buttonofmoney.com', 'mjazJZgmH6guLimtZoqb3kqbbo4VjwMsMd'); ";

  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

  if( rc != SQLITE_OK ){
     fprintf(stderr, "SQL error: %s\n", zErrMsg);
     sqlite3_free(zErrMsg);
  } else {
     fprintf(stdout, "SFP_ASSETS Record created successfully\n");
  }*/

    sql = (char *) "DROP TABLE ASSETS;";
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

    /* Create SQL statement */
    sql = (char *) "CREATE TABLE ASSETS("  \
      "ID INT PRIMARY KEY     NOT NULL," \
        "INITIAL_SUPPLY         BIGINT," \
        "PAYMAIL_ALIAS             CHAR(255)," \
        "MINTING_SCRIPT         TEXT);";

    /* Execute SQL statement */
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

    if( rc != SQLITE_OK ){
      fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
    } else {
      fprintf(stdout, "ASSETS Table created successfully\n");
    }

    /*sql = (char *) "INSERT INTO ASSETS (ID,NAME,USER_ID,INITIAL_SUPPLY,PAYMAIL_ALIAS,MINTING_SCRIPT) "  \
         "VALUES (1, 'Token1', 5, 1, '1662d8b52822.asset', '610773667040302e33243136363264386235323832322e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a9143417e66193cde6c4c2b4c3ca39ba8675dbb0e66b143417e66193cde6c4c2b4c3ca39ba8675dbb0e66b4630440220378f23b86600e8b42d0b095aea95530ab03865d9f190532ec7107b38c19a748302205ddd5ef721cbb5eb9bd28d976a01561c959e7dd488530a3aa042a44043d37c32246cbd06039e6be101be3bafc50fdd3ddf4459a7ad505cd04b3a1186d73a04ee8f00000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0d01000000000000007b7d0a0000'); ";


  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

  if( rc != SQLITE_OK ){
     fprintf(stderr, "SQL error: %s\n", zErrMsg);
     sqlite3_free(zErrMsg);
  } else {
     fprintf(stdout, "ASSETS Record created successfully\n");
  }*/

  sqlite3_close(db);
}

void initializeDB_old(std::string path) {
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    char *sql;
    const char* data = "Callback function called";

    //rc = sqlite3_open("test.db", &db);
    rc = sqlite3_open(path.c_str(), &db);

    if( rc ) {
      fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
      return(0);
    } else {
      fprintf(stderr, "Opened database successfully\n");
    }

    sql = (char *) "DROP TABLE SFP_UTXOS;";
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

    /* Create SQL statement */
    sql = (char *) "CREATE TABLE SFP_UTXOS("  \
      "ID INT PRIMARY KEY     NOT NULL," \
      "ASSET_ID       INT    NOT NULL," \
      "TXID           CHAR(64) NOT NULL," \
      "VOUT                INT," \
      "SCRIPT         TEXT," \
        "SATOSHIS       BIGINT," \
        "AMOUNT         BIGINT );";

    /* Execute SQL statement */
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

    if( rc != SQLITE_OK ){
      fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
    } else {
      fprintf(stdout, "SFP_UTXOS Table created successfully\n");
    }


  //VALUES (13, ...)
    /* Create SQL statement */
  //sql = (char *) "INSERT INTO SFP_UTXOS (ID,ASSET_ID,TXID,VOUT,SCRIPT,SATOSHIS,AMOUNT) "  \
         "VALUES (1, 1, '91935581f5ddda5536071f050ba4eba7fb98441c2370274ce21968434b645a40', 0," \
                 "'610773667040302e33246164336362313833316165622e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a9149e9e1f959811652b6b6741dfd3758fc2dac4389e142ca3d8061b9c7171c5ae7c4c0bc10781916139a746304402202ab94d63050c7acf3bad3b9fc038f195db57c22ff9045e510cf903fe7631b17d0220594056c20489e61521d11a7057d53ae422a25409d2fca155bf382bb6eb39d719242b3019b9bbdd9ea4af25e0c879a153f5b5c979ca4391835301338160c3c3deae00000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0b0100000000000000080000'," \
                 "'564', '1'); ";
  sql = (char *) "INSERT INTO SFP_UTXOS (ID,ASSET_ID,TXID,VOUT,SCRIPT,SATOSHIS,AMOUNT) "  \
        "VALUES (1, 2, 'faf51d1cafec2bc089c271ccc15a74faa03cb0e954485533bd675fb2de66487d', 0," \
               "'610773667040302e33243866353539383237353266372e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a91412f88c3fa18325a8e42100b1d5ffa16384fa50cf1412f88c3fa18325a8e42100b1d5ffa16384fa50cf4630440220794afb9e88984dda9c298c9857fbbfa5927318aa3eb97bd4b64b3d09b2ea54d60220264ffc692c47004b84cdf3dc6d569172c1e6cb71ccbcad179a78826f37374ac2246de1f73ca6ea14874933713e8478824f7fc0416a0b6c53d3d4412be1d7df2d9401000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0d01000000000000007b7d0a0000'," \
               "'566', '1'); ";

 /* Execute SQL statement */
  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

  if( rc != SQLITE_OK ){
     fprintf(stderr, "SQL error: %s\n", zErrMsg);
     sqlite3_free(zErrMsg);
  } else {
     fprintf(stdout, "SFP_UTXOS Record created successfully\n");
  }

  sql = (char *) "INSERT INTO SFP_UTXOS (ID,ASSET_ID,TXID,VOUT,SCRIPT,SATOSHIS,AMOUNT) "  \
        "VALUES (2, 2, '1734e148adbe61b3ea47e87f77f3b684f91f69640096b39ab0488ac67774edd7', 0," \
               "'610773667040302e33243866353539383237353266372e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a9141d783a74ab3d71e0e3ba79c94e398cafba9effc41412f88c3fa18325a8e42100b1d5ffa16384fa50cf4630440220305fee934d96fa861d52e85801aa794ac2a4f0138da619069f533732a16b25660220181328571869d47b4741497a894a03505f8c4edd763f31caccd56696eb1984d6247d4866deb25f67bd33554854e9b03ca0fa745ac1cc71c289c02becaf1c1df5fa00000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0b0100000000000000080000'," \
               "'564', '1'); ";

 /* Execute SQL statement */
  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

  if( rc != SQLITE_OK ){
     fprintf(stderr, "SQL error: %s\n", zErrMsg);
     sqlite3_free(zErrMsg);
  } else {
     fprintf(stdout, "SFP_UTXOS Record created successfully\n");
  }

  sql = (char *) "INSERT INTO SFP_UTXOS (ID,ASSET_ID,TXID,VOUT,SCRIPT,SATOSHIS,AMOUNT) "  \
        "VALUES (3, 2, 'dc7e17a734144d7648047f64405fd7956983feb733cb0f33fe12bef29e7165cb', 0," \
               "'610773667040302e33243866353539383237353266372e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a914024570df2d9092b044eed230f5aac1448919075a1412f88c3fa18325a8e42100b1d5ffa16384fa50cf46304402202f4faabde0430c3f3741be82c3437eedf5a4b9081e06a2729470d13582522c7f02202c778650ccb6c9d71ffeec89275a3025406f9a6fdf096e3c0a827d777a3a4ea924d7ed7477c68a48b09ab3960064691ff984b6f3777fe847eab361bead48e1341700000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0b0100000000000000080000'," \
               "'564', '1'); ";

 /* Execute SQL statement */
  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

  if( rc != SQLITE_OK ){
     fprintf(stderr, "SQL error: %s\n", zErrMsg);
     sqlite3_free(zErrMsg);
  } else {
     fprintf(stdout, "SFP_UTXOS Record created successfully\n");
  }

  sql = (char *) "INSERT INTO SFP_UTXOS (ID,ASSET_ID,TXID,VOUT,SCRIPT,SATOSHIS,AMOUNT) "  \
        "VALUES (4, 2, '109402280c7a5ae8d4c9e06a466299380a173d91ea4462ee701f37b110691fd3', 0," \
               "'610773667040302e33243866353539383237353266372e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a914432a14496b68288ec26f3877403ff8782bba0aec1412f88c3fa18325a8e42100b1d5ffa16384fa50cf473045022100e9e58abb4637de284561516b87c29a8e00c019b6f435e9aa6984cdfcde3011ef02202729a27042e13b64690c8a1f4e367264d14689c7c780ef36b8990ed0fdc2117b24cb65719ef2be12fe330fcb33b7fe836995d75f40647f0448764d1434a7177edc00000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0b0100000000000000080000'," \
               "'565', '1'); ";

 /* Execute SQL statement */
  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

  if( rc != SQLITE_OK ){
     fprintf(stderr, "SQL error: %s\n", zErrMsg);
     sqlite3_free(zErrMsg);
  } else {
     fprintf(stdout, "SFP_UTXOS Record created successfully\n");
  }

  sql = (char *) "INSERT INTO SFP_UTXOS (ID,ASSET_ID,TXID,VOUT,SCRIPT,SATOSHIS,AMOUNT) "  \
        "VALUES (5, 2, '0f8e052c32cf054eba9b03c02464efe738224f254824ba6077203f7dd3062d0b', 0," \
               "'610773667040302e33243866353539383237353266372e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a914b582f14ebc63fa84aff302ff371d276ceb7f96081412f88c3fa18325a8e42100b1d5ffa16384fa50cf473045022100e48d1445a443e9f5b807deef3413b83077ace44e7bfcb92b3df8be2dd7767a5402206ac96181a11141ffd4e61b05bf11897f3b68746d1094401a439b998bdf6811ce24d31f6910b1371f70ee6244ea913d170a389962466ae0c9d4e85a7a0c2802941000000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0b0100000000000000080000'," \
               "'565', '1'); ";

 /* Execute SQL statement */
  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

  if( rc != SQLITE_OK ){
     fprintf(stderr, "SQL error: %s\n", zErrMsg);
     sqlite3_free(zErrMsg);
  } else {
     fprintf(stdout, "SFP_UTXOS Record created successfully\n");
  }

  sql = (char *) "INSERT INTO SFP_UTXOS (ID,ASSET_ID,TXID,VOUT,SCRIPT,SATOSHIS,AMOUNT) "  \
        "VALUES (6, 2, 'd70f0f58fadaec3cad56b6d7d605dc1c912dbbac051fa104ec394844d1cd3c4a', 0," \
               "'610773667040302e33243866353539383237353266372e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a9141d72965e1b5d764b07229af4839e0aa63fb561861412f88c3fa18325a8e42100b1d5ffa16384fa50cf46304402202cd6aff9189019a9784347c97d8bfe9cf4b3eb4940e452eddf0e422654d58c2302201c411d3c92d19d56cfa020498751dd70c3e8565cf1c612c1e624a4ad241ef9e0240b2d06d37d3f207760ba2448254f2238e7ef6424c0039bba4e05cf322c058e0f00000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0b0100000000000000080000'," \
               "'564', '1'); ";

 /* Execute SQL statement */
  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

  if( rc != SQLITE_OK ){
     fprintf(stderr, "SQL error: %s\n", zErrMsg);
     sqlite3_free(zErrMsg);
  } else {
     fprintf(stdout, "SFP_UTXOS Record created successfully\n");
  }

    sql = (char *) "DROP TABLE SFP_ASSETS;";
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

    /* Create SQL statement */
    sql = (char *) "CREATE TABLE SFP_ASSETS("  \
      "ID INT PRIMARY KEY     NOT NULL," \
      "ALIAS           CHAR(100) NOT NULL," \
      "ISSUER_ADDRESS         CHAR(100));";

    /* Execute SQL statement */
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

    if( rc != SQLITE_OK ){
      fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
    } else {
      fprintf(stdout, "SFP_ASSETS Table created successfully\n");
    }

    /* Create SQL statement */
  sql = (char *) "INSERT INTO SFP_ASSETS (ID,ALIAS,ISSUER_ADDRESS) "  \
         "VALUES (1, 'ad3cb1831aeb.asset@buttonofmoney.com', 'mjazJZgmH6guLimtZoqb3kqbbo4VjwMsMd'); ";

 /* Execute SQL statement */
  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

  if( rc != SQLITE_OK ){
     fprintf(stderr, "SQL error: %s\n", zErrMsg);
     sqlite3_free(zErrMsg);
  } else {
     fprintf(stdout, "SFP_ASSETS Record created successfully\n");
  }

  sql = (char *) "INSERT INTO SFP_ASSETS (ID,ALIAS,ISSUER_ADDRESS) "  \
         "VALUES (2, '8f55982752f7.asset@buttonofmoney.com', 'mhFGCuy98LDwgHpUWyvvVcp3JLrigeFvdw'); ";

 /* Execute SQL statement */
  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

  if( rc != SQLITE_OK ){
     fprintf(stderr, "SQL error: %s\n", zErrMsg);
     sqlite3_free(zErrMsg);
  } else {
     fprintf(stdout, "SFP_ASSETS Record created successfully\n");
  }

    sql = (char *) "DROP TABLE ASSETS;";
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

    /* Create SQL statement */
    sql = (char *) "CREATE TABLE ASSETS("  \
      "ID INT PRIMARY KEY     NOT NULL," \
      "NAME                           CHAR(255)," \
        "USER_ID                     BIGINT," \
        "INITIAL_SUPPLY         BIGINT," \
        "PAYMAIL_ALIAS             CHAR(255)," \
        "MINTING_SCRIPT         TEXT);";

    /* Execute SQL statement */
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

    if( rc != SQLITE_OK ){
      fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
    } else {
      fprintf(stdout, "ASSETS Table created successfully\n");
    }

    sql = (char *) "INSERT INTO ASSETS (ID,NAME,USER_ID,INITIAL_SUPPLY,PAYMAIL_ALIAS,MINTING_SCRIPT) "  \
         "VALUES (1, 'Token1', 5, 1, 'ad3cb1831aeb.asset', '610773667040302e33246164336362313833316165622e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a9142ca3d8061b9c7171c5ae7c4c0bc10781916139a7142ca3d8061b9c7171c5ae7c4c0bc10781916139a7463044022029556bfe4aadb8a50fd326ac4f51e8cf4ddebe81823b1c0888ffb8d6bdbd7a29022053d8b1ad41978ee1ba56fee8fd40b71abae2cab8ddbf6cf20bc72820affa2f9b24ae3ea23a10a7af2e8fca307ec7393f8c039f632fe6c11f1e84cfd6f9b0b99b8f00000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0d01000000000000007b7d0a0000'); ";


 /* Execute SQL statement */
  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

  if( rc != SQLITE_OK ){
     fprintf(stderr, "SQL error: %s\n", zErrMsg);
     sqlite3_free(zErrMsg);
  } else {
     fprintf(stdout, "ASSETS Record created successfully\n");
  }

  sql = (char *) "INSERT INTO ASSETS (ID,NAME,USER_ID,INITIAL_SUPPLY,PAYMAIL_ALIAS,MINTING_SCRIPT) "  \
         "VALUES (2, 'Token1', 5, 1, '8f55982752f7.asset', '610773667040302e33243866353539383237353266372e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a91412f88c3fa18325a8e42100b1d5ffa16384fa50cf1412f88c3fa18325a8e42100b1d5ffa16384fa50cf4630440220794afb9e88984dda9c298c9857fbbfa5927318aa3eb97bd4b64b3d09b2ea54d60220264ffc692c47004b84cdf3dc6d569172c1e6cb71ccbcad179a78826f37374ac2246de1f73ca6ea14874933713e8478824f7fc0416a0b6c53d3d4412be1d7df2d9401000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0d01000000000000007b7d0a0000'); ";


 /* Execute SQL statement */
  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

  if( rc != SQLITE_OK ){
     fprintf(stderr, "SQL error: %s\n", zErrMsg);
     sqlite3_free(zErrMsg);
  } else {
     fprintf(stdout, "ASSETS Record created successfully\n");
  }

    sqlite3_close(db);
}

void createSFPUtxos(std::string path) {
  sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    char *sql;
    //const char* data = "Callback function called";

    //rc = sqlite3_open("test.db", &db);
    rc = sqlite3_open(path.c_str(), &db);

    if( rc ) {
      fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
      return;
    } else {
      fprintf(stderr, "Opened database successfully\n");
    }

  Records records;

  std::string sql_query = std::string("SELECT * FROM UTXOS WHERE ASSET_ID != 0;");

  sql = (char *) sql_query.c_str();

  rc = sqlite3_exec(db, sql, select_callback, &records, &zErrMsg);
  //sqlite3_exec(db, sql, callback, 0, &zErrMsg);
  if( rc != SQLITE_OK ) {
    fprintf(stderr, "SQL error: %s\n", zErrMsg);
    sqlite3_free(zErrMsg);
  } else {
    fprintf(stdout, "Operation done successfully\n");
    printf("%lu records returned\n", records.size());

    for(size_t i = 0; i < records.size(); i++) {

      Records records0;
      std::string sql_query0 = std::string("SELECT * FROM SFP_UTXOS WHERE TXID = '") + records[i][7] + std::string("';");
      sql = (char *) sql_query0.c_str();

      rc = sqlite3_exec(db, sql, select_callback, &records0, &zErrMsg);

      if( rc != SQLITE_OK ) {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
      } else {
        fprintf(stdout, "Operation done successfully\n");
        printf("%lu records returned\n", records0.size());

        if(records0.size() == 0) {
          int id = 1;
          Records records1;
          std::string sql_query1 = std::string("SELECT * FROM SFP_UTXOS;");
          sql = (char *) sql_query1.c_str();

          rc = sqlite3_exec(db, sql, select_callback, &records0, &zErrMsg);

          if( rc != SQLITE_OK ) {
            fprintf(stderr, "SQL error: %s\n", zErrMsg);
            sqlite3_free(zErrMsg);
          } else {
            fprintf(stdout, "Operation done successfully\n");
            printf("%lu records returned\n", records1.size());

            id = id + records1.size();
          }

          std::string sql_query2 = std::string("INSERT INTO SFP_UTXOS (ID,ASSET_ID,TXID,VOUT,SCRIPT,SATOSHIS,AMOUNT) ") + \
            std::string("VALUES (") + std::to_string(id) + std::string(", ") + records[i][12] + std::string(", '") + \
            records[i][7] + std::string("', ") + records[i][8] + std::string(", '") + records[i][9] + std::string("', '") + \
            records[i][4] + std::string("', '") + records[i][11] + std::string("');");

          sql = (char *) sql_query2.c_str();
          printf("sql_query2 = %s\n", sql_query2.c_str());

          rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

          if( rc != SQLITE_OK ) {
            fprintf(stderr, "SQL error: %s\n", zErrMsg);
            sqlite3_free(zErrMsg);
          } else {
            fprintf(stdout, "SFP_UTXOS Record Operation done successfully\n");
          }

        }

      }
    }
  }

  printf("PRINTING SFP_UTXOS TABLE\n");
  sql = (char *) "SELECT * FROM SFP_UTXOS";

  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
  if( rc != SQLITE_OK ) {
    fprintf(stderr, "SQL error: %s\n", zErrMsg);
    sqlite3_free(zErrMsg);
  } else {
    fprintf(stdout, "Operation done successfully\n");
  }

  sqlite3_close(db);
}

void createSFPAssets(std::string path) {
  printf("CREATE SFP ASSETS\n");
  sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    char *sql;
    //const char* data = "Callback function called";

    //rc = sqlite3_open("test.db", &db);
    rc = sqlite3_open(path.c_str(), &db);

    if( rc ) {
      fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
      return;
    } else {
      fprintf(stderr, "Opened database successfully\n");
    }

  Records records;

  std::string sql_query = std::string("SELECT * FROM UTXOS WHERE ASSET_ID != 0;");

  sql = (char *) sql_query.c_str();

  rc = sqlite3_exec(db, sql, select_callback, &records, &zErrMsg);
  //sqlite3_exec(db, sql, callback, 0, &zErrMsg);
  if( rc != SQLITE_OK ) {
    fprintf(stderr, "SQL error: %s\n", zErrMsg);
    sqlite3_free(zErrMsg);
  } else {
    fprintf(stdout, "Operation done successfully\n");
    printf("%lu records returned\n", records.size());

    for(size_t i = 0; i < records.size(); i++) {

      Records records0;
      std::string sql_query0 = std::string("SELECT * FROM SFP_ASSETS WHERE ISSUER_ADDRESS = '") + records[i][5] + std::string("';");
      sql = (char *) sql_query0.c_str();

      rc = sqlite3_exec(db, sql, select_callback, &records0, &zErrMsg);

      if( rc != SQLITE_OK ) {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
      } else {
        fprintf(stdout, "Operation done successfully\n");
        printf("%lu records returned\n", records0.size());

        if(records0.size() == 0) {
          int id = 1;
          Records records1;
          std::string sql_query1 = std::string("SELECT * FROM SFP_ASSETS;");
          sql = (char *) sql_query1.c_str();

          rc = sqlite3_exec(db, sql, select_callback, &records1, &zErrMsg);

          if( rc != SQLITE_OK ) {
            fprintf(stderr, "SQL error: %s\n", zErrMsg);
            sqlite3_free(zErrMsg);
          } else {
            fprintf(stdout, "Operation done successfully\n");
            printf("%lu records returned\n", records1.size());

            id = id + records1.size();
          }

          Records records2;
          std::string sql_query2 = std::string("SELECT * FROM ASSETS WHERE MINTING_SCRIPT = '") + records[i][9] + std::string("';");
          //std::string sql_query2 = std::string("SELECT * FROM ASSETS WHERE ID = ") + records[i][12] + std::string(";");
          //std::string sql_query2 = std::string("SELECT * FROM ASSETS;");
          sql = (char *) sql_query2.c_str();
          //printf("sql_query2 = %s\n", sql_query2.c_str());

          rc = sqlite3_exec(db, sql, select_callback, &records2, &zErrMsg);

          if( rc != SQLITE_OK ) {
            fprintf(stderr, "SQL error: %s\n", zErrMsg);
            sqlite3_free(zErrMsg);
          } else {
            fprintf(stdout, "Operation done successfully\n");
            printf("%lu records returned\n", records2.size());

            if(records2.size() > 0) {
              //sql = (char *) "INSERT INTO SFP_ASSETS (ID,ALIAS,ISSUER_ADDRESS) "  \
                     "VALUES (1, 'ad3cb1831aeb.asset@buttonofmoney.com', 'mjazJZgmH6guLimtZoqb3kqbbo4VjwMsMd'); ";
              std::string sql_query3 = std::string("INSERT INTO SFP_ASSETS (ID,ALIAS,ISSUER_ADDRESS) ") + \
                std::string("VALUES (") + std::to_string(id) + std::string(", '") + records2[i][2] + std::string("@buttonofmoney.com', '") + \
                records[i][5] + std::string("');");

              sql = (char *) sql_query3.c_str();
              //printf("sql_query3 = %s\n", sql_query2.c_str());

              rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

              if( rc != SQLITE_OK ) {
                fprintf(stderr, "SQL error: %s\n", zErrMsg);
                sqlite3_free(zErrMsg);
              } else {
                fprintf(stdout, "SFP_ASSETS Record Operation done successfully\n");
              }
            }
          }
        }
      }
    }
  }

  printf("PRINTING ASSETS TABLE\n");
  sql = (char *) "SELECT * FROM ASSETS";

  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
  if( rc != SQLITE_OK ) {
    fprintf(stderr, "SQL error: %s\n", zErrMsg);
    sqlite3_free(zErrMsg);
  } else {
    fprintf(stdout, "Operation done successfully\n");
  }

  printf("PRINTING SFP_ASSETS TABLE\n");
  sql = (char *) "SELECT * FROM SFP_ASSETS";

  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
  if( rc != SQLITE_OK ) {
    fprintf(stderr, "SQL error: %s\n", zErrMsg);
    sqlite3_free(zErrMsg);
  } else {
    fprintf(stdout, "Operation done successfully\n");
  }

  sqlite3_close(db);
}


extern bool isTxidUnspentSFPToken (long long walletId, const char *txid, const char *path_) {
  sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    char *sql;
    //const char* data = "Callback function called";

    std::vector<Utxo> utxos;
    
    std::string path = std::string(path_) + std::string("/sfp.db");
    printf("path: %s\n", path.c_str());

    //rc = sqlite3_open("test.db", &db);
    rc = sqlite3_open(path.c_str(), &db);

    if( rc ) {
      fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
      return false;
    } else {
      fprintf(stderr, "Opened database successfully\n");
    }

  Records records;

  std::string sql_query = std::string("SELECT * FROM UTXOS WHERE WALLET_ID = ") + std::to_string(walletId) + \
  std::string(" AND TXID = '") + txid + std::string("' AND SPENT_TXID = '' AND ASSET_ID != 0;");

  sql = (char *) sql_query.c_str();
  printf("sql_query = %s\n", sql_query.c_str());

  rc = sqlite3_exec(db, sql, select_callback, &records, &zErrMsg);
  //sqlite3_exec(db, sql, callback, 0, &zErrMsg);
  if( rc != SQLITE_OK ) {
    fprintf(stderr, "SQL error: %s\n", zErrMsg);
    sqlite3_free(zErrMsg);
  } else {
    fprintf(stdout, "Operation done successfully\n");
    printf("%lu records returned\n", records.size());

    if(records.size() > 0)
      return true;
  }

  return false;
}

std::string getMnemonic(int64_t walletId, std::string path) {
  sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    char *sql;

  std::string res("");

  //rc = sqlite3_open("test.db", &db);
    rc = sqlite3_open(path.c_str(), &db);

    if( rc ) {
      fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
      return res;
    } else {
      fprintf(stderr, "Opened database successfully\n");
    }

  Records records;

  std::string sql_query = std::string("SELECT * FROM WALLETS WHERE ID = ") + std::to_string(walletId) + std::string(";");

  sql = (char *) sql_query.c_str();

  rc = sqlite3_exec(db, sql, select_callback, &records, &zErrMsg);
  //sqlite3_exec(db, sql, callback, 0, &zErrMsg);
  if( rc != SQLITE_OK ) {
    fprintf(stderr, "SQL error: %s\n", zErrMsg);
    sqlite3_free(zErrMsg);
  } else {
    fprintf(stdout, "Operation done successfully\n");
    printf("%lu records returned\n", records.size());

    if(records.size() > 0) {
      res = records[0][2];
    }
  }
  sqlite3_close(db);
  return res;
}

extern void authorizerInitializeTables(const char *path_) {
    
    std::string path = std::string(path_) + std::string("/sfp.db");
    printf("path: %s\n", path.c_str());
    
    initializeWallet(path);
    
    initializeAddresses(path);
    
    initializeDB(path);

    initializeUtxos(path);
}

static int64_t getWalletIdByTxid(const char * txid_, std::string path) {
    sqlite3 *db;
      char *zErrMsg = 0;
      int rc;
      char *sql;
    
    std::string txid(txid_);

    int64_t res = 0;

      rc = sqlite3_open(path.c_str(), &db);

      if( rc ) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return res;
      } else {
        fprintf(stderr, "Opened database successfully\n");
      }

    Records records;

    std::string sql_query = std::string("SELECT * FROM UTXOS WHERE TXID = '") + txid + \
    std::string("' AND ASSET_ID != 0;");

    sql = (char *) sql_query.c_str();

    rc = sqlite3_exec(db, sql, select_callback, &records, &zErrMsg);
    //sqlite3_exec(db, sql, callback, 0, &zErrMsg);
    if( rc != SQLITE_OK ) {
      fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
    } else {
      fprintf(stdout, "Operation done successfully\n");
      printf("%lu records returned\n", records.size());

      if(records.size() > 0) {
        res = std::stoi(records[0][2]);
      }
    }
    sqlite3_close(db);
    return res;
}


static int64_t getWalletIdByAddress(const char * address_, std::string path) {
    sqlite3 *db;
      char *zErrMsg = 0;
      int rc;
      char *sql;
    
    std::string address(address_);

    int64_t res = 0;

      rc = sqlite3_open(path.c_str(), &db);

      if( rc ) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return res;
      } else {
        fprintf(stderr, "Opened database successfully\n");
      }

    Records records;

    std::string sql_query = std::string("SELECT * FROM ADDRESSES WHERE ADDRESS = '") + address + std::string("';");

    sql = (char *) sql_query.c_str();

    rc = sqlite3_exec(db, sql, select_callback, &records, &zErrMsg);
    //sqlite3_exec(db, sql, callback, 0, &zErrMsg);
    if( rc != SQLITE_OK ) {
      fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
    } else {
      fprintf(stdout, "Operation done successfully\n");
      printf("%lu records returned\n", records.size());

      if(records.size() > 0) {
        res = std::stoi(records[0][1]);
      }
    }
    sqlite3_close(db);
    return res;
}

static PaymentOutput getPaymentOutputByTxid(const char * txid_, std::string path) {
    sqlite3 *db;
      char *zErrMsg = 0;
      int rc;
      char *sql;
    
    std::string txid(txid_);

    PaymentOutput output;

      rc = sqlite3_open(path.c_str(), &db);

      if( rc ) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return output;
      } else {
        fprintf(stderr, "Opened database successfully\n");
      }

    Records records;

    std::string sql_query = std::string("SELECT * FROM UTXOS WHERE TXID = '") + txid + \
    std::string("' AND ASSET_ID != 0 AND SPENT_TXID = '';");

    sql = (char *) sql_query.c_str();

    rc = sqlite3_exec(db, sql, select_callback, &records, &zErrMsg);
    //sqlite3_exec(db, sql, callback, 0, &zErrMsg);
    if( rc != SQLITE_OK ) {
      fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
    } else {
      fprintf(stdout, "Operation done successfully\n");
      printf("%lu records returned\n", records.size());

      if(records.size() > 0) {
          
        //std::vector<unsigned char> utxo_script = hexToUchBuffer(records[0][9]);
        //CScript script(utxo_script.begin(), utxo_script.end());
        //std::vector<Chunks> chunks = getChunks(script);
        //output.asset.alias = hexToString(chunks[Sfp::PAYMAIL].buf);
          
        output.amount = std::stoi(records[0][11]);
        output.asset.id = std::stoi(records[0][12]);
        
        Records records0;

        std::string sql_query0 = std::string("SELECT * FROM ASSETS WHERE ID = ") + std::to_string(output.asset.id) + std::string(";");

        sql = (char *) sql_query0.c_str();

        rc = sqlite3_exec(db, sql, select_callback, &records0, &zErrMsg);
        //sqlite3_exec(db, sql, callback, 0, &zErrMsg);
        if( rc != SQLITE_OK ) {
            fprintf(stderr, "SQL error: %s\n", zErrMsg);
            sqlite3_free(zErrMsg);
        } else {
            fprintf(stdout, "Operation done successfully\n");
            printf("%lu records returned\n", records0.size());
            
            if(records0.size() > 0) {
                output.asset.alias = records0[0][2] + std::string("@buttonofmoney.com");
                //output.asset.alias = std::string("1662d8b52822.asset@buttonofmoney.com");
            }
        }
      }
    }
    sqlite3_close(db);
    return output;
}

extern void authorizerCreateSerialization(char *authHexStr, int authHexSize, const char *toAddress_, const char *txid_, const char *path_) {
//extern void authorizerCreateSerialization(const char *toAddress, const char *fromAddress, const char *txid, long long vout, long long satoshis, const char *script_) {
    
    std::string path = std::string(path_) + std::string("/sfp.db");
    printf("path: %s\n", path.c_str());

    createSFPUtxos(path);

    createSFPAssets(path);
    
    printf("Building\n");
    
    //std::string mnemonic("humble satisfy matrix magic february exit can now fluid panther demand design"); //2
    //std::string mnemonic("turkey bird toddler amused nephew nominee review useless hover music outdoor sweet"); //3

    //int64_t walletId = 2;
    int64_t walletId = getWalletIdByTxid(txid_, path);
    //int64_t walletId = 3;
    
    std::string mnemonic = getMnemonic(walletId, path);
    
    std::string fromAddress = getNewReceiveAddressById(walletId, path);
    //std::string fromAddress("miCsMXv3JmyVfftkNgWD1wR73LVPZRT3pc");
    //std::string fromAddress("n2m1gRaZf1ELBXtUeJ1QpTXHQNo7zqJ6Pz");
    printf("FROM ADDRESS: %s\n", fromAddress.c_str());
    //int64_t toWalletId = 3;
    int64_t toWalletId = getWalletIdByAddress(toAddress_, path);
    //int64_t toWalletId = 2;
    //std::string toAddress("mnriHFPhurER3c94QSxHUkqjCVRbqcjPWg");
    //std::string toAddress("miCsMXv3JmyVfftkNgWD1wR73LVPZRT3pc");
    //std::string toAddress("miCmvEDxA7LPPdm5HDDqdgjtDVuQS8BuQS");
    std::string toAddress = getNewReceiveAddressById(toWalletId, path);
    //std::string toAddress("mhUAJXzkVRU35yw5qSc9bkDEdMzGrMQyQJ");
    printf("TO ADDRESS: %s\n", toAddress.c_str());

    PaymentOutput output = getPaymentOutputByTxid(txid_, path);
    //PaymentOutput output;
    output.type = std::string("TOKEN_TRANSFER");
    //output.amount = 1;
    //output.asset.id = 1;
    //output.asset.alias = std::string("1662d8b52822.asset@buttonofmoney.com");
    std::vector<PaymentOutput> paymentOutputs;
    paymentOutputs.push_back(output);
    
    TxBuilder *bsvTxBuilder = new TxBuilder;

    bsvTxBuilder->setDust(TRANSACTION_DUST_AMOUNT);
    bsvTxBuilder->setFeePerKbNum(TRANSACTION_FEE_PER_BYTE * 1000);
    bsvTxBuilder->setChangeAddress(fromAddress);
    bsvTxBuilder->sendDustChangeToFees(true);
    
    TxBuilderOutputsStruct outputsStruct = addTxBuilderOutputs(bsvTxBuilder, paymentOutputs, toAddress, walletId, path);
    
    int totalOutputAmount = outputsStruct.totalOutputAmount;
    std::vector<TokenDataStruct> tokenOutputs = outputsStruct.tokenOutputs;

    printf("ADD TOKEN SCRIPT\n");
    if (tokenOutputs.size() > 0) {
    addTokenScripts(bsvTxBuilder, tokenOutputs, path);
    }

    //for(size_t i = 0; i < bsvTxBuilder->tx.vin.size(); i++) {
    //    std::vector<Chunks> chunks = getChunks(bsvTxBuilder->tx.vin[i].scriptSig);
    //    printf("Chunks.size() = %lu\n", chunks.size());
    //}

    //addTxBuilderInputs(bsvTxBuilder, txid0, vout0, satoshis0, script0, address0);
    addTxBuilderInputs(bsvTxBuilder, walletId, path);

    bsvTxBuilder->build(true);

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION | 0);
    bsvTxBuilder->tx.Serialize(ssTx);
    std::string hex_str = HexStr(ssTx);
    printf("WALLET HEX: %s\n", hex_str.c_str());

    std::map<std::string, int> addressesUsed;
    std::vector<std::string> addressesArray;

    for(std::map<std::string, std::vector<SigOpStruct>>::iterator it = bsvTxBuilder->sigOperations.map.begin(); it != bsvTxBuilder->sigOperations.map.end(); it++) {
        std::vector<SigOpStruct> arr = it->second;

        for(size_t i = 0; i < arr.size(); i++) {
            addressesUsed[arr[i].addressStr] = 1;
        }
    }

    for(std::map<std::string, int>::iterator it = addressesUsed.begin(); it != addressesUsed.end(); it++) {
        printf("addressesUsed = %s\n", it->first.c_str());
        addressesArray.push_back(it->first);
    }

    std::vector<int> indexes = findIndexesByAddresses(walletId, addressesArray, path);

    for(size_t i = 0; i < indexes.size(); i++) {
        printf("%d\n", indexes[i]);
    }

    //int index1 = 41;
    //int index2 = 35;

    #if MAINNET
        SelectParams(CBaseChainParams::MAIN);
    #else
        SelectParams(CBaseChainParams::TESTNET);
    #endif

    ECC_Start();

    //CSHA512 sha;
    //sha = sha.Write(const unsigned char* data, size_t len);

    //std::string mbuf("7475726b6579206269726420746f64646c657220616d75736564206e6570686577206e6f6d696e656520726576696577207573656c65737320686f766572206d75736963206f7574646f6f72207377656574");
    //const SecureString mbuf = "7475726b6579206269726420746f64646c657220616d75736564206e6570686577206e6f6d696e656520726576696577207573656c65737320686f766572206d75736963206f7574646f6f72207377656574";
    //const SecureString mbuf = "9d8ac7756c9c5ac88312f571bde624707c8ec517d56e113c42230ad15ffe028ff53f7192b3bfbc8a2667b3424989339a41ab018388adbb163b598a639d2e19b436363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636";
    //const SecureString mbuf = "4243445d534f16545f445216425952525a534416575b43455352165853465e53411658595b5f585353164453405f5341164345535a534545165e59405344165b43455f55165943425259594416454153534236363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636";
    //const SecureString mbuf = "4243445d534f16545f445216425952525a534416575b43455352165853465e53411658595b5f585353164453405f5341164345535a534545165e59405344165b43455f551659434252595944164541535342";
    //const SecureString mbuf = "28292e3739257c3e352e387c2833383830392e7c3d31292f39387c32392c34392b7c323331353239397c2e392a35392b7c292f3930392f2f7c34332a392e7c31292f353f7c3329283833332e7c2f2b3939285c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c";
    //const SecureString mbuf = "28292e3739257c3e352e387c2833383830392e7c3d31292f39387c32392c34392b7c323331353239397c2e392a35392b7c292f3930392f2f7c34332a392e7c31292f353f7c3329283833332e7c2f2b3939285c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c";

    //printf("mbuf.data() = %s\n", mbuf.data());
    //printf("mbuf.size() = %lu\n", mbuf.size());

    std::vector<unsigned char> mbuf = hexToUchBuffer(stringToHex(mnemonic));
    printf("Mneumonic Buf: \n");
    for(size_t i = 0; i < mbuf.size(); i++) {
        printf("%02x", mbuf[i]);
    }
    printf("\n");

    //std::string pbuf("6d6e656d6f6e6963");

    std::string passphrase("");

    std::string pstr = std::string("mnemonic") + passphrase;

    std::vector<unsigned char> pbuf = hexToUchBuffer(stringToHex(pstr));

    //uint32_t rounds = 64;
    uint32_t rounds = 2048;

    //wallet::CCrypter crypt;
    //bool res2 = crypt.SetKeyFromPassphrase(mbuf, hexToUchBuffer(pbuf), rounds, 0);
    //if(res2) printf("SET KEY FROM PASS PHRASE SUCCESS\n");

    std::vector<unsigned char, secure_allocator<unsigned char>> vchKey;
    //vchKey.resize(wallet::WALLET_CRYPTO_KEY_SIZE);
    vchKey.resize(CSHA512::OUTPUT_SIZE);
    //BytesToKeySHA512AES_(mbuf, hexToUchBuffer(pbuf), rounds, vchKey.data(), vchIV.data());
    BytesToKeySHA512AES_(mbuf, pbuf, rounds, vchKey.data());
    //printf("vchKey.data() = %s\n", vchKey.data());

    printf("SEED: \n");
    for(size_t i = 0; i < vchKey.size(); i++) {
        printf("%02x", vchKey[i]);
    }
    printf("\n");

    //std::string seedStr_(vchKey.data());
    //printf("SEED STR = %s\n", stringToHex(seedStr_).c_str());

    char hex_[CSHA512::OUTPUT_SIZE*2];

    for (int i = 0, j = 0; i < CSHA512::OUTPUT_SIZE; ++i, j += 2) {
        //printf("%02x", str.c_str()[i] & 0xff);
        sprintf(hex_ + j, "%02x", vchKey[i] & 0xff);
    }
    //printf("\n");
    std::string seedStr(hex_);

    printf("RET: %s\n", seedStr.c_str());


    //unsigned char * vchKey;
    //unsigned char * vchIV;
    //BytesToKeySHA512AES_(hexToUchBuffer(pbuf), mbuf, rounds, vchKey, vchIV);
    //printf("vchKey = %s\n", vchKey);

    //printf("BYTESTOKEY: \n");
    //for(size_t i; i < vchKey.size(); i++) {
    //    printf("%02x ", vchKey[i]);
    //}
    //printf("\n");

    //std::string seedStr("99fd607225b24c580a05095fe1774e224765e1a1ae826d2a34f9b66edf2305095a98f23575b16d56824f26ae03d2b73ee1b9dda9b664d9f52285f842208996d9");

    std::vector<unsigned char> seed = hexToUchBuffer(seedStr);

    CExtKey basePrivKey;
    basePrivKey.SetSeed(seed);

    std::string Wif = EncodeSecret(basePrivKey.key);
    printf("Wif = %s\n", Wif.c_str());

    std::vector<unsigned int> childIndexes;
    childIndexes.push_back(2147483692);
    childIndexes.push_back(2147483648);
    childIndexes.push_back(2147483648);
    childIndexes.push_back(0);

    //CExtKey bip32 = basePrivKey;
    for(size_t i = 0; i < childIndexes.size(); i++) {
      bool res_ = basePrivKey.Derive(basePrivKey, childIndexes[i]);
    }

    //CExtKey bip32_ = bip32;

    std::string Wif2 = EncodeSecret(basePrivKey.key);
    printf("Wif2 = %s\n", Wif2.c_str());

    std::vector<KeyPair> keyPairs;

    for(size_t i = 0; i < indexes.size(); i++) {
        CExtKey bip32 = basePrivKey;

        //bool res = basePrivKey.Derive(bip32, 41); //"muyeUy6h8KGXPYjmBDaGbp21FKNPc5pHLm"
        bool res = bip32.Derive(bip32, indexes[i]); //"n3aGeHeTw1B5YWjCLkvWzBwMEU612jgZAb"
        //bool res = bip32.Derive(bip32, index1); //"n3aGeHeTw1B5YWjCLkvWzBwMEU612jgZAb"
        //bool res = bip32.Derive(bip32, 50); //"miCsMXv3JmyVfftkNgWD1wR73LVPZRT3pc"
        //bool res = bip32.Derive(bip32, 75); //"mnriHFPhurER3c94QSxHUkqjCVRbqcjPWg"

        std::string Wif3 = EncodeSecret(bip32.key);
        printf("Wif3 = %s\n", Wif3.c_str());

        CKey privKey = DecodeSecret(Wif3);
        CPubKey pubKey = privKey.GetPubKey();
        KeyPair keyPair;
        keyPair.PrivKey = privKey;
        keyPair.pubKey = pubKey;

        keyPairs.push_back(keyPair);
    }

    //CExtKey bip32_ = basePrivKey;
    //res = basePrivKey.Derive(bip32_, indexes[1]);
    //std::string Wif4 = EncodeSecret(bip32_.key);
    //printf("Wif4 = %s\n", Wif4.c_str());

    //CKey privKey_ = DecodeSecret(Wif4);
    //CPubKey pubKey_ = privKey_.GetPubKey();
    //KeyPair keyPair_;
    //keyPair_.PrivKey = privKey_;
    //keyPair_.pubKey = pubKey_;

    //std::string Wif = EncodeSecret(bip32.key);

    //printf("Wif = %s\n", Wif.c_str());

    //CExtKey basePrivKey = DecodeExtKey(mnemonic);
    //CExtKey
    //bool res = Derive(CExtKey& out, unsigned int nChild);

    ECC_Stop();


    bsvTxBuilder->signWithKeyPairs (keyPairs);

    CDataStream ssTx_(SER_NETWORK, PROTOCOL_VERSION | 0);
    bsvTxBuilder->tx.Serialize(ssTx_);
    std::string hex = HexStr(ssTx_);
    printf("PAYMENT.RAWTX: %s\n", hex.c_str());
    
    printf("Authorizing\n");
    
    Sfp sfp("cQLs3wbw3fUCZRe6KyWmu1DE4UmcG2R21NB4TX2fSM6k7uBTFMJA", path);
    std::vector<TokenDataStruct> outputs;

    BuildTokenStruct tokenData = buildTokenTx(sfp, hex, outputs);

    sfp.validate(tokenData.tokenTx);
    
    sfp.authorize (tokenData.bsvTxBuilder, tokenData.tokenTx);

    CDataStream ssTx2(SER_NETWORK, PROTOCOL_VERSION | 0);
    tokenData.bsvTxBuilder->tx.Serialize(ssTx2);
    std::string hex2 = HexStr(ssTx2);
    std::cout << "AUTHORIZE ACTION HEX: " << hex2 << "\n";
    //printf("AUTHORIZE ACTION HEX: %s\n", hex2.c_str());
    
    snprintf(authHexStr, authHexSize, "%s", hex2.c_str());
}
    
} //end extern "C"
