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
                sqlite3_close(db);
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

    //sql = (char *) "DROP TABLE ADDRESSES;";
    //rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

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
    
  sql = (char *) "INSERT INTO ADDRESSES (ID,WALLET_ID,ADDRESS,ADDRESS_INDEX) "  \
           "VALUES (17, 2, 'mvmnXNFC3gGqQeW5mstLbC474zXxhmQn28', 13); ";
  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
    
  sql = (char *) "INSERT INTO ADDRESSES (ID,WALLET_ID,ADDRESS,ADDRESS_INDEX) "  \
             "VALUES (18, 2, 'mp3UATarJWkvc1MnxwZgqZAhtuwnWn3cx3', 14); ";
  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
    
  sql = (char *) "INSERT INTO ADDRESSES (ID,WALLET_ID,ADDRESS,ADDRESS_INDEX) "  \
               "VALUES (19, 3, 'mjj3yvAvELAN5ufrhg2jL3n91U3Ht76Aqf', 3); ";
  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
    
    sql = (char *) "INSERT INTO ADDRESSES (ID,WALLET_ID,ADDRESS,ADDRESS_INDEX) "  \
             "VALUES (20, 3, 'muPQfeACfp6bewaJz3R5rz8S8x77vVAZkC', 4); ";
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

    sql = (char *) "INSERT INTO ADDRESSES (ID,WALLET_ID,ADDRESS,ADDRESS_INDEX) "  \
             "VALUES (21, 3, 'mku1WnX4fijuRD5wQtvX9TzCdW8M4YBfiX', 5); ";
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

    sql = (char *) "INSERT INTO ADDRESSES (ID,WALLET_ID,ADDRESS,ADDRESS_INDEX) "  \
             "VALUES (22, 2, 'mkC8iRKNZMo15hoz9SmCfvwoC8VzqUFn15', 15); ";
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

    sql = (char *) "INSERT INTO ADDRESSES (ID,WALLET_ID,ADDRESS,ADDRESS_INDEX) "  \
             "VALUES (23, 3, 'ms39svxvcazktz8wKZwCjAipq77VWPhhxf', 6); ";
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
    
    sql = (char *) "INSERT INTO ADDRESSES (ID,WALLET_ID,ADDRESS,ADDRESS_INDEX) "  \
                 "VALUES (24, 3, 'mnAsk2zPhGRWs8inAc8VKH6rerYikns7De', 7); ";
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

    sql = (char *) "INSERT INTO ADDRESSES (ID,WALLET_ID,ADDRESS,ADDRESS_INDEX) "  \
             "VALUES (25, 3, 'mmJsf7d11jiWiAM6iCQSxRVXqSEo3LvHFi', 8); ";
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

    sql = (char *) "INSERT INTO ADDRESSES (ID,WALLET_ID,ADDRESS,ADDRESS_INDEX) "  \
             "VALUES (26, 2, 'mmigN8vzA8H4ARCiqLva2PMcc7mqq1njk2', 16); ";
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


                //std::string sql_query = std::string("SELECT * FROM ASSETS WHERE PAYMAIL_ALIAS = '") + alias + std::string("' AND MINTING_SCRIPT = '") \
        + uchbufToString(scriptToBuffer(tx.vout[i].scriptPubKey)) + std::string("'; ");
                std::string sql_query = std::string("SELECT * FROM ASSETS WHERE PAYMAIL_ALIAS = '") + alias + std::string("'; ");
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

    //sql = (char *) "DROP TABLE UTXOS;";
    //rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

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

extern void authorizerAddUtxoTest(const char* path_) {
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    char *sql;
    
    std::string path = std::string(path_) + std::string("/sfp.db");
    printf("path: %s\n", path.c_str());
    
    
  std::map<std::string,Utxo> utxos;
    
    //8fee043ad786113a4bd05c50ada75944df3ddd0fc5af3bbe01e16b9e0306bd6c
    std::string hex1("02000000013ff56da0901e3f308750aa6454da03ee6305ac646a9c147f9a07a3a6b9a39ed80000000049483045022100dd9bdbb2981269234edcb060ce04467f39b1c93c33b8adf367b73d9e489e1def022012da9a9a02bdb3ee011170f1a99966c7e8be2b743888d78c26335a6c0d48056541feffffff0200e1f505000000001976a914734c159ca8ad685650e528778c5acc99f6af066c88ac40101024010000001976a91409901ae5ad8a0edc43bd3708719561cca0bc37be88ac65000000");
    
    extractUtxoFromBsvjsTx(utxos, hex1, path);
    
    //4b606cff95fc5b890bf744b3d434f2f5b5a17e9db56aac847851e85f46df1c61
    std::string hex2("02000000016cbd06039e6be101be3bafc50fdd3ddf4459a7ad505cd04b3a1186d73a04ee8f010000006b483045022100b04ea5b96bfc356d655b5776140571720831a3e9b9a5a1e75b1b880db7f9804a02206f0f4daf01ab469903f3672ffc6ad3101bf6777e66c4252d19e53c715f30f640412102df727e98e8c8827c391eaea7a7f075f809872d96c135c19e115e9006d98ebf4bfeffffff025e2e1a1e010000001976a914c2d53183a55d5491248657e029588530d3e96ffe88ac00e1f505000000001976a914d776c017316a85970a1738f50bec6cc34a056c8188ac65000000");
    
    extractUtxoFromBsvjsTx(utxos, hex2, path);
    
    //3d5eb86b889942127b469425327f7753fb7ff3900f2db3e63d9ee8e0d9023239
    std::string hex3("01000000016cbd06039e6be101be3bafc50fdd3ddf4459a7ad505cd04b3a1186d73a04ee8f000000006a47304402205b251b47f65f79813b61b80dcf75b84fb476490747e90cddf5935ff1c27c905c02206c04347801ac7659561f7f3a9e7a17a6cfdb8c7b03775221838e7474ff581fd6412102c6556af9ee0238bcb0a30ec71a263174da89c2679396569da9046a2f1b9ac568ffffffff023602000000000000fd9901610773667040302e33243136363264386235323832322e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a9143417e66193cde6c4c2b4c3ca39ba8675dbb0e66b143417e66193cde6c4c2b4c3ca39ba8675dbb0e66b4630440220378f23b86600e8b42d0b095aea95530ab03865d9f190532ec7107b38c19a748302205ddd5ef721cbb5eb9bd28d976a01561c959e7dd488530a3aa042a44043d37c32246cbd06039e6be101be3bafc50fdd3ddf4459a7ad505cd04b3a1186d73a04ee8f00000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0d01000000000000007b7d0a00005addf505000000001976a914305177c10cd5b16ed2236fb16a694cf3a8114ea688ac00000000");
    
    extractUtxoFromBsvjsTx(utxos, hex3, path);
    
    //1a5436870c0a14858cd959f20ba8d5f7368234d441404c5c1d36b28ce7275fb5
    std::string hex4("0100000002393202d9e0e89e3de6b32d0f90f37ffb53777f322594467b124299886bb85e3d00000000fd9001483045022100d65ca06afaa7d3fb5feaea2c037dfa3a03687b82d7d88c0d52066860164f341f0220268cd778f5bb1797436a97d378b275c615224da1a54d99efa5802eb3501cf55c4121026cdaeddc0a73f799abf1c8ed7085f60b6e76fa883165d2f3ce98a5abcd6f6b1047304402201cc0578ecc2eecc55c49b1f15102578c966d3b44502874cd0cba6959cd86fa3c02204df60fa14f1bdc7495ea0cff585c037c3fdf95c3e92364f5391b519c320dc8c94121025f44adfa89cc33c42def4165be539a523c3d3fd7e537bc1e9bd44b32fa341cfd0773667040302e33473044022007ff66dd8eb913bb8bc1f2f03f39d618cdcab430ebe347636733a1f942d6da530220076193ec19ff60434c567cff3a5253ec942e6890a282df174491794b8fd1de3000483045022100d65ca06afaa7d3fb5feaea2c037dfa3a03687b82d7d88c0d52066860164f341f0220268cd778f5bb1797436a97d378b275c615224da1a54d99efa5802eb3501cf55c4121026cdaeddc0a73f799abf1c8ed7085f60b6e76fa883165d2f3ce98a5abcd6f6b10ffffffff393202d9e0e89e3de6b32d0f90f37ffb53777f322594467b124299886bb85e3d010000006a4730440220455896ffae2f0e1eb3487461e2bb495e31563aed620aa971cfd146122eeddfa202206d07633d7589414e433461051bec5160c49781eed20fb453b022325fba4466d0412102b23a60599582d7aa4bf4cf762e4b2b2f37ba9bf1179cfef4ed75547f1ec15086ffffffff023502000000000000fd9801610773667040302e33243136363264386235323832322e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a9145cc9252c3823f0e87d4cfe035bf8e384aa9983e7143417e66193cde6c4c2b4c3ca39ba8675dbb0e66b473045022100f1ff7b7186602eb832412501cd87b9d777bd960a965f912c8d7efd6baf0d10e202205e25aa0b46287da1a6ec370cbd4174b5be0180971f80b9b33d67ce1499ec45a224393202d9e0e89e3de6b32d0f90f37ffb53777f322594467b124299886bb85e3d00000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0b01000000000000000800000cdbf505000000001976a91478e51b3421fec4f8d7422f1fbbe6ca880745689588ac00000000");
    
    extractUtxoFromBsvjsTx(utxos, hex4, path);
    
    //9226ce281569b2254399677d6a2c24144101185b72343dae8cd41119d24b6174
      std::string hex5("0100000002b55f27e78cb2361d5c4c4041d4348236f7d5a80bf259d98c85140a0c8736541a00000000fd2a014730440220736012d56d31ed333014d48c708e56a755f63ce0857e7a2200feddbf38f5beb20220395c1a17658861a0759c07e74277ea26e47c5074e395712f70121265c6a8bd8d4121025335d45af2657ddef13039b2ef9b8c43091c9fd3ae0cc759730e7d067402fbe74830450221008c673d589d63c42f30bccc5db8f1de232fe219ba9b5a6a6428f1f072b61ff3200220365732454c95b24873b9172cc2bc6a4013fe3dc1f8c6b2c202357c177a12cc884121025f44adfa89cc33c42def4165be539a523c3d3fd7e537bc1e9bd44b32fa341cfd0773667040302e3348304502210098edd1f852c64fba6f0f813e6648ecbc4e59c6a57ea863f04ec3c176f4b1524c02203928d1949e8f4ff5324ea15ff712f80ccfbba2a3f26f25d9414c088582e14d100001000100ffffffff611cdf465fe8517884ac6ab59d7ea1b5f5f234d4b344f70b895bfc95ff6c604b010000006b483045022100878d770a7c1eca5fa7489c5fe123caea4395f7044b7540d34f3854787bc6565202200098d3d82a9e391c101d739e66b3037292e3c9aaf35191c6ad826560b8fbdd644121023c4c4ce585bfc5fc971c16229c5712f757927a96c25c41bfc01901c1bab26ab9ffffffff023402000000000000fd9701610773667040302e33243136363264386235323832322e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a91433496c855c70114a580c538b5582825c18eb3347143417e66193cde6c4c2b4c3ca39ba8675dbb0e66b463044022060affe2f34c8641cd0ce9553bb685fb4359e092db4107656c5b1d856b343d6d5022047de1b87c4c6901f27cd9b7b7be42b7176313852b831fb9e4a59416f36411e6e24b55f27e78cb2361d5c4c4041d4348236f7d5a80bf259d98c85140a0c8736541a00000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0b0100000000000000080000b3def505000000001976a9143b0477b3fb88edf65e55fd921ca43014f1152e3788ac00000000");

        extractUtxoFromBsvjsTx(utxos, hex5, path);

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

    //sql = (char *) "DROP TABLE WALLETS;"; //NEED TO DROP FOR SOME REASON
    //rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

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
               "-1, 15); ";

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
               "-1, 5); ";

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

static void initializeRunWallet (std::string path) {
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

    //sql = (char *) "DROP TABLE RUN_WALLETS;"; //NEED TO DROP FOR SOME REASON
    //rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

    /* Create SQL statement */
    sql = (char *) "CREATE TABLE RUN_WALLETS("  \
      "ID INT PRIMARY KEY     NOT NULL," \
        "PRIVKEY           CHAR(255)," \
        "PUBKEY           CHAR(255)," \
        "ADDRESS       CHAR(255));";

    /* Execute SQL statement */
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

    if( rc != SQLITE_OK ){
      fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
    } else {
      fprintf(stdout, "RUN_WALLETS Table created successfully\n");
    }

  sql = (char *) "INSERT INTO RUN_WALLETS (ID,PRIVKEY,PUBKEY,ADDRESS) "  \
        "VALUES (2, 'cRhJVJ6BTehSvMjM7XSAYhZyENTrU4EWsH1mmJxW1vooMPLEqfbF'," \
               "'024188a5f08b5a55e38655daf965fdda537561dabb27cb0472f680dc07ffef4920'," \
               "'n44HTiHtFQ1hdMHBZPfsiVUUwYep5V3Yq1'); ";

 /* Execute SQL statement */
  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

  if( rc != SQLITE_OK ){
     fprintf(stderr, "SQL error: %s\n", zErrMsg);
     sqlite3_free(zErrMsg);
  } else {
     fprintf(stdout, "RUN_WALLETS Record created successfully\n");
  }

    sql = (char *) "INSERT INTO RUN_WALLETS (ID,PRIVKEY,PUBKEY,ADDRESS) "  \
          "VALUES (3, 'cTTmPg6bxgr8u5JXLEWVPJxMztP9yrGtRr8CFHi37YJiS1BwxLGM'," \
                 "'02938cbc9083663507f1896dd5f4596ce58247963410ca921499fcab30e2d0d94f'," \
                 "'n2DXd5qGBnNGHQ2jtd162RjwgBRYdxxYiq'); ";

 /* Execute SQL statement */
  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

  if( rc != SQLITE_OK ){
     fprintf(stderr, "SQL error: %s\n", zErrMsg);
     sqlite3_free(zErrMsg);
  } else {
     fprintf(stdout, "RUN_WALLETS Record created successfully\n");
  }

    sqlite3_close(db);
}

static void initializeUsers (std::string path) {
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

    //sql = (char *) "DROP TABLE USERS;"; //NEED TO DROP FOR SOME REASON
    //rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

    /* Create SQL statement */
    sql = (char *) "CREATE TABLE USERS("  \
      "ID INT PRIMARY KEY     NOT NULL," \
        "ACTIVE_WALLET_ID           BIGINT," \
        "PRIMARY_ADDRESS       CHAR(255));";

    /* Execute SQL statement */
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

    if( rc != SQLITE_OK ){
      fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
    } else {
      fprintf(stdout, "USERS Table created successfully\n");
    }

  sql = (char *) "INSERT INTO USERS (ID,ACTIVE_WALLET_ID,PRIMARY_ADDRESS) "  \
        "VALUES (5, 2,'mpk55WSdhZ7FdK1qs1MbJjwv7kUfKki6Qp'); ";

 /* Execute SQL statement */
  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

  if( rc != SQLITE_OK ){
     fprintf(stderr, "SQL error: %s\n", zErrMsg);
     sqlite3_free(zErrMsg);
  } else {
     fprintf(stdout, "USERS Record created successfully\n");
  }

  sql = (char *) "INSERT INTO USERS (ID,ACTIVE_WALLET_ID,PRIMARY_ADDRESS) "  \
          "VALUES (6, 3,'tb1ql9p9x7pgethxqvrgyghpytza47g4dqunp86xvq'); ";

 /* Execute SQL statement */
  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

  if( rc != SQLITE_OK ){
     fprintf(stderr, "SQL error: %s\n", zErrMsg);
     sqlite3_free(zErrMsg);
  } else {
     fprintf(stdout, "USERS Record created successfully\n");
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

extern unsigned long long authorizerGetAmount(const char *script) {
    
    unsigned int QUANTITY_LENGTH = 8;
    
    long long val = 0;
    
    std::string txOut(script);
    std::vector<unsigned char> txOutBuf = hexToUchBuffer(txOut);
    CScript txOutScript(txOutBuf.begin(), txOutBuf.end());
    std::vector<Chunks> chunks = getChunks(txOutScript);
    
    std::string state = chunks[chunks.size() - 1].buf;
    
    std::vector<std::string> buffer = stringToBuffer(state);
    std::vector<std::string> sliced_buffer = sliceBuffer(buffer, 0, QUANTITY_LENGTH);
    std::vector<std::string> reverse_buffer = toLittleEndian(sliced_buffer);
    val = (unsigned long long) bufferToNumber(reverse_buffer);
    
    return val;
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

    //sql = (char *) "DROP TABLE SFP_UTXOS;";
    //rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

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

    //sql = (char *) "DROP TABLE SFP_ASSETS;";
    //rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

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

    //sql = (char *) "DROP TABLE ASSETS;";
    //rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

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
    
    //sql = (char *) "DROP TABLE TRANSFERS;";
    //rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

    /* Create SQL statement */
    sql = (char *) "CREATE TABLE TRANSFERS("  \
      "ID INT PRIMARY KEY     NOT NULL," \
      "TXID          CHAR(64) NOT NULL," \
      "ADDRESS                CHAR(100)," \
        "AMOUNT         BIGINT );";

    /* Execute SQL statement */
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

    if( rc != SQLITE_OK ){
      fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
    } else {
      fprintf(stdout, "TRANSFERS Table created successfully\n");
    }
    
    //sql = (char *) "DROP TABLE RUN_TRANSFERS;";
    //rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
    
    /* Create SQL statement */
    sql = (char *) "CREATE TABLE RUN_TRANSFERS("  \
      "ID INT PRIMARY KEY     NOT NULL," \
      "TXID          CHAR(64) NOT NULL," \
      "TO_ADDRESS                CHAR(100)," \
      "AMOUNT                BIGINT," \
      "MINT_ID                 CHAR(100)," \
      "FROM_ADDRESS                CHAR(100));";

    /* Execute SQL statement */
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

    if( rc != SQLITE_OK ){
      fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
    } else {
      fprintf(stdout, "RUN_TRANSFERS Table created successfully\n");
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
          unsigned long id = 1;
          Records records1;
          std::string sql_query1 = std::string("SELECT * FROM SFP_UTXOS;");
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
                std::string("VALUES (") + std::to_string(id) + std::string(", '") + records2[0][2] + std::string("@buttonofmoney.com', '") + \
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
    
    bool res = false;

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
    
    printf("PRINTING UTXOS TABLE\n");
    sql = (char *) "SELECT * FROM UTXOS";

    sqlite3_exec(db, sql, callback, 0, &zErrMsg);
    if( rc != SQLITE_OK ) {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    } else {
        fprintf(stdout, "Operation done successfully\n");
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
      res = true;
  }
  sqlite3_close(db);
    
  return res;
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
    
    initializeUsers(path);
    
    //SFP
    initializeWallet(path);
    
    initializeAddresses(path);
    
    initializeDB(path);

    initializeUtxos(path);
    
    //RUN
    initializeRunWallet(path);
    
}

extern long long getWalletIdByPrimaryAddress(const char *address_, const char *path_) {
    sqlite3 *db;
      char *zErrMsg = 0;
      int rc;
      char *sql;

    int64_t res = 0;
    
    std::string address(address_);
    
    std::string path = std::string(path_) + std::string("/sfp.db");

      rc = sqlite3_open(path.c_str(), &db);

      if( rc ) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return res;
      } else {
        fprintf(stderr, "Opened database successfully\n");
      }

    Records records;

    std::string sql_query = std::string("SELECT * FROM USERS WHERE PRIMARY_ADDRESS = '") + address + std::string("';");

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
        res = std::stoll(records[0][1]);
      }
    }
    sqlite3_close(db);
    return res;
}

extern void getRUNAddressByWalletId(long long walletId, char *addressHexStr, int addressSize, const char *path_) {
    sqlite3 *db;
      char *zErrMsg = 0;
      int rc;
      char *sql;

    int64_t res = 0;
    
    std::string path = std::string(path_) + std::string("/sfp.db");

      rc = sqlite3_open(path.c_str(), &db);

      if( rc ) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return;
      } else {
        fprintf(stderr, "Opened database successfully\n");
      }

    Records records;

    std::string sql_query = std::string("SELECT * FROM RUN_WALLETS WHERE ID = ") + std::to_string(walletId) + std::string(";");

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
        snprintf(addressHexStr, addressSize, "%s", records[0][3].c_str());
      }
    }
    sqlite3_close(db);
}


static int64_t getWalletIdByTxid(std::string txid, std::string path) {
    sqlite3 *db;
      char *zErrMsg = 0;
      int rc;
      char *sql;

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
        res = std::stoll(records[0][2]);
      }
    }
    sqlite3_close(db);
    return res;
}

static int64_t getWalletIdByAddress(std::string address, std::string path) {
    sqlite3 *db;
      char *zErrMsg = 0;
      int rc;
      char *sql;

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
        res = std::stoll(records[0][1]);
      }
    }
    sqlite3_close(db);
    return res;
}

static PaymentOutput getPaymentOutputByTxid(std::string txid, std::string path) {
    sqlite3 *db;
      char *zErrMsg = 0;
      int rc;
      char *sql;

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


extern void authorizerSaveTransfer(const char *txid_, const char *address_, unsigned long long amount_, const char *path_) {
    printf("txid = %s\n", txid_);
    printf("address = %s\n", address_);
    printf("path = %s\n", path_);
    
    std::string txid(txid_);
    std::string address(address_);
    
    unsigned long long amount = ceil((double) amount_/100000000);
    
    std::string path = std::string(path_) + std::string("/sfp.db");
    printf("path: %s\n", path.c_str());
    
    sqlite3 *db;
      char *zErrMsg = 0;
      int rc;
      char *sql;

      rc = sqlite3_open(path.c_str(), &db);

      if( rc ) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return;
      } else {
        fprintf(stderr, "Opened database successfully\n");
      }

    Records records;

    std::string sql_query = std::string("SELECT * FROM TRANSFERS;");

    sql = (char *) sql_query.c_str();

    rc = sqlite3_exec(db, sql, select_callback, &records, &zErrMsg);
    //sqlite3_exec(db, sql, callback, 0, &zErrMsg);
    if( rc != SQLITE_OK ) {
      fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
    } else {
      fprintf(stdout, "Operation done successfully\n");
      printf("%lu records returned\n", records.size());
        
      size_t id = records.size() + 1;

          std::string sql_query0 = std::string("INSERT INTO TRANSFERS (ID,TXID,ADDRESS,AMOUNT) VALUES (") + std::to_string(id) + std::string(", '") + txid + std::string("', '") + address + std::string("', ") + std::to_string(amount) + std::string("); ");
          
          sql = (char *) sql_query0.c_str();
          printf("sql_query0 = %s\n", sql_query0.c_str());

          rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

          if( rc != SQLITE_OK ) {
            fprintf(stderr, "SQL error: %s\n", zErrMsg);
            sqlite3_free(zErrMsg);
          } else {
            fprintf(stdout, "TRANSFERS Record Operation done successfully\n");
          }
      
    }
    sqlite3_close(db);
}

extern void authorizerSaveTransferWOC(const char *txid_, const char *address_, unsigned long long amount_, const char * mintId_, const char * fromAddress_, const char *path_) {
    printf("txid = %s\n", txid_);
    printf("address = %s\n", address_);
    printf("path = %s\n", path_);
    
    std::string txid(txid_);
    std::string address(address_);
    std::string mintId(mintId_);
    std::string fromAddress(fromAddress_);
    
    unsigned long long amount = ceil((double) amount_/100000000);
    
    std::string path = std::string(path_) + std::string("/sfp.db");
    printf("path: %s\n", path.c_str());
    
    sqlite3 *db;
      char *zErrMsg = 0;
      int rc;
      char *sql;

      rc = sqlite3_open(path.c_str(), &db);

      if( rc ) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return;
      } else {
        fprintf(stderr, "Opened database successfully\n");
      }

    Records records;

    std::string sql_query = std::string("SELECT * FROM RUN_TRANSFERS;");

    sql = (char *) sql_query.c_str();

    rc = sqlite3_exec(db, sql, select_callback, &records, &zErrMsg);
    //sqlite3_exec(db, sql, callback, 0, &zErrMsg);
    if( rc != SQLITE_OK ) {
      fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
    } else {
      fprintf(stdout, "Operation done successfully\n");
      printf("%lu records returned\n", records.size());
        
      size_t id = records.size() + 1;

          std::string sql_query0 = std::string("INSERT INTO RUN_TRANSFERS (ID,TXID,TO_ADDRESS,AMOUNT,MINT_ID,FROM_ADDRESS) VALUES (") + std::to_string(id) + std::string(", '") + txid + std::string("', '") + address + std::string("', ") + std::to_string(amount) + std::string(", '") + mintId + std::string("', '") + fromAddress + std::string("'); ");
          
          sql = (char *) sql_query0.c_str();
          printf("sql_query0 = %s\n", sql_query0.c_str());

          rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

          if( rc != SQLITE_OK ) {
            fprintf(stderr, "SQL error: %s\n", zErrMsg);
            sqlite3_free(zErrMsg);
          } else {
            fprintf(stdout, "RUN_TRANSFERS Record Operation done successfully\n");
          }
      
    }
    sqlite3_close(db);
}


typedef struct TransferRecord {
    std::string txid;
    std::string address;
    int64_t amount;
}TransferRecord;

static TransferRecord getTransfer(std::string path) {
    sqlite3 *db;
      char *zErrMsg = 0;
      int rc;
      char *sql;
    
    TransferRecord rec;

      rc = sqlite3_open(path.c_str(), &db);

      if( rc ) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return rec;
      } else {
        fprintf(stderr, "Opened database successfully\n");
      }

    Records records;

    std::string sql_query = std::string("SELECT * FROM TRANSFERS ORDER BY ID DESC;");

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
            rec.txid = records[0][1];
            rec.address = records[0][2];
            rec.amount = std::stoll(records[0][3]);
        }
    }
    return rec;
    sqlite3_close(db);
}

typedef struct TransferRecordRun {
    std::string txid;
    std::string address;
    int64_t amount;
    std::string mintId;
    std::string fromAddress;
}TransferRecordRun;

static TransferRecordRun getTransferRun(std::string path) {
    sqlite3 *db;
      char *zErrMsg = 0;
      int rc;
      char *sql;
    
    TransferRecordRun rec;

      rc = sqlite3_open(path.c_str(), &db);

      if( rc ) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return rec;
      } else {
        fprintf(stderr, "Opened database successfully\n");
      }

    Records records;

    std::string sql_query = std::string("SELECT * FROM RUN_TRANSFERS ORDER BY ID DESC;");

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
            rec.txid = records[0][1];
            rec.address = records[0][2];
            rec.amount = std::stoll(records[0][3]);
            rec.mintId = records[0][4];
            rec.fromAddress = records[0][5];
        }
    }
    return rec;
    sqlite3_close(db);
}


extern void authorizerCreateSerialization(char *authHexStr, int authHexSize, const char *path_) {
//extern void authorizerCreateSerialization(const char *toAddress, const char *fromAddress, const char *txid, long long vout, long long satoshis, const char *script_) {
    
    std::string path = std::string(path_) + std::string("/sfp.db");
    printf("path: %s\n", path.c_str());

    createSFPUtxos(path);

    createSFPAssets(path);
    
    TransferRecord rec = getTransfer(path);
    
    std::string txid_(rec.txid);
    //std::string txid_("1a5436870c0a14858cd959f20ba8d5f7368234d441404c5c1d36b28ce7275fb5");
    std::string toAddress_(rec.address);
    //std::string toAddress_("mkC8iRKNZMo15hoz9SmCfvwoC8VzqUFn15");
    
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

extern void authorizerGetTransferDataRun(char *txnIdHexStr, int txnIdSize, char *addressHexStr, int addressSize, char *mintIdHexStr, int mintIdSize, char *fromAddressHexStr, int fromAddressSize, long long *amount, const char *path_) {
    
    std::string path = std::string(path_) + std::string("/sfp.db");
    printf("path: %s\n", path.c_str());
    
    TransferRecordRun rec = getTransferRun(path);
    
    snprintf(txnIdHexStr, txnIdSize, "%s", rec.txid.c_str());
    
    snprintf(addressHexStr, addressSize, "%s", rec.address.c_str());
    
    snprintf(mintIdHexStr, mintIdSize, "%s", rec.mintId.c_str());
    
    snprintf(fromAddressHexStr, fromAddressSize, "%s", rec.fromAddress.c_str());
    
    *amount = rec.amount;
}

extern void authorizerGetPrivKeyRun(const char * address_, char *privkeyHexStr, int privkeySize, const char *path_) {
    
    std::string path = std::string(path_) + std::string("/sfp.db");
    printf("path: %s\n", path.c_str());
    
    std::string address(address_);
    
    sqlite3 *db;
      char *zErrMsg = 0;
      int rc;
      char *sql;

    int64_t res = 0;

      rc = sqlite3_open(path.c_str(), &db);

      if( rc ) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return;
      } else {
        fprintf(stderr, "Opened database successfully\n");
      }

    Records records;

    std::string sql_query = std::string("SELECT * FROM RUN_WALLETS WHERE ADDRESS = '") + address + \
    std::string("';");
    
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

      if(records.size() > 0) {
        snprintf(privkeyHexStr, privkeySize, "%s", records[0][1].c_str());
      }
    }
    sqlite3_close(db);
}

} //end extern "C"
