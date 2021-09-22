/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: Response.proto */

#ifndef PROTOBUF_C_Response_2eproto__INCLUDED
#define PROTOBUF_C_Response_2eproto__INCLUDED

#include "protobuf-c.h"

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1004000 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

#include "GetByKey.pb-c.h"
#include "GetBySolidityID.pb-c.h"
#include "ContractCallLocal.pb-c.h"
#include "ContractGetBytecode.pb-c.h"
#include "ContractGetInfo.pb-c.h"
#include "ContractGetRecords.pb-c.h"
#include "CryptoGetAccountBalance.pb-c.h"
#include "CryptoGetAccountRecords.pb-c.h"
#include "CryptoGetInfo.pb-c.h"
#include "CryptoGetLiveHash.pb-c.h"
#include "CryptoGetStakers.pb-c.h"
#include "FileGetContents.pb-c.h"
#include "FileGetInfo.pb-c.h"
#include "TransactionGetReceipt.pb-c.h"
#include "TransactionGetRecord.pb-c.h"
#include "TransactionGetFastRecord.pb-c.h"
#include "ConsensusGetTopicInfo.pb-c.h"
#include "NetworkGetVersionInfo.pb-c.h"
#include "TokenGetAccountNftInfos.pb-c.h"
#include "TokenGetInfo.pb-c.h"
#include "TokenGetNftInfo.pb-c.h"
#include "TokenGetNftInfos.pb-c.h"
#include "ScheduleGetInfo.pb-c.h"

typedef struct Proto__Response Proto__Response;


/* --- enums --- */


/* --- messages --- */

typedef enum {
  PROTO__RESPONSE__RESPONSE__NOT_SET = 0,
  PROTO__RESPONSE__RESPONSE_GET_BY_KEY = 1,
  PROTO__RESPONSE__RESPONSE_GET_BY_SOLIDITY_ID = 2,
  PROTO__RESPONSE__RESPONSE_CONTRACT_CALL_LOCAL = 3,
  PROTO__RESPONSE__RESPONSE_CONTRACT_GET_BYTECODE_RESPONSE = 5,
  PROTO__RESPONSE__RESPONSE_CONTRACT_GET_INFO = 4,
  PROTO__RESPONSE__RESPONSE_CONTRACT_GET_RECORDS_RESPONSE = 6,
  PROTO__RESPONSE__RESPONSE_CRYPTOGET_ACCOUNT_BALANCE = 7,
  PROTO__RESPONSE__RESPONSE_CRYPTO_GET_ACCOUNT_RECORDS = 8,
  PROTO__RESPONSE__RESPONSE_CRYPTO_GET_INFO = 9,
  PROTO__RESPONSE__RESPONSE_CRYPTO_GET_LIVE_HASH = 10,
  PROTO__RESPONSE__RESPONSE_CRYPTO_GET_PROXY_STAKERS = 11,
  PROTO__RESPONSE__RESPONSE_FILE_GET_CONTENTS = 12,
  PROTO__RESPONSE__RESPONSE_FILE_GET_INFO = 13,
  PROTO__RESPONSE__RESPONSE_TRANSACTION_GET_RECEIPT = 14,
  PROTO__RESPONSE__RESPONSE_TRANSACTION_GET_RECORD = 15,
  PROTO__RESPONSE__RESPONSE_TRANSACTION_GET_FAST_RECORD = 16,
  PROTO__RESPONSE__RESPONSE_CONSENSUS_GET_TOPIC_INFO = 150,
  PROTO__RESPONSE__RESPONSE_NETWORK_GET_VERSION_INFO = 151,
  PROTO__RESPONSE__RESPONSE_TOKEN_GET_INFO = 152,
  PROTO__RESPONSE__RESPONSE_SCHEDULE_GET_INFO = 153,
  PROTO__RESPONSE__RESPONSE_TOKEN_GET_ACCOUNT_NFT_INFOS = 154,
  PROTO__RESPONSE__RESPONSE_TOKEN_GET_NFT_INFO = 155,
  PROTO__RESPONSE__RESPONSE_TOKEN_GET_NFT_INFOS = 156
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(PROTO__RESPONSE__RESPONSE__CASE)
} Proto__Response__ResponseCase;

/*
 * A single response, which is returned from the node to the client, after the client sent the node a query. This includes all responses. 
 */
struct  Proto__Response
{
  ProtobufCMessage base;
  Proto__Response__ResponseCase response_case;
  union {
    /*
     * Get all entities associated with a given key
     */
    Proto__GetByKeyResponse *getbykey;
    /*
     * Get the IDs in the format used in transactions, given the format used in Solidity
     */
    Proto__GetBySolidityIDResponse *getbysolidityid;
    /*
     * Response to call a function of a smart contract instance
     */
    Proto__ContractCallLocalResponse *contractcalllocal;
    /*
     * Get the bytecode for a smart contract instance
     */
    Proto__ContractGetBytecodeResponse *contractgetbytecoderesponse;
    /*
     * Get information about a smart contract instance
     */
    Proto__ContractGetInfoResponse *contractgetinfo;
    /*
     *Get all existing records for a smart contract instance
     */
    Proto__ContractGetRecordsResponse *contractgetrecordsresponse;
    /*
     * Get the current balance in a cryptocurrency account
     */
    Proto__CryptoGetAccountBalanceResponse *cryptogetaccountbalance;
    /*
     * Get all the records that currently exist for transactions involving an account
     */
    Proto__CryptoGetAccountRecordsResponse *cryptogetaccountrecords;
    /*
     * Get all information about an account
     */
    Proto__CryptoGetInfoResponse *cryptogetinfo;
    /*
     * Contains a livehash associated to an account
     */
    Proto__CryptoGetLiveHashResponse *cryptogetlivehash;
    /*
     * Get all the accounts that proxy stake to a given account, and how much they proxy stake
     */
    Proto__CryptoGetStakersResponse *cryptogetproxystakers;
    /*
     * Get the contents of a file (the bytes stored in it)
     */
    Proto__FileGetContentsResponse *filegetcontents;
    /*
     * Get information about a file, such as its expiration date
     */
    Proto__FileGetInfoResponse *filegetinfo;
    /*
     * Get a receipt for a transaction
     */
    Proto__TransactionGetReceiptResponse *transactiongetreceipt;
    /*
     * Get a record for a transaction
     */
    Proto__TransactionGetRecordResponse *transactiongetrecord;
    /*
     * Get a record for a transaction (lasts 180 seconds)
     */
    Proto__TransactionGetFastRecordResponse *transactiongetfastrecord;
    /*
     * Parameters of and state of a consensus topic..
     */
    Proto__ConsensusGetTopicInfoResponse *consensusgettopicinfo;
    /*
     * Semantic versions of Hedera Services and HAPI proto
     */
    Proto__NetworkGetVersionInfoResponse *networkgetversioninfo;
    /*
     * Get all information about a token
     */
    Proto__TokenGetInfoResponse *tokengetinfo;
    /*
     * Get all information about a schedule entity
     */
    Proto__ScheduleGetInfoResponse *schedulegetinfo;
    /*
     * A list of the NFTs associated with the account
     */
    Proto__TokenGetAccountNftInfosResponse *tokengetaccountnftinfos;
    /*
     * All information about an NFT
     */
    Proto__TokenGetNftInfoResponse *tokengetnftinfo;
    /*
     * A list of the NFTs for the token
     */
    Proto__TokenGetNftInfosResponse *tokengetnftinfos;
  };
};
#define PROTO__RESPONSE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&proto__response__descriptor) \
    , PROTO__RESPONSE__RESPONSE__NOT_SET, {0} }


/* Proto__Response methods */
void   proto__response__init
                     (Proto__Response         *message);
size_t proto__response__get_packed_size
                     (const Proto__Response   *message);
size_t proto__response__pack
                     (const Proto__Response   *message,
                      uint8_t             *out);
size_t proto__response__pack_to_buffer
                     (const Proto__Response   *message,
                      ProtobufCBuffer     *buffer);
Proto__Response *
       proto__response__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   proto__response__free_unpacked
                     (Proto__Response *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Proto__Response_Closure)
                 (const Proto__Response *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor proto__response__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_Response_2eproto__INCLUDED */
