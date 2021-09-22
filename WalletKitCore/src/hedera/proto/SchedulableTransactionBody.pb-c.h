/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: SchedulableTransactionBody.proto */

#ifndef PROTOBUF_C_SchedulableTransactionBody_2eproto__INCLUDED
#define PROTOBUF_C_SchedulableTransactionBody_2eproto__INCLUDED

#include "protobuf-c.h"

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1004000 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

#include "SystemDelete.pb-c.h"
#include "SystemUndelete.pb-c.h"
#include "Freeze.pb-c.h"
#include "ContractCall.pb-c.h"
#include "ContractCreate.pb-c.h"
#include "ContractUpdate.pb-c.h"
#include "CryptoCreate.pb-c.h"
#include "CryptoDelete.pb-c.h"
#include "CryptoTransfer.pb-c.h"
#include "CryptoUpdate.pb-c.h"
#include "FileAppend.pb-c.h"
#include "FileCreate.pb-c.h"
#include "FileDelete.pb-c.h"
#include "FileUpdate.pb-c.h"
#include "ContractDelete.pb-c.h"
#include "ConsensusCreateTopic.pb-c.h"
#include "ConsensusUpdateTopic.pb-c.h"
#include "ConsensusDeleteTopic.pb-c.h"
#include "ConsensusSubmitMessage.pb-c.h"
#include "TokenCreate.pb-c.h"
#include "TokenFreezeAccount.pb-c.h"
#include "TokenUnfreezeAccount.pb-c.h"
#include "TokenGrantKyc.pb-c.h"
#include "TokenRevokeKyc.pb-c.h"
#include "TokenDelete.pb-c.h"
#include "TokenUpdate.pb-c.h"
#include "TokenMint.pb-c.h"
#include "TokenBurn.pb-c.h"
#include "TokenWipeAccount.pb-c.h"
#include "TokenAssociate.pb-c.h"
#include "TokenDissociate.pb-c.h"
#include "ScheduleDelete.pb-c.h"

typedef struct Proto__SchedulableTransactionBody Proto__SchedulableTransactionBody;


/* --- enums --- */


/* --- messages --- */

typedef enum {
  PROTO__SCHEDULABLE_TRANSACTION_BODY__DATA__NOT_SET = 0,
  PROTO__SCHEDULABLE_TRANSACTION_BODY__DATA_CONTRACT_CALL = 3,
  PROTO__SCHEDULABLE_TRANSACTION_BODY__DATA_CONTRACT_CREATE_INSTANCE = 4,
  PROTO__SCHEDULABLE_TRANSACTION_BODY__DATA_CONTRACT_UPDATE_INSTANCE = 5,
  PROTO__SCHEDULABLE_TRANSACTION_BODY__DATA_CONTRACT_DELETE_INSTANCE = 6,
  PROTO__SCHEDULABLE_TRANSACTION_BODY__DATA_CRYPTO_CREATE_ACCOUNT = 7,
  PROTO__SCHEDULABLE_TRANSACTION_BODY__DATA_CRYPTO_DELETE = 8,
  PROTO__SCHEDULABLE_TRANSACTION_BODY__DATA_CRYPTO_TRANSFER = 9,
  PROTO__SCHEDULABLE_TRANSACTION_BODY__DATA_CRYPTO_UPDATE_ACCOUNT = 10,
  PROTO__SCHEDULABLE_TRANSACTION_BODY__DATA_FILE_APPEND = 11,
  PROTO__SCHEDULABLE_TRANSACTION_BODY__DATA_FILE_CREATE = 12,
  PROTO__SCHEDULABLE_TRANSACTION_BODY__DATA_FILE_DELETE = 13,
  PROTO__SCHEDULABLE_TRANSACTION_BODY__DATA_FILE_UPDATE = 14,
  PROTO__SCHEDULABLE_TRANSACTION_BODY__DATA_SYSTEM_DELETE = 15,
  PROTO__SCHEDULABLE_TRANSACTION_BODY__DATA_SYSTEM_UNDELETE = 16,
  PROTO__SCHEDULABLE_TRANSACTION_BODY__DATA_FREEZE = 17,
  PROTO__SCHEDULABLE_TRANSACTION_BODY__DATA_CONSENSUS_CREATE_TOPIC = 18,
  PROTO__SCHEDULABLE_TRANSACTION_BODY__DATA_CONSENSUS_UPDATE_TOPIC = 19,
  PROTO__SCHEDULABLE_TRANSACTION_BODY__DATA_CONSENSUS_DELETE_TOPIC = 20,
  PROTO__SCHEDULABLE_TRANSACTION_BODY__DATA_CONSENSUS_SUBMIT_MESSAGE = 21,
  PROTO__SCHEDULABLE_TRANSACTION_BODY__DATA_TOKEN_CREATION = 22,
  PROTO__SCHEDULABLE_TRANSACTION_BODY__DATA_TOKEN_FREEZE = 23,
  PROTO__SCHEDULABLE_TRANSACTION_BODY__DATA_TOKEN_UNFREEZE = 24,
  PROTO__SCHEDULABLE_TRANSACTION_BODY__DATA_TOKEN_GRANT_KYC = 25,
  PROTO__SCHEDULABLE_TRANSACTION_BODY__DATA_TOKEN_REVOKE_KYC = 26,
  PROTO__SCHEDULABLE_TRANSACTION_BODY__DATA_TOKEN_DELETION = 27,
  PROTO__SCHEDULABLE_TRANSACTION_BODY__DATA_TOKEN_UPDATE = 28,
  PROTO__SCHEDULABLE_TRANSACTION_BODY__DATA_TOKEN_MINT = 29,
  PROTO__SCHEDULABLE_TRANSACTION_BODY__DATA_TOKEN_BURN = 30,
  PROTO__SCHEDULABLE_TRANSACTION_BODY__DATA_TOKEN_WIPE = 31,
  PROTO__SCHEDULABLE_TRANSACTION_BODY__DATA_TOKEN_ASSOCIATE = 32,
  PROTO__SCHEDULABLE_TRANSACTION_BODY__DATA_TOKEN_DISSOCIATE = 33,
  PROTO__SCHEDULABLE_TRANSACTION_BODY__DATA_SCHEDULE_DELETE = 34
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(PROTO__SCHEDULABLE_TRANSACTION_BODY__DATA__CASE)
} Proto__SchedulableTransactionBody__DataCase;

/*
 * A schedulable transaction. Note that the global/dynamic system property 
 *<tt>scheduling.whitelist</tt> controls which transaction types may be scheduled. 
 *In Hedera Services 0.13.0, it will include only <tt>CryptoTransfer</tt> and
 *<tt>ConsensusSubmitMessage</tt> functions. 
 */
struct  Proto__SchedulableTransactionBody
{
  ProtobufCMessage base;
  /*
   * The maximum transaction fee the client is willing to pay
   */
  uint64_t transactionfee;
  /*
   * A memo to include the execution record; the UTF-8 encoding may be up to 100 bytes and must not include the zero byte
   */
  char *memo;
  Proto__SchedulableTransactionBody__DataCase data_case;
  union {
    /*
     * Calls a function of a contract instance
     */
    Proto__ContractCallTransactionBody *contractcall;
    /*
     * Creates a contract instance
     */
    Proto__ContractCreateTransactionBody *contractcreateinstance;
    /*
     * Updates a contract
     */
    Proto__ContractUpdateTransactionBody *contractupdateinstance;
    /*
     *Delete contract and transfer remaining balance into specified account
     */
    Proto__ContractDeleteTransactionBody *contractdeleteinstance;
    /*
     * Create a new cryptocurrency account
     */
    Proto__CryptoCreateTransactionBody *cryptocreateaccount;
    /*
     * Delete a cryptocurrency account (mark as deleted, and transfer hbars out)
     */
    Proto__CryptoDeleteTransactionBody *cryptodelete;
    /*
     * Transfer amount between accounts
     */
    Proto__CryptoTransferTransactionBody *cryptotransfer;
    /*
     * Modify information such as the expiration date for an account
     */
    Proto__CryptoUpdateTransactionBody *cryptoupdateaccount;
    /*
     * Add bytes to the end of the contents of a file
     */
    Proto__FileAppendTransactionBody *fileappend;
    /*
     * Create a new file
     */
    Proto__FileCreateTransactionBody *filecreate;
    /*
     * Delete a file (remove contents and mark as deleted until it expires)
     */
    Proto__FileDeleteTransactionBody *filedelete;
    /*
     * Modify information such as the expiration date for a file
     */
    Proto__FileUpdateTransactionBody *fileupdate;
    /*
     * Hedera administrative deletion of a file or smart contract
     */
    Proto__SystemDeleteTransactionBody *systemdelete;
    /*
     *To undelete an entity deleted by SystemDelete
     */
    Proto__SystemUndeleteTransactionBody *systemundelete;
    /*
     * Freeze the nodes
     */
    Proto__FreezeTransactionBody *freeze;
    /*
     * Creates a topic
     */
    Proto__ConsensusCreateTopicTransactionBody *consensuscreatetopic;
    /*
     * Updates a topic
     */
    Proto__ConsensusUpdateTopicTransactionBody *consensusupdatetopic;
    /*
     * Deletes a topic
     */
    Proto__ConsensusDeleteTopicTransactionBody *consensusdeletetopic;
    /*
     * Submits message to a topic
     */
    Proto__ConsensusSubmitMessageTransactionBody *consensussubmitmessage;
    /*
     * Creates a token instance
     */
    Proto__TokenCreateTransactionBody *tokencreation;
    /*
     * Freezes account not to be able to transact with a token
     */
    Proto__TokenFreezeAccountTransactionBody *tokenfreeze;
    /*
     * Unfreezes account for a token
     */
    Proto__TokenUnfreezeAccountTransactionBody *tokenunfreeze;
    /*
     * Grants KYC to an account for a token
     */
    Proto__TokenGrantKycTransactionBody *tokengrantkyc;
    /*
     * Revokes KYC of an account for a token
     */
    Proto__TokenRevokeKycTransactionBody *tokenrevokekyc;
    /*
     * Deletes a token instance
     */
    Proto__TokenDeleteTransactionBody *tokendeletion;
    /*
     * Updates a token instance
     */
    Proto__TokenUpdateTransactionBody *tokenupdate;
    /*
     * Mints new tokens to a token's treasury account
     */
    Proto__TokenMintTransactionBody *tokenmint;
    /*
     * Burns tokens from a token's treasury account
     */
    Proto__TokenBurnTransactionBody *tokenburn;
    /*
     * Wipes amount of tokens from an account
     */
    Proto__TokenWipeAccountTransactionBody *tokenwipe;
    /*
     * Associate tokens to an account
     */
    Proto__TokenAssociateTransactionBody *tokenassociate;
    /*
     * Dissociate tokens from an account
     */
    Proto__TokenDissociateTransactionBody *tokendissociate;
    /*
     * Marks a schedule in the network's action queue as deleted, preventing it from executing
     */
    Proto__ScheduleDeleteTransactionBody *scheduledelete;
  };
};
#define PROTO__SCHEDULABLE_TRANSACTION_BODY__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&proto__schedulable_transaction_body__descriptor) \
    , 0, (char *)protobuf_c_empty_string, PROTO__SCHEDULABLE_TRANSACTION_BODY__DATA__NOT_SET, {0} }


/* Proto__SchedulableTransactionBody methods */
void   proto__schedulable_transaction_body__init
                     (Proto__SchedulableTransactionBody         *message);
size_t proto__schedulable_transaction_body__get_packed_size
                     (const Proto__SchedulableTransactionBody   *message);
size_t proto__schedulable_transaction_body__pack
                     (const Proto__SchedulableTransactionBody   *message,
                      uint8_t             *out);
size_t proto__schedulable_transaction_body__pack_to_buffer
                     (const Proto__SchedulableTransactionBody   *message,
                      ProtobufCBuffer     *buffer);
Proto__SchedulableTransactionBody *
       proto__schedulable_transaction_body__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   proto__schedulable_transaction_body__free_unpacked
                     (Proto__SchedulableTransactionBody *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Proto__SchedulableTransactionBody_Closure)
                 (const Proto__SchedulableTransactionBody *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor proto__schedulable_transaction_body__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_SchedulableTransactionBody_2eproto__INCLUDED */
