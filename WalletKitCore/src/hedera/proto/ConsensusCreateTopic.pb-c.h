/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: ConsensusCreateTopic.proto */

#ifndef PROTOBUF_C_ConsensusCreateTopic_2eproto__INCLUDED
#define PROTOBUF_C_ConsensusCreateTopic_2eproto__INCLUDED

#include "protobuf-c.h"

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1004000 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

#include "BasicTypes.pb-c.h"
#include "Duration.pb-c.h"

typedef struct Proto__ConsensusCreateTopicTransactionBody Proto__ConsensusCreateTopicTransactionBody;


/* --- enums --- */


/* --- messages --- */

/*
 * See [ConsensusService.createTopic()](#proto.ConsensusService)
 */
struct  Proto__ConsensusCreateTopicTransactionBody
{
  ProtobufCMessage base;
  /*
   * Short publicly visible memo about the topic. No guarantee of uniqueness.
   */
  char *memo;
  /*
   * Access control for updateTopic/deleteTopic.
   * Anyone can increase the topic's expirationTime via ConsensusService.updateTopic(), regardless of the adminKey.
   * If no adminKey is specified, updateTopic may only be used to extend the topic's expirationTime, and deleteTopic
   * is disallowed.
   */
  Proto__Key *adminkey;
  /*
   * Access control for submitMessage.
   * If unspecified, no access control is performed on ConsensusService.submitMessage (all submissions are allowed).
   */
  Proto__Key *submitkey;
  /*
   * The initial lifetime of the topic and the amount of time to attempt to extend the topic's lifetime by
   * automatically at the topic's expirationTime, if the autoRenewAccount is configured (once autoRenew functionality
   * is supported by HAPI).
   * Limited to MIN_AUTORENEW_PERIOD and MAX_AUTORENEW_PERIOD value by server-side configuration.
   * Required.
   */
  Proto__Duration *autorenewperiod;
  /*
   * Optional account to be used at the topic's expirationTime to extend the life of the topic (once autoRenew
   * functionality is supported by HAPI).
   * The topic lifetime will be extended up to a maximum of the autoRenewPeriod or however long the topic
   * can be extended using all funds on the account (whichever is the smaller duration/amount and if any extension
   * is possible with the account's funds).
   * If specified, there must be an adminKey and the autoRenewAccount must sign this transaction.
   */
  Proto__AccountID *autorenewaccount;
};
#define PROTO__CONSENSUS_CREATE_TOPIC_TRANSACTION_BODY__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&proto__consensus_create_topic_transaction_body__descriptor) \
    , (char *)protobuf_c_empty_string, NULL, NULL, NULL, NULL }


/* Proto__ConsensusCreateTopicTransactionBody methods */
void   proto__consensus_create_topic_transaction_body__init
                     (Proto__ConsensusCreateTopicTransactionBody         *message);
size_t proto__consensus_create_topic_transaction_body__get_packed_size
                     (const Proto__ConsensusCreateTopicTransactionBody   *message);
size_t proto__consensus_create_topic_transaction_body__pack
                     (const Proto__ConsensusCreateTopicTransactionBody   *message,
                      uint8_t             *out);
size_t proto__consensus_create_topic_transaction_body__pack_to_buffer
                     (const Proto__ConsensusCreateTopicTransactionBody   *message,
                      ProtobufCBuffer     *buffer);
Proto__ConsensusCreateTopicTransactionBody *
       proto__consensus_create_topic_transaction_body__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   proto__consensus_create_topic_transaction_body__free_unpacked
                     (Proto__ConsensusCreateTopicTransactionBody *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Proto__ConsensusCreateTopicTransactionBody_Closure)
                 (const Proto__ConsensusCreateTopicTransactionBody *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor proto__consensus_create_topic_transaction_body__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_ConsensusCreateTopic_2eproto__INCLUDED */
