/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: Response.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "Response.pb-c.h"
void   proto__response__init
                     (Proto__Response         *message)
{
  static const Proto__Response init_value = PROTO__RESPONSE__INIT;
  *message = init_value;
}
size_t proto__response__get_packed_size
                     (const Proto__Response *message)
{
  assert(message->base.descriptor == &proto__response__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t proto__response__pack
                     (const Proto__Response *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &proto__response__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t proto__response__pack_to_buffer
                     (const Proto__Response *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &proto__response__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Proto__Response *
       proto__response__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Proto__Response *)
     protobuf_c_message_unpack (&proto__response__descriptor,
                                allocator, len, data);
}
void   proto__response__free_unpacked
                     (Proto__Response *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &proto__response__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor proto__response__field_descriptors[23] =
{
  {
    "getByKey",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Proto__Response, response_case),
    offsetof(Proto__Response, getbykey),
    &proto__get_by_key_response__descriptor,
    NULL,
    0 | PROTOBUF_C_FIELD_FLAG_ONEOF,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "getBySolidityID",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Proto__Response, response_case),
    offsetof(Proto__Response, getbysolidityid),
    &proto__get_by_solidity_idresponse__descriptor,
    NULL,
    0 | PROTOBUF_C_FIELD_FLAG_ONEOF,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "contractCallLocal",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Proto__Response, response_case),
    offsetof(Proto__Response, contractcalllocal),
    &proto__contract_call_local_response__descriptor,
    NULL,
    0 | PROTOBUF_C_FIELD_FLAG_ONEOF,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "contractGetInfo",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Proto__Response, response_case),
    offsetof(Proto__Response, contractgetinfo),
    &proto__contract_get_info_response__descriptor,
    NULL,
    0 | PROTOBUF_C_FIELD_FLAG_ONEOF,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "contractGetBytecodeResponse",
    5,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Proto__Response, response_case),
    offsetof(Proto__Response, contractgetbytecoderesponse),
    &proto__contract_get_bytecode_response__descriptor,
    NULL,
    0 | PROTOBUF_C_FIELD_FLAG_ONEOF,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "contractGetRecordsResponse",
    6,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Proto__Response, response_case),
    offsetof(Proto__Response, contractgetrecordsresponse),
    &proto__contract_get_records_response__descriptor,
    NULL,
    0 | PROTOBUF_C_FIELD_FLAG_ONEOF,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "cryptogetAccountBalance",
    7,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Proto__Response, response_case),
    offsetof(Proto__Response, cryptogetaccountbalance),
    &proto__crypto_get_account_balance_response__descriptor,
    NULL,
    0 | PROTOBUF_C_FIELD_FLAG_ONEOF,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "cryptoGetAccountRecords",
    8,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Proto__Response, response_case),
    offsetof(Proto__Response, cryptogetaccountrecords),
    &proto__crypto_get_account_records_response__descriptor,
    NULL,
    0 | PROTOBUF_C_FIELD_FLAG_ONEOF,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "cryptoGetInfo",
    9,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Proto__Response, response_case),
    offsetof(Proto__Response, cryptogetinfo),
    &proto__crypto_get_info_response__descriptor,
    NULL,
    0 | PROTOBUF_C_FIELD_FLAG_ONEOF,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "cryptoGetLiveHash",
    10,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Proto__Response, response_case),
    offsetof(Proto__Response, cryptogetlivehash),
    &proto__crypto_get_live_hash_response__descriptor,
    NULL,
    0 | PROTOBUF_C_FIELD_FLAG_ONEOF,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "cryptoGetProxyStakers",
    11,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Proto__Response, response_case),
    offsetof(Proto__Response, cryptogetproxystakers),
    &proto__crypto_get_stakers_response__descriptor,
    NULL,
    0 | PROTOBUF_C_FIELD_FLAG_ONEOF,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "fileGetContents",
    12,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Proto__Response, response_case),
    offsetof(Proto__Response, filegetcontents),
    &proto__file_get_contents_response__descriptor,
    NULL,
    0 | PROTOBUF_C_FIELD_FLAG_ONEOF,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "fileGetInfo",
    13,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Proto__Response, response_case),
    offsetof(Proto__Response, filegetinfo),
    &proto__file_get_info_response__descriptor,
    NULL,
    0 | PROTOBUF_C_FIELD_FLAG_ONEOF,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "transactionGetReceipt",
    14,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Proto__Response, response_case),
    offsetof(Proto__Response, transactiongetreceipt),
    &proto__transaction_get_receipt_response__descriptor,
    NULL,
    0 | PROTOBUF_C_FIELD_FLAG_ONEOF,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "transactionGetRecord",
    15,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Proto__Response, response_case),
    offsetof(Proto__Response, transactiongetrecord),
    &proto__transaction_get_record_response__descriptor,
    NULL,
    0 | PROTOBUF_C_FIELD_FLAG_ONEOF,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "transactionGetFastRecord",
    16,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Proto__Response, response_case),
    offsetof(Proto__Response, transactiongetfastrecord),
    &proto__transaction_get_fast_record_response__descriptor,
    NULL,
    0 | PROTOBUF_C_FIELD_FLAG_ONEOF,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "consensusGetTopicInfo",
    150,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Proto__Response, response_case),
    offsetof(Proto__Response, consensusgettopicinfo),
    &proto__consensus_get_topic_info_response__descriptor,
    NULL,
    0 | PROTOBUF_C_FIELD_FLAG_ONEOF,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "networkGetVersionInfo",
    151,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Proto__Response, response_case),
    offsetof(Proto__Response, networkgetversioninfo),
    &proto__network_get_version_info_response__descriptor,
    NULL,
    0 | PROTOBUF_C_FIELD_FLAG_ONEOF,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "tokenGetInfo",
    152,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Proto__Response, response_case),
    offsetof(Proto__Response, tokengetinfo),
    &proto__token_get_info_response__descriptor,
    NULL,
    0 | PROTOBUF_C_FIELD_FLAG_ONEOF,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "scheduleGetInfo",
    153,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Proto__Response, response_case),
    offsetof(Proto__Response, schedulegetinfo),
    &proto__schedule_get_info_response__descriptor,
    NULL,
    0 | PROTOBUF_C_FIELD_FLAG_ONEOF,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "tokenGetAccountNftInfos",
    154,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Proto__Response, response_case),
    offsetof(Proto__Response, tokengetaccountnftinfos),
    &proto__token_get_account_nft_infos_response__descriptor,
    NULL,
    0 | PROTOBUF_C_FIELD_FLAG_ONEOF,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "tokenGetNftInfo",
    155,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Proto__Response, response_case),
    offsetof(Proto__Response, tokengetnftinfo),
    &proto__token_get_nft_info_response__descriptor,
    NULL,
    0 | PROTOBUF_C_FIELD_FLAG_ONEOF,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "tokenGetNftInfos",
    156,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Proto__Response, response_case),
    offsetof(Proto__Response, tokengetnftinfos),
    &proto__token_get_nft_infos_response__descriptor,
    NULL,
    0 | PROTOBUF_C_FIELD_FLAG_ONEOF,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned proto__response__field_indices_by_name[] = {
  16,   /* field[16] = consensusGetTopicInfo */
  2,   /* field[2] = contractCallLocal */
  4,   /* field[4] = contractGetBytecodeResponse */
  3,   /* field[3] = contractGetInfo */
  5,   /* field[5] = contractGetRecordsResponse */
  7,   /* field[7] = cryptoGetAccountRecords */
  8,   /* field[8] = cryptoGetInfo */
  9,   /* field[9] = cryptoGetLiveHash */
  10,   /* field[10] = cryptoGetProxyStakers */
  6,   /* field[6] = cryptogetAccountBalance */
  11,   /* field[11] = fileGetContents */
  12,   /* field[12] = fileGetInfo */
  0,   /* field[0] = getByKey */
  1,   /* field[1] = getBySolidityID */
  17,   /* field[17] = networkGetVersionInfo */
  19,   /* field[19] = scheduleGetInfo */
  20,   /* field[20] = tokenGetAccountNftInfos */
  18,   /* field[18] = tokenGetInfo */
  21,   /* field[21] = tokenGetNftInfo */
  22,   /* field[22] = tokenGetNftInfos */
  15,   /* field[15] = transactionGetFastRecord */
  13,   /* field[13] = transactionGetReceipt */
  14,   /* field[14] = transactionGetRecord */
};
static const ProtobufCIntRange proto__response__number_ranges[2 + 1] =
{
  { 1, 0 },
  { 150, 16 },
  { 0, 23 }
};
const ProtobufCMessageDescriptor proto__response__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "proto.Response",
  "Response",
  "Proto__Response",
  "proto",
  sizeof(Proto__Response),
  23,
  proto__response__field_descriptors,
  proto__response__field_indices_by_name,
  2,  proto__response__number_ranges,
  (ProtobufCMessageInit) proto__response__init,
  NULL,NULL,NULL    /* reserved[123] */
};
