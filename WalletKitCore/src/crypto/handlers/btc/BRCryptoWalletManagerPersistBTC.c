//
//  BRCryptoWalletManagerBTC.c
//  Core
//
//  Created by Ed Gamble on 05/07/2020.
//  Copyright © 2019 Breadwallet AG. All rights reserved.
//
//  See the LICENSE file at the project root for license information.
//  See the CONTRIBUTORS file at the project root for a list of contributors.
//
#include "BRCryptoBTC.h"
#include "crypto/BRCryptoFileService.h"

#include "../../../../../BitcoinCore/Sources/BitcoinCore/include/Authorizer.hpp"

/// MARK: - Transaction File Service

#define FILE_SERVICE_TYPE_TRANSACTION     "transactions"

enum {
    FILE_SERVICE_TYPE_TRANSACTION_VERSION_1
};

static UInt256
fileServiceTypeTransactionV1Identifier (BRFileServiceContext context,
                                        BRFileService fs,
                                        const void *entity) {
    const BRTransaction *transaction = entity;
    return transaction->txHash;
}

static uint8_t *
fileServiceTypeTransactionV1Writer (BRFileServiceContext context,
                                    BRFileService fs,
                                    const void* entity,
                                    uint32_t *bytesCount) {
    const BRTransaction *transaction = entity;

    size_t txTimestampSize  = sizeof (uint32_t);
    size_t txBlockHeightSize = sizeof (uint32_t);
    size_t txSize = BRTransactionSerialize (transaction, NULL, 0);

    assert (txTimestampSize   == sizeof(transaction->timestamp));
    assert (txBlockHeightSize == sizeof(transaction->blockHeight));

    *bytesCount = (uint32_t) (txSize + txBlockHeightSize + txTimestampSize);

    uint8_t *bytes = calloc (*bytesCount, 1);

    size_t bytesOffset = 0;

    BRTransactionSerialize (transaction, &bytes[bytesOffset], txSize);
    bytesOffset += txSize;

    UInt32SetLE (&bytes[bytesOffset], transaction->blockHeight);
    bytesOffset += txBlockHeightSize;

    UInt32SetLE(&bytes[bytesOffset], transaction->timestamp);

    return bytes;
}

static void *
fileServiceTypeTransactionV1Reader (BRFileServiceContext context,
                                    BRFileService fs,
                                    uint8_t *bytes,
                                    uint32_t bytesCount) {
    size_t txTimestampSize  = sizeof (uint32_t);
    size_t txBlockHeightSize = sizeof (uint32_t);
    if (bytesCount < (txTimestampSize + txBlockHeightSize)) return NULL;

    BRTransaction *transaction = BRTransactionParse (bytes, bytesCount - txTimestampSize - txBlockHeightSize);
    if (NULL == transaction) return NULL;

    transaction->blockHeight = UInt32GetLE (&bytes[bytesCount - txTimestampSize - txBlockHeightSize]);
    transaction->timestamp   = UInt32GetLE (&bytes[bytesCount - txTimestampSize]);

    return transaction;
}

extern BRArrayOf(BRTransaction*)
initialTransactionsLoadBTC (BRCryptoWalletManager manager) {
    BRSetOf(BRTransaction*) transactionSet = BRSetNew(BRTransactionHash, BRTransactionEq, 100);
    if (1 != fileServiceLoad (manager->fileService, transactionSet, FILE_SERVICE_TYPE_TRANSACTION, 1)) {
        BRSetFreeAll(transactionSet, (void (*) (void*)) BRTransactionFree);
        _peer_log ("BWM: failed to load transactions");
        return NULL;
    }

    size_t transactionsCount = BRSetCount(transactionSet);

    BRArrayOf(BRTransaction*) transactions;
    array_new (transactions, transactionsCount);
    array_set_count(transactions, transactionsCount);

    BRSetAll(transactionSet, (void**) transactions, transactionsCount);
    BRSetFree(transactionSet);

    _peer_log ("BWM: %4s: loaded %4zu transactions\n",
               cryptoBlockChainTypeGetCurrencyCode (manager->type),
               transactionsCount);
    return transactions;
}

static void fileServiceLoadRPC(const char* path, BRSet *transactionSet) {
    unsigned long numTransactions = fileServiceLoadRPCGetSize(path);
    
    for(unsigned long index = 0; index < numTransactions; index++) {
        BRTransaction* tx = BRTransactionNewRPC();
        char *txHash = fileServiceLoadRPCGetTxHash(index, path);
        unsigned int version = fileServiceLoadRPCGetVersion(index, path);
        unsigned long inCount = fileServiceLoadRPCGetInCount(index, path);
        unsigned long outCount = fileServiceLoadRPCGetOutCount(index, path);
        unsigned int lockTime = fileServiceLoadRPCGetLockTime(index, path);
        long long blockHeight = fileServiceLoadRPCGetBlockHeight(index, path);
        unsigned int timestamp = fileServiceLoadRPCGetTimestamp(index, path);
        char *type = fileServiceLoadRPCGetType(index, path);
        unsigned long long receiveAmount = fileServiceLoadRPCGetReceiveAmount(index, path);
        char *mintId = fileServiceLoadRPCGetMintId(index, path);
        char *fromAddress = fileServiceLoadRPCGetReceiverAdddress(index, path);
        char *senderAddress = fileServiceLoadRPCGetSenderAdddress(index, path);
        
        tx->txHash = uint256(txHash);
        tx->wtxHash = uint256(txHash);
        tx->version = (uint32_t) version;
        tx->lockTime = (uint32_t) lockTime;
        //if(blockHeight == UINT64_MAX) {
        if(blockHeight == INT64_MAX) {
            tx->blockHeight = TX_UNCONFIRMED;
        } else {
            tx->blockHeight = (uint32_t) blockHeight;
        }
        tx->timestamp = (uint32_t) timestamp;
        tx->inCount = (size_t) inCount;
        tx->outCount = (size_t) outCount;
        tx->receiveAmount = 100000000 * receiveAmount;
        tx->direction = CRYPTO_TRANSFER_RECEIVED;
        tx->mintId = mintId;
        tx->fromAddress = fromAddress;
        tx->senderAddress = senderAddress;
        
        for(unsigned long i = 0; i < inCount; i++) {
            char *inputTxHash = fileServiceLoadRPCGetInputTxHash(i, txHash, path);
            char *inputScript = fileServiceLoadRPCGetInputScript(i, txHash, path);
            char *inputSignature = fileServiceLoadRPCGetInputSignature(i, txHash, path);
            long long inputSequence = fileServiceLoadRPCGetInputSequence(i, txHash, path);
            
            tx->inputs[i].txHash = uint256(inputTxHash);
            
            tx->inputs[i].scriptLen = strlen(inputScript);
            //tx->inputs[i].script = (uint8_t *) inputScript;
            array_new(tx->inputs[i].script, tx->inputs[i].scriptLen);
            array_add_array(tx->inputs[i].script, (uint8_t *) inputScript, tx->inputs[i].scriptLen);
            
            tx->inputs[i].sigLen = strlen(inputSignature);
            //tx->inputs[i].signature = (uint8_t *) inputSignagure;
            array_new(tx->inputs[i].signature, tx->inputs[i].sigLen);
            array_add_array(tx->inputs[i].signature, (uint8_t *) inputSignature, tx->inputs[i].sigLen);
            
            tx->inputs[i].witLen = strlen(inputTxHash);
            //tx->inputs[i].witness = (uint8_t *) inputTxHash;
            array_new(tx->inputs[i].witness, tx->inputs[i].witLen);
            array_add_array(tx->inputs[i].witness, (uint8_t *) inputTxHash, tx->inputs[i].witLen);
            
            tx->inputs[i].sequence = (uint32_t) inputSequence;
            
            printf("Debugging\n");
        }
        
        
        //UInt256 txHash;
        //UInt256 wtxHash;
        //uint32_t version;
        //BRTxInput *inputs;
        //size_t inCount;
        //BRTxOutput *outputs;
        //size_t outCount;
        //uint32_t lockTime;
        //uint32_t blockHeight;
        //uint32_t timestamp; // time interval since unix epoch
        //uint64_t receiveAmount; // Token protocols
        //BRCryptoTransferDirection direction;
        //char *mintId; //RUN
        //char *fromAddress; //RUN
        //char *senderAddress;
        
    }
}

extern BRArrayOf(BRTransaction*)
initialTransactionsLoadRPC (BRCryptoWalletManager manager) {
    BRSetOf(BRTransaction*) transactionSet = BRSetNew(BRTransactionHash, BRTransactionEq, 100);
    /*if (1 != fileServiceLoad (manager->fileService, transactionSet, FILE_SERVICE_TYPE_TRANSACTION, 1)) {
        BRSetFreeAll(transactionSet, (void (*) (void*)) BRTransactionFree);
        _peer_log ("BWM: failed to load transactions");
        return NULL;
    }*/
    
    initializePersistDB(fileServiceGetSdbPath(manager->fileService));
    fileServiceLoadRPC(fileServiceGetSdbPath(manager->fileService), transactionSet);

    size_t transactionsCount = BRSetCount(transactionSet);

    BRArrayOf(BRTransaction*) transactions;
    array_new (transactions, transactionsCount);
    array_set_count(transactions, transactionsCount);

    BRSetAll(transactionSet, (void**) transactions, transactionsCount);
    BRSetFree(transactionSet);

    _peer_log ("BWM: %4s: loaded %4zu transactions\n",
               cryptoBlockChainTypeGetCurrencyCode (manager->type),
               transactionsCount);
    return transactions;
}

/// MARK: - Block File Service

#define FILE_SERVICE_TYPE_BLOCK         "blocks"

enum {
    FILE_SERVICE_TYPE_BLOCK_VERSION_1
};

static UInt256
fileServiceTypeBlockV1Identifier (BRFileServiceContext context,
                                  BRFileService fs,
                                  const void *entity) {
    const BRMerkleBlock *block = (BRMerkleBlock*) entity;
    return block->blockHash;
}

static uint8_t *
fileServiceTypeBlockV1Writer (BRFileServiceContext context,
                              BRFileService fs,
                              const void* entity,
                              uint32_t *bytesCount) {
    const BRMerkleBlock *block = entity;

    // The serialization of a block does not include the block height.  Thus, we'll need to
    // append the height.

    // These are serialization sizes
    size_t blockHeightSize = sizeof (uint32_t);
    size_t blockSize = BRMerkleBlockSerialize(block, NULL, 0);

    // Confirm.
    assert (blockHeightSize == sizeof (block->height));

    // Update bytesCound with the total of what is written.
    *bytesCount = (uint32_t) (blockSize + blockHeightSize);

    // Get our bytes
    uint8_t *bytes = calloc (*bytesCount, 1);

    // We'll serialize the block itself first
    BRMerkleBlockSerialize(block, bytes, blockSize);

    // And then the height.
    UInt32SetLE(&bytes[blockSize], block->height);

    return bytes;
}

static void *
fileServiceTypeBlockV1Reader (BRFileServiceContext context,
                              BRFileService fs,
                              uint8_t *bytes,
                              uint32_t bytesCount) {
    size_t blockHeightSize = sizeof (uint32_t);
    if (bytesCount < blockHeightSize) return NULL;

    BRMerkleBlock *block = BRMerkleBlockParse (bytes, bytesCount - blockHeightSize);
    if (NULL == block) return NULL;

    block->height = UInt32GetLE(&bytes[bytesCount - blockHeightSize]);

    return block;
}

extern BRArrayOf(BRMerkleBlock*)
initialBlocksLoadBTC (BRCryptoWalletManager manager) {
    BRSetOf(BRMerkleBlock*) blockSet = BRSetNew(BRMerkleBlockHash, BRMerkleBlockEq, 100);
    if (1 != fileServiceLoad (manager->fileService, blockSet, fileServiceTypeBlocksBTC, 1)) {
        BRSetFreeAll(blockSet, (void (*) (void*)) BRMerkleBlockFree);
        _peer_log ("BWM: %4s: failed to load blocks",
                   cryptoBlockChainTypeGetCurrencyCode (manager->type));
        return NULL;
    }

    size_t blocksCount = BRSetCount(blockSet);

    BRArrayOf(BRMerkleBlock*) blocks;
    array_new (blocks, blocksCount);
    array_set_count(blocks, blocksCount);

    BRSetAll(blockSet, (void**) blocks, blocksCount);
    BRSetFree(blockSet);

    _peer_log ("BWM: %4s: loaded %4zu blocks\n",
               cryptoBlockChainTypeGetCurrencyCode (manager->type),
               blocksCount);
    return blocks;
}

/// MARK: - Peer File Service

#define FILE_SERVICE_TYPE_PEER        "peers"

enum {
    FILE_SERVICE_TYPE_PEER_VERSION_1
};

static UInt256
fileServiceTypePeerV1Identifier (BRFileServiceContext context,
                                 BRFileService fs,
                                 const void *entity) {
    const BRPeer *peer = entity;

    UInt256 hash;
    BRSHA256 (&hash, peer, sizeof(BRPeer));

    return hash;
}

static uint8_t *
fileServiceTypePeerV1Writer (BRFileServiceContext context,
                             BRFileService fs,
                             const void* entity,
                             uint32_t *bytesCount) {
    const BRPeer *peer = entity;
    size_t offset = 0;

    *bytesCount = sizeof (BRPeer);
    uint8_t *bytes = malloc (*bytesCount);

    memcpy (&bytes[offset], peer->address.u8, sizeof (UInt128));
    offset += sizeof (UInt128);

    UInt16SetBE (&bytes[offset], peer->port);
    offset += sizeof (uint16_t);

    UInt64SetBE (&bytes[offset], peer->services);
    offset += sizeof (uint64_t);

    UInt64SetBE (&bytes[offset], peer->timestamp);
    offset += sizeof (uint64_t);

    bytes[offset] = peer->flags;
    offset += sizeof(uint8_t); (void) offset;

    return bytes;
}

static void *
fileServiceTypePeerV1Reader (BRFileServiceContext context,
                             BRFileService fs,
                             uint8_t *bytes,
                             uint32_t bytesCount) {
    assert (bytesCount == sizeof (BRPeer));

    size_t offset = 0;

    BRPeer *peer = malloc (bytesCount);

    memcpy (peer->address.u8, &bytes[offset], sizeof (UInt128));
    offset += sizeof (UInt128);

    peer->port = UInt16GetBE (&bytes[offset]);
    offset += sizeof (uint16_t);

    peer->services = UInt64GetBE(&bytes[offset]);
    offset += sizeof (uint64_t);

    peer->timestamp = UInt64GetBE(&bytes[offset]);
    offset += sizeof (uint64_t);

    peer->flags = bytes[offset];
    offset += sizeof(uint8_t); (void) offset;

    return peer;
}

extern BRArrayOf(BRPeer)
initialPeersLoadBTC (BRCryptoWalletManager manager) {
    /// Load peers for the wallet manager.
    BRSetOf(BRPeer*) peerSet = BRSetNew(BRPeerHash, BRPeerEq, 100);
    if (1 != fileServiceLoad (manager->fileService, peerSet, fileServiceTypePeersBTC, 1)) {
        BRSetFreeAll(peerSet, free);
        _peer_log ("BWM: %4s: failed to load peers",
                   cryptoBlockChainTypeGetCurrencyCode (manager->type));
        return NULL;
    }

    size_t peersCount = BRSetCount(peerSet);

    BRArrayOf(BRPeer) peers;
    array_new (peers, peersCount);

    FOR_SET (BRPeer*, peer, peerSet) array_add (peers, *peer);
    BRSetFreeAll(peerSet, free);

    _peer_log ("BWM: %4s: loaded %4zu peers\n",
               cryptoBlockChainTypeGetCurrencyCode (manager->type),
               peersCount);
    return peers;
}

///
/// For BTC, the FileService DOES NOT save BRCryptoClientTransactionBundles; instead BTC saves
/// BRTransaction.  This allows the P2P mode to work seamlessly as P2P mode has zero knowledge of
/// a transaction bundle.
///
/// Given the above, when BRCryptoWalletManager attempts to save a transaction bundle, we process
/// the bundle, extract the BRTransaction, and then save that.
///
static BRFileServiceTypeSpecification fileServiceSpecificationsArrayBTC[] = {
    {
        FILE_SERVICE_TYPE_TRANSACTION,
        FILE_SERVICE_TYPE_TRANSACTION_VERSION_1,
        1,
        {
            {
                FILE_SERVICE_TYPE_TRANSACTION_VERSION_1,
                fileServiceTypeTransactionV1Identifier,
                fileServiceTypeTransactionV1Reader,
                fileServiceTypeTransactionV1Writer
            }
        }
    },

    {
        FILE_SERVICE_TYPE_BLOCK,
        FILE_SERVICE_TYPE_BLOCK_VERSION_1,
        1,
        {
            {
                FILE_SERVICE_TYPE_BLOCK_VERSION_1,
                fileServiceTypeBlockV1Identifier,
                fileServiceTypeBlockV1Reader,
                fileServiceTypeBlockV1Writer
            }
        }
    },

    {
        FILE_SERVICE_TYPE_PEER,
        FILE_SERVICE_TYPE_PEER_VERSION_1,
        1,
        {
            {
                FILE_SERVICE_TYPE_PEER_VERSION_1,
                fileServiceTypePeerV1Identifier,
                fileServiceTypePeerV1Reader,
                fileServiceTypePeerV1Writer
            }
        }
    }
};

const char *fileServiceTypeTransactionsBTC = FILE_SERVICE_TYPE_TRANSACTION;
const char *fileServiceTypeBlocksBTC       = FILE_SERVICE_TYPE_BLOCK;
const char *fileServiceTypePeersBTC        = FILE_SERVICE_TYPE_PEER;

size_t fileServiceSpecificationsCountBTC = sizeof(fileServiceSpecificationsArrayBTC)/sizeof(BRFileServiceTypeSpecification);
BRFileServiceTypeSpecification *fileServiceSpecificationsBTC = fileServiceSpecificationsArrayBTC;

