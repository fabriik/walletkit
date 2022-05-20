//
//  BRStellarTransaction.h
//  Core
//
//  Created by Carl Cherry on 5/21/2019.
//  Copyright © 2019 Breadwinner AG. All rights reserved.
//
//  See the LICENSE file at the project root for license information.
//  See the CONTRIBUTORS file at the project root for a list of contributors.
//
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "BRStellar.h"
#include "BRStellarBase.h"
#include "BRStellarPrivateStructs.h"
#include "BRStellarAccountUtils.h"
#include "BRStellarSerialize.h"
#include "BRStellarAccount.h"
#include "support/BRCrypto.h"
#include "support/BRInt.h"
#include "support/BRArray.h"
#include "utils/b64.h"
#include "ed25519/ed25519.h"

struct BRStellarSerializedTransactionRecord {
    size_t   size;
    uint8_t  *buffer;
    uint8_t  txHash[32];
};

struct BRStellarTransactionRecord {
    // The address of the account "doing" the transaction
    BRStellarAccountID accountID; // sender
    BRStellarFee fee;
    BRStellarSequence sequence;
    BRStellarTimeBounds *timeBounds;
    uint32_t numTimeBounds;
    BRStellarMemo *memo;
    uint32_t numSignatures;
    BRArrayOf(BRStellarOperation) operations;

    BRStellarSerializedTransaction signedBytes; // Set after signing

    BRStellarTransactionResult result;
};

void stellarSerializedTransactionRecordFree(BRStellarSerializedTransaction * signedBytes)
{
    // Free the signed bytes object
    assert(signedBytes);
    assert(*signedBytes);
    if ((*signedBytes)->buffer) {
        free((*signedBytes)->buffer);
    }
    free(*signedBytes);
}

static BRStellarTransaction createTransactionObject(BRStellarAccountID *accountID,
                                                    BRStellarFee fee,
                                                    BRStellarTimeBounds *timeBounds,
                                                    int numTimeBounds,
                                                    BRStellarMemo *memo,
                                                    BRArrayOf(BRStellarOperation) operations)
{
    // Called when the user is actually creating a fully populated transaction
    BRStellarTransaction transaction = calloc (1, sizeof (struct BRStellarTransactionRecord));
    assert(transaction);
    transaction->accountID = *accountID;
    transaction->fee = fee;
    transaction->timeBounds = timeBounds;
    transaction->numTimeBounds = numTimeBounds;
    transaction->memo = memo;
    transaction->operations = operations;
    transaction->signedBytes = NULL;
    transaction->numSignatures = 0;
    return transaction;
}

extern BRStellarTransaction
stellarTransactionCreate(BRStellarAccountID *accountID,
                         BRStellarFee fee,
                         BRStellarTimeBounds *timeBounds,
                         int numTimeBounds,
                         BRStellarMemo *memo,
                         BRArrayOf(BRStellarOperation) operations)
{
    return createTransactionObject(accountID, fee, timeBounds, numTimeBounds,
                                memo, operations);
}

extern BRStellarTransaction /* caller must free - stellarTransactionFree */
stellarTransactionCreateFromBytes(uint8_t *tx_bytes, size_t tx_length)
{
    BRStellarTransaction transaction = calloc (1, sizeof (struct BRStellarTransactionRecord));
    array_new(transaction->operations, 0);

    // If we have some bytes then deserialize - otherwize the caller gets an empty tx
    if (tx_length > 0) // envelope_xdr
    {
        int32_t version = 0;
        uint8_t *signatures = NULL;
        stellarDeserializeTransaction(&transaction->accountID,
                                       &transaction->fee,
                                       &transaction->sequence,
                                       &transaction->timeBounds,
                                       &transaction->numTimeBounds,
                                       &transaction->memo,
                                       &transaction->operations,
                                       &version,
                                       &signatures,
                                       &transaction->numSignatures,
                                      tx_bytes, tx_length);
    }
    return transaction;
}

extern void stellarTransactionFree(BRStellarTransaction transaction)
{
    assert(transaction);
    if (transaction->signedBytes) {
        stellarSerializedTransactionRecordFree(&transaction->signedBytes);
    }
    // There could be some embeded arrays in the results
    if (transaction->operations) {
        for (int i = 0; i < array_count(transaction->operations); i++) {
            BRStellarOperation *op = &transaction->operations[i];
            if (op->type == ST_OP_MANAGE_BUY_OFFER) {
                // If we parsed a result_xdr there could be an array of ClaimedOffers
                if (op->operation.manageBuyOffer.offerResult.claimOfferAtom) {
                    array_free(op->operation.manageBuyOffer.offerResult.claimOfferAtom);
                }
            }
            if (op->type == ST_OP_MANAGE_SELL_OFFER) {
                // If we parsed a result_xdr there could be an array of ClaimedOffers
                if (op->operation.manageSellOffer.offerResult.claimOfferAtom) {
                    array_free(op->operation.manageSellOffer.offerResult.claimOfferAtom);
                }
            }
            if (op->type == ST_OP_CREATE_PASSIVE_SELL_OFFER) {
                // If we parsed a result_xdr there could be an array of ClaimedOffers
                if (op->operation.passiveSellOffer.offerResult.claimOfferAtom) {
                    array_free(op->operation.passiveSellOffer.offerResult.claimOfferAtom);
                }
            }
            if (op->type == ST_OP_INFLATION) {
                // If we parsed a result_xdr there could be an array of ClaimedOffers
                if (op->operation.inflation.payouts) {
                    array_free(op->operation.inflation.payouts);
                }
            }
        }
        array_free(transaction->operations);
    }
    free(transaction);
}

static void createTransactionHash(uint8_t *md32, uint8_t *tx, size_t txLength, const char* networkID)
{
    // What are we going to hash
    // sha256(networkID) + tx_type + tx
    // tx_type is basically a 4-byte packed int
    size_t size = 32 + 4 + txLength;
    uint8_t bytes_to_hash[size];
    uint8_t *pHash = bytes_to_hash;
    
    // Hash the networkID
    uint8_t networkHash[32];
    BRSHA256(networkHash, networkID, strlen(networkID));
    memcpy(pHash, networkHash, 32);
    pHash += 32;
    uint8_t tx_type[4] = {0, 0, 0, 2}; // Add the tx_type
    memcpy(pHash, tx_type, 4);
    pHash += 4;
    memcpy(pHash, tx, txLength); // Add the serialized transaction
    
    // Do a sha256 hash of the data
    BRSHA256(md32, bytes_to_hash, size);
}

// Map the network types to a string - get's hashed into the transaction
const char *stellarNetworks[] = {
    "Public Global Stellar Network ; September 2015",
    "Test SDF Network ; September 2015"
};

static BRStellarSignatureRecord stellarTransactionSign(uint8_t * tx_hash, size_t txHashLength,
                                                uint8_t *privateKey, uint8_t *publicKey)
{
    // Create a signature from the incoming bytes
    unsigned char signature[64];
    ed25519_sign(signature, tx_hash, txHashLength, publicKey, privateKey);
    
    // This is what they call a decorated signature - it includes
    // a 4-byte hint of what public key is used for signing
    BRStellarSignatureRecord sig;
    memcpy(sig.signature, &publicKey[28], 4); // Last 4 bytes of public key
    memcpy(&sig.signature[4], signature, 64);
    return sig;
}

extern BRStellarSerializedTransaction
stellarTransactionSerializeAndSign(BRStellarTransaction transaction, uint8_t *privateKey,
                                  uint8_t *publicKey, uint64_t sequence, BRStellarNetworkType networkType)
{
    // If this transaction was previously signed - delete that info
    if (transaction->signedBytes) {
        stellarSerializedTransactionRecordFree(&transaction->signedBytes);
        transaction->signedBytes = 0;
    }
    
    // Add in the provided parameters
    transaction->sequence = sequence;

    // Serialize the bytes
    uint8_t * buffer = NULL;
    size_t length = stellarSerializeTransaction(&transaction->accountID, transaction->fee, sequence,
                                                transaction->timeBounds,
                                                transaction->numTimeBounds,
                                                transaction->memo,
                                                transaction->operations,
                                                0, NULL, 0, &buffer);

    // Create the transaction hash that needs to be signed
    uint8_t tx_hash[32];
    createTransactionHash(tx_hash, buffer, length, stellarNetworks[networkType]);

    // Sign the bytes and get signature
    BRStellarSignatureRecord sig = stellarTransactionSign(tx_hash, 32, privateKey, publicKey);

    // Serialize the bytes and sign
    free(buffer);
    length = stellarSerializeTransaction(&transaction->accountID, transaction->fee, sequence,
                                                transaction->timeBounds,
                                                transaction->numTimeBounds,
                                                transaction->memo,
                                                transaction->operations,
                                                0, sig.signature, 1, &buffer);

    if (length) {
        transaction->signedBytes = calloc(1, sizeof(struct BRStellarSerializedTransactionRecord));
        transaction->signedBytes->buffer = calloc(1, length);
        memcpy(transaction->signedBytes->buffer, buffer, length);
        transaction->signedBytes->size = length;
        memcpy(transaction->signedBytes->txHash, tx_hash, 32);
    }
    
    // Return the pointer to the signed byte object (or perhaps NULL)
    return transaction->signedBytes;

}

extern BRStellarTransactionHash stellarTransactionGetHash(BRStellarTransaction transaction)
{
    assert(transaction);
    BRStellarTransactionHash hash;
    // The only time we get the hash is when we do the serialize and sign. That way
    // if someone changes the transaction we would need to generate a new hash
    if (transaction->signedBytes) {
        memcpy(hash.bytes, transaction->signedBytes->txHash, 32);
    } else {
        memset(hash.bytes, 0x00, 32);
    }
    return hash;
}

extern size_t stellarGetSerializedSize(BRStellarSerializedTransaction s)
{
    assert(s);
    return s->size;
}
extern uint8_t* stellarGetSerializedBytes(BRStellarSerializedTransaction s)
{
    assert(s);
    return (s->buffer);
}

extern BRStellarAccountID stellarTransactionGetAccountID(BRStellarTransaction transaction)
{
    assert(transaction);
    return transaction->accountID;
}

extern size_t stellarTransactionGetOperationCount(BRStellarTransaction transaction)
{
    assert(transaction);
    return array_count(transaction->operations);
}
extern uint32_t stellarTransactionGetSignatureCount(BRStellarTransaction transaction)
{
    assert(transaction);
    return transaction->numSignatures;
}

extern BRStellarMemo * /* DO NOT FREE - owned by the transaction object */
stellarTransactionGetMemo(BRStellarTransaction transaction)
{
    assert(transaction);
    return transaction->memo;
}

extern BRStellarOperation * /* DO NOT FREE - owned by the transaction object */
stellarTransactionGetOperation(BRStellarTransaction transaction, uint32_t operationIndex)
{
    assert(transaction);
    if (operationIndex >= array_count(transaction->operations)) {
        return NULL;
    } else {
        return &transaction->operations[operationIndex];
    }
}

extern BRStellarTransactionResult
stellarTransactionGetResult(BRStellarTransaction transaction, const char* result_xdr)
{
    // Convert the result_xdr to bytes
    assert(result_xdr);
    assert(strlen(result_xdr) > 0);
    assert(transaction);
    // Convert the base64 string returned from the server to a byte array
    size_t byteSize = 0;
    uint8_t * bytes = b64_decode_ex(result_xdr, strlen(result_xdr), &byteSize);
    // The result may (or may not) have any operations, depending on at what level
    // any error occurred. If there are operations in the result then the assumption
    // is that results are in the same order as they were in the transaction. Since
    // there are no operation identifiers this must be the case.
    stellarDeserializeResultXDR(bytes, byteSize, &transaction->operations, &transaction->result);
    free(bytes);
    transaction->result.resultParsed = 1;
    return transaction->result;
}

