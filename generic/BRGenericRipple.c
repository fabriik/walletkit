//
//  BRGenericRipple.c
//  Core
//
//  Created by Ed Gamble on 6/19/19.
//  Copyright © 2019 Breadwinner AG. All rights reserved.
//
//  See the LICENSE file at the project root for license information.
//  See the CONTRIBUTORS file at the project root for a list of contributors.

#include "BRGenericRipple.h"
#include "ripple/BRRippleAccount.h"
#include "ripple/BRRippleWallet.h"
#include "ripple/BRRippleTransaction.h"
#include "ripple/BRRippleFeeBasis.h"
#include "support/BRSet.h"
#include "ethereum/util/BRUtilHex.h"

// MARK: - Generic Network

// MARK: - Generic Account

static BRGenericAccountRef
genericRippleAccountCreate (const char *type, UInt512 seed) {
    return (BRGenericAccountRef) rippleAccountCreateWithSeed (seed);
}

static BRGenericAccountRef
genericRippleAccountCreateWithPublicKey (const char *type, BRKey key) {
    return (BRGenericAccountRef) rippleAccountCreateWithKey (key);
}

static BRGenericAccountRef
genericRippleAccountCreateWithSerialization (const char *type, uint8_t *bytes, size_t bytesCount) {
    return (BRGenericAccountRef) rippleAccountCreateWithSerialization (bytes, bytesCount);
}

static void
genericRippleAccountFree (BRGenericAccountRef account) {
    rippleAccountFree ((BRRippleAccount) account);
}

static BRGenericAddressRef
genericRippleAccountGetAddress (BRGenericAccountRef account) {
    return (BRGenericAddressRef) rippleAccountGetAddress((BRRippleAccount) account);
}

static uint8_t *
genericRippleAccountGetSerialization (BRGenericAccountRef account,
                                      size_t *bytesCount) {
    return rippleAccountGetSerialization ((BRRippleAccount) account, bytesCount);
}

static void
genericRippleAccountSignTransferWithSeed (BRGenericAccountRef account,
                                          BRGenericTransferRef transfer,
                                          UInt512 seed)
{
    // Get the transaction pointer from this transfer
    BRRippleTransaction transaction = rippleTransferGetTransaction((BRRippleTransfer) transfer);
    if (transaction) {
        rippleAccountSignTransaction ((BRRippleAccount) account, transaction, seed);
    }
}

static void
genericRippleAccountSignTransferWithKey (BRGenericAccountRef account,
                                         BRGenericTransferRef transfer,
                                         BRKey *key)
{
    // Get the transaction pointer from this transfer
    BRRippleTransaction transaction = rippleTransferGetTransaction ((BRRippleTransfer) transfer);
    if (transaction) {
//        rippleAccountSignTransaction(account, transaction, seed);
        assert (0);
    }
}

// MARK: - Generic Address

static BRGenericAddressRef
genericRippleAddressCreate (const char *string) {
    return (BRGenericAddressRef) rippleAddressCreateFromString (string);
}

static char *
genericRippleAddressAsString (BRGenericAddressRef address) {
    return rippleAddressAsString ((BRRippleAddress) address);
}

static int
genericRippleAddressEqual (BRGenericAddressRef address1,
                           BRGenericAddressRef address2) {
    return rippleAddressEqual ((BRRippleAddress) address1,
                               (BRRippleAddress) address2);
}

static void
genericRippleAddressFree (BRGenericAddressRef address) {
    rippleAddressFree ((BRRippleAddress) address);
}

// MARK: - Generic Transfer

static BRGenericTransferRef
genericRippleTransferCreate (BRGenericAddressRef source,
                             BRGenericAddressRef target,
                             UInt256 amount)
{
    BRRippleUnitDrops amountDrops = UInt64GetLE(amount.u8);

    return (BRGenericTransferRef) rippleTransferCreateNew ((BRRippleAddress) source,
                                                           (BRRippleAddress) target,
                                                           amountDrops);
}

static BRGenericTransferRef
genericRippleTransferCopy (BRGenericTransferRef transfer) {
    return (BRGenericTransferRef) rippleTransferClone ((BRRippleTransfer) transfer);
}

static void
genericRippleTransferFree (BRGenericTransferRef transfer) {
    rippleTransferFree ((BRRippleTransfer) transfer);
}

static BRGenericAddressRef
genericRippleTransferGetSourceAddress (BRGenericTransferRef transfer) {
    return (BRGenericAddressRef) rippleTransferGetSource ((BRRippleTransfer) transfer);
}

static BRGenericAddressRef
genericRippleTransferGetTargetAddress (BRGenericTransferRef transfer) {
    return (BRGenericAddressRef) rippleTransferGetTarget ((BRRippleTransfer) transfer);
}

static UInt256
genericRippleTransferGetAmount (BRGenericTransferRef transfer) {
    BRRippleUnitDrops drops = rippleTransferGetAmount ((BRRippleTransfer) transfer);
    return createUInt256(drops);
}

static BRGenericFeeBasis
genericRippleTransferGetFeeBasis (BRGenericTransferRef transfer) {
    BRRippleUnitDrops rippleFee = rippleTransferGetFee ((BRRippleTransfer) transfer);
    return (BRGenericFeeBasis) {
        createUInt256 (rippleFee),
        1
    };
}

static BRGenericHash
genericRippleTransferGetHash (BRGenericTransferRef transfer) {
    BRRippleTransactionHash hash = rippleTransferGetTransactionId ((BRRippleTransfer) transfer);
    UInt256 value;
    memcpy (value.u8, hash.bytes, 32);
    return (BRGenericHash) { value };
}

static uint8_t *
genericRippleTransferGetSerialization (BRGenericTransferRef transfer, size_t *bytesCount)
{
    uint8_t * result = NULL;
    *bytesCount = 0;
    BRRippleTransaction transaction = rippleTransferGetTransaction ((BRRippleTransfer) transfer);
    if (transaction) {
        result = rippleTransactionSerialize(transaction, bytesCount);
    }
    return result;
}

// MARK: Generic Wallet

static BRGenericWalletRef
genericRippleWalletCreate (BRGenericAccountRef account) {
    return (BRGenericWalletRef) rippleWalletCreate ((BRRippleAccount) account);
}

static void
genericRippleWalletFree (BRGenericWalletRef wallet) {
    rippleWalletFree ((BRRippleWallet) wallet);
}

static UInt256
genericRippleWalletGetBalance (BRGenericWalletRef wallet) {
    return createUInt256 (rippleWalletGetBalance ((BRRippleWallet) wallet));
}

static UInt256
genericRippleWalletGetBalanceLimit (BRGenericWalletRef wallet,
                                    int asMaximum,
                                    int *hasLimit) {
    return createUInt256 (rippleWalletGetBalanceLimit ((BRRippleWallet) wallet, asMaximum, hasLimit));
}

static BRGenericAddressRef
genericRippleGetAddress (BRGenericWalletRef wallet, int asSource) {
    return (BRGenericAddressRef) (asSource
                                  ? rippleWalletGetSourceAddress ((BRRippleWallet) wallet)
                                  : rippleWalletGetTargetAddress ((BRRippleWallet) wallet));
}

static int
genericRippleWalletHasAddress (BRGenericWalletRef wallet,
                               BRGenericAddressRef address) {
    return rippleWalletHasAddress ((BRRippleWallet) wallet,
                                   (BRRippleAddress) address);
}

static int
genericRippleWalletHasTransfer (BRGenericWalletRef wallet,
                                BRGenericTransferRef transfer) {
    return rippleWalletHasTransfer ((BRRippleWallet) wallet, (BRRippleTransfer) transfer);
}

static void
genericRippleWalletAddTransfer (BRGenericWalletRef wallet,
                                OwnershipKept BRGenericTransferRef transfer) {
    rippleWalletAddTransfer ((BRRippleWallet) wallet, (BRRippleTransfer) transfer);
}

static BRGenericTransferRef
genericRippleWalletCreateTransfer (BRGenericWalletRef wallet,
                                   BRGenericAddressRef target,
                                   UInt256 amount,
                                   BRGenericFeeBasis estimatedFeeBasis,
                                   size_t attributeCount,
                                   BRGenericTransferAttribute *attributes) {
    BRRippleAddress source  = rippleWalletGetSourceAddress ((BRRippleWallet) wallet);
    BRRippleUnitDrops drops = amount.u64[0];

    BRRippleTransfer transfer = rippleTransferCreateNew (source,
                                                         (BRRippleAddress) target,
                                                         drops);

    BRRippleTransaction transaction = rippleTransferGetTransaction(transfer);

    for (size_t index = 0; index < attributeCount; index++) {
        BRGenericTransferAttribute *attribute = &attributes[index];
        if (0 == strcmp (attribute->key, "DestinationTag")) {
            BRCoreParseStatus tag;
            sscanf (attribute->value, "%u", &tag);
            rippleTransactionSetDestinationTag (transaction, tag);
        }
        else if (0 == strcmp (attribute->key, "InvoiceId")) {
            // TODO:
        }
        else {
            // TODO: Impossible if validated?
        }
    }

    rippleAddressFree(source);

    return (BRGenericTransferRef) transfer;
}

static BRGenericFeeBasis
genericRippleWalletEstimateFeeBasis (BRGenericWalletRef wallet,
                                     BRGenericAddressRef address,
                                     UInt256 amount,
                                     UInt256 pricePerCostFactor) {
    return (BRGenericFeeBasis) {
        pricePerCostFactor,
        1
    };
}

static const char **
genericRippleWalletGetTransactionAttributeKeys (BRGenericWalletRef wallet,
                                                int asRequired,
                                                size_t *count) {
    static size_t rippleTransactionFieldRequiredCount = 0;
    static const char **rippleTransactionFieldRequiredNames = NULL;

    static size_t rippleTransactionFieldOptionalCount = 2;
    static const char *rippleTransactionFieldOptionalNames[] = {
        "DestinationTag",
        "InvoiceId"
    };

    if (asRequired) { *count = rippleTransactionFieldRequiredCount; return rippleTransactionFieldRequiredNames; }
    else {            *count = rippleTransactionFieldOptionalCount; return rippleTransactionFieldOptionalNames; }
}

static int
genericRippleWalletValidateTransactionAttribute (BRGenericWalletRef wallet,
                                                 BRGenericTransferAttribute attribute) {
    if (0 == strcmp (attribute.key, "DestinationTag")) {
        uint32_t tag;
        return 1 == sscanf(attribute.value, "%u", &tag);
    }
    else if (0 == strcmp (attribute.key, "InvoiceId")) {
        BRCoreParseStatus status;
        createUInt256Parse(attribute.value, 10, &status);
        return CORE_PARSE_OK == status;
    }
    else return 0;
}

static int
genericRippleWalletValidateTransactionAttributes (BRGenericWalletRef wallet,
                                                  size_t attributesCount,
                                                  BRGenericTransferAttribute *attributes) {
    // Validate one-by-one
    for (size_t index = 0; index < attributesCount; index++)
        if (0 == genericRippleWalletValidateTransactionAttribute (wallet, attributes[index]))
            return 0;
    return 1;
}

// MARK: - Generic Manager

static BRGenericTransferRef
genericRippleWalletManagerRecoverTransfer (const char *hash,
                                           const char *from,
                                           const char *to,
                                           const char *amount,
                                           const char *currency,
                                           const char *fee,
                                           uint64_t timestamp,
                                           uint64_t blockHeight) {
    BRRippleUnitDrops amountDrops, feeDrops = 0;
    sscanf(amount, "%llu", &amountDrops);
    if (NULL != fee) sscanf(fee,    "%llu", &feeDrops);
    BRRippleAddress toAddress   = rippleAddressCreateFromString(to);
    BRRippleAddress fromAddress = rippleAddressCreateFromString(from);
    // Convert the hash string to bytes
    BRRippleTransactionHash txId;
    decodeHex(txId.bytes, sizeof(txId.bytes), hash, strlen(hash));

    BRRippleTransfer transfer = rippleTransferCreate(fromAddress, toAddress, amountDrops, feeDrops, txId, timestamp, blockHeight);

    rippleAddressFree (toAddress);
    rippleAddressFree (fromAddress);

    return (BRGenericTransferRef) transfer;
}

static BRArrayOf(BRGenericTransferRef)
genericRippleWalletManagerRecoverTransfersFromRawTransaction (uint8_t *bytes,
                                                            size_t   bytesCount) {
    return NULL;
}

static BRGenericAPISyncType
genericRippleWalletManagerGetAPISyncType (void) {
    return GENERIC_SYNC_TYPE_TRANSFER;
}

// MARK: - Generic Handlers

struct BRGenericHandersRecord genericRippleHandlersRecord = {
    GEN_NETWORK_TYPE_XRP,
    { // Network
    },

    {    // Account
        genericRippleAccountCreate,
        genericRippleAccountCreateWithPublicKey,
        genericRippleAccountCreateWithSerialization,
        genericRippleAccountFree,
        genericRippleAccountGetAddress,
        genericRippleAccountGetSerialization,
        genericRippleAccountSignTransferWithSeed,
        genericRippleAccountSignTransferWithKey,
    },

    {    // Address
        genericRippleAddressCreate,
        genericRippleAddressAsString,
        genericRippleAddressEqual,
        genericRippleAddressFree
    },

    {    // Transfer
        genericRippleTransferCreate,
        genericRippleTransferCopy,
        genericRippleTransferFree,
        genericRippleTransferGetSourceAddress,
        genericRippleTransferGetTargetAddress,
        genericRippleTransferGetAmount,
        genericRippleTransferGetFeeBasis,
        genericRippleTransferGetHash,
        genericRippleTransferGetSerialization,
    },

    {   // Wallet
        genericRippleWalletCreate,
        genericRippleWalletFree,
        genericRippleWalletGetBalance,
        /* set balance */
        genericRippleWalletGetBalanceLimit,
        genericRippleGetAddress,
        genericRippleWalletHasAddress,
        genericRippleWalletHasTransfer,
        genericRippleWalletAddTransfer,
        genericRippleWalletCreateTransfer,
        genericRippleWalletEstimateFeeBasis,

        genericRippleWalletGetTransactionAttributeKeys,
        genericRippleWalletValidateTransactionAttribute,
        genericRippleWalletValidateTransactionAttributes
    },

    { // Wallet Manager
        genericRippleWalletManagerRecoverTransfer,
        genericRippleWalletManagerRecoverTransfersFromRawTransaction,
        genericRippleWalletManagerGetAPISyncType,
    },
};

const BRGenericHandlers genericRippleHandlers = &genericRippleHandlersRecord;
