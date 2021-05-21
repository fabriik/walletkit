//
//  WKTransferXLM.c
//  WalletKitCore
//
//  Created by Carl Cherry on 2021-05-21.
//  Copyright © 2021 Breadwinner AG. All rights reserved.
//
//  See the LICENSE file at the project root for license information.
//  See the CONTRIBUTORS file at the project root for a list of contributors.
//
#include "WKXLM.h"
#include "crypto/BRCryptoAmountP.h"
#include "crypto/BRCryptoHashP.h"
#include "stellar/BRStellarTransaction.h"
#include "ethereum/util/BRUtilMath.h"

static BRCryptoTransferDirection
transferGetDirectionFromXLM (BRStellarTransaction transaction,
                             BRStellarAccount account);

extern BRCryptoTransferXLM
cryptoTransferCoerceXLM (BRCryptoTransfer transfer) {
    assert (CRYPTO_NETWORK_TYPE_XLM == transfer->type);
    return (BRCryptoTransferXLM) transfer;
}

typedef struct {
    BRStellarTransaction xlmTransaction;
} BRCryptoTransferCreateContextXLM;

extern BRStellarTransaction
cryptoTransferAsXLM (BRCryptoTransfer transfer) {
    BRCryptoTransferXLM transferXLM = cryptoTransferCoerceXLM (transfer);
    return transferXLM->xlmTransaction;
}

static void
cryptoTransferCreateCallbackXLM (BRCryptoTransferCreateContext context,
                                    BRCryptoTransfer transfer) {
    BRCryptoTransferCreateContextXLM *contextXLM = (BRCryptoTransferCreateContextXLM*) context;
    BRCryptoTransferXLM transferXLM = cryptoTransferCoerceXLM (transfer);

    transferXLM->xlmTransaction = contextXLM->xlmTransaction;
}

extern BRCryptoTransfer
cryptoTransferCreateAsXLM (BRCryptoTransferListener listener,
                           BRCryptoUnit unit,
                           BRCryptoUnit unitForFee,
                           BRCryptoTransferState state,
                           OwnershipKept BRStellarAccount xlmAccount,
                           OwnershipGiven BRStellarTransaction xlmTransfer) {
    
    BRCryptoTransferDirection direction = transferGetDirectionFromXLM (xlmTransfer, xlmAccount);
    
    BRCryptoAmount amount = cryptoAmountCreateAsXLM (unit,
                                                     CRYPTO_FALSE,
                                                     stellarTransactionGetAmount(xlmTransfer));

    BRCryptoFeeBasis feeBasisEstimated = cryptoFeeBasisCreateAsXLM (unitForFee, (CRYPTO_TRANSFER_RECEIVED == direction ? 0 : stellarTransactionGetFee(xlmTransfer)));
    
    BRCryptoAddress sourceAddress = cryptoAddressCreateAsXLM (stellarTransactionGetSource(xlmTransfer));
    BRCryptoAddress targetAddress = cryptoAddressCreateAsXLM (stellarTransactionGetTarget(xlmTransfer));

    BRCryptoTransferCreateContextXLM contextXLM = {
        xlmTransfer
    };

    BRCryptoTransfer transfer = cryptoTransferAllocAndInit (sizeof (struct BRCryptoTransferXLMRecord),
                                                            CRYPTO_NETWORK_TYPE_XLM,
                                                            listener,
                                                            unit,
                                                            unitForFee,
                                                            feeBasisEstimated,
                                                            amount,
                                                            direction,
                                                            sourceAddress,
                                                            targetAddress,
                                                            state,
                                                            &contextXLM,
                                                            cryptoTransferCreateCallbackXLM);

    cryptoFeeBasisGive (feeBasisEstimated);
    cryptoAddressGive (sourceAddress);
    cryptoAddressGive (targetAddress);

    return transfer;
}

static void
cryptoTransferReleaseXLM (BRCryptoTransfer transfer) {
    BRCryptoTransferXLM transferXLM = cryptoTransferCoerceXLM(transfer);
    stellarTransactionFree (transferXLM->xlmTransaction);
}

static BRCryptoHash
cryptoTransferGetHashXLM (BRCryptoTransfer transfer) {
    BRCryptoTransferXLM transferXLM = cryptoTransferCoerceXLM(transfer);
    BRStellarTransactionHash hash = stellarTransactionGetHash(transferXLM->xlmTransaction);
    return cryptoHashCreateAsXLM (hash);
}

static uint8_t *
cryptoTransferSerializeXLM (BRCryptoTransfer transfer,
                            BRCryptoNetwork network,
                            BRCryptoBoolean  requireSignature,
                            size_t *serializationCount) {
    assert (CRYPTO_TRUE == requireSignature);
    BRCryptoTransferXLM transferXLM = cryptoTransferCoerceXLM (transfer);

    uint8_t *serialization = NULL;
    *serializationCount = 0;
    BRStellarTransaction transaction = transferXLM->xlmTransaction;
    if (transaction) {
        serialization = stellarTransactionSerialize (transaction, serializationCount);
    }
    
    return serialization;
}

static int
cryptoTransferIsEqualXLM (BRCryptoTransfer tb1, BRCryptoTransfer tb2) {
    if (tb1 == tb2) return 1;

    BRCryptoHash h1 = cryptoTransferGetHashXLM (tb1);
    BRCryptoHash h2 = cryptoTransferGetHashXLM (tb2);

    int result = (CRYPTO_TRUE == cryptoHashEqual (h1, h2));

    cryptoHashGive (h2);
    cryptoHashGive (h1);

    return result;
}

static BRCryptoTransferDirection
transferGetDirectionFromXLM (BRStellarTransaction transaction,
                             BRStellarAccount account) {
    BRStellarAddress address = stellarAccountGetAddress(account);

    int isSource = stellarTransactionHasSource(transaction, address);
    int isTarget = stellarTransactionHasTarget(transaction, address);

    stellarAddressFree(address);

    return (isSource && isTarget
            ? CRYPTO_TRANSFER_RECOVERED
            : (isSource
               ? CRYPTO_TRANSFER_SENT
               : CRYPTO_TRANSFER_RECEIVED));
}

BRCryptoTransferHandlers cryptoTransferHandlersXLM = {
    cryptoTransferReleaseXLM,
    cryptoTransferGetHashXLM,
    NULL, // setHash
    NULL,
    cryptoTransferSerializeXLM,
    NULL, // getBytesForFeeEstimate
    cryptoTransferIsEqualXLM
};
