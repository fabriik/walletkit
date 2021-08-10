//
//  WKWalletManagerXLM.c
//  WalletKitCore
//
//  Created by Carl Cherry on 2021-05-19.
//  Copyright © 2021 Breadwinner AG. All rights reserved.
//
//  See the LICENSE file at the project root for license information.
//  See the CONTRIBUTORS file at the project root for a list of contributors.
//
#include "WKXLM.h"

#include "crypto/BRCryptoAccountP.h"
#include "crypto/BRCryptoNetworkP.h"
#include "crypto/BRCryptoKeyP.h"
#include "crypto/BRCryptoClientP.h"
#include "crypto/BRCryptoWalletP.h"
#include "crypto/BRCryptoAmountP.h"
#include "crypto/BRCryptoWalletManagerP.h"
#include "crypto/BRCryptoFileService.h"

#include "stellar/BRStellarAccount.h"


// MARK: - Events

static const BREventType *xlmEventTypes[] = {
    CRYPTO_CLIENT_EVENT_TYPES
};

static const unsigned int
xlmEventTypesCount = (sizeof (xlmEventTypes) / sizeof (BREventType*));

// MARK: - Handlers

static BRCryptoWalletManager
cryptoWalletManagerCreateXLM (BRCryptoWalletManagerListener listener,
                               BRCryptoClient client,
                               BRCryptoAccount account,
                               BRCryptoNetwork network,
                               BRCryptoSyncMode mode,
                               BRCryptoAddressScheme scheme,
                               const char *path) {
    return cryptoWalletManagerAllocAndInit (sizeof (struct BRCryptoWalletManagerXLMRecord),
                                            cryptoNetworkGetType(network),
                                            listener,
                                            client,
                                            account,
                                            network,
                                            scheme,
                                            path,
                                            CRYPTO_CLIENT_REQUEST_USE_TRANSFERS,
                                            NULL,
                                            NULL);
}

static void
cryptoWalletManagerReleaseXLM (BRCryptoWalletManager manager) {
    
}

static BRFileService
crytpWalletManagerCreateFileServiceXLM (BRCryptoWalletManager manager,
                                         const char *basePath,
                                         const char *currency,
                                         const char *network,
                                         BRFileServiceContext context,
                                         BRFileServiceErrorHandler handler) {
    return fileServiceCreateFromTypeSpecifications (basePath, currency, network,
                                                    context, handler,
                                                    cryptoFileServiceSpecificationsCount,
                                                    cryptoFileServiceSpecifications);
}

static const BREventType **
cryptoWalletManagerGetEventTypesXLM (BRCryptoWalletManager manager,
                                      size_t *eventTypesCount) {
    assert (NULL != eventTypesCount);
    *eventTypesCount = xlmEventTypesCount;
    return xlmEventTypes;
}

static BRCryptoClientP2PManager
crytpWalletManagerCreateP2PManagerXLM (BRCryptoWalletManager manager) {
    // not supported
    return NULL;
}

static BRCryptoBoolean
cryptoWalletManagerSignTransactionWithSeedXLM (BRCryptoWalletManager manager,
                                                BRCryptoWallet wallet,
                                                BRCryptoTransfer transfer,
                                                UInt512 seed) {
    BRStellarAccount account = cryptoAccountAsXLM (manager->account);
    BRKey publicKey = stellarAccountGetPublicKey (account);
    BRStellarTransaction transaction = cryptoTransferCoerceXLM(transfer)->xlmTransaction;

    // TODO - carl
    size_t tx_size = 0; //stellarTransactionSignTransaction (transaction, publicKey, seed, nodeAddress);

    return AS_CRYPTO_BOOLEAN(tx_size > 0);
}

static BRCryptoBoolean
cryptoWalletManagerSignTransactionWithKeyXLM (BRCryptoWalletManager manager,
                                               BRCryptoWallet wallet,
                                               BRCryptoTransfer transfer,
                                               BRCryptoKey key) {
    assert(0);
    return CRYPTO_FALSE;
}

//TODO:XLM make common?
static BRCryptoAmount
cryptoWalletManagerEstimateLimitXLM (BRCryptoWalletManager manager,
                                      BRCryptoWallet  wallet,
                                      BRCryptoBoolean asMaximum,
                                      BRCryptoAddress target,
                                      BRCryptoNetworkFee networkFee,
                                      BRCryptoBoolean *needEstimate,
                                      BRCryptoBoolean *isZeroIfInsuffientFunds,
                                      BRCryptoUnit unit) {
    UInt256 amount = UINT256_ZERO;
    
    *needEstimate = CRYPTO_FALSE;
    *isZeroIfInsuffientFunds = CRYPTO_FALSE;
    
    if (CRYPTO_TRUE == asMaximum) {
        BRCryptoAmount minBalance = wallet->balanceMinimum;
        assert(minBalance);
        
        // Available balance based on minimum wallet balance
        BRCryptoAmount balance = cryptoAmountSub(wallet->balance, minBalance);
        
        // Stellar has fixed network fee (costFactor = 1.0)
        BRCryptoAmount fee = cryptoNetworkFeeGetPricePerCostFactor (networkFee);
        BRCryptoAmount newBalance = cryptoAmountSub(balance, fee);
        
        if (CRYPTO_TRUE == cryptoAmountIsNegative(newBalance)) {
            amount = UINT256_ZERO;
        } else {
            amount = cryptoAmountGetValue(newBalance);
        }
        
        cryptoAmountGive (balance);
        cryptoAmountGive (fee);
        cryptoAmountGive (newBalance);
    }
    
    return cryptoAmountCreate (unit, CRYPTO_FALSE, amount);
}

static BRCryptoFeeBasis
cryptoWalletManagerEstimateFeeBasisXLM (BRCryptoWalletManager manager,
                                         BRCryptoWallet  wallet,
                                         BRCryptoCookie cookie,
                                         BRCryptoAddress target,
                                         BRCryptoAmount amount,
                                         BRCryptoNetworkFee networkFee,
                                         size_t attributesCount,
                                         OwnershipKept BRCryptoTransferAttribute *attributes) {
    UInt256 value = cryptoAmountGetValue (cryptoNetworkFeeGetPricePerCostFactor (networkFee));
    BRStellarFeeBasis xlmFeeBasis;

    // No margin needed.
    xlmFeeBasis.pricePerCostFactor = (BRStellarFee) value.u32[0];
    xlmFeeBasis.costFactor = 1;  // 'cost factor' is 'transaction'

    // TODO - Carl
    return NULL; //cryptoFeeBasisCreateAsXLM (wallet->unitForFee, xlmFeeBasis);
}

static void
cryptoWalletManagerRecoverTransfersFromTransactionBundleXLM (BRCryptoWalletManager manager,
                                                              OwnershipKept BRCryptoClientTransactionBundle bundle) {
    // Not Stellar functionality
    assert (0);
}

static void
cryptoWalletManagerRecoverTransferFromTransferBundleXLM (BRCryptoWalletManager manager,
                                                          OwnershipKept BRCryptoClientTransferBundle bundle) {
    // create BRStellarTransaction
    
    BRStellarAccount xlmAccount = cryptoAccountAsXLM (manager->account);
    
    BRStellarAmount amount = 0;
    sscanf(bundle->amount, "%" PRIu64, &amount);
    BRStellarFee fee = 0;
    if (NULL != bundle->fee) sscanf(bundle->fee, "%" PRIi32, &fee);
    BRStellarFeeBasis stellarFeeBasis = { fee, 1};
    BRStellarAddress toAddress   = stellarAddressCreateFromString(bundle->to,   false);
    BRStellarAddress fromAddress = stellarAddressCreateFromString(bundle->from, false);
    // Convert the hash string to bytes
    BRStellarTransactionHash txHash;
    memset(txHash.bytes, 0x00, sizeof(txHash.bytes));
    if (bundle->hash != NULL) {
        hexDecode(txHash.bytes, sizeof(txHash.bytes), bundle->hash, strlen(bundle->hash));
    }

    int error = (CRYPTO_TRANSFER_STATE_ERRORED == bundle->status);

    bool xlmTransactionNeedFree = true;
    BRStellarTransaction xlmTransaction = stellarTransactionCreateFull(fromAddress,
                                                                  toAddress,
                                                                  amount,
                                                                  stellarFeeBasis,
                                                                  txHash,
                                                                  bundle->blockTimestamp,
                                                                  bundle->blockNumber,
                                                                  error);

    stellarAddressFree (toAddress);
    stellarAddressFree (fromAddress);

    // create BRCryptoTransfer
    
    BRCryptoWallet wallet = cryptoWalletManagerGetWallet (manager);
    BRCryptoHash hash = cryptoHashCreateAsXLM (txHash);

    BRCryptoTransfer baseTransfer = cryptoWalletGetTransferByHash (wallet, hash);
    cryptoHashGive(hash);

    BRCryptoFeeBasis      feeBasis = cryptoFeeBasisCreateAsXLM (wallet->unit, stellarTransactionGetFee(xlmTransaction));
    BRCryptoTransferState state    = cryptoClientTransferBundleGetTransferState (bundle, feeBasis);

    if (NULL == baseTransfer) {
        baseTransfer = cryptoTransferCreateAsXLM (wallet->listenerTransfer,
                                                   wallet->unit,
                                                   wallet->unitForFee,
                                                   state,
                                                   xlmAccount,
                                                   xlmTransaction);
        xlmTransactionNeedFree = false;

        cryptoWalletAddTransfer (wallet, baseTransfer);
    }
    else {
        cryptoTransferSetState (baseTransfer, state);
    }
    
    cryptoWalletManagerRecoverTransferAttributesFromTransferBundle (wallet, baseTransfer, bundle);
    
    cryptoTransferGive(baseTransfer);
    cryptoFeeBasisGive (feeBasis);
    cryptoTransferStateGive (state);

    if (xlmTransactionNeedFree)
        stellarTransactionFree (xlmTransaction);
}

extern BRCryptoWalletSweeperStatus
cryptoWalletManagerWalletSweeperValidateSupportedXLM (BRCryptoWalletManager manager,
                                                       BRCryptoWallet wallet,
                                                       BRCryptoKey key) {
    return CRYPTO_WALLET_SWEEPER_UNSUPPORTED_CURRENCY;
}

extern BRCryptoWalletSweeper
cryptoWalletManagerCreateWalletSweeperXLM (BRCryptoWalletManager manager,
                                            BRCryptoWallet wallet,
                                            BRCryptoKey key) {
    // not supported
    return NULL;
}

static BRCryptoWallet
cryptoWalletManagerCreateWalletXLM (BRCryptoWalletManager manager,
                                     BRCryptoCurrency currency,
                                     Nullable OwnershipKept BRArrayOf(BRCryptoClientTransactionBundle) transactions,
                                     Nullable OwnershipKept BRArrayOf(BRCryptoClientTransferBundle) transfers) {
    BRStellarAccount xlmAccount = cryptoAccountAsXLM(manager->account);

    // Create the primary BRCryptoWallet
    BRCryptoNetwork  network       = manager->network;
    BRCryptoUnit     unitAsBase    = cryptoNetworkGetUnitAsBase    (network, currency);
    BRCryptoUnit     unitAsDefault = cryptoNetworkGetUnitAsDefault (network, currency);

    BRCryptoWallet wallet = cryptoWalletCreateAsXLM (manager->listenerWallet,
                                                      unitAsDefault,
                                                      unitAsDefault,
                                                      xlmAccount);
    cryptoWalletManagerAddWallet (manager, wallet);

    //TODO:XLM load transfers from fileService

    cryptoUnitGive (unitAsDefault);
    cryptoUnitGive (unitAsBase);

    return wallet;
}

BRCryptoWalletManagerHandlers cryptoWalletManagerHandlersXLM = {
    cryptoWalletManagerCreateXLM,
    cryptoWalletManagerReleaseXLM,
    crytpWalletManagerCreateFileServiceXLM,
    cryptoWalletManagerGetEventTypesXLM,
    crytpWalletManagerCreateP2PManagerXLM,
    cryptoWalletManagerCreateWalletXLM,
    cryptoWalletManagerSignTransactionWithSeedXLM,
    cryptoWalletManagerSignTransactionWithKeyXLM,
    cryptoWalletManagerEstimateLimitXLM,
    cryptoWalletManagerEstimateFeeBasisXLM,
    NULL, // BRCryptoWalletManagerSaveTransactionBundleHandler
    NULL, // BRCryptoWalletManagerSaveTransactionBundleHandler
    cryptoWalletManagerRecoverTransfersFromTransactionBundleXLM,
    cryptoWalletManagerRecoverTransferFromTransferBundleXLM,
    NULL,//BRCryptoWalletManagerRecoverFeeBasisFromFeeEstimateHandler not supported
    cryptoWalletManagerWalletSweeperValidateSupportedXLM,
    cryptoWalletManagerCreateWalletSweeperXLM
};
