//
//  WKWalletXLM.c
//  WalletKitCore
//
//  Created by Ehsan Rezaie on 2020-05-19.
//  Copyright © 2019 Breadwinner AG. All rights reserved.
//
//  See the LICENSE file at the project root for license information.
//  See the CONTRIBUTORS file at the project root for a list of contributors.
//
#include "WKXLM.h"
#include "BRCryptoBase.h"
#include "crypto/BRCryptoWalletP.h"
#include "crypto/BRCryptoAmountP.h"
#include "stellar/BRStellar.h"
#include "support/BRSet.h"
#include "ethereum/util/BRUtilMath.h"

#include <stdio.h>
#include <errno.h>


static BRCryptoWalletXLM
cryptoWalletCoerce (BRCryptoWallet wallet) {
    assert (CRYPTO_NETWORK_TYPE_XLM == wallet->type);
    return (BRCryptoWalletXLM) wallet;
}

typedef struct {
    BRStellarAccount xlmAccount;
} BRCryptoWalletCreateContextXLM;

static void
cryptoWalletCreateCallbackXLM (BRCryptoWalletCreateContext context,
                               BRCryptoWallet wallet) {
    BRCryptoWalletCreateContextXLM *contextXLM = (BRCryptoWalletCreateContextXLM*) context;
    BRCryptoWalletXLM walletXLM = cryptoWalletCoerce (wallet);

    walletXLM->xlmAccount = contextXLM->xlmAccount;
}

private_extern BRCryptoWallet
cryptoWalletCreateAsXLM (BRCryptoWalletListener listener,
                         BRCryptoUnit unit,
                         BRCryptoUnit unitForFee,
                         BRStellarAccount xlmAccount) {
    int hasMinBalance;
    int hasMaxBalance;
    BRStellarAmount minBalanceXLM = stellarAccountGetBalanceLimit (xlmAccount, 0, &hasMinBalance);
    BRStellarAmount maxBalanceXLM = stellarAccountGetBalanceLimit (xlmAccount, 1, &hasMaxBalance);

    BRCryptoAmount minBalance = hasMinBalance ? cryptoAmountCreateAsXLM(unit, CRYPTO_FALSE, minBalanceXLM) : NULL;
    BRCryptoAmount maxBalance = hasMaxBalance ? cryptoAmountCreateAsXLM(unit, CRYPTO_FALSE, maxBalanceXLM) : NULL;

    BRStellarFeeBasis feeBasisXLM = stellarAccountGetDefaultFeeBasis (xlmAccount);
    BRCryptoFeeBasis feeBasis    = cryptoFeeBasisCreateAsXLM (unitForFee, feeBasisXLM.pricePerCostFactor);

    BRCryptoWalletCreateContextXLM contextXLM = {
        xlmAccount
    };

    BRCryptoWallet wallet = cryptoWalletAllocAndInit (sizeof (struct BRCryptoWalletXLMRecord),
                                                      CRYPTO_NETWORK_TYPE_XLM,
                                                      listener,
                                                      unit,
                                                      unitForFee,
                                                      minBalance,
                                                      maxBalance,
                                                      feeBasis,
                                                      &contextXLM,
                                                      cryptoWalletCreateCallbackXLM);

    cryptoFeeBasisGive(feeBasis);
    cryptoAmountGive (maxBalance);
    cryptoAmountGive (minBalance);

    return wallet;
}

static void
cryptoWalletReleaseXLM (BRCryptoWallet wallet) {
    BRCryptoWalletXLM walletXLM = cryptoWalletCoerce (wallet);
    stellarAccountFree(walletXLM->xlmAccount);
}

static BRCryptoAddress
cryptoWalletGetAddressXLM (BRCryptoWallet wallet,
                           BRCryptoAddressScheme addressScheme) {
    assert (CRYPTO_ADDRESS_SCHEME_NATIVE == addressScheme);
    BRCryptoWalletXLM walletXLM = cryptoWalletCoerce (wallet);
    return cryptoAddressCreateAsXLM (stellarAccountGetAddress(walletXLM->xlmAccount));
}

static bool
cryptoWalletHasAddressXLM (BRCryptoWallet wallet,
                           BRCryptoAddress address) {
    BRCryptoWalletXLM walletXLM = cryptoWalletCoerce (wallet);
    BRStellarAddress xlmAddress = cryptoAddressAsXLM (address);
    
    return stellarAccountHasAddress (walletXLM->xlmAccount, xlmAddress);
}

extern size_t
cryptoWalletGetTransferAttributeCountXLM (BRCryptoWallet wallet,
                                          BRCryptoAddress target) {
    BRStellarAddress xlmTarget = (NULL == target) ? NULL : cryptoAddressAsXLM (target);
    
    size_t countRequired, countOptional;
    stellarAddressGetTransactionAttributeKeys (xlmTarget, 1, &countRequired);
    stellarAddressGetTransactionAttributeKeys (xlmTarget, 0, &countOptional);
    return countRequired + countOptional;
}

extern BRCryptoTransferAttribute
cryptoWalletGetTransferAttributeAtXLM (BRCryptoWallet wallet,
                                       BRCryptoAddress target,
                                       size_t index) {
    BRStellarAddress xlmTarget = (NULL == target) ? NULL : cryptoAddressAsXLM (target);
    
    size_t countRequired, countOptional;
    const char **keysRequired = stellarAddressGetTransactionAttributeKeys (xlmTarget, 1, &countRequired);
    const char **keysOptional = stellarAddressGetTransactionAttributeKeys (xlmTarget, 0, &countOptional);

    assert (index < (countRequired + countOptional));

    BRCryptoBoolean isRequired = AS_CRYPTO_BOOLEAN (index < countRequired);
    const char **keys      = (isRequired ? keysRequired : keysOptional);
    size_t       keysIndex = (isRequired ? index : (index - countRequired));

    return cryptoTransferAttributeCreate(keys[keysIndex], NULL, isRequired);
}

extern BRCryptoTransferAttributeValidationError
cryptoWalletValidateTransferAttributeXLM (BRCryptoWallet wallet,
                                          OwnershipKept BRCryptoTransferAttribute attribute,
                                          BRCryptoBoolean *validates) {
    const char *key = cryptoTransferAttributeGetKey (attribute);
    const char *val = cryptoTransferAttributeGetValue (attribute);
    BRCryptoTransferAttributeValidationError error = 0;

    // If attribute.value is NULL, we validate unless the attribute.value is required.
    if (NULL == val) {
        if (cryptoTransferAttributeIsRequired(attribute)) {
            error = CRYPTO_TRANSFER_ATTRIBUTE_VALIDATION_ERROR_REQUIRED_BUT_NOT_PROVIDED;
            *validates = CRYPTO_FALSE;
        } else {
            *validates = CRYPTO_TRUE;
        }
        return error;
    }

    if (stellarCompareFieldOption (key, FIELD_OPTION_DESTINATION_TAG)) {
        char *end = NULL;
        errno = 0;

        uintmax_t tag = strtoumax (val, &end, 10);
        if (ERANGE != errno && EINVAL != errno && '\0' == end[0] && tag <= UINT32_MAX) {
            *validates = CRYPTO_TRUE;
        } else {
            *validates = CRYPTO_FALSE;
            error = CRYPTO_TRANSFER_ATTRIBUTE_VALIDATION_ERROR_MISMATCHED_TYPE;
        }
    }
    else if (stellarCompareFieldOption (key, FIELD_OPTION_INVOICE_ID)) {
        BRCoreParseStatus status;
        uint256CreateParse(val, 10, &status);
        if (status) {
            *validates = CRYPTO_TRUE;
        } else {
                *validates = CRYPTO_FALSE;
                error = CRYPTO_TRANSFER_ATTRIBUTE_VALIDATION_ERROR_MISMATCHED_TYPE;
            }
    }
    else {
        error = CRYPTO_TRANSFER_ATTRIBUTE_VALIDATION_ERROR_RELATIONSHIP_INCONSISTENCY;
        *validates = CRYPTO_FALSE;
    }
    
    return error;
}

extern BRCryptoTransfer
cryptoWalletCreateTransferXLM (BRCryptoWallet  wallet,
                               BRCryptoAddress target,
                               BRCryptoAmount  amount,
                               BRCryptoFeeBasis estimatedFeeBasis,
                               size_t attributesCount,
                               OwnershipKept BRCryptoTransferAttribute *attributes,
                               BRCryptoCurrency currency,
                               BRCryptoUnit unit,
                               BRCryptoUnit unitForFee) {
    BRCryptoWalletXLM walletXLM = cryptoWalletCoerce (wallet);

    UInt256 value = cryptoAmountGetValue (amount);
    
    BRStellarAddress source  = stellarAccountGetAddress(walletXLM->xlmAccount);
    BRStellarAmount amountXLM = (double)value.u64[0];

    // TODO - Carl - I think this is when we create a new transaction to submit
    BRStellarTransaction xlmTransaction = stellarTransactionCreate (source,
                                                                  cryptoAddressAsXLM(target),
                                                                  amountXLM,
                                                                  cryptoFeeBasisAsXLM(estimatedFeeBasis));

    if (NULL == xlmTransaction)
        return NULL;

    // TODO - attributes?
    for (size_t index = 0; index < attributesCount; index++) {
        BRCryptoTransferAttribute attribute = attributes[index];
        if (NULL != cryptoTransferAttributeGetValue(attribute)) {
            /*
            if (stellarCompareFieldOption (cryptoTransferAttributeGetKey(attribute), FIELD_OPTION_DESTINATION_TAG)) {
                BRCoreParseStatus tag;
                sscanf (cryptoTransferAttributeGetValue(attribute), "%u", &tag);
                stellarTransactionSetDestinationTag (xlmTransaction, tag);
            }
            else if (stellarCompareFieldOption (cryptoTransferAttributeGetKey(attribute), FIELD_OPTION_INVOICE_ID)) {
                // TODO: Handle INVOICE_ID (note: not used in BRD App)
            }
            else {
                // TODO: Impossible if validated?
            }
             */
        }
    }

    stellarAddressFree(source);

    BRCryptoTransferState state    = cryptoTransferStateInit(CRYPTO_TRANSFER_STATE_CREATED);
    BRCryptoTransfer      transfer = cryptoTransferCreateAsXLM (wallet->listenerTransfer,
                                                                unit,
                                                                unitForFee,
                                                                state,
                                                                walletXLM->xlmAccount,
                                                                xlmTransaction);


    cryptoTransferSetAttributes (transfer, attributesCount, attributes);
    cryptoTransferStateGive(state);

    return transfer;
}

extern BRCryptoTransfer
cryptoWalletCreateTransferMultipleXLM (BRCryptoWallet wallet,
                                       size_t outputsCount,
                                       BRCryptoTransferOutput *outputs,
                                       BRCryptoFeeBasis estimatedFeeBasis,
                                       BRCryptoCurrency currency,
                                       BRCryptoUnit unit,
                                       BRCryptoUnit unitForFee) {
    // not supported
    return NULL;
}

static OwnershipGiven BRSetOf(BRCryptoAddress)
cryptoWalletGetAddressesForRecoveryXLM (BRCryptoWallet wallet) {
    BRSetOf(BRCryptoAddress) addresses = cryptoAddressSetCreate (1);

    BRCryptoWalletXLM walletXLM = cryptoWalletCoerce(wallet);

    BRSetAdd (addresses, cryptoAddressCreateAsXLM (stellarAccountGetAddress (walletXLM->xlmAccount)));

    return addresses;
}

static void
cryptoWalletAnnounceTransferXLM (BRCryptoWallet wallet,
                                 BRCryptoTransfer transfer,
                                 BRCryptoWalletEventType type) {
    BRCryptoWalletXLM walletXLM = cryptoWalletCoerce (wallet);

    // Now update the account's sequence id
    BRStellarSequence sequence = 0;

    // The address for comparison with `transfer` source and target addresses.
    BRStellarAddress accountAddress = stellarAccountGetAddress (walletXLM->xlmAccount);

    // We need to keep track of the first block number where this account shows up to do this:
    // initial_sequence = blockNumber << 32;
    int64_t minBlockHeight = INT64_MAX;
    for (size_t index = 0; index < array_count(wallet->transfers); index++) {
        BRStellarTransaction xlmTransfer = cryptoTransferAsXLM (wallet->transfers[index]);

        // If we are the source of the transfer then we might want to update our sequence number
        if (stellarTransactionHasSource (xlmTransfer, accountAddress)) {
            // Update the sequence number if in a block OR successful
            if (stellarTransactionIsInBlock(xlmTransfer) || !stellarTransactionHasError(xlmTransfer))
                sequence += 1;
        } else if (!stellarTransactionHasError(xlmTransfer) && stellarTransactionHasTarget (xlmTransfer, accountAddress)) {
            // We are the target of the transfer - so we need to find the very first (successful) transfer where
            // our account received some XRP as this can affect our beginning sequence number. Ignore failed
            // transfers as Bockset could create a failed transfer for us before our account is created
            uint64_t blockHeight = stellarTransactionGetBlockHeight(xlmTransfer);
            minBlockHeight = blockHeight < minBlockHeight ? blockHeight : minBlockHeight;
        }
    }

    stellarAddressFree (accountAddress);
    stellarAccountSetBlockNumberAtCreation(walletXLM->xlmAccount, minBlockHeight);
    stellarAccountSetSequence (walletXLM->xlmAccount, sequence);
}

static bool
cryptoWalletIsEqualXLM (BRCryptoWallet wb1, BRCryptoWallet wb2) {
    if (wb1 == wb2) return true;

    BRCryptoWalletXLM w1 = cryptoWalletCoerce(wb1);
    BRCryptoWalletXLM w2 = cryptoWalletCoerce(wb2);
    return w1->xlmAccount == w2->xlmAccount;
}

BRCryptoWalletHandlers cryptoWalletHandlersXLM = {
    cryptoWalletReleaseXLM,
    cryptoWalletGetAddressXLM,
    cryptoWalletHasAddressXLM,
    cryptoWalletGetTransferAttributeCountXLM,
    cryptoWalletGetTransferAttributeAtXLM,
    cryptoWalletValidateTransferAttributeXLM,
    cryptoWalletCreateTransferXLM,
    cryptoWalletCreateTransferMultipleXLM,
    cryptoWalletGetAddressesForRecoveryXLM,
    cryptoWalletAnnounceTransferXLM,
    cryptoWalletIsEqualXLM
};


#if defined (NEVER_DEFINED)  // Keep as an example
static void stellarWalletUpdateSequence (BRStellarWallet wallet,
                                        OwnershipKept BRStellarAddress accountAddress) {
    // Now update the account's sequence id
    BRStellarSequence sequence = 0;
    // We need to keep track of the first block where this account shows up due to a
    // change in how stellar assigns the sequence number to new accounts
    uint64_t minBlockHeight = UINT64_MAX;
    for (size_t index = 0; index < array_count(wallet->transfers); index++) {
        BRStellarTransfer transfer = wallet->transfers[index];
        BRStellarAddress targetAddress = stellarTransferGetTarget(transfer);
        if (stellarTransferHasError(transfer) == 0
            && stellarAddressEqual(accountAddress, targetAddress)) {
            // We trying to find the lowest block number where we were sent
            // currency successful - basically this is the block where our account
            // was created *** ignore failed transfers TO us since we end up seeing
            // items before our account is actually created.
            uint64_t blockHeight = stellarTransferGetBlockHeight(transfer);
            minBlockHeight = blockHeight < minBlockHeight ? blockHeight : minBlockHeight;
        }
        stellarAddressFree(targetAddress);
        if (stellarTransferHasSource (wallet->transfers[index], accountAddress))
            sequence += 1;
    }

    stellarAccountSetBlockNumberAtCreation(wallet->account, minBlockHeight);
    stellarAccountSetSequence (wallet->account, sequence);
}

extern void stellarWalletAddTransfer (BRStellarWallet wallet,
                                     OwnershipKept BRStellarTransfer transfer)
{
    assert(wallet);
    assert(transfer);
    pthread_mutex_lock (&wallet->lock);
    if (!walletHasTransfer(wallet, transfer)) {
        // We'll add `transfer` to `wallet->transfers`; since we don't own `transfer` we must copy.
        transfer = stellarTransferClone(transfer);
        array_add(wallet->transfers, transfer);

        // Update the balance
        BRStellarUnitDrops amount = (stellarTransferHasError(transfer)
                                    ? 0
                                    : stellarTransferGetAmount(transfer));
        BRStellarUnitDrops fee    = stellarTransferGetFee(transfer);

        BRStellarAddress accountAddress = stellarAccountGetAddress(wallet->account);
        BRStellarAddress source = stellarTransferGetSource(transfer);
        BRStellarAddress target = stellarTransferGetTarget(transfer);

        int isSource = stellarAccountHasAddress (wallet->account, source);
        int isTarget = stellarAccountHasAddress (wallet->account, target);

        if (isSource && isTarget)
            wallet->balance -= fee;
        else if (isSource)
            wallet->balance -= (amount + fee);
        else if (isTarget)
            wallet->balance += amount;
        else {
            // something is seriously wrong
        }
        stellarAddressFree (source);
        stellarAddressFree (target);

        stellarWalletUpdateSequence(wallet, accountAddress);
        stellarAddressFree (accountAddress);
    }
    pthread_mutex_unlock (&wallet->lock);
    // Now update the balance
}

extern void stellarWalletRemTransfer (BRStellarWallet wallet,
                                     OwnershipKept BRStellarTransfer transfer)
{
    assert(wallet);
    assert(transfer);
    pthread_mutex_lock (&wallet->lock);
    if (walletHasTransfer(wallet, transfer)) {
        for (size_t index = 0; index < array_count(wallet->transfers); index++)
            if (stellarTransferEqual (transfer, wallet->transfers[index])) {
                stellarTransferFree(wallet->transfers[index]);
                array_rm (wallet->transfers, index);
                break;
            }

        // Update the balance
        BRStellarUnitDrops amount = (stellarTransferHasError(transfer)
                                    ? 0
                                    : stellarTransferGetAmount(transfer));

        BRStellarUnitDrops fee    = stellarTransferGetFee(transfer);

        BRStellarAddress accountAddress = stellarAccountGetAddress(wallet->account);
        BRStellarAddress source = stellarTransferGetSource(transfer);
        BRStellarAddress target = stellarTransferGetTarget(transfer);

        int isSource = stellarAccountHasAddress (wallet->account, source);
        int isTarget = stellarAccountHasAddress (wallet->account, target);

        if (isSource && isTarget)
            wallet->balance += fee;
        else if (isSource)
            wallet->balance += (amount + fee);
        else if (isTarget)
            wallet->balance -= amount;
        else {
            // something is seriously wrong
        }
        stellarAddressFree (source);
        stellarAddressFree (target);

        stellarWalletUpdateSequence(wallet, accountAddress);
        stellarAddressFree (accountAddress);
    }
    pthread_mutex_unlock (&wallet->lock);
    // Now update the balance
}
#endif
