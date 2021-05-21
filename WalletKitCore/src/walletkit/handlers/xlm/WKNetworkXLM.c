//
//  WKNetworkXLM.c
//  WalletKitCore
//
//  Created by Carl Cherry on 2020-05-19.
//  Copyright © 2021 Breadwinner AG. All rights reserved.
//
//  See the LICENSE file at the project root for license information.
//  See the CONTRIBUTORS file at the project root for a list of contributors.
//
#include "WKXLM.h"
#include "crypto/BRCryptoAccountP.h"
#include "crypto/BRCryptoHashP.h"

static BRCryptoNetworkXLM
cryptoNetworkCoerce (BRCryptoNetwork network) {
    assert (CRYPTO_NETWORK_TYPE_XLM == network->type);
    return (BRCryptoNetworkXLM) network;
}

static BRCryptoNetwork
cryptoNetworkCreateXLM (BRCryptoNetworkListener listener,
                       const char *uids,
                       const char *name,
                       const char *desc,
                       bool isMainnet,
                       uint32_t confirmationPeriodInSeconds,
                       BRCryptoAddressScheme defaultAddressScheme,
                       BRCryptoSyncMode defaultSyncMode,
                       BRCryptoCurrency nativeCurrency) {
    assert (0 == strcmp (desc, (isMainnet ? "mainnet" : "testnet")));

    return cryptoNetworkAllocAndInit (sizeof (struct BRCryptoNetworkRecord),
                                      CRYPTO_NETWORK_TYPE_XLM,
                                      listener,
                                      uids,
                                      name,
                                      desc,
                                      isMainnet,
                                      confirmationPeriodInSeconds,
                                      defaultAddressScheme,
                                      defaultSyncMode,
                                      nativeCurrency,
                                      NULL,
                                      NULL);
}

static void
cryptoNetworkReleaseXLM (BRCryptoNetwork network) {
    BRCryptoNetworkXLM networkXLM = cryptoNetworkCoerce (network);
    (void) networkXLM;
}

static BRCryptoAddress
cryptoNetworkCreateAddressXLM (BRCryptoNetwork network,
                               const char *addressAsString) {
    return cryptoAddressCreateFromStringAsXLM (addressAsString);
}

static BRCryptoBlockNumber
cryptoNetworkGetBlockNumberAtOrBeforeTimestampXLM (BRCryptoNetwork network,
                                                   BRCryptoTimestamp timestamp) {
    // not supported (used for p2p sync checkpoints)
    return 0;
}

// MARK: Account Initialization

static BRCryptoBoolean
cryptoNetworkIsAccountInitializedXLM (BRCryptoNetwork network,
                                      BRCryptoAccount account) {
    BRCryptoNetworkXLM networkXLM = cryptoNetworkCoerce (network);
    (void) networkXLM;

    BRStellarAccount xlmAccount = cryptoAccountAsXLM (account);
    assert (NULL != xlmAccount);
    return AS_CRYPTO_BOOLEAN (true);
}


static uint8_t *
cryptoNetworkGetAccountInitializationDataXLM (BRCryptoNetwork network,
                                              BRCryptoAccount account,
                                              size_t *bytesCount) {
    BRCryptoNetworkXLM networkXLM = cryptoNetworkCoerce (network);
    (void) networkXLM;

    BRStellarAccount xlmAccount = cryptoAccountAsXLM (account);
    assert (NULL != xlmAccount);
    if (NULL != bytesCount) *bytesCount = 0;
    return NULL;
}

static void
cryptoNetworkInitializeAccountXLM (BRCryptoNetwork network,
                                   BRCryptoAccount account,
                                   const uint8_t *bytes,
                                   size_t bytesCount) {
    BRCryptoNetworkXLM networkXLM = cryptoNetworkCoerce (network);
    (void) networkXLM;

    BRStellarAccount xlmAccount = cryptoAccountAsXLM (account);
    assert (NULL != xlmAccount);
    return;
}

static BRCryptoHash
cryptoNetworkCreateHashFromStringXLM (BRCryptoNetwork network,
                                      const char *string) {
    BRStellarTransactionHash hash = stellarHashCreateFromString (string);
    return cryptoHashCreateAsXLM (hash);
}

static char *
cryptoNetworkEncodeHashXLM (BRCryptoHash hash) {
    return cryptoHashStringAsHex (hash, false);
}

// MARK: - Handlers

BRCryptoNetworkHandlers cryptoNetworkHandlersXLM = {
    cryptoNetworkCreateXLM,
    cryptoNetworkReleaseXLM,
    cryptoNetworkCreateAddressXLM,
    cryptoNetworkGetBlockNumberAtOrBeforeTimestampXLM,
    cryptoNetworkIsAccountInitializedXLM,
    cryptoNetworkGetAccountInitializationDataXLM,
    cryptoNetworkInitializeAccountXLM,
    cryptoNetworkCreateHashFromStringXLM,
    cryptoNetworkEncodeHashXLM
};

