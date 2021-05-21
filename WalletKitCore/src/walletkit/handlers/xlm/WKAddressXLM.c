//
//  WKAddressXLM.c
//  WalletKitCore
//
//  Created by Carl Cherry on 2021-05-19.
//  Copyright © 2021 Breadwinner AG. All rights reserved.
//
//  See the LICENSE file at the project root for license information.
//  See the CONTRIBUTORS file at the project root for a list of contributors.
//
#include <assert.h>

#include "WKXLM.h"
#include "stellar/BRStellarAddress.h"


static BRCryptoAddressXLM
cryptoAddressCoerce (BRCryptoAddress address) {
    assert (CRYPTO_NETWORK_TYPE_XLM == address->type);
    return (BRCryptoAddressXLM) address;
}

typedef struct {
    BRStellarAddress xlmAddress;
} BRCryptoAddressCreateContextXLM;

static void
cryptoAddressCreateCallbackXLM (BRCryptoAddressCreateContext context,
                                BRCryptoAddress address) {
    BRCryptoAddressCreateContextXLM *contextXLM = (BRCryptoAddressCreateContextXLM*) context;
    BRCryptoAddressXLM addressXLM = cryptoAddressCoerce (address);

    addressXLM->addr = contextXLM->xlmAddress;
}

extern BRCryptoAddress
cryptoAddressCreateAsXLM (OwnershipGiven BRStellarAddress addr) {
    BRCryptoAddressCreateContextXLM contextXLM = {
        addr
    };

    return cryptoAddressAllocAndInit (sizeof (struct BRCryptoAddressXLMRecord),
                                      CRYPTO_NETWORK_TYPE_XLM,
                                      stellarAddressHashValue(addr),
                                      &contextXLM,
                                      cryptoAddressCreateCallbackXLM);
}

extern BRCryptoAddress
cryptoAddressCreateFromStringAsXLM (const char *string) {
    assert(string);
    
    BRStellarAddress address = stellarAddressCreateFromString (string, true);
    return (NULL != address
            ? cryptoAddressCreateAsXLM (address)
            : NULL);
}

private_extern OwnershipKept BRStellarAddress
cryptoAddressAsXLM (BRCryptoAddress address) {
    BRCryptoAddressXLM addressXLM = cryptoAddressCoerce (address);
    return addressXLM->addr;
}

// MARK: - Handlers

static void
cryptoAddressReleaseXLM (BRCryptoAddress address) {
    BRCryptoAddressXLM addressXLM = cryptoAddressCoerce (address);
    stellarAddressFree (addressXLM->addr);
}

static char *
cryptoAddressAsStringXLM (BRCryptoAddress address) {
    BRCryptoAddressXLM addressXLM = cryptoAddressCoerce (address);
    return stellarAddressAsString (addressXLM->addr);
}

static bool
cryptoAddressIsEqualXLM (BRCryptoAddress address1, BRCryptoAddress address2) {
    BRCryptoAddressXLM a1 = cryptoAddressCoerce (address1);
    BRCryptoAddressXLM a2 = cryptoAddressCoerce (address2);

    return stellarAddressEqual (a1->addr, a2->addr);
}

BRCryptoAddressHandlers cryptoAddressHandlersXLM = {
    cryptoAddressReleaseXLM,
    cryptoAddressAsStringXLM,
    cryptoAddressIsEqualXLM
};
