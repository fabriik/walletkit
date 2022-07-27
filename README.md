
![WalletKit](../gh-pages/public/img/logo-tight.png)

WalletKit provides a uniform wallet interface to access numerous crypto-currencies including
Bitcoin and Ethereum.  WalletKit is implemented in the C programming language and includes
a number of bindings for other languages, notably Swift and Java.

WalletKit supports the following crypto-currencies: Bitcoin, Bitcoin Cash, Bitcoin SV, Ethereum,
Ethereum ERC20 'tokens', Ripple, Hedera, and Tezos.  Other crypto-currencies are added
regularly.  Adding another blockchain is accomplished by satisfying a WalletKit-defined API.

WalletKit is the basis for the BRD iOS and Android mobile applications.

![badge-mit][]   ![badge-languages][]   ![badge-platforms][]

# Features

## Crypto-Currency Agnostic

## Syncing Modes

## Event-Based

## Multiple Language Bindings

### C

WalletKit defines a C interface, with associated C implementation, that runs on both macOS
and on Linux platforms.  The C interface can be accessed through the 'foreign function interface'
offered by other languages, such as Swift and Java.

The C interface is located in `.../WalletKit/WalletKitCore/include`.

### Swift

WalletKit includes a Swift framework, called `WalletKit` layered on the C code.

### Java

WalletKit includes a Java library ...

## Demo Mobile Applications

WalletKit includes iOS and Android demo applications.  These applications illustrate
basic usage of WalletKit to connect to numerous blockchains and to manage numerous wallets
holding assets based on blockchain transactions.

The iOS demo application is accessed using Xcode; the Andriod demo application is accessed
using Android Studio.

# Concepts

WalletKit is crypto-currency agnostic; as such, WalletKit defines a number of concepts that
apply across disparate blockchains but also can be extended with blockchain-specific data and
behaviors.

## Network

A `BRCryptoNetwork` ...

## Currency

A `BRCryptoCurrency` ...

## Transfer

A `BRCryptoTransfer` ...

## Wallet

A `BRCryptoWallet` ...

## WalletManager

A `BRCryptoWalletManager` ...

# Installation and Use

WalletKit is delivered as a Git repository for development within Xcode and Android Studio.

## Access

### Git

Clone WalletKit with
```
git clone --recurse-submodules git@github.com:fabriik/walletkit.git WalletKit
```
If you've cloned WalletKit but without the `--recursive-submodules` flag then perform:
```
(cd .../WalletKit; git submodule update --init --recursive)
```

### SwiftPM

### Maven

## Building

### Swift Package Manager

The WalletKit Swift framework can be built with `swift build`; the unit tests can be run with
`swift test`.  This will work on macOS and on Linux operating systems.  The
`swift-tools-version` must be 5.3 or greater (see
`.../WalletKit/WalletKitSwift/Package.swift`)

### Gradle

The WalletKit Java library can be built with `./gradle assemble`; this should be build from the WalletKitJava directory

### Xcode

WalletKit can be started in Xcode using `open .../WalletKit/WalletKitSwift/WalletKitDemo/WalletKitDemo.xcworkspace`.
This defines a workspace that allows one to access the Swift Demo App, the `WalletKit` Swift
code and the `WalletKitCore` C code.

### Android Studio

WalletKit can be started in Android Studio by opening the WalletKitJava directory in Andriod Studio

# Versions

## 1.0

Version 1.0 is currently the basis for the Fabriik iOS and Android mobile applications

# Support

Contact [Fabriik](https://fabriik.com "Fabriik")

[badge-languages]: https://img.shields.io/badge/languages-C%20%7C%20Swift%20%7C%20Java-orange.svg
[badge-platforms]: https://img.shields.io/badge/platforms-iOS%20%7C%20Android%20%7C%20macOS%20%7C%20Linux-lightgrey.svg
[badge-mit]: https://img.shields.io/badge/license-MIT-blue.svg
