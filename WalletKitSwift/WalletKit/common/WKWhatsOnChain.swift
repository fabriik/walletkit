//
//  BRBlockset.swift
//  WalletKit
//
//  Created by Ed Gamble on 3/27/19.
//  Copyright © 2019 Breadwinner AG. All rights reserved.
//
//  See the LICENSE file at the project root for license information.
//  See the CONTRIBUTORS file at the project root for a list of contributors.
//
import Foundation // DispatchQueue

#if os(Linux)
import FoundationNetworking
import WalletKitCore
#endif

private struct BlocksetCapabilities: OptionSet, CustomStringConvertible {
    let rawValue: Int

    static let transferStatusRevert = BlocksetCapabilities (rawValue: 1 << 0)
    static let transferStatusReject = BlocksetCapabilities (rawValue: 1 << 1)

    var description: String {
        switch rawValue {
        case 1 << 0: return "revert"
        case 1 << 1: return "reject"
        default:     return options.map { $0.description }.joined (separator: ", ")
        }
    }

    var options: [BlocksetCapabilities] {
        (0..<2).compactMap {
            switch rawValue & (1 << $0) {
            case 1 << 0: return .transferStatusRevert
            case 1 << 1: return .transferStatusReject
            default: return nil
            }
        }
    }

    static let v2020_03_21: BlocksetCapabilities = [
        .transferStatusRevert,
        .transferStatusReject
    ]

    var versionDescription: String {
        switch self {
        case BlocksetCapabilities.v2020_03_21: return "application/vnd.blockset.V_2020-03-21+json"
        default: return "application/json"
        }
    }

    static let current = v2020_03_21
}

public class WhatsOnChainSystemClient: SystemClient {
    static fileprivate let capabilities =  BlocksetCapabilities.current

    /// Base URL (String) for Blockset
    let bdbBaseURL: String

    // The session to use for DataTaskFunc as in `session.dataTask (with: request, ...)`.
    let session = URLSession (configuration: .default)

    /// A DispatchQueue Used for certain queries that can't be accomplished in the session's data
    /// task.  Such as when multiple request are needed in getTransactions().
    let queue = DispatchQueue.init(label: "BlocksetSystemClient")

    /// A function type that decorates a `request`, handles 'challenges', performs decrypting and/or
    /// uncompression of response data, redirects if requires and creates a `URLSessionDataTask`
    /// for the provided `session`.
    public typealias DataTaskFunc = (URLSession, URLRequest, @escaping (Data?, URLResponse?, Error?) -> Void) -> URLSessionDataTask

    /// A DataTaskFunc for submission to Blockset
    internal let bdbDataTaskFunc: DataTaskFunc

    /// A default DataTaskFunc that simply invokes `session.dataTask (with: request, ...)`
    static let defaultDataTaskFunc: DataTaskFunc = {
        (_ session: URLSession,
        _ request: URLRequest,
        _ completionHandler: @escaping (Data?, URLResponse?, Error?) -> Void) -> URLSessionDataTask in
        session.dataTask (with: request, completionHandler: completionHandler)
    }
    
    public typealias DataTaskFuncSet = (URLSession, URLRequest, Data?, @escaping (Data?, URLResponse?, Error?) -> Void) -> URLSessionDataTask
    
    static let defaultDataTaskFuncSet: DataTaskFuncSet = {
        (_ session: URLSession,
        _ request: URLRequest,
         _ data: Data?,
        _ completionHandler: @escaping (Data?, URLResponse?, Error?) -> Void) -> URLSessionDataTask in
        session.dataTask (with: request, completionHandler: completionHandler)
    }
    
    typealias DataTaskFuncSetJSON = (URLSession, URLRequest, JSON.Dict?, @escaping (Data?, URLResponse?, Error?) -> Void) -> URLSessionDataTask
    
    static let defaultDataTaskFuncSetJSON: DataTaskFuncSetJSON = {
        (_ session: URLSession,
        _ request: URLRequest,
         _ data: JSON.Dict?,
        _ completionHandler: @escaping (Data?, URLResponse?, Error?) -> Void) -> URLSessionDataTask in
        session.dataTask (with: request, completionHandler: completionHandler)
    }

    ///
    /// A Subscription allows for BlockchainDB 'Asynchronous Notifications'.
    ///
//    public struct Subscription {
//
//        /// A unique identifier for the subscription
//        public let subscriptionId: String
//
//        /// A unique identifier for the device.
//        public let deviceId: String
//
//        ///
//        /// An endpoint definition allowing the BlockchainDB to 'target' this App.  Allows
//        /// for APNS, FCM and other notification systems.  This is an optional value; when set to
//        /// .none, any existing notification will be disabled
//        ///
//        /// environment : { unknown, production, development }
//        /// kind        : { unknown, apns, fcm, ... }
//        /// value       : For apns/fcm this will be the registration token, apns should be hex-encoded
//        public let endpoint: (environment: String, kind: String, value: String)?
//
//        public init (id: String, deviceId: String? = nil, endpoint: (environment: String, kind: String, value: String)?) {
//            self.subscriptionId = id
//            self.deviceId = deviceId ?? id
//            self.endpoint = endpoint
//        }
//    }

    /// A User-specific identifier - a string representation of a UUIDv4
    internal var walletId: String? = nil

    /// A Subscription specificiation
    internal var subscription: Subscription? = nil

    #if false
    private var modelSubscription: SystemClient.Subscription? {
        guard let _ = walletId,  let subscription = subscription, let endpoint = subscription.endpoint
            else { return nil }

        return (id: subscription.subscriptionId,
                device: subscription.deviceId,
                endpoint: (environment: endpoint.environment, kind: endpoint.kind, value: endpoint.value))
    }
    #endif

    // A BlocksetSystemClient wallet requires at least one 'currency : [<addr>+]' entry.  Create a minimal,
    // default one using a compromised ETH address.  This will get replaced as soon as we have
    // a real ETH account.
    internal static let minimalCurrencies = ["eth" : ["A9De3DBd7D561e67527BC1ECB025C59D53B9F7EF"]]

    public func subscribe (walletId: String, subscription: Subscription) {
        self.walletId = walletId
        self.subscription = subscription

        // TODO: Update caller System.subscribe
        #if false
        // Subscribing requires a wallet on the BlockChainDD, so start by create the BlocksetSystemClient
        // SystemClient.Wallet and then get or create one on the DB.

        let wallet = (id: walletId, currencies: BlocksetSystemClient.minimalCurrencies)

        getOrCreateWallet (wallet) { (walletRes: Result<SystemClient.Wallet, SystemClientError>) in
            guard case .success = walletRes
                else { print ("SYS: BDB:Wallet: Missed"); return }

            if let model = self.modelSubscription {
                // If the subscription included an endpoint, then put the subscription on the
                // blockchainDB - via POST or PUT.
                self.getSubscription (id: model.id) { (subRes: Result<SystemClient.Subscription, SystemClientError>) in
                    switch subRes {
                    case let .success (subscription):
                        self.updateSubscription (subscription) {
                            (resSub: Result<BlocksetSystemClient.SystemClient.Subscription, SystemClientError>) in
                        }

                    case .failure:
                        self.createSubscription (model) {
                            (resSub: Result<BlocksetSystemClient.SystemClient.Subscription, SystemClientError>) in
                        }
                    }
                }
            }

            else {
                // Otherwise delete it.
                self.deleteSubscription(id: subscription.subscriptionId) {
                    (subRes: Result<BlocksetSystemClient.SystemClient.Subscription, SystemClientError>) in
                }
            }
        }
        #endif
    }

    ///
    /// Initialize a BlocksetSystemClient
    ///
    /// - Parameters:
    ///   - session: the URLSession to use.  Defaults to `URLSession (configuration: .default)`
    ///   - bdbBaseURL: the baseURL for Blockset.  Defaults to "http://api.blockset.com"
    ///   - bdbDataTaskFunc: an optional DataTaskFunc for Blockset.  This defaults to
    ///       `session.dataTask (with: request, ...)`
    ///
    //public init (bdbBaseURL: String = "https://api.blockset.com",
    public init (bdbBaseURL: String = "https://api.whatsonchain.com",
                 bdbDataTaskFunc: DataTaskFunc? = nil) {
        self.bdbBaseURL = bdbBaseURL
        self.bdbDataTaskFunc = bdbDataTaskFunc ?? BlocksetSystemClient.defaultDataTaskFunc
    }

    ///
    /// Create a BlocksetSystemClient using a specified Authorization token.  This is declared 'public'
    /// so that the Crypto Demo can use it.
    ///
    public static func createForTest (bdbBaseURL: String, bdbToken: String) -> WhatsOnChainSystemClient {
        return WhatsOnChainSystemClient (bdbBaseURL: bdbBaseURL,
                                     bdbDataTaskFunc: { (session, request, completion) -> URLSessionDataTask in
                                         var decoratedReq = request
                                         decoratedReq.setValue ("Bearer \(bdbToken)", forHTTPHeaderField: "Authorization")
                                         return session.dataTask (with: decoratedReq, completionHandler: completion)
        })
    }

    public static func createForTest (blocksetAccess: BlocksetAccess) -> WhatsOnChainSystemClient {
        return createForTest(bdbBaseURL: blocksetAccess.baseURL, bdbToken: blocksetAccess.token)
    }

    public func cancelAll () {
        print ("SYS: BDB: Cancel All")
        session.getAllTasks(completionHandler: { $0.forEach { $0.cancel () } })
    }

    ///
    /// The BlocksetSystemClient Model (aka Schema-ish)
    ///
    public struct Model {

        /// Blockchain

        static internal func asBlockchainFee (json: JSON) -> SystemClient.BlockchainFee? {
            guard let confirmationTime = json.asUInt64(name: "estimated_confirmation_in"),
                  let amountValue = json.asDict(name: "fee")?["amount"] as? String,
                  let _ = json.asDict(name: "fee")?["currency_id"] as? String,
                  let tier = json.asString(name: "tier")
            else {
                print ("SYS: BDB: API: ERROR in asBlockchainFee JSON: '\(json)'")
                return nil
            }

            return (amount: amountValue, tier: tier, confirmationTimeInMilliseconds: confirmationTime)
        }

        static internal func asBlockchain (json: JSON) -> SystemClient.Blockchain? {
            guard let id = json.asString (name: "id"),
                  let name = json.asString (name: "name"),
                  let network = json.asString (name: "network"),
                  let isMainnet = json.asBool (name: "is_mainnet"),
                  let currency = json.asString (name: "native_currency_id"),
                  let blockHeight = json.asInt64 (name: "verified_height"),
                  let confirmationsUntilFinal = json.asUInt32(name: "confirmations_until_final")
            else {
                print ("SYS: BDB: API: ERROR in asBlockchain JSON: '\(json)'")
                return nil
            }

            guard let feeEstimates = json.asArrayMapped(name: "fee_estimates", transform: asBlockchainFee)
            else { return nil }

            let verifiedBlockHash = json.asString(name: "verified_block_hash")

            return (id: id, name: name, network: network, isMainnet: isMainnet, currency: currency,
                    blockHeight: (-1 == blockHeight ? nil : UInt64 (blockHeight)),
                    verifiedBlockHash: verifiedBlockHash,
                    feeEstimates: feeEstimates,
                    confirmationsUntilFinal: confirmationsUntilFinal)
        }
        
        static internal func asBlockchainWOC (json: JSON) -> SystemClient.Blockchain? {
            guard let chain = json.asString (name: "chain"),
                  let blocks = json.asInt64 (name: "blocks"),
                  //let headers = json.asInt64 (name: "headers"),
                  let bestblockhash = json.asString (name: "bestblockhash"),
                  //let difficulty = json.asData (name: "difficulty"),
                  let mediantime = json.asUInt64 (name: "mediantime")
                  //let verificationprogress = json.asData (name: "verificationprogress"),
                  //let pruned = json.asBool (name: "pruned"),
                  //let chainwork = json.asString(name: "chainwork")
            else {
                print ("SYS: BDB: API: ERROR in asBlockchainWOC JSON: '\(json)'")
                return nil
            }
            
            let isMainnet = (chain == "main") ? true : false
            
            let feeEstimates = [(amount: "500", tier: "tier", confirmationTimeInMilliseconds: mediantime)]
            
            /*
             id: String,
             name: String,
             network: String,
             isMainnet: Bool,
             currency: String,
             blockHeight: UInt64?,
             verifiedBlockHash: String?,
             feeEstimates: [BlockchainFee],
             confirmationsUntilFinal: UInt32)
             */

            return (SystemClient.Blockchain) (id: bestblockhash, name: chain, network: "WhatsOnChain", isMainnet: isMainnet, currency: "satoshis",
                    blockHeight: -1 == blocks ? nil : UInt64 (blocks),
                    verifiedBlockHash: bestblockhash,
                    feeEstimates: feeEstimates,
                    confirmationsUntilFinal: 0)
        }

        /// Currency & CurrencyDenomination

        static internal func asCurrencyDenomination (json: JSON) -> SystemClient.CurrencyDenomination? {
            guard let name = json.asString (name: "name"),
                  let code = json.asString (name: "short_name"),
                  let decimals = json.asUInt8 (name: "decimals")
                    // let symbol = json.asString (name: "symbol")
            else {
                print ("SYS: BDB: API: ERROR in asCurrencyDenomination JSON: '\(json)'")
                return nil
            }

            let symbol = lookupSymbol (code)

            return (name: name, code: code, decimals: decimals, symbol: symbol)
        }

        static internal let currencySymbols = ["btc":"₿", "eth":"Ξ"]
        static internal func lookupSymbol (_ code: String) -> String {
            return currencySymbols[code] ?? code.uppercased()
        }

        static private let currencyInternalAddress = "__native__"

        static internal func asCurrency (json: JSON) -> SystemClient.Currency? {
            guard let id = json.asString (name: "currency_id"),
                  let name = json.asString (name: "name"),
                  let code = json.asString (name: "code"),
                  let type = json.asString (name: "type"),
                  let bid  = json.asString (name: "blockchain_id"),
                  let verified = json.asBool(name: "verified")
            else {
                print ("SYS: BDB: API: ERROR in asCurrency JSON: '\(json)'")
                return nil
            }

            // Address is optional
            let address = json.asString(name: "address")

            // All denomincations must parse
            guard let demoninations = json.asArrayMapped (name: "denominations", transform: asCurrencyDenomination)
            else { return nil }
            
            return (id: id, name: name, code: code, type: type,
                    blockchainID: bid,
                    address: (address == currencyInternalAddress ? nil : address),
                    verified: verified,
                    demoninations: demoninations)
        }

        static internal let addressBRDTestnet = "0x7108ca7c4718efa810457f228305c9c71390931a" // testnet
        static internal let addressBRDMainnet = "0x558ec3152e2eb2174905cd19aea4e34a23de9ad6" // mainnet

        /// Amount

        static internal func asAmount (json: JSON) -> SystemClient.Amount? {
            guard let currency = json.asString (name: "currency_id"),
                  let value = json.asString (name: "amount")
            else {
                print ("SYS: BDB: API: ERROR in asAmount JSON: '\(json)'")
                return nil
            }
            return (currency: currency, value: value)
        }

        /// Transfer

        static internal func asTransfer (json: JSON) -> SystemClient.Transfer? {
            guard let id   = json.asString (name: "transfer_id"),
                  let bid    = json.asString (name: "blockchain_id"),
                  let index  = json.asUInt64 (name: "index"),
                  let amount = json.asDict (name: "amount")
                    .map ({ JSON (dict: $0) })
                    .flatMap ({ asAmount(json: $0) })
            else {
                print ("SYS: BDB: API: ERROR in asTransfer JSON: '\(json)'")
                return nil
            }

            // TODO: Resolve if optional or not
            let acks   = json.asUInt64 (name: "acknowledgements") ?? 0
            let source = json.asString (name: "from_address")
            let target = json.asString (name: "to_address")
            let tid    = json.asString (name: "transaction_id")
            let meta   = json.asDict(name: "meta")?.mapValues { return $0 as! String }

            return (id: id, source: source, target: target, amount: amount,
                    acknowledgements: acks, index: index,
                    transactionId: tid, blockchainId: bid,
                    metaData: meta)
        }

        /// Transaction

        static internal func asTransactionValidateStatus (_ status: String) -> Bool {
            switch status {
            case "confirmed",
                 "submitted",
                 "failed":
                return true
            case "reverted":
                return WhatsOnChainSystemClient.capabilities.contains(.transferStatusRevert)
            case "rejected":
                return WhatsOnChainSystemClient.capabilities.contains(.transferStatusReject)
            default:
                return false
            }
        }

        static internal func asTransaction (json: JSON) -> SystemClient.Transaction? {
            guard let id = json.asString(name: "transaction_id"),
                  let bid        = json.asString (name: "blockchain_id"),
                  let hash       = json.asString (name: "hash"),
                  let identifier = json.asString (name: "identifier"),
                  let status     = json.asString (name: "status"),
                  let size       = json.asUInt64 (name: "size"),
                  let fee        = json.asDict (name: "fee")
                    .map ({ JSON (dict: $0) })
                    .flatMap ({ asAmount(json: $0)}),
                  asTransactionValidateStatus(status)
            else {
                print ("SYS: BDB: API: ERROR in asTransaction JSON: '\(json)'")
                return nil
            }

            // TODO: Resolve if optional or not
            let acks       = json.asUInt64 (name: "acknowledgements") ?? 0
            // TODO: Resolve if optional or not
            let firstSeen     = json.asDate   (name: "first_seen")
            let blockHash     = json.asString (name: "block_hash")
            let blockHeight   = json.asUInt64 (name: "block_height")
            let index         = json.asUInt64 (name: "index")
            let confirmations = json.asUInt64 (name: "confirmations")
            let timestamp     = json.asDate   (name: "timestamp")
            let meta          = json.asDict(name: "meta")?.mapValues { return $0 as! String }

            let raw      = json.asData (name: "raw")
            let embedded = json.asJSON (name: "_embedded")
            
            guard let transfers = (nil == embedded || nil == embedded!.asArray(name: "transfers")
                                   ? [] // No "_embedded" or no "transfers"
                                   : embedded!.asArrayMapped(name: "transfers", transform: asTransfer))
            else {
                print ("SYS: BDB: API: ERROR in asTransaction.Transfers JSON: '\(json)'")
                return nil
            }

            /*return (id: id, blockchainId: bid,
                     hash: hash, identifier: identifier,
                     blockHash: blockHash, blockHeight: blockHeight, index: index, confirmations: confirmations, status: status,
                     size: size, timestamp: timestamp, firstSeen: firstSeen,
                     raw: raw,
                     fee: fee,
                     transfers: transfers,
                     acknowledgements: acks,
                     metaData: meta)*/
            return (id: id, blockchainId: bid,
                     hash: hash, identifier: identifier,
                     blockHash: blockHash, blockHeight: blockHeight, index: index, confirmations: confirmations, status: status,
                     size: size, timestamp: timestamp, firstSeen: firstSeen,
                     raw: raw,
                     fee: fee,
                     transfers: transfers,
                     acknowledgements: acks,
                     metaData: meta,
                     version: nil,
                     lockTime: nil,
                     time: nil,
                     inCount: nil,
                     inputs: nil,
                     outCount: nil,
                     outputs: nil
                     )
        }
        
        static internal func asTransactionWOC (json: JSON) -> SystemClient.Transaction? {
            /*guard let id = json.asString(name: "transaction_id"),
                  let bid        = json.asString (name: "blockchain_id"),
                  let hash       = json.asString (name: "hash"),
                  let identifier = json.asString (name: "identifier"),
                  let status     = json.asString (name: "status"),
                  let size       = json.asUInt64 (name: "size"),
                  let fee        = json.asDict (name: "fee")
                    .map ({ JSON (dict: $0) })
                    .flatMap ({ asAmount(json: $0)}),
                  asTransactionValidateStatus(status)
            else {
                print ("SYS: BDB: API: ERROR in asTransaction JSON: '\(json)'")
                return nil
            }*/
            
            guard let hash = json.asString(name: "hash"),
                  let blockHeight = json.asInt64 (name: "blockheight"),
                  let blockHash = json.asString (name: "blockhash"),
                  let identifier = json.asString (name: "txid"),
                  let confirmations     = json.asUInt64 (name: "confirmations"),
                  let size       = json.asInt64 (name: "size"),
                  let version    = json.asInt64 (name: "version"),
                  let lockTime   = json.asInt64 (name: "locktime"),
                  let time       = json.asInt64 (name: "time"),
                  let vin        = json.asJSONArray (name: "vin"),
                  let vout       = json.asJSONArray (name: "vout")
                  //let raw = json.asData (name: "txid")
            else {
                print ("SYS: BDB: API: ERROR in asTransaction JSON: '\(json)'")
                return nil
            }
            
            //var count = 0
            //var json_array : [JSON.Dict] = []

            var inputs : [SystemClient.Inputs] = []
            for anItem in vin {
                let sequence = anItem.asInt64 (name: "sequence")
                let scriptSig = anItem.asDict (name: "scriptSig")
                //let scriptSig = anItem["scriptSig"] as! JSON.Dict
                let script = scriptSig!["hex"] as! String
                //let script = scriptSig.asString (name: "hex")
                let signature = scriptSig!["asm"] as! String
                let txid = anItem.asString (name: "txid")
                
                let input : SystemClient.Inputs = (txHash: txid!, script: script, signature: signature, sequence: sequence!)
                inputs.append(input)
                
                //let script = anItem.asString ()
                print("Stop")
            }
            
            var outputs : [SystemClient.Outputs] = []
            for anItem in vout {
                let value = anItem.asString (name: "value")
                let scriptPubKey = anItem.asDict (name: "scriptPubKey")
                //let scriptSig = anItem["scriptSig"] as! JSON.Dict
                let script = scriptPubKey!["hex"] as! String

                
                //let output : SystemClient.Outputs = (script: script, amount: value!)
                let output : SystemClient.Outputs = (script: script, amount: "0")
                outputs.append(output)
                
                //let script = anItem.asString ()
                print("Stop")
            }
          
            let inCount = inputs.count
            
            let outCount = outputs.count
            
            
            
            //let url = URL(string: "https://api.whatsonchain.com/v1/bsv/test/tx/\(hash)/hex")!
            
            //print("\(url)")

            //var request = URLRequest(url: url)
            //request.httpMethod = "GET"
            
            
            let session_ = URLSession (configuration: .default)
            var request = URLRequest(url: URL(string: "https://api.whatsonchain.com/v1/bsv/test/tx/\(hash)/hex")!);
            //var request = URLRequest(url: URL(string: "https://api.whatsonchain.com/v1/bsv/main/tx/\(hash)/hex")!); //FIXME!!!
            //var request = URLRequest(url: URL(string: "https://api.whatsonchain.com/v1/bsv/test/chain/info")!);
            request.httpMethod = "GET"
            
            //var request = NSMutableURLRequest(url: URL(string: "https://api.whatsonchain.com/v1/bsv/test/tx/\(hash)/hex")!)
            //var session = URLSession.shared
            //request.httpMethod = "GET"
            print("request: \(request)")
            
            var data_: Data?
                
            let semaphore: DispatchSemaphore = DispatchSemaphore(value: 0)
                //let task = URLSession.shared.dataTask(with: request) { (data, response, error) in
            let task = WhatsOnChainSystemClient.defaultDataTaskFuncSet (session_, request, data_) { (data, res, error) in
            //var task = session.dataTask(with: request as URLRequest, completionHandler: {data, response, error -> Void in
                //print("Response: \(response)")})
                    //get responce here
                    //Use response
                    print("2")
                    do {
                        //let jsonResult = try JSONSerialization.data (withJSONObject: data, options: [])
                        //let jsonResult = try JSONSerialization.jsonObject(with: data!, options: [])
                        let convertedString = String(data: data!, encoding: String.Encoding.utf8)
                        data_ = data
                        print("data: \(convertedString)")
                    } catch let error as NSError {
                        print(error.localizedDescription)
                    }
                    semaphore.signal()
                }
                task.resume()
                print("1")
                semaphore.wait()
                print("3")
        
            
            
            let dict_ : Dictionary<String,String> = [:]
            
            let transfers = [(
                id: identifier,
                source: "source",
                target: "target",
                amount: (currency: "satoshi", value: "0"),
                acknowledgements: confirmations,
                index: UInt64(0),
                transactionId: identifier,
                blockchainId: "test",
                metaData: dict_)
            ]

            return (id: identifier,
                     blockchainId: "test",
                     hash: hash,
                     identifier: identifier,
                     blockHash: blockHash,
                     blockHeight: -1 == blockHeight ? nil : UInt64(blockHeight),
                     index: UInt64(0),
                     confirmations: 0 == confirmations ? nil : confirmations,
                     status: "confirmed",
                     size: 0 <= size ? 0 : UInt64(size),
                     timestamp: Date(),
                     firstSeen: Date(),
                     raw: data_,
                     fee: (currency: "satoshi", value: "0"),
                     transfers: transfers,
                     acknowledgements: confirmations,
                     metaData: dict_,
                     version: version,
                     lockTime: lockTime,
                     time: time,
                     inCount: inCount,
                     inputs: inputs,
                     outCount: outCount,
                     outputs: outputs
            
            )
            /*return (id: identifier, blockchainId: "test",
                     hash: hash, identifier: identifier,
                     blockHash: blockHash, blockHeight: blockHeight,
                     index: UInt64(0),
                     confirmations: confirmations,
                     status: "",
                     size: UInt64(size),
                     timestamp: NSDate(),
                     firstSeen: NSDate(),
                     raw: raw,
                     fee: (currency: "satoshi", value: "0"),
                     transfers: transfers,
                     acknowledgements: confirmations,
                     metaData: dict_)*/
        }
        
        
        static internal func asTransactionWOCArray (json_: [JSON.Dict]) -> [SystemClient.Transaction]? {
            /*guard let id = json.asString(name: "transaction_id"),
                  let bid        = json.asString (name: "blockchain_id"),
                  let hash       = json.asString (name: "hash"),
                  let identifier = json.asString (name: "identifier"),
                  let status     = json.asString (name: "status"),
                  let size       = json.asUInt64 (name: "size"),
                  let fee        = json.asDict (name: "fee")
                    .map ({ JSON (dict: $0) })
                    .flatMap ({ asAmount(json: $0)}),
                  asTransactionValidateStatus(status)
            else {
                print ("SYS: BDB: API: ERROR in asTransaction JSON: '\(json)'")
                return nil
            }*/
            
            var result_array : [SystemClient.Transaction] = []
            
            let json_array = json_.map { JSON (dict: $0) }
            
            for json in json_array {
           
                guard let hash = json.asString(name: "hash"),
                      let blockHeight = json.asInt64 (name: "blockheight"),
                      let blockHash = json.asString (name: "blockhash"),
                      let identifier = json.asString (name: "txid"),
                      let confirmations     = json.asUInt64 (name: "confirmations"),
                      let size       = json.asInt64 (name: "size"),
                      let version    = json.asInt64 (name: "version"),
                      let lockTime   = json.asInt64 (name: "locktime"),
                      let time       = json.asInt64 (name: "time"),
                      let vin        = json.asJSONArray (name: "vin"),
                      let vout       = json.asJSONArray (name: "vout")
                else {
                    print ("SYS: BDB: API: ERROR in asTransaction JSON: '\(json)'")
                    return nil
                }
                
                //var count = 0
                //var json_array : [JSON.Dict] = []

                var inputs : [SystemClient.Inputs] = []
                for anItem in vin {
                    let sequence = anItem.asInt64 (name: "sequence")
                    let scriptSig = anItem.asDict (name: "scriptSig")
                    //let scriptSig = anItem["scriptSig"] as! JSON.Dict
                    let script = scriptSig!["hex"] as! String
                    //let script = scriptSig.asString (name: "hex")
                    let signature = scriptSig!["asm"] as! String
                    let txid = anItem.asString (name: "txid")
                    
                    let input : SystemClient.Inputs = (txHash: txid!, script: script, signature: signature, sequence: sequence!)
                    inputs.append(input)
                    
                    //let script = anItem.asString ()
                    print("Stop")
                }
                
                var outputs : [SystemClient.Outputs] = []
                for anItem in vout {
                    let value = anItem.asString (name: "value")
                    let scriptPubKey = anItem.asDict (name: "scriptPubKey")
                    //let scriptSig = anItem["scriptSig"] as! JSON.Dict
                    let script = scriptPubKey!["hex"] as! String

                    
                    let output : SystemClient.Outputs = (script: script, amount: value! )
                    outputs.append(output)
                    
                    //let script = anItem.asString ()
                    print("Stop")
                }
              
                let inCount = inputs.count
                
                let outCount = outputs.count
                
                
                
                //let url = URL(string: "https://api.whatsonchain.com/v1/bsv/test/tx/\(hash)/hex")!
                
                //print("\(url)")

                //var request = URLRequest(url: url)
                //request.httpMethod = "GET"
                
                
                let session_ = URLSession (configuration: .default)
                var request = URLRequest(url: URL(string: "https://api.whatsonchain.com/v1/bsv/test/tx/\(hash)/hex")!);
                //var request = URLRequest(url: URL(string: "https://api.whatsonchain.com/v1/bsv/main/tx/\(hash)/hex")!); //FIXME!!!
                //var request = URLRequest(url: URL(string: "https://api.whatsonchain.com/v1/bsv/test/chain/info")!);
                request.httpMethod = "GET"
                
                //var request = NSMutableURLRequest(url: URL(string: "https://api.whatsonchain.com/v1/bsv/test/tx/\(hash)/hex")!)
                //var session = URLSession.shared
                //request.httpMethod = "GET"
                print("request: \(request)")
                
                var data_: Data?
                    
                let semaphore: DispatchSemaphore = DispatchSemaphore(value: 0)
                    //let task = URLSession.shared.dataTask(with: request) { (data, response, error) in
                let task = WhatsOnChainSystemClient.defaultDataTaskFuncSet (session_, request, data_) { (data, res, error) in
                //var task = session.dataTask(with: request as URLRequest, completionHandler: {data, response, error -> Void in
                    //print("Response: \(response)")})
                        //get responce here
                        //Use response
                        print("2")
                        do {
                            //let jsonResult = try JSONSerialization.data (withJSONObject: data, options: [])
                            //let jsonResult = try JSONSerialization.jsonObject(with: data!, options: [])
                            let convertedString = String(data: data!, encoding: String.Encoding.utf8)
                            data_ = data
                            print("data: \(convertedString)")
                        } catch let error as NSError {
                            print(error.localizedDescription)
                        }
                        semaphore.signal()
                    }
                    task.resume()
                    print("1")
                    semaphore.wait()
                    print("3")
            
                
                
                let dict_ : Dictionary<String,String> = [:]
                
                let transfers = [(
                    id: identifier,
                    source: "source",
                    target: "target",
                    amount: (currency: "satoshi", value: "0"),
                    acknowledgements: confirmations,
                    index: UInt64(0),
                    transactionId: identifier,
                    blockchainId: "test",
                    metaData: dict_)
                ]
                
                result_array.append((id: identifier,
                                    blockchainId: "test",
                                    hash: hash,
                                    identifier: identifier,
                                    blockHash: blockHash,
                                    blockHeight: -1 == blockHeight ? nil : UInt64(blockHeight),
                                    index: UInt64(0),
                                    confirmations: 0 == confirmations ? nil : confirmations,
                                    status: "confirmed",
                                    size: 0 <= size ? 0 : UInt64(size),
                                    timestamp: Date(),
                                    firstSeen: Date(),
                                    raw: data_,
                                    fee: (currency: "satoshi", value: "0"),
                                    transfers: transfers,
                                    acknowledgements: confirmations,
                                    metaData: dict_,
                                    version: version,
                                    lockTime: lockTime,
                                    time: time,
                                    inCount: inCount,
                                    inputs: inputs,
                                    outCount: outCount,
                                    outputs: outputs))
                    
            }

            return result_array
            
        }
        
        

        static internal func asTransactionIdentifier (json: JSON) -> SystemClient.TransactionIdentifier? {
            guard let id         = json.asString(name: "transaction_id"),
                  let bid        = json.asString (name: "blockchain_id"),
                  let identifier = json.asString (name: "identifier")
            else {
                print ("SYS: BDB: API: ERROR in asTransactionIdentifier JSON: '\(json)'")
                return nil
            }

            let hash = json.asString (name: "hash")

            return (id: id, blockchainId: bid, hash: hash, identifier: identifier)
        }

        /// Transaction Fee

        public typealias TransactionFee = (
            costUnits: UInt64,
            foo: String
        )

        static internal func asTransactionFee (json: JSON) -> SystemClient.TransactionFee? {
            guard let costUnits = json.asUInt64(name: "cost_units")
            else {
                print ("SYS: BDB: API: ERROR in asTransactionFee JSON: '\(json)'")
                return nil
            }

            let properties = json.asDict(name: "properties")?.mapValues { return $0 as! String }

            return (costUnits: costUnits, properties: properties)
        }

        /// Block

        public typealias Block = (
            id: String,
            blockchainId: String,
            hash: String,
            height: UInt64,
            header: String?,
            raw: Data?,
            mined: Date,
            size: UInt64,
            prevHash: String?,
            nextHash: String?, // fees
            transactions: [Transaction]?,
            acknowledgements: UInt64
        )

        static internal func asBlock (json: JSON) -> SystemClient.Block? {
            guard let id = json.asString(name: "block_id"),
                let bid      = json.asString(name: "blockchain_id"),
                let hash     = json.asString (name: "hash"),
                let height   = json.asUInt64 (name: "height"),
                let mined    = json.asDate   (name: "mined"),
                let size     = json.asUInt64 (name: "size")
            else {
                print ("SYS: BDB: API: ERROR in asBlock JSON: '\(json)'")
                return nil
            }

            let acks     = json.asUInt64 (name: "acknowledgements") ?? 0
            let header   = json.asString (name: "header")
            let raw      = json.asData   (name: "raw")
            let prevHash = json.asString (name: "prev_hash")
            let nextHash = json.asString (name: "next_hash")

            let transactions = json.asArrayMapped (name: "transactions", transform: asTransaction)

            return (id: id, blockchainId: bid,
                    hash: hash, height: height, header: header, raw: raw, mined: mined, size: size,
                    prevHash: prevHash, nextHash: nextHash,
                    transactions: transactions,
                    acknowledgements: acks)
        }

        /// Subscription Endpoint

        public typealias SubscriptionEndpoint = (environment: String, kind: String, value: String)

        static internal func asSubscriptionEndpoint (json: JSON) -> SubscriptionEndpoint? {
            guard let environment = json.asString (name: "environment"),
                  let kind = json.asString(name: "kind"),
                  let value = json.asString(name: "value")
            else {
                print ("SYS: BDB: API: ERROR in asSubscriptionEndpoint JSON: '\(json)'")
                return nil
            }

            return (environment: environment, kind: kind, value: value)
        }

        static internal func asJSON (subscriptionEndpoint: SubscriptionEndpoint) -> JSON.Dict {
            return [
                "environment"   : subscriptionEndpoint.environment,
                "kind"          : subscriptionEndpoint.kind,
                "value"         : subscriptionEndpoint.value
            ]
        }


        /// Subscription Event

        public typealias SubscriptionEvent = (name: String, confirmations: [UInt32]) // More?

        static internal func asSubscriptionEvent (json: JSON) -> SubscriptionEvent? {
            guard let name = json.asString(name: "name")
            else {
                print ("SYS: BDB: API: ERROR in asSubscriptionEvent JSON: '\(json)'")
                return nil
            }
            return (name: name, confirmations: [])
        }

        static internal func asJSON (subscriptionEvent: SubscriptionEvent) -> JSON.Dict {
            switch subscriptionEvent.name {
            case "submitted":
                return [
                    "name" : subscriptionEvent.name
                ]
            case "confirmed":
                return [
                    "name"          : subscriptionEvent.name,
                    "confirmations" : subscriptionEvent.confirmations
                ]
            default:
                preconditionFailure()
            }
        }

        /// Subscription Currency

        public typealias SubscriptionCurrency = (addresses: [String], currencyId: String, events: [SubscriptionEvent])

        static internal func asSubscriptionCurrency (json: JSON) -> SubscriptionCurrency? {
            guard let addresses = json.asStringArray (name: "addresses"),
                  let currencyId = json.asString (name: "currency_id"),
                  let events = json.asArrayMapped(name: "events", transform: asSubscriptionEvent)
            else {
                print ("SYS: BDB: API: ERROR in asSubscriptionCurrency JSON: '\(json)'")
                return nil
            }

            return (addresses: addresses, currencyId: currencyId, events: events)
        }

        static internal func asJSON (subscriptionCurrency: SubscriptionCurrency) -> JSON.Dict {
            return [
                "addresses"   : subscriptionCurrency.addresses,
                "currency_id" : subscriptionCurrency.currencyId,
                "events"       : subscriptionCurrency.events.map { asJSON(subscriptionEvent: $0) }
            ]
        }

        /// Subscription

        // TODO: Apparently `currences` can not be empty.
        public typealias Subscription = (
            id: String,     // subscriptionId
            device: String, //  devcieId
            endpoint: SubscriptionEndpoint,
            currencies: [SubscriptionCurrency]
        )

        static internal func asSubscription (json: JSON) -> Subscription? {
            guard let id = json.asString (name: "subscription_id"),
                  let device = json.asString (name: "device_id"),
                  let endpoint = json.asDict(name: "endpoint")
                    .flatMap ({ asSubscriptionEndpoint (json: JSON (dict: $0)) }),
                  let currencies = json.asArrayMapped(name: "currencies", transform: asSubscriptionCurrency)
            else {
                print ("SYS: BDB: API: ERROR in asSubscription JSON: '\(json)'")
                return nil
            }

            return (id: id,
                    device: device,
                    endpoint: endpoint,
                    currencies: currencies)
        }

        static internal func asJSON (subscription: Subscription) -> JSON.Dict {
            return [
                "subscription_id" : subscription.id,
                "device_id"       : subscription.device,
                "endpoint"        : asJSON (subscriptionEndpoint: subscription.endpoint),
                "currencies"      : subscription.currencies.map { asJSON (subscriptionCurrency: $0) }
            ]
        }

        /// Address

        static internal func asAddress (json: JSON) -> SystemClient.Address? {
            guard let bid     = json.asString (name: "blockchain_id"),
                  let address   = json.asString (name: "address"),
                  let timestamp = json.asUInt64 (name: "timestamp"),
                  let balances  = json.asArrayMapped(name: "balances", transform: asAmount)
            else {
                print ("SYS: BDB: API: ERROR in asAddress JSON: '\(json)'")
                return nil
            }

            let nonce = json.asUInt64 (name: "nonce")
            let meta  = json.asDict(name: "meta")?.mapValues { return $0 as! String }

            return (blockchainID: bid, address: address,
                    nonce: nonce, timestamp: timestamp,
                    metaData: meta,
                    balances: balances)
        }

        /// Hedera Account

        static internal func asHederaAccount (json: JSON) -> SystemClient.HederaAccount? {
            guard let id      = json.asString (name: "account_id"),
                  let status    = json.asString (name: "account_status")
            else {
                print ("SYS: BDB: API: ERROR in asHederaAccount JSON: '\(json)'")
                return nil
            }

            let balance   = json.asUInt64 (name: "hbar_balance")

            return (id: id,
                    balance: balance,
                    deleted: "active" != status)
        }
        
        static internal func asTransactionHistoryWOC (json: JSON) -> [SystemClient.TransactionHistory]? {
            /*guard let tx_hash  = json.asString (name: "tx_hash_0"),
                  let height   = json.asUInt64 (name: "height_0")
            else {
                print ("SYS: BDB: API: ERROR in asTransactionHistory JSON: '\(json)'")
                return nil
            }

            return [(tx_hash: tx_hash, height: height)]*/
            
            let size = json.dict.count/2
            
            var json_array : [SystemClient.TransactionHistory] = []
            
            if size > 0 {
                for i in 0...(size-1) {
                    let tx_hash_  = json.asString (name: "tx_hash_\(i)") ?? "nil"
                    print("tx_hash_\(i): \(tx_hash_)")
                    let height_   = json.asUInt64 (name: "height_\(i)") ?? 0
                    json_array.append((tx_hash: tx_hash_, height: height_))
                }
            }
            
            return json_array
            
        }
        
        /*public typealias HistoryByAddress = (tx_hash: String, height: Int64)
        
        static internal func asJSON (history: HistoryByAddress) -> JSON.Dict {
            return [
                "tx_hash"   : history.tx_hash,
                "height" : history.height
            ]
        }*/

    } // End of Model

    public func getBlockchains (mainnet: Bool? = nil, completion: @escaping (Result<[SystemClient.Blockchain],SystemClientError>) -> Void) {
        let queryKeys = [
            mainnet.map { (_) in "testnet" },
            "verified"]
            .compactMap { $0 } // Remove `nil` from blockchainId

        let queryVals: [String] = [
            mainnet.map { (!$0).description },
            "true"]
            .compactMap { $0 }  // Remove `nil` from blockchainId

        bdbMakeRequest (path: "blockchains", query: zip (queryKeys, queryVals)) {
            (more: URL?, res: Result<[JSON], SystemClientError>) in
            precondition (nil == more)
            completion (res.flatMap {
                WhatsOnChainSystemClient.getManyExpected(data: $0, transform: Model.asBlockchain)
            })
        }
    }

    public func getBlockchain (blockchainId: String, completion: @escaping (Result<SystemClient.Blockchain,SystemClientError>) -> Void) {
        //bdbMakeRequest(path: "v1/bsv/\(blockchainId)/chain/info", query: zip(["verified"], ["true"]), embedded: false) {
        bdbMakeRequest(path: "v1/bsv/\(blockchainId)/chain/info", query: nil, embedded: false) {
        //bdbMakeRequest(path: "v1/bsv/main/chain/info", query: nil, embedded: false) { //FIXME!!!!!
            (more: URL?, res: Result<[JSON], SystemClientError>) in
            precondition (nil == more)
            completion (res.flatMap {
                //WhatsOnChainSystemClient.getOneExpected (id: blockchainId, data: $0, transform: Model.asBlockchain)
                WhatsOnChainSystemClient.getOneExpected (id: blockchainId, data: $0, transform: Model.asBlockchainWOC)
            })
        }
    }

    public func getCurrencies (blockchainId: String? = nil, mainnet: Bool = true, completion: @escaping (Result<[SystemClient.Currency],SystemClientError>) -> Void) {
        let results = ChunkedResults (queue: self.queue,
                                      transform: Model.asCurrency,
                                      completion: completion,
                                      resultsExpected: 1)

        func handleResult (more: URL?, result: Result<[JSON], SystemClientError>) {
            results.extend (result)

            // If `more` and no `error`, make a followup request
            if let url = more, !results.completed {
                self.bdbMakeRequest (url: url,
                                     embedded: true,
                                     embeddedPath: "currencies",
                                     completion: handleResult)
            }

                // Otherwise, we completed one.
            else {
                results.extendedOne()
            }
        }

        let queryKeysBase = [
            blockchainId.map { (_) in "blockchain_id" },
            "testnet",
            "verified"]
            .compactMap { $0 } // Remove `nil` from blockchainId

        let queryValsBase: [String] = [
            blockchainId,
            (!mainnet).description,
            "true"]
            .compactMap { $0 }  // Remove `nil` from blockchainId

        bdbMakeRequest (path: "currencies",
                        query: zip (queryKeysBase, queryValsBase),
                        completion: handleResult)
    }

    public func getCurrency (currencyId: String, completion: @escaping (Result<SystemClient.Currency,SystemClientError>) -> Void) {
        bdbMakeRequest (path: "currencies/\(currencyId)", query: nil, embedded: false) {
            (more: URL?, res: Result<[JSON], SystemClientError>) in
            precondition (nil == more)
            completion (res.flatMap {
                WhatsOnChainSystemClient.getOneExpected(id: currencyId, data: $0, transform: Model.asCurrency)
            })
        }
    }

    /// Subscription

    internal func makeSubscriptionRequest (path: String, data: JSON.Dict?, httpMethod: String,
                                           completion: @escaping (Result<SystemClient.Subscription, SystemClientError>) -> Void) {
        makeRequest (bdbDataTaskFunc, bdbBaseURL,
                     path: path,
                     query: nil,
                     data: data,
                     httpMethod: httpMethod) {
                        (res: Result<JSON.Dict, SystemClientError>) in
                        completion (res.flatMap {
                            Model.asSubscription(json: JSON(dict: $0))
                                .map { Result.success ($0) }
                                ?? Result.failure(SystemClientError.badResponse("Missed Subscription"))
                        })
        }
    }

    public func getSubscriptions (completion: @escaping (Result<[SystemClient.Subscription], SystemClientError>) -> Void) {
        bdbMakeRequest (path: "subscriptions", query: nil, embedded: true) {
            (more: URL?, res: Result<[JSON], SystemClientError>) in
            completion (res.flatMap {
                WhatsOnChainSystemClient.getManyExpected(data: $0, transform: Model.asSubscription)
            })
        }
    }

    public func getSubscription (id: String, completion: @escaping (Result<SystemClient.Subscription, SystemClientError>) -> Void) {
        bdbMakeRequest (path: "subscriptions/\(id)", query: nil, embedded: false) {
            (more: URL?, res: Result<[JSON], SystemClientError>) in
            precondition (nil == more)
            completion (res.flatMap {
                WhatsOnChainSystemClient.getOneExpected (id: id, data: $0, transform: Model.asSubscription)
            })
        }
    }

    public func getOrCreateSubscription (_ subscription: SystemClient.Subscription,
                                         completion: @escaping (Result<SystemClient.Subscription, SystemClientError>) -> Void) {
        getSubscription(id: subscription.id) {
            (res: Result<SystemClient.Subscription, SystemClientError>) in
            if case .success = res { completion (res) }
            else {
                self.createSubscription (subscription, completion: completion)
            }
        }
    }

    public func createSubscription (_ subscription: SystemClient.Subscription, // TODO: Hackily
                                    completion: @escaping (Result<SystemClient.Subscription, SystemClientError>) -> Void) {
        makeSubscriptionRequest (
            path: "subscriptions",
            data: [
                // We can not use asJSON(Subscription) because that will include the 'id'
                "device_id"       : subscription.device,
                "endpoint"        : BlocksetSystemClient.Model.asJSON (subscriptionEndpoint: subscription.endpoint),
                "currencies"      : subscription.currencies.map { BlocksetSystemClient.Model.asJSON (subscriptionCurrency: $0) }],
            httpMethod: "POST",
            completion: completion)
    }

    public func updateSubscription (_ subscription: SystemClient.Subscription, completion: @escaping (Result<SystemClient.Subscription, SystemClientError>) -> Void) {
        makeSubscriptionRequest (
            path: "subscriptions/\(subscription.id )",
            data: Model.asJSON (subscription: subscription),
            httpMethod: "PUT",
            completion: completion)
    }

    public func deleteSubscription (id: String, completion: @escaping (Result<Void, SystemClientError>) -> Void) {
        let path = "subscriptions/\(id)"
        makeRequest (bdbDataTaskFunc, bdbBaseURL,
                     path: path,
                     query: nil,
                     data: nil,
                     httpMethod: "DELETE",
                     deserializer: { (data: Data?) in
                        return (nil == data || 0 == data!.count 
                            ? Result.success (())
                            : Result.failure (SystemClientError.badResponse ("Unexpected Data on DELETE"))) },
                     completion: completion)
    }

    // Transfers

    static let ADDRESS_COUNT = 50
    static let DEFAULT_MAX_PAGE_SIZE = 20

    private func canonicalAddresses (_ addresses: [String], _ blockchainId: String) -> [String] {
        guard let type = Network.getTypeFromName (name: blockchainId)
            else { return addresses }

        switch type {
        case .eth:
            return addresses.map { $0.lowercased() }
        default:
            return addresses
        }
    }

    public func getTransfers (blockchainId: String,
                              addresses: [String],
                              begBlockNumber: UInt64,
                              endBlockNumber: UInt64,
                              maxPageSize: Int? = nil,
                              completion: @escaping (Result<[SystemClient.Transfer], SystemClientError>) -> Void) {
        precondition(!addresses.isEmpty, "Empty `addresses`")
        let chunkedAddresses = canonicalAddresses(addresses, blockchainId)
            .chunked(into: BlocksetSystemClient.ADDRESS_COUNT)

        let results = ChunkedResults (queue: self.queue,
                                      transform: Model.asTransfer,
                                      completion: completion,
                                      resultsExpected: chunkedAddresses.count)

        func handleResult (more: URL?, result: Result<[JSON], SystemClientError>) {
            results.extend (result)

            // If `more` and no `error`, make a followup request
            if let url = more, !results.completed {
                self.bdbMakeRequest (url: url,
                                     embedded: true,
                                     embeddedPath: "transfers",
                                     completion: handleResult)
            }

            // Otherwise, we completed one.
            else {
                results.extendedOne()
            }
        }

        let maxPageSize = maxPageSize ?? BlocksetSystemClient.DEFAULT_MAX_PAGE_SIZE

        for addresses in chunkedAddresses {
            let queryKeys = ["blockchain_id",
                             "start_height",
                             "end_height",
                             "merge_currencies",
                             "max_page_size"] + Array (repeating: "address", count: addresses.count)

            let queryVals = [blockchainId,
                             begBlockNumber.description,
                             endBlockNumber.description,
                             "true", 
                             maxPageSize.description] + addresses

            self.bdbMakeRequest (path: "transfers",
                                 query: zip (queryKeys, queryVals),
                                 completion: handleResult)
        }
    }

    public func getTransfer (transferId: String, completion: @escaping (Result<SystemClient.Transfer, SystemClientError>) -> Void) {
        bdbMakeRequest (path: "transfers/\(transferId)", query: zip(["merge_currencies"], ["true"]), embedded: false) {
            (more: URL?, res: Result<[JSON], SystemClientError>) in
            precondition (nil == more)
            completion (res.flatMap {
                WhatsOnChainSystemClient.getOneExpected (id: transferId, data: $0, transform: Model.asTransfer)
            })
        }
    }
    
    public func getTransactionHistory (blockchainId: String, address: String, completion: @escaping (Result<[SystemClient.TransactionHistory], SystemClientError>) -> Void) {
        bdbMakeRequest_(path: "v1/bsv/\(blockchainId)/address/\(address)/history", query: nil, embedded: false) {
        //bdbMakeRequest_(path: "v1/bsv/main/address/\(address)/history", query: nil, embedded: false) { //FIXME!!!
            (more: URL?, res: Result<[JSON], SystemClientError>) in
            precondition (nil == more)
            completion(res.flatMap {
                WhatsOnChainSystemClient.getManyExpected_ (data: $0, transform: Model.asTransactionHistoryWOC)
            })
        }
    }
    
    public func getTransactionWOC (blockchainId: String, tx_hash: String, completion: @escaping (Result<[SystemClient.Transaction], SystemClientError>) -> Void) {
        //bdbMakeRequest(path: "v1/bsv/\(blockchainId)/chain/info", query: zip(["verified"], ["true"]), embedded: false) {
        bdbMakeRequest(path: "v1/bsv/\(blockchainId)/tx/hash/\(tx_hash)", query: nil, embedded: false) {
            (more: URL?, res: Result<[JSON], SystemClientError>) in
            precondition (nil == more)
            completion(res.flatMap {
                //WhatsOnChainSystemClient.getOneExpected (id: blockchainId, data: $0, transform: Model.asBlockchain)
                WhatsOnChainSystemClient.getManyExpected (data: $0, transform: Model.asTransactionWOC)
            })
        }
    }

    // Transactions
    
    public func getTransactions__ (blockchainId: String,
                                addresses: [String],
                                begBlockNumber: UInt64? = nil,
                                endBlockNumber: UInt64? = nil,
                                includeRaw: Bool = false,
                                includeProof: Bool = false,
                                includeTransfers: Bool = true,
                                maxPageSize: Int? = nil,
                                completion: @escaping (Result<SystemClient.Transaction,SystemClientError>) -> Void) {
        precondition(!addresses.isEmpty, "Empty `addresses`")
        
        bdbMakeRequest(path: "v1/bsv/\(blockchainId)/chain/info", query: nil, embedded: false) {
            (more: URL?, res: Result<[JSON], SystemClientError>) in
            precondition (nil == more)
            completion (res.flatMap {
                //WhatsOnChainSystemClient.getOneExpected (id: blockchainId, data: $0, transform: Model.asBlockchain)
                WhatsOnChainSystemClient.getOneExpected (id: blockchainId, data: $0, transform: Model.asTransactionWOC)
            })
        }
    }

    public func getTransactions (blockchainId: String,
                                 addresses: [String],
                                 begBlockNumber: UInt64? = nil,
                                 endBlockNumber: UInt64? = nil,
                                 includeRaw: Bool = false,
                                 includeProof: Bool = false,
                                 includeTransfers: Bool = true,
                                 maxPageSize: Int? = nil,
                                 completion: @escaping (Result<[SystemClient.Transaction], SystemClientError>) -> Void) {
        precondition(!addresses.isEmpty, "Empty `addresses`")
        
        
        let chunkedAddresses = canonicalAddresses(addresses, blockchainId)
            .chunked(into: BlocksetSystemClient.ADDRESS_COUNT)
        
        for address_ in chunkedAddresses {
            print("address: \(address_)")
        }

        /*let results = ChunkedResults (queue: self.queue,
                                      transform: Model.asTransaction,
                                      completion: completion,
                                      resultsExpected: chunkedAddresses.count)
        
        func handleResult (more: URL?, result: Result<[JSON], SystemClientError>) {
            results.extend (result)

            // If `more` and no `error`, make a followup request
            if let url = more, !results.completed {
                self.bdbMakeRequest (url: url,
                                     embedded: true,
                                     embeddedPath: "transactions",
                                     completion: handleResult)
            }

                // Otherwise, we completed one.
            else {
                results.extendedOne()
            }
        }*/
        
        
        //let address = "mztdmgGKqvBcsHWyoTve5iUyydgdCXHvoG"
        let address = "mvR32p5C2G17LAYcaW1iwNGzfUGK7XcS2k"
        //let address = "msJuk1N8xZCkpEPiUC8wQwgkPn3et8TkC4" //RUN address
        //let address = "15822TVow39ZCdAepQkNhcnsDPczcdJjo9" //FIXME!!!
        //let address = "1GVsoAjjLhKezSBYsdKPhoHyakCPg1aWnT" //FIXME!!!
        //for address in addresses {
            print("blockchainId: \(blockchainId) address: \(address)")
        
            
        getTransactionHistory(blockchainId: blockchainId, address: address) {
            (res: Result<[SystemClient.TransactionHistory], SystemClientError>) in
            defer { print("Deferring")}
            res.resolve (
                success: {
                    //print("SYS: GetTransactionHistory: Success \($0[0].tx_hash)")
                    
                    var data_array: [JSON.Dict] = []
                    
                    for tx in $0 {
                    
                        
                     /*self.bdbMakeRequest(path: "v1/bsv/\(blockchainId)/tx/hash/\(tx.tx_hash)", query: nil, embedded: false) {
                        //self.bdbMakeRequest(path: "v1/bsv/main/tx/hash/\(tx.tx_hash)", query: nil, embedded: false) { //FIXME!!!
                            (more: URL?, res: Result<[JSON], SystemClientError>) in
                            precondition (nil == more)
                            completion(res.flatMap {
                                //WhatsOnChainSystemClient.getOneExpected (id: blockchainId, data: $0, transform: Model.asBlockchain)
                                WhatsOnChainSystemClient.getManyExpected (data: $0, transform: Model.asTransactionWOC)
                            })
                      }*/
                        
                        let session_ = URLSession (configuration: .default)
                        var request = URLRequest(url: URL(string: "https://api.whatsonchain.com/v1/bsv/\(blockchainId)/tx/hash/\(tx.tx_hash!)")!);
                        request.httpMethod = "GET"
                        
                        
                        var data_: JSON.Dict?
                            
                        let semaphore: DispatchSemaphore = DispatchSemaphore(value: 0)
                            //let task = URLSession.shared.dataTask(with: request) { (data, response, error) in
                        let task = WhatsOnChainSystemClient.defaultDataTaskFuncSetJSON (session_, request, data_) { (data, res, error) in
                                do {
                                    let json = try JSONSerialization.jsonObject(with: data!, options: []) as? JSON.Dict
                                    print("Stop")
                                    data_ = json
                                } catch let error as NSError {
                                    print(error.localizedDescription)
                                }
                                semaphore.signal()
                            }
                            task.resume()
                            semaphore.wait()
                        
                        data_array.append(data_!)
                        print("Stop")
                        
                    }
                    completion(
                        WhatsOnChainSystemClient.getManyExpected__ (data: data_array, transform: Model.asTransactionWOC)
                    )
                    
                        
                },
                failure: { (e) in
                    print ("SYS: GetTransactionHistory: Error: \(e)")

                })
            }
        
            
            /*bdbMakeRequest(path: "v1/bsv/\(blockchainId)/address/\(address)/history", query: nil, embedded: false) {
                (more: URL?, res: Result<[JSON], SystemClientError>) in
                precondition (nil == more)
                res.flatMap {
                    WhatsOnChainSystemClient.getManyExpected (data: $0, transform: Model.asTransactionHistoryWOC)
                }
            }*/
            
        //}
        
        
        
        /*let chunkedAddresses = canonicalAddresses(addresses, blockchainId)
            .chunked(into: BlocksetSystemClient.ADDRESS_COUNT)

        let results = ChunkedResults (queue: self.queue,
                                      transform: Model.asTransaction,
                                      completion: completion,
                                      resultsExpected: chunkedAddresses.count)

        func handleResult (more: URL?, result: Result<[JSON], SystemClientError>) {
            results.extend (result)

            // If `more` and no `error`, make a followup request
            if let url = more, !results.completed {
                self.bdbMakeRequest (url: url,
                                     embedded: true,
                                     embeddedPath: "transactions",
                                     completion: handleResult)
            }

                // Otherwise, we completed one.
            else {
                results.extendedOne()
            }
        }

        let maxPageSize = maxPageSize ?? ((includeTransfers ? 1 : 3) * BlocksetSystemClient.DEFAULT_MAX_PAGE_SIZE)

        let queryKeysBase = [
            "blockchain_id",
            begBlockNumber.map { (_) in "start_height" },
            endBlockNumber.map { (_) in "end_height" },
            "merge_currencies",
            "include_proof",
            "include_raw",
            "include_transfers",
            "include_calls",
            "max_page_size"]
            .compactMap { $0 } // Remove `nil` from {beg,end}BlockNumber

        let queryValsBase: [String] = [
            blockchainId,
            begBlockNumber.map { $0.description },
            endBlockNumber.map { $0.description },
            "true",  // merge_currencies
            includeProof.description,
            includeRaw.description,
            includeTransfers.description,
            "false",
            maxPageSize.description]
            .compactMap { $0 }  // Remove `nil` from {beg,end}BlockNumber

        for addresses in chunkedAddresses {
            let queryKeys = queryKeysBase + Array (repeating: "address", count: addresses.count)
            let queryVals = queryValsBase + addresses

            // Make the first request.  Ideally we'll get all the transactions in one gulp
            self.bdbMakeRequest (path: "transactions",
                                 query: zip (queryKeys, queryVals),
                                 completion: handleResult)
        }
        */
    }
    
    //Original
    public func _getTransactions (blockchainId: String,
                                 addresses: [String],
                                 begBlockNumber: UInt64? = nil,
                                 endBlockNumber: UInt64? = nil,
                                 includeRaw: Bool = false,
                                 includeProof: Bool = false,
                                 includeTransfers: Bool = true,
                                 maxPageSize: Int? = nil,
                                 completion: @escaping (Result<[SystemClient.Transaction], SystemClientError>) -> Void) {
        precondition(!addresses.isEmpty, "Empty `addresses`")
        let chunkedAddresses = canonicalAddresses(addresses, blockchainId)
            .chunked(into: BlocksetSystemClient.ADDRESS_COUNT)

        let results = ChunkedResults (queue: self.queue,
                                      transform: Model.asTransaction,
                                      completion: completion,
                                      resultsExpected: chunkedAddresses.count)

        func handleResult (more: URL?, result: Result<[JSON], SystemClientError>) {
            results.extend (result)

            // If `more` and no `error`, make a followup request
            if let url = more, !results.completed {
                self.bdbMakeRequest (url: url,
                                     embedded: true,
                                     embeddedPath: "transactions",
                                     completion: handleResult)
            }

                // Otherwise, we completed one.
            else {
                results.extendedOne()
            }
        }

        let maxPageSize = maxPageSize ?? ((includeTransfers ? 1 : 3) * BlocksetSystemClient.DEFAULT_MAX_PAGE_SIZE)

        let queryKeysBase = [
            "blockchain_id",
            begBlockNumber.map { (_) in "start_height" },
            endBlockNumber.map { (_) in "end_height" },
            "merge_currencies",
            "include_proof",
            "include_raw",
            "include_transfers",
            "include_calls",
            "max_page_size"]
            .compactMap { $0 } // Remove `nil` from {beg,end}BlockNumber

        let queryValsBase: [String] = [
            blockchainId,
            begBlockNumber.map { $0.description },
            endBlockNumber.map { $0.description },
            "true",  // merge_currencies
            includeProof.description,
            includeRaw.description,
            includeTransfers.description,
            "false",
            maxPageSize.description]
            .compactMap { $0 }  // Remove `nil` from {beg,end}BlockNumber

        for addresses in chunkedAddresses {
            let queryKeys = queryKeysBase + Array (repeating: "address", count: addresses.count)
            let queryVals = queryValsBase + addresses

            // Make the first request.  Ideally we'll get all the transactions in one gulp
            self.bdbMakeRequest (path: "transactions",
                                 query: zip (queryKeys, queryVals),
                                 completion: handleResult)
        }
    }

    public func getTransaction (transactionId: String,
                                includeRaw: Bool = false,
                                includeProof: Bool = false,
                                completion: @escaping (Result<SystemClient.Transaction, SystemClientError>) -> Void) {
        let queryKeys = ["include_proof", "include_raw", "merge_currencies"]
        let queryVals = [includeProof.description, includeRaw.description, "true"]

        bdbMakeRequest (path: "transactions/\(transactionId)", query: zip (queryKeys, queryVals), embedded: false) {
            (more: URL?, res: Result<[JSON], SystemClientError>) in
            precondition (nil == more)
            completion (res.flatMap {
                WhatsOnChainSystemClient.getOneExpected (id: transactionId, data: $0, transform: Model.asTransaction)
            })
        }
    }

    public func createTransaction (blockchainId: String,
                                   transaction: Data,
                                   identifier: String?,
                                   completion: @escaping (Result<TransactionIdentifier, SystemClientError>) -> Void) {
        let data            = transaction.base64EncodedString()
        let json: JSON.Dict = [
            "blockchain_id"  : blockchainId,
            "submit_context" : "WalletKit:\(blockchainId):\(identifier ?? "Data:\(String(data.prefix(20)))")",
            "data"           : transaction.base64EncodedString()
        ]

        makeRequest (bdbDataTaskFunc, bdbBaseURL,
                     path: "/transactions",
                     data: json,
                     httpMethod: "POST") {
            self.bdbHandleResult ($0, embedded: false, embeddedPath: "") {
                (more: URL?, res: Result<[JSON], SystemClientError>) in
                precondition(nil == more)
                completion (res.flatMap {
                    WhatsOnChainSystemClient.getOneExpected (id: "POST /transactions",
                                                         data: $0,
                                                         transform: Model.asTransactionIdentifier)
                })
            }
        }
    }

    public func estimateTransactionFee (blockchainId: String,
                                        transaction: Data,
                                        completion: @escaping (Result<SystemClient.TransactionFee, SystemClientError>) -> Void) {
        let data            = transaction.base64EncodedString()
        let json: JSON.Dict = [
            "blockchain_id"  : blockchainId,
            "submit_context" : "WalletKit:\(blockchainId):Data:\(String(data.prefix(20))) (FeeEstimate)",
            "data"           : data
        ]

        makeRequest (bdbDataTaskFunc, bdbBaseURL,
                     path: "/transactions",
                     query: zip(["estimate_fee"], ["true"]),
                     data: json,
                     httpMethod: "POST") {
                        self.bdbHandleResult ($0, embedded: false, embeddedPath: "") {
                            (more: URL?, res: Result<[JSON], SystemClientError>) in
                            precondition (nil == more)
                            completion (res.flatMap {
                                WhatsOnChainSystemClient.getOneExpected (id: "POST /transactions?estimate_fee",
                                                             data: $0,
                                                             transform: Model.asTransactionFee)
                            })
                        }
        }
    }

    // Blocks

    public func getBlocks (blockchainId: String,
                           begBlockNumber: UInt64 = 0,
                           endBlockNumber: UInt64 = 0,
                           includeRaw: Bool = false,
                           includeTx: Bool = false,
                           includeTxRaw: Bool = false,
                           includeTxProof: Bool = false,
                           maxPageSize: Int? = nil,
                           completion: @escaping (Result<[SystemClient.Block], SystemClientError>) -> Void) {

        let results = ChunkedResults (queue: self.queue,
                                      transform: Model.asBlock,
                                      completion: completion,
                                      resultsExpected: 1)

        func handleResult (more: URL?, result: Result<[JSON], SystemClientError>) {
            results.extend (result)

            // If `more` and no `error`, make a followup request
            if let url = more, !results.completed {
                self.bdbMakeRequest (url: url,
                                     embedded: true,
                                     embeddedPath: "blocks",
                                     completion: handleResult)
            }

                // Otherwise, we completed one.
            else {
                results.extendedOne()
            }
        }

        var queryKeys = ["blockchain_id",
                         "start_height",
                         "end_height",
                         "include_raw",
                         "include_tx",
                         "include_tx_raw",
                         "include_tx_proof",
                         "merge_currencies"]

        var queryVals = [blockchainId,
                         begBlockNumber.description,
                         endBlockNumber.description,
                         includeRaw.description,
                         includeTx.description,
                         includeTxRaw.description,
                         includeTxProof.description,
                         "true"]

        if let maxPageSize = maxPageSize {
            queryKeys += ["max_page_size"]
            queryVals += [String(maxPageSize)]
        }

        self.bdbMakeRequest (path: "blocks",
                             query: zip (queryKeys, queryVals),
                             completion: handleResult)
    }

    public func getBlock (blockId: String,
                          includeRaw: Bool = false,
                          includeTx: Bool = false,
                          includeTxRaw: Bool = false,
                          includeTxProof: Bool = false,
                          completion: @escaping (Result<SystemClient.Block, SystemClientError>) -> Void) {
        let queryKeys = ["include_raw", 
                         "include_tx", 
                         "include_tx_raw", 
                         "include_tx_proof",
                         "merge_currencies"]

        let queryVals = [includeRaw.description, 
                         includeTx.description, 
                         includeTxRaw.description, 
                         includeTxProof.description,
                         "true"]

        bdbMakeRequest (path: "blocks/\(blockId)", query: zip (queryKeys, queryVals), embedded: false) {
            (more: URL?, res: Result<[JSON], SystemClientError>) in
            precondition (nil == more)
            completion (res.flatMap {
                WhatsOnChainSystemClient.getOneExpected (id: blockId, data: $0, transform: Model.asBlock)
            })
        }
    }

    // Address

    public func getAddresses (blockchainId: String, publicKey: String,
                              completion: @escaping (Result<[SystemClient.Address],SystemClientError>) -> Void) {
        let queryKeys = ["blockchain_id", "public_key"]
        let queryVals = [ blockchainId,    publicKey]

        bdbMakeRequest (path: "addresses", query: zip (queryKeys, queryVals)) {
            (more: URL?, res: Result<[JSON], SystemClientError>) in
            precondition (nil == more)
            completion (res.flatMap {
                WhatsOnChainSystemClient.getManyExpected(data: $0, transform: Model.asAddress)
            })
        }
    }

    public func getAddress (blockchainId: String, address: String, timestamp: UInt64? = nil,
                            completion: @escaping (Result<SystemClient.Address,SystemClientError>) -> Void) {
        let queryKeys = ["blockchain_id", timestamp.map { (ignore) in "timestamp" }].compactMap { $0 }
        let queryVals = [ blockchainId,   timestamp?.description].compactMap { $0 }

        bdbMakeRequest (path: "addresses/\(address)", query: zip (queryKeys, queryVals), embedded: false) {
            (more: URL?, res: Result<[JSON], SystemClientError>) in
            precondition (nil == more)
            completion (res.flatMap {
                WhatsOnChainSystemClient.getOneExpected(id: address, data: $0, transform: Model.asAddress)
            })
        }
    }

    public func createAddress (blockchainId: String, data: Data,
                               completion: @escaping (Result<SystemClient.Address, SystemClientError>) -> Void) {
        let json: JSON.Dict = [
            "blockchain_id": blockchainId,
            "data" : data.base64EncodedString()
        ]

        makeRequest (bdbDataTaskFunc, bdbBaseURL,
                     path: "/addresses",
                     data: json,
                     httpMethod: "POST") {
                        self.bdbHandleResult ($0, embedded: false, embeddedPath: "") {
                            (more: URL?, res: Result<[JSON], SystemClientError>) in
                            precondition (nil == more)
                            completion (res.flatMap {
                                WhatsOnChainSystemClient.getOneExpected (id: "POST /addresses",
                                                             data: $0,
                                                             transform: Model.asAddress)
                            })
                        }
        }
    }

    // Experimental - Hedera Account Creation

    private func canonicalizePublicKey (_ publicKey: String) -> String {
        return publicKey.starts(with: "0x") || publicKey.starts(with: "0X")
            ? String (publicKey.dropFirst (2))
            : publicKey
    }

    private func getHederaAccount (blockchainId: String,
                                   publicKey: String,
                                   transactionId: String,
                                   completion: @escaping (Result<[SystemClient.HederaAccount],SystemClientError>) -> Void) {
        // We don't actually use the `transactionID` through the `GET .../account_transactions`
        // endpoint.  It is more direct to just repeatedly "GET .../accounts"
        // let path = "/_experimental/hedera/account_transactions/\(blockchainId):\(transactionId)"
        let noDataFailure = Result<[SystemClient.HederaAccount],SystemClientError>.failure(SystemClientError.badResponse("No Data"))

        let initialDelayInSeconds  = 2
        let retryPeriodInSeconds   = 5
        let retryDurationInSeconds = 4 * 60
        var retriesRemaining = (retryDurationInSeconds / retryPeriodInSeconds) - 1

        func handleResult (res: Result<[SystemClient.HederaAccount], SystemClientError>) {
            // On a Result with a SystemClientError just assume there is no account... and try again.
            let accounts = res.getWithRecovery { (_) in return [] }

            if accounts.count > 0 { completion (Result.success (accounts)) }
            else {
                guard retriesRemaining > 0
                    else { completion (noDataFailure); return }

                retriesRemaining -= 1
                let deadline = DispatchTime (uptimeNanoseconds: DispatchTime.now().uptimeNanoseconds + UInt64(1_000_000_000 * retryPeriodInSeconds))
                self.queue.asyncAfter (deadline: deadline) {
                    self.getHederaAccount(blockchainId: blockchainId,
                                          publicKey: publicKey,
                                          completion: handleResult)
                }
            }
        }

        let deadline = DispatchTime (uptimeNanoseconds: DispatchTime.now().uptimeNanoseconds + UInt64(1_000_000_000 * initialDelayInSeconds))
        self.queue.asyncAfter (deadline: deadline) {
            self.getHederaAccount(blockchainId: blockchainId,
                             publicKey: publicKey,
                             completion: handleResult)
        }
    }

    public func getHederaAccount (blockchainId: String,
                                  publicKey: String,
                                  completion: @escaping (Result<[SystemClient.HederaAccount], SystemClientError>) -> Void) {
        let queryKeys = ["blockchain_id", "pub_key"  ]
        let queryVals = [ blockchainId,    canonicalizePublicKey (publicKey) ]

        makeRequest (bdbDataTaskFunc, bdbBaseURL,
                     path: "/_experimental/hedera/accounts",
                     query: zip (queryKeys, queryVals),
                     data: nil,
                     httpMethod: "GET") {
                        (res: Result<JSON.Dict, SystemClientError>) in
                        self.bdbHandleResult (res, embeddedPath: "accounts") {
                            (ignore, res: Result<[WhatsOnChainSystemClient.JSON], SystemClientError>) in
                            completion (res.flatMap {
                                WhatsOnChainSystemClient.getManyExpected(data: $0, transform: Model.asHederaAccount)
                            })
                        }
        }
    }

    public func createHederaAccount (blockchainId: String,
                                     publicKey: String,
                                     completion: @escaping (Result<[SystemClient.HederaAccount], SystemClientError>) -> Void) {
        let noDataFailure = Result<[SystemClient.HederaAccount],SystemClientError>.failure(SystemClientError.badResponse("No Data"))

        let publicKey = canonicalizePublicKey (publicKey)

        let postData: JSON.Dict = [
            "blockchain_id": blockchainId,
            "pub_key": publicKey
        ]

        // Make a POST request to `/_experimental/hedera/accounts`.  On success a "transaction_id"
        // will be returned, in the JSON reponse data, that can be repeatedly queried for the
        // created AccountID.  On failure, if the POST produced a '422' status, then the AccountID
        // already exists and can be queried.
        makeRequest (bdbDataTaskFunc, bdbBaseURL,
                     path: "/_experimental/hedera/accounts",
                     data: postData,
                     httpMethod: "POST") {
                        (res: Result<JSON.Dict, SystemClientError>) in
                        switch res {
                        case .failure (let error):
                            // If a submission error (with HTTP status of 422), the Hedera accont
                            // already exists.  Just get it.
                            if case .submission (_, _) = error {
                                self.getHederaAccount (blockchainId: blockchainId,
                                                       publicKey: publicKey,
                                                       completion: completion)
                            }
                            else {
                                completion (Result.failure(error))
                            }
                        case .success (let dict ):
                            let json = JSON (dict: dict)

                            guard let transactionId = json.asString(name: "transaction_id")
                                else { completion (noDataFailure); return }

                            self.getHederaAccount (blockchainId: blockchainId,
                                                   publicKey: publicKey,
                                                   transactionId: transactionId,
                                                   completion: completion)
                        }
        }
    }

    /// BTC - nothing

    /// ETH

    /// The ETH JSON_RPC request identifier.
    var rid: UInt32 = 0

    /// Return the current request identifier and then increment it.
    var ridIncr: UInt32 {
        let rid = self.rid
        self.rid += 1
        return rid
    }

     static internal let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
        return formatter
    }()

    internal struct JSON {
        typealias Dict = [String:Any]

        let dict: Dict

        init (dict: Dict) {
            self.dict = dict
        }

        internal func asString (name: String) -> String? {
            return dict[name] as? String
        }

        internal func asBool (name: String) -> Bool? {
            return dict[name] as? Bool
        }

        internal func asInt64 (name: String) -> Int64? {
            return (dict[name] as? NSNumber)
                .flatMap { Int64 (exactly: $0)}
        }

        internal func asUInt64 (name: String) -> UInt64? {
            return (dict[name] as? NSNumber)
                .flatMap { UInt64 (exactly: $0)}
        }

        internal func asUInt32 (name: String) -> UInt32? {
            return (dict[name] as? NSNumber)
                .flatMap { UInt32 (exactly: $0)}
        }

        internal func asUInt8 (name: String) -> UInt8? {
            return (dict[name] as? NSNumber)
                .flatMap { UInt8 (exactly: $0)}
        }

        internal func asDate (name: String) -> Date? {
            return (dict[name] as? String)
                .flatMap { dateFormatter.date (from: $0) }
        }

        internal func asData (name: String) -> Data? {
            return (dict[name] as? String)
                .flatMap { Data (base64Encoded: $0)! }
        }

        internal func asArray (name: String) -> [Dict]? {
            return dict[name] as? [Dict]
        }

        internal func asDict (name: String) -> Dict? {
            return dict[name] as? Dict
        }

        internal func asStringArray (name: String) -> [String]? {
            return dict[name] as? [String]
        }

        internal func asJSON (name: String) -> JSON? {
            return asDict(name: name).map { JSON (dict: $0) }
        }

        internal func asJSONArray (name: String) -> [JSON]? {
            return asArray(name: name)?.map { JSON (dict: $0) }
        }

        internal func asArrayMapped<T> (name: String, transform: (JSON) -> T?) -> [T]? {
            guard let result = asJSONArray(name: name)?.map (transform)
            else { return nil }

            let resultCompacted = result.compactMap { $0 }
            return result.count != resultCompacted.count ? nil : resultCompacted
        }
    }

    private static func deserializeAsJSON<T> (_ data: Data?) -> Result<T, SystemClientError> {
        guard let data = data else {
            return Result.failure (SystemClientError.badResponse("No Data"));
        }

        do {
            guard let json = try JSONSerialization.jsonObject(with: data, options: []) as? T
                else {
                    let dataString = data.map { String(format: "%c", $0) }.joined()
                    print ("SYS: BDB:API: ERROR: JSON.Dict: '\(dataString)'")
                    return Result.failure(SystemClientError.badResponse("JSON Parse: '\(dataString)'")) }

            return Result.success (json)
        }
        catch let jsonError as NSError {
            let dataString = data.map { String(format: "%c", $0) }.joined()
            let warnString = "JSON.Error: '\(jsonError.description)'; Data: '\(dataString)'"
            print ("SYS: BDB:API: ERROR: \(warnString)")
            return Result.failure (SystemClientError.badResponse(warnString))
        }
    }

    
    //private static func deserializeAsJSON_<T> (_ data: Data?) -> Result<T, SystemClientError> {
    private static func deserializeAsJSON_ (_ data: Data?) -> Result<JSON.Dict, SystemClientError> {
        guard let data = data else {
            return Result.failure (SystemClientError.badResponse("No Data"));
        }
        
        
        do {
            //guard let json = try JSONSerialization.jsonObject(with: data, options: []) as? T
            let json = try JSONSerialization.jsonObject(with: data, options: [])
            /*else {
                    let dataString = data.map { String(format: "%c", $0) }.joined()
                    print ("SYS: BDB:API: ERROR: JSON.Dict: '\(dataString)'")
                    return Result.failure(SystemClientError.badResponse("JSON Parse: '\(dataString)'")) }*/
            
            var count = 0
            //var json_array : [JSON.Dict] = []
            var json_dict : JSON.Dict = [:]
            for anItem in json as! [Dictionary<String, AnyObject>] {
                let txhash = anItem["tx_hash"] as! String
                let height = anItem["height"] as! Int64
                //var json_item : JSON.Dict = [ "tx_hash_\(count)": txhash, "height_\(count)": height ]
                //var json_item : JSON.Dict = [ "tx_hash": txhash, "height": height ]
                json_dict["tx_hash_\(count)"] = txhash
                json_dict["height_\(count)"] = height
                //json_array.append(json_item)
                count += 1
            }
            //return Result.success(json_array)
            return Result.success(json_dict)
            //return Result.success (json)
        }
        catch let jsonError as NSError {
            let dataString = data.map { String(format: "%c", $0) }.joined()
            let warnString = "JSON.Error: '\(jsonError.description)'; Data: '\(dataString)'"
            print ("SYS: BDB:API: ERROR: \(warnString)")
            return Result.failure (SystemClientError.badResponse(warnString))
        }
        
        /*do {
            //guard let json = try JSONSerialization.jsonObject(with: data, options: []) as? T
            guard let json = try JSONSerialization.jsonObject(with: data, options: []) as? JSON.Dict
            else {
                    let dataString = data.map { String(format: "%c", $0) }.joined()
                    print ("SYS: BDB:API: ERROR: JSON.Dict: '\(dataString)'")
                    return Result.failure(SystemClientError.badResponse("JSON Parse: '\(dataString)'")) }

            return Result.success (json)
        }
        catch let jsonError as NSError {
            let dataString = data.map { String(format: "%c", $0) }.joined()
            let warnString = "JSON.Error: '\(jsonError.description)'; Data: '\(dataString)'"
            print ("SYS: BDB:API: ERROR: \(warnString)")
            return Result.failure (SystemClientError.badResponse(warnString))
        }*/
    }

    private func sendRequest<T> (_ request: URLRequest,
                                 _ dataTaskFunc: DataTaskFunc,
                                 _ responseSuccess: [Int],
                                 deserializer: @escaping (_ data: Data?) -> Result<T, SystemClientError>,
                                 completion: @escaping (Result<T, SystemClientError>) -> Void) {
        dataTaskFunc (session, request) { (data, res, error) in
            guard nil == error else {
                var sce: SystemClientError = SystemClientError.badResponse ("General Error: \(String (reflecting: error))")
                let error = error! as NSError

                if error.domain == NSURLErrorDomain {
                    switch error.code {
                    case NSURLErrorCannotFindHost,
                        NSURLErrorCannotConnectToHost,
                        NSURLErrorRedirectToNonExistentLocation:
                        sce = SystemClientError.unavailable

                    case NSURLErrorTimedOut,
                        NSURLErrorNetworkConnectionLost,
                        NSURLErrorDNSLookupFailed,
                        NSURLErrorNotConnectedToInternet:
                        sce = SystemClientError.lostConnectivity

                    default: break
                    }
                }

                completion (Result.failure(sce))
                return
            }

            guard let res = res as? HTTPURLResponse else {
                completion (Result.failure (SystemClientError.badResponse ("Expected HTTP URL Response")))
                return
            }

            guard responseSuccess.contains(res.statusCode) else {
                // Try to parse the `data` as JSON
                let json = data.flatMap { try? JSONSerialization.jsonObject(with: $0, options: []) as? [String:Any] }

                var respError: SystemClientError!

                switch (res.statusCode) {
                case 400, 404: respError = SystemClientError.badRequest ("Resource Not Found")
                case 403:      respError = SystemClientError.permission
                case 429:      respError = SystemClientError.resource
                case 500, 504: respError = SystemClientError.badResponse ("Submission Status Error: \(res.statusCode)")
                case 422:
                    // We expect `json` with more information about the error
                    let status = json.flatMap { JSON (dict: $0) }.flatMap { $0.asString (name: "submit_status") }

                    if nil == data {
                        respError = SystemClientError.badResponse ("Submission Status Error: No 'data' Provided")
                    }
                    else if nil == status {
                        let dataString = data!.map { String(format: "%c", $0) }.joined()
                        respError = SystemClientError.badResponse ("Submission Status Error: No 'submit_status': \(dataString)")
                    }
                    else {
                        let submitDetails = json.flatMap { JSON (dict: $0) }.flatMap { $0.asString (name: "network_message") }
                        ?? "Submission Status Error: Missed 'network_message': \(data!.map { String(format: "%c", $0) }.joined())"

                        var submitError: SystemClientSubmissionError!
                        switch (status!) {
                        case "success":                       submitError = .unknown // unexpected "success" on 422
                        case "error_internal":                fallthrough
                        case "error_unknown":                 submitError = .unknown
                        case "error_transaction_invalid":     submitError = .transaction
                        case "error_transaction_expired":     submitError = .transactionExpired
                        case "error_transaction_duplicate":   submitError = .transactionDuplicate
                        case "error_signature_invalid":       submitError = .signature

                        case "error_nonce_invalid":           submitError = .nonceInvalid
                        case "error_nonce_used":              submitError = .nonceTooLow
                        case "error_nonce_gap":               submitError = .nonceInvalid

                        case "error_fee_insufficient":        submitError = .insufficientFee
                        case "error_fee_rate_insufficient":   submitError = .insufficientNetworkFee
                        case "error_fee_budget_insufficient": submitError = .insufficientNetworkCostUnit

                        case "error_balance_insufficient":    submitError = .insufficientBalance
                        case "error_account_unknown":         submitError = .account
                        default:                              submitError = .unknown
                        }
                        respError = SystemClientError.submission(error: submitError, details: submitDetails)
                    }
                default:
                    respError = SystemClientError.badResponse("Submission Status Error: Unrecognized Status Code: \(res.statusCode)")
                }

                completion (Result.failure(respError))
                return
            }

            completion (deserializer (data))
            }.resume()
    }
    
    private func sendRequest_<T> (_ request: URLRequest,
                                 _ dataTaskFunc: DataTaskFunc,
                                 _ responseSuccess: [Int],
                                 deserializer: @escaping (_ data: Data?) -> Result<T, SystemClientError>,
                                 completion: @escaping (Result<T, SystemClientError>) -> Void) {
        dataTaskFunc (session, request) { (data, res, error) in
            guard nil == error else {
                var sce: SystemClientError = SystemClientError.badResponse ("General Error: \(String (reflecting: error))")
                let error = error! as NSError

                if error.domain == NSURLErrorDomain {
                    switch error.code {
                    case NSURLErrorCannotFindHost,
                        NSURLErrorCannotConnectToHost,
                        NSURLErrorRedirectToNonExistentLocation:
                        sce = SystemClientError.unavailable

                    case NSURLErrorTimedOut,
                        NSURLErrorNetworkConnectionLost,
                        NSURLErrorDNSLookupFailed,
                        NSURLErrorNotConnectedToInternet:
                        sce = SystemClientError.lostConnectivity

                    default: break
                    }
                }

                completion (Result.failure(sce))
                return
            }

            guard let res = res as? HTTPURLResponse else {
                completion (Result.failure (SystemClientError.badResponse ("Expected HTTP URL Response")))
                return
            }

            guard responseSuccess.contains(res.statusCode) else {
                // Try to parse the `data` as JSON
                let json = data.flatMap { try? JSONSerialization.jsonObject(with: $0, options: []) as? [String:Any] }

                var respError: SystemClientError!

                switch (res.statusCode) {
                case 400, 404: respError = SystemClientError.badRequest ("Resource Not Found")
                case 403:      respError = SystemClientError.permission
                case 429:      respError = SystemClientError.resource
                case 500, 504: respError = SystemClientError.badResponse ("Submission Status Error: \(res.statusCode)")
                case 422:
                    // We expect `json` with more information about the error
                    let status = json.flatMap { JSON (dict: $0) }.flatMap { $0.asString (name: "submit_status") }

                    if nil == data {
                        respError = SystemClientError.badResponse ("Submission Status Error: No 'data' Provided")
                    }
                    else if nil == status {
                        let dataString = data!.map { String(format: "%c", $0) }.joined()
                        respError = SystemClientError.badResponse ("Submission Status Error: No 'submit_status': \(dataString)")
                    }
                    else {
                        let submitDetails = json.flatMap { JSON (dict: $0) }.flatMap { $0.asString (name: "network_message") }
                        ?? "Submission Status Error: Missed 'network_message': \(data!.map { String(format: "%c", $0) }.joined())"

                        var submitError: SystemClientSubmissionError!
                        switch (status!) {
                        case "success":                       submitError = .unknown // unexpected "success" on 422
                        case "error_internal":                fallthrough
                        case "error_unknown":                 submitError = .unknown
                        case "error_transaction_invalid":     submitError = .transaction
                        case "error_transaction_expired":     submitError = .transactionExpired
                        case "error_transaction_duplicate":   submitError = .transactionDuplicate
                        case "error_signature_invalid":       submitError = .signature

                        case "error_nonce_invalid":           submitError = .nonceInvalid
                        case "error_nonce_used":              submitError = .nonceTooLow
                        case "error_nonce_gap":               submitError = .nonceInvalid

                        case "error_fee_insufficient":        submitError = .insufficientFee
                        case "error_fee_rate_insufficient":   submitError = .insufficientNetworkFee
                        case "error_fee_budget_insufficient": submitError = .insufficientNetworkCostUnit

                        case "error_balance_insufficient":    submitError = .insufficientBalance
                        case "error_account_unknown":         submitError = .account
                        default:                              submitError = .unknown
                        }
                        respError = SystemClientError.submission(error: submitError, details: submitDetails)
                    }
                default:
                    respError = SystemClientError.badResponse("Submission Status Error: Unrecognized Status Code: \(res.statusCode)")
                }

                completion (Result.failure(respError))
                return
            }

            completion (deserializer (data))
            }.resume()
    }

    /// Update `request` with 'application/json' headers and the httpMethod
    internal func decorateRequest (_ request: inout URLRequest, httpMethod: String) {
        request.addValue (WhatsOnChainSystemClient.capabilities.versionDescription, forHTTPHeaderField: "Accept")
        request.addValue ("application/json", forHTTPHeaderField: "Content-Type")
        request.httpMethod = httpMethod
    }

    /// https://tools.ietf.org/html/rfc7231#page-24
    internal func responseSuccess (_ httpMethod: String) -> [Int] {
        switch httpMethod {
        case "GET":
            //            The 200 (OK) status code indicates that the request has succeeded.
            return [200]

        case "POST":
            //            If one or more resources has been created on the origin server as a
            //            result of successfully processing a POST request, the origin server
            //            SHOULD send a 201 (Created) response containing a Location header
            //            field that provides an identifier for the primary resource created
            //            (Section 7.1.2) and a representation that describes the status of the
            //            request while referring to the new resource(s).
            //
            //            Responses to POST requests are only cacheable when they include
            //            explicit freshness information (see Section 4.2.1 of [RFC7234]).
            //            However, POST caching is not widely implemented.  For cases where an
            //            origin server wishes the client to be able to cache the result of a
            //            POST in a way that can be reused by a later GET, the origin server
            //            MAY send a 200 (OK) response containing the result and a
            //            Content-Location header field that has the same value as the POST's
            //            effective request URI (Section 3.1.4.2).
            return [200, 201]

        case "DELETE":
            //            If a DELETE method is successfully applied, the origin server SHOULD
            //            send a 202 (Accepted) status code if the action will likely succeed
            //            but has not yet been enacted, a 204 (No Content) status code if the
            //            action has been enacted and no further information is to be supplied,
            //            or a 200 (OK) status code if the action has been enacted and the
            //            response message includes a representation describing the status.
            return [200, 202, 204]

        case "PUT":
            //            If the target resource does not have a current representation and the
            //            PUT successfully creates one, then the origin server MUST inform the
            //            user agent by sending a 201 (Created) response.  If the target
            //            resource does have a current representation and that representation
            //            is successfully modified in accordance with the state of the enclosed
            //            representation, then the origin server MUST send either a 200 (OK) or
            //            a 204 (No Content) response to indicate successful completion of the
            //            request.
            return [200, 201, 204]

        default:
            return [200]
        }
    }

    /// Make a reqeust but w/o the need to create a URL.  Just create a URLRequest, decorate it,
    /// and then send it off.
    internal func makeRequest<T> (_ dataTaskFunc: DataTaskFunc,
                                  url: URL,
                                  httpMethod: String = "POST",
                                  deserializer: @escaping (_ data: Data?) -> Result<T, SystemClientError> = deserializeAsJSON,
                                  completion: @escaping (Result<T, SystemClientError>) -> Void) {
        print ("SYS: BDB: Request: \(url.absoluteString): Method: \(httpMethod): Data: []")
        var request = URLRequest (url: url)
        decorateRequest(&request, httpMethod: httpMethod)
        sendRequest (request, dataTaskFunc, responseSuccess (httpMethod), deserializer: deserializer, completion: completion)
    }

    /// Make a request by building a URL request from baseURL, path, query and data.  Once we have
    /// a request, decorate it and then send it off.
    internal func makeRequest<T> (_ dataTaskFunc: DataTaskFunc,
                                  _ baseURL: String,
                                  path: String,
                                  query: Zip2Sequence<[String],[String]>? = nil,
                                  data: JSON.Dict? = nil,
                                  httpMethod: String = "POST",
                                  deserializer: @escaping (_ data: Data?) -> Result<T, SystemClientError> = deserializeAsJSON,
                                  completion: @escaping (Result<T, SystemClientError>) -> Void) {
        guard var urlBuilder = URLComponents (string: baseURL)
            else { completion (Result.failure(SystemClientError.badRequest("Malformed `baseURL`: \(baseURL)"))); return }

        urlBuilder.path = path.starts(with: "/") ? path : "/\(path)"
        if let query = query {
            urlBuilder.queryItems = query.map { URLQueryItem (name: $0, value: $1) }
        }

        guard let url = urlBuilder.url
            else { completion (Result.failure (SystemClientError.badRequest("Bad URL: \(String (reflecting: urlBuilder))"))); return }

        print ("SYS: BDB: Request: \(url.absoluteString): Method: \(httpMethod): Data: \(data?.description ?? "[]")")

        var request = URLRequest (url: url)
        decorateRequest(&request, httpMethod: httpMethod)

        // If we have data as a JSON.Dict, then add it as the httpBody to the request.
        if let data = data {
            do { request.httpBody = try JSONSerialization.data (withJSONObject: data, options: []) }
            catch let jsonError as NSError {
                let warnString = "JSON.Error: '\(jsonError.description)'; Data: '\(data.description)'"
                completion (Result.failure (SystemClientError.badRequest(warnString)))
            }
        }

        sendRequest (request, dataTaskFunc, responseSuccess (httpMethod), deserializer: deserializer, completion: completion)
    }
    
    //internal func makeRequest_<T> (_ dataTaskFunc: DataTaskFunc,
    internal func makeRequest_ (_ dataTaskFunc: DataTaskFunc,
                                  _ baseURL: String,
                                  path: String,
                                  query: Zip2Sequence<[String],[String]>? = nil,
                                  data: JSON.Dict? = nil,
                                  httpMethod: String = "POST",
                                  //deserializer: @escaping (_ data: Data?) -> Result<T, SystemClientError> = deserializeAsJSON_,
                                   deserializer: @escaping (_ data: Data?) -> Result<JSON.Dict, SystemClientError> = deserializeAsJSON_,
                                  //completion: @escaping (Result<T, SystemClientError>) -> Void) {
                                  completion: @escaping (Result<JSON.Dict, SystemClientError>) -> Void) {
        guard var urlBuilder = URLComponents (string: baseURL)
            else { completion (Result.failure(SystemClientError.badRequest("Malformed `baseURL`: \(baseURL)"))); return }

        urlBuilder.path = path.starts(with: "/") ? path : "/\(path)"
        if let query = query {
            urlBuilder.queryItems = query.map { URLQueryItem (name: $0, value: $1) }
        }

        guard let url = urlBuilder.url
            else { completion (Result.failure (SystemClientError.badRequest("Bad URL: \(String (reflecting: urlBuilder))"))); return }

        print ("SYS: BDB: Request: \(url.absoluteString): Method: \(httpMethod): Data: \(data?.description ?? "[]")")

        var request = URLRequest (url: url)
        decorateRequest(&request, httpMethod: httpMethod)

        // If we have data as a JSON.Dict, then add it as the httpBody to the request.
        if let data = data {
            do { request.httpBody = try JSONSerialization.data (withJSONObject: data, options: []) }
            catch let jsonError as NSError {
                let warnString = "JSON.Error: '\(jsonError.description)'; Data: '\(data.description)'"
                completion (Result.failure (SystemClientError.badRequest(warnString)))
            }
        }

        sendRequest_ (request, dataTaskFunc, responseSuccess (httpMethod), deserializer: deserializer, completion: completion)
    }

    /// We have two flavors of bdbMakeRequest but they both handle their result identically.
    /// Provide this helper function to process the JSON result to extract the content and then
    /// to call the completion handler.
    internal func bdbHandleResult (_ res: Result<JSON.Dict, SystemClientError>,
                                   embedded: Bool = true,
                                   embeddedPath path: String,
                                   completion: @escaping (URL?, Result<[JSON], SystemClientError>) -> Void) {
        let res = res.map { JSON (dict: $0) }

        // Determine is there are more results for this query.  The BlocksetSystemClient
        // will provide a "_links" JSON dictionary with a "next" field that provides
        // a URL to use for the remaining values.  The "_links" dictionary looks
        // like
        // "_links":{ "next": { "href": <url> },
        //            "self": { "href": <url> }}

        let moreURL = try? res
            .map {  $0.asJSON (name: "_links") }
            .map { $0?.asJSON (name: "next")   }
            .map { $0?.asString(name: "href")  }      // -> Result<String?, ...>
            .map { $0.flatMap { URL (string: $0) } }  // -> Result<URL?,    ...>
            .recover { (ignore) in return nil }       // -> ...
            .get ()
        // moreURL will be `nil` if `res` was not .success

        // Invoke the callback with `moreURL` and Result with [JSON]
        completion (moreURL,
                    res.flatMap { (json: JSON) -> Result<[JSON], SystemClientError> in
                        let json = (embedded
                            ? (json.asDict(name: "_embedded")?[path] ?? [])
                            : [json.dict])

                        guard let data = json as? [JSON.Dict]
                            else { return Result.failure(SystemClientError.badResponse ("[JSON.Dict] expected")) }

                        return Result.success (data.map { JSON (dict: $0) })
        })
    }
    
    internal func bdbHandleResult_ (_ res: Result<JSON.Dict, SystemClientError>,
                                   embedded: Bool = true,
                                   embeddedPath path: String,
                                   completion: @escaping (URL?, Result<[JSON], SystemClientError>) -> Void) {
        
        //let res = res.map { [JSON.Dict] ($0) }
        let res = res.map { JSON (dict: $0) }
         
        // Determine is there are more results for this query.  The BlocksetSystemClient
        // will provide a "_links" JSON dictionary with a "next" field that provides
        // a URL to use for the remaining values.  The "_links" dictionary looks
        // like
        // "_links":{ "next": { "href": <url> },
        //            "self": { "href": <url> }}

        let moreURL = try? res
            .map {  $0.asJSON (name: "_links") }
            .map { $0?.asJSON (name: "next")   }
            .map { $0?.asString(name: "href")  }      // -> Result<String?, ...>
            .map { $0.flatMap { URL (string: $0) } }  // -> Result<URL?,    ...>
            .recover { (ignore) in return nil }       // -> ...
            .get ()
        // moreURL will be `nil` if `res` was not .success

        // Invoke the callback with `moreURL` and Result with [JSON]
        completion (moreURL,
                    res.flatMap { (json: JSON) -> Result<[JSON], SystemClientError> in
                        let json = (embedded
                            ? (json.asDict(name: "_embedded")?[path] ?? [])
                            : [json.dict])

                        guard let data = json as? [JSON.Dict]
                            else { return Result.failure(SystemClientError.badResponse ("[JSON.Dict] expected")) }

                        return Result.success (data.map { JSON (dict: $0) })
        })

    }


    /// In the case where a BDB request has 'paged' (with more results than and be returned in
    /// one query, the BDB will give us a URL to use for the next page.  Thus this function
    /// is identical to the following bdbMakeReqeust(path:query:embedded:completion) except that
    /// instead of building a URL, we've got a URL.  In this function, we need to pass in
    /// the 'embeddedPath' so that the JSON parser can find the data.
    internal func bdbMakeRequest (url: URL,
                                  embedded: Bool = true,
                                  embeddedPath: String,
                                  completion: @escaping (URL?, Result<[JSON], SystemClientError>) -> Void) {
        makeRequest(bdbDataTaskFunc, url: url, httpMethod: "GET") {
            self.bdbHandleResult ($0, embedded: embedded, embeddedPath: embeddedPath, completion: completion)
        }
    }

    internal func bdbMakeRequest (path: String,
                                  query: Zip2Sequence<[String],[String]>?,
                                  embedded: Bool = true,
                                  completion: @escaping (URL?, Result<[JSON], SystemClientError>) -> Void) {
        print("bdbBaseURL: \(bdbBaseURL) path: \(path) ")
        makeRequest (bdbDataTaskFunc, bdbBaseURL,
                     path: path,
                     query: query,
                     data: nil,
                     httpMethod: "GET") {
                        self.bdbHandleResult ($0, embedded: embedded, embeddedPath: path, completion: completion)
        }
    }
    
    internal func bdbMakeRequest_ (path: String,
                                  query: Zip2Sequence<[String],[String]>?,
                                  embedded: Bool = true,
                                completion: @escaping (URL?, Result<[JSON], SystemClientError>) -> Void) {
        print("bdbBaseURL: \(bdbBaseURL) path: \(path) ")
        makeRequest_ (bdbDataTaskFunc, bdbBaseURL,
                     path: path,
                     query: query,
                     data: nil,
                     httpMethod: "GET") {
                        self.bdbHandleResult_ ($0, embedded: embedded, embeddedPath: path, completion: completion)
        }
    }

    ///
    /// Convert an array of JSON into a single value using a specified transform
    ///
    /// - Parameters:
    ///   - id: If no value exists, report SystemClientError.NoEntity (id: id)
    ///   - data: The array of JSON
    ///   - transform: Function to tranfrom JSON -> T?
    ///
    /// - Returns: A `Result` with success of `T`
    ///
    private static func getOneExpected<T> (id: String, data: [JSON], transform: (JSON) -> T?) -> Result<T, SystemClientError> {
        switch data.count {
        case  0:
            return Result.failure (SystemClientError.badResponse("No Entity: \(id)"))
        case  1:
            guard let transfer = transform (data[0])
                else { return Result.failure (SystemClientError.badResponse ("(JSON) -> T transform error (one)"))}
            return Result.success (transfer)
        default:
            return Result.failure (SystemClientError.badResponse ("(JSON) -> T expected one only"))
        }
    }

    ///
    /// Convert an array of JSON into an array of `T` using a specified transform.  If any
    /// individual JSON cannot be converted, then a SystemClientError is return for `Result`
    ///
    /// - Parameters:
    ///   - data: Array of JSON
    ///   - transform: Function to transform JSON -> T?
    ///
    /// - Returns: A `Result` with success of `[T]`
    ///
    private static func getManyExpected<T> (data: [JSON], transform: (JSON) -> T?) -> Result<[T], SystemClientError> {
        let results = data.map (transform)
        return results.contains(where: { $0 == nil })
            ? Result.failure(SystemClientError.badResponse ("(JSON) -> T transform error (many)"))
            : Result.success(results as! [T])
    }
    
    private static func getManyExpected_<T> (data: [JSON], transform: (JSON) -> [T]?) -> Result<[T], SystemClientError> {
        let results = data.map (transform)
        return results.contains(where: { $0 == nil })
            ? Result.failure(SystemClientError.badResponse ("(JSON) -> T transform error (many)"))
            : Result.success(results[0]!)
            //: Result.success(results as! [T])
    }
    
    private static func getManyExpected__<T> (data: [JSON.Dict], transform: (JSON) -> T?) -> Result<[T], SystemClientError> {
        
        let data = data.map { JSON (dict: $0) }
        let results = data.map (transform)
        return results.contains(where: { $0 == nil })
            ? Result.failure(SystemClientError.badResponse ("(JSON) -> T transform error (many)"))
            : Result.success(results as! [T])
    }

    ///
    /// Given JSON extract a value and then apply a completion
    ///
    /// - Parameters:
    ///   - extract: A function that extracts the "result" field from JSON to return T?
    ///   - completion: A function to process a Result on T
    ///
    /// - Returns: A function to process a Result on JSON
    ///
    private static func getOneResult<T> (_ extract: @escaping (JSON) -> (String) ->T?,
                                         _ completion: @escaping (Result<T,SystemClientError>) -> Void) -> ((Result<JSON,SystemClientError>) -> Void) {
        return { (res: Result<JSON,SystemClientError>) in
            completion (res.flatMap {
                extract ($0)("result").map { Result.success ($0) } // extract()() returns an optional
                    ?? Result<T,SystemClientError>.failure(SystemClientError.badResponse("No Data")) })
        }
    }


    /// Given JSON extract a value with JSON.asString (returning String?) and then apply a completion
    ///
    /// - Parameter completion: A function to process a Result on String
    ///
    /// - Returns: A function to process a Result on JSON
    ///
    private static func getOneResultString (_ completion: @escaping (Result<String,SystemClientError>) -> Void) -> ((Result<JSON,SystemClientError>) -> Void) {
        return getOneResult (JSON.asString, completion)
    }

    final class ChunkedResults<T> {
        private let queue: DispatchQueue
        private let transform:  (JSON) -> T?
        private let completion: (Result<[T], SystemClientError>) -> Void

        private let resultsExpected: Int
        private var resultsReceived: Int = 0;
        private var results: [T] = []
        private var error: SystemClientError? = nil

        init (queue: DispatchQueue,
              transform:  @escaping (JSON) -> T?,
              completion: @escaping (Result<[T], SystemClientError>) -> Void,
              resultsExpected: Int) {
            self.queue = queue
            self.transform  = transform
            self.completion = completion
            self.resultsExpected = resultsExpected
        }

        private var _completed: Bool {
            return nil != error || resultsReceived == resultsExpected
        }

        var completed: Bool {
            return queue.sync {
                return _completed
            }
        }

        func extend (_ result: Result<[JSON], SystemClientError>) {
            var newError: SystemClientError? = nil

            let newResults = result
                .flatMap { WhatsOnChainSystemClient.getManyExpected(data: $0, transform: transform) }
                .getWithRecovery { newError = $0; return [] }

            queue.async {
                if !self._completed {
                    if nil != newError {
                        self.error = newError
                        self.completion (Result.failure (self.error!))
                    }
                    else {
                        self.results += newResults
                    }
                }
            }
        }

        func extendedOne () {
            queue.async {
                if !self._completed {
                    self.resultsReceived += 1
                    if self._completed {
                        self.completion (Result.success(self.results))
                    }
                }
            }
        }
    }
}
