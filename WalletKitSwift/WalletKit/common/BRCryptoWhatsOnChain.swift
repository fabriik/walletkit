//
//  File.swift
//  
//
//  Created by Christina Peterson on 7/25/22.
//

import Foundation
import BitcoinCore

#if os(Linux)
import FoundationNetworking
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

    /// Base URL (String) for the BRD BlockChain DB
    let bdbBaseURL: String

    /// Base URL (String) for BRD API Services
    let apiBaseURL: String

    // The session to use for DataTaskFunc as in `session.dataTask (with: request, ...)`.
    let session = URLSession (configuration: .default)

    /// A DispatchQueue Used for certain queries that can't be accomplished in the session's data
    /// task.  Such as when multiple request are needed in getTransactions().
    let queue = DispatchQueue.init(label: "BlocksetSystemClient")

    /// A function type that decorates a `request`, handles 'challenges', performs decrypting and/or
    /// uncompression of response data, redirects if requires and creates a `URLSessionDataTask`
    /// for the provided `session`.
    public typealias DataTaskFunc = (URLSession, URLRequest, @escaping (Data?, URLResponse?, Error?) -> Void) -> URLSessionDataTask

    /// A DataTaskFunc for submission to the BRD API
    internal let apiDataTaskFunc: DataTaskFunc

    /// A DataTaskFunc for submission to the BRD BlockChain DB
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
    ///   - bdbBaseURL: the baseURL for the BRD BlockChain DB.  Defaults to "http://blockchain-db.us-east-1.elasticbeanstalk.com"
    ///   - bdbDataTaskFunc: an optional DataTaskFunc for BRD BlockChain DB.  This defaults to
    ///       `session.dataTask (with: request, ...)`
    ///   - apiBaseURL: the baseRUL for the BRD API Server.  Defaults to "https://api.breadwallet.com".
    ///       if this is a DEBUG build then "https://stage2.breadwallet.com" will be used instead.
    ///   - apiDataTaskFunc: an optional DataTaskFunc for BRD API services.  For a non-DEBUG build,
    ///       this function would need to properly authenticate with BRD.  This means 'decorating
    ///       the request' header, perhaps responding to a 'challenge', perhaps decripting and/or
    ///       uncompressing response data.  This defaults to `session.dataTask (with: request, ...)`
    ///       which suffices for DEBUG builds.
    ///
    //public init (bdbBaseURL: String = "https://api.blockset.com",
    public init (bdbBaseURL: String = "http://api.whatsonchain.com",
    //public init (bdbBaseURL: String = "https://api.whatsonchain.com",
                 bdbDataTaskFunc: DataTaskFunc? = nil,
                 //apiBaseURL: String = "https://api.breadwallet.com",
                 apiBaseURL: String = "http://api.whatsonchain.com",
                 apiDataTaskFunc: DataTaskFunc? = nil) {

        self.bdbBaseURL = bdbBaseURL
        self.apiBaseURL = apiBaseURL

        //self.bdbDataTaskFunc = bdbDataTaskFunc ?? BlocksetSystemClient.defaultDataTaskFunc
        //self.apiDataTaskFunc = apiDataTaskFunc ?? BlocksetSystemClient.defaultDataTaskFunc
        self.bdbDataTaskFunc = bdbDataTaskFunc ?? WhatsOnChainSystemClient.defaultDataTaskFunc
        self.apiDataTaskFunc = apiDataTaskFunc ?? WhatsOnChainSystemClient.defaultDataTaskFunc
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
                else { return nil }

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
                print ("SYS: BDB:API: ERROR in Blockchain JSON: '\(json)'")
                return nil
            }

            guard let feeEstimates = json.asArray(name: "fee_estimates")?
                .map ({ JSON (dict: $0) })
                .map ({ asBlockchainFee (json: $0) }) as? [SystemClient.BlockchainFee]
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
                print ("SYS: BDB:API: ERROR in Blockchain JSON: '\(json)'")
                return nil
            }

            let isMainnet = (chain == "main") ? true : false
            
            let feeEstimates = [(amount: "500", tier: "tier", confirmationTimeInMilliseconds: mediantime)]
            
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
                else { return nil }

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
                else { return nil }

            // Address is optional
            let address = json.asString(name: "address")

            // All denomincations must parse
            guard let demoninations = json.asArray (name: "denominations")?
                .map ({ JSON (dict: $0 )})
                .map ({ asCurrencyDenomination(json: $0)}) as? [SystemClient.CurrencyDenomination]
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
                else { return nil }
            return (currency: currency, value: value)
        }

        /// Transfer

        static internal func asTransfer (json: JSON) -> SystemClient.Transfer? {
            guard let id   = json.asString (name: "transfer_id"),
                let bid    = json.asString (name: "blockchain_id"),
                let index  = json.asUInt64 (name: "index"),
                let amount = json.asDict (name: "amount")
                    .map ({ JSON (dict: $0) })
                    .map ({ asAmount(json: $0) }) as? SystemClient.Amount
                else { return nil }

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
                    .map ({ asAmount(json: $0)}) as? SystemClient.Amount,
                asTransactionValidateStatus(status)
                else { return nil }

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

            let raw = json.asData (name: "raw")

            // Require "_embedded" : "transfers" as [JSON.Dict]
            let transfersJSON = json.asDict (name: "_embedded")?["transfers"] as? [JSON.Dict] ?? []

            // Require asTransfer is not .none
            guard let transfers = transfersJSON
                .map ({ JSON (dict: $0) })
                .map ({ asTransfer (json: $0) }) as? [SystemClient.Transfer]
                else { return nil }

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
                     outputs: nil,
                     type: nil,
                     receiveAmount: nil,
                     mintId: nil,
                     fromAddress: nil,
                     senderAddress: nil
                     )
        }
        
        static internal func getSenderAddress (hash: String, blockchainId: String) -> String {
            var blockchain : String = "test"
            if(blockchainId == "whatsonchain-mainnet") {
                blockchain = "main"
            }
            
            var senderAddress : String = String("")
            
            let session = URLSession (configuration: .default)
            var request = URLRequest(url: URL(string: "http://api.whatsonchain.com/v1/bsv/\(blockchain)/tx/hash/\(hash)")!);
            request.httpMethod = "GET"
            
            var data_: JSON.Dict?
                
            let semaphore: DispatchSemaphore = DispatchSemaphore(value: 0)
            let task = WhatsOnChainSystemClient.defaultDataTaskFuncSetJSON (session, request, data_) { (data, res, error) in
                do {
                    if(data != nil) {
                        let json = try JSONSerialization.jsonObject(with: data!, options: []) as? JSON.Dict
                        data_ = json
                    } else {
                        data_ = nil
                    }
                } catch let error as NSError {
                    print(error.localizedDescription)
                }
                semaphore.signal()
            }
            task.resume()
            semaphore.wait()
        
            if(data_ != nil) {
                let vout       = data_!["vout"] as! [NSDictionary]
                let scriptPubKey = vout[1]["scriptPubKey"] as! NSDictionary
                let addresses : [String] = scriptPubKey["addresses"] as! [String]
                if(addresses.count != 0) {
                    senderAddress = addresses[0]
                }
            }
            
            return senderAddress
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
            
            guard let identifier = json.asString (name: "txid"),
                  let hash = json.asString(name: "hash"),
                  let version    = json.asInt64 (name: "version"),
                  let size       = json.asInt64 (name: "size"),
                  let lockTime   = json.asInt64 (name: "locktime"),
                  let vin        = json.asJSONArray (name: "vin"),
                  let vout       = json.asJSONArray (name: "vout")
                  //let blockHeight = json.asInt64 (name: "blockheight"),
                  //let blockHash = json.asString (name: "blockhash"),
                  //let confirmations     = json.asUInt64 (name: "confirmations"),
                  //let time       = json.asInt64 (name: "time")
            else {
                print ("SYS: BDB: API: ERROR in asTransaction JSON: '\(json)'")
                return nil
            }
            var curStatus : String = String("submitted")
            var blockHeight : Int64? = -1
            if(json.dict["blockheight"] != nil) {
                blockHeight = json.asInt64 (name: "blockheight")
                curStatus = String("confirmed")
            }
            
            var blockHash : String? = String("")
            if(json.dict["blockhash"] != nil) {
                blockHash = json.asString (name: "blockhash")
            }
            
            var confirmations : UInt64 = 0
            if(json.dict["confirmations"] != nil) {
                confirmations = json.asUInt64 (name: "confirmations")!
            }
            
            var time : Int64? = 0
            if(json.dict["time"] != nil) {
                time = json.asInt64 (name: "time")
            }
            
            //var count = 0
            //var json_array : [JSON.Dict] = []
            var type : String?
            var mintId : String?
            var fromAddress : String?
            var receiveAmount : UInt64? = 1

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
            }
            
            var count = 0
            var outputs : [SystemClient.Outputs] = []
            for anItem in vout {
                //let value = anItem.asString (name: "value")
                let value = (anItem.dict["value"] as? NSNumber).flatMap { Double (exactly: $0)}
                
                let scriptPubKey = anItem.asDict (name: "scriptPubKey")
                //let scriptSig = anItem["scriptSig"] as! JSON.Dict
                let script = scriptPubKey!["hex"] as! String

                
                //let output : SystemClient.Outputs = (script: script, amount: value!)
                let output : SystemClient.Outputs = (script: script, amount: value ?? 0)
                outputs.append(output)
                
                if(scriptPubKey!["opReturn"] != nil) {
                    let opReturn = scriptPubKey!["opReturn"] as! JSON.Dict
                    type = opReturn["type"] as! String
                    let parts = opReturn["parts"] as! NSArray
                    let str = parts[2] as! String
                    
                    print("STR: : (\(str))")
                    
                    let beginOfMintId = str.firstIndex(of: "[")!
                    let firstIndexMintId = str.index(beginOfMintId, offsetBy: 2)
                    let endOfMintId = str.firstIndex(of: "_")!
                    let lastIndexMintId = str.index(endOfMintId, offsetBy: -1)
                    //let substring = str[beginOfSentence...endOfSentence]
                    let substring = str[firstIndexMintId...lastIndexMintId]
                    mintId = String(substring)
                    
                    let beginOfAmount = str.lastIndex(of: ",")!
                    let firstIndexAmount = str.index(beginOfAmount, offsetBy: 1)
                    let endOfAmount = str.lastIndex(of: "]")!
                    let endIndexAmount = str.index(endOfAmount, offsetBy: -4)
                    let substringAmount = str[firstIndexAmount...endIndexAmount]
                    let amount = String(substringAmount)
                    
                    receiveAmount = UInt64(amount) //FIXME!!!
                } else if (count == 1) {
                    let addresses : [String] = scriptPubKey!["addresses"] as! [String]
                    if(addresses.count != 0) {
                        fromAddress = addresses[0]
                        print("Debugging")
                    }
                }
                
                //let script = anItem.asString ()
                count = count + 1
            }
          
            let inCount = inputs.count
            
            let outCount = outputs.count
            
            var blockchainId : String = String("whatsonchain-mainnet")
            
            let session = URLSession (configuration: .default)
            var request = URLRequest(url: URL(string: "http://api.whatsonchain.com/v1/bsv/main/tx/\(hash)/hex")!);
            request.httpMethod = "GET"
            
            var data_: Data?
                
            var semaphore: DispatchSemaphore = DispatchSemaphore(value: 0)
            let task = WhatsOnChainSystemClient.defaultDataTaskFuncSet (session, request, data_) { (data, res, error) in
                    data_ = data
                    semaphore.signal()
                }
                task.resume()
                semaphore.wait()
        
            if(data_ != nil && data_!.count == 0) {
                blockchainId = String("whatsonchain-testnet")
                var request = URLRequest(url: URL(string: "http://api.whatsonchain.com/v1/bsv/test/tx/\(hash)/hex")!);
                request.httpMethod = "GET"
                semaphore = DispatchSemaphore(value: 0)
                let task1 = WhatsOnChainSystemClient.defaultDataTaskFuncSet (session, request, data_) { (data, res, error) in
                    data_ = data
                    semaphore.signal()
                }
                task1.resume()
                semaphore.wait()
            }
            
            var senderAddress : String = String("")
            if(inCount > 0) {
                senderAddress = getSenderAddress (hash: inputs[0].txHash, blockchainId: blockchainId)
            }
            
            let dict_ : Dictionary<String,String> = [:]
            
            let transfers = [(
                id: identifier,
                source: "source",
                target: "target",
                amount: (currency: "satoshi", value: "5"),
                acknowledgements: confirmations,
                index: UInt64(0),
                transactionId: identifier,
                blockchainId: blockchainId,
                metaData: dict_)
            ]

            return (id: identifier,
                     blockchainId: blockchainId,
                     hash: hash,
                     identifier: identifier,
                     blockHash: blockHash,
                     blockHeight: -1 == blockHeight! ? nil : UInt64(blockHeight!),
                     index: UInt64(0),
                     //confirmations: 0 == confirmations ? nil : UInt64(confirmations),
                     confirmations:  confirmations,
                     //status: "confirmed",
                     status: curStatus,
                     size: 0 <= size ? 0 : UInt64(size),
                     timestamp: Date(),
                     firstSeen: Date(),
                     raw: data_ != nil ? data_ : Data(),
                     fee: (currency: "satoshi", value: "1"),
                     transfers: transfers,
                     acknowledgements: confirmations,
                     metaData: dict_,
                     version: version,
                     lockTime: lockTime,
                     time: time,
                     inCount: inCount,
                     inputs: inputs,
                     outCount: outCount,
                     outputs: outputs,
                     type: type,
                     receiveAmount: receiveAmount,
                     mintId: mintId,
                     fromAddress: fromAddress,
                     senderAddress: senderAddress
            
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
        

        static internal func asTransactionIdentifier (json: JSON) -> SystemClient.TransactionIdentifier? {
            guard let id         = json.asString(name: "transaction_id"),
                  let bid        = json.asString (name: "blockchain_id"),
                  let identifier = json.asString (name: "identifier")
            else { return nil }

            let hash = json.asString (name: "hash")

            return (id: id, blockchainId: bid, hash: hash, identifier: identifier)
        }
        
        static internal func asTransactionIdentifierWOC (json: JSON) -> SystemClient.TransactionIdentifier? {
            guard let id         = json.asString(name: "txid")
            else { return nil }
            
            var blockchainId : String = String("whatsonchain-mainnet")
            
            let session = URLSession (configuration: .default)
            var request = URLRequest(url: URL(string: "http://api.whatsonchain.com/v1/bsv/main/tx/\(id)/hex")!);
            request.httpMethod = "GET"
            
            var data_: Data?
                
            let semaphore: DispatchSemaphore = DispatchSemaphore(value: 0)
            let task = WhatsOnChainSystemClient.defaultDataTaskFuncSet (session, request, data_) { (data, res, error) in
                    data_ = data
                    semaphore.signal()
                }
                task.resume()
                semaphore.wait()
        
            if(data_ != nil && data_!.count == 0) {
                blockchainId = String("whatsonchain-testnet")
            }

            return (id: id, blockchainId: blockchainId, hash: id, identifier: id)
        }

        /// Transaction Fee

        public typealias TransactionFee = (
            costUnits: UInt64,
            foo: String
        )

        static internal func asTransactionFee (json: JSON) -> SystemClient.TransactionFee? {
            guard let costUnits = json.asUInt64(name: "cost_units")
                else { return nil }
            
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
                else { return nil }

            let acks     = json.asUInt64 (name: "acknowledgements") ?? 0
            let header   = json.asString (name: "header")
            let raw      = json.asData   (name: "raw")
            let prevHash = json.asString (name: "prev_hash")
            let nextHash = json.asString (name: "next_hash")

            let transactions = json.asArray (name: "transactions")?
                .map ({ JSON (dict: $0 )})
                .map ({ asTransaction (json: $0)}) as? [SystemClient.Transaction]  // not quite

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
                else { return nil }

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
                else { return nil }
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
                let events = json.asArray(name: "events")?
                    .map ({ JSON (dict: $0) })
                    .map ({ asSubscriptionEvent(json: $0) }) as? [SubscriptionEvent] // not quite
                else { return nil }

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
                let currencies = json.asArray(name: "currencies")?
                    .map ({ JSON (dict: $0) })
                    .map ({ asSubscriptionCurrency (json: $0) }) as? [SubscriptionCurrency]
                else { return nil }

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
                let balances = json.asArray (name: "balances")?
                    .map ({ JSON (dict: $0) })
                    .map ({ asAmount(json: $0)}) as? [SystemClient.Amount]
                else { return nil }

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
                else { return nil }

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
        var blockchain : String = "test"
        if(blockchainId == "whatsonchain-mainnet") {
            blockchain = "main"
        }
        //bdbMakeRequest(path: "blockchains/\(blockchainId)", query: zip(["verified"], ["true"]), embedded: false) {
        bdbMakeRequest(path: "v1/bsv/\(blockchain)/chain/info", query: nil, embedded: false) {
            (more: URL?, res: Result<[JSON], SystemClientError>) in
            precondition (nil == more)
            completion (res.flatMap {
                //WhatsOnChainSystemClient.getOneExpected (id: blockchainId, data: $0, transform: Model.asBlockchain)
                WhatsOnChainSystemClient.getOneExpected (id: blockchainId, data: $0, transform: Model.asBlockchainWOC)
            })
        }
    }

    public func getBlockchainDebug (blockchainId: String, completion: @escaping (Result<SystemClient.Blockchain,SystemClientError>) -> Void) {
        /*var blockchain : String = "test"
        if(blockchainId == "whatsonchain-mainnet") {
            blockchain = "main"
        }*/
        //bdbMakeRequest(path: "blockchains/\(blockchainId)", query: zip(["verified"], ["true"]), embedded: false) {
        //bdbMakeRequest(path: "v1/bsv/\(blockchainId)/chain/info", query: nil, embedded: false) {
        /*bdbMakeRequest_(path: "v1/bsv/\(blockchainId)/chain/info", query: nil, embedded: false) {
            (more: URL?, res: Result<[JSON], SystemClientError>) in
            precondition (nil == more)
            completion (res.flatMap {
                //WhatsOnChainSystemClient.getOneExpected (id: blockchainId, data: $0, transform: Model.asBlockchain)
                WhatsOnChainSystemClient.getOneExpected (id: blockchainId, data: $0, transform: Model.asBlockchainWOC)
            })
        }*/
        
        //let session_ = URLSession (configuration: .default)
        //var request = URLRequest(url: URL(string: "http://bitcoin:local321@127.0.0.1:18332/")!);
        var request = URLRequest(url: URL(string: "http://api.whatsonchain.com/v1/bsv/test/chain/info")!);
        //var request = URLRequest(url: URL(string: "https://api.whatsonchain.com/v1/bsv/test/chain/info")!);
        //var request = URLRequest(url: URL(string: "https://api.whatsonchain.com/v1/bsv/test/tx/decode")!);
        //request.httpMethod = "POST"
        request.httpMethod = "GET"
        
        /*let data: JSON.Dict = [
            "jsonrpc"  : "1.0",
            "id" : 1644337268902,
            "method" : "getrawmempool",
            "params" : []
        ]*/
        //let data: JSON.Dict = [:]
        /*let data: JSON.Dict = [
            "txhex"  : "0100000002e9c310fb7c62b3af431062941e034626a6a357c5d96611b594ef6d45e858131800000000fd2901483045022100ee3fd9bb4186335d24a10161b0e2e2518ff11e3923b16bfdc1f2151c1780e1c10220342cd7e844c89bce12e645d48ce45b58dd96ff87865130f518702f2213e72afd41210302e079d826eb9aa1b3b051206a3eb311185de3bfe21418c76e2be2cee6a3719847304402203985d151c1b40c8db99219f89ebdaf46500032a3b4a0cd07545aa4fd3034bf3d02200d89a98b10b7a3d24d804205613acc8ec2157a8feb1e1608bafca329109d9f5c4121025f44adfa89cc33c42def4165be539a523c3d3fd7e537bc1e9bd44b32fa341cfd0773667040302e334730440220066c269dba2c931729ab29f3d62939856f770bde8bae3a71c0ebde2eb5fe9759022009b50c89f99db8b7fa77b7f397091d5d6133930c8d2e5a74646699da3d2da6bb0001000100ffffffff6a18154dffa2b1ea67da06081d96d6e5f8791c5440a8812a8c57d5dc5dd7a8c7010000006b483045022100b931c5821f187c244d8be6227efaba3efa1d02a281c8cc8b744d69c70eab9c82022033213d3f83457d999ef012fbb4b06fef8c590cf07abd82dce372bb4f942ed5f6412102a717d8ac10318dcf42bd397eb1c31f85219ebb1497198783b688d8401063b01dffffffff023402000000000000fd9701610773667040302e33243866353539383237353266372e617373657440627574746f6e6f666d6f6e65792e636f6d14ac30986d081592ff27a65da9bcf1b31813dc19a9146d861709c1cdb8fef249f13568efcf778fefef0d1412f88c3fa18325a8e42100b1d5ffa16384fa50cf4630440220260d19bcc4e5b25d5b7eaaa3a4ca898e42ac451a8a528cbcb120d1b302385cb20220252a2d0ee15728c6b19157d48142b8dc5255d06133cfdd3a9c01feb183318c9a24e9c310fb7c62b3af431062941e034626a6a357c5d96611b594ef6d45e858131800000000000000000000005d79577a75567a567a567a567a567a567a5c79567a75557a557a557a557a557a5b79557a75547a547a547a547a5a79547a75537a537a537a5979537a75527a527a5779527a75517a5879517a75615f7901008791635e79a9537987695f795f79ac696851790087916900790087916956795e798769011479a954798769011579011579ac69011279a955798769011379011379ac777777777777777777777777777777777777777777776a0b01000000000000000800002bd3f505000000001976a91462aad08fc7df538ab349812ec41ef59cd9729e3f88ac00000000"
        ]*/
        
       //if let data = data {
        //    do { request.httpBody = try JSONSerialization.data (withJSONObject: data, options: []) }
        //    catch let jsonError as NSError {
        //        let warnString = "JSON.Error: '\(jsonError.description)'; Data: '\(data.description)'"
         //       completion (Result.failure (SystemClientError.model(warnString)))
         //   }
        //}
        
        var data_: JSON.Dict?
            
        let semaphore: DispatchSemaphore = DispatchSemaphore(value: 0)
            //let task = URLSession.shared.dataTask(with: request) { (data, response, error) in
        //let task = BitcoinRPCSystemClient.defaultDataTaskFuncSetJSON (session, request, data_) { (data, res, error) in
        let task = WhatsOnChainSystemClient.defaultDataTaskFunc (session, request) { (data, res, error) in
                do {
                    if(data != nil) {
                        let json = try JSONSerialization.jsonObject(with: data!, options: []) as? JSON.Dict
                        print("Stop")
                        //data_ = json
                    } else {
                        //data_ = nil
                    }
                } catch let error as NSError {
                    print(error.localizedDescription)
                }
                semaphore.signal()
            }
            task.resume()
            semaphore.wait()
        
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
                                ?? Result.failure(SystemClientError.model("Missed Subscription"))
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
                            : Result.failure (SystemClientError.model ("Unexpected Data on DELETE"))) },
                     completion: completion)
    }

    // Transfers

    static let ADDRESS_COUNT = 100
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
                             "max_page_size"] + Array (repeating: "address", count: addresses.count)

            let queryVals = [blockchainId,
                             begBlockNumber.description,
                             endBlockNumber.description,
                             maxPageSize.description] + addresses

            self.bdbMakeRequest (path: "transfers",
                                 query: zip (queryKeys, queryVals),
                                 completion: handleResult)
        }
    }

    public func getTransfer (transferId: String, completion: @escaping (Result<SystemClient.Transfer, SystemClientError>) -> Void) {
        bdbMakeRequest (path: "transfers/\(transferId)", query: nil, embedded: false) {
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
    
    static internal func getMintId (json: JSON.Dict) -> String {
        
        let vout = json["vout"] as! [NSDictionary]
        
        var ret : String = String("")
        
        for anItem in vout {
            
            let scriptPubKey = anItem["scriptPubKey"] as! NSDictionary
            
            if(scriptPubKey["opReturn"] != nil) {
                let opReturn = scriptPubKey["opReturn"] as! JSON.Dict
                
                let parts = opReturn["parts"] as! NSArray
                
                let str : String = parts[2] as! String
                
                //let indexBegin = str.range(of: ":[")
                //let indexEnd = str.range(of: "_o1")
                //let substring = str[indexBegin!.lowerBound..<indexEnd!.lowerBound]
                
                let beginOfSentence = str.firstIndex(of: "[")!
                let firstIndex = str.index(beginOfSentence, offsetBy: 2)
                let endOfSentence = str.firstIndex(of: "_")!
                let lastIndex = str.index(endOfSentence, offsetBy: -1)
                //let substring = str[beginOfSentence...endOfSentence]
                let substring = str[firstIndex...lastIndex]
                ret = String(substring)
            }
            
        }
        //return String("189bc8ad3bc44632581ec2701a244e1c23478eda69ab5c123e2bd47caa8666cc")
        return ret
    }
    
    static internal func getDeployId (json: JSON.Dict) -> String {
        
        let vin = json["vin"] as! [NSDictionary]
        
        let txid : String = vin[1]["txid"] as! String
        
        return txid
    }

    // Transactions

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
        
        let storagePath = FileManager.default
            .urls(for: .documentDirectory, in: .userDomainMask)[0]
           .appendingPathComponent("Core").path
        
        let walletId : Int64 = getWalletIdByPrimaryAddress(chunkedAddresses[0][0], storagePath)
        
        var addressHexBuf = [Int8](repeating: 0, count: 255) // Buffer for C string
        getRUNAddressByWalletId(walletId, &addressHexBuf, Int32(addressHexBuf.count), storagePath)
        let address = String(cString: addressHexBuf)
        
        //let address = chunkedAddresses[0][0]
        //let address = "n44HTiHtFQ1hdMHBZPfsiVUUwYep5V3Yq1"
        //let address = "n2DXd5qGBnNGHQ2jtd162RjwgBRYdxxYiq"
        
        var blockchain : String = "test"
        if(blockchainId == "whatsonchain-mainnet") {
            blockchain = "main"
        }
        
        getTransactionHistory(blockchainId: blockchain, address: address) {
            (res: Result<[SystemClient.TransactionHistory], SystemClientError>) in
            defer { print("Deferring")}
            res.resolve (
                success: {
                    //print("SYS: GetTransactionHistory: Success \($0[0].tx_hash)")
                    
                    var data_array: [JSON.Dict] = []
                    
                    for tx in $0 {
                    
                        let session_ = URLSession (configuration: .default)
                        var request = URLRequest(url: URL(string: "http://api.whatsonchain.com/v1/bsv/\(blockchain)/tx/hash/\(tx.tx_hash!)")!);
                        request.httpMethod = "GET"
                        
                        var data_: JSON.Dict?
                            
                        var semaphore: DispatchSemaphore = DispatchSemaphore(value: 0)
                            //let task = URLSession.shared.dataTask(with: request) { (data, response, error) in
                        let task = WhatsOnChainSystemClient.defaultDataTaskFuncSetJSON (session_, request, data_) { (data, res, error) in
                                do {
                                    if(data != nil) {
                                        let json = try JSONSerialization.jsonObject(with: data!, options: []) as? JSON.Dict
                                        data_ = json
                                    } else {
                                        data_ = nil
                                    }
                                } catch let error as NSError {
                                    print(error.localizedDescription)
                                }
                                semaphore.signal()
                            }
                            task.resume()
                            semaphore.wait()
                        //if(data_ != nil && data_!.count == 12) {
                        if(data_ != nil) {
                            let hash : String = data_!["hash"] as! String
                            print("HASH: \(hash)")
                            
                            var privkeyHexBuf = [Int8](repeating: 0, count: 255) // Buffer for C string
                            authorizerGetPrivKeyRun(address, &privkeyHexBuf, Int32(privkeyHexBuf.count), storagePath)
                            let privkeyHex = String(cString: privkeyHexBuf)
                            
                            var data0_: JSON.Dict?
                            
                            
                            
                            var request0 = URLRequest(url: URL(string: "http://localhost:8000/inventory/")!);
                            self.decorateRequest(&request0, httpMethod: "POST")
                            
                            let mintId : String = WhatsOnChainSystemClient.getMintId(json: data_!);
                            
                            //let deployId : String = WhatsOnChainSystemClient.getDeployId(json: data_!);
                            
                            let data: JSON.Dict = [
                                "txid"  : "\(hash)",
                                "mintId" : "\(mintId)",
                                //"deployId" : "\(deployId)",
                                "privkey" : "\(privkeyHex)",
                                "network" : "\(blockchain)"
                            ]
                            
                           //if let data = data {
                                do { request0.httpBody = try JSONSerialization.data (withJSONObject: data, options: []) }
                                catch let jsonError as NSError {
                                    let warnString = "JSON.Error: '\(jsonError.description)'; Data: '\(data.description)'"
                                    completion (Result.failure (SystemClientError.model(warnString)))
                                }
                            //}
                            
                            semaphore = DispatchSemaphore(value: 0)
                                //let task = URLSession.shared.dataTask(with: request) { (data, response, error) in
                            let task0 = WhatsOnChainSystemClient.defaultDataTaskFuncSetJSON (session_, request0, data0_) { (data, res, error) in
                                    do {
                                        if(data != nil) {
                                            let json = try JSONSerialization.jsonObject(with: data!, options: []) as? JSON.Dict
                                            data0_ = json
                                        } else {
                                            data0_ = nil
                                        }
                                    } catch let error as NSError {
                                        print(error.localizedDescription)
                                    }
                                    semaphore.signal()
                                }
                                task0.resume()
                                semaphore.wait()
                            
                            if(data0_ != nil) {
                                let txid : String = data0_!["txid"] as! String
                                
                                print("TXID: \(txid)")
                                if(txid != "") {
                                    data_array.append(data_!)
                                }
                            }
                            
                        }
                        
                    }
                    completion(
                        WhatsOnChainSystemClient.getManyExpected__ (data: data_array, transform: Model.asTransactionWOC)
                    )
                    
                        
                },
                failure: { (e) in
                    print ("SYS: GetTransactionHistory: Error: \(e)")

                })
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
        }

        let maxPageSize = maxPageSize ?? ((includeTransfers ? 1 : 3) * BlocksetSystemClient.DEFAULT_MAX_PAGE_SIZE)

        let queryKeysBase = [
            "blockchain_id",
            begBlockNumber.map { (_) in "start_height" },
            endBlockNumber.map { (_) in "end_height" },
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
        }*/
    }

    public func getTransaction (transactionId: String,
                                includeRaw: Bool = false,
                                includeProof: Bool = false,
                                completion: @escaping (Result<SystemClient.Transaction, SystemClientError>) -> Void) {
        let queryKeys = ["include_proof", "include_raw"]
        let queryVals = [includeProof.description, includeRaw.description]

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
        
        let storagePath = FileManager.default
            .urls(for: .documentDirectory, in: .userDomainMask)[0]
           .appendingPathComponent("Core").path
        
        var txnIdList : String = String("")
        var mintIdList : String = String("")
        var privkeyList : String = String("")
        var addressList : String = String("")
        var amountList : String = String("")
        
        var numTxns : Int64 = 1
        authorizerGetNumTxnsForTransferRUN(&numTxns, storagePath)
        for index in 0...(numTxns - 1) {
            if(index != 0) {
                txnIdList = txnIdList + String(",")
                mintIdList = mintIdList + String(",")
                privkeyList = privkeyList + String(",")
                addressList = addressList + String(",")
                amountList = amountList + String(",")
            }
            var txnIdHexBuf = [Int8](repeating: 0, count: 100) // Buffer for C string
            var addressHexBuf = [Int8](repeating: 0, count: 100) // Buffer for C string
            var mintIdHexBuf = [Int8](repeating: 0, count: 100) // Buffer for C string
            var fromAddressHexBuf = [Int8](repeating: 0, count: 100) // Buffer for C string
            var amount : Int64 = 1
            
            authorizerGetTransferDataRun(index, &txnIdHexBuf, Int32(txnIdHexBuf.count), &addressHexBuf, Int32(addressHexBuf.count), &mintIdHexBuf, Int32(mintIdHexBuf.count), &fromAddressHexBuf, Int32(fromAddressHexBuf.count), &amount, storagePath)
            let txnIdHex = String(cString: txnIdHexBuf)
            let addressHex = String(cString: addressHexBuf)
            let mintIdHex = String(cString: mintIdHexBuf)
            let fromAddressHex = String(cString: fromAddressHexBuf)
            
            var privkeyHexBuf = [Int8](repeating: 0, count: 255) // Buffer for C string
            authorizerGetPrivKeyRun(fromAddressHex, &privkeyHexBuf, Int32(privkeyHexBuf.count), storagePath)
            let privkeyHex = String(cString: privkeyHexBuf)
            
            txnIdList = txnIdList + txnIdHex
            mintIdList = mintIdList + mintIdHex
            privkeyList = privkeyList + privkeyHex
            addressList = addressList + addressHex
            amountList = amountList + String(amount)
        }
        
        
        /*let data            = transaction.base64EncodedString()
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
        }*/
        
        var blockchain : String = "test"
        if(blockchainId == "whatsonchain-mainnet") {
            blockchain = "main"
        }
        
        let json: JSON.Dict = [
            //"txid"  : "\(txnIdHex)",
            "txid"  : "\(txnIdList)",
            "mintId"  : "\(mintIdList)",
            "privkey"  : "\(privkeyList)",
            "address"  : "\(addressList)",
            "amount" : "\(amountList)",
            "network" : blockchain
        ]
        
        //makeRequest (bdbDataTaskFunc, bdbBaseURL,
        makeRequest (bdbDataTaskFunc, "http://localhost:8000",
                     path: "/transfer",
                     data: json,
                     httpMethod: "POST") {
            self.bdbHandleResult ($0, embedded: false, embeddedPath: "") {
                (more: URL?, res: Result<[JSON], SystemClientError>) in
                precondition(nil == more)
                completion (res.flatMap {
                    WhatsOnChainSystemClient.getOneExpected (id: blockchainId,
                                                         data: $0,
                                                         transform: Model.asTransactionIdentifierWOC)
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
                         "include_tx_proof"]

        var queryVals = [blockchainId,
                         begBlockNumber.description,
                         endBlockNumber.description,
                         includeRaw.description,
                         includeTx.description,
                         includeTxRaw.description,
                         includeTxProof.description]

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
        let queryKeys = ["include_raw", "include_tx", "include_tx_raw", "include_tx_proof"]

        let queryVals = [includeRaw.description, includeTx.description, includeTxRaw.description, includeTxProof.description]

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
        let noDataFailure = Result<[SystemClient.HederaAccount],SystemClientError>.failure(SystemClientError.noData)

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
        let noDataFailure = Result<[SystemClient.HederaAccount],SystemClientError>.failure(SystemClientError.noData)

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
                            // If a reponse error with HTTP status of 422, the Hedera accont
                            // already exists.  Just get it.
                            if case let .response (code, _, _) = error, code == 422 {
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
    }

    private static func deserializeAsJSON<T> (_ data: Data?) -> Result<T, SystemClientError> {
        guard let data = data else {
            return Result.failure (SystemClientError.noData);
        }

        do {
            guard let json = try JSONSerialization.jsonObject(with: data, options: []) as? T
                else {
                    print ("SYS: BDB:API: ERROR: JSON.Dict: '\(data.map { String(format: "%c", $0) }.joined())'")
                    return Result.failure(SystemClientError.jsonParse(nil)) }

            return Result.success (json)
        }
        catch let jsonError as NSError {
            print ("SYS: BDB:API: ERROR: JSON.Error: '\(data.map { String(format: "%c", $0) }.joined())'")
            return Result.failure (SystemClientError.jsonParse (jsonError))
        }
    }
    
    //private static func deserializeAsJSON_<T> (_ data: Data?) -> Result<T, SystemClientError> {
    private static func deserializeAsJSON_ (_ data: Data?) -> Result<JSON.Dict, SystemClientError> {
        guard let data = data else {
            return Result.failure (SystemClientError.url("No Data"));
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
            return Result.failure (SystemClientError.url(warnString))
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
                completion (Result.failure(SystemClientError.submission (error!))) // NSURLErrorDomain
                return
            }

            guard let res = res as? HTTPURLResponse else {
                completion (Result.failure (SystemClientError.url ("No Response")))
                return
            }

            guard responseSuccess.contains(res.statusCode) else {
                let json = data
                    .flatMap { try? JSONSerialization.jsonObject(with: $0, options: []) as? [String:Any] }

                // It is an error if there IS data but IS NOT json (could not parse).
                let jsonError = nil != data && nil == json

                completion (Result.failure (SystemClientError.response(res.statusCode, json, jsonError)))
                return
            }

            completion (deserializer (data))
            }.resume()
    }
    
    /*private func sendRequest<T> (_ request: URLRequest,
                                 _ dataTaskFunc: DataTaskFunc,
                                 _ responseSuccess: [Int],
                                 deserializer: @escaping (_ data: Data?) -> Result<T, SystemClientError>,
                                 completion: @escaping (Result<T, SystemClientError>) -> Void) {
        dataTaskFunc (session, request) { (data, res, error) in
            guard nil == error else {
                var sce: SystemClientError = SystemClientError.url ("General Error: \(String (reflecting: error))")
                let error = error! as NSError

                if error.domain == NSURLErrorDomain {
                    switch error.code {
                    case NSURLErrorCannotFindHost,
                        NSURLErrorCannotConnectToHost,
                        NSURLErrorRedirectToNonExistentLocation:
                        sce = SystemClientError.url ("unavailable")

                    case NSURLErrorTimedOut,
                        NSURLErrorNetworkConnectionLost,
                        NSURLErrorDNSLookupFailed,
                        NSURLErrorNotConnectedToInternet:
                        sce = SystemClientError.url ("lostConnectivity")

                    default: break
                    }
                }

                completion (Result.failure(sce))
                return
            }

            guard let res = res as? HTTPURLResponse else {
                completion (Result.failure (SystemClientError.url ("Expected HTTP URL Response")))
                return
            }

            guard responseSuccess.contains(res.statusCode) else {
                // Try to parse the `data` as JSON
                let json = data.flatMap { try? JSONSerialization.jsonObject(with: $0, options: []) as? [String:Any] }

                var respError: SystemClientError!

                switch (res.statusCode) {
                case 400, 404: respError = SystemClientError.url ("Resource Not Found")
                case 403:      respError = SystemClientError.url ("403")
                case 429:      respError = SystemClientError.url ("429")
                case 500, 504: respError = SystemClientError.url ("Submission Status Error: \(res.statusCode)")
                case 422:
                    // We expect `json` with more information about the error
                    let status = json.flatMap { JSON (dict: $0) }.flatMap { $0.asString (name: "submit_status") }

                    if nil == data {
                        respError = SystemClientError.url ("Submission Status Error: No 'data' Provided")
                    }
                    else if nil == status {
                        let dataString = data!.map { String(format: "%c", $0) }.joined()
                        respError = SystemClientError.url ("Submission Status Error: No 'submit_status': \(dataString)")
                    }
                    else {
                        let submitDetails = json.flatMap { JSON (dict: $0) }.flatMap { $0.asString (name: "network_message") }
                        ?? "Submission Status Error: Missed 'network_message': \(data!.map { String(format: "%c", $0) }.joined())"

                        var submitError: String
                        switch (status!) {
                        case "success":                       submitError = "success" // unexpected "success" on 422
                        case "error_internal":                fallthrough
                        case "error_unknown":                 submitError = "error_unknown"
                        case "error_transaction_invalid":     submitError = "error_unknown"
                        case "error_transaction_expired":     submitError = "error_transaction_expired"
                        case "error_transaction_duplicate":   submitError = "error_transaction_duplicate"
                        case "error_signature_invalid":       submitError = "error_signature_invalid"

                        case "error_nonce_invalid":           submitError = "error_nonce_invalid"
                        case "error_nonce_used":              submitError = "error_nonce_used"
                        case "error_nonce_gap":               submitError = "error_nonce_gap"

                        case "error_fee_insufficient":        submitError = "error_fee_insufficient"
                        case "error_fee_rate_insufficient":   submitError = "error_fee_rate_insufficient"
                        case "error_fee_budget_insufficient": submitError = "error_fee_budget_insufficient"

                        case "error_balance_insufficient":    submitError = "error_balance_insufficient"
                        case "error_account_unknown":         submitError = "error_account_unknown"
                        default:                              submitError = "unknown"
                        }
                        respError = SystemClientError.url(submitError)
                    }
                default:
                    respError = SystemClientError.url("Submission Status Error: Unrecognized Status Code: \(res.statusCode)")
                }

                completion (Result.failure(respError))
                return
            }

            completion (deserializer (data))
            }.resume()
    }*/

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
            else { completion (Result.failure(SystemClientError.url("URLComponents"))); return }

        urlBuilder.path += path.starts(with: "/") ? path : "/\(path)"
        if let query = query {
            urlBuilder.queryItems = query.map { URLQueryItem (name: $0, value: $1) }
        }

        guard let url = urlBuilder.url
            else { completion (Result.failure (SystemClientError.url("URLComponents.url"))); return }

        print ("SYS: BDB: Request: \(url.absoluteString): Method: \(httpMethod): Data: \(data?.description ?? "[]")")

        var request = URLRequest (url: url)
        decorateRequest(&request, httpMethod: httpMethod)

        // If we have data as a JSON.Dict, then add it as the httpBody to the request.
        if let data = data {
            do { request.httpBody = try JSONSerialization.data (withJSONObject: data, options: []) }
            catch let jsonError as NSError {
                completion (Result.failure (SystemClientError.jsonParse(jsonError)))
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
            else { completion (Result.failure(SystemClientError.url("URLComponents"))); return }

        urlBuilder.path += path.starts(with: "/") ? path : "/\(path)"
        if let query = query {
            urlBuilder.queryItems = query.map { URLQueryItem (name: $0, value: $1) }
        }

        guard let url = urlBuilder.url
            else { completion (Result.failure (SystemClientError.url("URLComponents.url"))); return }

        print ("SYS: BDB: Request: \(url.absoluteString): Method: \(httpMethod): Data: \(data?.description ?? "[]")")

        var request = URLRequest (url: url)
        decorateRequest(&request, httpMethod: httpMethod)

        // If we have data as a JSON.Dict, then add it as the httpBody to the request.
        if let data = data {
            do { request.httpBody = try JSONSerialization.data (withJSONObject: data, options: []) }
            catch let jsonError as NSError {
                completion (Result.failure (SystemClientError.jsonParse(jsonError)))
            }
        }

        sendRequest (request, dataTaskFunc, responseSuccess (httpMethod), deserializer: deserializer, completion: completion)
    }
    
    /*internal func makeRequest<T> (_ dataTaskFunc: DataTaskFunc,
                                  _ baseURL: String,
                                  path: String,
                                  query: Zip2Sequence<[String],[String]>? = nil,
                                  data: JSON.Dict? = nil,
                                  httpMethod: String = "POST",
                                  deserializer: @escaping (_ data: Data?) -> Result<T, SystemClientError> = deserializeAsJSON,
                                  completion: @escaping (Result<T, SystemClientError>) -> Void) {
        guard var urlBuilder = URLComponents (string: baseURL)
            else { completion (Result.failure(SystemClientError.url("URLComponents.url"))); return }

        urlBuilder.path = path.starts(with: "/") ? path : "/\(path)"
        if let query = query {
            urlBuilder.queryItems = query.map { URLQueryItem (name: $0, value: $1) }
        }

        guard let url = urlBuilder.url
            else { completion (Result.failure (SystemClientError.url("URLComponents.url"))); return }

        print ("SYS: BDB: Request: \(url.absoluteString): Method: \(httpMethod): Data: \(data?.description ?? "[]")")

        var request = URLRequest (url: url)
        decorateRequest(&request, httpMethod: httpMethod)

        // If we have data as a JSON.Dict, then add it as the httpBody to the request.
        if let data = data {
            do { request.httpBody = try JSONSerialization.data (withJSONObject: data, options: []) }
            catch let jsonError as NSError {
                let warnString = "JSON.Error: '\(jsonError.description)'; Data: '\(data.description)'"
                completion (Result.failure (SystemClientError.jsonParse(jsonError)))
            }
        }

        sendRequest (request, dataTaskFunc, responseSuccess (httpMethod), deserializer: deserializer, completion: completion)
    }*/

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
                            else { return Result.failure(SystemClientError.model ("[JSON.Dict] expected")) }

                        return Result.success (data.map { JSON (dict: $0) })
        })
    }
    
    internal func bdbHandleResult_ (_ res: Result<JSON.Dict, SystemClientError>,
                                   embedded: Bool = true,
                                   embeddedPath path: String,
                                   completion: @escaping (URL?, Result<[JSON], SystemClientError>) -> Void) {
        //let res = res.map { JSON (dict: $0) }
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
                            else { return Result.failure(SystemClientError.model ("[JSON.Dict] expected")) }

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
            return Result.failure (SystemClientError.noEntity(id: id))
        case  1:
            guard let transfer = transform (data[0])
                else { return Result.failure (SystemClientError.model ("(JSON) -> T transform error (one)"))}
            return Result.success (transfer)
        default:
            return Result.failure (SystemClientError.model ("(JSON) -> T expected one only"))
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
            ? Result.failure(SystemClientError.model ("(JSON) -> T transform error (many)"))
            : Result.success(results as! [T])
    }
    
    private static func getManyExpected_<T> (data: [JSON], transform: (JSON) -> [T]?) -> Result<[T], SystemClientError> {
        let results = data.map (transform)
        return results.contains(where: { $0 == nil })
            ? Result.failure(SystemClientError.model ("(JSON) -> T transform error (many)"))
            : Result.success(results[0]!)
            //: Result.success(results as! [T])
    }
    
    private static func getManyExpected__<T> (data: [JSON.Dict], transform: (JSON) -> T?) -> Result<[T], SystemClientError> {
        
        let data = data.map { JSON (dict: $0) }
        let results = data.map (transform)
        return results.contains(where: { $0 == nil })
            ? Result.failure(SystemClientError.model ("(JSON) -> T transform error (many)"))
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
                    ?? Result<T,SystemClientError>.failure(SystemClientError.noData) })
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
