//
//  NTagECCManager.swift
//  NFCTagWriter
//
//  Created by 刘平安 on 1/15/26.
//

import Foundation
import CryptoKit

struct SecureKeys {
    // 去掉空格后的 Hex 字符串
    static let publicKeyHex = "3059301306072A8648CE3D020106082A8648CE3D03010703420004A802CDC3DE42CFA61970BD84B80D68506F67FB1AF6AEE4912BF13C38AE17F49E24AAD6EBBD4F43D8B7F4976229865CFC253FCFFD9B1D99383DCEAEAC6D3A4A36"
    
    static let privateKeyHex = "308193020100301306072A8648CE3D020106082A8648CE3D03010704793077020101042060211B0892A704FC584854586F23079C3E9538882F383FE8DCFC4298737E52D8A00A06082A8648CE3D030107A14403420004A802CDC3DE42CFA61970BD84B80D68506F67FB1AF6AEE4912BF13C38AE17F49E24AAD6EBBD4F43D8B7F4976229865CFC253FCFFD9B1D99383DCEAEAC6D3A4A36"
}

// 辅助扩展：Hex String 转 Data
extension Data {
    init?(hexString: String) {
        let len = hexString.count / 2
        var data = Data(capacity: len)
        var i = hexString.startIndex
        for _ in 0..<len {
            let j = hexString.index(i, offsetBy: 2)
            if let byte = UInt8(hexString[i..<j], radix: 16) {
                data.append(byte)
            } else { return nil }
            i = j
        }
        self = data
    }
}

class NTagECCManager {
    
    /// 从 X.509/SPKI 格式中提取原始公钥点 (65字节: 0x04 + x + y)
    /// - Parameter x509Data: X.509/SPKI DER 编码的公钥数据
    /// - Returns: 原始公钥点数据 (65字节)
    private func extractRawPublicKeyPoint(from x509Data: Data) throws -> Data {
        // 首先尝试精确的 ASN.1 解析
        do {
            return try extractRawPublicKeyPointASN1(from: x509Data)
        } catch {
            // 如果 ASN.1 解析失败，使用简单的查找方法作为备用
            return try extractRawPublicKeyPointSimple(from: x509Data)
        }
    }
    
    /// 使用 ASN.1 解析提取公钥点
    private func extractRawPublicKeyPointASN1(from x509Data: Data) throws -> Data {
        // X.509/SPKI 格式结构：
        // SEQUENCE {
        //   SEQUENCE { algorithm identifier }
        //   BIT STRING { 0x04 + x(32 bytes) + y(32 bytes) }
        // }
        
        var index = 0
        
        // 1. 验证并跳过外层 SEQUENCE (0x30)
        guard index < x509Data.count, x509Data[index] == 0x30 else {
            throw NSError(domain: "NTagECCManager", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid X.509 format: missing SEQUENCE"])
        }
        index += 1
        
        // 2. 读取并跳过外层 SEQUENCE 的长度
        guard index < x509Data.count else {
            throw NSError(domain: "NTagECCManager", code: -2, userInfo: [NSLocalizedDescriptionKey: "Invalid X.509 format: incomplete SEQUENCE length"])
        }
        if (x509Data[index] & 0x80) == 0 {
            // 单字节长度
            index += 1
        } else {
            // 多字节长度
            let lengthOfLength = Int(x509Data[index] & 0x7F)
            guard lengthOfLength > 0, index + lengthOfLength < x509Data.count else {
                throw NSError(domain: "NTagECCManager", code: -3, userInfo: [NSLocalizedDescriptionKey: "Invalid X.509 format: invalid length encoding"])
            }
            index += 1 + lengthOfLength
        }
        
        // 3. 验证并跳过算法标识符 SEQUENCE (0x30)
        guard index < x509Data.count, x509Data[index] == 0x30 else {
            throw NSError(domain: "NTagECCManager", code: -4, userInfo: [NSLocalizedDescriptionKey: "Invalid X.509 format: missing algorithm SEQUENCE"])
        }
        index += 1
        
        // 4. 读取并跳过算法标识符的长度
        guard index < x509Data.count else {
            throw NSError(domain: "NTagECCManager", code: -5, userInfo: [NSLocalizedDescriptionKey: "Invalid X.509 format: incomplete algorithm identifier length"])
        }
        if (x509Data[index] & 0x80) == 0 {
            // 单字节长度
            let algLength = Int(x509Data[index])
            index += 1 + algLength
        } else {
            // 多字节长度
            let lengthOfLength = Int(x509Data[index] & 0x7F)
            guard lengthOfLength > 0, index + lengthOfLength < x509Data.count else {
                throw NSError(domain: "NTagECCManager", code: -6, userInfo: [NSLocalizedDescriptionKey: "Invalid X.509 format: invalid algorithm identifier length encoding"])
            }
            index += 1
            var algLength = 0
            for _ in 0..<lengthOfLength {
                guard index < x509Data.count else {
                    throw NSError(domain: "NTagECCManager", code: -7, userInfo: [NSLocalizedDescriptionKey: "Invalid X.509 format: incomplete algorithm identifier length"])
                }
                algLength = (algLength << 8) | Int(x509Data[index])
                index += 1
            }
            index += algLength
        }
        
        // 5. 验证 BIT STRING (0x03)
        guard index < x509Data.count, x509Data[index] == 0x03 else {
            throw NSError(domain: "NTagECCManager", code: -8, userInfo: [NSLocalizedDescriptionKey: "Invalid X.509 format: missing BIT STRING"])
        }
        index += 1
        
        // 6. 读取 BIT STRING 长度
        guard index < x509Data.count else {
            throw NSError(domain: "NTagECCManager", code: -9, userInfo: [NSLocalizedDescriptionKey: "Invalid X.509 format: incomplete BIT STRING length"])
        }
        if (x509Data[index] & 0x80) == 0 {
            // 单字节长度
            index += 1
        } else {
            // 多字节长度
            let lengthOfLength = Int(x509Data[index] & 0x7F)
            guard lengthOfLength > 0, index + lengthOfLength < x509Data.count else {
                throw NSError(domain: "NTagECCManager", code: -10, userInfo: [NSLocalizedDescriptionKey: "Invalid X.509 format: invalid BIT STRING length encoding"])
            }
            index += 1
            for _ in 0..<lengthOfLength {
                guard index < x509Data.count else {
                    throw NSError(domain: "NTagECCManager", code: -11, userInfo: [NSLocalizedDescriptionKey: "Invalid X.509 format: incomplete BIT STRING length"])
                }
                index += 1
            }
        }
        
        // 7. 跳过 unused bits 字节（通常是 0x00）
        guard index < x509Data.count else {
            throw NSError(domain: "NTagECCManager", code: -12, userInfo: [NSLocalizedDescriptionKey: "Invalid X.509 format: incomplete BIT STRING content"])
        }
        index += 1
        
        // 8. 验证并提取公钥点（应该是 0x04 + 64字节）
        guard index < x509Data.count,
              x509Data[index] == 0x04,
              index + 65 <= x509Data.count else {
            // 提供更详细的错误信息
            let actualByte = index < x509Data.count ? String(format: "0x%02X", x509Data[index]) : "EOF"
            let remainingBytes = index < x509Data.count ? x509Data.count - index : 0
            throw NSError(domain: "NTagECCManager", code: -13, userInfo: [
                NSLocalizedDescriptionKey: "Invalid X.509 format: cannot find public key point (0x04) in BIT STRING. Found: \(actualByte), remaining bytes: \(remainingBytes), index: \(index)"
            ])
        }
        
        // 提取 65 字节：0x04 + x(32 bytes) + y(32 bytes)
        return x509Data.subdata(in: index..<(index + 65))
    }
    
    /// 使用简单方法提取公钥点（备用方法）
    /// 查找数据中最后一个可能的 0x04，然后验证其后的 64 字节是否有效
    private func extractRawPublicKeyPointSimple(from x509Data: Data) throws -> Data {
        // 从后往前查找 0x04，因为公钥点通常在数据末尾
        var pointIndex: Int? = nil
        for i in stride(from: x509Data.count - 65, through: 0, by: -1) {
            if x509Data[i] == 0x04 && i + 65 <= x509Data.count {
                pointIndex = i
                break
            }
        }
        
        guard let index = pointIndex else {
            throw NSError(domain: "NTagECCManager", code: -20, userInfo: [
                NSLocalizedDescriptionKey: "Invalid X.509 format: cannot find public key point (0x04) in data"
            ])
        }
        
        // 提取 65 字节：0x04 + x(32 bytes) + y(32 bytes)
        return x509Data.subdata(in: index..<(index + 65))
    }
    
    // 1. 加载公钥进行验签 (X.509 格式)
    func loadPublicKey() throws -> P256.Signing.PublicKey {
        let data = Data(hexString: SecureKeys.publicKeyHex)!
        
        // 方法1: 优先使用 derRepresentation (X.509 是 DER 编码的 SPKI) - 这是正确的方法
        // iOS 14+ 支持，iOS 20 完全支持
        if #available(iOS 14.0, *) {
            do {
                return try P256.Signing.PublicKey(derRepresentation: data)
            } catch {
                // 如果 derRepresentation 失败（理论上不应该），fallback 到方法2
                print("derRepresentation failed, falling back to x963Representation: \(error)")
            }
        }
        
        // 方法2: 从 X.509 格式中提取原始公钥点，使用 x963Representation
        // x963Representation 从 iOS 13 开始支持，iOS 20 完全支持
        // 专门用于未压缩点格式 (0x04 + x + y)
        let rawPoint = try extractRawPublicKeyPoint(from: data)
        return try P256.Signing.PublicKey(x963Representation: rawPoint)
    }
    
    // 2. 加载私钥进行签名 (PKCS#8 格式)
    func loadPrivateKey() throws -> P256.Signing.PrivateKey {
        let data = Data(hexString: SecureKeys.privateKeyHex)!
        // 使用 derRepresentation 解析 PKCS#8 格式的私钥 (PKCS#8 是 DER 编码格式)
        return try P256.Signing.PrivateKey(derRepresentation: data)
    }
    
    // Swift 验签示例
    // Signature: 3044022063766b19ff92290e1dfd75c00dcf87d1f99b794b9bf3c543ee86ff6f1bafbe68022023235849678347951689f8ae8a66c128401c9d8d94f5ab591c922444629b4f1f
    // uidHex: 0464171A282290
    func verify(uidHex: String, signatureHex: String) -> Bool {
        do {
            let pubKey = try loadPublicKey()
            let uidData = Data(hexString: uidHex)!
            let sigData = Data(hexString: signatureHex)!
            
            // 关键点：将 Android 的 DER 格式转换为 CryptoKit 结构
            let signature = try P256.Signing.ECDSASignature(derRepresentation: sigData)
            
            if pubKey.isValidSignature(signature, for: uidData) {
                print("验证成功！")
                return true
            } else {
                print("验证失败。")
                return false
            }
        } catch {
            print("错误: \(error)")
            return false
        }
    }

    /// 使用公钥验证来自 Kotlin 的签名
    /// - Parameters:
    ///   - uidHex: UID 的十六进制字符串
    ///   - signatureDerHex: DER 编码签名的十六进制字符串
    ///   - publicKeyDerHex: X.509 公钥的十六进制字符串
    func verifySignature(uidHex: String, signatureDerHex: String, publicKeyDerHex: String) -> Bool {
        guard let dataToVerify = Data(hexString: uidHex),
              let signatureData = Data(hexString: signatureDerHex),
              let publicKeyData = Data(hexString: publicKeyDerHex) else {
            return false
        }

        do {
            // 1. 从 DER 导入公钥 (X.509 格式)
            let publicKey: P256.Signing.PublicKey
            
            // 尝试使用 derRepresentation (iOS 14+)
            if #available(iOS 14.0, *) {
                do {
                    publicKey = try P256.Signing.PublicKey(derRepresentation: publicKeyData)
                } catch {
                    // 如果失败，从 X.509 提取原始点，使用 x963Representation
                    let rawPoint = try extractRawPublicKeyPoint(from: publicKeyData)
                    publicKey = try P256.Signing.PublicKey(x963Representation: rawPoint)
                }
            } else {
                // iOS 13 及以下，使用原始点，使用 x963Representation
                let rawPoint = try extractRawPublicKeyPoint(from: publicKeyData)
                publicKey = try P256.Signing.PublicKey(x963Representation: rawPoint)
            }
            
            // 2. 从 DER 导入签名 (Kotlin 默认输出 DER 编码)
            let signature = try P256.Signing.ECDSASignature(derRepresentation: signatureData)
            
            // 3. 验证 (SHA256)
            return publicKey.isValidSignature(signature, for: dataToVerify)
        } catch {
            print("Verification failed with error: \(error)")
            return false
        }
    }

    /// 在 Swift 中生成签名给 Kotlin 验证
    func signData(uidHex: String, privateKeyPem: String) -> String? {
        guard let dataToSign = Data(hexString: uidHex) else { return nil }
        
        do {
            // 这里假设私钥是 PEM 或原始格式
            // 如果是 CryptoKit 生成的私钥：
            let privateKey = try P256.Signing.PrivateKey()
            let signature = try privateKey.signature(for: dataToSign)
            
            // 返回 DER 编码的十六进制，方便跨平台传输
            return signature.derRepresentation.hexEncodedString()
        } catch {
            return nil
        }
    }
}

// MARK: - 辅助扩展
extension Data {
//    init?(hexString: String) {
//        let len = hexString.count / 2
//        var data = Data(capacity: len)
//        var i = hexString.startIndex
//        for _ in 0..<len {
//            let j = hexString.index(i, offsetBy: 2)
//            if let byte = UInt8(hexString[i..<j], radix: 16) {
//                data.append(byte)
//            } else {
//                return nil
//            }
//            i = j
//        }
//        self = data
//    }

    func hexEncodedString() -> String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
}
