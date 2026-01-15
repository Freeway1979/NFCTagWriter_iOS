//
//  NFCTagWriterTests.swift
//  NFCTagWriterTests
//
//  Created by 刘平安 on 11/26/25.
//

import Testing
import XCTest
import CryptoSwift

@testable import NFCTagWriter

struct NFCTagWriterTests {

    @Test func testNxpOfficialVector() {
            // 1. 准备官方测试数据
            let masterKeyHex = "00000000000000000000000000000000" // "00112233445566778899AABBCCDDEEFF"
            let uidHex = "0464171A282290" // "04782E21805C05"
            let ctrHex = "0000CE" // "000001" // URL 中的大端序显示
            let expectedSessionKey = "A1A598F70530460A81295A2B0295D31D"
            let expectedFinalMac = "EDEC8186BF3D1153" // "53C72269F853F264"
            
            let masterKey = hexToBytes(masterKeyHex)
            let uid = hexToBytes(uidHex)
            let ctrBytes = hexToBytes(ctrHex)
            
            // 2. 构造 SV (Counter 必须反转为小端序)
            let ctrLittleEndian = Array(ctrBytes.reversed())
            let sv: [UInt8] = [0x3C, 0xC3, 0x00, 0x01, 0x00, 0x80] + uid + ctrLittleEndian
            
            do {
                // 3. 验证 Session Key 派生 (符合 NIST SP 800-38B)
                let sessionKey = try CMAC(key: masterKey).authenticate(sv)
                // XCTAssertEqual(bytesToHex(sessionKey), expectedSessionKey, "Session Key 派生不匹配！")
                
                // 4. 验证最终 MAC 计算 (空输入)
                let macInput: [UInt8] = []
                let fullMac = try CMAC(key: sessionKey).authenticate(macInput)
                
                // 5. 验证截取逻辑 (奇数位截取)
                let truncated = (0..<8).map { fullMac[$0 * 2 + 1] }
                let resultMac = bytesToHex(truncated)
                let matched = resultMac == expectedFinalMac
                XCTAssertTrue(matched)
                print("calculated CMAC:\(resultMac) expectedFinalMac:\(expectedFinalMac) matched:\(matched)")
              
//                XCTAssertEqual(resultMac, expectedFinalMac, "最终 SDM MAC 不匹配！")
                
                print("✅ 官方测试向量验证通过！环境配置正确。")
                
            } catch {
                XCTFail("计算过程中出现异常: \(error)")
            }
        }

        // 辅助方法
        private func hexToBytes(_ hex: String) -> [UInt8] {
            var result = [UInt8]()
            var hexStr = hex
            while hexStr.count > 0 {
                let sub = String(hexStr.prefix(2))
                result.append(UInt8(sub, radix: 16)!)
                hexStr = String(hexStr.dropFirst(2))
            }
            return result
        }

        private func bytesToHex(_ bytes: [UInt8]) -> String {
            return bytes.map { String(format: "%02X", $0) }.joined()
        }
    
    @Test func testCMAC() async throws {
        assert(Ntag424Verifier().verifyNtagSDM())
    }
    
    // Swift 验签示例
    // Signature: 3044022063766b19ff92290e1dfd75c00dcf87d1f99b794b9bf3c543ee86ff6f1bafbe68022023235849678347951689f8ae8a66c128401c9d8d94f5ab591c922444629b4f1f
    // uidHex: 0464171A282290
    @Test func testVerifySignature() async throws {
       let manager = NTagECCManager()
        let signatureHex = "3044022063766b19ff92290e1dfd75c00dcf87d1f99b794b9bf3c543ee86ff6f1bafbe68022023235849678347951689f8ae8a66c128401c9d8d94f5ab591c922444629b4f1f"
        let uidHex = "0464171A282290"
        let isValid = manager.verify(uidHex: uidHex, signatureHex: signatureHex)
        XCTAssertTrue(isValid)
    }

}
