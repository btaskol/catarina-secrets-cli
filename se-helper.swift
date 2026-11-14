// csec-se — tiny Secure Enclave helper for the csec CLI (macOS, Touch ID).
//
//   csec-se create
//       → {"blob": <base64 SE key handle>, "pub": <base64 X9.63 P-256 public key>}
//       The private key is generated inside the Secure Enclave, never leaves it, and can
//       only be used after user presence (Touch ID or the Mac password).
//
//   echo '{"blob": "...", "peer": "<base64 X9.63>"}' | csec-se derive --reason "…"
//       → {"shared": <base64 ECDH shared secret>}   (shows the Touch ID prompt)
//
// The "blob" is an encrypted handle that only this Mac's Secure Enclave can use.

import CryptoKit
import Foundation
import LocalAuthentication
import Security

struct Fail: Error { let message: String }

func emit(_ obj: [String: String]) {
    let data = try! JSONSerialization.data(withJSONObject: obj)
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write("\n".data(using: .utf8)!)
}

func run() throws {
    let args = CommandLine.arguments
    guard args.count >= 2 else { throw Fail(message: "usage: csec-se create | derive --reason TEXT") }
    guard SecureEnclave.isAvailable else { throw Fail(message: "secure_enclave_unavailable") }

    switch args[1] {
    case "create":
        var cfErr: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .userPresence], &cfErr
        ) else { throw Fail(message: "access_control: \(String(describing: cfErr))") }
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        emit(["blob": key.dataRepresentation.base64EncodedString(),
              "pub": key.publicKey.x963Representation.base64EncodedString()])

    case "derive":
        var reason = "use your Catarina secrets"
        if let i = args.firstIndex(of: "--reason"), i + 1 < args.count { reason = String(args[i + 1].prefix(120)) }
        let input = FileHandle.standardInput.readDataToEndOfFile()
        guard let obj = try JSONSerialization.jsonObject(with: input) as? [String: String],
              let blob = obj["blob"].flatMap({ Data(base64Encoded: $0) }),
              let peer = obj["peer"].flatMap({ Data(base64Encoded: $0) })
        else { throw Fail(message: "bad_input") }
        let ctx = LAContext()
        ctx.localizedReason = reason
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob, authenticationContext: ctx)
        let shared = try key.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: peer))
        let bytes = shared.withUnsafeBytes { Data($0) }
        emit(["shared": bytes.base64EncodedString()])

    default:
        throw Fail(message: "unknown command")
    }
}

do {
    try run()
} catch let e as Fail {
    FileHandle.standardError.write("csec-se: \(e.message)\n".data(using: .utf8)!)
    exit(2)
} catch {
    // LAError.userCancel etc. land here.
    let ns = error as NSError
    let cancelled = ns.domain == LAErrorDomain || ns.code == -128 || "\(error)".contains("authenticationFailed") || "\(error)".contains("userCancel")
    FileHandle.standardError.write("csec-se: \(cancelled ? "cancelled" : "\(error)")\n".data(using: .utf8)!)
    exit(cancelled ? 3 : 2)
}
