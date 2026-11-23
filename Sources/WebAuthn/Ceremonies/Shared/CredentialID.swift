#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

public struct CredentialID: Hashable, Sendable {
    private let storage: ContiguousArray<UInt8>

    public init(bytes: some Sequence<UInt8>) {
        self.storage = ContiguousArray(bytes)
    }

    public var bytes: Span<UInt8> {
        @_lifetime(borrow self)
        borrowing get { storage.span }
    }

    public var base64URLEncoded: URLEncodedBase64 {
        EncodedBase64(Data(storage).base64EncodedString()).urlEncoded
    }
}
