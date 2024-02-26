import Foundation

public protocol KeychainServiceProtocol {
    func set<Value>(_ value: Value, for: String) throws where Value: Codable
    func get<Value>(for: String) throws -> Value? where Value: Codable
    func remove(for: String) throws
    func removeAllKeys() throws
    func hasValue(for: String) -> Bool
}

public enum KeychainError: Error {
    case error(OSStatus)
}
