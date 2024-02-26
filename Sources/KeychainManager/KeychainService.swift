import Foundation

private let secMatchLimit: String = kSecMatchLimit as String
private let secReturnData: String = kSecReturnData as String
private let secReturnPersistentRef: String = kSecReturnPersistentRef as String
private let secValueData: String = kSecValueData as String
private let secAttrAccessible: String = kSecAttrAccessible as String
private let secClass: String = kSecClass as String
private let secAttrService: String = kSecAttrService as String
private let secAttrGeneric: String = kSecAttrGeneric as String
private let secAttrAccount: String = kSecAttrAccount as String
private let secAttrAccessGroup: String = kSecAttrAccessGroup as String
private let secReturnAttributes: String = kSecReturnAttributes as String

public class KeychainService: KeychainServiceProtocol {
    private let encoder: JSONEncoder = .init()
    private let decoder: JSONDecoder = .init()
    private let lock = NSLock()

    private (set) public var serviceName: String
    private (set) public var accessGroup: String?

    public init(serviceName: String, accessGroup: String? = nil) {
        self.serviceName = serviceName
        self.accessGroup = accessGroup
    }

    public func set<Value>(_ value: Value, for key: String) throws where Value: Codable {
        lock.lock()
        defer { lock.unlock() }
        let encoded: Data = try encoder.encode(value)
        try set(encoded, for: key, withAccessibility: nil)
    }

    public func get<Value>(for key: String) throws -> Value? where Value: Codable {
        lock.lock()
        defer { lock.unlock() }
        if let data = data(for: key, withAccessibility: nil) {
            return try decoder.decode(Value.self, from: data)
        }
        return nil
    }

    public func remove(for key: String) throws {
        lock.lock()
        defer { lock.unlock() }
        try remove(for: key, withAccessibility: nil)
    }

    public func removeAllKeys() throws {
        lock.lock()
        defer { lock.unlock() }
        let status: OSStatus = SecItemDelete(getBaseDictionary() as CFDictionary)

        if status != errSecSuccess && status != errSecItemNotFound {
            throw KeychainError.error(status)
        }
    }

    public func hasValue(for key: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        let data: Data? = data(for: key, withAccessibility: nil)
        return data != nil
    }

    private func getDictionary(
        for key: String,
        withAccessibility accessibility: KeychainItemAccessibility? = nil) -> [String: Any] {
        let encodedIdentifier: Data? = key.data(using: String.Encoding.utf8)
        var keychainQueryDictionary: [String: Any] = getBaseDictionary()
        if let accessibility {
            keychainQueryDictionary[secAttrAccessible] = accessibility.keychainAttrValue
        }
        keychainQueryDictionary[secAttrGeneric] = encodedIdentifier
        keychainQueryDictionary[secAttrAccount] = encodedIdentifier

        return keychainQueryDictionary
    }

    private func getBaseDictionary() -> [String: Any] {
        var keychainQueryDictionary: [String: Any] = [secClass: kSecClassGenericPassword]
        keychainQueryDictionary[secAttrService] = serviceName
        if let accessGroup = self.accessGroup {
            keychainQueryDictionary[secAttrAccessGroup] = accessGroup
        }
        return keychainQueryDictionary
    }

    private func data(for key: String,
                      withAccessibility accessibility: KeychainItemAccessibility?) -> Data? {
        var keychainQueryDictionary = getDictionary(for: key, withAccessibility: accessibility)

        keychainQueryDictionary[secMatchLimit] = kSecMatchLimitOne
        keychainQueryDictionary[secReturnData] = kCFBooleanTrue

        var result: AnyObject?
        let status = SecItemCopyMatching(keychainQueryDictionary as CFDictionary, &result)

        if status == noErr {
            return result as? Data
        }

        return nil
    }

    private func set(_ value: Data,
                     for key: String,
                     withAccessibility accessibility: KeychainItemAccessibility?) throws {
        var keychainQueryDictionary: [String: Any] = getDictionary(for: key, withAccessibility: accessibility)

        keychainQueryDictionary[secValueData] = value

        if let accessibility {
            keychainQueryDictionary[secAttrAccessible] = accessibility.keychainAttrValue
        } else {
            // Assign default protection - Protect the keychain entry so it's only valid when the device is unlocked
            keychainQueryDictionary[secAttrAccessible] = KeychainItemAccessibility.whenUnlocked.keychainAttrValue
        }

        let status: OSStatus = SecItemAdd(keychainQueryDictionary as CFDictionary, nil)

        if status == errSecDuplicateItem {
            try update(value, for: key, withAccessibility: accessibility)
        } else if status != errSecSuccess {
            throw KeychainError.error(status)
        }
    }

    private func remove(
        for key: String,
        withAccessibility accessibility: KeychainItemAccessibility?) throws {
        let keychainQueryDictionary: [String: Any] = getDictionary(for: key, withAccessibility: accessibility)

        let status: OSStatus = SecItemDelete(keychainQueryDictionary as CFDictionary)

        if status != errSecSuccess && status != errSecItemNotFound {
            throw KeychainError.error(status)
        }
    }

    private class func deleteKeychainSecClass(_ sClass: AnyObject) throws {
        let query = [secClass: sClass]
        let status: OSStatus = SecItemDelete(query as CFDictionary)

        if status != errSecSuccess && status != errSecItemNotFound {
            throw KeychainError.error(status)
        }
    }

    private func update(
        _ value: Data,
        for key: String,
        withAccessibility accessibility: KeychainItemAccessibility?) throws {
        let keychainQueryDictionary: [String: Any] = getDictionary(for: key, withAccessibility: accessibility)
        let updateDictionary = [secValueData: value]

        let status: OSStatus = SecItemUpdate(keychainQueryDictionary as CFDictionary, updateDictionary as CFDictionary)

        if status != errSecSuccess {
            throw KeychainError.error(status)
        }
    }
}

public enum KeychainItemAccessibility {
    case afterFirstUnlock
    case afterFirstUnlockThisDeviceOnly
    case whenPasscodeSetThisDeviceOnly
    case whenUnlocked
    case whenUnlockedThisDeviceOnly

    static func accessibilityForAttributeValue(_ keychainAttrValue: CFString) -> KeychainItemAccessibility? {
        for (key, value) in keychainItemAccessibilityLookup where value == keychainAttrValue {
            return key
        }
        return nil
    }
}

private let keychainItemAccessibilityLookup: [KeychainItemAccessibility: CFString] = {
    var lookup: [KeychainItemAccessibility: CFString] = [
        .afterFirstUnlock: kSecAttrAccessibleAfterFirstUnlock,
        .afterFirstUnlockThisDeviceOnly: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        .whenPasscodeSetThisDeviceOnly: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
        .whenUnlocked: kSecAttrAccessibleWhenUnlocked,
        .whenUnlockedThisDeviceOnly: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    ]

    return lookup
}()

protocol KeychainAttrRepresentable {
    var keychainAttrValue: CFString { get }
}

extension KeychainItemAccessibility: KeychainAttrRepresentable {
    internal var keychainAttrValue: CFString {
        // swiftlint: disable force_unwrapping
        keychainItemAccessibilityLookup[self]!
        // swiftlint: enable force_unwrapping
    }
}
