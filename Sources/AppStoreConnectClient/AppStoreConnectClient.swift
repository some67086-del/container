import Foundation
import CryptoKit

public struct AppStoreConnectCredentials: Sendable {
    public let issuerID: String
    public let keyID: String
    public let privateKeyPEM: String

    public init(issuerID: String, keyID: String, privateKeyPEM: String) {
        self.issuerID = issuerID
        self.keyID = keyID
        self.privateKeyPEM = privateKeyPEM
    }
}

public enum AppStoreConnectError: Error, LocalizedError {
    case invalidResponse
    case http(status: Int, body: String)

    public var errorDescription: String? {
        switch self {
        case .invalidResponse: return "App Store Connect returned an invalid HTTP response."
        case let .http(status, body): return "App Store Connect HTTP \(status): \(body)"
        }
    }
}

public struct ASCResource<Attributes: Decodable & Sendable>: Decodable, Sendable {
    public let type: String
    public let id: String
    public let attributes: Attributes?
}

public struct ASCCollection<Attributes: Decodable & Sendable>: Decodable, Sendable {
    public let data: [ASCResource<Attributes>]
}

public struct AppAttributes: Decodable, Sendable {
    public let name: String?
    public let bundleId: String?
    public let sku: String?
    public let primaryLocale: String?
}

public struct BuildAttributes: Decodable, Sendable {
    public let version: String?
    public let uploadedDate: String?
    public let expirationDate: String?
    public let expired: Bool?
    public let minOsVersion: String?
    public let processingState: String?
    public let buildAudienceType: String?
    public let usesNonExemptEncryption: Bool?
}

public struct BetaGroupAttributes: Decodable, Sendable {
    public let name: String?
    public let createdDate: String?
    public let isInternalGroup: Bool?
    public let hasAccessToAllBuilds: Bool?
    public let publicLinkEnabled: Bool?
    public let publicLink: String?
    public let feedbackEnabled: Bool?
}

public actor AppStoreConnectClient {
    public static let defaultBaseURL = URL(string: "https://api.appstoreconnect.apple.com/")!

    private let credentials: AppStoreConnectCredentials
    private let baseURL: URL
    private let session: URLSession
    private let decoder = JSONDecoder()

    public init(
        credentials: AppStoreConnectCredentials,
        baseURL: URL = defaultBaseURL,
        session: URLSession = .shared
    ) {
        self.credentials = credentials
        self.baseURL = baseURL
        self.session = session
    }

    public func apps(limit: Int = 50) async throws -> [ASCResource<AppAttributes>] {
        try await getCollection(
            path: "v1/apps",
            query: [
                URLQueryItem(name: "fields[apps]", value: "name,bundleId,sku,primaryLocale"),
                URLQueryItem(name: "limit", value: String(min(max(limit, 1), 200)))
            ]
        )
    }

    public func builds(appID: String? = nil, limit: Int = 50) async throws -> [ASCResource<BuildAttributes>] {
        var query = [
            URLQueryItem(name: "fields[builds]", value: "version,uploadedDate,expirationDate,expired,minOsVersion,processingState,buildAudienceType,usesNonExemptEncryption"),
            URLQueryItem(name: "limit", value: String(min(max(limit, 1), 200)))
        ]
        if let appID {
            query.append(URLQueryItem(name: "filter[app]", value: appID))
        }
        return try await getCollection(path: "v1/builds", query: query)
    }

    public func betaGroups(appID: String? = nil, limit: Int = 50) async throws -> [ASCResource<BetaGroupAttributes>] {
        var query = [
            URLQueryItem(name: "fields[betaGroups]", value: "name,createdDate,isInternalGroup,hasAccessToAllBuilds,publicLinkEnabled,publicLink,feedbackEnabled"),
            URLQueryItem(name: "limit", value: String(min(max(limit, 1), 200)))
        ]
        if let appID {
            query.append(URLQueryItem(name: "filter[app]", value: appID))
        }
        return try await getCollection(path: "v1/betaGroups", query: query)
    }

    public func request(
        method: String = "GET",
        path: String,
        query: [URLQueryItem] = [],
        body: Data? = nil
    ) async throws -> Data {
        var components = URLComponents(url: baseURL.appending(path: path), resolvingAgainstBaseURL: false)!
        if !query.isEmpty { components.queryItems = query }
        var request = URLRequest(url: components.url!)
        request.httpMethod = method
        request.httpBody = body
        request.setValue("Bearer \(try makeJWT())", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if body != nil { request.setValue("application/json", forHTTPHeaderField: "Content-Type") }

        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw AppStoreConnectError.invalidResponse }
        guard (200..<300).contains(http.statusCode) else {
            throw AppStoreConnectError.http(
                status: http.statusCode,
                body: String(data: data, encoding: .utf8) ?? "<non-UTF8 response>"
            )
        }
        return data
    }

    private func getCollection<A: Decodable & Sendable>(
        path: String,
        query: [URLQueryItem]
    ) async throws -> [ASCResource<A>] {
        let data = try await request(path: path, query: query)
        return try decoder.decode(ASCCollection<A>.self, from: data).data
    }

    private func makeJWT(now: Date = Date()) throws -> String {
        let header = ["alg": "ES256", "kid": credentials.keyID, "typ": "JWT"]
        let issuedAt = Int(now.timeIntervalSince1970)
        let payload: [String: Any] = [
            "iss": credentials.issuerID,
            "iat": issuedAt,
            "exp": issuedAt + 20 * 60,
            "aud": "appstoreconnect-v1"
        ]

        let headerData = try JSONSerialization.data(withJSONObject: header, options: [.sortedKeys])
        let payloadData = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
        let signingInput = "\(base64URL(headerData)).\(base64URL(payloadData))"

        let key = try P256.Signing.PrivateKey(pemRepresentation: credentials.privateKeyPEM)
        let signature = try key.signature(for: Data(signingInput.utf8))
        return "\(signingInput).\(base64URL(signature.rawRepresentation))"
    }

    private func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
