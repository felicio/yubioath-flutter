import ExternalAccessory
import Flutter
import Security
import YubiKit

/// YubiKey sessions for a physical iPhone: NFC, USB-C smart card, and Lightning (5Ci).
final class YubiKeyPlugin: NSObject, FlutterPlugin, FlutterStreamHandler {
  static var eventSink: FlutterEventSink?
  private let session = YubiKeySession()

  static func register(with registrar: FlutterPluginRegistrar) {
    let plugin = YubiKeyPlugin()
    let methods = FlutterMethodChannel(
      name: "ios.yubikey",
      binaryMessenger: registrar.messenger()
    )
    registrar.addMethodCallDelegate(plugin, channel: methods)
    let events = FlutterEventChannel(
      name: "ios.yubikey.events",
      binaryMessenger: registrar.messenger()
    )
    events.setStreamHandler(plugin)
    Task {
      await plugin.session.setHandler { payload in
        DispatchQueue.main.async {
          YubiKeyPlugin.eventSink?(payload)
        }
      }
      await plugin.session.start()
    }
  }

  func onListen(withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink)
    -> FlutterError?
  {
    YubiKeyPlugin.eventSink = events
    return nil
  }

  func onCancel(withArguments arguments: Any?) -> FlutterError? {
    YubiKeyPlugin.eventSink = nil
    return nil
  }

  func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    let args = call.arguments as? [String: Any] ?? [:]
    Task {
      do {
        let payload = try await session.handle(call.method, args: args)
        DispatchQueue.main.async { result(payload) }
      } catch {
        DispatchQueue.main.async { result(Self.flutterError(error)) }
      }
    }
  }

  private static func flutterError(_ error: Error) -> FlutterError {
    if let connection = error as? SmartCardConnectionError {
      switch connection {
      case .cancelled, .cancelledByUser:
        return FlutterError(code: "cancelled", message: "Cancelled", details: nil)
      case .unsupported:
        return FlutterError(
          code: "unsupported",
          message:
            "NFC is not included in this install. A personal Apple team cannot enable it. A Lightning YubiKey still works.",
          details: nil
        )
      default:
        return FlutterError(code: "yubikey", message: String(describing: connection), details: nil)
      }
    }
    return FlutterError(code: "yubikey", message: String(describing: error), details: nil)
  }
}

private actor YubiKeySession {
  var onSnapshot: (@Sendable (Any?) -> Void)?
  private var wired: (any SmartCardConnection)?
  private var scanning = false
  private var credentials: [String: OATHSession.Credential] = [:]
  private var sessionPassword: String?
  private var watchTask: Task<Void, Never>?

  func setHandler(_ handler: @escaping @Sendable (Any?) -> Void) {
    onSnapshot = handler
  }

  func start() {
    Task { @MainActor in
      EAAccessoryManager.shared().registerForLocalNotifications()
    }
    watchTask = Task { await self.watchWired() }
  }

  func handle(_ method: String, args: [String: Any]) async throws -> Any? {
    switch method {
    case "scan":
      return try await scan()
    case "disconnect":
      await disconnect()
      return nil
    case "oathUnlock":
      let password = args["password"] as? String ?? ""
      let remember = args["remember"] as? Bool ?? false
      sessionPassword = password
      do {
        let snapshot = try await oathUnlock(password: password, remember: remember)
        return snapshot
      } catch {
        sessionPassword = nil
        throw error
      }
    case "oathSetPassword":
      return try await oathSetPassword(
        current: args["current"] as? String,
        password: args["password"] as? String ?? ""
      )
    case "oathUnsetPassword":
      return try await oathUnsetPassword(current: args["current"] as? String ?? "")
    case "oathForgetPassword":
      forgetPassword(deviceId: args["deviceId"] as? String)
      return nil
    case "oathReset":
      return try await mutate { session, _ in
        try await session.reset()
      }
    case "oathAdd":
      let uri = args["uri"] as? String ?? ""
      let requireTouch = args["requireTouch"] as? Bool ?? false
      return try await mutate { session, _ in
        guard let url = URL(string: uri) else {
          throw OATHSessionError.illegalArgument("Invalid otpauth URI", source: .here())
        }
        var template = try OATHSession.CredentialTemplate(url: url)
        template.requiresTouch = requireTouch
        _ = try await session.addCredential(template: template)
      }
    case "oathRename":
      let id = args["id"] as? String ?? ""
      let name = args["name"] as? String ?? ""
      let issuer = args["issuer"] as? String
      return try await mutate { session, stored in
        guard let credential = stored[id] else {
          throw OATHSessionError.credentialNotPresentOnCurrentYubiKey(source: .here())
        }
        try await session.renameCredential(credential, newName: name, newIssuer: issuer)
      }
    case "oathDelete":
      let id = args["id"] as? String ?? ""
      return try await mutate { session, stored in
        guard let credential = stored[id] else {
          throw OATHSessionError.credentialNotPresentOnCurrentYubiKey(source: .here())
        }
        try await session.deleteCredential(credential)
      }
    case "oathCalculate":
      let id = args["id"] as? String ?? ""
      return try await mutate { session, stored in
        guard let credential = stored[id] else {
          throw OATHSessionError.credentialNotPresentOnCurrentYubiKey(source: .here())
        }
        _ = try await session.calculateCredentialCode(for: credential)
      }
    default:
      throw SmartCardConnectionError.unsupported
    }
  }

  private func watchWired() async {
    while !Task.isCancelled {
      if scanning || wired != nil {
        try? await Task.sleep(for: .milliseconds(400))
        continue
      }
      let available = await wiredAvailable()
      if !available {
        try? await Task.sleep(for: .seconds(1))
        continue
      }
      do {
        let connection = try await connectWired()
        wired = connection
        let snapshot = try await readSnapshot(connection, transport: "usb")
        publish(snapshot)
        _ = await connection.waitUntilClosed()
        wired = nil
        if !scanning {
          credentials = [:]
          sessionPassword = nil
          publish(nil)
        }
      } catch {
        wired = nil
        try? await Task.sleep(for: .seconds(1))
      }
    }
  }

  private func scan() async throws -> [String: Any] {
    scanning = true
    if let wired {
      self.wired = nil
      await wired.close(error: nil)
    }
    defer { scanning = false }
    let connection = try await NFCSmartCardConnection(
      alertMessage: "Hold your YubiKey near the top of your iPhone"
    )
    do {
      let snapshot = try await readSnapshot(connection, transport: "nfc")
      if let nfc = connection as? NFCSmartCardConnection {
        await nfc.close(message: "YubiKey read")
      } else {
        await connection.close(error: nil)
      }
      publish(snapshot)
      return snapshot
    } catch {
      await connection.close(error: error)
      throw error
    }
  }

  private func disconnect() async {
    if let wired {
      self.wired = nil
      await wired.close(error: nil)
    }
    credentials = [:]
    sessionPassword = nil
    publish(nil)
  }

  private func mutate(
    _ change: (OATHSession, [String: OATHSession.Credential]) async throws -> Void
  ) async throws -> [String: Any] {
    if let wired, !scanning {
      let session = try await OATHSession.makeSession(connection: wired)
      try await change(session, credentials)
      let snapshot = try await readSnapshot(wired, transport: "usb")
      publish(snapshot)
      return snapshot
    }
    scanning = true
    defer { scanning = false }
    let connection = try await NFCSmartCardConnection(
      alertMessage: "Hold your YubiKey near the top of your iPhone"
    )
    do {
      let session = try await OATHSession.makeSession(connection: connection)
      let listed = try? await session.listCredentials()
      var stored = credentials
      if let listed {
        stored = Dictionary(uniqueKeysWithValues: listed.map { (Self.hex($0.id), $0) })
      }
      try await change(session, stored)
      let snapshot = try await readSnapshot(connection, transport: "nfc")
      if let nfc = connection as? NFCSmartCardConnection {
        await nfc.close(message: "Done")
      } else {
        await connection.close(error: nil)
      }
      publish(snapshot)
      return snapshot
    } catch {
      await connection.close(error: error)
      throw error
    }
  }

  private func oathUnlock(password: String, remember: Bool) async throws -> [String: Any] {
    try await mutate { session, _ in
      do {
        try await session.unlock(password: password)
        if remember {
          let deviceId = (try? await session.listCredentials().first?.deviceId) ?? ""
          if !deviceId.isEmpty {
            Self.savePassword(password, account: deviceId)
          }
        }
      } catch let error as OATHSessionError {
        if case .invalidPassword = error {
          throw error
        }
        throw error
      }
    }
  }

  private func oathSetPassword(current: String?, password: String) async throws -> [String: Any] {
    let previous = sessionPassword
    sessionPassword = password
    do {
      return try await mutate { session, _ in
        if let current, !current.isEmpty {
          try await session.unlock(password: current)
        }
        try await session.setPassword(password)
      }
    } catch {
      sessionPassword = previous
      throw error
    }
  }

  private func oathUnsetPassword(current: String) async throws -> [String: Any] {
    let previous = sessionPassword
    sessionPassword = nil
    do {
      return try await mutate { session, _ in
        try await session.unlock(password: current)
        try await session.deleteAccessKey()
        if let deviceId = try? await session.listCredentials().first?.deviceId {
          Self.deletePassword(account: deviceId)
        }
      }
    } catch {
      sessionPassword = previous
      throw error
    }
  }

  private func forgetPassword(deviceId: String?) {
    if let deviceId {
      Self.deletePassword(account: deviceId)
    }
  }

  private func readSnapshot(
    _ connection: any SmartCardConnection,
    transport: String
  ) async throws -> [String: Any] {
    let management = try await Management.Session.makeSession(connection: connection)
    let info = try await management.getDeviceInfo()
    let version = await management.version
    var snapshot: [String: Any] = [
      "transport": transport,
      "name": info.serialNumber == 0 ? "YubiKey" : "YubiKey \(info.serialNumber)",
      "info": Self.deviceInfoMap(info, version: version),
    ]

    snapshot["oath"] = NSNull()
    snapshot["credentials"] = []
    if let oath = try? await readOath(connection, serial: info.serialNumber) {
      snapshot["oath"] = oath.state
      snapshot["credentials"] = oath.credentials
      credentials = oath.stored
    }

    snapshot["otp"] = (try? await readOtp(connection)) ?? NSNull()
    snapshot["piv"] = (try? await readPiv(connection, version: version)) ?? NSNull()
    snapshot["fido"] = (try? await readFido(connection)) ?? NSNull()
    return snapshot
  }

  private struct OathRead {
    var state: [String: Any]
    var credentials: [[String: Any]]
    var stored: [String: OATHSession.Credential]
  }

  private func readOath(
    _ connection: any SmartCardConnection,
    serial: UInt
  ) async throws -> OathRead {
    let session = try await OATHSession.makeSession(connection: connection)
    let version = await session.version
    var locked = false
    var pairs: [(OATHSession.Credential, OATHSession.Code?)] = []
    do {
      pairs = try await session.calculateCredentialCodes()
    } catch let error as OATHSessionError {
      guard error.responseStatus?.status == .securityConditionNotSatisfied else { throw error }
      locked = true
      let listed = try await session.listCredentials()
      let account = listed.first?.deviceId ?? "\(serial)"
      let saved = sessionPassword ?? Self.loadPassword(account: account)
      if let saved {
        do {
          try await session.unlock(password: saved)
          sessionPassword = saved
          locked = false
          pairs = try await session.calculateCredentialCodes()
        } catch {
          pairs = listed.map { ($0, nil) }
        }
      } else {
        pairs = listed.map { ($0, nil) }
      }
    }

    let deviceId = pairs.first?.0.deviceId ?? "\(serial)"
    let stored = Dictionary(uniqueKeysWithValues: pairs.map { (Self.hex($0.0.id), $0.0) })
    let credentials = pairs.map { pair -> [String: Any] in
      let credential = pair.0
      let touch = Self.isTotp(credential) && pair.1 == nil && !locked
      var entry: [String: Any] = [
        "credential": [
          "device_id": credential.deviceId,
          "id": Self.hex(credential.id),
          "issuer": credential.issuer ?? NSNull(),
          "name": credential.name,
          "oath_type": Self.isTotp(credential) ? 0x20 : 0x10,
          "period": Self.period(credential),
          "touch_required": touch,
        ]
      ]
      if let code = pair.1 {
        entry["code"] = [
          "value": code.code,
          "valid_from": Int(code.validFrom.timeIntervalSince1970 * 1000),
          "valid_to": Self.validTo(code),
        ]
      } else {
        entry["code"] = NSNull()
      }
      return entry
    }
    let remembered = Self.loadPassword(account: deviceId) != nil && !locked
    let state: [String: Any] = [
      "device_id": deviceId,
      "version": [Int(version.major), Int(version.minor), Int(version.micro)],
      "has_key": locked || sessionPassword != nil,
      "remembered": remembered,
      "locked": locked,
      "keystore": remembered ? "allowed" : "unknown",
    ]
    return OathRead(state: state, credentials: credentials, stored: stored)
  }

  private func readOtp(_ connection: any SmartCardConnection) async throws -> [String: Any] {
    let session = try await YubiOTP.Session.makeSession(connection: connection)
    let state = await session.configState
    return [
      "slot1_configured": (try? state.isConfigured(.one)) ?? false,
      "slot2_configured": (try? state.isConfigured(.two)) ?? false,
    ]
  }

  private func readPiv(
    _ connection: any SmartCardConnection,
    version: Version
  ) async throws -> [String: Any] {
    let session = try await PIVSession.makeSession(connection: connection)
    let pin = try? await session.getPinMetadata()
    let slots: [PIV.Slot] = [
      .authentication, .signature, .keyManagement, .cardAuth,
      .retired1, .retired2, .retired3, .retired4, .retired5,
      .retired6, .retired7, .retired8, .retired9, .retired10,
      .retired11, .retired12, .retired13, .retired14, .retired15,
      .retired16, .retired17, .retired18, .retired19, .retired20,
    ]
    var slotMaps: [[String: Any]] = []
    for slot in slots {
      var entry: [String: Any] = ["slot": Int(slot.rawValue)]
      if let certificate = try? await session.getCertificate(in: slot) {
        entry["cert_info"] = Self.certInfo(certificate)
      }
      slotMaps.append(entry)
    }
    return [
      "state": [
        "version": [Int(version.major), Int(version.minor), Int(version.micro)],
        "authenticated": true,
        "stored_key": false,
        "pin_attempts": pin?.retriesRemaining ?? 3,
        "supports_bio": false,
      ],
      "slots": slotMaps,
    ]
  }

  private func readFido(_ connection: any SmartCardConnection) async throws -> [String: Any] {
    let session = try await CTAP2.Session.makeSession(connection: connection)
    let info = try await session.getInfo()
    var options: [String: Any] = [
      "clientPin": info.options.clientPin == true,
      "credMgmt": info.options.credentialManagement == true
        || info.options.credentialMgmtPreview == true,
      "alwaysUv": info.options.alwaysUV == true,
    ]
    if info.options.credentialManagement != nil {
      options["credentialMgmtPreview"] = info.options.credentialMgmtPreview == true
    }
    if let bio = info.options.bioEnroll {
      options["bioEnroll"] = bio
    }
    if let enterprise = info.options.enterpriseAttestation {
      options["ep"] = enterprise
    }
    if let readOnly = info.options.perCredMgmtRO {
      options["perCredMgmtRO"] = readOnly
    }
    var raw: [String: Any] = [
      "options": options,
      "min_pin_length": Int(info.minPinLength ?? 4),
      "force_pin_change": info.forcePinChange == true,
    ]
    if let remaining = info.remainingDiscoverableCredentials {
      raw["remaining_disc_creds"] = Int(remaining)
    }
    return [
      "info": raw,
      "unlocked": false,
      "unlocked_read": false,
    ]
  }

  private func wiredAvailable() async -> Bool {
    if let devices = try? await USBSmartCardConnection.availableDevices(), !devices.isEmpty {
      return true
    }
    return await lightningPresent()
  }

  private func connectWired() async throws -> any SmartCardConnection {
    if let slot = try await USBSmartCardConnection.availableDevices().first {
      return try await USBSmartCardConnection(slot: slot)
    }
    return try await LightningSmartCardConnection()
  }

  private func lightningPresent() async -> Bool {
    await MainActor.run {
      EAAccessoryManager.shared().connectedAccessories.contains {
        $0.protocolStrings.contains("com.yubico.ylp")
      }
    }
  }

  private func publish(_ payload: Any?) {
    onSnapshot?(payload)
  }

  private static func deviceInfoMap(_ info: DeviceInfo, version: Version) -> [String: Any] {
    let versionList = [Int(version.major), Int(version.minor), Int(version.micro)]
    var config: [String: Any] = [
      "enabled_capabilities": capabilityMap(info.config.enabledCapabilities)
    ]
    config["auto_eject_timeout"] = info.config.autoEjectTimeout.map(Int.init) ?? NSNull()
    config["challenge_response_timeout"] =
      info.config.challengeResponseTimeout.map(Int.init) ?? NSNull()
    config["device_flags"] = info.config.deviceFlags.map(Int.init) ?? NSNull()
    var result: [String: Any] = [:]
    result["config"] = config
    result["serial"] = info.serialNumber == 0 ? NSNull() : Int(info.serialNumber)
    result["version"] = versionList
    result["form_factor"] = Int(info.formFactor.rawValue)
    result["supported_capabilities"] = capabilityMap(info.supportedCapabilities)
    result["is_locked"] = info.isConfigLocked
    result["is_fips"] = info.isFIPS
    result["is_sky"] = info.isSKY
    result["pin_complexity"] = info.pinComplexity
    result["fips_capable"] = Int(info.fipsCapabilityFlags)
    result["fips_approved"] = Int(info.fipsApprovalFlags)
    result["reset_blocked"] = Int(info.resetBlockedFlags)
    result["version_qualifier"] = [
      "version": versionList,
      "type": 2,
      "iteration": 0,
    ]
    return result
  }

  private static func capabilityMap(_ values: [DeviceTransport: UInt]) -> [String: Int] {
    var map: [String: Int] = [:]
    if let usb = values[.usb] { map["usb"] = Int(usb) }
    if let nfc = values[.nfc] { map["nfc"] = Int(nfc) }
    if map["usb"] == nil { map["usb"] = 0 }
    return map
  }

  private static func certInfo(_ cert: X509Cert) -> [String: Any] {
    var subject = "Certificate"
    if let certificate = SecCertificateCreateWithData(nil, cert.der as CFData),
      let summary = SecCertificateCopySubjectSummary(certificate)
    {
      subject = summary as String
    }
    return [
      "key_type": NSNull(),
      "subject": subject,
      "issuer": subject,
      "serial": "",
      "not_valid_before": "",
      "not_valid_after": "",
      "fingerprint": hex(Data(cert.der.prefix(8))),
    ]
  }

  private static func isTotp(_ credential: OATHSession.Credential) -> Bool {
    if case .totp = credential.type { return true }
    return false
  }

  private static func period(_ credential: OATHSession.Credential) -> Int {
    if case .totp(let period) = credential.type { return Int(period) }
    return 30
  }

  private static func validTo(_ code: OATHSession.Code) -> Int {
    let millis = code.validTo.timeIntervalSince1970 * 1000
    if millis.isFinite {
      return Int(millis)
    }
    return Int(Date().timeIntervalSince1970 * 1000) + 86_400_000 * 3650
  }

  private static func hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
  }

  private static let passwordService = "com.yubico.yubioath.oath"

  private static func savePassword(_ password: String, account: String) {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: passwordService,
      kSecAttrAccount as String: account,
    ]
    SecItemDelete(query as CFDictionary)
    var add = query
    add[kSecValueData as String] = Data(password.utf8)
    SecItemAdd(add as CFDictionary, nil)
  }

  private static func loadPassword(account: String) -> String? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: passwordService,
      kSecAttrAccount as String: account,
      kSecReturnData as String: true,
      kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    var item: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
      let data = item as? Data
    else { return nil }
    return String(data: data, encoding: .utf8)
  }

  private static func deletePassword(account: String) {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: passwordService,
      kSecAttrAccount as String: account,
    ]
    SecItemDelete(query as CFDictionary)
  }
}
