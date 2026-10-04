import SwiftUI
import AppKit
import Foundation
import CryptoKit
import Security
import JavaScriptCore

struct Account: Codable, Identifiable {
    var id = UUID().uuidString
    var email: String
    var password: String
    var secret: String
}
enum Failure: Error, LocalizedError {
    case message(String)
    var errorDescription: String? { if case .message(let s) = self { return s }; return nil }
}
func decodeSecret(_ input: String) throws -> [UInt8] {
    let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    let s = input.uppercased().filter { !$0.isWhitespace }.replacingOccurrences(of: "=", with: "")
    guard !s.isEmpty else { throw Failure.message("TOTP 密钥不能为空") }
    var bits = 0, value = 0, result = [UInt8]()
    for c in s {
        guard let n = alphabet.firstIndex(of: c) else { throw Failure.message("TOTP 密钥只能包含 A–Z 和 2–7；请复制长期密钥，不是六位验证码") }
        value = (value << 5) | n; bits += 5
        if bits >= 8 { bits -= 8; result.append(UInt8((value >> bits) & 255)); value &= (1 << bits) - 1 }
    }
    guard result.count >= 10, value == 0, [0,2,4,5,7].contains(s.count % 8) else { throw Failure.message("TOTP 密钥长度或结尾无效") }
    return result
}
func totp(_ secret: String, time: TimeInterval = Date().timeIntervalSince1970, digits: Int = 6) throws -> String {
    let key = SymmetricKey(data: Data(try decodeSecret(secret)))
    var counter = UInt64(time / 30).bigEndian
    let mac = withUnsafeBytes(of: &counter) { HMAC<Insecure.SHA1>.authenticationCode(for: Data($0), using: key) }
    let bytes = Array(mac), offset = Int(bytes.last! & 15)
    var number: UInt32 = 0
    for i in offset..<(offset + 4) { number = (number << 8) | UInt32(bytes[i]) }
    number &= 0x7fffffff
    return String(format: "%0*u", digits, number % UInt32(pow(10.0, Double(digits))))
}
func parseAccounts(_ text: String) throws -> [Account] {
    var result = [Account](), seen = Set<String>()
    for (index, raw) in text.components(separatedBy: .newlines).enumerated() {
        let line = raw.trimmingCharacters(in: .whitespaces)
        if line.isEmpty { continue }
        var columns: [String]
        if line.contains("\t") { columns = line.components(separatedBy: "\t") } else if line.contains("|") {
            var body = line
            if body.hasPrefix("|") { body.removeFirst() }
            if body.hasSuffix("|") { body.removeLast() }
            columns = body.components(separatedBy: "|")
        } else { columns = line.components(separatedBy: line.contains("\t") ? "\t" : "----") }
        columns = columns.map { $0.trimmingCharacters(in: .whitespaces) }
        if columns.allSatisfy({ !$0.isEmpty && $0.allSatisfy { "-: ".contains($0) } }) { continue }
        if let first = columns.first, ["邮箱", "账号", "email", "account"].contains(first.lowercased()) { continue }
        guard columns.count == 2 || columns.count == 3 else { throw Failure.message("第 \(index + 1) 行：需要邮箱和密码两列，第三列 TOTP 密钥可选") }
        let email = columns[0].replacingOccurrences(of: "\\@", with: "@").lowercased()
        guard email.contains("@"), !email.contains(" "), !columns[1].isEmpty else { throw Failure.message("第 \(index + 1) 行：邮箱或密码无效") }
        let secret = columns.count == 3 ? columns[2].uppercased().filter { !$0.isWhitespace } : ""
        if !secret.isEmpty {
            do { _ = try decodeSecret(secret) } catch { throw Failure.message("第 \(index + 1) 行：\(error.localizedDescription)") }
        }
        guard seen.insert(email).inserted else { throw Failure.message("第 \(index + 1) 行：导入内容中邮箱重复") }
        result.append(Account(email: email, password: columns[1], secret: secret))
    }
    guard !result.isEmpty else { throw Failure.message("没有可导入的账号") }
    return result
}
struct Vault {
    static var query: [String: Any] { [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "local.flowlauncher.v1", kSecAttrAccount as String: "accounts"] }
    static func read() throws -> [Account] {
        var q = query; q[kSecReturnData as String] = true; q[kSecMatchLimit as String] = kSecMatchLimitOne
        var value: CFTypeRef?; let status = SecItemCopyMatching(q as CFDictionary, &value)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess, let data = value as? Data else { throw Failure.message("无法读取钥匙串（\(status)）；不会覆盖原有数据") }
        return try JSONDecoder().decode([Account].self, from: data)
    }
    static func write(_ accounts: [Account]) throws {
        let data = try JSONEncoder().encode(accounts)
        var status = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecItemNotFound {
            var q = query; q[kSecValueData as String] = data
            q[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            status = SecItemAdd(q as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw Failure.message("钥匙串保存失败（\(status)），原列表未更改") }
    }
}

struct DriverFailure: Error, LocalizedError {
    let code: String
    var errorDescription: String? {
        let messages = ["timeout": "页面加载超时", "script timeout": "页面脚本响应超时", "invalid session id": "Chrome 会话已关闭，请关闭此账号窗口后重试", "no such window": "Chrome 标签页已关闭，请关闭此账号窗口后重试", "javascript error": "页面结构发生变化或正在跳转", "session not created": "无法创建 Chrome 会话：可能被旧窗口占用，请退出旧版助手及其 Chrome 后重试", "unknown error": "Chrome 返回内部错误"]
        return messages[code] ?? "Chrome 控制错误（请关闭此账号窗口后重试）"
    }
    var transient: Bool { ["timeout", "script timeout", "javascript error", "stale element reference"].contains(code) }
}
enum LoginFields {
    static let email = "#identifierId,input[name='identifier'],input[type='email'],input[autocomplete='username']"
    static let password = "input[name='Passwd'],input[type='password']"
    static let otp = "#totpPin,input[name='totpPin']"
    static let visibleScript = "return Array.from(document.querySelectorAll(arguments[0])).find(e=>e.getClientRects().length && !e.disabled && !e.readOnly) || null"
}
final class StopFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var flag = false
    var stopped: Bool { lock.lock(); defer { lock.unlock() }; return flag }
    func set(_ value: Bool) { lock.lock(); flag = value; lock.unlock() }
}
enum GooglePrompts {
    static let skipPasskeyScript = """
    if(location.protocol!=='https:' || location.hostname!=='accounts.google.com') return 'none';
    const text=document.body?.innerText||'';
    const heading=Array.from(document.querySelectorAll('h1,[role="heading"]')).map(e=>e.innerText||e.textContent||'').join(' ');
    if(!/(通行密钥|通行密鑰|通行金鑰|passkeys?)/i.test(text)) return 'none';
    if(!/(简化.*登录|簡化.*登入|Simplify.*sign.?in|Sign in faster|Create.*passkey|创建通行密钥|建立通行金鑰)/i.test(heading)) return 'none';
    const nodes=Array.from(document.querySelectorAll('button,a,[role="button"]'));
    const skip=nodes.find(e=>e.getClientRects().length&&!e.disabled&&e.getAttribute('aria-disabled')!=='true'&&/^(以后再说|以後再說|稍后再说|稍後再說|Not now|Maybe later)$/i.test((e.innerText||e.textContent||e.getAttribute('aria-label')||'').trim()));
    if(!skip)return 'none';
    skip.click();return 'skipped';
    """
}
enum FlowPage {
    // Detect actual workspace controls, not landing-page marketing text or cookies.
    static let signedInScript = """
    if(location.protocol!=='https:' || !['flow.google.com','labs.google'].includes(location.hostname))return false;
    if(location.hostname==='labs.google' && !/^\\/fx\\/(?:[a-z-]+\\/)?tools\\/flow(?:\\/|$)/i.test(location.pathname))return false;
    if(/\\/about(?:\\/|$)/i.test(location.pathname))return false;
    const visible=e=>e.getClientRects().length && !e.disabled && e.getAttribute('aria-disabled')!=='true';
    const nodes=Array.from(document.querySelectorAll('button,a,[role="button"]')).filter(visible);
    const label=e=>(e.innerText||e.textContent||e.getAttribute('aria-label')||'').replace(/\\s+/g,' ').trim();
    if(nodes.some(e=>/^(sign in|log in|sign in with google|登录|登入|使用 Google (账号|帐号)登录)$/i.test(label(e))))return false;
    return nodes.some(e=>/^(?:(?:add|plus|新建|新增|\\+)\\s*)?(?:新建项目|创建项目|新建專案|建立專案|new project|create project)$/i.test(label(e)));
    """

    // Exact entry labels only. Do not click terms, purchase or account creation confirmations.
    static let actionScript = """
    if(location.protocol !== 'https:' || !['flow.google.com','labs.google'].includes(location.hostname)) return 'none';
    const visible=e=>!!e.getClientRects().length && !e.disabled;
    const label=e=>(e.innerText||e.textContent||e.getAttribute('aria-label')||'').replace(/\\s+/g,' ').trim();
    const safe=e=>{const h=e.getAttribute('href');if(!h)return true;try{const u=new URL(h,location.href);return u.protocol==='https:'&&['flow.google.com','labs.google','accounts.google.com'].includes(u.hostname)}catch{return false}};
    const nodes=Array.from(document.querySelectorAll('a,button,[role="button"]')).filter(e=>visible(e)&&safe(e));
    const entry=nodes.find(e=>/^(使用\\s*(Google\\s*)?Flow\\s*创建|Create with (Google )?Flow|Try (Google )?Flow|开始使用\\s*Flow)$/i.test(label(e)));
    if(entry){entry.click();return 'entry'}
    const signin=nodes.find(e=>/^(Sign in( with Google)?|Log in|登录|登入|使用 Google (账号|帐号)登录)$/i.test(label(e)) || (()=>{try{return new URL(e.getAttribute('href'),location.href).hostname==='accounts.google.com'}catch{return false}})());
    if(signin){signin.click();return 'signin'}
    return 'none';
    """
}

enum LoginTarget: String, Codable {
    case flow = "flow"
    case runninghub = "runninghub"
    var entryURL: String {
        switch self {
        case .flow: return "https://flow.google.com/"
        case .runninghub: return "https://www.runninghub.ai/zh-tw"
        }
    }
    var title: String {
        switch self {
        case .flow: return "Google Flow"
        case .runninghub: return "RunningHub"
        }
    }
    var hosts: [String] {
        switch self {
        case .flow: return ["flow.google.com", "labs.google"]
        case .runninghub: return ["runninghub.ai", "www.runninghub.ai"]
        }
    }
}

enum RunningHubPage {
    // Signed-out pages still show the login entry (header button or login modal).
    // Signed-in pages hide the entry and show a user avatar. Avatar selectors are
    // best effort: only the signed-out DOM was verified, so when unsure the
    // caller keeps waiting instead of claiming success.
    static let signedInScript = """
    if(location.protocol!=='https:' || !['runninghub.ai','www.runninghub.ai'].includes(location.hostname)) return false;
    const visible=e=>e.getClientRects().length && !e.disabled && e.getAttribute('aria-disabled')!=='true';
    const label=e=>(e.innerText||e.textContent||e.getAttribute('aria-label')||'').replace(/\\s+/g,' ').trim();
    const nodes=Array.from(document.querySelectorAll('button,a,[role="button"]')).filter(visible);
    if(nodes.some(e=>/(登\\s*入|註\\s*冊|注\\s*册|登\\s*录|^log\\s*in$|^sign\\s*in$)/i.test(label(e)))) return false;
    const avatar=document.querySelector('.ant-avatar,[class*="avatar"],[class*="Avatar"]');
    return !!(avatar && visible(avatar));
    """

    // Clicks the login entry, then the Google button inside the login modal.
    // Returns 'entry', 'google', 'modal' or 'none'. Never follows off-site links.
    static let actionScript = """
    if(location.protocol!=='https:' || !['runninghub.ai','www.runninghub.ai'].includes(location.hostname)) return 'none';
    const visible=e=>!!e.getClientRects().length && !e.disabled;
    const label=e=>(e.innerText||e.textContent||e.getAttribute('aria-label')||'').replace(/\\s+/g,' ').trim();
    const safe=e=>{const h=e.getAttribute('href');if(!h)return true;try{const u=new URL(h,location.href);return u.protocol==='https:'&&['runninghub.ai','www.runninghub.ai','accounts.google.com'].includes(u.hostname)}catch{return false}};
    const modalRoot=document.querySelector('.ant-modal-root');
    const modal=(modalRoot&&visible(modalRoot))?modalRoot:null;
    if(modal){
        const gimg=modal.querySelector('img[alt*="Google"]');
        let gbtn=gimg;
        while(gbtn&&gbtn!==modal){const t=gbtn.tagName;if(t==='BUTTON'||t==='A'||gbtn.getAttribute('role')==='button')break;gbtn=gbtn.parentElement;}
        const byText=Array.from(modal.querySelectorAll('button,a,[role="button"]')).find(e=>visible(e)&&safe(e)&&/使用\\s*Google.*(登入|登录)|Sign in with Google/i.test(label(e)));
        const target=(gbtn&&gbtn!==modal&&visible(gbtn)&&safe(gbtn))?gbtn:byText;
        if(target){target.click();return 'google'}
        return 'modal';
    }
    const entry=Array.from(document.querySelectorAll('button.login-btn,button,a,[role="button"]')).find(e=>visible(e)&&safe(e)&&/^(登入\\s*\\/\\s*註冊|登\\s*入|登\\s*录|log\\s*in|sign\\s*in)$/i.test(label(e)));
    if(entry){entry.click();return 'entry'}
    return 'none';
    """
}

func loginEntryMessage(target: LoginTarget, action: String) -> String {
    switch (target, action) {
    case (.flow, "entry"): return "已点击“使用 Google Flow 创建”，等待登录页"
    case (.flow, _): return "已点击 Google 登录，等待账号页面"
    case (.runninghub, "entry"): return "已点击登入，等待登录弹窗"
    case (.runninghub, "google"): return "已点击 Google 登录，等待账号页面"
    case (.runninghub, "modal"): return "登录弹窗已打开，正在定位 Google 登录按钮"
    case (_, _): return "已操作登录入口，等待页面响应"
    }
}

// One CDP connection per active tab. Replies are matched by id; unsolicited events
// never consume a waiting command. Everything stays on the loopback interface.
final class CDPReply: @unchecked Sendable {
    let ready = DispatchSemaphore(value: 0)
    var result: Result<[String: Any], Error>?
}
final class CDPConnection: @unchecked Sendable {
    private let socket: URLSessionWebSocketTask
    private let lock = NSLock()
    private var pending = [Int: CDPReply]()
    private var serial = 0
    private var closed = false
    init(url: URL) throws {
        guard url.scheme == "ws", url.host == "127.0.0.1", url.port != nil else { throw Failure.message("拒绝连接非本机 CDP 地址") }
        socket = Browser.http.webSocketTask(with: url)
        socket.resume(); receive()
    }
    private func receive() {
        socket.receive { [weak self] result in
            guard let self = self else { return }
            switch result {
            case .failure(_): self.failAll(Failure.message("Chrome CDP 连接已断开"))
            case .success(let message):
                let data: Data
                switch message { case .string(let text): data = Data(text.utf8); case .data(let bytes): data = bytes; @unknown default: self.receive(); return }
                if let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any], let id = root["id"] as? Int {
                    self.lock.lock()
                    if let reply = self.pending.removeValue(forKey: id) {
                        if root["error"] != nil { reply.result = .failure(DriverFailure(code: "javascript error")) }
                        else { reply.result = .success(root["result"] as? [String: Any] ?? [:]) }
                        reply.ready.signal()
                    }
                    self.lock.unlock()
                }
                self.receive()
            }
        }
    }
    private func failAll(_ error: Error) {
        lock.lock(); closed = true
        for reply in pending.values { reply.result = .failure(error); reply.ready.signal() }
        pending.removeAll(); lock.unlock()
    }
    func command(_ method: String, _ params: [String: Any] = [:]) throws -> [String: Any] {
        let reply = CDPReply()
        lock.lock()
        if closed { lock.unlock(); throw Failure.message("Chrome CDP 连接已关闭") }
        serial += 1; let id = serial; pending[id] = reply
        lock.unlock()
        let data = try JSONSerialization.data(withJSONObject: ["id": id, "method": method, "params": params])
        socket.send(.string(String(decoding: data, as: UTF8.self))) { [weak self] error in
            if error != nil { self?.failAll(Failure.message("无法向 Chrome 发送指令")) }
        }
        if reply.ready.wait(timeout: .now() + 20) != .success {
            lock.lock(); pending[id] = nil; lock.unlock()
            throw DriverFailure(code: "script timeout")
        }
        lock.lock(); let result = reply.result; lock.unlock()
        guard let result = result else { throw Failure.message("Chrome 未返回指令结果") }
        return try result.get()
    }
    func close() { failAll(Failure.message("CDP 已关闭")); socket.cancel(with: .goingAway, reason: nil) }
    deinit { socket.cancel(with: .goingAway, reason: nil) }
}

final class Browser: @unchecked Sendable {
    static let http = URLSession(configuration: .ephemeral)
    static let chromeBinary = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    var testCDP: ((String, [String: Any]) throws -> [String: Any])?
    let process = Process()
    let id: String
    var automatic = true
    var session = ""
    var port = 0
    var base: String { "http://127.0.0.1:\(port)" }
    private var connection: CDPConnection?
    private var logPipe: Pipe?
    let binaryPath: String
    init(id: String, binaryPath: String = Browser.chromeBinary) { self.id = id; self.binaryPath = binaryPath }
    static func arguments(profile: URL) -> [String] {
        ["--user-data-dir=" + profile.path, "--no-first-run", "--no-default-browser-check"]
    }
    static func allocatePort() throws -> Int {
        let fd = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw Failure.message("无法分配本机连接端口") }
        defer { Darwin.close(fd) }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bound = withUnsafePointer(to: &address) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard bound == 0 else { throw Failure.message("无法绑定本机连接端口") }
        var size = socklen_t(MemoryLayout<sockaddr_in>.size)
        let result = withUnsafeMutablePointer(to: &address) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &size) }
        }
        guard result == 0 else { throw Failure.message("无法取得本机连接端口") }
        return Int(UInt16(bigEndian: address.sin_port))
    }
    static func endpoint(from log: String, port: Int) -> String? {
        let prefix = "DevTools listening on ws://127.0.0.1:\(port)/devtools/browser/"
        guard let range = log.range(of: prefix) else { return nil }
        let suffix = log[range.upperBound...].prefix(while: { !$0.isWhitespace })
        guard !suffix.isEmpty else { return nil }
        return "ws://127.0.0.1:\(port)/devtools/browser/" + suffix
    }
    private func httpJSON(_ path: String) throws -> Any {
        let semaphore = DispatchSemaphore(value: 0)
        var data: Data?, failed = false
        let task = Self.http.dataTask(with: URLRequest(url: URL(string: base + path)!, timeoutInterval: 3)) { bytes, response, error in
            data = bytes; failed = error != nil || (response as? HTTPURLResponse)?.statusCode != 200; semaphore.signal()
        }
        task.resume()
        guard semaphore.wait(timeout: .now() + 4) == .success else { task.cancel(); throw Failure.message("本机 Chrome 连接超时") }
        guard !failed, let data = data else { throw Failure.message("无法读取 Chrome 调试信息") }
        return try JSONSerialization.jsonObject(with: data)
    }
    private func command(_ method: String, _ params: [String: Any] = [:]) throws -> [String: Any] {
        if let testCDP = testCDP { return try testCDP(method, params) }
        guard let connection = connection else { throw Failure.message("Chrome CDP 尚未连接") }
        return try connection.command(method, params)
    }
    private func pages() throws -> [[String: Any]] {
        (try httpJSON("/json/list") as? [[String: Any]] ?? []).filter { $0["type"] as? String == "page" }
    }
    func pageIDs() throws -> [String] { try pages().compactMap { $0["id"] as? String } }
    private func attach(_ page: [String: Any]) throws {
        guard let id = page["id"] as? String, let address = page["webSocketDebuggerUrl"] as? String,
              let url = URL(string: address), url.port == port else { throw Failure.message("Chrome 标签页连接信息无效") }
        connection?.close(); connection = try CDPConnection(url: url); session = id
        _ = try command("Page.enable")
    }
    func start(profile: URL, automatic: Bool = true, openingURL: String = "https://flow.google.com/") throws {
        self.automatic = automatic
        guard FileManager.default.fileExists(atPath: binaryPath) else { throw Failure.message("请将 Google Chrome 安装到应用程序文件夹") }
        try FileManager.default.createDirectory(at: profile, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        // Never delete an active profile's lock or attach to a browser we did not start.
        if let _ = try? FileManager.default.destinationOfSymbolicLink(atPath: profile.appendingPathComponent("SingletonLock").path) {
            throw Failure.message("此账号的 Chrome 配置仍有锁，请先关闭它的旧窗口；不会强行删除锁或账号数据")
        }
        process.executableURL = URL(fileURLWithPath: binaryPath)
        var args = Self.arguments(profile: profile)
        if automatic {
            port = try Self.allocatePort()
            args += ["--remote-debugging-address=127.0.0.1", "--remote-debugging-port=\(port)"]
        }
        if CommandLine.arguments.contains("--headless-test") { args.append("--headless=new") }
        args += ["--new-window", automatic ? "about:blank" : openingURL]
        process.arguments = args
        let pipe = Pipe(); logPipe = pipe
        process.standardOutput = FileHandle.nullDevice; process.standardError = pipe
        let fd = pipe.fileHandleForReading.fileDescriptor
        let flags = fcntl(fd, F_GETFL); _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
        try process.run()
        var log = "", endpoint: String?
        let deadline = Date().addingTimeInterval(20)
        repeat {
            var buffer = [UInt8](repeating: 0, count: 8192)
            let count = read(fd, &buffer, buffer.count)
            if count > 0 { log += String(decoding: buffer.prefix(count), as: UTF8.self) }
            if automatic { endpoint = Self.endpoint(from: log, port: port); if endpoint != nil { break } }
            else if process.isRunning, Date().timeIntervalSince(deadline.addingTimeInterval(-20)) > 1 { break }
            if !process.isRunning { break }
            Thread.sleep(forTimeInterval: 0.1)
        } while Date() < deadline
        _ = fcntl(fd, F_SETFL, flags)
        pipe.fileHandleForReading.readabilityHandler = { handle in
            if handle.availableData.isEmpty { handle.readabilityHandler = nil }
        }
        guard process.isRunning else {
            if CommandLine.arguments.contains("--browser-test") { print("Chrome test startup exited: \(process.terminationStatus)") }
            throw Failure.message("Chrome 启动后退出（退出码 \(process.terminationStatus)），请确认 Chrome 可正常打开且该账号旧窗口已关闭")
        }
        guard automatic else { return }
        guard let endpoint = endpoint else { throw Failure.message("Chrome 未提供 CDP 连接，请关闭此账号旧窗口后重试") }
        let version = try httpJSON("/json/version") as? [String: Any]
        guard version?["webSocketDebuggerUrl"] as? String == endpoint else { throw Failure.message("调试端口与本次启动的 Chrome 不匹配，已停止连接") }
        let available = try pages()
        guard let page = available.first(where: { $0["url"] as? String == "about:blank" }) ?? available.first else { throw Failure.message("Chrome 尚未创建标签页") }
        try attach(page)
    }
    func script(_ source: String, args: [Any] = []) throws -> Any {
        let encoded = String(decoding: try JSONSerialization.data(withJSONObject: args), as: UTF8.self)
        let expression = "(function(){" + source + "}).apply(null," + encoded + ")"
        let response = try command("Runtime.evaluate", ["expression": expression, "returnByValue": true, "awaitPromise": true, "timeout": 10000])
        if response["exceptionDetails"] != nil { throw DriverFailure(code: "javascript error") }
        return (response["result"] as? [String: Any])?["value"] ?? NSNull()
    }
    func navigate(_ url: String) throws {
        let response = try command("Page.navigate", ["url": url])
        if response["errorText"] != nil { throw Failure.message("Chrome 无法打开目标页面，请检查网络") }
        let deadline = Date().addingTimeInterval(12)
        while Date() < deadline {
            if let ready = try? script("return document.readyState"), let state = ready as? String, state != "loading" { return }
            Thread.sleep(forTimeInterval: 0.15)
        }
        // A usable document can exist while media or background requests are still loading.
    }
    func followNewTab(_ previous: Set<String>) throws {
        let current = try pages()
        if let added = current.first(where: { !previous.contains($0["id"] as? String ?? "") }) { try attach(added) }
        else if !current.contains(where: { $0["id"] as? String == session }), let page = current.first { try attach(page) }
    }
    static let trustedFieldScript = """
    if(location.protocol!=='https:' || location.hostname!=='accounts.google.com') throw Error('Origin mismatch');
    const e=Array.from(document.querySelectorAll(arguments[0])).find(e=>e.getClientRects().length&&!e.disabled&&!e.readOnly);
    if(!e) throw Error('Missing field');
    e.scrollIntoView({block:'center'});e.focus();
    if(arguments[1] && typeof e.select==='function') e.select();
    const r=e.getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2};
    """
    func fill(_ selector: String, text: String, next: String) throws {
        _ = try script(Self.trustedFieldScript, args: [selector, true])
        // Text is passed only over the local CDP socket, never via process arguments.
        _ = try command("Input.insertText", ["text": text])
        let verified = try script("""
        if(location.protocol!=='https:' || location.hostname!=='accounts.google.com') return false;
        const e=Array.from(document.querySelectorAll(arguments[0])).find(e=>e.getClientRects().length&&!e.disabled);
        return !!e&&document.activeElement===e&&e.value===arguments[1];
        """, args: [selector, text]) as? Bool ?? false
        guard verified else { throw Failure.message("输入内容未成功写入，请在 Chrome 中手动填写后继续") }
        let point = try script(Self.trustedFieldScript, args: [next + ",button[type='submit'],input[type='submit']", false]) as? [String: Any] ?? [:]
        guard let x = point["x"] as? Double, let y = point["y"] as? Double else { throw Failure.message("未找到下一步按钮") }
        _ = try command("Input.dispatchMouseEvent", ["type": "mousePressed", "x": x, "y": y, "button": "left", "clickCount": 1])
        _ = try command("Input.dispatchMouseEvent", ["type": "mouseReleased", "x": x, "y": y, "button": "left", "clickCount": 1])
    }
    func minimize() throws {
        guard automatic, process.isRunning else {throw Failure.message("此窗口不是 FL 自动打开的窗口")}
        let info = try command("Browser.getWindowForTarget")
        guard let windowID = info["windowId"] as? Int else {throw Failure.message("未找到 Chrome 窗口")}
        _ = try command("Browser.setWindowBounds",["windowId":windowID,"bounds":["windowState":"normal"]])
        _ = try command("Browser.setWindowBounds",["windowId":windowID,"bounds":["windowState":"minimized"]])
        let result = try command("Browser.getWindowBounds",["windowId":windowID])["bounds"] as? [String:Any]
        guard result?["windowState"] as? String == "minimized" else {throw Failure.message("Chrome 未确认窗口最小化")}
    }
    func tile(to rect: CGRect) throws -> Bool {
        guard automatic, process.isRunning else {throw Failure.message("此窗口不是 FL 自动打开的窗口")}
        let info = try command("Browser.getWindowForTarget")
        guard let windowID = info["windowId"] as? Int else {throw Failure.message("未找到 Chrome 窗口")}
        _ = try command("Browser.setWindowBounds",["windowId":windowID,"bounds":["windowState":"normal"]])
        _ = try command("Browser.setWindowBounds",["windowId":windowID,"bounds":["left":Int(rect.minX),"top":Int(rect.minY),"width":Int(rect.width),"height":Int(rect.height)]])
        let actual = try command("Browser.getWindowBounds",["windowId":windowID])["bounds"] as? [String:Any] ?? [:]
        return abs((actual["width"] as? Double ?? 0)-rect.width) <= 2 && abs((actual["height"] as? Double ?? 0)-rect.height) <= 2
    }
    func login(_ account: Account, target: LoginTarget = .flow, stop: StopFlag, update: @escaping (String) -> Void) throws {
        var stage = "打开 \(target.title)"
        do {
            update("正在打开 \(target.title)")
            try navigate(target.entryURL)
            var emailAttempts = 0, passwordSent = false, otpSent = false
            var emailLastSent = Date.distantPast
            var entryAttempts = 0, scriptFailures = 0
            var workspaceMatches = 0
            var passkeySkips = 0
            var lastPasskeySkip = Date.distantPast
            var lastAction = Date.distantPast
            var handles = Set(try pageIDs())
            let deadline = Date().addingTimeInterval(120)
            while Date() < deadline {
                if stop.stopped { update("已停止 · 浏览器窗口保留"); return }
                try followNewTab(handles)
                handles = Set(try pageIDs())
                let state: [String: Any]
                do {
                    state = try script("""
                    const visible=s=>Array.from(document.querySelectorAll(s)).some(e=>e.getClientRects().length&&!e.disabled&&!e.readOnly);
                    return {host:location.hostname,path:location.pathname,https:location.protocol==='https:',
                    email:visible(arguments[0]),password:visible(arguments[1]),otp:visible(arguments[2]),
                    error:!!document.querySelector('[aria-invalid=true]'),blocked:/此浏览器或应用可能不安全|This browser or app may not be secure/i.test(document.body?.innerText||'')};
                    """, args: [LoginFields.email, LoginFields.password, LoginFields.otp]) as? [String: Any] ?? [:]
                    scriptFailures = 0
                } catch let error as DriverFailure where error.transient && scriptFailures < 5 {
                    scriptFailures += 1; Thread.sleep(forTimeInterval: 1); continue
                }
                let host = state["host"] as? String ?? "", path = state["path"] as? String ?? ""
                if !target.hosts.contains(host) { workspaceMatches = 0 }
                if host == "accounts.google.com", state["https"] as? Bool == true {
                    if state["blocked"] as? Bool == true { update("Google 拒绝自动化登录 · 请点击普通打开，手动完成登录"); return }
                    if state["email"] as? Bool != true, state["password"] as? Bool != true, state["otp"] as? Bool != true,
                       passkeySkips < 3, Date().timeIntervalSince(lastPasskeySkip) > 5 {
                        stage = "处理通行密钥提示"
                        do {
                            if try script(GooglePrompts.skipPasskeyScript) as? String == "skipped" {
                                passkeySkips += 1; lastPasskeySkip = Date()
                                update("已点击“以后再说”，继续登录")
                                Thread.sleep(forTimeInterval: 1); continue
                            }
                        } catch let error as DriverFailure where error.transient {
                            Thread.sleep(forTimeInterval: 1); continue
                        }
                    }
                    if state["error"] as? Bool == true { update("需要人工操作：请检查登录信息或验证结果"); return }
                    if state["email"] as? Bool == true, emailAttempts < 2, Date().timeIntervalSince(emailLastSent) > 8 {
                        stage = "填写 Google 账号"; update(stage)
                        try fill(LoginFields.email, text: account.email, next: "#identifierNext"); emailAttempts += 1; emailLastSent = Date()
                    } else if state["password"] as? Bool == true, !passwordSent {
                        stage = "填写密码"; update(stage)
                        try fill(LoginFields.password, text: account.password, next: "#passwordNext"); passwordSent = true
                    } else if state["otp"] as? Bool == true, !otpSent {
                        guard !account.secret.isEmpty else {
                            update("此账号未配置 TOTP，请在 Chrome 中手动完成二步验证"); return
                        }
                        stage = "TOTP 验证"; update(stage)
                        if Int(Date().timeIntervalSince1970) % 30 > 25 { Thread.sleep(forTimeInterval: 6) }
                        try fill(LoginFields.otp, text: try totp(account.secret), next: "#totpNext"); otpSent = true
                    } else if state["email"] as? Bool == true, emailAttempts >= 2, Date().timeIntervalSince(emailLastSent) > 8 {
                        update("邮箱提交后仍停在登录页，请查看 Google 页面提示"); return
                    } else { update("等待 Google 页面 · 如出现额外验证请手动完成") }
                } else if target.hosts.contains(host), state["https"] as? Bool == true {
                    let signedIn = try script(target == .flow ? FlowPage.signedInScript : RunningHubPage.signedInScript) as? Bool == true
                    if signedIn {
                        workspaceMatches += 1
                        if workspaceMatches >= 2 {
                            update("已登录 · \(target.title)已就绪，继续下一个"); return
                        }
                        update("检测到\(target.title)已登录，正在确认状态")
                        Thread.sleep(forTimeInterval:1.2); continue
                    }
                    workspaceMatches = 0
                    if target == .flow, path.contains("/project/") || path.hasSuffix("/project") {
                        update("已进入 Flow 项目页 · 请在窗口确认账号"); return
                    }
                    if Date().timeIntervalSince(lastAction) > 8, entryAttempts < 4 {
                        stage = "进入\(target.title)登录入口"
                        let action: String
                        do { action = try script(target == .flow ? FlowPage.actionScript : RunningHubPage.actionScript) as? String ?? "none" }
                        catch let error as DriverFailure where error.transient {
                            Thread.sleep(forTimeInterval: 1); continue
                        }
                        if action != "none" {
                            lastAction = Date(); entryAttempts += 1
                            update(loginEntryMessage(target: target, action: action))
                        } else { update("正在识别\(target.title)页面 · 可手动点击登录") }
                    }
                } else if !host.isEmpty {
                    update("需要人工操作：浏览器进入了其他页面"); return
                }
                Thread.sleep(forTimeInterval: 1.2)
            }
            update("自动处理结束 · 请在 Chrome 确认可用状态或完成额外验证")
        } catch { throw Failure.message("\(stage)：\(error.localizedDescription)") }
    }
    func close() {
        if connection != nil { _ = try? command("Browser.close") }
        connection?.close(); connection = nil; session = ""
        if process.isRunning {
            process.terminate()
            let deadline = Date().addingTimeInterval(5)
            while process.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.1) }
        }
        logPipe?.fileHandleForReading.readabilityHandler = nil
    }
}

struct AccountGroup: Codable, Identifiable {
    var id = UUID().uuidString
    var name: String
    var scope: String
    var members: [String] = []
    var color = "#16A66A"
    var url = "https://flow.google.com/"
}

struct BookmarkItem: Codable, Identifiable {
    var id = UUID().uuidString
    var name: String
    var url: String
}
struct WorkspaceState: Codable {
    var groups: [AccountGroup] = []
    var recentIDs: [String] = []
    var notes: [String: String] = [:]
    var chromePath = Browser.chromeBinary
    var dataRoot = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("FlowLauncher").path
    var bookmarks: [BookmarkItem] = [BookmarkItem(name: "Google Flow", url: "https://flow.google.com/")]
    var fontSize: Double = 12
    var rowHeight: Double = 40
    var accent = "#16A66A"
    var styleRevision: Int? = 1
    mutating func migrateStyle() {
        guard styleRevision == nil else { return }
        fontSize = min(fontSize, 12); rowHeight = min(rowHeight, 40)
        styleRevision = 1
    }
    var runEnabled = true
    mutating func assign(_ ids: Set<String>, to groupID: String) {
        guard let i = groups.firstIndex(where: { $0.id == groupID }) else { return }
        groups[i].members = Array(Set(groups[i].members).union(ids)).sorted()
    }
    func ids(scope: String, filter: String, all: [String]) -> Set<String> {
        let available = Set(all)
        if filter == "recent" { return available.intersection(recentIDs) }
        if filter == "ungrouped" { return available.subtracting(groups.filter { $0.scope == scope }.flatMap(\.members)) }
        if filter == "all" { return available }
        return available.intersection(groups.first { $0.id == filter && $0.scope == scope }?.members ?? [])
    }
}
struct SystemProfile: Identifiable {
    var directory: String
    var name: String
    var email: String
    var id: String { "sys:" + directory }
}
enum ProfileFiles {
    static let systemRoot = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/Google/Chrome")
    static func safeSystemDirectory(_ directory: String, root: URL = systemRoot) throws -> URL {
        guard directory == "Default" || directory.range(of: "^Profile [0-9]+$", options: .regularExpression) != nil else { throw Failure.message("无效的系统浏览器目录") }
        let url = root.appendingPathComponent(directory)
        guard (try? FileManager.default.destinationOfSymbolicLink(atPath:url.path)) == nil else { throw Failure.message("不允许操作符号链接浏览器配置") }
        guard url.resolvingSymlinksInPath().deletingLastPathComponent() == root.resolvingSymlinksInPath() else { throw Failure.message("不允许操作指向其他目录的浏览器配置") }
        return url
    }
    struct ProcessEntry {
        let pid:Int32
        let command:String
    }
    static func processSnapshot() throws -> [ProcessEntry] {
        let process=Process(),pipe=Pipe()
        process.executableURL=URL(fileURLWithPath:"/bin/ps")
        process.arguments=["-axo","pid=,command="]
        process.standardOutput=pipe;process.standardError=FileHandle.nullDevice
        try process.run()
        let output=pipe.fileHandleForReading.readDataToEndOfFile();process.waitUntilExit()
        guard process.terminationStatus==0 else{throw Failure.message("无法读取进程状态，未更改浏览器环境")}
        return String(decoding:output,as:UTF8.self).components(separatedBy:.newlines).compactMap { line in
            let parts=line.trimmingCharacters(in:.whitespaces).split(maxSplits:1,whereSeparator:{$0.isWhitespace})
            guard parts.count==2,let pid=Int32(parts[0]) else{return nil}
            return ProcessEntry(pid:pid,command:String(parts[1]))
        }
    }
    static func ownsProfile(_ command:String,root:URL) -> Bool {
        // Match a complete user-data-dir value, not another profile sharing its prefix.
        for path in Set([root.path,root.resolvingSymlinksInPath().path]) {
            for prefix in ["--user-data-dir="+path,"--user-data-dir=\""+path+"\"","--user-data-dir "+path] {
                if let range=command.range(of:prefix) {
                    if range.upperBound==command.endIndex || command[range.upperBound].isWhitespace {return true}
                }
            }
        }
        return false
    }
    static func localHosts() -> Set<String> {
        var bytes=[CChar](repeating:0,count:256)
        var hosts=Set([ProcessInfo.processInfo.hostName])
        if gethostname(&bytes,bytes.count)==0 {hosts.insert(String(cString:bytes))}
        return hosts
    }
    static func staleLock(_ target:String, host:String, processExists:(Int32)->Bool, profileInUse:Bool) -> Bool {
        guard !profileInUse,let separator=target.lastIndex(of:"-"),String(target[..<separator])==host,
              let pid=Int32(target[target.index(after:separator)...]),pid>0 else{return false}
        return !processExists(pid)
    }
    static func lockOwner(_ root:URL) throws -> (String,Int32,String)? {
        let lock=root.appendingPathComponent("SingletonLock")
        guard let target=try? FileManager.default.destinationOfSymbolicLink(atPath:lock.path) else {
            if FileManager.default.fileExists(atPath:lock.path){throw Failure.message("浏览器锁格式未知，未更改")}
            return nil
        }
        guard let split=target.lastIndex(of:"-"),let pid=Int32(target[target.index(after:split)...]),pid>0 else{throw Failure.message("浏览器锁内容无效，未更改")}
        let host=String(target[..<split])
        guard localHosts().contains(host) else{throw Failure.message("浏览器锁来自其他电脑名称："+host+"，未自动清理")}
        return (target,pid,host)
    }
    static func isChrome(_ entry:ProcessEntry) -> Bool {
        // PID reuse must never cause an unrelated process to be terminated.
        guard let app=NSRunningApplication(processIdentifier:entry.pid),
              let executable=app.executableURL else{return false}
        return executable.lastPathComponent=="Google Chrome" && app.bundleIdentifier=="com.google.Chrome"
    }
    static func unlocked(_ root: URL) throws {
        guard let owner=try lockOwner(root) else{return}
        let snapshot=try processSnapshot()
        guard !snapshot.contains(where:{ownsProfile($0.command,root:root)}) else {
            throw Failure.message("此账号仍有 Chrome 后台进程，请点击该行 😴 关闭后重试")
        }
        if let entry=snapshot.first(where:{$0.pid==owner.1}) {
            // Permit stale IDs reused by a positively identified non-Chrome process.
            if isChrome(entry) || entry.command.localizedCaseInsensitiveContains("chrome") {
                throw Failure.message("锁记录的 Chrome 进程仍在运行，但无法确认所属窗口，未自动清理")
            }
        } else if kill(owner.1,0)==0 || errno != ESRCH {
            throw Failure.message("无法确认锁对应进程是否已退出，未清理")
        }
        let lock=root.appendingPathComponent("SingletonLock")
        guard (try? FileManager.default.destinationOfSymbolicLink(atPath:lock.path))==owner.0 else{throw Failure.message("锁已变化，请重试")}
        let latest=try processSnapshot()
        guard !latest.contains(where:{ownsProfile($0.command,root:root)}),
              latest.first(where:{$0.pid==owner.1})?.command == snapshot.first(where:{$0.pid==owner.1})?.command else{throw Failure.message("进程状态变化，请重试")}
        try FileManager.default.removeItem(at:lock)
    }
    static func closeManaged(_ root:URL) throws {
        // Recover only a Chrome process with this exact managed profile argument.
        let entries=try processSnapshot().filter{ownsProfile($0.command,root:root) && isChrome($0)}
        for entry in entries {
            guard let current=try processSnapshot().first(where:{$0.pid==entry.pid}),
                  current.command==entry.command,isChrome(current),ownsProfile(current.command,root:root) else{continue}
            guard let app=NSRunningApplication(processIdentifier:entry.pid),app.terminate() else {
                throw Failure.message("未能请求 Chrome 退出，请在活动监视器中退出对应进程")
            }
        }
        let deadline=Date().addingTimeInterval(8)
        while !entries.isEmpty && Date()<deadline {
            if try !processSnapshot().contains(where:{ownsProfile($0.command,root:root)}) {break}
            Thread.sleep(forTimeInterval:0.2)
        }
        try unlocked(root)
    }
    static func cookieFiles(_ profile: URL) -> [URL] {
        ["Cookies", "Cookies-journal", "Cookies-wal", "Cookies-shm", "Network/Cookies", "Network/Cookies-journal", "Network/Cookies-wal", "Network/Cookies-shm"].map { profile.appendingPathComponent($0) }
    }
    static func clearCookies(_ profile: URL) throws {
        let files=cookieFiles(profile).filter{FileManager.default.fileExists(atPath:$0.path)}
        for file in files {
            guard file.resolvingSymlinksInPath().path.hasPrefix(profile.resolvingSymlinksInPath().path+"/") else {throw Failure.message("Cookie 文件指向所选配置之外，未清理")}
        }
        for file in files {try FileManager.default.removeItem(at:file)}
    }
    static func validURL(_ text: String) -> Bool {
        guard let url = URL(string: text), let host = url.host, !host.isEmpty else { return false }
        return ["https", "http"].contains(url.scheme?.lowercased() ?? "")
    }
    static func applyBookmarks(_ items: [BookmarkItem], profile: URL) throws {
        guard items.allSatisfy({ !$0.name.trimmingCharacters(in: .whitespaces).isEmpty && validURL($0.url) }) else { throw Failure.message("书签名称和 http/https 地址不能为空") }
        let fm = FileManager.default
        try fm.createDirectory(at: profile, withIntermediateDirectories: true)
        let file = profile.appendingPathComponent("Bookmarks")
        guard file.resolvingSymlinksInPath().path.hasPrefix(profile.resolvingSymlinksInPath().path+"/") else {throw Failure.message("书签文件指向所选配置之外，未修改")}
        var root: [String: Any]
        if fm.fileExists(atPath: file.path) {
            guard let object = try JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any] else { throw Failure.message("原书签格式无法识别，未覆盖") }
            root = object
        } else {
            func folder(_ id: String, _ name: String) -> [String: Any] { ["id":id,"name":name,"type":"folder","children":[Any](),"date_added":"0","date_modified":"0"] }
            root = ["version":1,"roots":["bookmark_bar":folder("1","Bookmarks bar"),"other":folder("2","Other bookmarks"),"synced":folder("3","Mobile bookmarks")]]
        }
        guard var roots = root["roots"] as? [String: Any], var bar = roots["bookmark_bar"] as? [String: Any] else { throw Failure.message("原书签缺少书签栏，未覆盖") }
        var children = bar["children"] as? [[String: Any]] ?? []
        children.removeAll { ($0["meta_info"] as? [String: Any])?["flow_launcher_template"] as? String == "1" }
        var nextID = 4
        func scan(_ node: Any) {
            if let dict = node as? [String: Any] { if let id = dict["id"] as? String, let number = Int(id) { nextID = max(nextID,number+1) }; for value in dict.values { scan(value) } }
            else if let list = node as? [Any] { list.forEach(scan) }
        }
        scan(root)
        let folderID = nextID; nextID += 1
        let entries: [[String: Any]] = items.map { item in defer { nextID += 1 }; return ["id":String(nextID),"type":"url","name":item.name,"url":item.url,"date_added":"0"] }
        children.append(["id":String(folderID),"type":"folder","name":"Flow 助手模板","children":entries,"date_added":"0","date_modified":"0","meta_info":["flow_launcher_template":"1"]])
        bar["children"] = children; roots["bookmark_bar"] = bar; root["roots"] = roots; root.removeValue(forKey: "checksum")
        if fm.fileExists(atPath: file.path) { let backup = profile.appendingPathComponent("Bookmarks.flow-backup-" + UUID().uuidString); try fm.copyItem(at: file, to: backup) }
        try JSONSerialization.data(withJSONObject: root, options: [.sortedKeys]).write(to: file, options: .atomic)
    }
}

@MainActor final class Model: ObservableObject {
    static weak var active: Model?
    @Published var accounts = [Account]()
    @Published var systemProfiles = [SystemProfile]()
    @Published var workspace = WorkspaceState()
    @Published var selected = Set<String>()
    @Published var statuses = [String: String]()
    @Published var query = ""
    @Published var scope = "auto"
    @Published var filter = "all"
    @Published var tab = "accounts"
    @Published var copyNotice = ""
    private var copyNoticeID = UUID()
    @Published var error = ""
    @Published var busy = false
    let stop = StopFlag()
    var readable = true
    private var metadataReadable = true
    private var browsers = [String: Browser]()
    private var systemLaunches = [Process]()
    let queue = DispatchQueue(label: "flow.login.queue")
    private let testing: Bool
    let stateFile = FileManager.default.urls(for: .applicationSupportDirectory,in:.userDomainMask)[0].appendingPathComponent("FlowLauncher/workspace.json")
    var allRows: [Account] {
        scope == "auto" ? accounts : systemProfiles.map { Account(id:$0.id,email:$0.email.isEmpty ? $0.name : $0.email,password:"",secret:"") }
    }
    var visible: [Account] {
        let ids = workspace.ids(scope:scope,filter:filter,all:allRows.map(\.id))
        return allRows.filter { ids.contains($0.id) && (query.isEmpty || $0.email.localizedCaseInsensitiveContains(query) || (workspace.notes[$0.id] ?? "").localizedCaseInsensitiveContains(query)) }
    }
    var chosen: [Account] { allRows.filter { selected.contains($0.id) } }
    var groupTitle: String {
        if filter == "all" { return "全部" }; if filter == "recent" { return "最近" }; if filter == "ungrouped" { return "未分组" }
        return workspace.groups.first { $0.id == filter }?.name ?? "全部"
    }
    init(testing: Bool = false) {
        self.testing = testing
        if !testing {
            do { accounts = try Vault.read() } catch { readable = false; self.error = error.localizedDescription }
            if FileManager.default.fileExists(atPath: stateFile.path) {
                do { workspace = try JSONDecoder().decode(WorkspaceState.self, from:Data(contentsOf:stateFile)) }
                catch { metadataReadable = false; self.error = "分组配置读取失败，未覆盖原文件：" + error.localizedDescription }
            }
            if metadataReadable && workspace.styleRevision == nil {
                var next = workspace; next.migrateStyle()
                do { try saveWorkspace(next) } catch { self.error = error.localizedDescription }
            }
            refreshSystem(); Self.active = self
        }
    }
    func saveWorkspace(_ next: WorkspaceState) throws {
        guard metadataReadable else { throw Failure.message("分组配置未成功读取，请先恢复配置文件") }
        if !testing {
            try FileManager.default.createDirectory(at:stateFile.deletingLastPathComponent(),withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
            try JSONEncoder().encode(next).write(to:stateFile,options:.atomic)
            try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:stateFile.path)
        }
        workspace = next
    }
    func change(_ modify: (inout WorkspaceState)->Void) {
        do { var next = workspace; modify(&next); try saveWorkspace(next) } catch { self.error = error.localizedDescription }
    }
    func updateStyle(font: Double? = nil, row: Double? = nil, accent: String? = nil) {
        change { state in
            if let font = font { state.fontSize = min(18, max(11, font)) }
            if let row = row { state.rowHeight = min(80, max(36, row)) }
            if let accent = accent { state.accent = accent }
            state.styleRevision = 1
        }
    }
    func choose(scope: String, filter: String) { self.scope=scope; self.filter=filter; selected.removeAll() }
    func count(_ scope: String, _ filter: String) -> Int {
        workspace.ids(scope:scope,filter:filter,all:scope == "auto" ? accounts.map(\.id) : systemProfiles.map(\.id)).count
    }
    func group(_ name: String, copySelection: Bool) {
        let name = name.trimmingCharacters(in:.whitespacesAndNewlines)
        guard !name.isEmpty else { error="请输入分组名称"; return }
        guard !["全部","最近","未分组"].contains(name), !workspace.groups.contains(where:{$0.scope == scope && $0.name == name}) else { error="分组名称已存在或是保留名称";return }
        let group=AccountGroup(name:name,scope:scope,members:copySelection ? Array(selected).sorted() : [])
        do { var next=workspace; next.groups.append(group); try saveWorkspace(next); filter=group.id; selected.removeAll() } catch { self.error=error.localizedDescription }
    }
    private let dragSession = UUID().uuidString
    func dragPayload(_ account:Account) -> String {
        let available=Set(allRows.map(\.id))
        let ids=selected.contains(account.id) ? selected.intersection(available) : Set([account.id])
        return (["flow-accounts",dragSession,scope]+ids.sorted()).joined(separator:"|")
    }
    func dropAccounts(_ payloads:[String], scope targetScope:String, group:String) -> Bool {
        guard !busy,payloads.count==1,group != "all",group != "recent" else{return false}
        let parts=payloads[0].components(separatedBy:"|")
        guard parts.count>=4,parts[0]=="flow-accounts",parts[1]==dragSession,parts[2]==targetScope else{return false}
        let available=Set(targetScope=="auto" ? accounts.map(\.id) : systemProfiles.map(\.id))
        let ids=Set(parts.dropFirst(3))
        guard !ids.isEmpty,ids.isSubset(of:available),group=="ungrouped" || workspace.groups.contains(where:{$0.id==group && $0.scope==targetScope}) else{return false}
        do {
            var next=workspace
            if group=="ungrouped" {
                for i in next.groups.indices where next.groups[i].scope==targetScope {next.groups[i].members.removeAll{ids.contains($0)}}
            } else {next.assign(ids,to:group)}
            try saveWorkspace(next)
            copyNotice="已将 \(ids.count) 个账号" + (group=="ungrouped" ? "移至未分组" : "加入分组")
            return true
        } catch {self.error=error.localizedDescription;return false}
    }
    func assign(to id: String) { change { $0.assign(selected,to:id) }; copyNotice="已将所选账号加入分组，原账号保留" }
    func ungroup() { change { next in if let i=next.groups.firstIndex(where:{$0.id==filter}) { next.groups[i].members.removeAll { selected.contains($0) } } };selected.removeAll() }
    func deleteGroup(_ id: String) { change { $0.groups.removeAll {$0.id==id} }; if filter==id {filter="all"};selected.removeAll() }
    func updateGroup(_ group: AccountGroup) {
        guard !group.name.trimmingCharacters(in:.whitespaces).isEmpty, ProfileFiles.validURL(group.url) else {error="分组名称或默认网址无效";return}
        guard !workspace.groups.contains(where:{$0.id != group.id && $0.scope==group.scope && $0.name==group.name}) else {error="分组名称重复";return}
        change { next in if let i=next.groups.firstIndex(where:{$0.id==group.id}) {next.groups[i]=group} }
    }
    func shutdown(_ done:@escaping()->Void) { let entries=Array(browsers.values);queue.async {for b in entries {b.close()};DispatchQueue.main.async{done()}} }
    func copy(_ value:String,notice:String) {
        let clipboard=NSPasteboard.general;clipboard.clearContents()
        guard clipboard.setString(value,forType:.string) else {error="复制失败";return}
        copyNotice=notice;let token=UUID();copyNoticeID=token
        DispatchQueue.main.asyncAfter(deadline:.now()+4){if self.copyNoticeID==token{self.copyNotice=""}}
    }
    func copyTOTP(_ a:Account) {guard !a.secret.isEmpty else{return};do{copy(try totp(a.secret),notice:"验证码已复制，请及时粘贴")}catch{self.error=error.localizedDescription}}
    func editAccount(_ account: Account) throws {
        guard readable, !busy else { throw Failure.message("请等待登录队列结束，并确保钥匙串可访问") }
        guard let index = accounts.firstIndex(where:{$0.id == account.id}) else { throw Failure.message("账号已不存在") }
        var updated = account
        updated.email = account.email.trimmingCharacters(in:.whitespacesAndNewlines).lowercased()
        guard updated.email.contains("@"), !updated.email.contains(where:{$0.isWhitespace}), !updated.password.isEmpty else { throw Failure.message("邮箱或密码无效") }
        guard !accounts.contains(where:{$0.id != updated.id && $0.email.lowercased() == updated.email}) else { throw Failure.message("邮箱已存在") }
        updated.secret = account.secret.uppercased().filter{!$0.isWhitespace}
        if !updated.secret.isEmpty { _ = try totp(updated.secret) }
        var next = accounts; next[index] = updated
        if !testing { try Vault.write(next) }
        accounts = next; copyNotice = "账号已保存"
    }
    func add(_ items:[Account]) throws {
        guard readable && metadataReadable else {throw Failure.message("请先恢复钥匙串或分组配置访问")}
        let existing=Set(accounts.map(\.email));guard !items.contains(where:{existing.contains($0.email)}) else{throw Failure.message("邮箱已存在，未覆盖原凭据")}
        let old=accounts;let next=accounts+items
        if !testing {try Vault.write(next)}
        do {var config=workspace;config.recentIDs=items.map(\.id);try saveWorkspace(config)}
        catch {if !testing{try? Vault.write(old)};throw error}
        accounts=next;choose(scope:"auto",filter:"recent")
    }
    func profile(_ id:String)->URL {URL(fileURLWithPath:workspace.dataRoot).appendingPathComponent("ChromeProfiles/\(id)")}
    func refreshSystem() {
        guard !testing else{return}
        do {
            let root=ProfileFiles.systemRoot
            if !FileManager.default.fileExists(atPath:root.path){systemProfiles=[];return}
            let dirs=try FileManager.default.contentsOfDirectory(atPath:root.path)
            systemProfiles=dirs.compactMap { dir in
                guard let path=try? ProfileFiles.safeSystemDirectory(dir) else{return nil}
                let json=(try? Data(contentsOf:path.appendingPathComponent("Preferences"))).flatMap {try? JSONSerialization.jsonObject(with:$0) as? [String:Any]} ?? [:]
                let p=json["profile"] as? [String:Any] ?? [:]
                let info=(json["account_info"] as? [[String:Any]])?.first ?? [:]
                return SystemProfile(directory:dir,name:p["name"] as? String ?? dir,email:info["email"] as? String ?? "")
            }.sorted{$0.directory.localizedStandardCompare($1.directory ) == .orderedAscending}
        } catch {self.error="无法读取系统 Chrome 配置："+error.localizedDescription}
    }
    func openingURL()->String {workspace.groups.first{$0.id==filter}?.url ?? "https://flow.google.com/"}
    func run(_ items:[Account],automatic:Bool=true,target:LoginTarget = .flow) {
        guard !busy,!items.isEmpty else{return}
        guard workspace.runEnabled else{error="请先打开运行开关";return}
        if scope=="system" {
            let binary=workspace.chromePath
            guard FileManager.default.isExecutableFile(atPath:binary) else{error="Chrome 可执行文件不存在";return}
            for item in items {
                guard let info=systemProfiles.first(where:{$0.id==item.id}) else{continue}
                let process=Process();process.executableURL=URL(fileURLWithPath:binary)
                process.arguments=["--user-data-dir="+ProfileFiles.systemRoot.path,"--profile-directory="+info.directory,"--new-window",openingURL()]
                process.standardOutput=FileHandle.nullDevice;process.standardError=FileHandle.nullDevice
                process.terminationHandler={p in DispatchQueue.main.async{self.systemLaunches.removeAll{$0===p};if p.terminationStatus != 0{self.statuses[item.id]="Chrome 打开请求失败（\(p.terminationStatus)）"}}}
                do{try process.run();systemLaunches.append(process);statuses[item.id]="已请求打开系统配置"}catch{self.error=error.localizedDescription}
            }
            return
        }
        stop.set(false);busy=true
        let binary=workspace.chromePath,url=openingURL(),bookmarks=workspace.bookmarks
        let jobs=items.map{($0,profile($0.id),browsers[$0.id])}
        for a in items{statuses[a.id]="等待处理"}
        queue.async {
            for (account,path,previous) in jobs {
                if self.stop.stopped{DispatchQueue.main.async{self.statuses[account.id]="已取消排队"};continue}
                var reusable=previous
                if let old=reusable,old.automatic != automatic || !old.process.isRunning{old.close();reusable=nil}
                let browser=reusable ?? Browser(id:account.id,binaryPath:binary)
                let update:(String)->Void={s in DispatchQueue.main.async{self.statuses[account.id]=s}}
                DispatchQueue.main.async{self.browsers[account.id]=browser}
                do {
                    if reusable==nil {
                        update("正在启动 Chrome")
                        try ProfileFiles.unlocked(path)
                        if !FileManager.default.fileExists(atPath:path.appendingPathComponent("Default/Bookmarks").path){try ProfileFiles.applyBookmarks(bookmarks,profile:path.appendingPathComponent("Default"))}
                        try browser.start(profile:path,automatic:automatic,openingURL:url)
                    }
                    DispatchQueue.main.async{self.browsers[account.id]=browser}
                    if automatic{try browser.login(account,target:target,stop:self.stop,update:update)}else{update("已普通打开 · 登录状态保留")}
                }catch{
                    update(error.localizedDescription + (browser.process.isRunning ? " · 窗口保留，可重试或点击 😴" : ""))
                    if !browser.process.isRunning {DispatchQueue.main.async{self.browsers[account.id]=nil}}
                }
            }
            DispatchQueue.main.async{self.busy=false}
        }
    }
    func tileSelected() {
        guard !busy else {return}
        guard scope == "auto" else {error="平铺目前支持由 FL 打开的自动登录用户窗口";return}
        guard !selected.isEmpty else {error="请先勾选需要平铺的账号";return}
        let entries = accounts.filter{selected.contains($0.id)}.compactMap{browsers[$0.id]}.filter{$0.process.isRunning && $0.automatic}
        guard !entries.isEmpty else {error="请先通过 FL 打开账号窗口，再点击平铺窗口";return}
        let screen = NSApp.keyWindow?.screen ?? NSScreen.main ?? NSScreen.screens.first
        guard let screen = screen, let primary = NSScreen.screens.first else {return}
        let visible = screen.visibleFrame
        let area = CGRect(x:visible.minX,y:primary.frame.maxY-visible.maxY,width:visible.width,height:visible.height)
        let rects = WindowGrid.rects(count:entries.count,area:area)
        let others = accounts.filter{!selected.contains($0.id)}.compactMap{browsers[$0.id]}.filter{$0.process.isRunning && $0.automatic}
        busy = true
        queue.async {
            var completed = 0; var constrained = false; var failed = 0
            var minimized = 0; var minimizeFailed = 0
            for browser in others {
                do {try browser.minimize();minimized += 1} catch {minimizeFailed += 1}
            }
            for (browser,rect) in zip(entries,rects) {
                do {if try !browser.tile(to:rect) {constrained = true};completed += 1} catch {failed += 1}
            }
            let summary = "已排列 \(completed) 个窗口，已最小化 \(minimized) 个未选窗口" + (minimizeFailed > 0 ? "，\(minimizeFailed) 个窗口最小化失败" : "") + (failed > 0 ? "，\(failed) 个窗口未能调整" : "") + (constrained ? "；Chrome 最小窗口尺寸限制，部分窗口可能重叠" : "")
            DispatchQueue.main.async {self.busy=false;self.copyNotice=summary}
        }
    }
    func closeSelected(ids explicitIDs: Set<String>? = nil) {
        guard !busy else{return}
        if scope=="system"{error="系统用户窗口由 Chrome 管理，请在 Chrome 中关闭；不会关闭其他正在使用的窗口。";return}
        let entries=(explicitIDs ?? selected).map { id in (id,browsers[id],profile(id)) }
        busy=true
        queue.async {
            var errors=[String]()
            for (id,browser,root) in entries {
                do {
                    browser?.close()
                    try ProfileFiles.closeManaged(root)
                    DispatchQueue.main.async{self.browsers[id]=nil;self.statuses[id]="已关闭 · 登录状态保留"}
                } catch {errors.append(error.localizedDescription)}
            }
            let message=errors.joined(separator:"\n")
            DispatchQueue.main.async{self.busy=false;if !message.isEmpty{self.error=message}}
        }
    }

    func perform(_ action:String, ids explicitIDs: Set<String>? = nil) {
        let ids=explicitIDs ?? selected
        guard !busy,!ids.isEmpty else{return}
        let isSystem=scope=="system"
        if isSystem && !NSRunningApplication.runningApplications(withBundleIdentifier:"com.google.Chrome").isEmpty {error="请先退出所有 Google Chrome 窗口，再操作系统用户的数据";return}
        let entries=ids.map{($0,browsers[$0],profile($0))}
        let sys=systemProfiles
        let bookmarks=workspace.bookmarks
        busy=true
        queue.async {
            var success=[String](),messages=[String]()
            for(id,browser,managed) in entries {
                do {
                    browser?.close()
                    if !isSystem {try ProfileFiles.closeManaged(managed)}
                    let root:URL,folder:URL
                    if isSystem {
                        guard let info=sys.first(where:{$0.id==id}) else{continue}
                        root=ProfileFiles.systemRoot;folder=try ProfileFiles.safeSystemDirectory(info.directory)
                    }else{root=managed;folder=managed.appendingPathComponent("Default")}
                    try ProfileFiles.unlocked(root)
                    if action=="logout" {try ProfileFiles.clearCookies(folder)}
                    else if action=="bookmarks" {try ProfileFiles.applyBookmarks(bookmarks,profile:folder)}
                    else if action=="cache" {
                        for name in ["Cache","Code Cache","GPUCache"] {let dir=folder.appendingPathComponent(name);if FileManager.default.fileExists(atPath:dir.path){try FileManager.default.removeItem(at:dir)}}
                    }else if action=="browser" || action=="account" {
                        let target=isSystem ? folder : root
                        if FileManager.default.fileExists(atPath:target.path){try FileManager.default.trashItem(at:target,resultingItemURL:nil)}
                        if isSystem {try Self.removeSystemMetadata(folder.lastPathComponent)}
                    }
                    success.append(id)
                }catch{messages.append(id+"："+error.localizedDescription)}
            }
            DispatchQueue.main.async {
                for id in ids{self.browsers[id]=nil}
                if action=="account" && !isSystem {
                    let next=self.accounts.filter{!success.contains($0.id)}
                    do {try Vault.write(next);self.accounts=next;self.change{state in state.recentIDs.removeAll{success.contains($0)};for i in state.groups.indices{state.groups[i].members.removeAll{success.contains($0)}}}}
                    catch{messages.append("凭据删除失败："+error.localizedDescription)}
                }
                if isSystem {
                    if action=="browser"{self.change{state in for i in state.groups.indices{state.groups[i].members.removeAll{success.contains($0)}};for id in success{state.notes[id]=nil}}}
                    self.refreshSystem()
                }
                for id in success{self.statuses[id]=action=="logout" ? "网站 Cookie 已清除，下次打开需重新登录" : action=="bookmarks" ? "模板书签已更新" : action=="cache" ? "缓存已清理" : "浏览器环境已移到废纸篓"}
                if explicitIDs == nil {self.selected.removeAll()} else if action=="account" || isSystem && action=="browser" {self.selected.subtract(success)};self.busy=false
                self.copyNotice="已处理 \(success.count) 个"
                if !messages.isEmpty{self.error=messages.joined(separator:"\n")}
            }
        }
    }
    nonisolated static func removeSystemMetadata(_ directory:String,root:URL=ProfileFiles.systemRoot) throws {
        let file=root.appendingPathComponent("Local State")
        guard FileManager.default.fileExists(atPath:file.path) else{return}
        guard var json=try JSONSerialization.jsonObject(with:Data(contentsOf:file)) as? [String:Any],var profiles=json["profile"] as? [String:Any] else{throw Failure.message("无法更新系统配置索引")}
        var cache=profiles["info_cache"] as? [String:Any] ?? [:];cache[directory]=nil;profiles["info_cache"]=cache
        if profiles["last_used"] as? String==directory{profiles["last_used"]=cache.keys.sorted().first ?? "Default"}
        if var order=profiles["profiles_order"] as? [String]{order.removeAll{$0==directory};profiles["profiles_order"]=order}
        json["profile"]=profiles
        try FileManager.default.copyItem(at:file,to:file.deletingLastPathComponent().appendingPathComponent("Local State.flow-backup-"+UUID().uuidString))
        try JSONSerialization.data(withJSONObject:json).write(to:file,options:.atomic)
    }
    func saveSettings(_ draft:WorkspaceState) {
        guard !busy else{return}
        guard FileManager.default.isExecutableFile(atPath:draft.chromePath) else{error="Chrome 可执行文件路径无效";return}
        guard draft.dataRoot.hasPrefix("/"), draft.fontSize>=11,draft.fontSize<=18,draft.rowHeight>=36,draft.rowHeight<=80 else{error="数据路径或样式参数无效";return}
        guard draft.bookmarks.allSatisfy({!$0.name.isEmpty && ProfileFiles.validURL($0.url)}) else{error="书签名称或网址无效";return}
        let changesPaths=draft.chromePath != workspace.chromePath || URL(fileURLWithPath:draft.dataRoot).standardizedFileURL != URL(fileURLWithPath:workspace.dataRoot).standardizedFileURL
        guard !changesPaths || browsers.values.allSatisfy({!$0.process.isRunning}) else{error="请先关闭助手打开的所有浏览器窗口再修改路径";return}
        do {
            if URL(fileURLWithPath:draft.dataRoot).standardizedFileURL != URL(fileURLWithPath:workspace.dataRoot).standardizedFileURL {
                let old=URL(fileURLWithPath:workspace.dataRoot).appendingPathComponent("ChromeProfiles")
                let root=URL(fileURLWithPath:draft.dataRoot).standardizedFileURL
                guard !root.path.hasPrefix(old.path+"/"),root != old else{throw Failure.message("新目录不能位于原浏览器数据目录内部")}
                try FileManager.default.createDirectory(at:root,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
                let dest=root.appendingPathComponent("ChromeProfiles")
                if FileManager.default.fileExists(atPath:dest.path){throw Failure.message("新目录已包含 ChromeProfiles，为避免覆盖请选择空目录")}
                if FileManager.default.fileExists(atPath:old.path){
                    for dir in try FileManager.default.contentsOfDirectory(at:old,includingPropertiesForKeys:nil){try ProfileFiles.unlocked(dir)}
                    try FileManager.default.copyItem(at:old,to:dest)
                }
            }
            var next=draft;next.fontSize=workspace.fontSize;next.rowHeight=workspace.rowHeight;next.accent=workspace.accent;next.styleRevision=workspace.styleRevision;next.groups=workspace.groups;next.recentIDs=workspace.recentIDs;next.notes=workspace.notes
            try saveWorkspace(next);copyNotice=changesPaths ? "路径设置已保存；迁移时原目录保留为备份" : "设置已保存"
        }catch{self.error=error.localizedDescription}
    }
    func exportConfig() {
        let panel=NSSavePanel();panel.nameFieldStringValue="Flow-配置.json"
        if panel.runModal( ) == .OK,let url=panel.url{do{try JSONEncoder().encode(workspace).write(to:url,options:.atomic);copyNotice="配置已导出（不包含账号密码）"}catch{self.error=error.localizedDescription}}
    }
    func importConfig() {
        let panel=NSOpenPanel();panel.allowsMultipleSelection=false
        if panel.runModal( ) == .OK,let url=panel.url {
            do {
                let imported=try JSONDecoder().decode(WorkspaceState.self,from:Data(contentsOf:url))
                // Do not silently redirect browser storage or executable paths through an imported file.
                var next=imported;next.chromePath=workspace.chromePath;next.dataRoot=workspace.dataRoot
                guard next.groups.allSatisfy({ProfileFiles.validURL($0.url)}),next.bookmarks.allSatisfy({ProfileFiles.validURL($0.url)}) else{throw Failure.message("配置中含无效网址")}
                next.migrateStyle();next.fontSize=min(18,max(11,next.fontSize));next.rowHeight=min(80,max(36,next.rowHeight))
                try saveWorkspace(next);filter="all";selected.removeAll();copyNotice="分组、书签和样式配置已导入"
            }catch{self.error=error.localizedDescription}
        }
    }
}

@MainActor struct AccountEditor: View {
    @ObservedObject var model: Model
    @Environment(\.dismiss) var dismiss
    @State var account: Account
    @State private var error = ""
    @State private var checkedSecret = ""
    @State private var verified = false
    var body: some View {
        VStack(alignment:.leading,spacing:14) {
            Text("编辑账号").font(.title2.bold())
            TextField("邮箱",text:$account.email).textFieldStyle(.roundedBorder)
            SecureField("密码",text:$account.password).textFieldStyle(.roundedBorder)
            Text("TOTP 长期密钥（可选）").font(.headline)
            SecureField("粘贴验证器长期密钥，不是六位验证码",text:$account.secret).textFieldStyle(.roundedBorder)
                .onChange(of:account.secret){_ in verified=false;checkedSecret="";error=""}
            HStack {
                Button("校验并预览") {
                    do {
                        _ = try totp(account.secret)
                        checkedSecret = account.secret; verified = true; error = ""
                    } catch { self.error = error.localizedDescription; verified = false }
                }.disabled(account.secret.isEmpty)
                Button("清除密钥"){account.secret=""}
            }
            if verified {
                TimelineView(.periodic(from:.now,by:1)) { context in
                    let code = (try? totp(checkedSecret,time:context.date.timeIntervalSince1970)) ?? "------"
                    HStack {
                        Text(code).font(.system(size:24,weight:.semibold,design:.monospaced))
                        Text("剩余 \(30-Int(context.date.timeIntervalSince1970)%30) 秒").foregroundStyle(.secondary)
                        Button("复制验证码"){model.copy(code,notice:"验证码已复制")}
                    }
                }
                Text("密钥格式有效，已生成验证码。请与绑定该账号的验证器核对；Google 是否接受仍以登录验证为准。").font(.caption).foregroundStyle(.secondary)
            }
            Text("保存后，账号行的 TOTP 按钮会按当前时间生成并复制验证码。留空表示不配置二步验证密钥。").font(.caption).foregroundStyle(.secondary)
            if !error.isEmpty {Text(error).foregroundStyle(.red)}
            HStack {
                Button("取消"){dismiss()};Spacer()
                Button("保存") {
                    do {try model.editAccount(account);dismiss()} catch {self.error=error.localizedDescription}
                }.buttonStyle(.borderedProminent).disabled(model.busy)
            }
        }.padding(24).frame(width:510)
    }
}

struct ImportView: View {
    @ObservedObject var model: Model
    @Environment(\.dismiss) var dismiss
    @State var content = ""
    @State var preview = [Account]()
    @State var error = ""
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("导入 Flow 账号").font(.title2.bold())
            Text("每行：邮箱 | 密码（必填）| TOTP 长期密钥（可选）\n支持只导入账号和密码。支持 Markdown 表格、Tab 或 ---- 分隔。")
                .foregroundStyle(.secondary)
            if preview.isEmpty {
                Button("从剪贴板粘贴并解析") {
                    do {
                        guard let pasted = NSPasteboard.general.string(forType: .string) else { throw Failure.message("剪贴板中没有文本") }
                        preview = try parseAccounts(pasted); content = ""; error = ""
                    } catch { self.error = error.localizedDescription }
                }.buttonStyle(.borderedProminent)
                SecureField("或在这里粘贴单行账号数据", text: $content).textFieldStyle(.roundedBorder)
                Text("为保护密码，粘贴内容不明文显示；预览只显示邮箱。").font(.caption).foregroundStyle(.secondary)
            } else {
                List(preview) { Text($0.email) }.frame(height: 170)
                Text("将保存 \(preview.count) 个账号，不覆盖已有账号。")
            }
            if !error.isEmpty { Text(error).foregroundStyle(.red).textSelection(.enabled) }
            HStack {
                Button("取消") { content = ""; preview = []; dismiss() }
                Spacer()
                if preview.isEmpty {
                    Button("解析并预览") { do { preview = try parseAccounts(content); content = ""; error = "" } catch { self.error = error.localizedDescription } }.buttonStyle(.borderedProminent)
                } else {
                    Button("保存到钥匙串") { do { try model.add(preview); preview = []; dismiss() } catch { self.error = error.localizedDescription } }.buttonStyle(.borderedProminent)
                }
            }
        }.padding(24).frame(width: 560)
    }
}
extension Color {
    init(hex:String) {
        let clean=hex.trimmingCharacters(in:CharacterSet(charactersIn:"#"));let n=UInt64(clean,radix:16) ?? 0x16A66A
        self.init(red:Double((n>>16)&255)/255,green:Double((n>>8)&255)/255,blue:Double(n&255)/255)
    }
}
struct FlowAccentKey:EnvironmentKey {static let defaultValue=Color(hex:"#16A66A")}
extension EnvironmentValues {var flowAccent:Color {get{self[FlowAccentKey.self]}set{self[FlowAccentKey.self]=newValue}}}
struct FlowFontKey:EnvironmentKey {static let defaultValue:Double = 12}
extension EnvironmentValues {var flowFont:Double {get{self[FlowFontKey.self]}set{self[FlowFontKey.self]=newValue}}}
struct PillStyle:ButtonStyle {
    @Environment(\.flowFont) private var size
    @Environment(\.flowAccent) private var accent
    var orange=false
    var danger=false
    func makeBody(configuration:Configuration)->some View {
        configuration.label.font(.system(size:size,weight:.medium)).padding(.horizontal,10).padding(.vertical,4)
            .foregroundStyle(orange ? Color.white : danger ? Color(red:0.65,green:0.16,blue:0.12) : .black)
            .background(orange ? Color.orange : danger ? Color(red:1,green:0.94,blue:0.92) : accent.opacity(0.1))
            .clipShape(Capsule()).overlay(Capsule().stroke(orange ? Color.orange : danger ? .orange.opacity(0.4) : accent.opacity(0.4),lineWidth:1))
            .opacity(configuration.isPressed ? 0.65 : 1)
    }
}
struct GroupEditor:View {
    @ObservedObject var model:Model
    @Environment(\.dismiss) var dismiss
    @State var name=""
    @State var target="new"
    var copying:Bool
    var body:some View {
        VStack(alignment:.leading,spacing:18){
            Text(copying ? "将所选账号加入分组" : "新建分组").font(.title2.bold())
            if copying {
                Text("已选 \(model.selected.count) 个；账号保留在全部列表，可同时加入多个组。").foregroundStyle(.secondary)
                Picker("加入",selection:$target){Text("新建分组").tag("new");ForEach(model.workspace.groups.filter{$0.scope==model.scope}){g in Text(g.name).tag(g.id)}}
            }
            if target=="new"{TextField("分组名称",text:$name).textFieldStyle(.roundedBorder)}
            HStack{Button("取消"){dismiss()};Spacer();Button("确定"){
                let previous=model.error
                if target=="new"{model.group(name,copySelection:copying)}else{model.assign(to:target)}
                if model.error==previous{dismiss()}
            }.buttonStyle(PillStyle()).disabled(target=="new" && name.trimmingCharacters(in:.whitespaces).isEmpty)}
        }.padding(24).frame(width:470)
    }
}
@MainActor struct SettingsView:View {
    @ObservedObject var model:Model
    @State var draft:WorkspaceState
    @State var styleOpen=false
    init(model:Model){self.model=model;_draft=State(initialValue:model.workspace)}
    func card<Content:View>(_ title:String,@ViewBuilder content:()->Content)->some View {
        VStack(alignment:.leading,spacing:14){Text(title).font(.headline);Divider();content()}.padding(18).frame(maxWidth:.infinity,alignment:.leading).background(.white).overlay(RoundedRectangle(cornerRadius:8).stroke(Color.gray.opacity(0.22))).clipShape(RoundedRectangle(cornerRadius:8))
    }
    func choosePath(browser:Bool) {
        let panel=NSOpenPanel();panel.canChooseDirectories = !browser;panel.canChooseFiles=browser;panel.allowsMultipleSelection=false
        if panel.runModal() == .OK,let url=panel.url {
            if browser {
                if url.pathExtension=="app",let bundle=Bundle(url:url),let executable=bundle.executableURL{draft.chromePath=executable.path}else{draft.chromePath=url.path}
            }else{draft.dataRoot=url.path}
        }
    }
    func importBookmarks() {
        let panel=NSOpenPanel();panel.allowsMultipleSelection=false
        if panel.runModal() == .OK,let url=panel.url {
            do {
                let data=try Data(contentsOf:url)
                if let list=try? JSONDecoder().decode([BookmarkItem].self,from:data){draft.bookmarks=list}
                else {
                    let html=String(decoding:data,as:UTF8.self)
                    let regex=try NSRegularExpression(pattern:"<a[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>",options:[.caseInsensitive,.dotMatchesLineSeparators])
                    let text=html as NSString
                    let list=regex.matches(in:html,range:NSRange(location:0,length:text.length)).map{m in BookmarkItem(name:text.substring(with:m.range(at:2)).replacingOccurrences(of:"<[^>]+>",with:"",options:.regularExpression).replacingOccurrences(of:"&amp;",with:"&"),url:text.substring(with:m.range(at:1)).replacingOccurrences(of:"&amp;",with:"&"))}.filter{ProfileFiles.validURL($0.url)}
                    guard !list.isEmpty else{throw Failure.message("未识别到书签，请选择 Chrome 导出的 HTML 或模板 JSON")};draft.bookmarks=list
                }
            }catch{model.error=error.localizedDescription}
        }
    }
    var body:some View {
        ScrollView{
            VStack(alignment:.leading,spacing:16){
                HStack{Text("设置").font(.title.bold());Spacer();Text("已选 \(model.selected.count) 个浏览器").font(.caption).foregroundStyle(.secondary);Button("保存设置"){model.saveSettings(draft)}.buttonStyle(PillStyle(orange:true)).disabled(model.busy)}
                card("样式中心"){
                    HStack{Button(styleOpen ? "收起样式中心" : "打开样式中心"){styleOpen.toggle()}.buttonStyle(PillStyle());Text("调整立即生效并自动保存，切回账号管理即可查看").foregroundStyle(.secondary)}
                    if styleOpen{
                        HStack{Text("主题颜色");ForEach(["#16A66A","#1677FF","#9B59B6","#F57C00"],id:\.self){color in Button{model.updateStyle(accent:color)}label:{Circle().fill(Color(hex:color)).frame(width:24,height:24).overlay(Circle().stroke(model.workspace.accent==color ? .black : .clear,lineWidth:2))}.buttonStyle(.plain)}}
                        HStack{Text("字号 \(Int(model.workspace.fontSize))").frame(width:90,alignment:.leading);Slider(value:Binding(get:{model.workspace.fontSize},set:{model.updateStyle(font:$0)}),in:11...18,step:1)}
                        HStack{Text("行高 \(Int(model.workspace.rowHeight))").frame(width:90,alignment:.leading);Slider(value:Binding(get:{model.workspace.rowHeight},set:{model.updateStyle(row:$0)}),in:36...80,step:2)}
                        Button("恢复默认样式"){model.updateStyle(font:12,row:40,accent:"#16A66A")}.buttonStyle(PillStyle())
                    }
                }
                card("Chrome 浏览器可执行路径"){
                    HStack{TextField("选择 Google Chrome.app 或可执行文件",text:$draft.chromePath).textFieldStyle(.roundedBorder);Button("选择…"){choosePath(browser:true)}.buttonStyle(PillStyle())}
                    HStack{Button("自动检测"){draft.chromePath=Browser.chromeBinary}.buttonStyle(PillStyle());Text(FileManager.default.isExecutableFile(atPath:draft.chromePath) ? "✓ 路径有效" : "路径无效，请重新选择").foregroundStyle(FileManager.default.isExecutableFile(atPath:draft.chromePath) ? .green : .red)}
                }
                card("基础数据存储路径"){
                    HStack{TextField("数据文件夹",text:$draft.dataRoot).textFieldStyle(.roundedBorder);Button("选择…"){choosePath(browser:false)}.buttonStyle(PillStyle())}
                    Text("保存新路径时复制浏览器环境到新目录，旧目录保留为备份。账号密码继续保存在钥匙串。").font(.caption).foregroundStyle(.secondary)
                    HStack{Button("打开数据目录"){NSWorkspace.shared.open(URL(fileURLWithPath:model.workspace.dataRoot))}.buttonStyle(PillStyle());Button("清理所选浏览器缓存"){model.perform("cache")}.buttonStyle(PillStyle()).disabled(model.selected.isEmpty||model.busy)}
                }
                card("预设书签（模板）"){
                    Text("新建浏览器环境自动应用；已有环境可在账号页选中后点击“下发书签”。保留原有书签。").font(.caption).foregroundStyle(.secondary)
                    ForEach($draft.bookmarks){$item in HStack{TextField("名称",text:$item.name).textFieldStyle(.roundedBorder).frame(width:150);TextField("https://…",text:$item.url).textFieldStyle(.roundedBorder);Button("删除"){draft.bookmarks.removeAll{$0.id==item.id}}.buttonStyle(PillStyle(danger:true))}}
                    HStack{Button("＋ 添加书签"){draft.bookmarks.append(BookmarkItem(name:"新书签",url:"https://"))}.buttonStyle(PillStyle());Button("导入书签 HTML / JSON"){importBookmarks()}.buttonStyle(PillStyle())}
                }
                card("分组标签（仅本地）"){
                    Text("分组修改立即保存；默认链接用于“普通打开”。FL 自动登录进入 Google Flow，RH 自动登录进入 RunningHub。").font(.caption).foregroundStyle(.secondary)
                    ForEach(model.workspace.groups){group in GroupSettingsRow(model:model,group:group)}
                    if model.workspace.groups.isEmpty{Text("在账号管理页面选中账号后，点击“分组”创建。").foregroundStyle(.secondary)}
                }
            }.padding(24).frame(maxWidth:950,alignment:.leading).frame(maxWidth:.infinity,alignment:.leading)
        }.background(Color(red:0.97,green:0.98,blue:0.98))
    }
}
struct GroupSettingsRow:View {
    @ObservedObject var model:Model
    @State var group:AccountGroup
    var body:some View {
        HStack{
            Circle().fill(Color(hex:group.color)).frame(width:12,height:12)
            Text(group.scope=="auto" ? "自动" : "系统").font(.caption).foregroundStyle(.secondary)
            TextField("分组名",text:$group.name).textFieldStyle(.roundedBorder).frame(width:130)
            TextField("默认链接",text:$group.url).textFieldStyle(.roundedBorder)
            Menu("颜色"){ForEach(["#16A66A","#1677FF","#9B59B6","#F57C00"],id:\.self){c in Button(c){group.color=c}}}
            Button("保存"){model.updateGroup(group)}.buttonStyle(PillStyle())
            Button("删除分组"){model.deleteGroup(group.id)}.buttonStyle(PillStyle(danger:true))
        }
    }
}
// Keep functional groups left-aligned with constant spacing at every window width.
enum WindowGrid {
    static func rects(count:Int,area:CGRect)->[CGRect] {
        guard count > 0 else {return []}
        let columns = min(count,Int(ceil(sqrt(Double(count)*max(1,Double(area.width/area.height))))))
        let rows = Int(ceil(Double(count)/Double(columns)))
        return (0..<count).map { index in
            let row = index / columns
            let column = index % columns
            let inRow = min(columns,count-row*columns)
            let left = area.minX + floor(area.width*CGFloat(column)/CGFloat(inRow))
            let right = area.minX + floor(area.width*CGFloat(column+1)/CGFloat(inRow))
            let top = area.minY + floor(area.height*CGFloat(row)/CGFloat(rows))
            let bottom = area.minY + floor(area.height*CGFloat(row+1)/CGFloat(rows))
            return CGRect(x:left,y:top,width:right-left,height:bottom-top)
        }
    }
}
struct ToolbarNaturalSizeKey: PreferenceKey {
    static var defaultValue = CGSize(width:1600,height:28)
    static func reduce(value:inout CGSize,nextValue:()->CGSize){value=nextValue()}
}
struct ProportionalToolbar<Content:View>:View {
    let content:Content
    @State private var naturalSize = CGSize(width:1600,height:28)
    @State private var availableWidth:CGFloat = 1600
    init(@ViewBuilder content:()->Content){self.content=content()}
    var body:some View {
        GeometryReader { proxy in
            HStack(spacing:12){content}
                .fixedSize(horizontal:true,vertical:true)
                .background(GeometryReader { measure in
                    Color.clear.preference(key:ToolbarNaturalSizeKey.self,value:measure.size)
                })
                .scaleEffect(proxy.size.width/max(1,naturalSize.width),anchor:.topLeading)
                .frame(width:proxy.size.width,height:proxy.size.height,alignment:.topLeading)
                .onAppear{availableWidth=proxy.size.width}
                .onChange(of:proxy.size.width){availableWidth=$0}
        }
        .frame(height:naturalSize.height*availableWidth/max(1,naturalSize.width))
        .onPreferenceChange(ToolbarNaturalSizeKey.self){size in
            if size.width>0 && size.height>0 {naturalSize=size}
        }
    }
}

@MainActor struct MainView:View {
    @StateObject var model:Model
    @State var importing=false
    @State var grouping=false
    @State var copyingGroup=false
    @State var dropTarget:String?
    @State var pendingAction=""
    @State var pendingAccount:Account?
    @State var showingConfirmation=false
    @State var renaming:AccountGroup?
    @State var editingAccount:Account?
    init(model:Model?=nil){_model=StateObject(wrappedValue:model ?? Model())}
    func confirm(_ action:String){pendingAccount=nil;pendingAction=action;showingConfirmation=true}
    func confirmDelete(_ account:Account){pendingAccount=account;pendingAction=model.scope=="system" ? "browser" : "account";showingConfirmation=true}
    var confirmationText:String{
        switch pendingAction{
        case "logout":return "将关闭助手管理的所选窗口并清除全部网站 Cookie，使网站登录失效。不会移除 Chrome 同步帐号，也不会删除保存的密码、TOTP 或书签。系统用户需要先退出所有 Chrome。"
        case "browser":return "将所选浏览器环境移到废纸篓，包含浏览记录、Cookie、书签等本地数据。账号列表中的密码和 TOTP 保留，下次打开会新建环境。系统用户需要先退出所有 Chrome。"
        case "account":return "将删除所选账号保存的密码和 TOTP，并将对应浏览器环境移到废纸篓。凭据删除无法撤销。"
        case "bookmarks":return "将关闭助手管理的所选窗口，更新“Flow 助手模板”书签文件夹，其他书签保留。系统用户需要先退出所有 Chrome。"
        default:return "确认处理所选项目？"
        }
    }
    func navRow(_ title:String,_ scope:String,_ filter:String,color:Color?=nil)->some View {
        Button{model.choose(scope:scope,filter:filter)}label:{
            HStack(spacing:8){if let color=color{Circle().fill(color).frame(width:8,height:8)};Text(title).lineLimit(1);Spacer();Text("\(model.count(scope,filter))").foregroundStyle(.secondary).font(.system(size:model.workspace.fontSize-1))}
                .padding(.horizontal,16).padding(.vertical,9).frame(maxWidth:.infinity,alignment:.leading)
                .background(model.scope==scope&&model.filter==filter ? Color(hex:model.workspace.accent).opacity(0.09) : .clear)
        }.buttonStyle(.plain)
        .overlay(RoundedRectangle(cornerRadius:4).stroke(dropTarget==scope+"|"+filter ? Color(hex:model.workspace.accent) : .clear,lineWidth:2))
        .dropDestination(for:String.self) { items,_ in
            model.dropAccounts(items,scope:scope,group:filter)
        } isTargeted: { targeted in
            if targeted && filter != "all" && filter != "recent" && scope==model.scope && !model.busy {dropTarget=scope+"|"+filter}
            else if dropTarget==scope+"|"+filter {dropTarget=nil}
        }
    }
    var sidebar:some View {
        VStack(spacing:0){
            HStack{Text("分组列表").font(.system(size:model.workspace.fontSize,weight:.semibold));Spacer();Button("＋ 新建"){copyingGroup=false;grouping=true}.buttonStyle(PillStyle())}.padding(16)
            Divider()
            ScrollView{
                VStack(alignment:.leading,spacing:0){
                    ForEach(["auto","system"],id:\.self){scope in
                        Text(scope=="auto" ? "▾ 自动登录用户" : "▾ 系统用户").font(.system(size:model.workspace.fontSize,weight:.semibold)).padding(.horizontal,20).padding(.top,16).padding(.bottom,8)
                        navRow("全部",scope,"all")
                        if scope=="auto"{navRow("最近",scope,"recent")}
                        ForEach(model.workspace.groups.filter{$0.scope==scope}){g in
                            navRow(g.name,scope,g.id,color:Color(hex:g.color)).contextMenu{
                                Button("重命名 / 修改链接"){renaming=g}
                                Button("删除分组（保留账号）"){model.deleteGroup(g.id)}
                            }
                        }
                        navRow("未分组",scope,"ungrouped")
                        Divider().padding(.top,12)
                    }
                }
            }
            Button("刷新系统用户"){model.refreshSystem()}.buttonStyle(PillStyle()).padding(14)
        }.frame(width:210).background(Color(red:0.975,green:0.98,blue:0.975))
    }
    var toolbars:some View {
        ProportionalToolbar {
            HStack(spacing:6) {
                Button("＋ 添加账号"){importing=true}.buttonStyle(PillStyle(orange:true))
                Button("导出配置"){model.exportConfig()}.buttonStyle(PillStyle()).help("导出分组、样式、书签，不包含账号密码")
                Button("导入配置"){model.importConfig()}.buttonStyle(PillStyle()).disabled(model.busy).help("导入分组、样式和书签 JSON；账号请使用添加账号")
                Button("复制选中账号"){model.copy(model.chosen.map(\.email).joined(separator:"\n"),notice:"所选账号已复制")}.buttonStyle(PillStyle()).disabled(model.selected.isEmpty)
                Button("下发书签"){confirm("bookmarks")}.buttonStyle(PillStyle()).disabled(model.selected.isEmpty||model.busy)
            }.fixedSize(horizontal:true,vertical:false)
            HStack(spacing:6) {
                Toggle("运行开关",isOn:Binding(get:{model.workspace.runEnabled},set:{value in model.change{$0.runEnabled=value};if !value{model.stop.set(true)}})).toggleStyle(.switch).fixedSize()
                TextField("搜索邮箱 / 备注",text:$model.query).textFieldStyle(.roundedBorder).frame(width:180)
            }.fixedSize(horizontal:true,vertical:false)
            HStack(spacing:6) {
                Button("全选"){model.selected.formUnion(model.visible.map(\.id))}.buttonStyle(PillStyle())
                Button("反选"){model.selected.formSymmetricDifference(model.visible.map(\.id))}.buttonStyle(PillStyle())
                Button("清空选择"){model.selected.removeAll()}.buttonStyle(PillStyle())
                Button("分组"){copyingGroup=true;grouping=true}.buttonStyle(PillStyle()).disabled(model.selected.isEmpty)
                if !["all","recent","ungrouped"].contains(model.filter){Button("移出本组"){model.ungroup()}.buttonStyle(PillStyle()).disabled(model.selected.isEmpty)}
            }.fixedSize(horizontal:true,vertical:false)
            HStack(spacing:6) {
                Button("⚗ FL"){model.run(model.chosen)}.buttonStyle(PillStyle()).disabled(model.selected.isEmpty||model.busy)
                Button("⚗ RH"){model.run(model.chosen,target:.runninghub)}.buttonStyle(PillStyle()).disabled(model.selected.isEmpty||model.busy)
                Button("普通打开"){model.run(model.chosen,automatic:false)}.buttonStyle(PillStyle()).disabled(model.selected.isEmpty||model.busy)
                Button("平铺窗口"){model.tileSelected()}.buttonStyle(PillStyle()).disabled(model.busy || model.scope=="system" || model.selected.isEmpty).help("平铺勾选的 FL 窗口，同时最小化未勾选的 FL 窗口至 Dock")
                Button("关闭所选"){model.closeSelected()}.buttonStyle(PillStyle()).disabled(model.scope=="system"||model.selected.isEmpty||model.busy)
                Button("登出所选"){confirm("logout")}.buttonStyle(PillStyle()).disabled(model.selected.isEmpty||model.busy)
            }.fixedSize(horizontal:true,vertical:false)
            HStack(spacing:6) {
                Button("删除浏览器"){confirm("browser")}.buttonStyle(PillStyle(danger:true)).disabled(model.selected.isEmpty||model.busy)
                if model.scope=="auto"{Button("删除账号"){confirm("account")}.buttonStyle(PillStyle(danger:true)).disabled(model.selected.isEmpty||model.busy)}
            }.fixedSize(horizontal:true,vertical:false)
            if model.busy {
                HStack(spacing:6){ProgressView().controlSize(.small);Button("停止队列"){model.stop.set(true)}.buttonStyle(PillStyle())}.fixedSize()
            }
        }.padding(.horizontal,16).padding(.vertical,10).background(.white)
    }
    func accountRow(_ account:Account)->some View {
        let isSystem=model.scope=="system"
        return HStack(spacing:8){
            Image(systemName:"line.3.horizontal").foregroundStyle(.secondary).help("拖到左侧分组；已勾选的账号可一起拖动")
            Toggle("选择",isOn:Binding(get:{model.selected.contains(account.id)},set:{if $0{model.selected.insert(account.id)}else{model.selected.remove(account.id)}})).labelsHidden().toggleStyle(.checkbox)
            Button{model.copy(account.email,notice:"账号已复制")}label:{Text(account.email).lineLimit(1).foregroundStyle(Color(hex:model.workspace.accent)).padding(.horizontal,8).padding(.vertical,4).frame(width:230,alignment:.leading).background(Color(hex:model.workspace.accent).opacity(0.06)).overlay(RoundedRectangle(cornerRadius:5).stroke(Color(hex:model.workspace.accent).opacity(0.3)))}.buttonStyle(.plain)
            Button("PWD"){model.copy(account.password,notice:"密码已复制")}.buttonStyle(.bordered).disabled(isSystem)
            Button("TOTP"){model.copyTOTP(account)}.buttonStyle(.bordered).disabled(isSystem||account.secret.isEmpty)
            HStack(spacing:4){ForEach(model.workspace.groups.filter{$0.members.contains(account.id)}){g in Text(g.name).font(.caption).padding(.horizontal,5).padding(.vertical,2).background(Color(hex:g.color).opacity(0.13)).foregroundStyle(Color(hex:g.color)).clipShape(RoundedRectangle(cornerRadius:4))}}.frame(maxWidth:150,alignment:.leading).allowsHitTesting(false)
            TextField("点击编辑备注",text:Binding(get:{model.workspace.notes[account.id] ?? ""},set:{value in model.change{$0.notes[account.id]=value}})).textFieldStyle(.plain).frame(minWidth:95)
            Text(model.statuses[account.id] ?? (isSystem ? "系统配置 · 未打开" : "未打开")).font(.caption).foregroundStyle(.purple).lineLimit(2).frame(width:175,alignment:.leading).allowsHitTesting(false)
            if !isSystem { Button("编辑"){editingAccount=account}.buttonStyle(.borderless).disabled(model.busy) }
            Button("开"){model.run([account],automatic:false)}.buttonStyle(.borderless)
            Button("FL"){model.run([account])}.buttonStyle(.borderless).disabled(model.busy)
            Button("RH"){model.run([account],target:.runninghub)}.buttonStyle(.borderless).disabled(model.busy)
            Button("😴"){model.closeSelected(ids:[account.id])}.buttonStyle(.borderless).help("关闭此账号窗口，保留登录状态").accessibilityLabel("关闭此账号窗口").disabled(model.busy || isSystem)
            Button("🗑️"){confirmDelete(account)}.buttonStyle(.borderless).help(isSystem ? "删除此浏览器环境" : "删除此账号及浏览器环境").accessibilityLabel("删除此账号").disabled(model.busy)
        }.font(.system(size:model.workspace.fontSize)).padding(.horizontal,16).frame(height:max(model.workspace.rowHeight,model.workspace.fontSize*2+12))
            .background {
                Rectangle()
                    .fill(model.selected.contains(account.id) ? Color(hex:model.workspace.accent).opacity(0.09) : .white)
                    .contentShape(Rectangle())
                    .onTapGesture {
                        if model.selected.contains(account.id) {model.selected.remove(account.id)}
                        else {model.selected.insert(account.id)}
                    }
            }
            .overlay(alignment:.bottom){Divider()}
            .contentShape(Rectangle())
            .draggable(model.dragPayload(account)) {
                Text(model.selected.contains(account.id) ? "移动 \(model.selected.count) 个账号" : account.email)
                    .padding(10).background(.white).cornerRadius(6)
            }
    }
    var accountsPage:some View {
        VStack(spacing:0){toolbars;Divider();HStack(spacing:0){sidebar;Divider();VStack(alignment:.leading,spacing:0){
            HStack{Text("\(model.groupTitle)（\(model.visible.count) 条）").font(.system(size:model.workspace.fontSize,weight:.semibold));Spacer();Text("已选 \(model.selected.count)").foregroundStyle(.secondary)}.padding(.horizontal,16).padding(.vertical,10)
            Divider()
            if model.visible.isEmpty{VStack(spacing:12){Image(systemName:"person.crop.rectangle.stack").font(.system(size:36)).foregroundStyle(.gray);Text(model.scope=="system" ? "没有发现系统 Chrome 用户" : "当前分组没有账号");Text(model.scope=="system" ? "系统用户来自本机 Chrome 的 Default / Profile 配置" : "添加账号后进入“最近”，勾选后可加入分组").font(.caption).foregroundStyle(.secondary)}.frame(maxWidth:.infinity,maxHeight:.infinity)}
            else {
                GeometryReader { viewport in
                    ScrollView([.horizontal,.vertical]) {
                        LazyVStack(alignment:.leading,spacing:0) {
                            ForEach(model.visible) { accountRow($0) }
                        }
                        .frame(width:max(1090,viewport.size.width),alignment:.topLeading)
                        .frame(minHeight:viewport.size.height,alignment:.topLeading)
                    }
                    .frame(width:viewport.size.width,height:viewport.size.height,alignment:.topLeading)
                }
            }
        }.frame(maxWidth:.infinity,maxHeight:.infinity)}}
    }
    var body:some View {
        VStack(spacing:0){
            HStack(spacing:24){
                Text("Google 登录助手").font(.title3.bold()).foregroundStyle(Color(hex:model.workspace.accent))
                Button("账号管理"){model.tab="accounts"}.buttonStyle(.plain).foregroundStyle(model.tab=="accounts" ? Color(hex:model.workspace.accent) : .secondary)
                Button("设置"){model.tab="settings"}.buttonStyle(.plain).foregroundStyle(model.tab=="settings" ? Color(hex:model.workspace.accent) : .secondary)
                Spacer();Text("Chrome CDP · 0.25").font(.caption).foregroundStyle(.secondary)
            }.padding(.horizontal,16).frame(height:44).background(.white)
            Divider()
            if model.tab=="settings"{SettingsView(model:model)}else{accountsPage}
            Divider()
            HStack{Text(model.copyNotice.isEmpty ? "账号、密码与验证码可点击复制 · 最近仅显示最后一次导入" : model.copyNotice).font(.caption).foregroundStyle(.secondary);Spacer();if model.busy{Text("处理中…").font(.caption)}}.padding(.horizontal,20).frame(height:32).background(.white)
        }.controlSize(.small).environment(\.flowFont,model.workspace.fontSize).environment(\.flowAccent,Color(hex:model.workspace.accent)).font(.system(size:model.workspace.fontSize)).tint(Color(hex:model.workspace.accent)).preferredColorScheme(.light).frame(minWidth:1250,minHeight:720)
            .sheet(item:$editingAccount){account in AccountEditor(model:model,account:account)}
            .sheet(isPresented:$importing){ImportView(model:model)}
            .sheet(isPresented:$grouping){GroupEditor(model:model,copying:copyingGroup)}
            .sheet(item:$renaming){g in VStack(alignment:.leading,spacing:18){Text("编辑分组").font(.title2);GroupSettingsRow(model:model,group:g);Button("完成"){renaming=nil}}.padding(24).frame(width:850)}
            .alert(pendingAccount.map{"删除账号 \($0.email)？"} ?? "确认操作所选的 \(model.selected.count) 个浏览器？",isPresented:$showingConfirmation){Button("取消",role:.cancel){};Button("确认",role:.destructive){model.perform(pendingAction,ids:pendingAccount.map{Set([$0.id])})}}message:{Text(confirmationText)}
            .alert("操作未完成",isPresented:Binding(get:{!model.error.isEmpty},set:{if !$0{model.error=""}})){Button("好"){model.error=""}}message:{Text(model.error)}
    }
}

func signedInTests() throws {
    let fixtures: [(String,String,String,Bool,Bool)] = [
        ("flow.google.com","/","+ 新建项目",true,true),
        ("flow.google.com","/","add New project",true,true),
        ("labs.google","/fx/tools/flow","Create project",true,true),
        ("flow.google.com","/about","New project",true,false),
        ("evil.example","/","New project",true,false),
        ("labs.google","/other","New project",true,false),
        ("flow.google.com","/","New project",false,false),
        ("flow.google.com","/","Sign in",true,false),
        ("flow.google.com","/","Create with Google Flow",true,false)
    ]
    for (host,path,label,visible,expected) in fixtures {
        let ctx = JSContext()!
        let data = try JSONSerialization.data(withJSONObject:["hostname":host,"pathname":path,"protocol":"https:"])
        let labelData = try JSONSerialization.data(withJSONObject:[label])
        ctx.evaluateScript("var location="+String(decoding:data,as:UTF8.self)+";var labels="+String(decoding:labelData,as:UTF8.self)+";var document={querySelectorAll:()=>labels.map(text=>({innerText:text,getClientRects:()=>"+(visible ? "[1]" : "[]")+",getAttribute:()=>null,disabled:false}))};")
        let result = ctx.evaluateScript("(function(){"+FlowPage.signedInScript+"})()")?.toBool()
        guard ctx.exception == nil, result == expected else {throw Failure.message("工作台识别测试失败")}
    }
    print("PASS: signed-in workspace Chinese/English, landing/login/hidden/untrusted/unrelated pages excluded")
}

func entryTests() throws {
    let cases: [(String, String, String?, Bool, String)] = [
        ("flow.google.com", "使用 Google Flow 创建", nil, true, "entry"),
        ("flow.google.com", "Create with Google Flow", nil, true, "entry"),
        ("labs.google", "Try Flow", nil, true, "entry"),
        ("flow.google.com", "Sign in", "https://accounts.google.com/ServiceLogin", true, "signin"),
        ("flow.google.com", "接受条款并继续", nil, true, "none"),
        ("evil.example", "使用 Google Flow 创建", nil, true, "none"),
        ("flow.google.com", "使用 Google Flow 创建", "https://evil.example/", true, "none"),
        ("flow.google.com", "使用 Google Flow 创建", nil, false, "none")
    ]
    for (host, label, href, visible, expected) in cases {
        let ctx = JSContext()!
        let resolve: @convention(block) (String, String) -> [String: String] = { value, base in
            guard let url = URL(string: value, relativeTo: URL(string: base))?.absoluteURL, let host = url.host else { return [:] }
            return ["hostname": host, "protocol": (url.scheme ?? "") + ":"]
        }
        ctx.setObject(resolve, forKeyedSubscript: "resolveURL" as NSString)
        let data = try JSONSerialization.data(withJSONObject: ["host": host, "label": label, "href": href as Any? ?? NSNull(), "visible": visible])
        let fixture = String(data: data, encoding: .utf8)!
        ctx.evaluateScript("""
        const fixture=\(fixture); let clicked=false;
        const location={protocol:'https:',hostname:fixture.host,href:'https://'+fixture.host+'/about'};
        class URL{constructor(value,base){const r=resolveURL(String(value),base||location.href);if(!r.hostname)throw Error('bad URL');this.hostname=r.hostname;this.protocol=r.protocol}}
        const node={innerText:fixture.label,disabled:false,getClientRects:()=>fixture.visible?[{}]:[],getAttribute:n=>n==='href'?fixture.href:null,click:()=>{clicked=true}};
        const document={querySelectorAll:()=>[node]};
        """)
        guard ctx.exception == nil else { throw Failure.message("入口测试准备失败") }
        let actual = ctx.evaluateScript("(function(){" + FlowPage.actionScript + "})()")?.toString()
        guard ctx.exception == nil, actual == expected, ctx.evaluateScript("clicked")?.toBool() == (expected != "none") else {
            throw Failure.message("入口回归测试失败：" + label)
        }
    }
    guard DriverFailure(code: "timeout").transient, !DriverFailure(code: "invalid session id").transient else { throw Failure.message("错误分类测试失败") }
    print("PASS: eight landing-page fixtures (Chinese/English/button/link/hidden/untrusted/terms), driver error classification")
}
func runningHubTests() throws {
    // signedInScript fixtures: (host, entryVisible, avatarVisible, expected)
    let signCases: [(String, Bool, Bool, Bool)] = [
        ("www.runninghub.ai", true, false, false),
        ("runninghub.ai", false, true, true),
        ("www.runninghub.ai", false, false, false),
        ("evil.example", false, true, false),
        ("www.runninghub.ai", true, true, false),
    ]
    for (host, entryVisible, avatarVisible, expected) in signCases {
        let ctx = JSContext()!
        let loc = try JSONSerialization.data(withJSONObject: ["hostname": host, "protocol": "https:"])
        let flags = try JSONSerialization.data(withJSONObject: ["entry": entryVisible, "avatar": avatarVisible])
        ctx.evaluateScript("var location=" + String(decoding: loc, as: UTF8.self) + ";var flags=" + String(decoding: flags, as: UTF8.self) + ";")
        ctx.evaluateScript("""
        const entryBtn={innerText:'登入 / 註冊',disabled:false,getClientRects:()=>flags.entry?[{}]:[],getAttribute:()=>null};
        const avatar={disabled:false,getClientRects:()=>flags.avatar?[{}]:[],getAttribute:()=>null};
        var document={querySelectorAll:()=>flags.entry?[entryBtn]:[],querySelector:s=>/avatar/i.test(s)?avatar:null};
        """)
        let result = ctx.evaluateScript("(function(){" + RunningHubPage.signedInScript + "})()")?.toBool()
        guard ctx.exception == nil, result == expected else { throw Failure.message("RunningHub 登录态识别失败：" + host) }
    }
    // actionScript fixtures: (host, modalOpen, googleButton, entryButton, expected)
    let actionCases: [(String, Bool, Bool, Bool, String)] = [
        ("www.runninghub.ai", false, false, true, "entry"),
        ("www.runninghub.ai", true, true, false, "google"),
        ("www.runninghub.ai", true, false, false, "modal"),
        ("www.runninghub.ai", false, false, false, "none"),
        ("evil.example", false, false, true, "none"),
    ]
    for (host, modalOpen, hasGoogle, hasEntry, expected) in actionCases {
        let ctx = JSContext()!
        let loc = try JSONSerialization.data(withJSONObject: ["hostname": host, "protocol": "https:"])
        let flags = try JSONSerialization.data(withJSONObject: ["modal": modalOpen, "google": hasGoogle, "entry": hasEntry])
        ctx.evaluateScript("var location=" + String(decoding: loc, as: UTF8.self) + ";var flags=" + String(decoding: flags, as: UTF8.self) + ";var clicked='';")
        ctx.evaluateScript("""
        const btn=(text,tag)=>({tagName:tag,innerText:text,disabled:false,getClientRects:()=>[{}],getAttribute:()=>null,click:()=>{clicked=text},parentElement:null});
        const entryBtn=btn('登入 / 註冊','BUTTON');
        const gBtn=btn('使用 Google 帳號登入','BUTTON');
        const gImg={tagName:'IMG',disabled:false,getClientRects:()=>[{}],getAttribute:n=>n==='alt'?'Google 標誌':null,parentElement:gBtn};
        const modal={getClientRects:()=>[{}],disabled:false,getAttribute:()=>null,
          querySelector:s=>flags.google&&/img/i.test(s)?gImg:null,
          querySelectorAll:()=>flags.google?[gBtn]:[]};
        var document={querySelector:s=>flags.modal&&/ant-modal-root/.test(s)?modal:null,
          querySelectorAll:()=>flags.entry?[entryBtn]:[]};
        """)
        let actual = ctx.evaluateScript("(function(){" + RunningHubPage.actionScript + "})()")?.toString()
        let clicked = ctx.evaluateScript("clicked")?.toString() ?? ""
        let expectClick = expected == "entry" || expected == "google"
        guard ctx.exception == nil, actual == expected, clicked.isEmpty == !expectClick else {
            throw Failure.message("RunningHub 入口动作失败：" + host + "/" + expected)
        }
    }
    guard loginEntryMessage(target: .runninghub, action: "google") == "已点击 Google 登录，等待账号页面" else {
        throw Failure.message("RunningHub 状态文案失败")
    }
    guard LoginTarget.runninghub.entryURL == "https://www.runninghub.ai/zh-tw"
        && LoginTarget.flow.entryURL == "https://flow.google.com/" else {
        throw Failure.message("登录目标入口地址失败")
    }
    print("PASS: RunningHub signed-in detection, entry/modal/google actions, target entry URLs")
}
func fieldTests() throws {
    let ctx = JSContext()!
    // Fixture returns a hidden field before the visible identifier to exercise selection.
    ctx.evaluateScript("""
    const hidden={id:'hidden',disabled:false,readOnly:false,getClientRects:()=>[]};
    const email={id:'identifierId',disabled:false,readOnly:false,getClientRects:()=>[{}]};
    const disabled={id:'disabled',disabled:true,readOnly:false,getClientRects:()=>[{}]};
    let nodes=[hidden,disabled,email];
    const document={querySelectorAll:s=>s.includes('#identifierId')?nodes:[]};
    """)
    let function = ctx.evaluateScript("(function(){" + LoginFields.visibleScript + "})")!
    guard function.call(withArguments: [LoginFields.email])?.toDictionary()?["id"] as? String == "identifierId" else { throw Failure.message("可见邮箱输入框选择测试失败") }
    ctx.evaluateScript("nodes=[hidden,disabled]")
    guard function.call(withArguments: [LoginFields.email])?.isNull == true else { throw Failure.message("不可用输入框测试失败") }
    let stop = StopFlag(); guard !stop.stopped else { throw Failure.message("停止标记初始化失败") }
    stop.set(true); guard stop.stopped else { throw Failure.message("停止标记设置失败") }
    stop.set(false); guard !stop.stopped else { throw Failure.message("停止标记重置失败") }
    print("PASS: visible identifier selection, hidden/disabled exclusion, queue stop/reset")
}
func cdpTests() throws {
    guard Browser.endpoint(from: "DevTools listening on ws://127.0.0.1:45123/devtools/browser/test-id\n", port: 45123) == "ws://127.0.0.1:45123/devtools/browser/test-id",
          Browser.endpoint(from: "DevTools listening on ws://127.0.0.1:45124/devtools/browser/wrong", port: 45123) == nil else { throw Failure.message("CDP 端口归属校验测试失败") }
    let args = Browser.arguments(profile: URL(fileURLWithPath: "/tmp/test-cdp-profile"))
    guard args.contains("--user-data-dir=/tmp/test-cdp-profile"), !args.contains(where: { $0.contains("automation") || $0.contains("remote-debugging") }) else { throw Failure.message("普通启动参数回归失败") }
    for host in ["accounts.google.com", "evil.example"] {
        let context = JSContext()!
        context.evaluateScript("""
        const location={protocol:'https:',hostname:'\(host)'};
        let focused=false,selected=false;
        const field={disabled:false,readOnly:false,getClientRects:()=>[{}],scrollIntoView:()=>{},focus:()=>{focused=true},select:()=>{selected=true},getBoundingClientRect:()=>({x:10,y:20,width:100,height:40})};
        const document={querySelectorAll:()=>[field]};
        """)
        let fn = context.evaluateScript("(function(){" + Browser.trustedFieldScript + "})")!
        let result = fn.call(withArguments: ["#identifierId", true])
        if host == "accounts.google.com" {
            guard context.exception == nil, result?.toDictionary()?["x"] as? Int == 60, context.evaluateScript("selected&&focused")?.toBool() == true else { throw Failure.message("Google 输入框定位测试失败") }
        } else {
            guard context.exception != nil else { throw Failure.message("非 Google 域名未被拒绝") }
            context.exception = nil
            guard context.evaluateScript("focused")?.toBool() == false else { throw Failure.message("错误域名仍操作了输入框") }
        }
    }
    let b = Browser(id: "test")
    var inserted = [String](), clicks = 0, reject = false
    b.testCDP = { method, params in
        if method == "Runtime.evaluate" {
            let expression = params["expression"] as? String ?? ""
            if expression.contains("e.value===arguments[1]") { return ["result": ["value": !reject]] }
            return ["result": ["value": ["x": 60.0, "y": 40.0]]]
        }
        if method == "Input.insertText" { inserted.append(params["text"] as? String ?? "") }
        if method == "Input.dispatchMouseEvent" { clicks += 1 }
        return [:]
    }
    try b.fill(LoginFields.email, text: "fake@example.com", next: "#identifierNext")
    reject = true; var refused = false
    do { try b.fill(LoginFields.email, text: "another@example.com", next: "#identifierNext") } catch { refused = true }
    guard refused, clicks == 2, inserted == ["fake@example.com", "another@example.com"] else { throw Failure.message("CDP 填写校验或提交顺序错误") }
    print("PASS: CDP endpoint ownership, normal launch arguments, trusted-origin field selection, insert/verify/click and failed verification stops submission")
}
func optionalTOTPTests() throws {
    let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    let rows = [
        "test@example.com----fake",
        "test@example.com\tfake",
        "| 邮箱 | 密码 |\n| --- | --- |\n| test@example.com | fake |",
        "test@example.com----fake----",
        "| test@example.com | fake | |"
    ]
    for row in rows {
        let items = try parseAccounts(row)
        guard items.count == 1, items[0].secret.isEmpty, items[0].password == "fake" else { throw Failure.message("两列或空密钥导入测试失败") }
        let saved = try JSONEncoder().encode(items)
        guard try JSONDecoder().decode([Account].self, from: saved)[0].secret.isEmpty else { throw Failure.message("可选密钥保存兼容性测试失败") }
    }
    let mixed = try parseAccounts("one@example.com----fake\ntwo@example.com----fake----" + secret)
    guard mixed.count == 2, mixed[0].secret.isEmpty, mixed[1].secret == secret else { throw Failure.message("混合导入测试失败") }
    for row in ["test@example.com----", "test@example.com----fake----INVALID1", "test@example.com----fake----" + secret + "----extra"] {
        var rejected = false
        do { _ = try parseAccounts(row) } catch { rejected = true }
        guard rejected else { throw Failure.message("无效账号数据未被拒绝") }
    }
    print("PASS: two-column formats, blank optional TOTP, mixed import, persistence roundtrip, invalid data rejection")
}
func passkeyPromptTests() throws {
    let cases: [(String,String,String,String,Bool,String)] = [
        ("accounts.google.com","简化您的登录流程","借助通行密钥，您现在可以使用指纹", "以后再说",true,"skipped"),
        ("accounts.google.com","Simplify your sign-in","Create a passkey on this device", "Not now",true,"skipped"),
        ("accounts.google.com","簡化您的登入流程","通行金鑰", "以後再說",true,"skipped"),
        ("accounts.google.com","简化您的登录流程","通行密钥", "继续",true,"none"),
        ("accounts.google.com","验证您的身份","通行密钥", "以后再说",true,"none"),
        ("evil.example","简化您的登录流程","通行密钥", "以后再说",true,"none"),
        ("accounts.google.com","简化您的登录流程","通行密钥", "以后再说",false,"none")
    ]
    for (host,heading,body,label,visible,expected) in cases {
        let context = JSContext()!
        let data = try JSONSerialization.data(withJSONObject: ["host":host,"heading":heading,"body":body,"label":label,"visible":visible])
        let fixture = String(decoding:data,as:UTF8.self)
        context.evaluateScript("""
        const f=\(fixture);let clicked=false;
        const location={protocol:'https:',hostname:f.host};
        const skip={innerText:f.label,disabled:false,getClientRects:()=>f.visible?[{}]:[],getAttribute:()=>null,click:()=>{clicked=true}};
        const document={body:{innerText:f.body},querySelectorAll:s=>s.startsWith('h1')?[{innerText:f.heading}]:[skip]};
        """)
        let result = context.evaluateScript("(function(){"+GooglePrompts.skipPasskeyScript+"})()")?.toString()
        guard context.exception == nil, result == expected, context.evaluateScript("clicked")?.toBool() == (expected == "skipped") else { throw Failure.message("通行密钥提示回归失败："+label) }
    }
    print("PASS: optional passkey prompt skip in Chinese/English; Continue, mandatory challenge, other origin and hidden buttons excluded")
}
@MainActor func styleTests() throws {
    let model = Model(testing:true)
    let staleDraft = model.workspace
    model.updateStyle(font:15,row:48,accent:"#1677FF")
    assert(model.workspace.fontSize == 15 && model.workspace.rowHeight == 48 && model.workspace.accent == "#1677FF")
    var draft = staleDraft; draft.chromePath = "/usr/bin/true"
    model.saveSettings(draft)
    assert(model.error.isEmpty && model.workspace.fontSize == 15 && model.workspace.accent == "#1677FF")
    let saved = try JSONEncoder().encode(model.workspace)
    let restored = try JSONDecoder().decode(WorkspaceState.self,from:saved)
    assert(restored.fontSize == 15 && restored.rowHeight == 48)
    var legacy = try JSONSerialization.jsonObject(with:saved) as! [String:Any]
    legacy.removeValue(forKey:"styleRevision"); legacy["fontSize"] = 14; legacy["rowHeight"] = 64
    legacy["notes"] = ["fixture":"keep"]
    var migrated = try JSONDecoder().decode(WorkspaceState.self,from:JSONSerialization.data(withJSONObject:legacy))
    assert(migrated.styleRevision == nil)
    migrated.migrateStyle()
    assert(migrated.fontSize == 12 && migrated.rowHeight == 40 && migrated.accent == "#1677FF" && migrated.notes["fixture"] == "keep")
    migrated.fontSize = 16; migrated.migrateStyle(); assert(migrated.fontSize == 16)
    model.updateStyle(font:12,row:40,accent:"#16A66A")
    assert(model.workspace.fontSize == 12 && model.workspace.rowHeight == 40)
    print("PASS: immediate shared style, saved roundtrip, stale settings cannot revert style, legacy migration preserves metadata/theme, migration runs once, compact reset")
}
@MainActor func workspaceTests() throws {
    let model=Model(testing:true)
    let a=Account(email:"first@example.com",password:"fake",secret:"")
    let b=Account(email:"second@example.com",password:"fake",secret:"")
    try model.add([a,b]);assert(model.count("auto","recent")==2)
    model.selected=[a.id];model.group("第一组",copySelection:true);let first=model.filter
    model.selected=[a.id,b.id];model.group("第二组",copySelection:true)
    assert(model.count("auto",first)==1 && model.count("auto","all")==2)
    let c=Account(email:"third@example.com",password:"fake",secret:"")
    try model.add([c]);assert(model.workspace.recentIDs==[c.id] && model.count("auto","all")==3)
    assert(model.count("auto","ungrouped")==1)
    model.choose(scope:"auto",filter:first);model.selected=[a.id];model.ungroup()
    assert(model.count("auto",first)==0 && model.count("auto","ungrouped")==1)
    let encoded=try JSONEncoder().encode(model.workspace)
    let reloaded=try JSONDecoder().decode(WorkspaceState.self,from:encoded)
    assert(reloaded.recentIDs==[c.id] && reloaded.groups.count==2)
    model.deleteGroup(first);assert(model.accounts.count==3)
    let fm=FileManager.default;let temp=fm.temporaryDirectory.appendingPathComponent("flow-workspace-test-"+UUID().uuidString)
    try fm.createDirectory(at:temp.appendingPathComponent("Network"),withIntermediateDirectories:true)
    defer{try? fm.removeItem(at:temp)}
    try Data("test-cookie".utf8).write(to:temp.appendingPathComponent("Network/Cookies"))
    try Data("keep".utf8).write(to:temp.appendingPathComponent("Preferences"))
    try ProfileFiles.clearCookies(temp)
    assert(!fm.fileExists(atPath:temp.appendingPathComponent("Network/Cookies").path))
    assert(fm.fileExists(atPath:temp.appendingPathComponent("Preferences").path))
    let bookmarks=[BookmarkItem(name:"Test",url:"https://example.com/")]
    try ProfileFiles.applyBookmarks(bookmarks,profile:temp)
    var original=try JSONSerialization.jsonObject(with:Data(contentsOf:temp.appendingPathComponent("Bookmarks"))) as! [String:Any]
    var roots=original["roots"] as! [String:Any];var bar=roots["bookmark_bar"] as! [String:Any];var children=bar["children"] as! [[String:Any]]
    children.append(["id":"100","type":"url","name":"Existing","url":"https://example.org/"]);bar["children"]=children;roots["bookmark_bar"]=bar;original["roots"]=roots
    try JSONSerialization.data(withJSONObject:original).write(to:temp.appendingPathComponent("Bookmarks"))
    try ProfileFiles.applyBookmarks(bookmarks,profile:temp)
    let final=try JSONSerialization.jsonObject(with:Data(contentsOf:temp.appendingPathComponent("Bookmarks"))) as! [String:Any]
    let savedChildren=((final["roots"] as! [String:Any])["bookmark_bar"] as! [String:Any])["children"] as! [[String:Any]]
    assert(savedChildren.count==2 && savedChildren.contains{$0["name"] as? String=="Existing"})
    for name in ["../Default","Profile 1/../../else","foo"] {
        var refused=false;do{_ = try ProfileFiles.safeSystemDirectory(name,root:temp)}catch{refused=true};assert(refused)
    }
    try fm.createSymbolicLink(at:temp.appendingPathComponent("Profile 2"),withDestinationURL:temp)
    var refused=false;do{_ = try ProfileFiles.safeSystemDirectory("Profile 2",root:temp)}catch{refused=true};assert(refused)
    let localState:[String:Any] = ["profile":["info_cache":["Default":["name":"Personal"],"Profile 1":["name":"Work"]],"last_used":"Profile 1","profiles_order":["Default","Profile 1"]],"untouched":"keep"]
    try JSONSerialization.data(withJSONObject:localState).write(to:temp.appendingPathComponent("Local State"))
    try Model.removeSystemMetadata("Profile 1",root:temp)
    let updated=try JSONSerialization.jsonObject(with:Data(contentsOf:temp.appendingPathComponent("Local State"))) as! [String:Any]
    let updatedProfiles=updated["profile"] as! [String:Any]
    assert((updatedProfiles["info_cache"] as! [String:Any])["Profile 1"]==nil && updated["untouched"] as? String=="keep")
    assert(updatedProfiles["last_used"] as? String=="Default")
    let oldRoot=temp.appendingPathComponent("old"),newRoot=temp.appendingPathComponent("new")
    let dummy=oldRoot.appendingPathComponent("ChromeProfiles/test/Default")
    try fm.createDirectory(at:dummy,withIntermediateDirectories:true)
    try Data("profile-marker".utf8).write(to:dummy.appendingPathComponent("marker"))
    model.workspace.dataRoot=oldRoot.path;var draft=model.workspace;draft.dataRoot=newRoot.path;model.saveSettings(draft)
    assert(model.error.isEmpty && model.workspace.dataRoot==newRoot.path)
    assert(fm.fileExists(atPath:dummy.appendingPathComponent("marker").path) && fm.fileExists(atPath:newRoot.appendingPathComponent("ChromeProfiles/test/Default/marker").path))
    print("PASS: group copy/multiple membership, recent batch, ungroup preserves accounts, metadata persistence, cookie-only cleanup, bookmark preservation/idempotence, system path guards/index update, storage migration preserves original")
}
@MainActor func selfTest() throws {
    let editModel = Model(testing:true)
    let editable = Account(email:"edit@example.com",password:"fake",secret:"")
    try editModel.add([editable])
    var changed = editable; changed.secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    try editModel.editAccount(changed)
    let editCode = try totp(editModel.accounts[0].secret,time:59)
    assert(editModel.accounts[0].id == editable.id && editCode == "287082")
    changed.secret = "123456"
    do {try editModel.editAccount(changed);throw Failure.message("invalid secret accepted")} catch let failure as Failure {
        if failure.localizedDescription == "invalid secret accepted" {throw failure}
    }
    assert(editModel.accounts[0].secret != "123456")
    changed.secret = "";try editModel.editAccount(changed);assert(editModel.accounts[0].secret.isEmpty)
    print("PASS: edit adds TOTP, generates expected code, preserves ID, rejects invalid secret without mutation, supports clearing")
    let gridArea = CGRect(x:-1920,y:30,width:1920,height:1050)
    for count in [1,2,3,4,5,7,8,9,12] {
        let cells = WindowGrid.rects(count:count,area:gridArea)
        assert(cells.count == count && cells.allSatisfy{gridArea.contains($0)})
        assert(cells.reduce(CGFloat(0)){$0+$1.width*$1.height} == gridArea.width*gridArea.height)
        for i in cells.indices { for j in cells.indices where i != j { assert(!cells[i].intersects(cells[j])) } }
    }
    let eight = WindowGrid.rects(count:8,area:gridArea)
    assert(eight[0].minY == eight[3].minY && eight[4].minY > eight[0].minY)
    print("PASS: window grid count, screen bounds, no overlap, 8 windows in 4x2, negative monitor coordinates")
    try signedInTests()
    try styleTests()
    assert(ProfileFiles.staleLock("test-host-123",host:"test-host",processExists:{_ in false},profileInUse:false))
    assert(!ProfileFiles.staleLock("test-host-123",host:"test-host",processExists:{_ in true},profileInUse:false))
    assert(!ProfileFiles.staleLock("test-host-123",host:"test-host",processExists:{_ in false},profileInUse:true))
    for target in ["other-host-123","test-host-0","test-host-invalid","unknown"] {
        assert(!ProfileFiles.staleLock(target,host:"test-host",processExists:{_ in false},profileInUse:false))
    }
    print("PASS: stale local lock eligible; live PID, active profile, foreign host and malformed locks preserved")
    let fixtureRoot=URL(fileURLWithPath:"/tmp/Flow Test/Profile-A")
    assert(ProfileFiles.ownsProfile("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome --user-data-dir=/tmp/Flow Test/Profile-A --new-window",root:fixtureRoot))
    assert(!ProfileFiles.ownsProfile("Chrome --user-data-dir=/tmp/Flow Test/Profile-AB",root:fixtureRoot))
    assert(!ProfileFiles.ownsProfile("Chrome --user-data-dir=/tmp/Other",root:fixtureRoot))
    print("PASS: recovery matches complete profile path including spaces, excludes other profiles")
    let dragModel=Model(testing:true)
    let dragA=Account(email:"drag-a@example.com",password:"fake",secret:"")
    let dragB=Account(email:"drag-b@example.com",password:"fake",secret:"")
    try dragModel.add([dragA,dragB])
    dragModel.group("目标组",copySelection:false)
    let groupID=dragModel.filter
    dragModel.selected=[dragA.id,dragB.id]
    let payload=dragModel.dragPayload(dragA)
    assert(dragModel.dropAccounts([payload],scope:"auto",group:groupID))
    assert(dragModel.workspace.groups[0].members.count==2)
    assert(dragModel.dropAccounts([payload],scope:"auto",group:groupID))
    assert(dragModel.workspace.groups[0].members.count==2)
    assert(!dragModel.dropAccounts([payload],scope:"system",group:groupID))
    assert(!dragModel.dropAccounts(["external data"],scope:"auto",group:groupID))
    assert(!dragModel.dropAccounts([payload],scope:"auto",group:"recent"))
    dragModel.selected=[dragB.id]
    assert(dragModel.dropAccounts([dragModel.dragPayload(dragA)],scope:"auto",group:"ungrouped"))
    assert(dragModel.workspace.groups[0].members==[dragB.id] && dragModel.accounts.count==2)
    print("PASS: drag multiple/single accounts, idempotent grouping, ungrouping, cross-scope and external payload rejection")
    try workspaceTests()
    try passkeyPromptTests()
    try optionalTOTPTests()
    try cdpTests()
    try fieldTests()
    try entryTests()
    try runningHubTests()
    let s = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    let vectors: [(Double, String)] = [(59,"94287082"),(1111111109,"07081804"),(1111111111,"14050471"),(1234567890,"89005924"),(2000000000,"69279037"),(20000000000,"65353130")]
    for (t, code) in vectors { guard try totp(s,time:t,digits:8) == code else { fatalError("RFC 6238 vector failed") } }
    let a = try parseAccounts("| 邮箱 | 密码 | 密钥 |\n| --- | --- | --- |\n| test\\@example.com | fake-password | \(s) |")
    assert(a.count == 1 && a[0].email == "test@example.com")
    let tab = try parseAccounts("test@example.com\tfake\t\(s)"); assert(tab.count == 1)
    let dash = try parseAccounts("test@example.com----fake----\(s)"); assert(dash.count == 1)
    for bad in ["ABC123", "", "test@example.com|password|ABC123"] {
        var rejected = false
        do { if bad.contains("|") { _ = try parseAccounts(bad) } else { _ = try decodeSecret(bad) } } catch { rejected = true }
        assert(rejected)
    }
    print("PASS: six RFC 6238 vectors, three import formats, escaped email, invalid secret rejection")
}
@MainActor final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let model = Model.active else { return .terminateNow }
        if model.busy { model.error = "请等待当前登录队列结束后退出，或先在 Chrome 完成验证。"; return .terminateCancel }
        model.shutdown { sender.reply(toApplicationShouldTerminate: true) }
        return .terminateLater
    }
}
@MainActor func renderPreview(_ path:String,settings:Bool) throws {
    let m=Model(testing:true)
    let rows=(1...5).map { Account(email:"flow-demo-\($0)@example.com",password:"demo-only",secret:"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ") }
    try m.add(rows)
    m.selected=Set(rows.prefix(3).map(\.id));m.group("flow",copySelection:true)
    m.filter="all";m.selected=Set(rows.prefix(3).map(\.id))
    m.statuses[rows[0].id]="已打开 · 登录状态保留"
    m.workspace.notes[rows[1].id]="视频制作账号"
    m.systemProfiles=[SystemProfile(directory:"Default",name:"个人",email:"personal@example.com"),SystemProfile(directory:"Profile 1",name:"工作",email:"work@example.com")]
    m.tab=settings ? "settings" : "accounts"
    let renderer=ImageRenderer(content:MainView(model:m).frame(width:1500,height:900))
    renderer.scale=1
    guard let image=renderer.nsImage,let tiff=image.tiffRepresentation,let bitmap=NSBitmapImageRep(data:tiff),let png=bitmap.representation(using:.png,properties:[:]) else{throw Failure.message("无法渲染预览")}
    try png.write(to:URL(fileURLWithPath:path))
}
@main struct FlowLauncherApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    init() {
        if let i=CommandLine.arguments.firstIndex(of:"--render-preview"),CommandLine.arguments.count>i+1 {
            do {try renderPreview(CommandLine.arguments[i+1],settings:CommandLine.arguments.contains("--settings"));exit(0)}catch{print(error.localizedDescription);exit(1)}
        }
        if let i = CommandLine.arguments.firstIndex(of: "--browser-test"), CommandLine.arguments.count > i + 1 {
            let b = Browser(id: "smoke")
            do {
                try b.start(profile: URL(fileURLWithPath: CommandLine.arguments[i + 1]))
                try b.navigate("data:text/html,<title>Flow smoke test</title><input type=password id=p><button id=next>Next</button>")
                let title = try b.script("return document.title") as? String
                guard title == "Flow smoke test" else { throw Failure.message("Browser navigation failed") }
                var refused = false
                do { try b.fill("#p", text: "fake-test-only", next: "#next") } catch { refused = true }
                let value = try b.script("return document.querySelector('#p').value") as? String
                guard refused && value == "" else { throw Failure.message("Credential origin guard failed") }
                b.close(); print("PASS: Chrome launch, navigation, script execution, credential origin guard, graceful close"); exit(0)
            } catch { b.close(); print(error.localizedDescription); exit(1) }
        }
        if let i = CommandLine.arguments.firstIndex(of: "--cdp-wire-test"), CommandLine.arguments.count > i + 1 {
            do {
                let conn = try CDPConnection(url: URL(string: CommandLine.arguments[i + 1])!)
                let first = try conn.command("Test.echo", ["value": "hello"])
                let second = try conn.command("Test.echo", ["value": "second"])
                guard first["value"] as? String == "hello", second["value"] as? String == "second" else { throw Failure.message("CDP reply matching failed") }
                var rejected = false
                do { _ = try conn.command("Test.error") } catch { rejected = true }
                guard rejected else { throw Failure.message("CDP error not propagated") }
                conn.close(); print("PASS: real local WebSocket handshake, event filtering, command IDs, error propagation, close"); exit(0)
            } catch { print(error.localizedDescription); exit(1) }
        }
        if CommandLine.arguments.contains("--self-test") {
            do { try selfTest(); exit(0) } catch { print(error.localizedDescription); exit(1) }
        }
        NSApplication.shared.setActivationPolicy(.regular)
    }
    var body: some Scene { WindowGroup("Google 登录助手") { MainView() }.windowStyle(.titleBar) }
}
