# Aether v2 (`AetherFlow-v2`) 新一代協議規範與工程開發計畫

- **開發分支**：`dev/aether-v2`（嚴格隔離於 `main`，遵循分支開發規範）
- **目標基線**：`SagerNet/sing-box` 最新穩定版（當前為 `v1.14.4`，較現有 `v1.14.2` 領先 97 個上游修復提交）
- **文件定位**：針對 [`AETHER_V1_SECURITY_AUDIT.md`](./AETHER_V1_SECURITY_AUDIT.md) 揭露之 7 項安全漏洞（`S-1`～`S-7`）與 7 項可靠性缺陷（`R-1`～`R-7`），制定可直接指導編碼實作、密碼學驗證、壓力測試與後續上游自動同步打包的完整開發計畫。

---

## 一、設計目標與威脅模型（Threat Model & Goals）

### 1.1 必須抵禦的威脅模型
1. **白盒公開審查（White-Box Adversary）**：假設攻擊者完全掌握本公開倉庫的全部源碼、常數、狀態機與預設參數，安全性完全建立於標準密碼學原語與真實協議偽裝（Kerckhoffs 原則）。
2. **被動深度封包檢測（Passive DPI & Traffic Analysis）**：
   - 抵禦針對裸 TCP「全加密高熵流量（Fully Encrypted Traffic）」的熵值/可見字元比例檢測。
   - 抵禦針對「TLS-in-TLS」內層握手封包長度序列、2-Byte 獨立長度包、固定週期與固定大小心跳包的流量指紋識別。
3. **主動探測與重放攻擊（Active Probing & Replay Attacks）**：
   - 抵禦隨機位元組探測、半開慢速連線（Slowloris）、截獲首包重放、修改特定位元組（Bit-Flipping）觀測斷線時間與位元組閾值的預言機攻擊。
   - 確保服務重啟、負載均衡（Anycast / 多實例）或高併發峰值下**絕對不會發生 AEAD `(Key, Nonce)` 重用**。
4. **長期金鑰洩露風險（Forward Secrecy）**：確保伺服器配置或單一用戶憑證日後外洩時，歷史被錄製的網路封包（PCAP）無法被回溯解密。

### 1.2 核心可靠性與效能指標
- **零死鎖保證**：讀寫鎖完全解耦，雙向滿載 + 多路複用（`smux`/`yamux`/`h2mux`）+ 心跳併發下零卡死。
- **原子幀狀態機**：任何 `WriteDeadline` 超時或底層 Socket 半包寫入錯誤必須確保不會造成後續 AEAD Nonce 錯位，並具備真正的雙向死連線偵測（Dead Peer Detection）。
- **零拷貝與低 GC 壓力**：全面接入 `sing/common/buf.Buffer` 與 `N.ExtendedConn`（`ReadBuffer` / `WriteBuffer`）及單次系統呼叫寫入（Single-Write / `writev`），消除每幀多次 Slice 堆積配置。
- **完整 `sing-box` v1.14+ 生態相容**：原生支援 TLS 1.3 / uTLS / REALITY / ECH / ACME、L7 Fallback 回落、多用戶認證與流量統計、`Multiplex` + `UoT` / 原生 UDP 並存、行動網路切換重置（`InterfaceUpdated`）。

---

## 二、Aether v2 (`AetherFlow-v2`) 雙層協議架構規範

Aether v2 採用 **「外層標準偽裝載體 + 內層認證流控與動態填充幀」** 的雙模式統一架構，徹底淘汰 v1 的裸 TCP + XOR 長度遮罩設計：

```
+-----------------------------------------------------------------------+
| 應用層負載：TCP Stream / UDP Packet (Native Packet or UoT) / sing-mux |
+-----------------------------------------------------------------------+
| Aether v2 內層幀協議 (AetherFlow-v2 Framing & Control Plane)          |
|  - 0-RTT 首包合併 (Lazy Early Handshake: Header + Initial Padding +   |
|    Application Data 單次寫入)                                         |
|  - 多用戶 O(1) 身份雜湊認證 (EIH) + 256-bit ClientSalt 滑動視窗防重放 |
|  - 可編程突發填充引擎 (Burst Padding Scheme，消除 TLS-in-TLS 指紋)    |
|  - 非阻塞解耦式亂數抖動心跳 (Jittered Padded Ping/Pong + Read Watchdog)|
+-----------------------------------------------------------------------+
| 傳輸安全模式選擇：                                                    |
|  [模式 A：預設推薦 TLS / REALITY 載體模式 (tls.enabled = true)]       |
|   - 外層由 TLS 1.3 (uTLS 指紋 / REALITY / ECH / kTLS) 提供前向安全與  |
|     記錄層 AEAD 保護；驗簽失敗無縫回落至真實網站 (REALITY / Fallback) |
|   - 內層握手完成並結束首波填充幀後，可切換為極低開銷直通幀（免雙重加密|
|     CPU 損耗）                                                        |
|                                                                       |
|  [模式 B：獨立端對端前向安全模式 (Standalone X25519 + Dual-AEAD)]     |
|   - 適用於中繼鏈路 (Detour/Relay) 或不終止 TLS 的反代場景             |
|   - X25519 臨時金鑰交換 + 256-bit uPSK + ClientSalt(32B) +            |
|     ServerSalt(32B) 雙向獨立衍生                                      |
|   - 獨立 18-Byte AEAD 加密定長長度頭 (2B Length + 16B Tag)，徹底廢除  |
|     XOR MaskLength                                                    |
+-----------------------------------------------------------------------+
| 底層載體：TCP / MPTCP / V2Ray Transport (WS / HTTPUpgrade / gRPC)     |
+-----------------------------------------------------------------------+
```

### 2.1 金鑰管理與多用戶 `O(1)` 認證（解決 `S-6`）

1. **強制高熵主金鑰（256-bit Base64 Key）**：
   - 新增 CLI 工具：`sing-box generate aether-key`（輸出 32 Bytes CSPRNG Base64 字串）與 `sing-box generate aether-keypair`（用於模式 B 的 X25519 公私鑰對）。
   - 配置支援多用戶陣列 `users: [{ "name": "alice", "key": "..." }]`；若舊配置使用助記密碼字串，啟動時強制要求長度 `>= 16` 字元並透過 `Argon2id(password, "AetherFlow-v2-StaticSalt", time=3, mem=64MB, threads=4)` 預先衍生 32-Byte `uPSK`（僅在節點啟動時計算一次，零連線期開銷，徹底阻斷 GPU 高速雜湊爆破）。
2. **`O(1)` 多用戶身份標頭（Extensible Identity Header, `EIH`）**：
   - 伺服器預先計算每位用戶的 `userUID = BLAKE2b-128(uPSK, "AetherFlow-v2-User-UID")`。
   - 客戶端握手時生成 32 Bytes 隨機 `clientSalt`，計算遮罩 `eihMask = HKDF-SHA256(serverMasterIDKey, clientSalt, "AetherFlow-v2-EIH")[0:16]`（單用戶模式可省略 EIH；多用戶模式由共享 `server_id_key` 或公鑰衍生 `eihMask`，傳送 `maskedUID = userUID XOR eihMask`），服務端以 `O(1)` Map 查表定位用戶 `uPSK`，避免多用戶 `O(N)` 試解密放大 DoS。

### 2.2 握手線框格式與雙向隨機鹽（解決 `S-1`、`S-2`、`S-3`、`S-5`）

#### 客戶端首包（Client Stream Prefix — 必須與首筆上層資料合併為單次 `Write`）

| 欄位 | 長度 (Bytes) | 加密保護 | 說明 |
| :--- | :---: | :---: | :--- |
| `ClientSalt` | `32` | 明文隨機數（在模式 A 中位於外層 TLS 1.3 密文隧道內） | CSPRNG 生成，直接作為防重放過濾器唯一鍵值（256-bit 零碰撞） |
| `EphemeralPub` | `0` 或 `32` | 模式 A 為 `0`；模式 B 為 X25519 Elligator2/標準臨時公鑰 | 模式 B 與伺服器靜態私鑰執行 X25519 ECDH 提供 0-RTT 前向安全性 |
| `EIH` | `0` 或 `16` | `userUID XOR eihMask` | 多用戶 `O(1)` 路由索引 |
| `EncryptedFixedHeader` | `16 + 16(Tag)` | `AEAD_Seal(c2sHeaderKey, nonce=0, FixedHeader, AAD=ClientSalt\|\|EphemeralPub\|\|EIH)` | **定長 32 Bytes AEAD 區塊**！服務端固定讀取定長位元組即可立即完成真偽驗證，徹底消除「先解碼未認證長度再決定讀多少位元組」的預言機漏洞 |
| `EncryptedVarHeader` | `VarHeaderLen + 16(Tag)` | `AEAD_Seal(c2sPayloadKey, nonce=0, VarHeader, AAD=FixedHeader)` | 內含目標位址（ATYP + Addr + Port）、隨機填充（Padding）與 **0-RTT 首包應用資料（InitialPayload）** |

其中 `FixedHeader`（16 Bytes 明文）結構為：
- `Version` (`1B`): 固定 `0x02`（嚴格版本檢查，拒絕未知版本，廢除 v1 危險的 `default:` 相容分支）
- `Command` (`1B`): `0x01 = TCP`、`0x02 = UDP Packet (Native Framed)`、`0x03 = Mux`、`0x04 = UoT`
- `TimestampSec` (`8B`, `int64` Big-Endian): 透過 `ntp.TimeFuncFromContext(ctx)` 校準之 Unix 秒級/毫秒時間戳（預設允許 `±30s`）
- `PaddingLen` (`2B`, `uint16`): `VarHeader` 內隨機填充長度（`0..1024`）
- `VarHeaderLen` (`2B`, `uint16`): `VarHeader` 明文總長度（因為已在 `EncryptedFixedHeader` 通過 Poly1305/GCM 認證，服務端讀取 `VarHeaderLen` 時**已完成身份與完整性驗證**！）
- `Flags` (`2B`, `uint16`): 預留擴充旗標（如 Padding Policy ID）

#### 伺服器首包回應（Server Response Prefix — 強制雙向鹽隔離）

| 欄位 | 長度 (Bytes) | 加密保護 | 說明 |
| :--- | :---: | :---: | :--- |
| `ServerSalt` | `32` | 隨機數 | **伺服器每次連線獨立由 CSPRNG 生成！** |
| `ServerRespHeader` | `8 + 16(Tag)` | `AEAD_Seal(s2cHeaderKey, nonce=0, RespMeta, AAD=ClientSalt\|\|ServerSalt)` | 綁定 `ClientSalt` 與 `ServerSalt`，防止跨連線回應替換攻擊（Response Cut-and-Paste Attack） |

**金鑰衍生公式（Key Schedule）**：
- 模式 A（TLS 1.3 / REALITY 內層）：`ikm = uPSK`，並可選綁定 TLS Exporter `tls.ConnectionState().ExportKeyingMaterial("AetherFlow-v2-TLS-Binding", nil, 32)` 防止 TLS 終止中間人重放。
- 模式 B（獨立前向安全模式）：`ikm = uPSK || X25519(ephemeralPriv_C, staticPub_S)`。
- 上行金鑰組：`HKDF-SHA256(ikm, ClientSalt, "AetherFlow-v2-C2S")` -> `c2sHeaderKey(32B) || c2sPayloadKey(32B)`。
- 下行金鑰組：`HKDF-SHA256(ikm, ClientSalt || ServerSalt, "AetherFlow-v2-S2C")` -> `s2cHeaderKey(32B) || s2cPayloadKey(32B)`。
  > **密碼學保證**：即便服務端在 30 秒內重啟或採用無狀態叢集部署，由於每次回應均重新抽取 32-Byte `ServerSalt`，`s2c` 金鑰永遠唯一，**從數學上根絕 ChaCha20-Poly1305 / AES-GCM Nonce 重用**。

### 2.3 資料幀格式與可編程突發填充（解決 `S-1`、`S-2`、`S-4`、`R-4`）

1. **廢除 `MaskLength`，改用 AEAD 定長頭（模式 B）或 TLS 內層輕量幀（模式 A）**：
   - **模式 B（獨立 AEAD 幀）**：
     - 幀頭：`AEAD_Seal(HeaderKey, nonce=seq, [FrameType(1B) | PlainLen(2B) | PadLen(1B)], nil)` -> 固定 `4 + 16 = 20 Bytes`。
     - 幀體：`AEAD_Seal(PayloadKey, nonce=seq, [Payload(PlainLen) | ZeroOrRandPad(PadLen)], nil)` -> `PlainLen + PadLen + 16 Bytes`。
     - 幀頭與幀體組裝於單一 `*buf.Buffer` 內**一次 `Write` 發出**，絕不產生 `2B` 獨立 TCP 小包。
   - **模式 A（TLS / REALITY 內層幀）**：
     - 外層 TLS 1.3 已提供區段機密性、完整性與硬體 AES-NI / kTLS 加速。
     - 前 `N` 個握手階段資料包（預設前 `8` 幀，參考 `AnyTLS` 填充模型）套用 `padding_scheme` 動態填充與拆包，掩蓋內層 TLS ClientHello / ServerHello / Certificate 長度特徵；第 `N+1` 幀起使用極輕量幀頭 `[FrameType(1B) | PayloadLen(2B) | PadLen(2B)] + Payload + Padding` 單次緩衝寫入，兼顧抗指紋與零雙重加密損耗。
2. **嚴格幀類型定義（Frame Types）**：
   - `0x01`: `FrameData`（允許 `PlainLen == 0` 作為純填充掩護包 `Chaff Frame`，`Read` 迴圈遇到 `PlainLen == 0` 自動 `continue`，絕不回傳 `(0, nil)`！）
   - `0x02`: `FramePing`（強制附帶 `16..192` Bytes 隨機長度填充，消除固定 `17B` 心跳指紋）
   - `0x03`: `FramePong`（強制附帶獨立隨機長度填充，使 Ping 與 Pong 封包大小不對稱、不可關聯）
   - `0x04`: `FrameCloseWrite`（優雅傳遞應用層 TCP Half-Close `FIN`）
   - 其他任何值：立即回傳 `ErrUnknownFrameType` 並銷毀連線。

### 2.4 雙代滑動視窗防重放與主動探測無感回落（解決 `S-5`、`S-7`）

1. **雙代滾動布隆/雜湊環過濾器（`SlidingReplayFilter`）**：
   - 以完整 `[32]byte` `ClientSalt` 為鍵，維護 `current` 與 `previous` 兩個時間片（每 `timeLimit` 輪轉一次，預設 `30s`）。
   - 採用預分配位元陣列（Bloom Filter，例如 `8 Mbits = 1 MB` 記憶體可支撐每分鐘百萬級握手且誤判率 `< 10^-7`），**具有嚴格 `O(1)` 常數記憶體上限且永遠不會因高併發而清空在有效期內的記錄**。
2. **主動探測防禦（消除 `200ms` `HandleProbe` 指紋）**：
   - **TLS + REALITY 模式**：未持有合法 ShortID / 簽章的主動探測在 TLS 握手層即由 `sing-box` `common/tls` 透明轉發至真實目標網站（如 Apple/Microsoft/Cloudflare 站點），具備真實憑證與真實 H2/H1 網站行為。
   - **標準 TLS + Fallback 模式**：外層 TLS 握手成功但內層 Aether `EncryptedFixedHeader` 驗簽或重放檢查失敗時，將已讀取的首包位元組封裝為 `bufio.NewCachedConn` 無縫轉交給 `fallback` / `fallback_for_alpn` 指定的本地 Nginx/Caddy 真實網站處理。
   - **無 Fallback 獨立模式**：強制設定握手總超時（預設 `8s` + 隨機抖動 `0..4s`），驗簽失敗後不立即 `FIN` 亦不使用固定 `200ms`，而是進入與標準 HTTP 伺服器 `client_header_timeout` 一致的隨機延遲排空關閉，並以帶速率限制的 `logger.WarnContext` 記錄來源 IP 與失敗原因（區分 `bad_tag`、`replay`、`clock_skew`、`timeout`）。

### 2.5 無死鎖控制平面與雙向死連線偵測（解決 `R-1`、`R-2`、`R-3`）

```
                   +---------------------------+
Application Write ->|                           |
                   |  Serialized Frame Writer  |---> Single-Buffer Conn.Write()
Control Queue ---->|  (Atomic Nonce + Poison   |     (任何寫入錯誤立即標記
(chan frameType, 2) |   on Partial Write Error) |      connPoisoned 並 Close)
                   +---------------------------+
                               ^
                               | 非阻塞投遞 (select { case ctrlCh <- FramePong: default: })
                   +---------------------------+
Socket Read ------>|  Frame Reader (readMu)    |---> 更新 lastRead.Store(now)
                   |  絕不獲取 writeMu！       |
                   +---------------------------+
```

1. **徹底解除 `Read -> Write` 鎖耦合**：
   - `Conn.Read` 收到 `FramePing` 時，僅透過容量為 1 的非阻塞通道 `pongSignal` 通知背景寫入協程發送 `FramePong`，**絕不在持有 `readMu` 期間呼叫 `writeMu.Lock()` 或 `Conn.Write`**，從根源消除雙向 TCP 視窗滿載死鎖。
2. **原子寫入與錯誤熔斷（Write-or-Close Invariant）**：
   - 將上層 `SetWriteDeadline` 與內部控制幀超時分離管理；一旦底層 `c.Conn.Write` 發生任何錯誤（特別是寫入部分位元組後中斷），立即原子設定 `c.broken.Store(true)` 並關閉底層 Socket，禁止任何後續寫入使用錯位的 AEAD Nonce。
3. **真正的雙向健康檢查（Dead Peer Detection）**：
   - 心跳協程啟用亂數抖動計時器（`interval * [0.75, 1.25]`）。
   - 當距離 `lastRead.Load()` 超過 `heartbeat_interval` 時發送帶隨機填充的 `FramePing`，並記錄 `pingSentAt`；若在 `pong_timeout`（預設 `2 * heartbeat_interval` 或 `15s`）內 `lastRead.Load()` 仍未推進，主動執行 `c.Close()` 釋放殭屍連線並觸發上層 `sing-mux` / `URLTest` 快速切換。

---

## 三、配置結構設計（`option/aether.go` v2 草案）

```go
package option

import "github.com/sagernet/sing/common/json/badoption"

type AetherUser struct {
	Name string `json:"name,omitempty"`
	Key  string `json:"key"` // 32-byte base64 CSPRNG key (或 >=16 字元高強度密碼)
}

type AetherInboundOptions struct {
	ListenOptions
	InboundTLSOptionsContainer
	Users                []AetherUser              `json:"users,omitempty"`
	Key                  string                    `json:"key,omitempty"`       // 單用戶簡寫
	ServerPrivateKey     string                    `json:"private_key,omitempty"` // 模式 B: X25519 私鑰
	TimeWindow           badoption.Duration        `json:"time_window,omitempty"` // 預設 30s
	HandshakeTimeout     badoption.Duration        `json:"handshake_timeout,omitempty"` // 預設 8s
	HeartbeatInterval    badoption.Duration        `json:"heartbeat_interval,omitempty"`
	PaddingScheme        badoption.Listable[string] `json:"padding_scheme,omitempty"`
	Fallback             *ServerOptions            `json:"fallback,omitempty"`
	FallbackForALPN      map[string]*ServerOptions `json:"fallback_for_alpn,omitempty"`
	Multiplex            *InboundMultiplexOptions  `json:"multiplex,omitempty"`
	Transport            *V2RayTransportOptions    `json:"transport,omitempty"`
}

type AetherOutboundOptions struct {
	DialerOptions
	ServerOptions
	OutboundTLSOptionsContainer
	Network              NetworkList               `json:"network,omitempty"`
	Key                  string                    `json:"key"`
	ServerPublicKey      string                    `json:"public_key,omitempty"` // 模式 B: X25519 公鑰
	HeartbeatInterval    badoption.Duration        `json:"heartbeat_interval,omitempty"`
	PaddingScheme        badoption.Listable[string] `json:"padding_scheme,omitempty"`
	Multiplex            *OutboundMultiplexOptions `json:"multiplex,omitempty"`
	UDPOverTCP           *UDPOverTCPOptions        `json:"udp_over_tcp,omitempty"`
	Transport            *V2RayTransportOptions    `json:"transport,omitempty"`
}
```

---

## 四、分階段開發與交付計畫（Phased Development Roadmap）

所有開發工作均在 **`dev/aether-v2`** 分支（或其子功能分支）進行，驗收通過前絕不合併回 `main`。

### Phase 0：分支治理、上游基線升級與開發環境整備（預計 0.5 天）
- [ ] **0.1 同步上游最新正式版**：在 `dev/aether-v2` 分支拉取 `SagerNet/sing-box` 最新穩定 Tag（`v1.14.4` 或更新正式版），完成無衝突基底對齊。
- [ ] **0.2 修正建置標籤與隔離舊版 CI**：
  - 補齊 `.github/workflows/` 中缺失的 `with_quic`、`with_acme` 編譯 Tag。
  - 移除或停用繼承自上游、會誤推向 `ghcr.io/sagernet/sing-box` 的 `docker.yml` 觸發器，並防止非 Release Tag 提交覆蓋正式版二進位檔案。
- [ ] **0.3 CLI 金鑰生成支援**：於 `cmd/sing-box/cmd_generate.go` 擴充 `aether-key` 與 `aether-keypair` 子指令。

### Phase 1：密碼學核心與雙代防重放模組實作（預計 1.5 天）
- [ ] **1.1 金鑰排程與雙鹽 AEAD 引擎（`protocol/aether/crypto.go`）**：
  - 實作 256-bit Base64 金鑰解析與啟動期 `Argon2id` 口令強化檢查（拒絕空密碼與 `<16` 字元弱口令）。
  - 實作 `X25519` 臨時金鑰交換、TLS Exporter 通道綁定、`ClientSalt` + `ServerSalt` 雙向 `HKDF-SHA256` 金鑰衍生，以及硬體加速演算法自動選擇（AES-NI 環境優先 `AES-256-GCM`，無硬體加速環境自動選用 `ChaCha20-Poly1305`）。
  - 實作多用戶 `EIH` `O(1)` 身份索引表。
- [ ] **1.2 雙代滑動視窗布隆防重放器（`protocol/aether/replay.go`）**：
  - 以 `[32]byte` `ClientSalt` + `ntp.TimeFuncFromContext(ctx)` 實作雙時間片輪轉 Bloom Filter，徹底移除 `map` 清空邏輯。
- [ ] **1.3 單元測試**：編寫 KAT（已知答案測試向量）、雙向鹽隔離測試、重放邊界與時鐘偏移測試、高併發百萬次插入零清空測試。

### Phase 2：線框編解碼、突發填充引擎與無死鎖零拷貝連線層（預計 2 天）
- [ ] **2.1 定長認證頭與幀編解碼器（`protocol/aether/wire.go`、`padding.go`）**：
  - 實作 `Version = 0x02` `EncryptedFixedHeader` + `EncryptedVarHeader` 編解碼，移除 `MaskLength` 與 `noise.go`。
  - 實作可配置 `PaddingScheme`（針對前 `N` 幀進行長度分佈塑形與隨機 Chaff 掩護幀）。
- [ ] **2.2 無死鎖、零拷貝 `Conn` 與 0-RTT `EarlyConn`（`protocol/aether/conn.go`）**：
  - 實作延遲首包合併（`DialEarlyConn`）：於上層首次 `Write` / `WriteBuffer` 時將握手頭、首波填充與首筆應用資料組裝於單一 `*buf.Buffer` 一次寫出；服務端正確將 `InitialPayload` 注入初始讀取緩衝區。
  - 實作 `N.ExtendedConn`（`ReadBuffer` / `WriteBuffer`）與 `CloseWrite()` 半關閉支援。
  - 解耦控制通道（非阻塞 `FramePong` 排程）、實作寫入失敗原子熔斷（防止 Nonce 失步）與基於 `lastRead` 的亂數抖動心跳超時斷線機制。

### Phase 3：`sing-box` v1.14+ Inbound / Outbound 完整生態整合（預計 1.5 天）
- [ ] **3.1 Inbound 服務化改造（`protocol/aether/inbound.go`、`service.go`）**：
  - 整合 `tls.NewServerWithOptions`（支援 TLS 1.3、REALITY、ACME、ECH）與 `v2ray.NewServerTransport`。
  - 實作 Trojan 級別 `fallback` 與 `fallback_for_alpn` 無縫回落（透過 `bufio.NewCachedConn` 重放首包至真實 Web 伺服器），徹底廢除 `probe_guard.go` 的 `200ms` 硬編碼關閉邏輯。
  - 實作多用戶 `metadata.User` 注入、`adapter.TCPInjectableInbound`、`InboundDetour` 與分級安全審計日誌。
- [ ] **3.2 Outbound 完整介面補齊（`protocol/aether/outbound.go`）**：
  - 整合 `tls.NewClient`（含 `uTLS` 瀏覽器指紋偽裝）與 `v2ray.NewClientTransport`。
  - 完整實作 `adapter.OutboundWithMultiplex`：`MultiplexEnabled()`、`InterfaceUpdated(ctx)`（網路切換立即重置連線池）、`Close()`（優雅釋放 `multiplexDialer` 與傳輸層）。
  - 修復 `Multiplex` + `UDP` 支援：同時支援 `multiplexDialer.ListenPacket`、`uotClient.ListenPacket` 與原生 `CommandUDP` 封包幀，根絕 UDP 誤導流至 TCP 的錯誤；確保所有錯誤路徑妥善關閉底層 `rawConn`。

### Phase 4：全面安全驗證、模糊測試與高壓可靠性驗收（預計 1.5 天）
- [ ] **4.1 自動化模糊測試（Go Native Fuzzing）**：
  - 建立 `FuzzServerHandshake`、`FuzzFrameDecoder`、`FuzzAddressCodec`，針對畸形長度、截斷封包、隨機翻轉位元進行不少於 1,000 萬次迭代驗證零 Panic、零 OOM。
- [ ] **4.2 並發競態與死鎖壓測（`-race` & Backpressure Chaos Test）**：
  - 模擬受限 TCP 接收視窗（4KB Socket Buffer）+ 64 路並發雙向大流量 + 100ms 高頻率 `FramePing`/`FramePong` + 隨機 `SetWriteDeadline` 超時，在 `go test -race` 下驗證零死鎖、零 Nonce 失步、零 Goroutine / FD 洩漏。
- [ ] **4.3 流量特徵與抗主動探測黑盒驗證**：
  - 抓包驗證：首包無裸隨機高熵暴露（REALITY/TLS 模式）、全程零 `2-Byte` 獨立 TCP 段、心跳封包長度與間隔呈隨機分佈。
  - 主動探測模擬：發送隨機短包、超長包、慢速滴灌包、截獲重放包，確認探測者獲得的回應與真實目標 HTTPS 站點 100% 一致。

### Phase 5：平滑遷移上線與「每週自動追蹤上游 `sing-box` 正式版」CI/CD 部署（預計 1 天）
- [ ] **5.1 雙棧灰度切換**：
  - 節點端短期可透過不同埠口（或 `Inbound` 過渡配置）並行運行舊版與 `Aether v2`，待所有客戶端升級至 `v2` 後下線 `v1` 並將 `dev/aether-v2` 合併回 `main`。
- [ ] **5.2 啟用每週上游 `SagerNet/sing-box` 正式版自動同步與打包 GitHub Action**：
  - 當 `Aether v2` 完成安全驗收並合入主幹後，部署 `.github/workflows/upstream-sync-release.yml`：
    1. **排程觸發**：每週一 UTC `02:00`（`cron: '0 2 * * 1'`）及支援手動 `workflow_dispatch`。
    2. **正式版過濾**：透過 GitHub API 查詢 `SagerNet/sing-box/releases/latest`（自動排除 `alpha` / `beta` / `rc` 預發佈版本），比對本庫最新已發佈之 `-Custom-Aether` 基底版本號。
    3. **自動融合與驗證**：若發現上游新正式版（如 `v1.14.4`、`v1.15.0`），自動建立同步分支拉取上游 Tag，融合 `Aether v2` 模組，執行 **`go vet` + `go test -race ./protocol/aether/...` + 完整二進位編譯（含 `with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api`）**。
    4. **安全發佈機制**：測試與編譯全部通過後，更新 `constant/version.go` 為 `<UPSTREAM_VER>-Aether-v2`，自動打 Tag 並發佈對應版本的 GitHub Release（附 SHA256 校驗碼與上游更新摘要）；若遇上游大型重構產生合併衝突或測試失敗，則自動建立 Pull Request / Issue 通知維護者介入，絕不發佈損壞版本。

---

## 五、預期變更模組清單（File Blueprint on `dev/aether-v2`）

| 檔案路徑 | 操作類型 | 職責說明 |
| :--- | :---: | :--- |
| `option/aether.go` | 重構 | 升級 v2 配置結構（整合 TLS/REALITY、Users、Fallback、Transport、PaddingScheme） |
| `protocol/aether/crypto.go` | 新增（取代 `cipher.go`） | Argon2id/Base64 金鑰載入、X25519 PFS、雙鹽 HKDF、EIH 多用戶查表、AES-GCM/ChaCha20 AEAD |
| `protocol/aether/wire.go` | 新增（取代 `frame.go`、`noise.go`） | v2 定長認證頭、指令與位址編解碼、單次緩衝幀封裝 |
| `protocol/aether/padding.go` | 新增 | 可編程突發填充方案（Burst Padding Scheme）與隨機掩護幀生成 |
| `protocol/aether/replay.go` | 重構 | 雙代滑動視窗 256-bit `ClientSalt` 布隆過濾器 + NTP 時間源整合 |
| `protocol/aether/conn.go` | 重構 | 0-RTT `EarlyConn`、`N.ExtendedConn` 零拷貝緩衝、無死鎖控制佇列、雙向心跳超時偵測 |
| `protocol/aether/service.go` | 新增（取代 `probe_guard.go`） | 服務端握手調度、連線超時控制、L7 Fallback 無縫回落轉發 |
| `protocol/aether/inbound.go` | 重構 | 接入 `common/tls`、`transport/v2ray`、`mux`、`uot` 與安全審計日誌 |
| `protocol/aether/outbound.go` | 重構 | 補齊 `OutboundWithMultiplex`、`InterfaceUpdated`、`Close`、UDP/Mux/UoT 完整矩陣 |
| `protocol/aether/*_test.go` | 新增 | 單元測試、`-race` 並發死鎖壓測、Go Fuzzing 模糊測試套件 |
| `cmd/sing-box/cmd_generate.go` | 擴充 | 新增 `sing-box generate aether-key` / `aether-keypair` |
| `.github/workflows/upstream-sync-release.yml` | Phase 5 新增 | 每週自動檢查上游 `SagerNet/sing-box` 正式版、融合 Aether v2 測試並打包發佈 |
