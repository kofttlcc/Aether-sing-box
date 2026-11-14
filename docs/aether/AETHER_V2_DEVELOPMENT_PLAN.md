# Aether v2 (`AetherFlow-v2`) 專線純淨版協議規範與工程開發計畫

- **開發分支**：`dev/aether-v2`（嚴格隔離於 `main`，遵循分支開發規範）
- **應用場景定位**：**跨境/跨網專線（IPLC / IEPL / 企業專線），不經過國家級 GFW，專注規避省級防火牆/運營商機房審計識別為常規代理協議，並提供高強度前向安全加密與專線級極致吞吐穩定性**
- **架構裁剪決策**：**剔除外層 TLS / REALITY / Fallback / V2Ray Transport 模組**（零明文 SNI 暴露、零證書維運成本、零雙重加密損耗、代碼體積精簡約 45%）
- **目標基線**：`SagerNet/sing-box` 最新穩定正式版（當前為 `v1.14.4`）

---

## 一、專線場景威脅模型重評估（Why Pure-Binary Aether v2）

### 1.1 剔除外層 TLS 後的防禦重點轉移
在專線入口（國內 BGP / 省網接入點）環境下：
1. **不採用外層 TLS 的核心優勢**：省級防火牆與國內機房合規網關普遍部署 **TLS SNI / HTTP Host ICP 備案白名單檢測**。剔除外層 TLS 後，連線上完全不存在任何域名特徵，徹底免疫未備案域名阻斷，同時免除額外 1-RTT TLS 握手延遲與雙層加密 CPU 消耗。
2. **省級防火牆（省牆 / 運營商旁路 DPI）實際檢測維度**：
   - **常規代理協議靜態簽章**：精確匹配 SOCKS5、HTTP CONNECT、Shadowsocks/SSR 已知結構、VMess、VLESS、Trojan CRLF、WireGuard 固定 4-Byte 訊息頭（`0x01 0x00 0x00 00` 等）及固定握手長度（148B / 92B）。
   - **異常封包序列與流統計指紋（Aether v1 翻車主因）**：
     - 檢測「每幀先發 `2-Byte` 獨立 TCP 小包、再發密文包」的異常分片比例（v1 雙次 `Write` 缺陷）。
     - 檢測「0 負載固定握手包 -> 緊隨 ~517B 內層 ClientHello -> 3KB+ 內層憑證突發」的典型代理嵌套流特徵，以及固定週期、固定 `17-Byte` 的機械式心跳包。
   - **機房資產測繪與合規主動掃描（FOFA / 運營商端口巡檢）**：發送常見協議探針或隨機短包，觀測是否出現特定代理服務端的固定超時斷線特徵（如 v1 硬編碼 `200ms` 關閉）或預言機回應。
3. **密碼學與高併發專線可靠性剛性要求**：
   - 專線通常承載匯聚流量（高併發連線、長時 `sing-mux` 多路複用、大頻寬跑滿），必須具備 **X25519 前向安全性（PFS）**、**雙向隨機鹽防 Nonce 重用**、**AEAD 認證定長長度頭**、**常數記憶體不清空的防重放器**，以及 **100% 無死鎖、零拷貝的雙向流控機制**。

---

## 二、Aether v2（專線純淨版）單層高性能密碼學與線框規範

剔除外層 TLS 後，Aether v2 採用 **「全隨機無特徵 X25519+PSK 握手 + 18-Byte AEAD 定長認證頭 + 首部前 N 幀輕量塑形」** 的極簡純二進位架構，且**完全使用 Go 標準庫與 `sing-box` 現有依賴（零外部新增套件）**：

```
+-----------------------------------------------------------------------+
| 應用層負載：TCP / Native Framed UDP / UoT / sing-mux                  |
+-----------------------------------------------------------------------+
| Aether v2 專線流控與首部塑形層 (Head-Only Shaping & Early Data)       |
|  - 0-RTT 首包合併 (DialEarlyConn：握手頭 + 隨機雜訊 + 首筆應用資料    |
|    合併於單一緩衝區一次發出，消除空握手包特徵)                        |
|  - 僅前 6 幀動態填充拆包 (掩蓋內層 HTTPS 握手長度)，第 7 幀起零填充   |
|    跑滿 10Gbps+ 專線頻寬                                              |
|  - 解耦式空閒亂數抖動心跳 (Idle-Only Jittered Padded Ping/Pong)       |
+-----------------------------------------------------------------------+
| Aether v2 單層認證加密核心 (Single-Layer PFS AEAD Engine)             |
|  - 僅需配置單一共享密鑰即可透過臨時 X25519 ECDHE 獲得完整前向安全性   |
|    (可選配靜態公私鑰實現首包 0-RTT 前向安全)                          |
|  - ClientSalt(32B) + ServerSalt(32B) 雙鹽隔離，根絕 AEAD Nonce 重用   |
|  - 18-Byte AEAD 加密定長長度頭 (2B Length + 16B Tag)，徹底廢除        |
|    XOR MaskLength                                                     |
|  - 自動硬體加速協商：AES-NI / ARMv8 硬體指令優先選用 AES-256-GCM，    |
|    軟路由無硬體加速時自動選用 ChaCha20-Poly1305                       |
+-----------------------------------------------------------------------+
| 底層載體：原生 TCP / MPTCP（零 TLS SNI、零常規代理協議特徵）          |
+-----------------------------------------------------------------------+
```

### 2.1 金鑰體系與零配置負擔的前向安全性（解決 `S-6`）

1. **主密鑰規範與弱口令防護**：
   - 支援 `sing-box generate aether-key` 生成 32-Byte CSPRNG Base64 金鑰（推薦），並支援多用戶列表 `users: [{ "name": "node-gz", "key": "..." }]` 與單用戶簡寫 `key` / `password`。
   - 若填入助記字串口令，節點啟動時強制校驗長度 `>= 16` 字元（拒絕空密碼與短密碼），並於啟動期執行一次 `Argon2id(password, "AetherFlow-v2-KDF", time=3, mem=64MB, threads=4)` 衍生 256-bit `uPSK`（連線期零開銷，徹底防禦離線 GPU 字典爆破）。
2. **全隨機偽裝之臨時 `X25519` 金鑰交換（無 Curve25519 高位元偏置特徵）**：
   - 客戶端每次連線使用 `crypto/ecdh.X25519()` 生成一次性臨時金鑰對 `(ek_c, epk_c)`，伺服器回應時亦生成一次性臨時金鑰對 `(ek_s, epk_s)`。
   - **消除公鑰統計特徵**：標準 X25519 公鑰第 31 位元組最高位恆為 `0`（若明文傳送多次可被統計識別，如早期 OBFS4/WireGuard 分析）。Aether v2 利用 `HKDF-SHA256(uPSK, Salt, "AetherFlow-v2-EPK-Mask")` 產生的 ChaCha20 金鑰流對 32-Byte `epk` 進行流遮罩（並將遮罩後位元組納入 AEAD `AAD` 完整性認證），使線路上每個位元組呈現 **100% 理想均勻隨機分佈**，無需引入複雜緩慢的 Elligator2 運算。
   - **平滑金鑰棘輪（Key Ratchet）**：
     - 客戶端首包由 `initKey = HKDF(uPSK, ClientSalt)`（若配置了可選 `server_public_key`，則 `initKey = HKDF(uPSK || X25519(ek_c, spk_s), ClientSalt)` 達成首包 0-RTT PFS）加密保護。
     - 伺服器首包回應立即攜帶 `ServerSalt` 與 `epk_s`，並將雙向會話金鑰升級為 **`masterSecret = HKDF-SHA256(uPSK || X25519(ek_c, epk_s), ClientSalt || ServerSalt, "AetherFlow-v2-Session")`**！
     - **效果**：用戶無需額外管理公私鑰對（維持與 v1 一樣簡單的單一 `key`/`password` 配置），即可讓**全部下行資料與後續所有上行資料具備完整 X25519 前向安全性**！

### 2.2 握手線框格式與雙鹽防重放（解決 `S-1`、`S-2`、`S-3`、`S-5`）

#### 客戶端首包（Client Initial Burst — 與首筆應用資料單次合併寫出）

| 偏移量 | 欄位名稱 | 長度 (Bytes) | 說明 |
| :---: | :--- | :---: | :--- |
| `0..32` | `ClientSalt` | `32` | CSPRNG 隨機鹽，同時作為雙代布隆防重放器的 256-bit 唯一鍵 |
| `32..64` | `MaskedClientEPK` | `32` | 經 `uPSK + ClientSalt` 流遮罩之客戶端一次性 X25519 公鑰 `epk_c` |
| `64..80` | `EIH`（可選） | `0` 或 `16` | 僅在配置多用戶 `users` 時啟用，提供 `O(1)` 雜湊查表定位用戶 `uPSK` |
| `...` | `EncryptedFixedHeader` | `16 + 16(Tag) = 32` | **定長 32 Bytes ChaCha20-Poly1305 認證頭**，`AAD = ClientSalt \|\| MaskedClientEPK \|\| EIH` |
| `...` | `EncryptedVarHeader` | `VarLen + 16(Tag)` | 經認證後讀取的變長區塊，內含：`NoisePadding` + `TargetAddr` + `InitialPayload` |

**`FixedHeader`（16 Bytes 明文）欄位定義**：
- `Version` (`1B`): 固定 `0x02`
- `Command` (`1B`): `0x01 = TCP`、`0x02 = Native UDP`、`0x03 = Sing-Mux`、`0x04 = UoT`
- `CipherSuite` (`1B`): 資料面 AEAD 演算法協商（`0x01 = AES-256-GCM`、`0x02 = ChaCha20-Poly1305`；由客戶端依雙方硬體指令支援自動選擇或配置指定）
- `Reserved` (`1B`): `0x00`
- `TimestampSec` (`8B`, `int64` BE): 經 `ntp.TimeFuncFromContext(ctx)` 校準之時間戳（預設容許 `±30s`）
- `NoiseLen` (`2B`, `uint16` BE): 首包隨機填充長度（`32..384` Bytes）
- `VarHeaderLen` (`2B`, `uint16` BE): `VarHeader` 明文總長度（上限 `16384` Bytes）

> **關鍵安全特性（徹底消滅 `S-1` 預言機）**：服務端永遠先讀取**固定長度（96 Bytes 單用戶 / 112 Bytes 多用戶）**的前綴並立即執行 AEAD 驗簽、時間戳驗證與 256-bit 布隆防重放檢查！**任何未持合法密鑰的探測封包在讀取變長欄位前即已判定失敗**，探測者無論如何翻轉位元組都無法影響服務端讀取長度，徹底根絕主動探測與離線密碼爆破預言機。

#### 伺服器回應前綴（Server Response Prefix — 隨首筆下行資料合併寫出）

| 偏移量 | 欄位名稱 | 長度 (Bytes) | 說明 |
| :---: | :--- | :---: | :--- |
| `0..32` | `ServerSalt` | `32` | **伺服器每次連線獨立生成的 32B CSPRNG 隨機鹽** |
| `32..64` | `MaskedServerEPK` | `32` | 經流遮罩之伺服器一次性 X25519 公鑰 `epk_s` |
| `64..84` | `EncryptedRespHeader` | `4 + 16(Tag) = 20` | 使用升級後 `X25519` 會話金鑰加密之回應確認頭，`AAD = ClientSalt \|\| ServerSalt \|\| MaskedServerEPK` |

### 2.3 高速資料幀格式與「首部輕量塑形」（解決 `S-2`、`S-4`、`R-4`）

1. **獨立金鑰雙區塊 AEAD 幀（Shadowsocks-2022 / SSH 同級設計，單次 `Write` 發送）**：
   每個方向的會話金鑰透過 `HKDF-SHA256` 切分為獨立的 `HeaderKey (32B)` 與 `PayloadKey (32B)`：
   - **加密長度頭（固定 `18 Bytes`）**：`AEAD_Seal(HeaderKey, nonce=seq, [PlainFrameLen (2B uint16)], nil)` -> `2 + 16 = 18 Bytes`。
   - **加密幀主體（`PlainFrameLen + 16 Bytes`）**：`AEAD_Seal(PayloadKey, nonce=seq, [FrameType (1B) | PadLen (1B) | Padding (PadLen) | Data], nil)`。
   - **單次緩衝寫入**：`18B` 加密長度頭與加密幀主體直接連續寫入同一個 `*buf.Buffer` 緩衝區，**每次發送僅呼叫一次底層 `Conn.Write`**，網路層絕對不會出現 `2-Byte` 分裂封包。
2. **專線友善的「首部前 6 幀輕量塑形（Head-Only Shaping）」**：
   - **Frame `0..5`（連線建立初期，對應內層 TLS 握手階段）**：自動附加 `16..255` Bytes 隨機填充（並對超過 `1200B` 的突發握手順勢做隨機切分），打碎內層 `ClientHello` / `ServerHello` / `Certificate` 的固定封包大小指紋，規避省牆「嵌套代理流」統計分類器。
   - **Frame `6+`（進入穩定資料傳輸期）**：`PadLen` 自動降為 `0`，以最大 `16KB` 幀與硬體 `AES-256-GCM` 全速轉發，頻寬額外開銷低於 **`0.22%`**（每 16384B 僅增加 36B 協議開銷），完美跑滿 1Gbps～10Gbps 專線！
3. **嚴格幀類型語義**：
   - `0x01`: `FrameData`（若 `len(Data) == 0` 視為純填充掩護包 Chaff，`Read` 自動跳過繼續讀取，絕不回傳違規的 `(0, nil)`）
   - `0x02`: `FramePing`（僅在連線完全空閒時發送，強制附帶 `32..224` Bytes 隨機填充）
   - `0x03`: `FramePong`（強制附帶獨立隨機長度填充，打破 Ping/Pong 等長對稱特徵）
   - `0x04`: `FrameCloseWrite`（支援 TCP 半關閉 `CloseWrite` 傳遞）
   - 未知類型立即報錯斷線（移除 v1 危險的 `default:` 分支）。

### 2.4 抗掃描靜默排空（Stealth Drain）與雙代布隆防重放（解決 `S-5`、`S-7`）

1. **雙代滑動布隆過濾器（`SlidingBloomFilter`）**：
   - 針對完整 `[32]byte` `ClientSalt` 維護 `current` 與 `previous` 雙時間片（預設每 `30s` 輪轉），固定佔用約 `1 MB` 位元陣列，可承受每分鐘百萬次專線短連線握手而**永不清空有效歷史記錄**。
2. **防機房掃描器與防 Slowloris DoS 保護（取代 `probe_guard.go`）**：
   - **並行未認證握手信號量（Handshake Semaphore）**：限制同時處於未完成握手階段的連線上限（預設 `256`），防止惡意空連線耗盡 FD 與記憶體。
   - **消除 `200ms` 固定指紋**：正常握手設定嚴格截止時間（預設 `6s`）；若定長頭驗簽失敗或觸發重放，不立即 `RST`/`FIN` 亦不使用固定 `200ms`，而是設定每個連線獨立隨機抽取的 `3s..10s` 靜默讀取排空超時（行為與一般內部 TCP 服務讀超時無異），並透過帶速率限制的日誌記錄異常來源 IP。

### 2.5 無死鎖控制平面、原子熔斷與完整 `sing-box` 介面（解決 `R-1`～`R-7`）

1. **徹底根除 `Read -> Pong` 死鎖（`R-1`）**：`Conn.Read` 收到 `FramePing` 時僅對容量為 1 的 `pongCh` 執行非阻塞通知，由獨立寫入協調邏輯發送 `FramePong`，**絕不在持有 `readMu` 時爭搶 `writeMu` 或呼叫阻塞 `Write`**。
2. **寫入錯誤原子熔斷（`R-2`）**：分離應用層 `SetWriteDeadline` 與背景控制幀寫入；底層 `Conn.Write` 一旦發生任何錯誤或半包中斷，立即設定 `c.closed` 熔斷連線，從根本杜絕 AEAD Nonce 錯位。
3. **真正的雙向死連線偵測（`R-3`）**：空閒超過 `heartbeat_interval * jitter(0.75..1.25)` 時發送隨機填充 `FramePing`，並實際檢查 `c.lastRead.Load()` 是否在 `pong_timeout` 內更新，超時立即主動關閉底層 Socket，讓 `sing-mux` 與 `URLTest` 秒級自動重連。
4. **完整 `sing-box` v1.14+ 介面與零拷貝支援（`R-5`、`R-6`、`R-7`）**：
   - 實作 `N.ExtendedConn`（`ReadBuffer` / `WriteBuffer` 基於 `sing/common/buf` 記憶體池零拷貝）。
   - `Outbound` 完整實作 `adapter.OutboundWithMultiplex`、`InterfaceUpdated(ctx)`、`Close()`。
   - 打通 `Multiplex` + `UoT` + 原生 `CommandUDP` 封包幀（支援 `multiplexDialer.ListenPacket`、`uotClient.ListenPacket` 及原生無開啟 UoT 時的 `CommandUDP` 雙向 UDP 封裝），徹底修復 v1 的 UDP/Mux 互斥 Bug。

---

## 三、精簡後配置結構設計（`option/aether.go` v2 專線版）

保持與現有配置高度直覺相容（無任何 TLS / 證書 / Transport 冗餘欄位）：

```go
package option

import "github.com/sagernet/sing/common/json/badoption"

type AetherUser struct {
	Name     string `json:"name,omitempty"`
	Password string `json:"password"` // 支援 32B Base64 隨機金鑰，或 >=16 字元高強度口令
}

type AetherInboundOptions struct {
	ListenOptions
	Password          string                    `json:"password,omitempty"`          // 單用戶模式直接配置
	Users             []AetherUser              `json:"users,omitempty"`             // 多用戶模式 (選配)
	ServerPrivateKey  string                    `json:"private_key,omitempty"`       // 選配：開啟首包 0-RTT PFS
	TimeWindow        badoption.Duration        `json:"time_window,omitempty"`       // 防重放時間窗，預設 30s
	HandshakeTimeout  badoption.Duration        `json:"handshake_timeout,omitempty"` // 握手超時，預設 6s
	HeartbeatInterval badoption.Duration        `json:"heartbeat_interval,omitempty"`// 空閒心跳基準間隔，預設 30s
	DisableShaping    bool                      `json:"disable_shaping,omitempty"`   // 選配：是否關閉前 6 幀長度塑形
	Multiplex         *InboundMultiplexOptions  `json:"multiplex,omitempty"`
}

type AetherOutboundOptions struct {
	DialerOptions
	ServerOptions
	Network           NetworkList               `json:"network,omitempty"`
	Password          string                    `json:"password"`
	Cipher            string                    `json:"cipher,omitempty"`            // "auto"(預設) / "aes-256-gcm" / "chacha20-poly1305"
	ServerPublicKey   string                    `json:"public_key,omitempty"`        // 選配：對應服務端 private_key
	HeartbeatInterval badoption.Duration        `json:"heartbeat_interval,omitempty"`
	DisableShaping    bool                      `json:"disable_shaping,omitempty"`
	Multiplex         *OutboundMultiplexOptions `json:"multiplex,omitempty"`
	UDPOverTCP        *UDPOverTCPOptions        `json:"udp_over_tcp,omitempty"`
}
```

---

## 四、分階段開發與交付路線圖（工期縮減至約 4～4.5 天，分支：`dev/aether-v2`）

### Phase 0：分支上游基線對齊與 CLI 金鑰工具（0.5 天）
- [ ] **0.1 同步上游 `SagerNet/sing-box` 最新穩定版（`v1.14.4`）**：於 `dev/aether-v2` 合併上游 97 個穩定性修復提交。
- [ ] **0.2 修正建置鏈路**：補齊 `with_quic,with_acme` 編譯標籤，關閉繼承自上游會誤觸發的 `docker.yml` 發佈事件。
- [ ] **0.3 CLI 支援**：在 `cmd/sing-box/cmd_generate.go` 實作 `sing-box generate aether-key`（32B Base64 密鑰）與可選 `aether-keypair`。

### Phase 1：單層前向安全密碼學核心與雙代布隆防重放（1 天）
- [ ] **1.1 密碼學與金鑰棘輪（`protocol/aether/crypto.go`）**：
  - 實作 Base64 金鑰載入與啟動期 `Argon2id` 強化（攔截 `<16` 字元弱密碼）。
  - 實作流遮罩 `X25519` 臨時金鑰交換、`ClientSalt` + `ServerSalt` 雙鹽 `HKDF-SHA256` 衍生、硬體 AES-NI / ARMv8 自動偵測（`AES-256-GCM` vs `ChaCha20-Poly1305`），以及多用戶 `EIH` `O(1)` 索引。
- [ ] **1.2 雙代布隆防重放器（`protocol/aether/replay.go`）**：
  - 實作 256-bit `ClientSalt` 雙時間片輪轉布隆過濾器 + `ntp.TimeFuncFromContext(ctx)`，通過百萬次併發寫入零清空壓測。

### Phase 2：定長認證線框、首部 6 幀塑形與無死鎖零拷貝連線層（1.5 天）
- [ ] **2.1 線框與首部塑形（`protocol/aether/wire.go`）**：
  - 實作 96B 定長認證握手頭、18B AEAD 加密幀長度頭、原生 UDP 封包幀（`CommandUDP`），移除 `noise.go` 的 `MaskLength`。
  - 實作前 6 幀動態填充拆包與第 7 幀起零填充直通切換。
- [ ] **2.2 零拷貝 `Conn` 與 `EarlyConn`（`protocol/aether/conn.go`）**：
  - 實作 0-RTT 首包合併寫入（`DialEarlyConn`）與單次 `*buf.Buffer` 幀寫出（消除 `2-Byte` 分裂封包）。
  - 實作 `N.ExtendedConn`（`ReadBuffer` / `WriteBuffer`）、`CloseWrite()`、非阻塞 `pongCh` 解耦控制寫入、寫入錯誤原子熔斷，以及基於 `lastRead` 的空閒亂數抖動心跳與死連線斷開。

### Phase 3：Inbound / Outbound 適配與高壓模糊測試驗收（1 天）
- [ ] **3.1 `sing-box` 適配層重構（`inbound.go`、`outbound.go`、`drain.go`）**：
  - Inbound 接入握手併發信號量與隨機 `3s..10s` 靜默排空（移除 `200ms` `HandleProbe`），補齊分級安全告警日誌與 `TCPInjectableInbound`。
  - Outbound 完整實作 `OutboundWithMultiplex`、`InterfaceUpdated`、`Close`，以及 `Multiplex` / `UoT` / `CommandUDP` 全路徑 UDP 支援。
- [ ] **3.2 安全與穩定性全套驗證（`*_test.go`）**：
  - Go Fuzzing（`FuzzHandshake`、`FuzzFrameStream`）驗證畸形輸入零 Panic、零預言機洩露。
  - `go test -race` 高壓雙向小視窗滿載 + 密集心跳 + 隨機 `WriteDeadline` 壓測驗證零死鎖、零 Nonce 失步、零 FD/Goroutine 洩漏。
  - 封包擷取（PCAP）驗證：確認全流零明文特徵、零 `2-Byte` 小包、前 6 幀無固定 ClientHello 長度暴露、第 7 幀起滿速低開銷。

### Phase 4：合入主幹與啟用「每週上游 `sing-box` 正式版自動融合打包」Action（0.5 天）
- [ ] **4.1 分支切換與上線**：完成專線節點灰度驗證後，將 `dev/aether-v2` 合併回 `main`。
- [ ] **4.2 部署 `.github/workflows/upstream-sync-release.yml`**：
  - 每週定時（`cron: '0 2 * * 1'`）及支援手動觸發檢查 `SagerNet/sing-box/releases/latest` 正式版（排除 `alpha`/`beta`/`rc`）。
  - 若上游發佈新正式版，自動拉取合併、執行 `go test -race ./protocol/aether/...` 全套回歸測試，通過後編譯全功能二進位（含 `with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api`）並自動發佈新版 GitHub Release。

---

## 五、精簡後模組藍圖（File Blueprint on `dev/aether-v2`）

| 檔案路徑 | 操作 | 職責說明 |
| :--- | :---: | :--- |
| `option/aether.go` | 重構 | 極簡專線版 v2 配置結構（無冗餘 TLS/Transport 欄位，原生相容單密鑰與多用戶） |
| `protocol/aether/crypto.go` | 新增（取代 `cipher.go`） | Argon2id/Base64 金鑰載入、流遮罩 X25519 PFS 棘輪、雙鹽 HKDF、AES-GCM/ChaCha20 自動加速 |
| `protocol/aether/wire.go` | 新增（取代 `frame.go`、`noise.go`） | 96B 定長認證握手頭、18B AEAD 長度頭、前 6 幀塑形、TCP/Native-UDP 編解碼 |
| `protocol/aether/replay.go` | 重構 | 雙代滑動 256-bit `ClientSalt` 布隆過濾器 + NTP 時間源 |
| `protocol/aether/conn.go` | 重構 | 0-RTT `EarlyConn`、單次 `*buf.Buffer` 零拷貝讀寫、無死鎖 `pongCh`、雙向死連線偵測 |
| `protocol/aether/drain.go` | 新增（取代 `probe_guard.go`） | 並行握手信號量限制 + 隨機 `3s..10s` 無特徵靜默排空 |
| `protocol/aether/inbound.go` | 重構 | 多用戶路由、原生 TCP/UDP 分發、安全審計日誌 |
| `protocol/aether/outbound.go` | 重構 | 完整實作 `OutboundWithMultiplex`、`InterfaceUpdated`、`Close` 及全模式 UDP 轉發 |
| `protocol/aether/*_test.go` | 新增 | KAT 密碼學測試、`-race` 雙向死鎖壓測、Go Fuzzing 測試、封包分裂檢查測試 |
| `cmd/sing-box/cmd_generate.go` | 擴充 | 新增 `sing-box generate aether-key` / `aether-keypair` |
| `.github/workflows/upstream-sync-release.yml` | Phase 4 新增 | 每週自動檢查上游 `SagerNet/sing-box` 正式版、跑通測試並融合打包發佈 |
