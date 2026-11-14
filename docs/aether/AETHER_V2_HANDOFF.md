# Aether v2 (`AetherFlow-v2`) 階段性開發交接文檔（Handoff Guide）

- **專案倉庫**：`kofttlcc/Aether-sing-box`
- **工作分支**：`dev/aether-v2`（遠端同步分支：`origin/dev/aether-v2`）
- **主分支保護狀態**：`main` 維持在 `fdaa4c455761bd6ca9d336d6dd09acb3639b34f1`（`v1.14.2-Custom-Aether`），**完全未改動**
- **上游基線版本**：已同步合併 `SagerNet/sing-box` `v1.14.4`（`c005f35300ce76427dc285481ec5695f5b179cd2`）
- **交接時間**：2026-11-14

---

## 一、當前進度總覽（Executive Summary）

本次任務已完成 **Aether v1 安全與可靠性審計**、**專線純淨版 Aether v2（剔除外層 TLS）架構設計**、**Phase 0（里程碑 M1）全套實作與五重審查簽核**，以及 **Phase 1（里程碑 M2）密碼學核心與雙代滑動布隆防重放器的完整編碼與 `-race` 測試驗證**。所有已完成代碼與單元測試均已通過 `go test -race ./cmd/sing-box/... ./protocol/aether/...` 驗證並推送至 `origin/dev/aether-v2`。

| 里程碑 | 對應開發計畫階段 | 核心交付內容 | 當前狀態 |
| :--- | :--- | :--- | :---: |
| **M1** | **Phase 0**：上游基線對齊、配置型別、CLI 金鑰工具與 CI 修正 | 合併上游 `v1.14.4`、`constant/version.go` 更新、v2 `option/aether.go`、`cmd_generate_aether.go`（`aether-key` / `aether-keypair`）、修正 `docker.yml` / `linux.yml` / `build-linux-amd64.yml` | **已完成**（通過五重獨立審查閘門） |
| **M2** | **Phase 1**：單層 PFS 密碼學核心與雙代滑動布隆防重放 | `protocol/aether/crypto.go` + `crypto_test.go`（29 組 KAT 向量、流遮罩 X25519、雙鹽 HKDF、Argon2id/Base64、EIH 多用戶、硬體 AEAD 自動選擇）及 `replay.go` + `replay_test.go`（1 MiB 雙代布隆過濾器 + NTP） | **代碼與 `-race` 測試已完成**（可直接進入審查或銜接 M3） |
| **M3** | **Phase 2**：定長認證線框、前 6 幀塑形、零拷貝 `Conn`/`EarlyConn` 與原生 UDP | 實作 `wire.go`、`conn.go`、`packet.go`（96B/112B 定長前綴、84B 回應前綴、18B AEAD 長度頭、單次 `*buf.Buffer` 寫入、前 6 幀塑形、`pongCh` 解耦、寫入錯誤原子熔斷、亂數心跳 + `lastRead` DPD、`CommandUDP`） | **待開始（下一階段首選目標）** |
| **M4** | **Phase 3**：Inbound/Outbound v2 適配、抗掃描靜默排空與 Fuzz/Race/PCAP 驗證 | 實作 `drain.go`、重構 `inbound.go` / `outbound.go`、移除 v1 舊檔（`cipher.go`, `frame.go`, `noise.go`, `probe_guard.go` 及 `replay.go` 尾部舊 shim）、新增 `fuzz_test.go` / `stress_race_test.go` / `pcap_test.go` | **待開始**（依賴 M3） |
| **M5** | **Phase 4**：每週上游 `sing-box` 正式版自動同步打包 GitHub Action | 新增 `.github/workflows/upstream-sync-release.yml`（`cron: '0 2 * * 1'` + `workflow_dispatch`，僅抓正式版、保護 `.github/workflows/`、跑 `-race` 測試後編譯發佈 Release）與 Schema 校驗 | **待開始**（依賴 M4） |
| **E2E & M6** | **端對端黑盒測試與對抗性加固驗收** | 建立 `protocol/aether/e2e/*_test.go`（`box.Box` + Wire-Tap 黑盒 Tiers 1–4 與白盒對抗 Tier 5 測試），全量 `-race` 100% 通過後完成最終交付 | **待開始**（測試矩陣已完成設計，待編寫測試碼並與 M4/M5 聯調） |

---

## 二、已完成模組與現有檔案狀態說明

### 2.1 已交付且正式生效的新模組（M1 + M2）
1. **`option/aether.go`**：
   - 已升級為專線純淨版 v2 配置結構：`AetherUser`、`AetherInboundOptions`、`AetherOutboundOptions`（無任何外層 TLS / Transport 冗餘欄位）。
   - 支援 `Password` 與 `Key` 別名互轉（`option.ResolveSecret(password, key)`，若同時填寫且不一致則報錯），`Cipher` 欄位帶 `enum:"auto,aes-256-gcm,chacha20-poly1305"` Schema 標籤，時間參數統一採用 `badoption.Duration`。
2. **`cmd/sing-box/cmd_generate_aether.go` & `cmd_generate_aether_test.go`**：
   - `sing-box generate aether-key`：輸出 32 Bytes CSPRNG 之 `base64.StdEncoding` 字串（44 字元 + `\n`）。
   - `sing-box generate aether-keypair`：輸出 X25519 靜態金鑰對（`PrivateKey: <b64>\nPublicKey: <b64>\n`）。
3. **`.github/workflows/{build-linux-amd64.yml,docker.yml,linux.yml}` & `constant/version.go`**：
   - `constant.Version` 已更新為 `"1.14.4-Custom-Aether"`。
   - `docker.yml` 與 `linux.yml` 已註解掉繼承自上游的 `release: types: [published]` 誤觸發器。
   - `build-linux-amd64.yml` 已支援 `dev/**` 分支測試建置、補齊 `with_quic,with_acme,badlinkname,tfogo_checklinkname0` 編譯標籤、加入 `go test -race ./cmd/sing-box/... ./protocol/aether/...` 閘門，且限制僅在 `refs/tags/v*` 時發佈 GitHub Release（不會覆蓋線上舊版 Release）。
4. **`protocol/aether/crypto.go` & `crypto_test.go`（M2 完整實作）**：
   - 實作全部 v2 密碼學原語、金鑰排程、X25519 臨時公鑰 ChaCha20 流遮罩、可選 0-RTT 靜態公私鑰混合、三種認證模式（單用戶 96B、多用戶帶 `iPSK` `O(1)` EIH 112B、多用戶無 `iPSK` 96B）、雙向獨立 `DirectionalCipher`（零堆積配置 `0 allocs/op`），以及 **29 組獨立參考 KAT 測試向量** 與全部 14 個 Curve25519 低階點攔截驗證。
5. **`protocol/aether/replay.go` & `replay_test.go`（M2 完整實作）**：
   - 實作 `SlidingBloomFilter`：固定 `1.00 MiB` 內嵌雙時間片位元陣列（`2 * 65536 uint64`, `k = 6` 帶實例獨立隨機 32B CSPRNG 種子防碰撞構造），每 `2 * TimeWindow`（預設 `60s`）惰性輪轉，整合 `ntp.TimeFuncFromContext(ctx)`，通過 100 萬筆單代寫入零清空、10 代輪轉與 32 協程 `-race` 壓測。

### 2.2 暫留的 v1 過渡相容檔案（將在 M3/M4 替換與刪除）
為了在 M1/M2 階段保持整個倉庫隨時可透過 `go build ./cmd/sing-box` 正常編譯，以下檔案目前仍保留 v1 程式碼或過渡 shim，**後續實作 M3 與 M4 時須按計畫替換/清理**：
- **M3 將重寫**：`protocol/aether/conn.go`，並新增 `protocol/aether/wire.go`、`protocol/aether/packet.go`。
- **M4 將重寫並清理**：
  - 重寫 `protocol/aether/inbound.go`、`protocol/aether/outbound.go`（目前含有 M1 為了適配 `v1.14.4` `Start(stage, scope)` 與新版 `option` 欄位所加的過渡適配碼），並新增 `protocol/aether/drain.go`。
  - **刪除 v1 廢棄檔案**：`protocol/aether/cipher.go`、`protocol/aether/frame.go`、`protocol/aether/noise.go`、`protocol/aether/probe_guard.go`。
  - **刪除過渡 Shim**：移除 `protocol/aether/replay.go` 第 212–251 行僅供舊版 `inbound.go` 編譯用的 `ReplayFilter` 包裝器（保留純淨 `SlidingBloomFilter`）。

---

## 三、M2 已就緒的核心 Go API 速查（供 M3 / M4 直接調用）

`protocol/aether/crypto.go` 與 `replay.go` 已將複雜密碼學狀態機封裝完畢，M3（`wire.go` / `conn.go`）與 M4（`inbound.go` / `outbound.go`）請直接調用以下 API，**切勿重複實作密碼學細節**：

### 3.1 客戶端握手與會話建立流程（Outbound / Client `Conn`）
1. **啟動期解析憑證（Outbound 初始化時執行一次，避免每次連線跑 Argon2id）**：
   - `creds, err := ParseOutboundCredentials(secret)` -> 自動支援單密鑰 `"<uPSK>"` 與多用戶 EIH `"<iPSK>:<uPSK>"`。
   - `staticPub, err := ParseX25519PublicKey(options.ServerPublicKey)`（若非空）。
   - `suite, err := SelectCipherSuite(options.Cipher)` -> 回傳 `CipherAES256GCM (0x01)` 或 `CipherChaCha20Poly1305 (0x02)`。
2. **每條連線發起握手（0-RTT 首包組裝）**：
   - 組裝 `16B` 明文 `fixedHdrPlain`（見第四節契約）。
   - `hs, prefixBytes, err := StartClientHandshake(creds, staticPub, fixedHdrPlain)` -> 產出 `96B`（無 EIH）或 `112B`（帶 EIH）定長前綴。
   - `encVarHdr := hs.SealVarHeader(dst, varHdrPlain)` -> 使用 `initAEAD` (`nonce=1`, `AAD=fixedHdrPlain[:]`) 加密變長頭（內含 `Noise || TargetAddr || InitialPayload`）。
   - 將 `prefixBytes || encVarHdr` 寫入單一 `*buf.Buffer` 一次發送！
3. **收到伺服器 `84B` 回應前綴時完成棘輪升級**：
   - `sendCipher, recvCipher, negotiatedSuite, err := hs.Complete(serverPrefix84B, expectedCipherSuite)` -> 自動解罩 `epk_s`、執行 X25519 ECDH、驗證 `EncryptedRespHeader` 並回傳雙向 `*DirectionalCipher`。

### 3.2 服務端握手與防重放驗證流程（Inbound / Server `Conn`）
1. **啟動期建立驗證器與防重放器（Inbound 初始化時執行一次）**：
   - `auth, err := NewServerAuthenticatorFromOptions(options)` -> 自動判定 `AuthModeSingleUser` / `AuthModeMultiUserEIH` / `AuthModeMultiUserTrial`，預計算 Argon2id 與 `O(1)` `UserTable`。
   - `bloom := NewSlidingBloomFilterFromContext(ctx, timeWindow)`。
2. **每條連線驗證定長前綴（徹底消除預言機）**：
   - 固定讀取 `n := auth.ClientPrefixSize()` 位元組（`96` 或 `112` Bytes）。
   - `srvHS, fixedHdrPlain, err := auth.OpenClientFixedPrefix(prefixBuf)` -> 驗證 ChaCha20-Poly1305 Tag 與可選靜態 X25519 金鑰（失敗則轉入 `StealthDrain`）。
   - 解析 `fixedHdrPlain`（檢查 `Version == 0x02`、`Command`、`CipherSuite`、`NoiseLen`、`VarHeaderLen`），接著呼叫 **`bloom.ValidateAndRecord(srvHS.ClientSalt, timestampSec)`**（**必須在 `OpenClientFixedPrefix` 驗簽成功之後才檢查與寫入布隆過濾器**，防止未認證偽造包污染位元集！）。
   - 讀取 `VarHeaderLen + 16` 位元組，呼叫 `varPlain, err := srvHS.OpenVarHeader(dst, encVarHdr)` 解出目標位址與 0-RTT `InitialPayload`。
   - 呼叫 `serverPrefix84B, sendCipher, recvCipher, err := srvHS.Complete(negotiatedSuite)` 生成 `84B` 回應前綴（與首筆下行資料合併於單一 `*buf.Buffer` 發出），並由 `srvHS.UserName` 填入 `metadata.User`。

### 3.3 資料幀雙區塊 AEAD 加解密（`DirectionalCipher`）
- **封裝單幀**：`sealed, err := sendCipher.SealFrame(dst, bodyPlain)`
  - 輸入 `bodyPlain` 為 `[FrameType(1B) | PadLen(1B) | Padding(PadLen) | Data]`（長度 `2..16641` Bytes）。
  - 輸出為連續 `[EncryptedLengthHeader(18B) || EncryptedPayloadBody(len(bodyPlain)+16B)]`，`0 allocs/op`。
- **解開單幀**：
  - 先讀 `18` Bytes 呼叫 `plainLen, err := recvCipher.OpenLengthHeader(hdr18B)`（自動校驗 `2 <= plainLen <= 16641`）。
  - 再讀 `int(plainLen) + 16` Bytes 呼叫 `bodyPlain, err := recvCipher.OpenPayloadBody(dst, encBody)`（自動遞增內部 `seq` 並在 `math.MaxUint64` 時保護性拒絕溢出）。

---

## 四、凍結位元組級線框與行為契約（Frozen Contracts `U-1`～`U-15`）

後續實作 `M3`、`M4`、`M5` 與 `E2E` 測試時，**必須嚴格遵守以下位元組級契約**：

### 4.1 握手定長頭與回應頭結構
- **`FixedHeader`（`16 Bytes` 明文，Big-Endian）**：
  - `[0]` `Version` = `0x02`
  - `[1]` `Command`：`0x01 = CommandTCP`、`0x02 = CommandUDP`、`0x03 = CommandMux`、`0x04 = CommandUoT`
  - `[2]` `CipherSuite`：`0x01 = CipherAES256GCM`、`0x02 = CipherChaCha20Poly1305`
  - `[3]` `Reserved` = `0x00`（服務端須驗證為 `0x00`）
  - `[4:12]` `TimestampSec`：`int64` Big-Endian（Unix 秒級時間戳，預設允許 `±30s`）
  - `[12:14]` `NoiseLen`：`uint16` Big-Endian，合法範圍 `32 <= NoiseLen <= 384`
  - `[14:16]` `VarHeaderLen`：`uint16` Big-Endian，合法範圍 `NoiseLen + minAddrLen <= VarHeaderLen <= 16384`
- **`VarHeader`（`VarHeaderLen` Bytes 明文）**：
  - `[0 : NoiseLen]`：CSPRNG 隨機填充位元組
  - `[NoiseLen : NoiseLen+addrLen]`：使用 `M.SocksaddrSerializer`（`sing/common/metadata`）編碼之目標位址（`CommandMux` 時可編碼空/佔位位址如 `0.0.0.0:0`）
  - `[NoiseLen+addrLen : VarHeaderLen]`：0-RTT `InitialPayload`（客戶端透過 `EarlyWriter` 首包順帶發出的應用層資料；服務端解密後必須放入連線初始讀緩衝供上層 `Read`/`ReadBuffer` 讀取，**絕不可像 v1 一樣丟棄**！）
- **`ServerResponsePrefix`（固定 `84 Bytes`）**：
  - `ServerSalt (32B) || MaskedServerEPK (32B) || EncryptedRespHeader (20B)`
  - 其中 `RespHeader` 明文 `4B` 為 `[0x02 (Version), 0x00 (StatusOK), CipherSuite, 0x00 (Reserved)]`（已由 `ServerHandshakeState.Complete` / `ClientHandshakeState.Complete` 內建處理）。
  - **合併寫出策略**：服務端在首次向客戶端寫入下行資料（或發送控制幀）時，將 `84B` 前綴與首個加密資料幀合併於同一個 `*buf.Buffer` 單次 `Write` 送出（若客戶端在收到下行資料前需要讀超時，或 `CommandUDP` 回包，均隨首幀一併發出）。

### 4.2 資料幀、首部 6 幀塑形與原生 UDP 封裝
- **幀體明文結構（`PlainFrameLen` = `2..16641` Bytes）**：
  - `[0]` `FrameType`：
    - `0x01 = FrameData`：若 `Data` 長度為 `0`（即 `PlainFrameLen == 2 + int(PadLen)`），視為純填充掩護包（Chaff Frame），讀取迴圈必須跳過繼續讀下一幀，**嚴禁對上層回傳 `(0, nil)`**！
    - `0x02 = FramePing`：強制附帶 `PadLen` $\in [32, 224]$ Bytes CSPRNG 填充，`Data` 為空。
    - `0x03 = FramePong`：強制附帶獨立隨機 `PadLen` $\in [32, 224]$ Bytes CSPRNG 填充，`Data` 為空。
    - `0x04 = FrameCloseWrite`：傳遞 TCP 半關閉（收到後對上層 `Read` 回傳 `io.EOF`，不立即關閉反向寫入通道）。
    - 其他任何位元組：立即回傳致命協議錯誤並關閉連線（**嚴禁保留 v1 的 `default:` 相容分支**）。
  - `[1]` `PadLen`：`uint8`（`0..255`）。若 `int(2 + PadLen) > len(bodyPlain)`，立即回傳格式錯誤。
  - `[2 : 2+PadLen]`：填充位元組。
  - `[2+PadLen : ]`：實際 `Data`（單幀上限 `MaxDataSize = 16384` Bytes）。
- **首部前 6 幀輕量塑形（Head-Only Shaping，`!DisableShaping`）**：
  - 維護單向計數器 `sendFrameIdx`（從 `0` 開始計算發出的 `FrameData`）：
  - 當 `sendFrameIdx < 6`：若單次寫入資料量 `> 1200` Bytes，隨機切分為 `512..1100` Bytes 的區塊（每次切分遞增 `sendFrameIdx`），且每幀附加 `16..255` Bytes 隨機填充。
  - 當 `sendFrameIdx >= 6`（或 `DisableShaping == true`）：`PadLen = 0`，單幀最大承載 `16384` Bytes（每 16KB 僅 36B 協議開銷 = `0.2197%`）。
- **原生 UDP 流式封包格式（`CommandUDP = 0x02`）**：
  - 在 `Conn` 資料流之上封裝 `PacketConn`（同時實作 `net.PacketConn` 與 `N.PacketConn`）：
  - 每個 UDP 封包編碼為：`[Socksaddr (M.SocksaddrSerializer.WriteAddrPort)] || [PayloadLen (uint16 BE, 2B)] || [Payload (PayloadLen Bytes)]`。
  - **Outbound 三模式 UDP 路由優先序**：
    1. 若啟用 `Multiplex`（`out.multiplexDialer != nil`）：`DialContext` 與 `ListenPacket` 統一委派給 `out.multiplexDialer`（由 `sing-mux` 在 `CommandMux` 隧道內複用 TCP 與 UDP！）。
    2. 否則若啟用 `UDPOverTCP`（`out.uotClient != nil`）：UDP 委派給 `out.uotClient`（底層透過 `CommandUoT` 建立連接）。
    3. 否則（預設原生模式）：UDP 直接透過 `CommandUDP (0x02)` 建立 Aether 封包流並回傳 `aetherPacketConn`！徹底根治 v1 中 UDP 報錯或誤導流至裸 TCP 的缺陷。

### 4.3 無死鎖控制平面、心跳 DPD 與抗掃描靜默排空契約
1. **非阻塞 `pongCh` 解耦（根治 `R-1`）**：
   - `Conn` 內設 `pongCh chan struct{}`（容量 `1`）。`Read` / `ReadBuffer` 收到 `FramePing` 時僅執行 `select { case c.pongCh <- struct{}{}: default: }` 後立即進入下一輪讀取，**絕不在 `readMu` 內獲取 `writeMu`**；背景協程監聽 `pongCh` 非同步獲取 `writeMu` 發送 `FramePong`。
2. **寫入錯誤原子熔斷與 Deadline 隔離（根治 `R-2`）**：
   - 背景 `FramePing` / `FramePong` 發送前不得受上層過期的 `SetWriteDeadline` 干擾（或透過內部寫入封裝管理超時），且一旦底層 `rawConn.Write` 發生任何錯誤或短寫（Short Write），**必須立即原子標記 `writeBroken = true` 並呼叫 `rawConn.Close()`**，保證絕不會在後續幀發生 AEAD Nonce 失步。
3. **空閒亂數抖動心跳與 `lastRead` 死連線偵測（根治 `R-3`）**：
   - 預設 `HeartbeatInterval = 30s`（若配置 `< 0` 則停用心跳）。
   - 當距離上次讀寫活動超過 `HeartbeatInterval * uniform(0.75, 1.25)` 時發送隨機填充 `FramePing`。
   - **Pong 超時計算公式**：當 `HeartbeatInterval >= 20s` 時，`PongTimeout = HeartbeatInterval / 2`（例如 30s 心跳對應 15s 超時）；當測試配置較短間隔（`< 20s`）時，`PongTimeout = max(HeartbeatInterval/2, 500*time.Millisecond)`（方便單元/E2E 測試在毫秒級快速驗證死連線斷開，無需苦等 10 秒）。若發送 Ping 後經過 `PongTimeout` 且 `lastRead.Load()` 仍未推進，主動 `Close()` 底層連線。
4. **`StealthDrain` 抗掃描靜默排空（根治 `S-1` / `S-7`）**：
   - Inbound 設置 `handshakeSem`（容量 `256`）與獨立 `drainSem`（容量 `512`），握手總超時預設 `HandshakeTimeout = 6s`。
   - 當握手驗簽、時間戳或防重放失敗時：**嚴禁呼叫 `N.CloseOnHandshakeFailure`（因其內部會呼叫 `SetLinger(0)` 發送異常 `TCP RST` 指紋）**，亦嚴禁使用固定 `200ms`！
   - 若成功取得 `drainSem` 令牌，設定獨立均勻隨機 `3s..10s` 讀取截止時間（`SetReadDeadline`），將後續位元組讀入丟棄緩衝區直到對端關閉或超時，最後直接呼叫 `conn.Close()` 發送正常 `TCP FIN`，再呼叫 `if onClose != nil { onClose(err) }`；同時以按來源 IP 限流的日誌器記錄告警（區分 `auth_failed`、`replay`、`clock_skew`、`timeout`、`malformed`）。
5. **`sing-box v1.14.4` 介面與記憶體池所有權契約**：
   - 生命週期簽章必須為 `Start(stage adapter.StartStage, scope *adapter.Scope) error`。
   - Outbound 實作 `adapter.OutboundWithMultiplex`、`adapter.InterfaceUpdateListener`（`InterfaceUpdated` 重置 `multiplexDialer`）、`adapter.IdleConnectionKeeper` 與 `Close()`。
   - `WriteBuffer(buffer *buf.Buffer)` 與 `WritePacket(buffer *buf.Buffer, destination M.Socksaddr)` **必須在所有返回路徑 `defer buffer.Release()`**；`ReadBuffer(buffer *buf.Buffer)` **絕不可釋放傳入的 `buffer`**；`ReaderReplaceable()` / `WriterReplaceable()` 均維持 `false`。

---

## 五、環境注意事項與快速恢復指南（How to Resume）

### 5.1 編譯與測試命令
若在受限雲端沙盒環境（`proxy.golang.org` 返回 403 時），執行 Go 命令請帶上 `GOPROXY=direct GOSUMDB=off`：

```bash
# 1. 執行現有 M1 + M2 全量單元與競態測試（目前 100% 通過）
GOPROXY=direct GOSUMDB=off go test -v -race ./cmd/sing-box/... ./protocol/aether/...

# 2. 完整生產級二進位編譯驗證（含全部 sing-box v1.14.4 特性標籤）
GOPROXY=direct GOSUMDB=off CGO_ENABLED=0 go build -trimpath \
  -tags "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,badlinkname,tfogo_checklinkname0" \
  -ldflags "-X 'github.com/sagernet/sing-box/constant.Version=1.14.4-Custom-Aether' $(cat release/LDFLAGS) -s -w -buildid=" \
  -o /tmp/sing-box-bin ./cmd/sing-box
```

### 5.2 第 5 階段（M5）每週上游同步 GitHub Action 實作要點提醒
在實作 `.github/workflows/upstream-sync-release.yml` 時，請務必注意以下三點細節（已在前期 CI 調研中確認）：
1. **保護自訂 Workflows**：合併上游 `SagerNet/sing-box` 新正式版 Tag 時，上游若修改 `.github/workflows/` 可能覆蓋或重啟 `docker.yml` / `linux.yml` 的觸發器，合併腳本需保留本庫的 `.github/workflows/` 設定或自動校驗 `release:` 觸發器保持停用。
2. **單 Job 內完成發佈**：GitHub Actions 使用預設 `GITHUB_TOKEN` 推送新 Tag 時不會觸發另一個獨立 Workflow，因此「拉取上游正式版 -> 融合 Aether v2 -> 執行 `go test -race ./protocol/aether/...` -> 編譯二進位與 SHA256 -> 建立 Tag 並發佈 GitHub Release」應在 `upstream-sync-release.yml` 同一條工作流內閉環完成；若合併衝突或測試失敗則自動建立 Issue / PR 告警並中止發佈。
3. **分支策略**：在用戶明確指示將 `dev/aether-v2` 合入 `main` 前，所有開發提交均保持在 `dev/aether-v2` 分支。

### 5.3 下次恢復開發的建議指令
下次繼續任務時，可直接發送以下提示詞（單代理直接實作或使用 `/goal`、`/teamwork` 皆可）：

> 請讀取 `dev/aether-v2` 分支上的 `docs/aether/AETHER_V2_HANDOFF.md` 與 `docs/aether/AETHER_V2_DEVELOPMENT_PLAN.md`，從 **里程碑 M3（Phase 2：`wire.go`、`conn.go`、`packet.go`）** 接著往下實施，依序完成 M3、M4（`drain.go`、`inbound.go`、`outbound.go`、清理 v1 舊檔及 Fuzz/Race/PCAP 測試）、M5（`upstream-sync-release.yml`）與 E2E 端對端測試驗收，全程保持在 `dev/aether-v2` 分支。
