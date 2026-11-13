# Aether v1 (`AetherFlow-v1`) 協議層安全性與可靠性全面審計報告

- **審計專案**：`kofttlcc/Aether-sing-box`（基於 `sing-box v1.14.2`）
- **審計範圍**：`protocol/aether/*.go`、`option/aether.go`、`constant/proxy.go`、`include/registry.go`、`.github/workflows/build-linux-amd64.yml`
- **審計日期**：2026-11-13
- **綜合結論**：**高危 / 不可繼續作為主力抗審查傳輸協議（必須啟動 Aether v2 重新設計與開發）**

---

## 一、執行摘要與「近期安全事故頻發」根因診斷

針對近期實際部署中安全與穩定性事故頻發的現象，經對 `protocol/aether` 全部源碼進行逐行密碼學、網路封包特徵、主動探測對抗與並發狀態機審計後，確認 **Aether v1 在協議設計層存在根本性缺陷**，單純依靠小幅修補（Hotfix）無法在不破壞線上升級相容性的前提下修復。

導致近期安全事故（連接埠/IP 快速被封鎖、主動探測識別、高負載斷流卡死、UDP 異常）的四大直接根因如下：

1. **白盒公開暴露（零「私有協議隱蔽性」）**：
   `kofttlcc/Aether-sing-box` 為 **GitHub 公開倉庫（Public Repository）**。審查方與自動化爬蟲可直接獲取完整的握手結構、HKDF 標籤（`"AetherFlow-v1-Session-Subkey"`）、長度混淆演算法與 `200ms` 探測防禦計時器。在完全白盒條件下，Aether v1 缺乏任何抗 DPI 與抗主動探測能力。
2. **裸 TCP 全加密高熵特徵 + 雙次 `Write` 封包長度指紋（被動 DPI 秒級識別）**：
   Aether v1 未整合 TLS 1.3 / REALITY / 偽裝層，首包直接發送 32 Bytes 均勻隨機 `salt` 與高熵密文，完全命中現代防火牆「全加密流量（Fully Encrypted Traffic）」熵值與可見字元比例過濾規則；更嚴重的是，`Conn.Write` 與 `sendControlFrame` 對每個資料幀均分兩次呼叫底層 `c.Conn.Write`（先寫 **2 Bytes 長度頭**，再寫密文負載），在 Go 預設 `TCP_NODELAY` 下於網卡層產生極度異常的 `[2B TCP 封包, NB TCP 封包]` 交替序列，以及固定週期的 `[2B, 17B]` Ping/Pong 心跳指紋。
3. **未認證 XOR 長度頭 + 無握手超時 + 固定 `200ms` 關閉計時器（100% 主動探測指紋與離線密碼爆破預言機）**：
   `NewServerConn` 未設定任何讀取超時（Read Deadline），而失敗分支 `HandleProbe` 卻硬編碼 `200ms` 後主動發送 `FIN` 關閉連線。主動探測器僅需發送任意隨機 34 Bytes 並等待 `250ms`：約 **75%** 的連線（解碼後 `chunkLen > 16400`）會在精確的 `200ms` 斷開，其餘 **25%**（`1 <= chunkLen <= 16400`）則永久掛起等待後續位元組。此行為不僅構成 **100% 零誤報的伺服器指紋**，更允許攻擊者在**無需截獲任何真實用戶流量**的情況下，透過自選 `salt` 二分探測還原 `HKDF(SHA256(password), salt)` 的 `maskKey` 位元，進而離線 GPU 暴力破解弱密碼。
4. **缺少伺服器端隨機鹽（`serverSalt`）與並發死鎖（重放導致 AEAD Nonce 重用 + 雙向流量卡死）**：
   伺服器下行密鑰完全由客戶端 `salt` 單向衍生（無 `serverSalt`），配合 `ReplayFilter` 滿 10,000 筆即清空整張雜湊表的缺陷，一旦發生重放或跨節點/重啟重放，將直接觸發 **ChaCha20-Poly1305 `(Key, Nonce)` 完全重用**，導致密文明文洩露與訊息偽造；同時 `Conn.Read` 持有 `readMu` 時同步呼叫 `sendControlFrame(FramePong)` 爭搶 `writeMu`，在雙向大流量（特別是開啟 `multiplex`）TCP 發送視窗滿載時必然觸發**永久死鎖**。

---

## 二、協議層安全漏洞清單（Security Vulnerabilities）

| 編號 | 嚴重等級 | 漏洞名稱 | 涉及檔案與行號 | 影響概述 |
| :--- | :---: | :--- | :--- | :--- |
| **S-1** | **CRITICAL** | 長度欄位僅做 XOR 遮罩且未納入 AEAD AAD，配合 `HandleProbe` 形成主動探測與離線爆破預言機 | `conn.go:178-197`<br>`cipher.go:92-115`<br>`probe_guard.go:8-24` | 100% 暴露 Aether 服務端身份；未截獲流量即可洩露 `maskKey` 供離線密碼破解；竄改長度導致幀邊界失步 |
| **S-2** | **CRITICAL** | 裸 TCP 全高熵首包 + 分離式 `2B` 長度寫入 + 固定 `17B` 心跳封包指紋 | `option/aether.go:3-19`<br>`conn.go:88-93, 142-147, 317-322` | 缺乏 TLS/REALITY 外層偽裝，且每次寫入分裂為 `2B` + `NB` 兩個 TCP 段，極易被 GFW 被動流量分析精準封鎖 |
| **S-3** | **CRITICAL** | 伺服器未生成 `serverSalt`，重放或重啟下導致 ChaCha20-Poly1305 Key/Nonce 災難性重用 | `cipher.go:52-86`<br>`conn.go:156-220` | 下行 `serverKey` 僅取決於 `PSK` 與客戶端 `salt`；一旦重放穿透（如 30s 內服務重啟或快取清空），下行金鑰流與 Poly1305 認證金鑰完全暴露 |
| **S-4** | **HIGH** | `MaskLength` 存在 `seq % 15` 模運算錯誤且上下行共用同一 `maskKey`（Two-Time Pad） | `noise.go:34-43`<br>`cipher.go:60-64` | `maskKey[15]` 永不被 `k0` 使用，週期僅 240 幀；客戶端與伺服器共用相同遮罩序列，上下行長度相異或加上 TCP 段長度即可直接還原 `maskKey` |
| **S-5** | **HIGH** | 防重放過濾器 `ReplayFilter` 滿載整表清空漏洞、僅檢驗 64-bit Nonce 且未接入 NTP | `replay.go:34-63` | 30 秒內達 10,000 筆握手時直接 `make(map)` 清空全部歷史記錄，使前 30 秒內所有被截獲握手包可瞬間重放成功 |
| **S-6** | **HIGH** | 零前向安全性（No Forward Secrecy）、單輪無鹽 `SHA-256` 弱密碼衍生、無多用戶隔離 | `cipher.go:48-50`<br>`inbound.go:36` | 靜態 PSK 無 X25519 臨時金鑰交換，密碼一旦洩露可解密所有歷史錄製流量；未限制空密碼或低熵密碼 |
| **S-7** | **HIGH** | 握手階段無 Read Deadline（Slowloris 資源耗盡 DoS）且握手失敗零日誌記錄 | `conn.go:156-198`<br>`inbound.go:80-84` | 攻擊者建立空 TCP 連線不發資料即可無限期佔用 Goroutine 與 FD；所有探測/重放/驗簽失敗均無日誌告警 |

### 關鍵安全漏洞技術細節

#### 1. `S-1` & `S-4`：長度遮罩失效與主動探測預言機（Active Probing Oracle）
在 `protocol/aether/noise.go:34-39` 中：
```go
func MaskLength(length uint16, maskKey [16]byte, seq uint64) uint16 {
	k0 := maskKey[seq%15]
	k1 := maskKey[(seq+1)%16]
	mask := uint16(k0) | (uint16(k1) << 8)
	return length ^ mask
}
```
- **演算法缺陷**：第 35 行誤寫為 `seq%15` 而非 `seq%16`，且 `CipherSession` 對上行與下行使用完全相同的 `maskKey` 與從 `0` 遞增的序號（雙重一次性密碼本誤用）。
- **預言機機制**：在 `NewServerConn`（`conn.go:178-197`）中，伺服器先讀取 32 Bytes `salt` 與 2 Bytes `lenBuf`，解罩得到 `chunkLen`：
  - 若 `chunkLen > 16400`（`MaxChunkSize + TagSize`），立即進入 `HandleProbe(rawConn)`，在 **200ms** 後關閉連線。
  - 若 `1 <= chunkLen <= 16400`，則進入無超時的 `io.ReadFull(rawConn, encryptedHeader)` **永久阻塞**。
  - 探測者對任意自選 `salt` 發送 34 Bytes 即可根據連線是否在 `200ms` 斷開判定 `(lenBuf ^ mask) > 16400` 是否成立，最多 16 次握手即可精確解出 16-bit `mask`，徹底繞過「必須先嗅探合法客戶端封包才能離線破解密碼」的前提。

#### 2. `S-2`：雙次 `Conn.Write` 造成的網路層封包分裂指紋
在 `protocol/aether/conn.go:88-93` 與 `317-322` 中：
```go
if _, err := c.Conn.Write(lenBuf[:]); err != nil {
	return written, err
}
if _, err := c.Conn.Write(encrypted); err != nil {
	return written, err
}
```
- 由於未將 `lenBuf`（2 Bytes）與 `encrypted` 合併至同一緩衝區（或 `net.Buffers` `writev`），每次傳送資料幀與心跳幀都會觸發兩次系統呼叫。在預設啟用 `TCP_NODELAY` 的 TCP Socket 上，首個 `Write` 會立即發送一個 **Payload 僅 2 Bytes 的獨立 TCP 封包**，緊接著發送密文封包。
- 此外，`Outbound.dial`（`outbound.go:87`）在建立連線時固定傳入 `initialData = nil` 立即發送握手包，上層應用（如 TLS ClientHello 或 HTTP 請求）則在幾微秒後作為第二筆幀發出，形成固定的「0 負載握手包 -> 首個應用包」時序特徵。

#### 3. `S-3` & `S-5`：缺少 `serverSalt` 與防重放清空導致的 AEAD 崩潰
- `NewCipherSession`（`cipher.go:52-64`）僅以客戶端傳來的 `salt` 執行 `hkdf.New(sha256.New, psk[:], salt[:], ...)` 同時切出 `clientKey` 與 `serverKey`。
- `ReplayFilter.CheckAndAdd`（`replay.go:56-58`）在雜湊表達到 `10000` 筆且未過期時執行：
  ```go
  if len(rf.seen) >= rf.maxSize {
      rf.seen = make(map[uint64]int64, rf.maxSize)
  }
  ```
  這相當於在併發峰值（>333 conn/s）時**主動關閉過去 30 秒的防重放保護**。此外，服務重啟（30 秒時間窗內）或多機共用密碼負載均衡時，攻擊者重放同一筆客戶端握手包，伺服器將以完全相同的 `serverKey` 與 `sendNonce = 0` 加密下行回應，徹底破壞 ChaCha20-Poly1305 的機密性與完整性。

---

## 三、協議層可靠性與工程缺陷清單（Reliability & Engineering Defects）

| 編號 | 嚴重等級 | 缺陷名稱 | 涉及檔案與行號 | 故障表現 |
| :--- | :---: | :--- | :--- | :--- |
| **R-1** | **CRITICAL** | `Read` 處理 `FramePing` 時同步鎖定 `writeMu` 寫入 `FramePong`，引發雙向 TCP 死鎖 | `conn.go:74-97, 222-261` | 多路複用（Mux）或雙向滿載傳輸時，雙方 `Read` 卡在等待 `writeMu`/TCP 傳送緩衝區，整條隧道永久僵死 |
| **R-2** | **CRITICAL** | 非原子寫入與 `WriteDeadline` 超時導致 AEAD `sendNonce` / `sendSeq` 永久失步 | `conn.go:66-68, 79-93, 308-322` | 先遞增 `sendNonce` 再執行 `Conn.Write`；一旦遇上層 `SetWriteDeadline` 超時或半包寫入失敗，後續所有封包觸發 `ErrInvalidTag` 斷線 |
| **R-3** | **CRITICAL** | 心跳機制「只發不驗」：`lastRead` 全庫從未被讀取（Dead Peer Detection 完全失效） | `conn.go:35, 42-44, 50-72` | `c.lastRead` 僅寫入從未 `Load()`，遇到 NAT 靜默丟包或半開黑洞連線時永遠不會主動斷開重連 |
| **R-4** | **HIGH** | 空 `FrameData` 回傳 `(0, nil)` 違反 `io.Reader` 規範、`default:` 分支污染資料流、0-RTT Payload 被丟棄 | `conn.go:257-287`<br>`inbound.go:80-91` | 空幀觸發上層 `io.ErrNoProgress`；無版本號的 `default:` 分支會截斷 `0x00..0x02` 開頭資料或注入未知控制幀；`header.Payload` 在服務端被直接忽略丟棄 |
| **R-5** | **HIGH** | Outbound `Multiplex` 與 `UDP` 邏輯互斥損壞，且裸 UDP `DialContext` 誤導流至 TCP | `outbound.go:62-75, 100-139`<br>`frame.go:17-24` | 開啟 `multiplex` 時 `ListenPacket` 直接報錯拒絕 UDP；開啟 `udp_over_tcp` 時靜默禁用 `multiplex`；兩者皆關時將 UDP 流量當作 TCP 發往服務端 |
| **R-6** | **HIGH** | 缺少 `sing-box` v1.14 生命週期介面（`Close`、`InterfaceUpdated`、`OutboundWithMultiplex`）及連線洩漏 | `outbound.go:26-93`<br>`conn.go:100-150` | 重載配置或切換 Wi-Fi/行動網路時洩漏整個 `multiplexDialer` 連線池與心跳 Goroutine；`PackHeader` 失敗時洩漏底層 `rawConn` |
| **R-7** | **MEDIUM** | 高頻率堆積記憶體配置（無 `sing/common/buf` 零拷貝）、零單元/模糊測試、CI 缺少 `with_quic` 且覆蓋 Release | `conn.go:246, 304, 308`<br>`.github/workflows/build-linux-amd64.yml:32-44` | 每 16KB 讀寫產生 5 次臨時 Slice 配置，高吞吐下 GC 壓力大；`protocol/aether` 測試覆蓋率為 0%；上游已更新至 `v1.14.4` |

---

## 四、評估結論：為何不能維持現狀並直接建立上游自動打包 Action？

1. **安全性不達標**：Aether v1 的線框格式（Wire Format）從第 0 個位元組起即暴露高熵隨機特徵、缺乏 TLS/REALITY 外層保護、缺少 `serverSalt` 與前向安全性，且存在無需流量的主動探測預言機。若直接建立每週自動拉取上游 `sing-box` 並融合 Aether v1 打包的流水線，只會將已知的高危協議缺陷持續部署到生產環境，無法解決「安全事故頻發」的核心問題。
2. **線框不相容演進需求**：修復上述問題必須引入 **版本協商（`Version = 0x02`）**、**外層 TLS 1.3 / REALITY 與 Fallback 偽裝整合**、**雙向隨機鹽（`clientSalt` + `serverSalt`）與 AEAD 長度頭加密（或 TLS 內層認證填充幀）**、**顯式協議指令（TCP / UDP / Mux）** 以及 **無死鎖控制幀機制**。這屬於協議層的全新迭代（**Aether v2 / `AetherFlow-v2`**）。
3. **行動決策**：
   - 保持 `main` 分支凍結不動，避免觸發線上 Release 覆蓋或影響既有舊版節點緊急相容。
   - 切換至全新獨立開發分支 **`dev/aether-v2`**，執行《Aether v2 新一代協議架構設計與開發計畫》（見同目錄 [`AETHER_V2_DEVELOPMENT_PLAN.md`](./AETHER_V2_DEVELOPMENT_PLAN.md)），並在 **Phase 5** 完成 Aether v2 驗收後正式啟用「每週自動追蹤上游 `SagerNet/sing-box` 正式版並融合打包」的 GitHub Actions 工作流。
