* **Tên đề tài:** Phân tích Dòng vốn và Cảnh báo Sự cố quanh Các Sự kiện An ninh DeFi (*Flow Analysis and Incident Alerting Around DeFi Security Events*)

* **Mục tiêu cốt lõi:** Hoàn thiện một đồ án Thạc sĩ có tính thuyết phục cao thông qua việc bàn giao:
1. Bộ dữ liệu sự cố DeFi đã xác minh và có khả năng tái lập.
2. Phương pháp tái dựng dòng vốn dựa trên phân loại luồng chuyển dịch (*flow-leg based reconstruction*).
3. Bộ dữ liệu chuỗi thời gian theo giờ đã đóng băng (*frozen hourly research dataset*).
4. Khung hồi cứu cảnh báo sự cố không rò rỉ dữ liệu tương lai (*no-look-ahead incident alert replay framework*).
5. Hệ thống bằng chứng khoa học, biểu đồ trực quan, báo cáo luận văn và slide bảo vệ hoàn chỉnh.

---

## 1. Diễn giải hiện trạng & Các giả định lập kế hoạch

* **Sự thật kỹ thuật đã xác nhận:**
* Hạ tầng thu thập dữ liệu on-chain (AWS Public Blockchain, Etherscan ABI, CLI orchestration) đã hoàn thiện và kiểm thử *smoke run* thành công trên Euler Finance và KyberSwap Elastic.

* CoinGecko API đang tắt do lỗi xác thực HTTP 401; Curve Finance chưa hoàn thiện xác minh các pool bị ảnh hưởng.

* Bản nộp trước gặp các lỗi: sử dụng `EVT_002`, `EVT_008` làm ví dụ nhưng tệp CSV rỗng; `EVT_004` có `attacker_outflow = 0`; gộp chung mọi địa chỉ ngoài attacker thành người dùng; thay giá thiếu và giờ trống bằng số `0`.


* **Giả định lập kế hoạch:**
* Đơn vị Token gốc (`WETH`, `USDC`, `DAI`, `WBTC`...) được dùng làm thước đo chuẩn; giá trị USD chỉ quy đổi khi có giá neo trước sự cố $P(T_0^-)$ hoặc chuỗi giá đã kiểm tra độ phủ, tuyệt đối không gán `price = 0`[cite: 2, 4].
* Nghiên cứu dừng ở mức phân tích mô tả phân pha, kiểm định phi tham số và mô phỏng cảnh báo nhân quả ($\le t$), không đưa ra tuyên bố nhân quả kinh tế lượng (BSTS/VAR/Granger)[cite: 4, 6].
---

## 2. Câu hỏi nghiên cứu, Giả thuyết & Chỉ số đo lường

* **RQ1:** Việc phân loại theo từng luồng chuyển dịch (*flow-leg classification*) làm thay đổi ước lượng tổn thất thanh khoản quanh các sự cố an ninh DeFi như thế nào?
* *Giả thuyết:* Nếu không tách giao dịch `swap/MEV` và chuyển khoản nội bộ, dòng rút vốn ròng của người dùng sẽ bị ước lượng sai lệch đáng kể.
* *Bằng chứng & Chỉ số:* Ước lượng dòng vốn thô (*Naive flow estimation*), ước lượng dòng vốn sau phân loại (*Classified flow estimation*) và tỷ lệ phân loại sai (*Misclassification ratio*).

* **RQ2:** Dòng vốn rút ròng của người dùng khác biệt như thế nào giữa giai đoạn nền (*baseline*) và 24 giờ đầu tiên sau sự cố an ninh?
* *Giả thuyết:* Cường độ rút vốn ròng theo giờ của người dùng trong 24h đầu sau exploit tăng đột biến có ý nghĩa thống kê so với giai đoạn nền 7 ngày trước sự cố.
* *Bằng chứng & Chỉ số:* `User Net Outflow`, kiểm định phi tham số **Mann-Whitney U**, hệ số tác động **Cliff's Delta**, so sánh Trung vị (*Median*) và Khoảng tứ phân vị (*IQR*).


* **RQ3:** Một quy tắc phát hiện sự cố không rò rỉ tương lai (*no-look-ahead*) sẽ kích hoạt tại thời điểm nào so với thời điểm xảy ra exploit và thời điểm phát hành các cảnh báo công khai đã xác minh?
* *Giả thuyết:* Kết hợp ngưỡng đột biến dòng rút ròng với tín hiệu sụt giảm dự trữ pool lõi cho phép phát hiện sự cố với độ trễ thấp hơn hoặc tương đương cảnh báo công khai gốc.
* *Bằng chứng & Chỉ số:* Độ trễ phát hiện so với block exploit (*Detection delay*), độ trễ so với cảnh báo công khai (*Alert lag*), tỷ lệ cảnh báo giả trên cửa sổ nền (*False alert rate*) và phân tích độ nhạy ngưỡng (*Sensitivity analysis*).
---

## 3. Quyết định Phạm vi, Tính khả thi & Phân bổ nguồn lực

### 3.1. Phạm vi đưa vào nghiên cứu (Included)

* **Case chính (Bắt buộc — Mandatory):**
* **Sự kiện:** Euler Finance (`13/03/2023`).


* **Mạng lưới:** Ethereum Mainnet.


* **Cửa sổ dữ liệu:** `T-7 ngày` $\rightarrow$ `T+3 ngày` (240 giờ)[cite: 4, 6].


* **Case phụ (Kiểm chứng có điều kiện — Conditional Validation):**
* **Sự kiện:** KyberSwap Elastic (`22/11/2023`).


* **Mạng lưới:** Chỉ phạm vi Ethereum (*Ethereum only*).


* **Điều kiện kích hoạt:** Chỉ đưa vào phân tích nếu vượt qua Cổng Sẵn sàng Dữ liệu (*Data Readiness Gate*) trước khi kết thúc Ngày 2.

### 3.2. Hạng mục loại bỏ khỏi phạm vi (Excluded)

* **Các sự kiện loại bỏ:** Curve Finance, `EVT_002`, `EVT_004`, `EVT_008`


* **Các phương pháp & mô hình cắt bỏ:** BSTS, VAR, Granger Causality, Isolation Forest, các phần mở rộng Machine Learning, Deep Learning và Sentiment Models.
---

## 4. Cấu trúc nhóm & Tổng quan chuỗi Epic
### Bảng tổng quan các Epic

| Mã Epic | Tên Epic | Mức ưu tiên | Người phụ trách chính |
| --- | --- | --- | --- |
| **E0** | Đóng băng Phạm vi & Danh mục Bằng chứng (*Scope Freeze & Evidence Registry*) | **P0** | TV1 |
| **E1** | Sẵn sàng Dữ liệu Euler (*Euler Data Readiness*) | **P0** | TV2 |
| **E2** | Giải mã & Phân loại Luồng vốn (*Flow-Leg Decoding & Classification*) | **P0** | TV2 (TV1 hỗ trợ audit) |
| **E3** | Đóng băng Bộ dữ liệu theo giờ (*Hourly Dataset Freeze*) | **P0** | TV2 & TV3 |
| **E4** | Phân tích Mô tả & Kiểm định Thống kê (*Descriptive & Statistical Analysis*) | **P0** | TV3 |
| **E5** | Hồi cứu Cảnh báo Không rò rỉ Tương lai (*No-Look-Ahead Alert Replay*) | **P0** | TV1 |
| **E6** | Kiểm chứng Có điều kiện trên Kyber (*Kyber Conditional Validation*) | **P1** | TV2 & TV3 |
| **E7** | Gói Hồ sơ Nộp bài Cuối cùng (*Final Submission Package*) | **P0** | Cả nhóm (`TV1, TV2, TV3`)[cite: 4, 6] |

---

## 5. Đặc tả Chi tiết Từng Epic (E0 – E7)

### EPIC E0: Đóng băng Phạm vi & Danh mục Bằng chứng (*Scope Freeze & Evidence Registry*)

* **Mục tiêu:** Đóng băng phạm vi nghiên cứu, các điểm neo sự cố (*incident anchors*) và mốc đối chiếu cảnh báo công khai (*alert benchmarks*).


* **Người phụ trách:** TV1.


* **Các tác vụ chi tiết:**
* **E0.1 Xác minh Điểm neo Exploit (*Verify Exploit Anchors*):** Thu thập và đối chiếu `exploit_tx_hash`, `exploit_block`, `exploit_timestamp_utc` và `evidence_url` cho Euler (và Kyber).


* **E0.2 Xác minh Mốc Cảnh báo Công khai (*Verify Alert Benchmarks*):** Thu thập `source account` (ví dụ: PeckShield, BlockSec, tài khoản chính thức giao thức), `platform`, `timestamp`, `URL` và phân loại theo 4 nhóm: `initial_suspicion` (nghi vấn ban đầu), `confirmed_exploit` (xác nhận tấn công), `protocol_acknowledgement` (giao thức thừa nhận), `postmortem` (báo cáo hậu kiểm).


* **E0.3 Nhật ký Loại trừ Sự kiện (*Event Exclusion Log*):** Ghi nhận bằng chứng lý do loại bỏ `EVT_002`, `EVT_004`, `EVT_008` và `Curve`.

* **Đầu ra:** `events_master_verified.csv`, `event_exclusion_log.md`, `research_scope_v1.md`.


* **Tiêu chí nghiệm thu:** Điểm neo Euler được xác minh; các mốc thời gian UTC chính xác; mốc đối chiếu cảnh báo công khai được lập hồ sơ; phạm vi nghiên cứu được đóng băng.
---

### EPIC E1: Sẵn sàng Dữ liệu Euler (*Euler Data Readiness*)

* **Mục tiêu:** Tạo lập bộ dữ liệu thô hoàn chỉnh và đáng tin cậy cho sự kiện Euler Finance trong cửa sổ `T-7 ngày -> T+3 ngày`.


* **Người phụ trách:** TV2.


* **Các tác vụ chi tiết:**
* **E1.1 Thu thập Dữ liệu Đầy đủ (*Full Collection*):** Cập nhật `configs/events.yaml` theo cửa sổ 240 giờ và chạy lệnh thu thập toàn bộ giai đoạn[cite: 4, 6]:
```bash
python -m defi_lsa collect \
  --event euler \
  --stage all \
  --source auto \
  --resume

```


* **E1.2 Kiểm toán Dữ liệu Thô & Độ phủ Giá (*Raw Audit & Price Anchor Check*):** Chạy kiểm toán `D2` xác nhận `missing_blocks = 0`, `missing_exploit_receipts = 0`; trích xuất giá neo tham chiếu trước sự cố $P(T_0^-)$ và kiểm tra độ phủ dữ liệu[cite: 1, 2, 4].


* **Đầu ra:** `data/raw/euler/*`, `reports/d2_audit_euler.md`, `data/processed/euler_price_anchor.parquet`.
* **Tiêu chí nghiệm thu:** Báo cáo kiểm toán D2 đạt `GO` hoặc `CONDITIONAL_GO` được phê duyệt (chấp nhận tắt CoinGecko nếu dùng đơn vị Token gốc + giá neo $P(T_0^-)$).



---

### EPIC E2: Giải mã & Phân loại Luồng vốn (*Flow-Leg Decoding & Classification*)

* **Mục tiêu:** Chuyển đổi log sự kiện thô thành các luồng dịch chuyển vốn được phân nhãn chính xác, khắc phục lỗi gộp chung giao dịch người dùng với swap/MEV và giao dịch nội bộ[cite: 1, 4].
* **Người phụ trách:** TV2 (TV1 hỗ trợ đối soát thủ công).


* **Các tác vụ chi tiết:**
* **E2.1 Giải mã Sự kiện Lõi (*Core Event Decoding*):** Giải mã các sự kiện `Transfer`, `Deposit`, `Withdraw`, `Swap`, `Borrow`, `Repay` trên các hợp đồng cốt lõi dựa vào bộ ABI đã lưu cache ở `E5`.


* **E2.2 Phân loại 5 Luồng vốn Loại trừ Lẫn nhau (*5-Label Flow-Leg Classification*):** Gán mỗi luồng chuyển dịch qua core contract vào đúng 1 trong 5 nhãn:
1. `attacker_drain` (tài sản bị kẻ tấn công rút ra khỏi pool/vault).
2. `recovery_flow` (tài sản được hoàn trả về kho bạc/hợp đồng bồi hoàn).
3. `user_net_flow` (`user_deposit` & `user_withdrawal` gọi trực tiếp hàm nạp/rút thanh khoản chuẩn của người dùng).
4. `swap_mev` (hoán đổi qua router/aggregator hoặc bot arbitrage trong cùng giao dịch).
5. `internal_transfer` (luân chuyển nội bộ giữa proxy, implementation, sub-account hoặc flash-loan hoàn trả trong cùng tx).




* **E2.3 Đối soát Thủ công Top 20 Giao dịch (*Manual Etherscan Audit*):** Kiểm tra thủ công 100% giao dịch exploit và Top 20 giao dịch có khối lượng lớn nhất trên Etherscan để tinh chỉnh quy tắc phân loại.




* **Đầu ra:** `data/decoded/euler_flow_legs.parquet`, `docs/manual_tx_audit.md`, `reports/d3_gate_report.json`[cite: 4, 5].
* **Tiêu chí nghiệm thu:** `decoded_token_volume_pct >= 95%`, `unknown_flow_share <= 5%`, độ chính xác phân loại trên tập kiểm tra thủ công Top 20 giao dịch đạt $\ge 95\%$[cite: 4, 5].

---

### EPIC E3: Đóng băng Bộ dữ liệu theo giờ (*Hourly Dataset Freeze*)

* **Mục tiêu:** Tổng hợp chuỗi thời gian theo giờ sạch, phân biệt rõ dữ liệu thiếu (`NaN`) với không có giao dịch (`0`), và đóng băng phiên bản dữ liệu nghiên cứu.


* **Người phụ trách:** TV2 (xây dựng pipeline) & TV3 (viết kiểm thử chất lượng).


* **Các tác vụ chi tiết:**
* **E3.1 Tái dựng Chuỗi Dòng vốn & Dự trữ theo giờ (*Hourly Panel Construction*):** Tổng hợp 240 bản ghi theo giờ (`T-7d -> T+3d`) cho từng token lõi (`WETH`, `USDC`, `DAI`, `WBTC`, `wstETH`) và quy đổi USD theo giá neo $P(T_0^-)$[cite: 2, 4].
* **E3.2 Thực thi Quy tắc Dữ liệu Khuyết (*Null-Semantics Enforcement*):** Chỉ gán `0` khi giờ $h$ đạt `missing_blocks = 0` và `missing_receipts = 0` nhưng không phát sinh giao dịch; gán `NaN` kèm cờ `data_status = MISSING_CHAIN_DATA` nếu thiếu block; tuyệt đối cấm gán `price = 0`.


* **E3.3 Kiểm thử Tự động & Đóng băng (*Unit Testing & SHA-256 Freeze*):** Chạy kiểm thử kiểm tra tính toàn vẹn `NaN vs 0`, xuất tệp Parquet/CSV đóng băng và ghi mã băm SHA-256.




* **Đầu ra:** `data/frozen/dataset_euler_v1.parquet` (kèm bản `.csv`), `data/frozen/dataset_manifest.json`, `docs/data_dictionary.md`[cite: 1, 4].
* **Tiêu chí nghiệm thu:** Đủ 240 giờ liên tục, vượt qua 100% unit test `NaN vs 0`, có mã băm SHA-256 trong manifest.



---

### EPIC E4: Phân tích Mô tả & Kiểm định Thống kê (*Descriptive & Statistical Analysis*)

* **Mục tiêu:** Trả lời trực diện `RQ1` và `RQ2` bằng bảng phân rã dòng vốn, biểu đồ phân pha định tính và kiểm định thống kê phi tham số[cite: 4, 6].
* **Người phụ trách:** TV3.


* **Các tác vụ chi tiết:**
* **E4.1 Phân rã Tổn thất Thanh khoản (`RQ1`):** So sánh ước lượng dòng rút vốn người dùng trước phân loại (*Naive*) và sau phân loại 5 luồng (*Classified*), tính tỷ lệ sai lệch (*Misclassification ratio*).


* **E4.2 Phân tích Phân pha & Kiểm định Thống kê (`RQ2`):** Tính tốc độ rút vốn ròng theo giờ, đường cong tích lũy, Trung vị (*Median*) và *IQR* qua các pha (`Baseline T-168h..T0`, `0–2h`, `2–24h`, `24–72h`); chạy kiểm định **Mann-Whitney U** và tính hệ số **Cliff's Delta**[cite: 4, 6].
* **E4.3 Xuất Biểu đồ Chuẩn Luận văn (*Thesis Figures Generation*):** Vẽ bộ biểu đồ dòng vốn 4 pha, so sánh trước/sau phân loại và diễn biến dự trữ pool theo thời gian[cite: 2, 4].


* **Đầu ra:** `reports/statistical_results_euler.csv`, `reports/figures/euler_*.png`.


* **Tiêu chí nghiệm thu:** Toàn bộ bảng số liệu và biểu đồ được sinh tự động từ `dataset_euler_v1.parquet` đóng băng[cite: 2, 4].

---

### EPIC E5: Hồi cứu Cảnh báo Không rò rỉ Tương lai (*No-Look-Ahead Alert Replay*)

* **Mục tiêu:** Trả lời `RQ3` thông qua mô phỏng hồi cứu bộ quy tắc cảnh báo sự cố tức thời chỉ dùng dữ liệu quá khứ ($\le t$) và xuất khuyến nghị hành động[cite: 4, 6].
* **Người phụ trách:** TV1.


* **Các tác vụ chi tiết:**
* **E5.1 Thiết kế Bộ quy tắc Cảnh báo Nhân quả (*Causal Alert Engine*):** Tại mỗi giờ $t$, chỉ đọc dữ liệu cửa sổ $[t-72\text{h}, t]$: kích hoạt cảnh báo khi dự trữ pool lõi giảm $>10\%$ trong 1 giờ **HOẶC** xuất hiện luồng rút không đốt LP vượt ngưỡng $P_{99}$ của 72h nền, đồng thời dòng rút ròng vượt quá $\text{Median} + 5 \times \text{MAD}$.


* **E5.2 Đánh giá Độ trễ & Độ nhạy (*Delay, Alert Lag & Sensitivity Replay*):** Chạy hồi cứu trên toàn bộ 240 giờ; tính `Detection delay` (so với block exploit), `Alert lag` (so với mốc cảnh báo công khai trong `events_master_verified.csv`), `False alert rate` trên 168 giờ nền và kiểm tra độ nhạy khi thay đổi ngưỡng[cite: 4, 6].
* **E5.3 Định dạng Bản tin Khuyến nghị Hành động (*Actionable Alert Payload*):** Xuất cấu trúc cảnh báo gồm: mức độ nghiêm trọng, chẩn đoán tỷ trọng `attacker_drain` vs. `user_withdrawal` và hành động khuyến nghị cho Quản trị giao thức (*Pause/Circuit Breaker*) và Người dùng (*Withdraw/Revoke Approval*).




* **Đầu ra:** `src/alerting/alert_engine.py`, `reports/alert_replay_results.json`.


* **Tiêu chí nghiệm thu:** Xác nhận 0 rò rỉ dữ liệu tương lai ($> t$), tính chính xác `Alert Lag` dựa trên mốc cảnh báo công khai đã xác minh[cite: 4, 6].

---

### EPIC E6: Kiểm chứng Có điều kiện trên Kyber (*Kyber Conditional Validation*)

* **Mục tiêu:** Thực hiện quy trình kiểm chứng chéo trên sự kiện thứ hai (**KyberSwap Elastic**, phạm vi Ethereum-only) để củng cố tính tổng quát của phương pháp.


* **Người phụ trách:** TV2 (thu thập & đóng băng) & TV3 (phân tích & biểu đồ).


* **Điều kiện kích hoạt:** Chỉ thực hiện khi `E1` (Euler) đã hoàn tất và cổng dữ liệu Kyber (`missing_blocks = 0` trong 240h) vượt qua trước cuối Ngày 2.


* **Các tác vụ chi tiết:**
* **E6.1 Thu thập & Giải mã Kyber (`T-7d -> T+3d`):** Chạy pipeline thu thập ưu tiên nguồn AWS Public Blockchain Parquet, áp dụng phân loại 5 luồng và kiểm tra thủ công Top 20 giao dịch trên Etherscan[cite: 3, 4].
* **E6.2 Đóng băng, Phân tích & Hồi cứu Cảnh báo:** Đóng băng `dataset_kyber_v1.parquet`, chạy kiểm định Mann-Whitney U, vẽ biểu đồ đối chiếu Euler vs. Kyber và chạy hồi cứu bộ quy tắc cảnh báo `E5`.




* **Đầu ra:** `data/frozen/dataset_kyber_v1.parquet`, `reports/figures/kyber_*.png`, bảng so sánh chéo 2 sự kiện.


* **Tiêu chí nghiệm thu:** Đạt cùng chuẩn chất lượng với Euler (`unknown_flow_share <= 5%`, `NaN vs 0` chuẩn xác) hoặc ghi nhận rõ trạng thái dừng có điều kiện nếu thiếu dữ liệu[cite: 2, 4].

---

### EPIC E7: Gói Hồ sơ Nộp bài Cuối cùng (*Final Submission Package*)

* **Mục tiêu:** Tổng hợp báo cáo đồ án, slide thuyết trình và notebook demo tái lập hoàn toàn kết quả, đảm bảo khớp 100% với tệp dữ liệu nộp kèm[cite: 4, 6].
* **Người phụ trách:** Cả nhóm (`TV1, TV2, TV3`).


* **Các tác vụ chi tiết:**
* **E7.1 Xây dựng Notebook Demo Tái lập (`TV3`):** Tạo `notebooks/demo_case_analysis.ipynb` đọc trực tiếp từ `data/frozen/` để tái tạo toàn bộ bảng thống kê, biểu đồ và mô phỏng phát cảnh báo trong dưới 2 phút.


* **E7.2 Hoàn thiện Báo cáo Đồ án (`TV1, TV2, TV3`):** Viết đầy đủ các chương: Đặt vấn đề & Phạm vi, Phương pháp phân loại 5 luồng & Xử lý dữ liệu khuyết, Kết quả phân tích định tính/định lượng (`RQ1–RQ2`), Đánh giá mô-đun cảnh báo (`RQ3`), và Giới hạn nghiên cứu[cite: 4, 6].
* **E7.3 Thiết kế Slide Bảo vệ & Đối soát Chéo (`TV1` chủ trì):** Làm 12–15 slide trả lời trực diện 8 góp ý của Giảng viên; đối soát chéo 1-1 mọi con số giữa Báo cáo – Slide – CSV nộp kèm.




* **Đầu ra:** `notebooks/demo_case_analysis.ipynb`, `docs/final_report.pdf`, `docs/defense_slides.pdf`, gói dữ liệu đóng băng.


* **Tiêu chí nghiệm thu:** 100% số liệu đồng nhất giữa các tệp, không còn mã sự kiện rỗng/lỗi, notebook chạy thông suốt không lỗi.



---

## 6. Cổng Quyết định Chất lượng (Go/No-Go Decision Gates)

1. **Cổng G1 — Sẵn sàng Dữ liệu & Mốc đối chiếu (*Data & Benchmark Readiness Gate* | Cuối Ngày 2):**
* `E0` và `E1` hoàn tất (`missing_blocks = 0` cho Euler); `events_master_verified.csv` và `event_exclusion_log.md` hoàn chỉnh[cite: 4, 6].
* *Quyết định phạm vi:* Kiểm tra trạng thái dữ liệu Kyber (`E6`). Nếu Kyber đạt `missing_blocks = 0`, kích hoạt `E6`; nếu chưa đạt, khóa phạm vi ở 1 case chuyên sâu Euler Finance.




2. **Cổng G2 — Chất lượng Phân loại & Đóng băng Dữ liệu (*Classification & Freeze Gate* | Cuối Ngày 4):**
* Hoàn thành `E2` và `E3`; `unknown_flow_share <= 5%`; hoàn tất audit thủ công Top 20 giao dịch; vượt qua unit test `NaN vs 0`; xuất tệp Parquet/CSV kèm mã băm SHA-256.




3. **Cổng G3 — Đủ Bằng chứng Khoa học & Cảnh báo (*Evidence & Alert Sufficiency Gate* | Cuối Ngày 5):**
* Hoàn tất `E4` và `E5`; có đủ bảng kiểm định Mann-Whitney U, biểu đồ 4 pha và kết quả hồi cứu cảnh báo không rò rỉ dữ liệu tương lai[cite: 4, 6].


4. **Cổng G4 — Sẵn sàng Nộp bài & Bảo vệ (*Submission Readiness Gate* | Chiều Ngày 7):**
* Hoàn tất `E7`; đối soát chéo 100% số liệu giữa Báo cáo, Slide và CSV; chạy thử thuyết trình + demo đạt chuẩn.





---

## 7. Lịch trình Triển khai Chi tiết 7 Ngày

| Ngày | Ca làm việc | Epic triển khai | Đầu việc trọng tâm & Người phụ trách | Mốc kiểm soát |
| --- | --- | --- | --- | --- |
| **Ngày 1 (T2)** | Tối (19:30–21:30) | **E0 + E1** | `TV1`: Xác minh anchor Euler & cảnh báo gốc (`E0.1–E0.3`).<br>

<br>`TV2`: Chạy full collection Euler 240h (`E1.1`).<br>

<br>`TV3`: Trích xuất giá neo $P(T_0^-)$ (`E1.2`). | D2 Audit Euler đạt chuẩn. |
| **Ngày 2 (T3)** | Tối (19:30–21:30) | **E1 + E6 (bước 1)** | `TV2`: Tải dữ liệu thô 240h KyberSwap Elastic.<br>

<br>`TV1`: Chốt `events_master_verified.csv` & `event_exclusion_log.md`.<br>

<br>`TV3`: Kiểm tra độ phủ block & giá của cả 2 case. | **Chốt Cổng G1** (Quyết định kích hoạt `E6`). |
| **Ngày 3 (T4)** | Tối (19:30–21:30) | **E2** | `TV2`: Triển khai giải mã & phân loại 5 luồng vốn (`E2.1–E2.2`).<br>

<br>`TV1 + TV2`: Audit thủ công 100% exploit tx + Top 20 tx Euler trên Etherscan (`E2.3`). | Hoàn tất phân loại Euler. |
| **Ngày 4 (T5)** | Tối (19:30–21:30) | **E2 + E3 + E6** | `TV2`: Audit Top 20 tx Kyber (nếu mở `E6`); sửa `D4` cấm điền `0` sai bản chất; đóng băng dataset v1 (`E3.1–E3.3`).<br>

<br>`TV3`: Viết unit test `NaN vs 0`. | **Chốt Cổng G2** (Dataset v1 đóng băng). |
| **Ngày 5 (T6)** | Tối (19:30–22:00) | **E4 + E5 + E6** | `TV3`: Chạy thống kê mô tả, Mann-Whitney U, Cliff's Delta và vẽ biểu đồ 4 pha (`E4.1–E4.3`).<br>

<br>`TV1`: Lập trình & chạy hồi cứu cảnh báo nhân quả (`E5.1–E5.3`). | **Chốt Cổng G3** (Đủ bảng & biểu đồ). |
| **Ngày 6 (T7)** | Ngày (09:00–16:30) | **E7** | `TV3`: Hoàn thiện `demo_case_analysis.ipynb` (`E7.1`).<br>

<br>`TV1 + TV2 + TV3`: Viết trọn vẹn bản thảo Báo cáo đồ án (`E7.2`). | Bản thảo Báo cáo & Notebook hoàn chỉnh. |
| **Ngày 7 (CN)** | Ngày (09:00–15:00) | **E7** | `TV1`: Hoàn thiện 12–15 slide bảo vệ (`E7.3`).<br>

<br>`Cả nhóm`: Đối soát chéo số liệu Báo cáo – Slide – CSV; chạy thử thuyết trình & demo 20 phút. | **Chốt Cổng G4 & Nộp bài.**[cite: 4, 6] |

---

## 8. Ma trận Truy xuất Bằng chứng (Đáp ứng Góp ý Giảng viên `[G05. C.3]`)

| Điểm góp ý của Giảng viên | Epic giải quyết | Sản phẩm / Bằng chứng đối chiếu |
| --- | --- | --- |
| Chọn rõ 1 mục tiêu cảnh báo (đầu vào, đầu ra, thời điểm sử dụng) | **E0, E5** | `research_scope_v1.md` & `alert_replay_results.json` |
| Phân tích dòng vốn phục vụ cảnh báo (tín hiệu vs. giải thích) | **E4, E5** | Cấu trúc Alert Payload trong `alert_engine.py` |
| Làm vài case đầy đủ, vẽ biểu đồ phân pha + kiểm định thống kê phù hợp | **E4, E6** | `reports/figures/*.png` & `statistical_results_*.csv` |
| Sửa lệch dữ liệu (`EVT_002`, `EVT_008` rỗng; `EVT_004` bằng 0) | **E0, E7** | `events_master_verified.csv` & `event_exclusion_log.md` |
| Kiểm tra thủ công tx & contract (tách drain, rút vốn, swap, nội bộ) | **E2** | `docs/manual_tx_audit.md` & `d3_gate_report.json` |
| Phân biệt thiếu dữ liệu (`NaN`) với `0`; kiểm tra độ phủ giá | **E1, E3** | Unit test `NaN vs 0` & `dataset_manifest.json` |
| Alert Lag cần giờ exploit & cảnh báo gốc xác minh; chống rò rỉ tương lai | **E0, E5** | `events_master_verified.csv` & kiểm tra nhân quả ($\le t$) |
| Không mở rộng crawl/BSTS/VAR/Granger khi chưa chuẩn phép đo | **E0, E7** | `research_scope_v1.md` & Mục Giới hạn nghiên cứu[cite: 4, 6] |

---

## 9. Bảng kiểm Hoàn tất Cuối cùng (Final Completion Checklist)

* [ ] Đã loại bỏ hoàn toàn `Curve`, `EVT_002`, `EVT_004`, `EVT_008` và lưu đầy đủ lý do trong `event_exclusion_log.md`.


* [ ] 100% sự kiện phân tích trong báo cáo có tệp Parquet/CSV đóng băng đi kèm mã băm SHA-256.


* [ ] Đã hoàn tất đối soát thủ công Top 20 giao dịch trên Etherscan (`manual_tx_audit.md`) và `unknown_flow_share <= 5%`[cite: 4, 5].
* [ ] Đã phân tách 5 luồng vốn (`attacker_drain`, `recovery_flow`, `user_net_flow`, `swap_mev`, `internal_transfer`).


* [ ] Không còn lỗi gán `price = 0` hoặc điền `0` cho giờ thiếu dữ liệu block.


* [ ] Mốc exploit và cảnh báo công khai gốc được xác minh chính xác đến phút/giây để tính `Alert Lag`[cite: 4, 6].
* [ ] Quy tắc cảnh báo trong `alert_engine.py` chỉ sử dụng dữ liệu quá khứ ($\le t$, không rò rỉ dữ liệu tương lai)[cite: 4, 6].
* [ ] Báo cáo nêu rõ giới hạn nghiên cứu, không đưa ra tuyên bố nhân quả kinh tế lượng vượt phạm vi.


* [ ] Toàn bộ con số trên Báo cáo, Slide, Notebook Demo và CSV nộp kèm khớp nhau 100%.