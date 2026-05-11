# Kế hoạch Nâng cấp WebFuzzer thành Gray-Box Fuzzer (AFL-based) - Đã Cập Nhật

Dự án `WebFuzzer` hiện tại đang hoạt động như một công cụ Black-box Fuzzing theo tuyến tính giống `ffuf`: đọc một danh sách từ khóa tĩnh, gửi HTTP requests, và phát hiện điểm bất thường (anomaly) thông qua `VulnerabilityDetector`.

Để nâng cấp thành **Gray-box Fuzzer** lấy cảm hứng từ **AFL**, chúng ta thay đổi kiến trúc từ "tuyến tính" sang "vòng lặp tiến hóa" (evolutionary loop). Tuy nhiên, để rạch ròi giữa Fuzzing Feedback và Vulnerability Detection, các định nghĩa sau được thiết lập:

## 1. Cơ chế Coverage: Behavioral Fingerprint (Tùy chọn 1.5)

Thay vì yêu cầu Agent (Option 1) hay tái lập lại bộ phát hiện Anomaly (Option 2), Coverage được định nghĩa là **Behavioral Fingerprint** của mục tiêu:

- **Fingerprint** = `Tuple<int StatusBucket, int SizeBucket, int TimingBucket>`
  - `StatusBucket`: HTTP Status Code nguyên bản (200, 301, 404, 500...).
  - `SizeBucket`: Làm tròn/nhóm Content-Length để tránh nhiễu do dynamic content (VD: chia cho 100).
  - `TimingBucket`: Phân loại thời gian phản hồi thành các mốc (Fast: <100ms, Medium: 100-500ms, Slow: >500ms).
- **New Edge (Nhánh mới):** Nếu một Fingerprint chưa từng xuất hiện trong toàn cục `CoverageBitmap/HashSet`, nó được tính là một **New Edge**. Dữ liệu tạo ra Fingerprint này được đánh giá là "Thú vị" (Interesting) và được thêm vào Corpus.
- _Lưu ý:_ Cơ chế này độc lập với `VulnerabilityDetector` (vốn tập trung tìm Regex, Error SQL, hay Leak). Fingerprint chỉ dùng để vẽ bản đồ đường đi của mục tiêu.

## 2. Quản lý Hàng đợi: Hợp nhất vào FuzzQueue Thread-safe

`Channel<string>` hiện tại dùng làm backpressure giữa WordlistReader và Workers sẽ bị **thay thế hoàn toàn**.

- Thay vào đó, tạo một lớp **`FuzzQueue`** (sử dụng cấu trúc `ConcurrentQueue` hoặc `PriorityQueue` có lock thread-safe bên trong).
- **Luồng hoạt động:**
  - `Producer`: Đọc toàn bộ Wordlist (hoặc đọc streaming) và nạp thẳng vào `FuzzQueue` làm **Initial Seeds**.
  - `Workers` (N threads): Liên tục `Dequeue` từ `FuzzQueue`. Gửi request -> Đánh giá Fingerprint -> Nếu là Fingerprint mới -> Sinh các bản mutate (đột biến) -> `Enqueue` các bản mutate này vào lại `FuzzQueue`.
  - Vòng lặp dừng khi `FuzzQueue` rỗng hoặc người dùng nhấn Ctrl+C.

## 3. Quy trình Mutator: Chỉ áp dụng trên Corpus

Chỉ những Payload nằm trong **Corpus (những seed tạo ra Fingerprint mới)** mới bị đem đi mutate.

1. Khởi chạy: Lấy wordlist ban đầu gửi đi nguyên bản (Không mutate).
2. Khi Payload X (ví dụ `admin`) gửi đi trả về Status 200, SizeBucket 12 (lần đầu tiên xuất hiện Fingerprint này):
   - X được đánh dấu là `IsInteresting = true`.
   - X được thêm vào Corpus.
3. Mutator sẽ bốc X từ Corpus, áp dụng các đột biến:
   - `BitFlip(X)`, `Arithmetic(X)`, `DictionaryInsert(X)`, `Havoc(X)`...
   - Sản sinh ra danh sách `[X_mut1, X_mut2, X_mut3...]` và nhét vào lại `FuzzQueue`.
   - Lặp lại quá trình với `X_mutN`.

## 4. Cấu trúc Module Mới

### [NEW] `src/WebFuzzer.Core/AFL/BehavioralFingerprint.cs`

- Hàm tính toán hash/bucket dựa trên `StatusCode`, `ContentLength`, `DurationMs`.
- Quản lý `HashSet<string> _globalFingerprints` (thread-safe) để theo dõi các Fingerprint đã biết.

### [NEW] `src/WebFuzzer.Core/AFL/FuzzQueue.cs`

- Wrapper quản lý `ConcurrentQueue` cho Initial Seeds và các Mutated Payloads.

### [NEW] `src/WebFuzzer.Core/AFL/Mutator.cs`

- Các hàm `Mutate(string seed, int energy)`: Tùy mức độ Energy mà sinh ra ít hay nhiều biến thể (bitflips, chèn ký tự nguy hiểm).

### [MODIFY] `src/WebFuzzer.Core/Engine/FuzzEngine.cs`

- Gỡ bỏ hoàn toàn `ChannelReader`.
- Worker gọi `FuzzQueue.TryDequeue()`.
- Tích hợp hàm kiểm tra `BehavioralFingerprint.IsNew(result)`. Nếu `true`, gọi `Mutator` sinh payload mới đẩy ngược vào `FuzzQueue`.

---

## Verification Plan

##### Môi trường thực hiện test tìm lổ hổng (Đây là web thuộc sở hữu cá nhân)

https://imagify-mabuw.onrender.com/

## User Review Required

> [!WARNING]
> Milestone 1 — Không phá vỡ gì hiện tại: thêm CoverageAnalyzer + HttpCoverageBitmap, chạy song song với flow hiện tại chỉ để log [NEW PATH], chưa enqueue lại. Xác nhận fingerprint hoạt động đúng.
> Milestone 2 — Thêm FuzzQueue + Mutator, nhưng giữ wordlist làm primary source, FuzzQueue chỉ nhận enqueue từ Milestone 1. Workers đọc từ cả hai nguồn với priority.
> Milestone 3 — Cắt Channel<string> tuyến tính, FuzzQueue trở thành nguồn duy nhất. Lúc này là evolutionary loop thực sự.

##### điểm nhỏ cần quyết định trước khi code

1. FuzzQueue dùng ConcurrentQueue hay PriorityQueue?
   Plan ghi "ConcurrentQueue hoặc PriorityQueue" — nhưng hai cái này cho kết quả khác nhau đáng kể. ConcurrentQueue là FIFO, initial seeds và mutated payloads được xử lý theo thứ tự đến. PriorityQueue (với energy score) ưu tiên seed nào đã tạo nhiều fingerprint mới hơn — đây mới là cơ chế AFL thực sự. Tuy nhiên PriorityQueue trong .NET không thread-safe, phải bọc lock. Gợi ý: bắt đầu với ConcurrentQueue cho Milestone 1–2, nâng lên PriorityQueue + lock ở Milestone 3 khi đã ổn định.
2. FuzzQueue rỗng khi nào thì dừng?
   Plan nói "vòng lặp dừng khi FuzzQueue rỗng" — nhưng với evolutionary loop, queue liên tục được thêm vào từ workers. Sẽ có race condition: worker A vừa dequeue phần tử cuối, queue báo Empty, nhưng worker B đang chuẩn bị enqueue mutation mới. Cần một activeWorkers counter — chỉ dừng khi queue rỗng và không có worker nào đang xử lý. Channel hiện tại xử lý điều này tự động qua Complete(), FuzzQueue tự làm thì phải implement thêm.
3. Energy trong Mutator.Mutate(seed, energy) tính từ đâu?
   Parameter energy trong signature Mutate(string seed, int energy) chưa có nguồn. Ai tính? Ai truyền vào? Gợi ý đơn giản nhất: energy = newFingerprintsCount của seed đó — seed nào đã dẫn đến 3 fingerprint mới thì energy = 3, sinh ra nhiều biến thể hơn. CorpusEntry cần giữ field này.
