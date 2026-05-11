using System.Collections.Concurrent;

namespace WebFuzzer.Core.AFL;

/// <summary>
/// Coverage-guided Behavioral Fingerprint cho Gray-Box Fuzzing.
/// Fingerprint = (StatusCode, SizeBucket, TimingBucket)
/// 
/// Một "New Edge" xảy ra khi Fingerprint chưa từng xuất hiện trước đó.
/// Cơ chế này HOÀN TOÀN ĐỘC LẬP với VulnerabilityDetector —
/// Fingerprint chỉ dùng để vẽ bản đồ hành vi (coverage map) của mục tiêu.
/// </summary>
public sealed class BehavioralFingerprint
{
    // Thread-safe set lưu trữ tất cả fingerprints đã biết.
    // Dùng ConcurrentDictionary<string, byte> vì .NET không có ConcurrentHashSet.
    private readonly ConcurrentDictionary<string, byte> _knownFingerprints = new();

    /// <summary>
    /// Tổng số fingerprints đã phát hiện (= số nhánh hành vi khác nhau).
    /// Dùng cho stats reporting.
    /// </summary>
    public int TotalFingerprints => _knownFingerprints.Count;

    /// <summary>
    /// Kiểm tra xem response này có tạo ra fingerprint mới hay không.
    /// Nếu fingerprint chưa từng xuất hiện → trả về true (= "New Edge").
    /// Thread-safe — có thể gọi đồng thời từ nhiều workers.
    /// </summary>
    /// <param name="statusCode">HTTP Status Code (200, 301, 404, 500...)</param>
    /// <param name="contentLength">Content-Length của response body (bytes)</param>
    /// <param name="durationMs">Thời gian phản hồi (milliseconds)</param>
    /// <returns>true nếu đây là fingerprint mới (New Edge)</returns>
    public bool IsNewFingerprint(int statusCode, int contentLength, long durationMs)
    {
        var fingerprint = ComputeFingerprint(statusCode, contentLength, durationMs);
        // TryAdd returns true if key was added (= new fingerprint)
        return _knownFingerprints.TryAdd(fingerprint, 0);
    }

    /// <summary>
    /// Tính fingerprint string từ 3 thành phần.
    /// Format: "STATUS|SIZE_BUCKET|TIMING_BUCKET"
    /// </summary>
    public static string ComputeFingerprint(int statusCode, int contentLength, long durationMs)
    {
        int sizeBucket = ComputeSizeBucket(contentLength);
        int timingBucket = ComputeTimingBucket(durationMs);
        return $"{statusCode}|{sizeBucket}|{timingBucket}";
    }

    /// <summary>
    /// Size Bucket dùng floor(log2(max(contentLength, 1))).
    /// Lấy cảm hứng từ paper webFuzz — ổn định hơn phép chia /100:
    ///   - 0 bytes → bucket 0
    ///   - 1 byte → bucket 0
    ///   - 100 bytes → bucket 6
    ///   - 1000 bytes → bucket 9
    ///   - 1001 bytes → bucket 9 (cùng bucket!)
    ///   - 10000 bytes → bucket 13
    /// So với chia 100:
    ///   - 1000 bytes → bucket 10, 1001 → bucket 10 (OK)
    ///   - 950 bytes → bucket 9, 1049 → bucket 10 (khác bucket! → BAD)
    /// </summary>
    public static int ComputeSizeBucket(int contentLength)
    {
        int safeLength = Math.Max(contentLength, 1);
        return (int)Math.Floor(Math.Log2(safeLength));
    }

    /// <summary>
    /// Timing Bucket: phân loại thời gian phản hồi thành 3 mốc.
    ///   - Fast:   <100ms  → 0
    ///   - Medium: 100-500ms → 1
    ///   - Slow:   >500ms → 2
    /// </summary>
    public static int ComputeTimingBucket(long durationMs)
    {
        if (durationMs < 100) return 0;  // Fast
        if (durationMs <= 500) return 1; // Medium
        return 2;                         // Slow
    }

    /// <summary>
    /// Reset toàn bộ fingerprints đã biết (dùng khi bắt đầu scan mới).
    /// </summary>
    public void Reset()
    {
        _knownFingerprints.Clear();
    }
}
