namespace WebFuzzer.Core.Detection;

/// <summary>
/// Severity level dựa trên confidence score tổng hợp.
/// </summary>
public enum Severity
{
    /// <summary>Score &lt; 15 — không phát hiện bất thường</summary>
    Normal,
    /// <summary>Score 15–39 — có dấu hiệu, cần xác minh thêm</summary>
    Suspicious,
    /// <summary>Score 40–69 — nhiều khả năng là lỗ hổng</summary>
    Likely,
    /// <summary>Score ≥ 70 — xác nhận lỗ hổng, có bằng chứng rõ ràng</summary>
    Confirmed
}

/// <summary>
/// Kết quả phân tích vulnerability cho một FuzzResult.
/// Bao gồm confidence score (0–100), severity, danh sách signal, và tóm tắt.
/// </summary>
public sealed class DetectionResult
{
    /// <summary>Điểm tin cậy tổng hợp, cap tại 100.</summary>
    public int ConfidenceScore { get; init; }

    /// <summary>Mức độ nghiêm trọng dựa trên score.</summary>
    public Severity Severity { get; init; }

    /// <summary>Loại lỗ hổng chính (VulnType có weight cao nhất).</summary>
    public VulnType PrimaryVulnType { get; init; }

    /// <summary>Danh sách tất cả signal đã phát hiện.</summary>
    public IReadOnlyList<DetectionSignal> Signals { get; init; } = [];

    /// <summary>Tóm tắt dạng text, ví dụ: "🔴 CONFIRMED 85% — SQLi (3 signals)"</summary>
    public string Summary { get; init; } = "";

    /// <summary>Emoji + label ngắn gọn cho UI DataGrid column.</summary>
    public string ShortLabel => Severity switch
    {
        Severity.Confirmed  => $"🔴 {ConfidenceScore}%",
        Severity.Likely     => $"🟠 {ConfidenceScore}%",
        Severity.Suspicious => $"🟡 {ConfidenceScore}%",
        _                   => ""
    };

    public static DetectionResult None { get; } = new()
    {
        ConfidenceScore = 0,
        Severity = Severity.Normal,
        PrimaryVulnType = VulnType.None,
        Signals = [],
        Summary = ""
    };

    public static Severity ScoreToSeverity(int score) => score switch
    {
        >= 70 => Severity.Confirmed,
        >= 40 => Severity.Likely,
        >= 15 => Severity.Suspicious,
        _     => Severity.Normal
    };
}
