namespace WebFuzzer.Core.Detection;

/// <summary>
/// Một signal đơn lẻ phát hiện anomaly trong response.
/// Mỗi signal mang trọng số (Weight) và bằng chứng cụ thể (Evidence).
/// </summary>
public sealed class DetectionSignal
{
    /// <summary>Tên signal, ví dụ: "ErrorKeyword_SQLi", "TimingAnomaly"</summary>
    public string Name { get; init; } = "";

    /// <summary>Điểm đóng góp (0–40). Tổng tất cả signal sẽ bị cap tại 100.</summary>
    public int Weight { get; init; }

    /// <summary>Loại lỗ hổng liên quan.</summary>
    public VulnType VulnType { get; init; }

    /// <summary>Bằng chứng chi tiết, ví dụ: "Found 'SQLITE_ERROR' in response body"</summary>
    public string Evidence { get; init; } = "";

    public override string ToString() => $"[{VulnType}] {Name} (+{Weight}): {Evidence}";
}
