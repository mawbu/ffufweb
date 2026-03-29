namespace WebFuzzer.Core.Filters;

/// <summary>
/// Cấu hình bộ lọc response.
/// </summary>
public class FilterConfig
{
    // ── Filter (ẩn nếu khớp) ──────────────────────────────────────
    /// <summary>Ẩn các response có status code này.</summary>
    public HashSet<int> FilterStatusCodes { get; init; } = new();

    /// <summary>Ẩn các response có Content-Length bằng giá trị này (bytes).</summary>
    public HashSet<int> FilterSizes { get; init; } = new();

    /// <summary>Ẩn các response có số từ bằng giá trị này.</summary>
    public HashSet<int> FilterWords { get; init; } = new();

    /// <summary>Ẩn các response có số dòng bằng giá trị này.</summary>
    public HashSet<int> FilterLines { get; init; } = new();

    // ── Match (chỉ hiển thị nếu khớp) ────────────────────────────
    /// <summary>Chỉ hiển thị các response có status code này.</summary>
    public HashSet<int> MatchStatusCodes { get; init; } = new();

    /// <summary>Kiểm tra có cấu hình filter/match nào không.</summary>
    public bool HasAnyRule =>
        FilterStatusCodes.Count > 0 || FilterSizes.Count > 0 ||
        FilterWords.Count      > 0 || FilterLines.Count > 0 ||
        MatchStatusCodes.Count > 0;
}
