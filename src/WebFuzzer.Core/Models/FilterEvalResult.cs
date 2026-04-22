namespace WebFuzzer.Core.Models;

/// <summary>
/// Lý do một result được hiển thị (pass soft rule).
/// Dùng để hiển thị tag trong DataGrid UI.
/// </summary>
public enum MatchReason
{
    None,
    ByStatusCode,   // khớp -mc (match codes)
    ByRegex,        // khớp -mr (match regex)
    BySize,         // khớp -ms (match size)
    ByWords,        // khớp -mw (match words)
    ByLines,        // khớp -ml (match lines)
    ByDetection     // bị filter nhưng detection score cao → bypass
}

public readonly struct FilterEvalResult
{
    public bool IsBlockedByStrictRule { get; init; }
    public bool IsPassedBySoftRule { get; init; }

    /// <summary>
    /// Lý do cụ thể tại sao result này được giữ lại.
    /// Chỉ có giá trị khi IsPassedBySoftRule = true.
    /// </summary>
    public MatchReason MatchReason { get; init; }
}