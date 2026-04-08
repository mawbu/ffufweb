namespace WebFuzzer.Core.Models;

public class FuzzResult
{
    public string Word { get; set; } = "";
    public string Payload { get; set; } = "";  // alias / synonym for Word
    public string Url { get; set; } = "";
    public int StatusCode { get; set; }
    public int ContentLength { get; set; }
    public int WordCount { get; set; }
    public int LineCount { get; set; }
    public long DurationMs { get; set; }
    public string? ResponseBody { get; set; }
    public string? ContentType { get; set; }
    public string? Error { get; set; }
    public bool IsFiltered { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// True nếu result này KHÔNG pass các Soft Rule mặc định (như MatchCodes 2xx, kích thước mặc định)
    /// NHƯNG được giữ lại nhờ VulnerabilityDetector phát hiện có khả năng là lỗi nghiêm trọng (score vượt threshold).
    /// </summary>
    public bool IsRetainedByDetection { get; set; }

    // Metadata từ detection engine
    public int DetectionScore { get; set; }
    public string? DetectedVulnType { get; set; }
    public string? DetectionSummary { get; set; }
    public string? ConfirmationSummary { get; set; }
}