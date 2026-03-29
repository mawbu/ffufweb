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
}