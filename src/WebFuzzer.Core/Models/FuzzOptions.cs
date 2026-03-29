namespace WebFuzzer.Core.Models;

public class FuzzOptions
{
    // Required
    public string Url { get; set; } = "";
    public string Wordlist { get; set; } = "";

    // Request
    public string Method { get; set; } = "GET";
    public string[]? Headers { get; set; }
    public string? Data { get; set; }
    public string? Cookie { get; set; }
    public string? ContentType { get; set; }
    public bool FollowRedirects { get; set; }
    public string? Proxy { get; set; }
    public int TimeoutSeconds { get; set; } = 10;

    // Performance
    public int Threads { get; set; } = 40;
    public int RateLimit { get; set; } = 0; // req/sec, 0 = unlimited
    public double DelayMin { get; set; } = 0;
    public double DelayMax { get; set; } = 0;

    // Match filters
    public string[]? MatchCodes { get; set; } = ["200", "301", "302"];
    public HashSet<int>? MatchSize { get; set; }
    public HashSet<int>? MatchWords { get; set; }
    public HashSet<int>? MatchLines { get; set; }
    public string? MatchRegex { get; set; }

    // Filter (exclude)
    public string[]? FilterCodes { get; set; }
    public HashSet<int>? FilterSize { get; set; }
    public HashSet<int>? FilterWords { get; set; }
    public HashSet<int>? FilterLines { get; set; }
    public string? FilterRegex { get; set; }

    // Output
    public string? OutputFile { get; set; }
    public string OutputFormat { get; set; } = "json";
    public bool Silent { get; set; }
    public bool Verbose { get; set; }
    public bool NoColor { get; set; }
}