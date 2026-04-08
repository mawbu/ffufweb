using System.Text;
using WebFuzzer.Core.Models;

namespace WebFuzzer.Core.Output;

public class ConsoleReporter : IFuzzReporter
{
    private readonly FuzzOptions _options;
    private readonly List<FuzzResult> _results = [];
    private readonly object _lock = new();
    private long _lastProgress = -1;

    // ANSI colors
    private const string Reset  = "\x1b[0m";
    private const string Bold   = "\x1b[1m";
    private const string Green  = "\x1b[32m";
    private const string Yellow = "\x1b[33m";
    private const string Red    = "\x1b[31m";
    private const string Cyan   = "\x1b[36m";
    private const string Gray   = "\x1b[90m";
    private const string Magenta = "\x1b[35m";

    public ConsoleReporter(FuzzOptions options) => _options = options;

    public Task InitAsync() => Task.CompletedTask;

    public async Task ReportAsync(FuzzResult result)
    {
        PrintResult(result);
        await Task.CompletedTask;
    }

    public async Task FinalizeAsync()
    {
        if (_options.OutputFile != null)
            await SaveAsync(_options.OutputFile);
    }

    public void PrintBanner(FuzzOptions options)
    {
        if (options.Silent) return;

        // Build các dòng filter/match tùy theo options được set
        var sb = new StringBuilder();
        sb.AppendLine($"{Bold}:: Target       :{Reset} {options.Url}");
        sb.AppendLine($"{Bold}:: Wordlist     :{Reset} {options.Wordlist}");
        sb.AppendLine($"{Bold}:: Threads      :{Reset} {options.Threads}");
        sb.AppendLine($"{Bold}:: Method       :{Reset} {options.Method}");
        sb.AppendLine($"{Bold}:: Match codes  :{Reset} {string.Join(",", options.MatchCodes ?? new[] { "200" })}");

        // ✅ Hiển thị regex nếu có
        if (!string.IsNullOrEmpty(options.MatchRegex))
            sb.AppendLine($"{Bold}:: Match regex  :{Reset} {Magenta}{options.MatchRegex}{Reset}");
        if (!string.IsNullOrEmpty(options.FilterRegex))
            sb.AppendLine($"{Bold}:: Filter regex :{Reset} {Magenta}{options.FilterRegex}{Reset}");

        Console.WriteLine($"""
            {Bold}{Cyan}
            ██╗    ██╗███████╗██████╗ ███████╗██╗   ██╗███████╗███████╗
            ██║    ██║██╔════╝██╔══██╗██╔════╝██║   ██║╚════██║╚════██║
            ██║ █╗ ██║█████╗  ██████╔╝█████╗  ██║   ██║    ██╔╝    ██╔╝
            ██║███╗██║██╔══╝  ██╔══██╗██╔══╝  ██║   ██║   ██╔╝    ██╔╝ 
            ╚███╔███╔╝███████╗██████╔╝██║     ╚██████╔╝   ██║     ██║  
             ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝      ╚═════╝    ╚═╝     ╚═╝  
            {Reset}WebFuzzer v1.0.0 — .NET 8 — by you
            ________________________________________________
            {sb.ToString().TrimEnd()}
            ________________________________________________
            """);
    }

    public void PrintResult(FuzzResult result)
    {
        lock (_lock)
        {
            _results.Add(result);

            var statusColor = result.StatusCode switch
            {
                200       => Green,
                201       => Green,
                301 or 302 or 307 => Yellow,
                403 or 500 => Red,
                _         => Cyan
            };

            // Xóa progress line trước khi in result
            if (!Console.IsOutputRedirected)
                Console.Write("\r" + new string(' ', Console.WindowWidth - 1) + "\r");

            // Hiển thị badge nếu là lỗi cao (quá threshold Likely=40)
            bool isVulnerable = result.DetectionScore >= 40 || result.IsRetainedByDetection;
            string badge = isVulnerable ? $"{Bold}{Red}[🔥 VULN] [Score: {result.DetectionScore}]{Reset} " : "";
            
            Console.WriteLine(
                $"{badge}{statusColor}[Status: {result.StatusCode,-3}]{Reset} " +
                $"{Bold}{result.Word,-40}{Reset} " +
                $"{Gray}[Size: {result.ContentLength,-8}]{Reset} " +
                $"{Gray}[Words: {result.WordCount,-6}]{Reset} " +
                $"{Gray}[Lines: {result.LineCount,-5}]{Reset} " +
                $"{Gray}[{result.DurationMs}ms]{Reset} " +
                $":: {Cyan}{result.Url}{Reset}"
            );

            // ✅ Verbose: in đoạn body liên quan đến regex match
            if (_options.Verbose && !string.IsNullOrEmpty(result.ResponseBody))
            {
                var preview = result.ResponseBody.Length > 300
                    ? result.ResponseBody[..300] + "..."
                    : result.ResponseBody;
                Console.WriteLine($"{Gray}    ↳ {preview}{Reset}");
            }
        }
    }

    public void UpdateProgress(long count, string currentWord)
    {
        if (_options.Silent || count == _lastProgress) return;
        _lastProgress = count;
        Console.Write($"\r{Gray}:: Progress: {count} | Current: {currentWord,-30}{Reset}");
    }

    public void PrintError(string word, string error)
    {
        lock (_lock)
            Console.WriteLine($"{Red}[ERR] {word}: {error}{Reset}");
    }

    public void PrintSummary(long total, long matches, TimeSpan duration)
    {
        if (_options.Silent) return;
        var durationStr = duration.ToString(@"mm\:ss\.fff");
        var reqPerSec   = duration.TotalSeconds > 0 ? (int)(total / duration.TotalSeconds) : 0;

        Console.WriteLine($"""

            ________________________________________________
            {Bold}:: Results{Reset}
            {Bold}:: Total requests  :{Reset} {total}
            {Bold}:: Matches found   :{Reset} {Green}{matches}{Reset}
            {Bold}:: Duration        :{Reset} {durationStr}
            {Bold}:: Req/sec         :{Reset} {reqPerSec}
            ________________________________________________
            """);
    }

    public async Task SaveAsync(string path)
    {
        await Task.CompletedTask;
    }
}