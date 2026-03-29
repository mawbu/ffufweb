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
            {Bold}:: Target       :{Reset} {options.Url}
            {Bold}:: Wordlist     :{Reset} {options.Wordlist}
            {Bold}:: Threads      :{Reset} {options.Threads}
            {Bold}:: Method       :{Reset} {options.Method}
            {Bold}:: Match codes  :{Reset} {string.Join(",", options.MatchCodes ?? ["200"])}
            ________________________________________________
            """);
    }

    public void PrintResult(FuzzResult result)
    {
        lock (_lock)
        {
            _results.Add(result);
            
            var color = result.StatusCode switch
            {
                200 => Green,
                301 or 302 or 307 => Yellow,
                403 => Red,
                _ => Cyan
            };

            // Clear progress line trước khi in result
            Console.Write("\r" + new string(' ', Console.WindowWidth - 1) + "\r");
            
            Console.WriteLine(
                $"{color}[Status: {result.StatusCode,-3}]{Reset} " +
                $"{Bold}{result.Word,-40}{Reset} " +
                $"{Gray}[Size: {result.ContentLength,-8}]{Reset} " +
                $"{Gray}[Words: {result.WordCount,-6}]{Reset} " +
                $"{Gray}[Lines: {result.LineCount,-5}]{Reset} " +
                $"{Gray}[{result.DurationMs}ms]{Reset} " +
                $":: {Cyan}{result.Url}{Reset}"
            );
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
        Console.WriteLine($"""

            ________________________________________________
            {Bold}:: Results{Reset}
            {Bold}:: Total requests  :{Reset} {total}
            {Bold}:: Matches found   :{Reset} {Green}{matches}{Reset}
            {Bold}:: Duration        :{Reset} {duration:mm\\:ss\\.fff}
            {Bold}:: Req/sec         :{Reset} {(int)(total / duration.TotalSeconds)}
            ________________________________________________
            """);
    }

    public async Task SaveAsync(string path)
    {
        // Được override bởi JsonReporter / CsvReporter
        await Task.CompletedTask;
    }
}